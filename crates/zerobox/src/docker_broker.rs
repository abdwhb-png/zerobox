use std::collections::{HashMap, HashSet};
use std::fs::{DirBuilder, Permissions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use serde_json::Value;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::{JoinHandle, JoinSet};
use zerobox_protocol::docker::{
    DockerAccessPolicy, DockerOperation, DockerTargetGrant, DockerTargetSelector,
};

use crate::process_owner::{RUN_DIR_PREFIX, is_process_alive, owner_pid};

const BROKER_SOCKET_NAME: &str = "broker.sock";
const MAX_REQUEST_HEADER_BYTES: usize = 64 * 1024;
const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
const MAX_BUFFERED_ENGINE_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone)]
enum BrokerMode {
    Full,
    Targeted(Arc<TargetSnapshot>),
}

#[derive(Debug, Default)]
struct TargetSnapshot {
    containers: HashMap<String, AllowedContainer>,
    aliases: HashMap<String, String>,
    exec_ids: Mutex<HashMap<String, String>>,
}

#[derive(Debug)]
struct AllowedContainer {
    operations: HashSet<DockerOperation>,
}

pub(crate) struct DockerBroker {
    socket_path: PathBuf,
    root: PathBuf,
    task: JoinHandle<()>,
}

impl DockerBroker {
    pub(crate) async fn start(policy: &DockerAccessPolicy) -> Result<Option<Self>> {
        let (endpoint, mode) = match policy {
            DockerAccessPolicy::Disabled => return Ok(None),
            DockerAccessPolicy::Full { endpoint } => {
                (endpoint.as_path().to_path_buf(), BrokerMode::Full)
            }
            DockerAccessPolicy::Targeted { endpoint, targets } => {
                let endpoint = endpoint.as_path().to_path_buf();
                let snapshot = resolve_target_snapshot(&endpoint, targets).await;
                (endpoint, BrokerMode::Targeted(Arc::new(snapshot)))
            }
        };

        let root = create_private_broker_root()?;
        let socket_path = root.join(BROKER_SOCKET_NAME);
        let listener = UnixListener::bind(&socket_path)
            .with_context(|| format!("failed to bind Docker broker {}", socket_path.display()))?;
        set_private_socket_permissions(&socket_path)?;

        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                let accepted = listener.accept().await;
                let Ok((mut client, _)) = accepted else {
                    break;
                };
                let endpoint = endpoint.clone();
                let mode = mode.clone();
                connections.spawn(async move {
                    let _ = match mode {
                        BrokerMode::Full => relay_full(&mut client, &endpoint).await,
                        BrokerMode::Targeted(snapshot) => {
                            handle_targeted_connection(&mut client, &endpoint, &snapshot).await
                        }
                    };
                });
                while connections.try_join_next().is_some() {}
            }
        });

        Ok(Some(Self {
            socket_path,
            root,
            task,
        }))
    }

    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

impl Drop for DockerBroker {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

async fn relay_full(client: &mut UnixStream, endpoint: &Path) -> Result<()> {
    let mut engine = UnixStream::connect(endpoint)
        .await
        .context("Docker Engine is unavailable")?;
    io::copy_bidirectional(client, &mut engine).await?;
    Ok(())
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    target: String,
    version: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpRequest {
    fn requests_upgrade(&self) -> bool {
        self.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("connection")
                && value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
    }

    fn serialize(&self, force_close: bool) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(
            format!("{} {} {}\r\n", self.method, self.target, self.version).as_bytes(),
        );
        for (name, value) in &self.headers {
            if name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("transfer-encoding")
                || (force_close && name.eq_ignore_ascii_case("connection"))
            {
                continue;
            }
            encoded.extend_from_slice(name.as_bytes());
            encoded.extend_from_slice(b": ");
            encoded.extend_from_slice(value.as_bytes());
            encoded.extend_from_slice(b"\r\n");
        }
        if !self.body.is_empty() {
            encoded
                .extend_from_slice(format!("Content-Length: {}\r\n", self.body.len()).as_bytes());
        }
        if force_close {
            encoded.extend_from_slice(b"Connection: close\r\n");
        }
        encoded.extend_from_slice(b"\r\n");
        encoded.extend_from_slice(&self.body);
        encoded
    }
}

#[derive(Debug)]
enum TargetedAction {
    Forward,
    Discovery,
    ExecCreate { container_id: String },
    ExecStream,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthorizationError {
    NotFound,
    Forbidden,
}

async fn handle_targeted_connection(
    client: &mut UnixStream,
    endpoint: &Path,
    snapshot: &TargetSnapshot,
) -> Result<()> {
    let request = match read_request(client).await {
        Ok(request) => request,
        Err(_) => {
            write_error(client, 400, "malformed Docker request").await?;
            return Ok(());
        }
    };

    let action = match authorize_request(snapshot, &request) {
        Ok(action) => action,
        Err(AuthorizationError::NotFound) => {
            write_error(client, 404, "Docker target not found").await?;
            return Ok(());
        }
        Err(AuthorizationError::Forbidden) => {
            write_error(client, 403, "Docker operation forbidden").await?;
            return Ok(());
        }
    };

    match action {
        TargetedAction::Forward => relay_authorized(client, endpoint, &request, false).await,
        TargetedAction::ExecStream => relay_authorized(client, endpoint, &request, true).await,
        TargetedAction::Discovery => {
            let raw = match engine_request_collect(endpoint, &request).await {
                Ok(raw) => raw,
                Err(_) => {
                    write_error(client, 503, "Docker Engine unavailable").await?;
                    return Ok(());
                }
            };
            let response = match parse_engine_response(&raw) {
                Ok(response) => response,
                Err(_) => {
                    write_error(client, 502, "invalid Docker Engine response").await?;
                    return Ok(());
                }
            };
            if !(200..300).contains(&response.status) {
                client.write_all(&raw).await?;
                return Ok(());
            }
            let body = match filter_discovery_response(snapshot, &response.body) {
                Ok(body) => body,
                Err(_) => {
                    write_error(client, 502, "invalid Docker Engine response").await?;
                    return Ok(());
                }
            };
            write_json(client, 200, &body).await
        }
        TargetedAction::ExecCreate { container_id } => {
            if !safe_exec_create_body(&request.body) {
                write_error(client, 403, "unsafe Docker exec forbidden").await?;
                return Ok(());
            }
            let raw = match engine_request_collect(endpoint, &request).await {
                Ok(raw) => raw,
                Err(_) => {
                    write_error(client, 503, "Docker Engine unavailable").await?;
                    return Ok(());
                }
            };
            if let Ok(response) = parse_engine_response(&raw)
                && (200..300).contains(&response.status)
                && let Ok(value) = serde_json::from_slice::<Value>(&response.body)
                && let Some(exec_id) = value
                    .get("Id")
                    .or_else(|| value.get("ID"))
                    .and_then(Value::as_str)
            {
                snapshot
                    .exec_ids
                    .lock()
                    .expect("Docker exec registry poisoned")
                    .insert(exec_id.to_string(), container_id);
            }
            client.write_all(&raw).await?;
            Ok(())
        }
    }
}

async fn read_request(stream: &mut UnixStream) -> Result<HttpRequest> {
    let mut bytes = Vec::with_capacity(4096);
    let header_end = loop {
        if let Some(index) = find_bytes(&bytes, b"\r\n\r\n") {
            break index + 4;
        }
        if bytes.len() >= MAX_REQUEST_HEADER_BYTES {
            bail!("Docker request headers are too large");
        }
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            bail!("Docker request ended before its headers");
        }
        bytes.extend_from_slice(&chunk[..read]);
    };
    if header_end > MAX_REQUEST_HEADER_BYTES {
        bail!("Docker request headers are too large");
    }

    let head = std::str::from_utf8(&bytes[..header_end - 4])?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().context("missing Docker request line")?;
    let mut request_parts = request_line.split(' ');
    let method = request_parts.next().unwrap_or_default().to_string();
    let target = request_parts.next().unwrap_or_default().to_string();
    let version = request_parts.next().unwrap_or_default().to_string();
    if request_parts.next().is_some()
        || method.is_empty()
        || !method.bytes().all(|byte| byte.is_ascii_uppercase())
        || !target.starts_with('/')
        || !matches!(version.as_str(), "HTTP/1.0" | "HTTP/1.1")
    {
        bail!("invalid Docker request line");
    }

    let mut headers = Vec::new();
    let mut content_length = None;
    let mut has_transfer_encoding = false;
    for line in lines {
        if line.starts_with([' ', '\t']) {
            bail!("obsolete folded Docker header");
        }
        let (name, value) = line.split_once(':').context("invalid Docker header")?;
        if name.is_empty() || !name.bytes().all(is_header_name_byte) {
            bail!("invalid Docker header name");
        }
        let value = value.trim().to_string();
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                bail!("duplicate Docker content length");
            }
            content_length = Some(value.parse::<usize>()?);
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            has_transfer_encoding = true;
        }
        headers.push((name.to_string(), value));
    }
    if has_transfer_encoding {
        bail!("transfer-encoded Docker requests are not supported");
    }

    let content_length = content_length.unwrap_or(0);
    if content_length > MAX_REQUEST_BODY_BYTES {
        bail!("Docker request body is too large");
    }
    let mut body = bytes.split_off(header_end);
    if body.len() > content_length {
        bail!("pipelined Docker requests are not supported");
    }
    while body.len() < content_length {
        let remaining = content_length - body.len();
        let mut chunk = vec![0_u8; remaining.min(4096)];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            bail!("Docker request body ended early");
        }
        body.extend_from_slice(&chunk[..read]);
    }

    Ok(HttpRequest {
        method,
        target,
        version,
        headers,
        body,
    })
}

fn is_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn authorize_request(
    snapshot: &TargetSnapshot,
    request: &HttpRequest,
) -> std::result::Result<TargetedAction, AuthorizationError> {
    let path = request.target.split('?').next().unwrap_or(&request.target);
    let path = strip_api_version(path);
    if matches!((request.method.as_str(), path), ("GET" | "HEAD", "/_ping"))
        || matches!((request.method.as_str(), path), ("GET", "/version"))
    {
        return Ok(TargetedAction::Forward);
    }
    if path == "/containers/json" {
        return if request.method == "GET" {
            Ok(TargetedAction::Discovery)
        } else {
            Err(AuthorizationError::Forbidden)
        };
    }

    let segments = decode_path_segments(path)?;
    if segments.len() >= 3 && segments[0] == "containers" {
        let container_id = snapshot
            .aliases
            .get(&segments[1])
            .ok_or(AuthorizationError::NotFound)?;
        let operation = match (request.method.as_str(), segments[2].as_str()) {
            ("GET", "json") => DockerOperation::Inspect,
            ("GET", "logs") => DockerOperation::Logs,
            ("GET", "stats") => DockerOperation::Stats,
            ("POST", "exec") => DockerOperation::Exec,
            ("POST", "start") => DockerOperation::Start,
            ("POST", "stop") => DockerOperation::Stop,
            ("POST", "restart") => DockerOperation::Restart,
            _ => return Err(AuthorizationError::Forbidden),
        };
        ensure_operation(snapshot, container_id, operation)?;
        if operation == DockerOperation::Exec {
            return Ok(TargetedAction::ExecCreate {
                container_id: container_id.clone(),
            });
        }
        return Ok(TargetedAction::Forward);
    }

    if segments.len() >= 3 && segments[0] == "exec" {
        let container_id = snapshot
            .exec_ids
            .lock()
            .expect("Docker exec registry poisoned")
            .get(&segments[1])
            .cloned()
            .ok_or(AuthorizationError::NotFound)?;
        let permitted = matches!(
            (request.method.as_str(), segments[2].as_str()),
            ("POST", "start" | "resize") | ("GET", "json")
        );
        if !permitted {
            return Err(AuthorizationError::Forbidden);
        }
        ensure_operation(snapshot, &container_id, DockerOperation::Exec)?;
        if segments[2] == "start" && !safe_exec_start_body(&request.body) {
            return Err(AuthorizationError::Forbidden);
        }
        return if segments[2] == "start" {
            Ok(TargetedAction::ExecStream)
        } else {
            Ok(TargetedAction::Forward)
        };
    }

    Err(AuthorizationError::Forbidden)
}

fn strip_api_version(path: &str) -> &str {
    let Some(remainder) = path.strip_prefix("/v") else {
        return path;
    };
    let Some(slash) = remainder.find('/') else {
        return path;
    };
    if remainder[..slash]
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
        && remainder[..slash].bytes().any(|byte| byte == b'.')
    {
        &remainder[slash..]
    } else {
        path
    }
}

fn decode_path_segments(path: &str) -> std::result::Result<Vec<String>, AuthorizationError> {
    path.trim_start_matches('/')
        .split('/')
        .map(percent_decode)
        .collect()
}

fn percent_decode(value: &str) -> std::result::Result<String, AuthorizationError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(AuthorizationError::Forbidden);
            }
            let high = hex_digit(bytes[index + 1]).ok_or(AuthorizationError::Forbidden)?;
            let low = hex_digit(bytes[index + 2]).ok_or(AuthorizationError::Forbidden)?;
            let byte = (high << 4) | low;
            if byte == b'/' || byte == 0 {
                return Err(AuthorizationError::Forbidden);
            }
            decoded.push(byte);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| AuthorizationError::Forbidden)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn ensure_operation(
    snapshot: &TargetSnapshot,
    container_id: &str,
    operation: DockerOperation,
) -> std::result::Result<(), AuthorizationError> {
    let container = snapshot
        .containers
        .get(container_id)
        .ok_or(AuthorizationError::NotFound)?;
    if container.operations.contains(&operation) {
        Ok(())
    } else {
        Err(AuthorizationError::Forbidden)
    }
}

fn filter_discovery_response(snapshot: &TargetSnapshot, body: &[u8]) -> Result<Vec<u8>> {
    let mut containers: Vec<Value> = serde_json::from_slice(body)?;
    containers.retain(|container| {
        container
            .get("Id")
            .and_then(Value::as_str)
            .and_then(|id| snapshot.containers.get(id))
            .is_some_and(|container| container.operations.contains(&DockerOperation::Ps))
    });
    Ok(serde_json::to_vec(&containers)?)
}

fn safe_exec_create_body(body: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return false;
    };
    !value
        .get("Privileged")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && !value
            .get("Detach")
            .and_then(Value::as_bool)
            .unwrap_or(false)
}

fn safe_exec_start_body(body: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return false;
    };
    !value
        .get("Detach")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && !value
            .get("Privileged")
            .and_then(Value::as_bool)
            .unwrap_or(false)
}

async fn relay_authorized(
    client: &mut UnixStream,
    endpoint: &Path,
    request: &HttpRequest,
    bidirectional: bool,
) -> Result<()> {
    let mut engine = match UnixStream::connect(endpoint).await {
        Ok(engine) => engine,
        Err(_) => {
            write_error(client, 503, "Docker Engine unavailable").await?;
            return Ok(());
        }
    };
    let request_upgrade = request.requests_upgrade();
    engine
        .write_all(&request.serialize(!request_upgrade && !bidirectional))
        .await?;
    if request_upgrade || bidirectional {
        io::copy_bidirectional(client, &mut engine).await?;
    } else {
        io::copy(&mut engine, client).await?;
    }
    Ok(())
}

async fn engine_request_collect(endpoint: &Path, request: &HttpRequest) -> Result<Vec<u8>> {
    let mut engine = UnixStream::connect(endpoint)
        .await
        .context("Docker Engine is unavailable")?;
    engine.write_all(&request.serialize(true)).await?;
    let mut response = Vec::new();
    loop {
        let mut chunk = [0_u8; 8192];
        let read = engine.read(&mut chunk).await?;
        if read == 0 {
            return Ok(response);
        }
        if response.len() + read > MAX_BUFFERED_ENGINE_RESPONSE_BYTES {
            bail!("Docker Engine response is too large");
        }
        response.extend_from_slice(&chunk[..read]);
    }
}

struct EngineResponse {
    status: u16,
    body: Vec<u8>,
}

fn parse_engine_response(raw: &[u8]) -> Result<EngineResponse> {
    let head_end = find_bytes(raw, b"\r\n\r\n").context("missing Docker response headers")?;
    let head = std::str::from_utf8(&raw[..head_end])?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .context("missing Docker response status")?
        .parse::<u16>()?;
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .context("invalid Docker response header")?;
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                bail!("duplicate Docker response content length");
            }
            content_length = Some(value.trim().parse::<usize>()?);
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked {
                bail!("duplicate Docker response transfer encoding");
            }
            chunked = value
                .split(',')
                .any(|coding| coding.trim().eq_ignore_ascii_case("chunked"));
            if !chunked {
                bail!("unsupported Docker response transfer encoding");
            }
        }
    }
    if chunked && content_length.is_some() {
        bail!("ambiguous Docker response framing");
    }

    let encoded_body = &raw[head_end + 4..];
    let body = if chunked {
        decode_chunked_body(encoded_body)?
    } else if let Some(content_length) = content_length {
        if encoded_body.len() != content_length {
            bail!("invalid Docker response content length");
        }
        encoded_body.to_vec()
    } else {
        encoded_body.to_vec()
    };
    Ok(EngineResponse { status, body })
}

fn decode_chunked_body(encoded: &[u8]) -> Result<Vec<u8>> {
    let mut decoded = Vec::new();
    let mut offset = 0;
    loop {
        let line_end = find_bytes(&encoded[offset..], b"\r\n")
            .map(|index| offset + index)
            .context("incomplete Docker response chunk size")?;
        let size_line = std::str::from_utf8(&encoded[offset..line_end])?;
        let size =
            usize::from_str_radix(size_line.split(';').next().unwrap_or_default().trim(), 16)?;
        offset = line_end + 2;
        if size == 0 {
            if !encoded[offset..].starts_with(b"\r\n")
                && find_bytes(&encoded[offset..], b"\r\n\r\n").is_none()
            {
                bail!("invalid Docker response trailers");
            }
            return Ok(decoded);
        }
        let chunk_end = offset
            .checked_add(size)
            .context("Docker response chunk overflow")?;
        if chunk_end + 2 > encoded.len() || &encoded[chunk_end..chunk_end + 2] != b"\r\n" {
            bail!("incomplete Docker response chunk");
        }
        decoded.extend_from_slice(&encoded[offset..chunk_end]);
        if decoded.len() > MAX_BUFFERED_ENGINE_RESPONSE_BYTES {
            bail!("decoded Docker response is too large");
        }
        offset = chunk_end + 2;
    }
}

async fn write_error(stream: &mut UnixStream, status: u16, message: &str) -> Result<()> {
    let body = serde_json::to_vec(&serde_json::json!({ "message": message }))?;
    write_json(stream, status, &body).await
}

async fn write_json(stream: &mut UnixStream, status: u16, body: &[u8]) -> Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Error",
    };
    stream
        .write_all(
            format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await?;
    stream.write_all(body).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn resolve_target_snapshot(endpoint: &Path, grants: &[DockerTargetGrant]) -> TargetSnapshot {
    let request = synthetic_get("/containers/json?all=1");
    let Ok(Ok(raw)) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        engine_request_collect(endpoint, &request),
    )
    .await
    else {
        return TargetSnapshot::default();
    };
    let Ok(response) = parse_engine_response(&raw) else {
        return TargetSnapshot::default();
    };
    if !(200..300).contains(&response.status) {
        return TargetSnapshot::default();
    }
    let Ok(summaries) = serde_json::from_slice::<Vec<Value>>(&response.body) else {
        return TargetSnapshot::default();
    };

    let mut snapshot = TargetSnapshot::default();
    for summary in summaries {
        let Some(id) = summary.get("Id").and_then(Value::as_str) else {
            continue;
        };
        let matching_grants: Vec<&DockerTargetGrant> = grants
            .iter()
            .filter(|grant| grant_matches_summary(grant, &summary))
            .collect();
        if matching_grants.is_empty() {
            continue;
        }

        let inspect_request = synthetic_get(&format!("/containers/{id}/json"));
        let Ok(Ok(inspect_raw)) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            engine_request_collect(endpoint, &inspect_request),
        )
        .await
        else {
            continue;
        };
        let Ok(inspect_response) = parse_engine_response(&inspect_raw) else {
            continue;
        };
        if !(200..300).contains(&inspect_response.status) {
            continue;
        }
        let Ok(inspect) = serde_json::from_slice::<Value>(&inspect_response.body) else {
            continue;
        };
        let unsafe_target = is_unsafe_target(&inspect);
        let eligible_grants: Vec<&DockerTargetGrant> = matching_grants
            .into_iter()
            .filter(|grant| !unsafe_target || grant.allow_unsafe_target)
            .collect();
        if eligible_grants.is_empty() {
            continue;
        }
        let operations: HashSet<DockerOperation> = eligible_grants
            .into_iter()
            .flat_map(|grant| grant.effective_operations().iter().copied())
            .collect();

        snapshot
            .containers
            .insert(id.to_string(), AllowedContainer { operations });
        snapshot.aliases.insert(id.to_string(), id.to_string());
        if let Some(names) = summary.get("Names").and_then(Value::as_array) {
            for name in names.iter().filter_map(Value::as_str) {
                let name = name.strip_prefix('/').unwrap_or(name);
                if !name.is_empty() {
                    snapshot.aliases.insert(name.to_string(), id.to_string());
                }
            }
        }
    }
    snapshot
}

fn synthetic_get(target: &str) -> HttpRequest {
    HttpRequest {
        method: "GET".to_string(),
        target: target.to_string(),
        version: "HTTP/1.1".to_string(),
        headers: vec![("Host".to_string(), "docker".to_string())],
        body: Vec::new(),
    }
}

fn grant_matches_summary(grant: &DockerTargetGrant, summary: &Value) -> bool {
    match &grant.selector {
        DockerTargetSelector::ContainerName { name: expected } => {
            !expected.is_empty()
                && summary
                    .get("Names")
                    .and_then(Value::as_array)
                    .is_some_and(|names| {
                        names
                            .iter()
                            .filter_map(Value::as_str)
                            .any(|name| name.strip_prefix('/').unwrap_or(name) == expected.as_str())
                    })
        }
        DockerTargetSelector::ComposeService { project, service } => {
            if project.is_empty() || service.is_empty() {
                return false;
            }
            let labels = summary.get("Labels").and_then(Value::as_object);
            labels.is_some_and(|labels| {
                labels
                    .get("com.docker.compose.project")
                    .and_then(Value::as_str)
                    == Some(project.as_str())
                    && labels
                        .get("com.docker.compose.service")
                        .and_then(Value::as_str)
                        == Some(service.as_str())
            })
        }
    }
}

fn is_unsafe_target(inspect: &Value) -> bool {
    let host = inspect.get("HostConfig").unwrap_or(&Value::Null);
    if host
        .get("Privileged")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return true;
    }
    for key in [
        "PidMode",
        "IpcMode",
        "NetworkMode",
        "UTSMode",
        "UsernsMode",
        "CgroupnsMode",
    ] {
        if host
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|mode| mode.eq_ignore_ascii_case("host"))
        {
            return true;
        }
    }
    for key in ["Binds", "Devices", "DeviceRequests"] {
        if host
            .get(key)
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty())
        {
            return true;
        }
    }
    if inspect
        .get("Mounts")
        .and_then(Value::as_array)
        .is_some_and(|mounts| {
            mounts.iter().any(|mount| {
                mount
                    .get("Type")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| kind.eq_ignore_ascii_case("bind"))
                    || ["Source", "Destination"]
                        .into_iter()
                        .filter_map(|key| mount.get(key).and_then(Value::as_str))
                        .any(is_runtime_socket_path)
            })
        })
    {
        return true;
    }
    const DANGEROUS_CAPABILITIES: &[&str] = &[
        "SYS_ADMIN",
        "SYS_MODULE",
        "SYS_PTRACE",
        "SYS_RAWIO",
        "DAC_OVERRIDE",
        "DAC_READ_SEARCH",
        "BPF",
        "PERFMON",
        "NET_ADMIN",
        "MKNOD",
    ];
    if host
        .get("CapAdd")
        .and_then(Value::as_array)
        .is_some_and(|caps| {
            caps.iter().filter_map(Value::as_str).any(|capability| {
                let capability = capability.to_ascii_uppercase();
                capability == "ALL" || DANGEROUS_CAPABILITIES.contains(&capability.as_str())
            })
        })
    {
        return true;
    }
    host.get("SecurityOpt")
        .and_then(Value::as_array)
        .is_some_and(|options| {
            options.iter().filter_map(Value::as_str).any(|option| {
                let option = option.to_ascii_lowercase();
                option.contains("seccomp=unconfined")
                    || option.contains("apparmor=unconfined")
                    || option.contains("label=disable")
            })
        })
}

fn is_runtime_socket_path(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    path.ends_with("docker.sock")
        || path.ends_with("podman.sock")
        || path.ends_with("containerd.sock")
        || path.ends_with("containerd/containerd.sock")
}

fn create_private_broker_root() -> Result<PathBuf> {
    create_private_broker_root_in(&crate::zerobox_home().join("tmp").join("docker"))
}

fn create_private_broker_root_in(parent: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    let mut builder = DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(parent)
        .with_context(|| format!("failed to create Docker broker root {}", parent.display()))?;
    std::fs::set_permissions(parent, Permissions::from_mode(0o700))?;
    let parent_metadata = std::fs::symlink_metadata(parent)?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.uid() != unsafe { libc::geteuid() }
    {
        bail!("Docker broker root must be an owner-controlled directory");
    }
    cleanup_stale_broker_dirs_in(parent)?;

    let pid = std::process::id();
    for _ in 0..64 {
        let mut nonce = [0_u8; 8];
        getrandom::fill(&mut nonce).context("failed to generate Docker broker nonce")?;
        let encoded = u64::from_le_bytes(nonce);
        let candidate = parent.join(format!("{RUN_DIR_PREFIX}{pid}-{encoded:016x}"));
        let mut candidate_builder = DirBuilder::new();
        candidate_builder.mode(0o700);
        match candidate_builder.create(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    bail!("failed to allocate a private Docker broker directory")
}

fn cleanup_stale_broker_dirs_in(parent: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    for entry in std::fs::read_dir(parent)? {
        let Ok(entry) = entry else {
            continue;
        };
        let Some(_pid) = owner_pid(&entry.file_name()).filter(|pid| !is_process_alive(*pid)) else {
            continue;
        };
        let Ok(metadata) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            continue;
        }
        let _ = std::fs::remove_dir_all(entry.path());
    }
    Ok(())
}

fn set_private_socket_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, Permissions::from_mode(0o600))
        .with_context(|| format!("failed to secure Docker broker socket {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::str::FromStr;

    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{UnixListener, UnixStream};
    use zerobox_protocol::docker::{
        DockerAccessPolicy, DockerOperation, DockerTargetGrant, DockerTargetSelector,
        UnixSocketPath,
    };

    use super::DockerBroker;

    #[tokio::test]
    async fn full_policy_relays_the_engine_protocol_over_a_private_socket() {
        let root = TempDir::new().unwrap();
        let engine_path = root.path().join("engine.sock");
        let engine = UnixListener::bind(&engine_path).unwrap();
        let engine_task = tokio::spawn(async move {
            let (mut stream, _) = engine.accept().await.unwrap();
            let mut request = vec![0_u8; 512];
            let read = stream.read(&mut request).await.unwrap();
            assert!(String::from_utf8_lossy(&request[..read]).starts_with("GET /_ping HTTP/1.1"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                .await
                .unwrap();
        });
        let policy = DockerAccessPolicy::Full {
            endpoint: UnixSocketPath::from_str(engine_path.to_str().unwrap()).unwrap(),
        };

        let broker = DockerBroker::start(&policy).await.unwrap().unwrap();
        assert_eq!(
            std::fs::metadata(broker.socket_path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let mut client = UnixStream::connect(broker.socket_path()).await.unwrap();
        client
            .write_all(b"GET /_ping HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();

        assert!(response.ends_with(b"\r\n\r\nOK"));
        engine_task.await.unwrap();
    }

    #[tokio::test]
    async fn dropping_the_broker_removes_its_private_socket_tree() {
        let root = TempDir::new().unwrap();
        let engine_path = root.path().join("engine.sock");
        let _engine = UnixListener::bind(&engine_path).unwrap();
        let policy = DockerAccessPolicy::Full {
            endpoint: UnixSocketPath::from_str(engine_path.to_str().unwrap()).unwrap(),
        };
        let broker = DockerBroker::start(&policy).await.unwrap().unwrap();
        let broker_root = broker.socket_path().parent().unwrap().to_path_buf();

        drop(broker);

        assert!(!broker_root.exists());
    }

    #[tokio::test]
    async fn targeted_policy_pins_targets_and_enforces_operations() {
        const CONTAINER_ID: &str =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        let root = TempDir::new().unwrap();
        let engine_path = root.path().join("engine.sock");
        let engine = UnixListener::bind(&engine_path).unwrap();
        let engine_task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = engine.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut request = vec![0_u8; 16 * 1024];
                    let read = stream.read(&mut request).await.unwrap();
                    let first_line = String::from_utf8_lossy(&request[..read])
                        .lines()
                        .next()
                        .unwrap()
                        .to_string();
                    let body = if first_line.contains("/containers/json") {
                        format!(
                            r#"[{{"Id":"{CONTAINER_ID}","Names":["/app-api-1"],"Labels":{{"com.docker.compose.project":"app","com.docker.compose.service":"api"}}}}]"#
                        )
                    } else if first_line.contains(&format!("/containers/{CONTAINER_ID}/json")) {
                        format!(
                            r#"{{"Id":"{CONTAINER_ID}","HostConfig":{{"Privileged":false,"PidMode":"","IpcMode":"","NetworkMode":"default","Binds":[],"Devices":[],"CapAdd":[],"SecurityOpt":[]}},"Mounts":[]}}"#
                        )
                    } else if first_line.contains(&format!("/containers/{CONTAINER_ID}/logs")) {
                        "allowed logs".to_string()
                    } else {
                        r#"{"message":"not found"}"#.to_string()
                    };
                    let status = if body == r#"{"message":"not found"}"# {
                        "404 Not Found"
                    } else {
                        "200 OK"
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                });
            }
        });
        let policy = DockerAccessPolicy::Targeted {
            endpoint: UnixSocketPath::from_str(engine_path.to_str().unwrap()).unwrap(),
            targets: vec![DockerTargetGrant {
                selector: DockerTargetSelector::ComposeService {
                    project: "app".to_string(),
                    service: "api".to_string(),
                },
                operations: Some(vec![DockerOperation::Logs]),
                allow_unsafe_target: false,
            }],
        };

        let broker = DockerBroker::start(&policy).await.unwrap().unwrap();
        let allowed = broker_request(
            broker.socket_path(),
            &format!("GET /v1.52/containers/{CONTAINER_ID}/logs?stdout=1 HTTP/1.1"),
        )
        .await;
        assert!(allowed.starts_with("HTTP/1.1 200"));
        assert!(allowed.ends_with("allowed logs"));

        let forbidden = broker_request(
            broker.socket_path(),
            &format!("GET /v1.52/containers/{CONTAINER_ID}/json HTTP/1.1"),
        )
        .await;
        assert!(forbidden.starts_with("HTTP/1.1 403"));

        let hidden = broker_request(
            broker.socket_path(),
            "GET /v1.52/containers/not-allowed/logs HTTP/1.1",
        )
        .await;
        assert!(hidden.starts_with("HTTP/1.1 404"));

        let discovery = broker_request(
            broker.socket_path(),
            "GET /v1.52/containers/json?all=1 HTTP/1.1",
        )
        .await;
        assert!(discovery.starts_with("HTTP/1.1 200"));
        assert!(discovery.ends_with("[]"));

        engine_task.abort();
    }

    async fn broker_request(socket: &Path, request_line: &str) -> String {
        let mut client = UnixStream::connect(socket).await.unwrap();
        client
            .write_all(
                format!("{request_line}\r\nHost: docker\r\nConnection: close\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        String::from_utf8(response).unwrap()
    }

    #[test]
    fn buffered_engine_responses_decode_chunked_json() {
        let response = super::parse_engine_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n[]\r\n0\r\n\r\n",
        )
        .unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"[]");
    }

    #[test]
    fn unsafe_target_detection_covers_host_escape_surfaces() {
        let safe = serde_json::json!({
            "HostConfig": {
                "Privileged": false,
                "PidMode": "",
                "IpcMode": "private",
                "NetworkMode": "default",
                "Binds": [],
                "Devices": [],
                "DeviceRequests": [],
                "CapAdd": [],
                "SecurityOpt": ["no-new-privileges"]
            },
            "Mounts": []
        });
        assert!(!super::is_unsafe_target(&safe));

        for unsafe_target in [
            serde_json::json!({"HostConfig":{"Privileged":true}}),
            serde_json::json!({"HostConfig":{"NetworkMode":"host"}}),
            serde_json::json!({"HostConfig":{"Binds":["/host:/mnt"]}}),
            serde_json::json!({"HostConfig":{"Devices":[{"PathOnHost":"/dev/kvm"}]}}),
            serde_json::json!({"HostConfig":{"CapAdd":["SYS_ADMIN"]}}),
            serde_json::json!({"HostConfig":{"CapAdd":["ALL"]}}),
            serde_json::json!({"HostConfig":{"SecurityOpt":["seccomp=unconfined"]}}),
            serde_json::json!({"HostConfig":{},"Mounts":[{"Type":"volume","Source":"/var/run/docker.sock"}]}),
        ] {
            assert!(super::is_unsafe_target(&unsafe_target));
        }
    }

    #[test]
    fn exec_routes_require_a_broker_created_exec_id_and_reject_detach() {
        let mut snapshot = super::TargetSnapshot::default();
        snapshot.containers.insert(
            "container-id".to_string(),
            super::AllowedContainer {
                operations: [DockerOperation::Exec].into_iter().collect(),
            },
        );
        snapshot
            .aliases
            .insert("api".to_string(), "container-id".to_string());

        let create = request("POST", "/v1.52/containers/api/exec", br#"{"Cmd":["true"]}"#);
        assert!(matches!(
            super::authorize_request(&snapshot, &create),
            Ok(super::TargetedAction::ExecCreate { .. })
        ));

        let unknown = request("POST", "/v1.52/exec/not-ours/start", b"{}");
        assert_eq!(
            super::authorize_request(&snapshot, &unknown).unwrap_err(),
            super::AuthorizationError::NotFound
        );
        snapshot
            .exec_ids
            .lock()
            .unwrap()
            .insert("ours".to_string(), "container-id".to_string());
        let attached = request("POST", "/v1.52/exec/ours/start", br#"{"Detach":false}"#);
        assert!(matches!(
            super::authorize_request(&snapshot, &attached),
            Ok(super::TargetedAction::ExecStream)
        ));
        let inspect = request("GET", "/v1.52/exec/ours/json", b"");
        assert!(matches!(
            super::authorize_request(&snapshot, &inspect),
            Ok(super::TargetedAction::Forward)
        ));
        let detached = request("POST", "/v1.52/exec/ours/start", br#"{"Detach":true}"#);
        assert_eq!(
            super::authorize_request(&snapshot, &detached).unwrap_err(),
            super::AuthorizationError::Forbidden
        );
    }

    #[test]
    fn targeted_routes_cover_only_the_supported_operation_bundle() {
        let mut snapshot = super::TargetSnapshot::default();
        snapshot.containers.insert(
            "container-id".to_string(),
            super::AllowedContainer {
                operations: DockerOperation::ALL.iter().copied().collect(),
            },
        );
        snapshot
            .aliases
            .insert("api".to_string(), "container-id".to_string());

        for (method, target) in [
            ("GET", "/v1.52/containers/json"),
            ("GET", "/v1.52/containers/api/json"),
            ("GET", "/v1.52/containers/api/logs"),
            ("GET", "/v1.52/containers/api/stats"),
            ("POST", "/v1.52/containers/api/exec"),
            ("POST", "/v1.52/containers/api/start"),
            ("POST", "/v1.52/containers/api/stop"),
            ("POST", "/v1.52/containers/api/restart"),
        ] {
            assert!(
                super::authorize_request(&snapshot, &request(method, target, b"{}")).is_ok(),
                "expected {method} {target} to be authorized"
            );
        }
        for (method, target) in [
            ("POST", "/v1.52/containers/create"),
            ("DELETE", "/v1.52/containers/api"),
            ("GET", "/v1.52/images/json"),
            ("GET", "/v1.52/networks"),
            ("GET", "/v1.52/events"),
        ] {
            assert_eq!(
                super::authorize_request(&snapshot, &request(method, target, b"{}")).unwrap_err(),
                super::AuthorizationError::Forbidden,
                "expected {method} {target} to be forbidden"
            );
        }
    }

    #[tokio::test]
    async fn target_snapshot_ignores_non_success_engine_responses() {
        const CONTAINER_ID: &str =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        let root = TempDir::new().unwrap();
        let engine_path = root.path().join("engine.sock");
        let engine = UnixListener::bind(&engine_path).unwrap();
        let engine_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = engine.accept().await.unwrap();
                let mut request = vec![0_u8; 4096];
                let read = stream.read(&mut request).await.unwrap();
                let first_line = String::from_utf8_lossy(&request[..read])
                    .lines()
                    .next()
                    .unwrap()
                    .to_string();
                let body = if first_line.contains("/containers/json") {
                    format!(r#"[{{"Id":"{CONTAINER_ID}","Names":["/api"]}}]"#)
                } else {
                    r#"{"HostConfig":{},"Mounts":[]}"#.to_string()
                };
                let response = format!(
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let grant = DockerTargetGrant {
            selector: DockerTargetSelector::ContainerName {
                name: "api".to_string(),
            },
            operations: Some(vec![DockerOperation::Logs]),
            allow_unsafe_target: false,
        };

        let snapshot = super::resolve_target_snapshot(&engine_path, &[grant]).await;

        assert!(snapshot.containers.is_empty());
        engine_task.abort();
    }

    #[tokio::test]
    async fn unsafe_snapshot_requires_the_explicit_override_even_with_no_operations() {
        const CONTAINER_ID: &str =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        let root = TempDir::new().unwrap();
        let engine_path = root.path().join("engine.sock");
        let engine = UnixListener::bind(&engine_path).unwrap();
        let engine_task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = engine.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut request = vec![0_u8; 4096];
                    let read = stream.read(&mut request).await.unwrap();
                    let first_line = String::from_utf8_lossy(&request[..read])
                        .lines()
                        .next()
                        .unwrap()
                        .to_string();
                    let body = if first_line.contains("/containers/json") {
                        format!(r#"[{{"Id":"{CONTAINER_ID}","Names":["/api"]}}]"#)
                    } else {
                        r#"{"HostConfig":{"Privileged":true},"Mounts":[]}"#.to_string()
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                });
            }
        });
        let grant = |allow_unsafe_target| DockerTargetGrant {
            selector: DockerTargetSelector::ContainerName {
                name: "api".to_string(),
            },
            operations: Some(Vec::new()),
            allow_unsafe_target,
        };

        let denied = super::resolve_target_snapshot(&engine_path, &[grant(false)]).await;
        let accepted = super::resolve_target_snapshot(&engine_path, &[grant(true)]).await;

        assert!(denied.containers.is_empty());
        assert!(accepted.containers.contains_key(CONTAINER_ID));
        engine_task.abort();
    }

    #[test]
    fn discovery_filters_recreated_and_non_ps_targets() {
        let mut snapshot = super::TargetSnapshot::default();
        snapshot.containers.insert(
            "pinned".to_string(),
            super::AllowedContainer {
                operations: [DockerOperation::Ps].into_iter().collect(),
            },
        );
        snapshot.containers.insert(
            "logs-only".to_string(),
            super::AllowedContainer {
                operations: [DockerOperation::Logs].into_iter().collect(),
            },
        );
        let filtered = super::filter_discovery_response(
            &snapshot,
            br#"[{"Id":"pinned"},{"Id":"logs-only"},{"Id":"replacement"}]"#,
        )
        .unwrap();

        assert_eq!(filtered, br#"[{"Id":"pinned"}]"#);
    }

    #[test]
    fn compose_selector_matches_every_current_replica_exactly() {
        let grant = DockerTargetGrant {
            selector: DockerTargetSelector::ComposeService {
                project: "app".to_string(),
                service: "api".to_string(),
            },
            operations: None,
            allow_unsafe_target: false,
        };
        for id in ["replica-1", "replica-2"] {
            let summary = serde_json::json!({
                "Id": id,
                "Names": [format!("/{id}")],
                "Labels": {
                    "com.docker.compose.project": "app",
                    "com.docker.compose.service": "api"
                }
            });
            assert!(super::grant_matches_summary(&grant, &summary));
        }
        let other = serde_json::json!({
            "Labels": {
                "com.docker.compose.project": "app-dev",
                "com.docker.compose.service": "api"
            }
        });
        assert!(!super::grant_matches_summary(&grant, &other));
    }

    #[test]
    fn broker_janitor_removes_only_dead_owned_run_directories() {
        let root = TempDir::new().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dead = root.path().join(format!("run-{}-dead", libc::pid_t::MAX));
        let alive = root
            .path()
            .join(format!("run-{}-alive", std::process::id()));
        let unrelated = root.path().join("keep-me");
        std::fs::create_dir(&dead).unwrap();
        std::fs::create_dir(&alive).unwrap();
        std::fs::create_dir(&unrelated).unwrap();

        super::cleanup_stale_broker_dirs_in(root.path()).unwrap();

        assert!(!dead.exists());
        assert!(alive.exists());
        assert!(unrelated.exists());
    }

    #[tokio::test]
    async fn targeted_parser_rejects_smuggling_and_oversized_bodies() {
        for raw in [
            b"POST /containers/x/start HTTP/1.1\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n"
                .as_slice(),
            b"POST /containers/x/start HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n"
                .as_slice(),
            b"POST /containers/x/start HTTP/1.1\r\nContent-Length: 1048577\r\n\r\n"
                .as_slice(),
        ] {
            let (mut client, mut broker) = UnixStream::pair().unwrap();
            client.write_all(raw).await.unwrap();
            client.shutdown().await.unwrap();
            assert!(super::read_request(&mut broker).await.is_err());
        }
    }

    fn request(method: &str, target: &str, body: &[u8]) -> super::HttpRequest {
        super::HttpRequest {
            method: method.to_string(),
            target: target.to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![("Host".to_string(), "docker".to_string())],
            body: body.to_vec(),
        }
    }
}
