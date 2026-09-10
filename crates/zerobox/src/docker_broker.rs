use std::collections::{HashMap, HashSet};
use std::fs::{DirBuilder, Permissions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde_json::Value;
use tokio::io::{self, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::task::{JoinHandle, JoinSet};
use zerobox_protocol::docker::{
    DockerAccessPolicy, DockerOperation, DockerTargetGrant, DockerTargetSelector,
};

use crate::process_owner::{RUN_DIR_PREFIX, is_process_alive, owner_pid};

const BROKER_SOCKET_NAME: &str = "broker.sock";
const MAX_REQUEST_HEADER_BYTES: usize = 64 * 1024;
const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
const MAX_BUFFERED_ENGINE_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_CONCURRENT_CONNECTIONS: usize = 64;
const REQUEST_DEADLINE: Duration = Duration::from_secs(10);
const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

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
    inspection_exec_ids: Mutex<HashSet<String>>,
    inspection_roots: HashMap<String, Vec<String>>,
    exec_expiries: HashMap<String, u64>,
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
    #[cfg(any(test, not(target_os = "linux")))]
    pub(crate) async fn start(policy: &DockerAccessPolicy) -> Result<Option<Self>> {
        Self::start_in(policy, &crate::zerobox_home().join("tmp").join("docker")).await
    }

    pub(crate) async fn start_in(
        policy: &DockerAccessPolicy,
        runtime_root: &Path,
    ) -> Result<Option<Self>> {
        let (endpoint, mode) = match policy {
            DockerAccessPolicy::Disabled => return Ok(None),
            DockerAccessPolicy::Full { endpoint } => {
                (endpoint.as_path().to_path_buf(), BrokerMode::Full)
            }
            DockerAccessPolicy::Targeted { endpoint, targets } => {
                let endpoint = endpoint.as_path().to_path_buf();
                let snapshot = resolve_target_snapshot(&endpoint, targets).await?;
                (endpoint, BrokerMode::Targeted(Arc::new(snapshot)))
            }
        };

        let root = create_private_broker_root_in(runtime_root)?;
        let socket_path = root.join(BROKER_SOCKET_NAME);
        let listener = UnixListener::bind(&socket_path)
            .with_context(|| format!("failed to bind Docker broker {}", socket_path.display()))?;
        set_private_socket_permissions(&socket_path)?;

        let task = tokio::spawn(run_broker(
            listener,
            endpoint,
            mode,
            MAX_CONCURRENT_CONNECTIONS,
        ));

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

async fn run_broker(
    listener: UnixListener,
    endpoint: PathBuf,
    mode: BrokerMode,
    max_connections: usize,
) {
    let permits = Arc::new(Semaphore::new(max_connections));
    let mut connections = JoinSet::new();
    loop {
        let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
            break;
        };
        let Ok((mut client, _)) = listener.accept().await else {
            break;
        };
        let endpoint = endpoint.clone();
        let mode = mode.clone();
        connections.spawn(async move {
            let _permit = permit;
            let _ = match mode {
                BrokerMode::Full => relay_full(&mut client, &endpoint).await,
                BrokerMode::Targeted(snapshot) => {
                    handle_targeted_connection(&mut client, &endpoint, &snapshot).await
                }
            };
        });
        while connections.try_join_next().is_some() {}
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
    copy_bidirectional_with_idle_timeout(client, &mut engine, STREAM_IDLE_TIMEOUT).await?;
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
    fn serialize(&self, force_close: bool) -> Result<Vec<u8>> {
        if self.method.is_empty()
            || !self.method.bytes().all(|byte| byte.is_ascii_uppercase())
            || !self.target.starts_with('/')
            || self.target.bytes().any(is_http_control_byte)
            || !matches!(self.version.as_str(), "HTTP/1.0" | "HTTP/1.1")
        {
            bail!("invalid Docker request line");
        }
        if self.headers.iter().any(|(name, value)| {
            name.is_empty()
                || !name.bytes().all(is_header_name_byte)
                || value.bytes().any(is_http_control_byte)
        }) {
            bail!("invalid Docker request header");
        }

        let mut encoded = Vec::new();
        encoded.extend_from_slice(
            format!("{} {} {}\r\n", self.method, self.target, self.version).as_bytes(),
        );
        for (name, value) in &self.headers {
            if name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("transfer-encoding")
                || (force_close
                    && (name.eq_ignore_ascii_case("connection")
                        || name.eq_ignore_ascii_case("upgrade")))
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
        Ok(encoded)
    }
}

#[derive(Debug)]
enum TargetedAction {
    Forward,
    ForwardContainer {
        container_id: String,
    },
    Discovery,
    ExecCreate {
        container_id: String,
        inspection: bool,
    },
    ExecStream,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthorizationError {
    NotFound,
    Forbidden,
    ExecOption(&'static str),
    ExecRestriction(&'static str),
}

async fn handle_targeted_connection(
    client: &mut UnixStream,
    endpoint: &Path,
    snapshot: &TargetSnapshot,
) -> Result<()> {
    handle_targeted_connection_with_timeouts(
        client,
        endpoint,
        snapshot,
        REQUEST_DEADLINE,
        STREAM_IDLE_TIMEOUT,
    )
    .await
}

async fn handle_targeted_connection_with_timeouts(
    client: &mut UnixStream,
    endpoint: &Path,
    snapshot: &TargetSnapshot,
    request_deadline: Duration,
    stream_idle_timeout: Duration,
) -> Result<()> {
    let mut request = match tokio::time::timeout(request_deadline, read_request(client)).await {
        Ok(Ok(request)) => request,
        _ => {
            write_error_with_timeout(client, 400, "malformed Docker request", stream_idle_timeout)
                .await?;
            return Ok(());
        }
    };

    let action = match authorize_request(snapshot, &request) {
        Ok(action) => action,
        Err(AuthorizationError::NotFound) => {
            write_error_with_timeout(
                client,
                404,
                "Docker target is not authorized by this grant or no longer exists",
                stream_idle_timeout,
            )
            .await?;
            return Ok(());
        }
        Err(AuthorizationError::Forbidden) => {
            write_error_with_timeout(
                client,
                403,
                "Docker operation is not granted or route is unsupported",
                stream_idle_timeout,
            )
            .await?;
            return Ok(());
        }
        Err(AuthorizationError::ExecOption(reason)) => {
            write_error_with_timeout(client, 403, reason, stream_idle_timeout).await?;
            return Ok(());
        }
        Err(AuthorizationError::ExecRestriction(reason)) => {
            write_error_with_timeout(client, 403, reason, stream_idle_timeout).await?;
            return Ok(());
        }
    };

    match action {
        TargetedAction::Forward => {
            relay_authorized(client, endpoint, &request, false, stream_idle_timeout).await
        }
        TargetedAction::ForwardContainer { container_id } => {
            request.target = rewrite_container_target(&request.target, &container_id)?;
            relay_authorized(client, endpoint, &request, false, stream_idle_timeout).await
        }
        TargetedAction::ExecStream => {
            relay_authorized(client, endpoint, &request, true, stream_idle_timeout).await
        }
        TargetedAction::Discovery => {
            let raw =
                match engine_request_collect_with_timeout(endpoint, &request, stream_idle_timeout)
                    .await
                {
                    Ok(raw) => raw,
                    Err(_) => {
                        write_error_with_timeout(
                            client,
                            503,
                            "Docker Engine unavailable",
                            stream_idle_timeout,
                        )
                        .await?;
                        return Ok(());
                    }
                };
            let response = match parse_engine_response(&raw) {
                Ok(response) => response,
                Err(_) => {
                    write_error_with_timeout(
                        client,
                        502,
                        "invalid Docker Engine response",
                        stream_idle_timeout,
                    )
                    .await?;
                    return Ok(());
                }
            };
            if !(200..300).contains(&response.status) {
                write_all_with_timeout(client, &raw, stream_idle_timeout).await?;
                return Ok(());
            }
            let body = match filter_discovery_response(snapshot, &response.body) {
                Ok(body) => body,
                Err(_) => {
                    write_error_with_timeout(
                        client,
                        502,
                        "invalid Docker Engine response",
                        stream_idle_timeout,
                    )
                    .await?;
                    return Ok(());
                }
            };
            write_json_with_timeout(client, 200, &body, stream_idle_timeout).await
        }
        TargetedAction::ExecCreate {
            container_id,
            inspection,
        } => {
            if let Err(reason) = validate_exec_body(&request.body, true) {
                write_error_with_timeout(client, 403, reason, stream_idle_timeout).await?;
                return Ok(());
            }
            request.target = rewrite_container_target(&request.target, &container_id)?;
            let raw =
                match engine_request_collect_with_timeout(endpoint, &request, stream_idle_timeout)
                    .await
                {
                    Ok(raw) => raw,
                    Err(_) => {
                        write_error_with_timeout(
                            client,
                            503,
                            "Docker Engine unavailable",
                            stream_idle_timeout,
                        )
                        .await?;
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
                if inspection {
                    snapshot
                        .inspection_exec_ids
                        .lock()
                        .expect("Docker inspection exec registry poisoned")
                        .insert(exec_id.to_string());
                }
            }
            write_all_with_timeout(client, &raw, stream_idle_timeout).await?;
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
        || target.bytes().any(is_http_control_byte)
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
        if value.bytes().any(is_http_control_byte) {
            bail!("invalid Docker header value");
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

fn is_http_control_byte(byte: u8) -> bool {
    byte < b' ' || byte == 0x7f
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
    if segments.len() == 3 && segments[0] == "containers" {
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
        if operation == DockerOperation::Exec {
            let inspection = match ensure_operation(snapshot, container_id, operation) {
                Ok(()) => false,
                Err(AuthorizationError::Forbidden)
                    if snapshot.inspection_roots.contains_key(container_id) =>
                {
                    let roots = &snapshot.inspection_roots[container_id];
                    validate_inspection_exec_body(&request.body, roots)
                        .map_err(AuthorizationError::ExecRestriction)?;
                    true
                }
                Err(error) => return Err(error),
            };
            return Ok(TargetedAction::ExecCreate {
                container_id: container_id.clone(),
                inspection,
            });
        }
        ensure_operation(snapshot, container_id, operation)?;
        return Ok(TargetedAction::ForwardContainer {
            container_id: container_id.clone(),
        });
    }

    if segments.len() == 3 && segments[0] == "exec" {
        let container_id = snapshot
            .exec_ids
            .lock()
            .expect("Docker exec registry poisoned")
            .get(&segments[1])
            .cloned()
            .ok_or(AuthorizationError::NotFound)?;
        let inspection = snapshot
            .inspection_exec_ids
            .lock()
            .expect("Docker inspection exec registry poisoned")
            .contains(&segments[1]);
        let permitted = matches!(
            (request.method.as_str(), segments[2].as_str()),
            ("POST", "start" | "resize") | ("GET", "json")
        ) && (!inspection || segments[2] != "resize");
        if !permitted {
            return Err(AuthorizationError::Forbidden);
        }
        if !inspection {
            ensure_operation(snapshot, &container_id, DockerOperation::Exec)?;
        }
        if segments[2] == "start" {
            validate_exec_body(&request.body, false).map_err(AuthorizationError::ExecOption)?;
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

fn rewrite_container_target(target: &str, container_id: &str) -> Result<String> {
    let (path, query) = target
        .split_once('?')
        .map_or((target, None), |(path, query)| (path, Some(query)));
    let route = strip_api_version(path);
    let prefix = &path[..path.len() - route.len()];
    let segments = decode_path_segments(route)
        .map_err(|_| anyhow::anyhow!("invalid Docker container route"))?;
    if segments.len() != 3 || segments[0] != "containers" {
        bail!("invalid Docker container route");
    }
    let mut rewritten = format!("{prefix}/containers/{container_id}/{}", segments[2]);
    if let Some(query) = query {
        rewritten.push('?');
        rewritten.push_str(query);
    }
    Ok(rewritten)
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
        if operation == DockerOperation::Exec
            && snapshot
                .exec_expiries
                .get(container_id)
                .is_some_and(|expiry| current_unix_time_ms().is_none_or(|now| now >= *expiry))
        {
            return Err(AuthorizationError::ExecRestriction(
                "Docker break-glass exec expired",
            ));
        }
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

fn validate_exec_body(body: &[u8], creating: bool) -> std::result::Result<(), &'static str> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| "Docker exec option forbidden: invalid request body")?;
    if !value.is_object() {
        return Err("Docker exec option forbidden: invalid request body");
    }
    for (field, reason) in [
        (
            "Privileged",
            "Docker exec option forbidden: privileged execution is not allowed",
        ),
        (
            "Detach",
            "Docker exec option forbidden: detached execution is not allowed",
        ),
    ] {
        if value
            .get(field)
            .is_some_and(|option| !option.is_null() && option.as_bool() != Some(false))
        {
            return Err(reason);
        }
    }
    if creating
        && value
            .get("DetachKeys")
            .is_some_and(|keys| !keys.is_null() && keys.as_str() != Some(""))
    {
        return Err("Docker exec option forbidden: DetachKeys must be empty");
    }
    Ok(())
}

fn validate_inspection_exec_body(
    body: &[u8],
    roots: &[String],
) -> std::result::Result<(), &'static str> {
    const RESTRICTED: &str =
        "Docker exec is restricted to read-only inspection for this host-access target";
    validate_exec_body(body, true)?;
    let value: Value = serde_json::from_slice(body).map_err(|_| RESTRICTED)?;
    let options = value.as_object().ok_or(RESTRICTED)?;
    const KNOWN_FIELDS: [&str; 12] = [
        "AttachStderr",
        "AttachStdin",
        "AttachStdout",
        "Cmd",
        "ConsoleSize",
        "Detach",
        "DetachKeys",
        "Env",
        "Privileged",
        "Tty",
        "User",
        "WorkingDir",
    ];
    if options
        .keys()
        .any(|field| !KNOWN_FIELDS.contains(&field.as_str()))
        || options.get("Env").is_some_and(|env| {
            !env.is_null() && env.as_array().is_none_or(|entries| !entries.is_empty())
        })
        || ["User", "WorkingDir"].iter().any(|field| {
            options
                .get(*field)
                .is_some_and(|option| !option.is_null() && option.as_str() != Some(""))
        })
    {
        return Err(RESTRICTED);
    }
    let command = value
        .get("Cmd")
        .and_then(Value::as_array)
        .ok_or(RESTRICTED)?;
    let command: Vec<&str> = command
        .iter()
        .map(Value::as_str)
        .collect::<Option<Vec<_>>>()
        .ok_or(RESTRICTED)?;
    let path = match command.as_slice() {
        ["test", "-r", path] => *path,
        ["stat", "--", path] => *path,
        ["ls", "-la", "--", path] => *path,
        _ => return Err(RESTRICTED),
    };
    if roots.iter().any(|root| path_is_within(path, root)) {
        Ok(())
    } else {
        Err(RESTRICTED)
    }
}

fn path_is_within(path: &str, root: &str) -> bool {
    use std::path::Component;

    let path = Path::new(path);
    let root = Path::new(root);
    path.is_absolute()
        && root.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        && (path == root || path.starts_with(root))
}

async fn relay_authorized(
    client: &mut UnixStream,
    endpoint: &Path,
    request: &HttpRequest,
    bidirectional: bool,
    stream_idle_timeout: Duration,
) -> Result<()> {
    let mut engine = match UnixStream::connect(endpoint).await {
        Ok(engine) => engine,
        Err(_) => {
            write_error_with_timeout(
                client,
                503,
                "Docker Engine unavailable",
                stream_idle_timeout,
            )
            .await?;
            return Ok(());
        }
    };
    if bidirectional {
        return relay_exec_stream(client, &mut engine, request, stream_idle_timeout).await;
    }
    write_all_with_timeout(&mut engine, &request.serialize(true)?, REQUEST_DEADLINE).await?;
    copy_with_idle_timeout(&mut engine, client, stream_idle_timeout).await?;
    Ok(())
}

async fn relay_exec_stream(
    client: &mut UnixStream,
    engine: &mut UnixStream,
    request: &HttpRequest,
    stream_idle_timeout: Duration,
) -> Result<()> {
    write_all_with_timeout(engine, &request.serialize(false)?, REQUEST_DEADLINE).await?;
    let prefix = match read_engine_response_prefix(engine, stream_idle_timeout).await {
        Ok(prefix) => prefix,
        Err(_) => {
            write_error_with_timeout(
                client,
                502,
                "invalid Docker Engine response",
                stream_idle_timeout,
            )
            .await?;
            return Ok(());
        }
    };
    let upgrade = match inspect_engine_response_head(&prefix) {
        Ok(head) => head,
        Err(_) => {
            write_error_with_timeout(
                client,
                502,
                "invalid Docker Engine response",
                stream_idle_timeout,
            )
            .await?;
            return Ok(());
        }
    };
    if upgrade.status == 101 && upgrade.connection_upgrade && upgrade.upgrade_tcp {
        write_all_with_timeout(client, &prefix, stream_idle_timeout).await?;
        copy_bidirectional_with_idle_timeout(client, engine, stream_idle_timeout).await?;
        return Ok(());
    }

    let response =
        match collect_engine_response(engine, prefix, &upgrade, stream_idle_timeout).await {
            Ok(response) => response,
            Err(_) => {
                write_error_with_timeout(
                    client,
                    502,
                    "invalid Docker Engine response",
                    stream_idle_timeout,
                )
                .await?;
                return Ok(());
            }
        };
    write_all_with_timeout(client, &response, stream_idle_timeout).await?;
    tokio::time::timeout(stream_idle_timeout, client.shutdown())
        .await
        .context("Docker stream idle timeout")??;
    Ok(())
}

async fn copy_with_idle_timeout(
    reader: &mut UnixStream,
    writer: &mut UnixStream,
    stream_idle_timeout: Duration,
) -> Result<()> {
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = tokio::time::timeout(stream_idle_timeout, reader.read(&mut buffer))
            .await
            .context("Docker stream idle timeout")??;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        write_all_with_timeout(writer, &buffer[..read], stream_idle_timeout).await?;
    }
}

async fn copy_bidirectional_with_idle_timeout(
    left: &mut UnixStream,
    right: &mut UnixStream,
    stream_idle_timeout: Duration,
) -> Result<()> {
    let (mut left_read, mut left_write) = io::split(left);
    let (mut right_read, mut right_write) = io::split(right);
    let mut left_buffer = [0_u8; 16 * 1024];
    let mut right_buffer = [0_u8; 16 * 1024];
    let mut left_eof = false;
    let mut right_eof = false;
    loop {
        if left_eof && right_eof {
            return Ok(());
        }
        tokio::select! {
            read = left_read.read(&mut left_buffer), if !left_eof => {
                let read = read?;
                if read == 0 {
                    left_eof = true;
                    right_write.shutdown().await?;
                } else {
                    write_all_with_timeout(&mut right_write, &left_buffer[..read], stream_idle_timeout).await?;
                }
            }
            read = right_read.read(&mut right_buffer), if !right_eof => {
                let read = read?;
                if read == 0 {
                    right_eof = true;
                    left_write.shutdown().await?;
                } else {
                    write_all_with_timeout(&mut left_write, &right_buffer[..read], stream_idle_timeout).await?;
                }
            }
            _ = tokio::time::sleep(stream_idle_timeout) => {
                bail!("Docker stream idle timeout");
            }
        }
    }
}

async fn write_all_with_timeout<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
    timeout: Duration,
) -> Result<()> {
    tokio::time::timeout(timeout, writer.write_all(bytes))
        .await
        .context("Docker stream idle timeout")??;
    Ok(())
}

#[derive(Debug)]
struct EngineResponseHead {
    status: u16,
    header_end: usize,
    content_length: Option<usize>,
    chunked: bool,
    connection_upgrade: bool,
    upgrade_tcp: bool,
}

async fn read_engine_response_prefix(
    engine: &mut UnixStream,
    stream_idle_timeout: Duration,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(4096);
    loop {
        if find_bytes(&bytes, b"\r\n\r\n").is_some() {
            return Ok(bytes);
        }
        if bytes.len() >= MAX_REQUEST_HEADER_BYTES {
            bail!("Docker Engine response headers are too large");
        }
        let mut chunk = [0_u8; 4096];
        let read = tokio::time::timeout(stream_idle_timeout, engine.read(&mut chunk))
            .await
            .context("Docker Engine response timed out")??;
        if read == 0 {
            bail!("Docker Engine response ended before its headers");
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
}

fn inspect_engine_response_head(raw: &[u8]) -> Result<EngineResponseHead> {
    let header_end = find_bytes(raw, b"\r\n\r\n")
        .map(|index| index + 4)
        .context("missing Docker response headers")?;
    if header_end > MAX_REQUEST_HEADER_BYTES {
        bail!("Docker Engine response headers are too large");
    }
    let head = std::str::from_utf8(&raw[..header_end - 4])?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().context("missing Docker response status")?;
    let mut status_parts = status_line.split_whitespace();
    let version = status_parts.next().unwrap_or_default();
    let status = status_parts
        .next()
        .context("missing Docker response status")?
        .parse::<u16>()?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        bail!("invalid Docker response version");
    }

    let mut content_length = None;
    let mut chunked = false;
    let mut connection_upgrade = false;
    let mut upgrade_tcp = false;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .context("invalid Docker response header")?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                bail!("duplicate Docker response content length");
            }
            content_length = Some(value.parse::<usize>()?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked {
                bail!("duplicate Docker response transfer encoding");
            }
            chunked = value
                .split(',')
                .any(|coding| coding.trim().eq_ignore_ascii_case("chunked"));
            if !chunked {
                bail!("unsupported Docker response transfer encoding");
            }
        } else if name.eq_ignore_ascii_case("connection") {
            connection_upgrade |= value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
        } else if name.eq_ignore_ascii_case("upgrade") {
            upgrade_tcp |= value.eq_ignore_ascii_case("tcp");
        }
    }
    if chunked && content_length.is_some() {
        bail!("ambiguous Docker response framing");
    }
    if content_length.unwrap_or(0) > MAX_BUFFERED_ENGINE_RESPONSE_BYTES {
        bail!("Docker Engine response is too large");
    }
    Ok(EngineResponseHead {
        status,
        header_end,
        content_length,
        chunked,
        connection_upgrade,
        upgrade_tcp,
    })
}

async fn collect_engine_response(
    engine: &mut UnixStream,
    mut bytes: Vec<u8>,
    head: &EngineResponseHead,
    stream_idle_timeout: Duration,
) -> Result<Vec<u8>> {
    if let Some(content_length) = head.content_length {
        let expected = head
            .header_end
            .checked_add(content_length)
            .context("Docker response length overflow")?;
        if bytes.len() > expected {
            bail!("pipelined Docker Engine response");
        }
        while bytes.len() < expected {
            read_engine_response_chunk(engine, &mut bytes, stream_idle_timeout).await?;
        }
        return Ok(bytes);
    }
    if head.chunked {
        loop {
            if let Some(end) = chunked_message_end(&bytes[head.header_end..])? {
                let expected = head.header_end + end;
                if bytes.len() != expected {
                    bail!("pipelined Docker Engine response");
                }
                return Ok(bytes);
            }
            read_engine_response_chunk(engine, &mut bytes, stream_idle_timeout).await?;
        }
    }
    if (100..200).contains(&head.status) || matches!(head.status, 204 | 304) {
        if bytes.len() != head.header_end {
            bail!("unexpected Docker Engine response body");
        }
        return Ok(bytes);
    }

    loop {
        let mut chunk = [0_u8; 8192];
        let read = tokio::time::timeout(stream_idle_timeout, engine.read(&mut chunk))
            .await
            .context("Docker Engine response timed out")??;
        if read == 0 {
            return Ok(bytes);
        }
        if bytes.len() + read > MAX_BUFFERED_ENGINE_RESPONSE_BYTES {
            bail!("Docker Engine response is too large");
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
}

async fn read_engine_response_chunk(
    engine: &mut UnixStream,
    bytes: &mut Vec<u8>,
    stream_idle_timeout: Duration,
) -> Result<()> {
    let mut chunk = [0_u8; 8192];
    let read = tokio::time::timeout(stream_idle_timeout, engine.read(&mut chunk))
        .await
        .context("Docker Engine response timed out")??;
    if read == 0 {
        bail!("Docker Engine response ended early");
    }
    if bytes.len() + read > MAX_BUFFERED_ENGINE_RESPONSE_BYTES {
        bail!("Docker Engine response is too large");
    }
    bytes.extend_from_slice(&chunk[..read]);
    Ok(())
}

fn chunked_message_end(encoded: &[u8]) -> Result<Option<usize>> {
    let mut offset = 0;
    loop {
        let Some(relative_line_end) = find_bytes(&encoded[offset..], b"\r\n") else {
            return Ok(None);
        };
        let line_end = offset + relative_line_end;
        let size_line = std::str::from_utf8(&encoded[offset..line_end])?;
        let size =
            usize::from_str_radix(size_line.split(';').next().unwrap_or_default().trim(), 16)?;
        offset = line_end + 2;
        if size == 0 {
            if encoded[offset..].starts_with(b"\r\n") {
                return Ok(Some(offset + 2));
            }
            let Some(trailer_end) = find_bytes(&encoded[offset..], b"\r\n\r\n") else {
                return Ok(None);
            };
            return Ok(Some(offset + trailer_end + 4));
        }
        let Some(chunk_end) = offset.checked_add(size) else {
            bail!("Docker response chunk overflow");
        };
        if chunk_end + 2 > encoded.len() {
            return Ok(None);
        }
        if &encoded[chunk_end..chunk_end + 2] != b"\r\n" {
            bail!("invalid Docker response chunk");
        }
        offset = chunk_end + 2;
    }
}

async fn engine_request_collect(endpoint: &Path, request: &HttpRequest) -> Result<Vec<u8>> {
    engine_request_collect_with_timeout(endpoint, request, STREAM_IDLE_TIMEOUT).await
}

async fn engine_request_collect_with_timeout(
    endpoint: &Path,
    request: &HttpRequest,
    stream_idle_timeout: Duration,
) -> Result<Vec<u8>> {
    let mut engine = UnixStream::connect(endpoint)
        .await
        .context("Docker Engine is unavailable")?;
    write_all_with_timeout(&mut engine, &request.serialize(true)?, REQUEST_DEADLINE).await?;
    let mut response = Vec::new();
    loop {
        let mut chunk = [0_u8; 8192];
        let read = tokio::time::timeout(stream_idle_timeout, engine.read(&mut chunk))
            .await
            .context("Docker Engine response timed out")??;
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

async fn write_error_with_timeout(
    stream: &mut UnixStream,
    status: u16,
    message: &str,
    stream_idle_timeout: Duration,
) -> Result<()> {
    let body = serde_json::to_vec(&serde_json::json!({ "message": message }))?;
    write_json_with_timeout(stream, status, &body, stream_idle_timeout).await
}

async fn write_json_with_timeout(
    stream: &mut UnixStream,
    status: u16,
    body: &[u8],
    stream_idle_timeout: Duration,
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    write_all_with_timeout(stream, head.as_bytes(), stream_idle_timeout).await?;
    write_all_with_timeout(stream, body, stream_idle_timeout).await?;
    tokio::time::timeout(stream_idle_timeout, stream.shutdown())
        .await
        .context("Docker stream idle timeout")??;
    Ok(())
}

async fn resolve_target_snapshot(
    endpoint: &Path,
    grants: &[DockerTargetGrant],
) -> Result<TargetSnapshot> {
    let request = synthetic_get("/containers/json?all=1");
    let raw = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        engine_request_collect(endpoint, &request),
    )
    .await
    .context("Docker target snapshot timed out")?
    .context("Docker target snapshot request failed")?;
    let response =
        parse_engine_response(&raw).context("invalid Docker target snapshot response")?;
    if !(200..300).contains(&response.status) {
        bail!(
            "Docker target snapshot failed with Engine status {}",
            response.status
        );
    }
    let summaries = serde_json::from_slice::<Vec<Value>>(&response.body)
        .context("invalid Docker target snapshot payload")?;

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
        let inspection_requested = eligible_grants.iter().any(|grant| {
            grant.allow_unsafe_target
                && !matches!(
                    grant.selector,
                    DockerTargetSelector::EphemeralContainer { .. }
                )
                && grant
                    .effective_operations()
                    .contains(&DockerOperation::Exec)
        });
        let persistent_exec = eligible_grants.iter().any(|grant| {
            !grant.allow_unsafe_target
                && !matches!(
                    grant.selector,
                    DockerTargetSelector::EphemeralContainer { .. }
                )
                && grant
                    .effective_operations()
                    .contains(&DockerOperation::Exec)
        });
        let ephemeral_exec_expiry = eligible_grants
            .iter()
            .filter_map(|grant| match &grant.selector {
                DockerTargetSelector::EphemeralContainer {
                    unsafe_exec_expires_at_ms,
                    ..
                } if grant
                    .effective_operations()
                    .contains(&DockerOperation::Exec) =>
                {
                    Some(*unsafe_exec_expires_at_ms)
                }
                _ => None,
            })
            .max();
        let operations: HashSet<DockerOperation> = eligible_grants
            .into_iter()
            .flat_map(|grant| {
                grant
                    .effective_operations()
                    .iter()
                    .copied()
                    .filter(|operation| {
                        *operation != DockerOperation::Exec
                            || !grant.allow_unsafe_target
                            || matches!(
                                grant.selector,
                                DockerTargetSelector::EphemeralContainer { .. }
                            )
                    })
            })
            .collect();

        snapshot
            .containers
            .insert(id.to_string(), AllowedContainer { operations });
        if inspection_requested {
            snapshot
                .inspection_roots
                .insert(id.to_string(), bind_mount_destinations(&inspect));
        }
        if !persistent_exec && let Some(expiry) = ephemeral_exec_expiry {
            snapshot.exec_expiries.insert(id.to_string(), expiry);
        }
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
    Ok(snapshot)
}

fn bind_mount_destinations(inspect: &Value) -> Vec<String> {
    let mut destinations: Vec<String> = inspect
        .get("Mounts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|mount| mount.get("Type").and_then(Value::as_str) == Some("bind"))
        .filter_map(|mount| mount.get("Destination").and_then(Value::as_str))
        .filter(|destination| {
            let path = Path::new(destination);
            path.is_absolute()
                && !path
                    .components()
                    .any(|component| matches!(component, std::path::Component::ParentDir))
        })
        .map(ToOwned::to_owned)
        .collect();
    destinations.sort();
    destinations.dedup();
    destinations
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
        DockerTargetSelector::EphemeralContainer { id, .. } => {
            summary.get("Id").and_then(Value::as_str) == Some(id.as_str())
        }
    }
}

fn current_unix_time_ms() -> Option<u64> {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_millis(),
    )
    .ok()
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
        if host.get(key).and_then(Value::as_str).is_some_and(|mode| {
            mode.eq_ignore_ascii_case("host")
                || mode
                    .split_once(':')
                    .is_some_and(|(kind, _)| kind.eq_ignore_ascii_case("container"))
        }) {
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
    use std::sync::Arc;
    use std::time::Duration;

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
    async fn broker_connection_limit_releases_capacity_after_cleanup() {
        let root = TempDir::new().unwrap();
        let broker_path = root.path().join("broker.sock");
        let engine_path = root.path().join("engine.sock");
        let listener = UnixListener::bind(&broker_path).unwrap();
        let engine = UnixListener::bind(&engine_path).unwrap();
        let broker_task = tokio::spawn(super::run_broker(
            listener,
            engine_path,
            super::BrokerMode::Full,
            1,
        ));

        let first_client = UnixStream::connect(&broker_path).await.unwrap();
        let (first_engine, _) = tokio::time::timeout(Duration::from_secs(1), engine.accept())
            .await
            .unwrap()
            .unwrap();
        let _second_client = UnixStream::connect(&broker_path).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), engine.accept())
                .await
                .is_err(),
            "a saturated broker started an extra Engine connection"
        );

        drop(first_client);
        drop(first_engine);
        let _second_engine = tokio::time::timeout(Duration::from_secs(1), engine.accept())
            .await
            .unwrap()
            .unwrap();
        broker_task.abort();
    }

    #[tokio::test]
    async fn targeted_header_read_has_a_deadline() {
        let root = TempDir::new().unwrap();
        let engine_path = root.path().join("engine.sock");
        let _engine = UnixListener::bind(&engine_path).unwrap();
        let (mut client, mut broker_side) = UnixStream::pair().unwrap();
        let snapshot = super::TargetSnapshot::default();
        client
            .write_all(b"GET /_ping HTTP/1.1\r\nHost:")
            .await
            .unwrap();

        super::handle_targeted_connection_with_timeouts(
            &mut broker_side,
            &engine_path,
            &snapshot,
            Duration::from_millis(25),
            super::STREAM_IDLE_TIMEOUT,
        )
        .await
        .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();

        assert!(response.starts_with(b"HTTP/1.1 400"));
    }

    #[tokio::test]
    async fn targeted_engine_body_stall_releases_the_connection() {
        let root = TempDir::new().unwrap();
        let engine_path = root.path().join("engine.sock");
        let engine = UnixListener::bind(&engine_path).unwrap();
        let engine_task = tokio::spawn(async move {
            let (mut stream, _) = engine.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nO")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });

        let mut snapshot = super::TargetSnapshot::default();
        snapshot.containers.insert(
            "container-id".to_string(),
            super::AllowedContainer {
                operations: [DockerOperation::Exec].into_iter().collect(),
            },
        );
        snapshot
            .exec_ids
            .lock()
            .unwrap()
            .insert("ours".to_string(), "container-id".to_string());
        let (mut client, mut broker_side) = UnixStream::pair().unwrap();
        client
            .write_all(
                b"POST /v1.52/exec/ours/start HTTP/1.1\r\nHost: docker\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n{\"Detach\":false}",
            )
            .await
            .unwrap();

        tokio::time::timeout(
            Duration::from_millis(250),
            super::handle_targeted_connection_with_timeouts(
                &mut broker_side,
                &engine_path,
                &snapshot,
                Duration::from_secs(1),
                Duration::from_millis(25),
            ),
        )
        .await
        .expect("stalled Engine body must not retain a broker permit")
        .unwrap();

        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 502"));
        engine_task.abort();
    }

    #[tokio::test]
    async fn targeted_client_write_stall_releases_the_connection() {
        let root = TempDir::new().unwrap();
        let engine_path = root.path().join("engine.sock");
        let engine = UnixListener::bind(&engine_path).unwrap();
        let engine_task = tokio::spawn(async move {
            let (mut stream, _) = engine.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            let body = vec![b'x'; 4 * 1024 * 1024];
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            stream.write_all(&body).await.unwrap();
        });

        let snapshot = super::TargetSnapshot::default();
        let (mut client, mut broker_side) = UnixStream::pair().unwrap();
        client
            .write_all(
                b"GET /v1.52/containers/json HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();

        tokio::time::timeout(
            Duration::from_millis(500),
            super::handle_targeted_connection_with_timeouts(
                &mut broker_side,
                &engine_path,
                &snapshot,
                Duration::from_secs(1),
                Duration::from_millis(25),
            ),
        )
        .await
        .expect("stalled client write must not retain a broker permit")
        .expect_err("the stalled client write must time out");

        drop(client);
        engine_task.await.unwrap();
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

    #[tokio::test]
    async fn targeted_non_streaming_routes_cannot_be_promoted_to_a_tunnel() {
        let root = TempDir::new().unwrap();
        let engine_path = root.path().join("engine.sock");
        let engine = UnixListener::bind(&engine_path).unwrap();
        let engine_task = tokio::spawn(async move {
            let (mut stream, _) = engine.accept().await.unwrap();
            let mut first = vec![0_u8; 4096];
            let first_len = stream.read(&mut first).await.unwrap();
            first.truncate(first_len);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK",
                )
                .await
                .unwrap();
            let mut second = vec![0_u8; 4096];
            let second_len =
                tokio::time::timeout(Duration::from_millis(300), stream.read(&mut second))
                    .await
                    .ok()
                    .transpose()
                    .unwrap()
                    .unwrap_or(0);
            second.truncate(second_len);
            (first, second)
        });

        let (mut client, mut broker_side) = UnixStream::pair().unwrap();
        let snapshot = Arc::new(super::TargetSnapshot::default());
        let handler = tokio::spawn({
            let endpoint = engine_path.clone();
            let snapshot = Arc::clone(&snapshot);
            async move {
                super::handle_targeted_connection(&mut broker_side, &endpoint, &snapshot)
                    .await
                    .unwrap();
            }
        });

        client
            .write_all(
                b"GET /_ping HTTP/1.1\r\nHost: docker\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = [0_u8; 512];
        let response_len = tokio::time::timeout(Duration::from_secs(1), client.read(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response[..response_len].ends_with(b"\r\n\r\nOK"));
        let _ = client
            .write_all(
                b"POST /containers/create HTTP/1.1\r\nHost: docker\r\nContent-Length: 0\r\n\r\n",
            )
            .await;
        let _ = client.shutdown().await;

        let (first, second) = engine_task.await.unwrap();
        let first = String::from_utf8(first).unwrap();
        assert!(first.contains("Connection: close\r\n"));
        assert!(!first.to_ascii_lowercase().contains("upgrade:"));
        assert!(
            second.is_empty(),
            "a second Docker request crossed the broker"
        );
        handler.await.unwrap();
    }

    #[tokio::test]
    async fn rejected_exec_streams_do_not_become_docker_tunnels() {
        let root = TempDir::new().unwrap();
        let engine_path = root.path().join("engine.sock");
        let engine = UnixListener::bind(&engine_path).unwrap();
        let engine_task = tokio::spawn(async move {
            let (mut stream, _) = engine.accept().await.unwrap();
            let mut first = vec![0_u8; 4096];
            let first_len = stream.read(&mut first).await.unwrap();
            first.truncate(first_len);
            stream
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\nConnection: keep-alive\r\n\r\ndenied",
                )
                .await
                .unwrap();
            let mut second = vec![0_u8; 4096];
            let second_len =
                tokio::time::timeout(Duration::from_millis(300), stream.read(&mut second))
                    .await
                    .ok()
                    .transpose()
                    .unwrap()
                    .unwrap_or(0);
            second.truncate(second_len);
            (first, second)
        });

        let mut snapshot = super::TargetSnapshot::default();
        snapshot.containers.insert(
            "container-id".to_string(),
            super::AllowedContainer {
                operations: [DockerOperation::Exec].into_iter().collect(),
            },
        );
        snapshot
            .exec_ids
            .lock()
            .unwrap()
            .insert("ours".to_string(), "container-id".to_string());
        let snapshot = Arc::new(snapshot);
        let (mut client, mut broker_side) = UnixStream::pair().unwrap();
        let handler = tokio::spawn({
            let endpoint = engine_path.clone();
            let snapshot = Arc::clone(&snapshot);
            async move {
                super::handle_targeted_connection(&mut broker_side, &endpoint, &snapshot)
                    .await
                    .unwrap();
            }
        });

        client
            .write_all(
                b"POST /v1.52/exec/ours/start HTTP/1.1\r\nHost: docker\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n{\"Detach\":false}",
            )
            .await
            .unwrap();
        let mut response = [0_u8; 512];
        let response_len = tokio::time::timeout(Duration::from_secs(1), client.read(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response[..response_len].starts_with(b"HTTP/1.1 403"));
        let _ = client
            .write_all(
                b"POST /containers/create HTTP/1.1\r\nHost: docker\r\nContent-Length: 0\r\n\r\n",
            )
            .await;
        let _ = client.shutdown().await;

        let (first, second) = engine_task.await.unwrap();
        assert!(
            String::from_utf8(first)
                .unwrap()
                .contains("/exec/ours/start")
        );
        assert!(
            second.is_empty(),
            "a rejected exec exposed the Docker tunnel"
        );
        handler.await.unwrap();
    }

    #[tokio::test]
    async fn authorized_exec_streams_require_a_valid_engine_upgrade() {
        let root = TempDir::new().unwrap();
        let engine_path = root.path().join("engine.sock");
        let engine = UnixListener::bind(&engine_path).unwrap();
        let engine_task = tokio::spawn(async move {
            let (mut stream, _) = engine.accept().await.unwrap();
            let mut request = vec![0_u8; 4096];
            let request_len = stream.read(&mut request).await.unwrap();
            assert!(String::from_utf8_lossy(&request[..request_len]).contains("/exec/ours/start"));
            stream
                .write_all(
                    b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\nengine-ready",
                )
                .await
                .unwrap();
            let mut client_bytes = [0_u8; 11];
            stream.read_exact(&mut client_bytes).await.unwrap();
            assert_eq!(&client_bytes, b"client-data");
            stream.write_all(b"engine-data").await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let mut snapshot = super::TargetSnapshot::default();
        snapshot.containers.insert(
            "container-id".to_string(),
            super::AllowedContainer {
                operations: [DockerOperation::Exec].into_iter().collect(),
            },
        );
        snapshot
            .exec_ids
            .lock()
            .unwrap()
            .insert("ours".to_string(), "container-id".to_string());
        let snapshot = Arc::new(snapshot);
        let (mut client, mut broker_side) = UnixStream::pair().unwrap();
        let handler = tokio::spawn({
            let endpoint = engine_path.clone();
            let snapshot = Arc::clone(&snapshot);
            async move {
                super::handle_targeted_connection(&mut broker_side, &endpoint, &snapshot)
                    .await
                    .unwrap();
            }
        });

        client
            .write_all(
                b"POST /v1.52/exec/ours/start HTTP/1.1\r\nHost: docker\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n{\"Detach\":false}",
            )
            .await
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(1), async {
            let mut response = Vec::new();
            while !response.ends_with(b"engine-ready") {
                let mut chunk = [0_u8; 256];
                let read = client.read(&mut chunk).await.unwrap();
                assert_ne!(read, 0, "exec upgrade ended before its first stream bytes");
                response.extend_from_slice(&chunk[..read]);
            }
            response
        })
        .await
        .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 101 UPGRADED"));
        assert!(response.ends_with(b"engine-ready"));
        client.write_all(b"client-data").await.unwrap();
        let mut engine_bytes = [0_u8; 11];
        client.read_exact(&mut engine_bytes).await.unwrap();
        assert_eq!(&engine_bytes, b"engine-data");
        client.shutdown().await.unwrap();

        engine_task.await.unwrap();
        handler.await.unwrap();
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
            serde_json::json!({"HostConfig":{"NetworkMode":"container:hostnet"}}),
            serde_json::json!({"HostConfig":{"PidMode":"container:hostpid"}}),
            serde_json::json!({"HostConfig":{"IpcMode":"container:hostipc"}}),
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
        assert!(
            super::validate_exec_body(br#"{"Cmd":["true"],"DetachKeys":"ctrl-x"}"#, true).is_err()
        );
        for body in [
            br#"{"DetachKeys":true}"#.as_slice(),
            br#"{"DetachKeys":[]}"#.as_slice(),
            br#"{"Privileged":true}"#.as_slice(),
            br#"{"Detach":true}"#.as_slice(),
        ] {
            assert!(super::validate_exec_body(body, true).is_err());
        }

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
            super::AuthorizationError::ExecOption(
                "Docker exec option forbidden: detached execution is not allowed"
            )
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

    #[test]
    fn targeted_routes_require_exact_path_shapes() {
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
        snapshot
            .exec_ids
            .lock()
            .unwrap()
            .insert("ours".to_string(), "container-id".to_string());

        for (method, target, body) in [
            ("GET", "/v1.52/containers/api/json/suffix", b"".as_slice()),
            ("GET", "/v1.52/containers/api/json/", b"".as_slice()),
            (
                "GET",
                "/v1.52/containers/api/%6a%73%6f%6e/suffix",
                b"".as_slice(),
            ),
            (
                "POST",
                "/v1.52/exec/ours/start/suffix",
                br#"{"Detach":false}"#.as_slice(),
            ),
            ("GET", "/v1.52/exec/ours/json/suffix", b"".as_slice()),
        ] {
            assert_eq!(
                super::authorize_request(&snapshot, &request(method, target, body)).unwrap_err(),
                super::AuthorizationError::Forbidden,
                "expected exact route rejection for {method} {target}"
            );
        }
    }

    #[tokio::test]
    async fn targeted_broker_fails_closed_when_snapshot_discovery_fails() {
        const CONTAINER_ID: &str =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        let root = TempDir::new().unwrap();
        let engine_path = root.path().join("engine.sock");
        let engine = UnixListener::bind(&engine_path).unwrap();
        let engine_task = tokio::spawn(async move {
            let (mut stream, _) = engine.accept().await.unwrap();
            let mut request = vec![0_u8; 4096];
            let read = stream.read(&mut request).await.unwrap();
            assert!(String::from_utf8_lossy(&request[..read]).contains("/containers/json"));
            let body = format!(r#"[{{"Id":"{CONTAINER_ID}","Names":["/api"]}}]"#);
            let response = format!(
                "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let grant = DockerTargetGrant {
            selector: DockerTargetSelector::ContainerName {
                name: "api".to_string(),
            },
            operations: Some(vec![DockerOperation::Logs]),
            allow_unsafe_target: false,
        };

        let policy = DockerAccessPolicy::Targeted {
            endpoint: UnixSocketPath::from_str(engine_path.to_str().unwrap()).unwrap(),
            targets: vec![grant],
        };
        let error = match DockerBroker::start(&policy).await {
            Err(error) => error,
            Ok(_) => panic!("targeted broker accepted a failed Engine snapshot"),
        };

        assert!(error.to_string().contains("Docker target snapshot"));
        assert!(!error.to_string().contains(CONTAINER_ID));
        engine_task.await.unwrap();
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
                        r#"{"HostConfig":{"Privileged":true},"Mounts":[{"Type":"bind","Source":"/host/auths","Destination":"/auths","RW":true}]}"#.to_string()
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

        let denied = super::resolve_target_snapshot(&engine_path, &[grant(false)])
            .await
            .unwrap();
        let accepted = super::resolve_target_snapshot(&engine_path, &[grant(true)])
            .await
            .unwrap();

        assert!(denied.containers.is_empty());
        assert!(accepted.containers.contains_key(CONTAINER_ID));

        let administration = DockerTargetGrant {
            selector: DockerTargetSelector::ContainerName {
                name: "api".to_string(),
            },
            operations: Some(vec![DockerOperation::Exec]),
            allow_unsafe_target: true,
        };
        let restricted = super::resolve_target_snapshot(&engine_path, &[administration])
            .await
            .unwrap();
        let read_probe = request(
            "POST",
            "/v1.52/containers/api/exec",
            br#"{"Cmd":["test","-r","/auths/main.log"]}"#,
        );
        let mutation = request(
            "POST",
            "/v1.52/containers/api/exec",
            br#"{"Cmd":["chmod","0644","/auths/main.log"]}"#,
        );

        assert!(matches!(
            super::authorize_request(&restricted, &read_probe),
            Ok(super::TargetedAction::ExecCreate { .. })
        ));
        assert_eq!(
            super::authorize_request(&restricted, &mutation).unwrap_err(),
            super::AuthorizationError::ExecRestriction(
                "Docker exec is restricted to read-only inspection for this host-access target"
            )
        );
        for overridden in [
            br#"{"Cmd":["test","-r","/auths/main.log"],"Env":["PATH=/auths"]}"#.as_slice(),
            br#"{"Cmd":["test","-r","/auths/main.log"],"User":"root"}"#.as_slice(),
            br#"{"Cmd":["test","-r","/auths/main.log"],"WorkingDir":"/auths"}"#.as_slice(),
        ] {
            assert_eq!(
                super::authorize_request(
                    &restricted,
                    &request("POST", "/v1.52/containers/api/exec", overridden),
                )
                .unwrap_err(),
                super::AuthorizationError::ExecRestriction(
                    "Docker exec is restricted to read-only inspection for this host-access target"
                )
            );
        }

        let expires_at = super::current_unix_time_ms().unwrap() + 60_000;
        let break_glass = DockerTargetGrant {
            selector: DockerTargetSelector::EphemeralContainer {
                id: CONTAINER_ID.to_string(),
                unsafe_exec_expires_at_ms: expires_at,
            },
            operations: Some(vec![DockerOperation::Exec]),
            allow_unsafe_target: true,
        };
        let elevated = super::resolve_target_snapshot(&engine_path, &[break_glass])
            .await
            .unwrap();
        assert!(matches!(
            super::authorize_request(&elevated, &mutation),
            Ok(super::TargetedAction::ExecCreate {
                inspection: false,
                ..
            })
        ));
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
    fn ephemeral_selector_matches_only_its_exact_container() {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let grant = |id: &str, expires_at| DockerTargetGrant {
            selector: DockerTargetSelector::EphemeralContainer {
                id: id.to_string(),
                unsafe_exec_expires_at_ms: expires_at,
            },
            operations: Some(vec![DockerOperation::Exec]),
            allow_unsafe_target: true,
        };
        let current = serde_json::json!({ "Id": "current" });
        let replacement = serde_json::json!({ "Id": "replacement" });

        assert!(super::grant_matches_summary(
            &grant("current", now_ms + 60_000),
            &current
        ));
        assert!(!super::grant_matches_summary(
            &grant("current", now_ms + 60_000),
            &replacement
        ));
        assert!(super::grant_matches_summary(
            &grant("current", now_ms.saturating_sub(1)),
            &current
        ));
    }

    #[test]
    fn broker_rechecks_break_glass_expiry_for_every_exec_request() {
        let mut snapshot = super::TargetSnapshot::default();
        snapshot.containers.insert(
            "current".to_string(),
            super::AllowedContainer {
                operations: [DockerOperation::Exec].into_iter().collect(),
            },
        );
        snapshot
            .aliases
            .insert("api".to_string(), "current".to_string());
        snapshot.exec_expiries.insert("current".to_string(), 0);
        let request = request("POST", "/v1.52/containers/api/exec", br#"{"Cmd":["true"]}"#);

        assert_eq!(
            super::authorize_request(&snapshot, &request).unwrap_err(),
            super::AuthorizationError::ExecRestriction("Docker break-glass exec expired")
        );
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
    async fn targeted_parser_never_forwards_control_byte_smuggling() {
        let root = TempDir::new().unwrap();
        let engine_path = root.path().join("engine.sock");
        let engine = UnixListener::bind(&engine_path).unwrap();
        let engine_task = tokio::spawn(async move {
            let Ok(Ok((mut stream, _))) =
                tokio::time::timeout(Duration::from_millis(300), engine.accept()).await
            else {
                return Vec::new();
            };
            let mut request = vec![0_u8; 4096];
            let read = stream.read(&mut request).await.unwrap();
            request.truncate(read);
            request
        });

        let (mut client, mut broker_side) = UnixStream::pair().unwrap();
        let snapshot = Arc::new(super::TargetSnapshot::default());
        let handler = tokio::spawn({
            let endpoint = engine_path.clone();
            let snapshot = Arc::clone(&snapshot);
            async move {
                super::handle_targeted_connection(&mut broker_side, &endpoint, &snapshot)
                    .await
                    .unwrap();
            }
        });

        client
            .write_all(
                b"GET /_ping HTTP/1.1\r\nHost: docker\r\nX-Test: ok\n\nPOST /containers/ungranted/start HTTP/1.1\nHost: docker\nContent-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();

        handler.await.unwrap();
        let engine_bytes = engine_task.await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 400"));
        assert!(
            engine_bytes.is_empty(),
            "malformed request bytes reached the Docker Engine"
        );
    }

    #[tokio::test]
    async fn targeted_alias_is_forwarded_as_the_pinned_container_id() {
        let root = TempDir::new().unwrap();
        let engine_path = root.path().join("engine.sock");
        let engine = UnixListener::bind(&engine_path).unwrap();
        let engine_task = tokio::spawn(async move {
            let (mut stream, _) = engine.accept().await.unwrap();
            let mut request = vec![0_u8; 4096];
            let read = stream.read(&mut request).await.unwrap();
            request.truncate(read);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .await
                .unwrap();
            request
        });

        let mut snapshot = super::TargetSnapshot::default();
        snapshot.containers.insert(
            "pinned-id".to_string(),
            super::AllowedContainer {
                operations: [DockerOperation::Logs].into_iter().collect(),
            },
        );
        snapshot
            .aliases
            .insert("api".to_string(), "pinned-id".to_string());
        let snapshot = Arc::new(snapshot);
        let (mut client, mut broker_side) = UnixStream::pair().unwrap();
        let handler = tokio::spawn({
            let endpoint = engine_path.clone();
            let snapshot = Arc::clone(&snapshot);
            async move {
                super::handle_targeted_connection(&mut broker_side, &endpoint, &snapshot)
                    .await
                    .unwrap();
            }
        });

        client
            .write_all(
                b"GET /v1.52/containers/api/logs?stdout=1 HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();

        handler.await.unwrap();
        let engine_bytes = engine_task.await.unwrap();
        let first_line = String::from_utf8_lossy(&engine_bytes)
            .lines()
            .next()
            .unwrap()
            .to_string();
        assert_eq!(
            first_line,
            "GET /v1.52/containers/pinned-id/logs?stdout=1 HTTP/1.1"
        );
    }

    #[tokio::test]
    async fn targeted_exec_accepts_standard_client_detach_keys() {
        for body in [
            br#"{"Cmd":["true"],"Privileged":false}"#.as_slice(),
            br#"{"Cmd":["true"],"DetachKeys":null}"#.as_slice(),
            br#"{"Cmd":["true"],"DetachKeys":""}"#.as_slice(),
        ] {
            let root = TempDir::new().unwrap();
            let endpoint = root.path().join("engine.sock");
            let engine = UnixListener::bind(&endpoint).unwrap();
            let engine_task = tokio::spawn(async move {
                let Ok(Ok((mut stream, _))) =
                    tokio::time::timeout(Duration::from_secs(1), engine.accept()).await
                else {
                    return None;
                };
                let request = super::read_request(&mut stream).await.unwrap();
                let body = br#"{"Id":"exec-created"}"#;
                stream.write_all(format!(
                    "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                ).as_bytes()).await.unwrap();
                stream.write_all(body).await.unwrap();
                Some(request)
            });
            let mut snapshot = super::TargetSnapshot::default();
            snapshot.containers.insert(
                "pinned-id".into(),
                super::AllowedContainer {
                    operations: [DockerOperation::Exec].into_iter().collect(),
                },
            );
            snapshot.aliases.insert("api".into(), "pinned-id".into());
            let (mut client, mut broker) = UnixStream::pair().unwrap();
            let handler = tokio::spawn(async move {
                super::handle_targeted_connection(&mut broker, &endpoint, &snapshot)
                    .await
                    .unwrap();
            });
            client.write_all(format!(
                "POST /v1.52/containers/api/exec HTTP/1.1\r\nHost: docker\r\nContent-Length: {}\r\n\r\n",
                body.len()
            ).as_bytes()).await.unwrap();
            client.write_all(body).await.unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            handler.await.unwrap();
            assert!(
                response.starts_with(b"HTTP/1.1 201"),
                "{}",
                String::from_utf8_lossy(&response)
            );
            let forwarded = engine_task
                .await
                .unwrap()
                .expect("request must reach engine");
            assert_eq!(forwarded.target, "/v1.52/containers/pinned-id/exec");
            assert_eq!(forwarded.body, body);
        }
    }

    #[tokio::test]
    async fn targeted_exec_create_rejects_detach_keys_before_engine_forwarding() {
        let root = TempDir::new().unwrap();
        let engine_path = root.path().join("engine.sock");
        let engine = UnixListener::bind(&engine_path).unwrap();
        let engine_task = tokio::spawn(async move {
            let Ok(Ok((mut stream, _))) =
                tokio::time::timeout(Duration::from_millis(300), engine.accept()).await
            else {
                return Vec::new();
            };
            let mut request = vec![0_u8; 4096];
            let read = stream.read(&mut request).await.unwrap();
            request.truncate(read);
            request
        });

        let mut snapshot = super::TargetSnapshot::default();
        snapshot.containers.insert(
            "pinned-id".to_string(),
            super::AllowedContainer {
                operations: [DockerOperation::Exec].into_iter().collect(),
            },
        );
        snapshot
            .aliases
            .insert("api".to_string(), "pinned-id".to_string());
        let snapshot = Arc::new(snapshot);
        let (mut client, mut broker_side) = UnixStream::pair().unwrap();
        let handler = tokio::spawn({
            let endpoint = engine_path.clone();
            let snapshot = Arc::clone(&snapshot);
            async move {
                super::handle_targeted_connection(&mut broker_side, &endpoint, &snapshot)
                    .await
                    .unwrap();
            }
        });
        let body = br#"{"Cmd":["true"],"DetachKeys":"ctrl-x"}"#;
        client
            .write_all(
                format!(
                    "POST /v1.52/containers/api/exec HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        client.write_all(body).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();

        handler.await.unwrap();
        let engine_bytes = engine_task.await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 403"));
        assert!(String::from_utf8_lossy(&response).contains("Docker exec option forbidden"));
        assert!(
            engine_bytes.is_empty(),
            "DetachKeys request reached the Docker Engine"
        );
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
