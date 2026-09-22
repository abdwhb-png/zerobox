use std::collections::HashMap;
use std::fs;
use std::io;
use std::io::Read;
use std::io::Write;
use std::mem;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::net::TcpListener as StdTcpListener;
use std::net::UdpSocket as StdUdpSocket;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::task::JoinSet;
use zerobox_network_proxy::NetworkProxyState;
use zerobox_protocol::mediated_direct::MAX_MEDIATED_DIRECT_PORTS;
use zerobox_protocol::mediated_direct::MEDIATED_DIRECT_ACK;
use zerobox_protocol::mediated_direct::MediatedDirectListenerManifest;

const MAX_CONNECTIONS: usize = 64;
const MAX_HANDSHAKE_BYTES: usize = 64 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_CACHE_TTL: Duration = Duration::from_secs(30);
const DNS_TTL_SECONDS: u32 = 30;

pub(crate) struct MediatedDirectBroker {
    socket_path: PathBuf,
    task: JoinHandle<()>,
}

impl MediatedDirectBroker {
    pub(crate) fn start(
        proxy_root: &Path,
        policy: Arc<NetworkProxyState>,
        ports: Vec<u16>,
    ) -> anyhow::Result<Self> {
        let expected_manifest = MediatedDirectListenerManifest::new(ports)?;
        let socket_path = proxy_root.join(format!("m-{}.sock", std::process::id()));
        let listener = std::os::unix::net::UnixListener::bind(&socket_path)
            .context("bind mediated direct broker socket")?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let listener = tokio::net::UnixListener::from_std(listener)?;
        let expected_uid = unsafe { libc::geteuid() };
        let task_path = socket_path.clone();
        let task = tokio::spawn(async move {
            if let Err(error) = run_broker(
                listener,
                &task_path,
                expected_uid,
                expected_manifest,
                policy,
            )
            .await
            {
                eprintln!("zerobox: mediated direct broker failed: {error:#}");
            }
        });
        Ok(Self { socket_path, task })
    }

    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

impl Drop for MediatedDirectBroker {
    fn drop(&mut self) {
        self.task.abort();
        let _ = fs::remove_file(&self.socket_path);
    }
}

struct TransferredListeners {
    manifest: MediatedDirectListenerManifest,
    direct: Vec<StdTcpListener>,
    dns_udp: StdUdpSocket,
    dns_tcp: StdTcpListener,
}

#[derive(Clone)]
struct BrokerPolicy {
    state: Arc<NetworkProxyState>,
    ports: Arc<Vec<u16>>,
    cache: Arc<Mutex<HashMap<(String, u16), CachedResolution>>>,
}

#[derive(Clone)]
struct CachedResolution {
    expires: Instant,
    addresses: Option<Vec<Ipv4Addr>>,
}

impl BrokerPolicy {
    fn new(state: Arc<NetworkProxyState>, ports: Vec<u16>) -> Self {
        Self {
            state,
            ports: Arc::new(ports),
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn resolve(&self, host: &str, port: u16) -> anyhow::Result<Option<Vec<Ipv4Addr>>> {
        let key = (host.to_string(), port);
        let now = Instant::now();
        if let Some(cached) = self.cache.lock().await.get(&key).cloned()
            && cached.expires > now
        {
            return Ok(cached.addresses);
        }
        let addresses = self.state.resolve_allowed_public_ipv4(host, port).await?;
        self.cache.lock().await.insert(
            key,
            CachedResolution {
                expires: now + DNS_CACHE_TTL,
                addresses: addresses.clone(),
            },
        );
        Ok(addresses)
    }

    async fn resolve_for_dns(&self, host: &str) -> anyhow::Result<Option<Vec<Ipv4Addr>>> {
        for port in self.ports.iter().copied() {
            if let Some(addresses) = self.resolve(host, port).await? {
                return Ok(Some(addresses));
            }
        }
        Ok(None)
    }
}

async fn run_broker(
    listener: tokio::net::UnixListener,
    socket_path: &Path,
    expected_uid: libc::uid_t,
    expected_manifest: MediatedDirectListenerManifest,
    state: Arc<NetworkProxyState>,
) -> anyhow::Result<()> {
    let (stream, _) = listener.accept().await?;
    let credentials = stream.peer_cred()?;
    if credentials.uid() != expected_uid {
        anyhow::bail!("mediated direct broker peer identity mismatch");
    }
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o000))?;
    fs::remove_file(socket_path)?;
    drop(listener);

    let stream = stream.into_std()?;
    stream.set_nonblocking(false)?;
    let transferred = tokio::task::spawn_blocking(move || receive_listeners(stream))
        .await
        .context("join mediated descriptor receiver")??;
    if transferred.manifest != expected_manifest {
        anyhow::bail!("mediated listener manifest does not match the effective grant");
    }
    let policy = BrokerPolicy::new(state, transferred.manifest.ports.clone());
    serve_transferred_listeners(transferred, policy).await
}

fn receive_listeners(mut stream: StdUnixStream) -> io::Result<TransferredListeners> {
    let mut payload = vec![0_u8; 6 + MAX_MEDIATED_DIRECT_PORTS * 2];
    let mut io_vector = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let maximum_descriptors = MAX_MEDIATED_DIRECT_PORTS + 2;
    let control_len = unsafe {
        libc::CMSG_SPACE((maximum_descriptors * mem::size_of::<libc::c_int>()) as libc::c_uint)
    } as usize;
    let mut control = vec![0_u8; control_len];
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut io_vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();

    let received =
        unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    if received == 0 || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid mediated listener descriptor message",
        ));
    }
    let payload_length = complete_listener_manifest(&mut stream, &mut payload, received as usize)?;
    let manifest = MediatedDirectListenerManifest::decode(&payload[..payload_length])?;
    let mut descriptors = unsafe { received_descriptors(&message)? };
    if descriptors.len() != manifest.descriptor_count() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mediated listener descriptor count mismatch",
        ));
    }

    let mut direct = Vec::with_capacity(manifest.ports.len());
    for expected_port in &manifest.ports {
        let listener = StdTcpListener::from(descriptors.remove(0));
        if listener.local_addr()?.port() != *expected_port {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mediated listener port mismatch",
            ));
        }
        direct.push(listener);
    }
    let dns_udp = StdUdpSocket::from(descriptors.remove(0));
    let dns_tcp = StdTcpListener::from(descriptors.remove(0));
    if dns_udp.local_addr()?.port() != 53 || dns_tcp.local_addr()?.port() != 53 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mediated DNS listener port mismatch",
        ));
    }
    stream.write_all(&[MEDIATED_DIRECT_ACK])?;
    Ok(TransferredListeners {
        manifest,
        direct,
        dns_udp,
        dns_tcp,
    })
}

fn complete_listener_manifest(
    stream: &mut impl Read,
    payload: &mut [u8],
    mut received: usize,
) -> io::Result<usize> {
    if received < 6 {
        stream.read_exact(&mut payload[received..6])?;
        received = 6;
    }
    let count = usize::from(u16::from_be_bytes([payload[4], payload[5]]));
    let expected = 6_usize
        .checked_add(count.checked_mul(2).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid mediated listener count",
            )
        })?)
        .filter(|length| *length <= payload.len())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid mediated listener count",
            )
        })?;
    if received > expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized mediated listener manifest",
        ));
    }
    stream.read_exact(&mut payload[received..expected])?;
    Ok(expected)
}

unsafe fn received_descriptors(message: &libc::msghdr) -> io::Result<Vec<OwnedFd>> {
    let header = unsafe { libc::CMSG_FIRSTHDR(message) };
    if header.is_null()
        || unsafe { (*header).cmsg_level } != libc::SOL_SOCKET
        || unsafe { (*header).cmsg_type } != libc::SCM_RIGHTS
        || !unsafe { libc::CMSG_NXTHDR(message, header) }.is_null()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mediated broker expected one descriptor control message",
        ));
    }
    let header_len = unsafe { (*header).cmsg_len };
    let empty_len = unsafe { libc::CMSG_LEN(0) } as usize;
    if header_len < empty_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid mediated descriptor control length",
        ));
    }
    let bytes = header_len - empty_len;
    if !bytes.is_multiple_of(mem::size_of::<RawFd>()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unaligned mediated descriptor control message",
        ));
    }
    let count = bytes / mem::size_of::<RawFd>();
    let data = unsafe { libc::CMSG_DATA(header).cast::<RawFd>() };
    Ok((0..count)
        .map(|index| unsafe { OwnedFd::from_raw_fd(*data.add(index)) })
        .collect())
}

async fn serve_transferred_listeners(
    transferred: TransferredListeners,
    policy: BrokerPolicy,
) -> anyhow::Result<()> {
    let TransferredListeners {
        manifest,
        direct,
        dns_udp,
        dns_tcp,
    } = transferred;
    dns_udp.set_nonblocking(true)?;
    dns_tcp.set_nonblocking(true)?;
    let dns_udp = UdpSocket::from_std(dns_udp)?;
    let dns_tcp = TcpListener::from_std(dns_tcp)?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    let mut tasks = JoinSet::new();
    for (port, listener) in manifest.ports.into_iter().zip(direct) {
        listener.set_nonblocking(true)?;
        tasks.spawn(serve_direct_listener(
            TcpListener::from_std(listener)?,
            port,
            policy.clone(),
            permits.clone(),
        ));
    }
    tasks.spawn(serve_dns_udp(dns_udp, policy.clone()));
    tasks.spawn(serve_dns_tcp(dns_tcp, policy, permits));

    match tasks.join_next().await {
        Some(Ok(Ok(()))) => anyhow::bail!("mediated listener exited unexpectedly"),
        Some(Ok(Err(error))) => Err(error),
        Some(Err(error)) => Err(error.into()),
        None => anyhow::bail!("mediated broker had no listeners"),
    }
}

async fn serve_direct_listener(
    listener: TcpListener,
    configured_port: u16,
    policy: BrokerPolicy,
    permits: Arc<Semaphore>,
) -> anyhow::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let policy = policy.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = mediate_connection(stream, configured_port, policy).await {
                        eprintln!("zerobox: mediated direct TCP connection denied: {error}");
                    }
                });
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    return Err(error.into());
                }
            }
        }
    }
}

async fn mediate_connection(
    mut client: TcpStream,
    configured_port: u16,
    policy: BrokerPolicy,
) -> anyhow::Result<()> {
    let destination = client.local_addr()?;
    if destination.port() != configured_port {
        anyhow::bail!("destination port does not match the configured listener");
    }
    let IpAddr::V4(destination_ip) = destination.ip() else {
        anyhow::bail!("IPv6 direct egress is unsupported");
    };
    let (hostname, prefix) = inspect_handshake(&mut client).await?;
    let Some(addresses) = policy.resolve(&hostname, configured_port).await? else {
        anyhow::bail!("hostname {hostname}:{configured_port} is not allowed");
    };
    if !addresses.contains(&destination_ip) {
        anyhow::bail!("hostname {hostname}:{configured_port} does not match the destination");
    }
    let mut upstream = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        TcpStream::connect(SocketAddrV4::new(destination_ip, configured_port)),
    )
    .await
    .context("upstream connection timed out")??;
    upstream.write_all(&prefix).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

async fn inspect_handshake(client: &mut TcpStream) -> anyhow::Result<(String, Vec<u8>)> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let mut prefix = Vec::with_capacity(4096);
        loop {
            match inspect_protocol(&prefix) {
                Inspection::Hostname(hostname) => return Ok((hostname, prefix)),
                Inspection::Reject(reason) => anyhow::bail!(reason),
                Inspection::NeedMore => {}
            }
            if prefix.len() == MAX_HANDSHAKE_BYTES {
                anyhow::bail!("handshake exceeds 64 KiB");
            }
            let available = MAX_HANDSHAKE_BYTES - prefix.len();
            let chunk = available.min(4096);
            let start = prefix.len();
            prefix.resize(start + chunk, 0);
            let read = client.read(&mut prefix[start..]).await?;
            prefix.truncate(start + read);
            if read == 0 {
                anyhow::bail!("connection closed before a hostname was observed");
            }
        }
    })
    .await
    .context("hostname inspection timed out")?
}

#[derive(Debug, PartialEq, Eq)]
enum Inspection {
    NeedMore,
    Hostname(String),
    Reject(&'static str),
}

fn inspect_protocol(prefix: &[u8]) -> Inspection {
    let Some(first) = prefix.first() else {
        return Inspection::NeedMore;
    };
    if *first == 0x16 {
        inspect_tls_client_hello(prefix)
    } else if first.is_ascii_alphabetic() {
        inspect_http_request(prefix)
    } else {
        Inspection::Reject("unsupported direct TCP protocol")
    }
}

fn inspect_http_request(prefix: &[u8]) -> Inspection {
    let Some(header_end) = prefix.windows(4).position(|bytes| bytes == b"\r\n\r\n") else {
        return Inspection::NeedMore;
    };
    let Ok(headers) = std::str::from_utf8(&prefix[..header_end + 2]) else {
        return Inspection::Reject("malformed HTTP headers");
    };
    let mut lines = headers.split("\r\n");
    let Some(request_line) = lines.next() else {
        return Inspection::Reject("malformed HTTP request");
    };
    if !request_line.ends_with(" HTTP/1.1") {
        return Inspection::Reject("unsupported direct HTTP version");
    }
    let hosts = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("host").then_some(value.trim())
        })
        .collect::<Vec<_>>();
    if hosts.len() != 1 {
        return Inspection::Reject("HTTP/1.1 requires one Host header");
    }
    match normalize_observed_hostname(hosts[0]) {
        Some(host) => Inspection::Hostname(host),
        None => Inspection::Reject("HTTP Host is not an enforceable hostname"),
    }
}

fn inspect_tls_client_hello(prefix: &[u8]) -> Inspection {
    let mut records = Vec::new();
    let mut offset = 0;
    loop {
        if prefix.len() < offset + 5 {
            return Inspection::NeedMore;
        }
        if prefix[offset] != 0x16 {
            return Inspection::Reject("unsupported TLS record");
        }
        let record_len = usize::from(u16::from_be_bytes([prefix[offset + 3], prefix[offset + 4]]));
        if prefix.len() < offset + 5 + record_len {
            return Inspection::NeedMore;
        }
        records.extend_from_slice(&prefix[offset + 5..offset + 5 + record_len]);
        offset += 5 + record_len;
        if records.len() < 4 {
            if offset == prefix.len() {
                return Inspection::NeedMore;
            }
            continue;
        }
        if records[0] != 1 {
            return Inspection::Reject("TLS handshake is not a ClientHello");
        }
        let hello_len = (usize::from(records[1]) << 16)
            | (usize::from(records[2]) << 8)
            | usize::from(records[3]);
        if records.len() < 4 + hello_len {
            if offset == prefix.len() {
                return Inspection::NeedMore;
            }
            continue;
        }
        return parse_client_hello(&records[4..4 + hello_len]);
    }
}

fn parse_client_hello(hello: &[u8]) -> Inspection {
    let mut cursor = 0;
    if take(hello, &mut cursor, 2 + 32).is_none() {
        return Inspection::Reject("malformed TLS ClientHello");
    }
    let Some(session_len) = take_u8(hello, &mut cursor) else {
        return Inspection::Reject("malformed TLS ClientHello");
    };
    if take(hello, &mut cursor, usize::from(session_len)).is_none() {
        return Inspection::Reject("malformed TLS ClientHello");
    }
    let Some(cipher_len) = take_u16(hello, &mut cursor) else {
        return Inspection::Reject("malformed TLS ClientHello");
    };
    if cipher_len == 0
        || cipher_len % 2 != 0
        || take(hello, &mut cursor, usize::from(cipher_len)).is_none()
    {
        return Inspection::Reject("malformed TLS ClientHello");
    }
    let Some(compression_len) = take_u8(hello, &mut cursor) else {
        return Inspection::Reject("malformed TLS ClientHello");
    };
    if take(hello, &mut cursor, usize::from(compression_len)).is_none() {
        return Inspection::Reject("malformed TLS ClientHello");
    }
    let Some(extensions_len) = take_u16(hello, &mut cursor) else {
        return Inspection::Reject("TLS ClientHello has no enforceable SNI");
    };
    let Some(extensions) = take(hello, &mut cursor, usize::from(extensions_len)) else {
        return Inspection::Reject("malformed TLS extensions");
    };
    if cursor != hello.len() {
        return Inspection::Reject("malformed TLS ClientHello length");
    }

    let mut extension_cursor = 0;
    let mut hostname = None;
    while extension_cursor < extensions.len() {
        let Some(extension_type) = take_u16(extensions, &mut extension_cursor) else {
            return Inspection::Reject("malformed TLS extension");
        };
        let Some(extension_len) = take_u16(extensions, &mut extension_cursor) else {
            return Inspection::Reject("malformed TLS extension");
        };
        let Some(extension) = take(
            extensions,
            &mut extension_cursor,
            usize::from(extension_len),
        ) else {
            return Inspection::Reject("malformed TLS extension");
        };
        if extension_type == 0xfe0d {
            return Inspection::Reject("TLS ECH is unsupported for mediated direct TCP");
        }
        if extension_type == 0 {
            if hostname.is_some() {
                return Inspection::Reject("TLS ClientHello has multiple SNI extensions");
            }
            hostname = parse_sni_extension(extension);
            if hostname.is_none() {
                return Inspection::Reject("TLS ClientHello has malformed SNI");
            }
        }
    }
    hostname
        .map(Inspection::Hostname)
        .unwrap_or(Inspection::Reject("TLS ClientHello has no enforceable SNI"))
}

fn parse_sni_extension(extension: &[u8]) -> Option<String> {
    let mut cursor = 0;
    let names_len = usize::from(take_u16(extension, &mut cursor)?);
    let names = take(extension, &mut cursor, names_len)?;
    if cursor != extension.len() {
        return None;
    }
    let mut names_cursor = 0;
    let mut hostname = None;
    while names_cursor < names.len() {
        let name_type = take_u8(names, &mut names_cursor)?;
        let name_len = usize::from(take_u16(names, &mut names_cursor)?);
        let name = take(names, &mut names_cursor, name_len)?;
        if name_type == 0 {
            if hostname.is_some() {
                return None;
            }
            hostname = normalize_observed_hostname(std::str::from_utf8(name).ok()?);
        }
    }
    hostname
}

fn normalize_observed_hostname(authority: &str) -> Option<String> {
    let authority = authority.trim();
    if authority.is_empty()
        || authority.starts_with('[')
        || authority.contains(['/', '\\', '@'])
        || authority.chars().any(char::is_whitespace)
    {
        return None;
    }
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.parse::<u16>().is_ok() => host,
        Some(_) if authority.contains(':') => return None,
        _ => authority,
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || host.parse::<IpAddr>().is_ok()
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return None;
    }
    Some(host)
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> Option<&'a [u8]> {
    let end = cursor.checked_add(length)?;
    let value = bytes.get(*cursor..end)?;
    *cursor = end;
    Some(value)
}

fn take_u8(bytes: &[u8], cursor: &mut usize) -> Option<u8> {
    Some(*take(bytes, cursor, 1)?.first()?)
}

fn take_u16(bytes: &[u8], cursor: &mut usize) -> Option<u16> {
    let bytes = take(bytes, cursor, 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

async fn serve_dns_udp(socket: UdpSocket, policy: BrokerPolicy) -> anyhow::Result<()> {
    let mut request = vec![0_u8; 4096];
    loop {
        let (length, peer) = socket.recv_from(&mut request).await?;
        let response = build_dns_response(&request[..length], &policy).await;
        if let Ok(response) = response {
            socket.send_to(&response, peer).await?;
        }
    }
}

async fn serve_dns_tcp(
    listener: TcpListener,
    policy: BrokerPolicy,
    permits: Arc<Semaphore>,
) -> anyhow::Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (mut stream, _) = accepted?;
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let policy = policy.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    loop {
                        let length = match stream.read_u16().await {
                            Ok(length) => usize::from(length),
                            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok::<(), anyhow::Error>(()),
                            Err(error) => return Err(error.into()),
                        };
                        if length == 0 || length > 4096 {
                            anyhow::bail!("invalid mediated TCP DNS request length");
                        }
                        let mut request = vec![0_u8; length];
                        stream.read_exact(&mut request).await?;
                        let response = build_dns_response(&request, &policy).await?;
                        stream.write_u16(u16::try_from(response.len())?).await?;
                        stream.write_all(&response).await?;
                    }
                });
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = completed {
                    return Err(error.into());
                }
            }
        }
    }
}

struct DnsQuestion {
    hostname: String,
    query_type: u16,
    question_end: usize,
}

async fn build_dns_response(request: &[u8], policy: &BrokerPolicy) -> anyhow::Result<Vec<u8>> {
    let question = parse_dns_question(request)?;
    let addresses = if question.query_type == 1 {
        policy
            .resolve_for_dns(&question.hostname)
            .await?
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let mut response = Vec::with_capacity(question.question_end + addresses.len() * 16);
    response.extend_from_slice(&request[..2]);
    let request_flags = u16::from_be_bytes([request[2], request[3]]);
    let response_flags = 0x8000 | 0x0080 | (request_flags & 0x0100);
    response.extend_from_slice(&response_flags.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&(addresses.len() as u16).to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&request[12..question.question_end]);
    for address in addresses {
        response.extend_from_slice(&0xc00c_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&DNS_TTL_SECONDS.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&address.octets());
    }
    Ok(response)
}

fn parse_dns_question(request: &[u8]) -> anyhow::Result<DnsQuestion> {
    if request.len() < 12
        || u16::from_be_bytes([request[4], request[5]]) != 1
        || u16::from_be_bytes([request[2], request[3]]) & 0x7800 != 0
    {
        anyhow::bail!("unsupported mediated DNS request");
    }
    let mut cursor = 12;
    let mut labels = Vec::new();
    loop {
        let length = usize::from(*request.get(cursor).context("truncated DNS name")?);
        cursor += 1;
        if length == 0 {
            break;
        }
        if length > 63 || length & 0xc0 != 0 {
            anyhow::bail!("compressed or malformed DNS question name");
        }
        let label = request
            .get(cursor..cursor + length)
            .context("truncated DNS label")?;
        labels.push(std::str::from_utf8(label)?);
        cursor += length;
    }
    let query_type_bytes = request
        .get(cursor..cursor + 2)
        .context("missing DNS query type")?;
    let query_type = u16::from_be_bytes([query_type_bytes[0], query_type_bytes[1]]);
    cursor += 2;
    let class = request
        .get(cursor..cursor + 2)
        .context("missing DNS query class")?;
    if u16::from_be_bytes([class[0], class[1]]) != 1 {
        anyhow::bail!("unsupported DNS query class");
    }
    cursor += 2;
    let hostname = normalize_observed_hostname(&labels.join("."))
        .context("DNS question has no enforceable hostname")?;
    Ok(DnsQuestion {
        hostname,
        query_type,
        question_end: cursor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_inspection_requires_one_hostname_and_hides_the_path() {
        assert_eq!(
            inspect_protocol(b"GET /private?token=secret HTTP/1.1\r\nHost: Example.COM:80\r\n\r\n"),
            Inspection::Hostname("example.com".to_string())
        );
        assert!(matches!(
            inspect_protocol(b"GET / HTTP/1.1\r\nHost: 93.184.216.34\r\n\r\n"),
            Inspection::Reject(_)
        ));
        assert!(matches!(
            inspect_protocol(b"GET / HTTP/1.1\r\n\r\n"),
            Inspection::Reject(_)
        ));
    }

    #[test]
    fn fragmented_http_and_tls_wait_for_the_complete_hostname() {
        assert_eq!(
            inspect_protocol(b"GET / HTTP/1.1\r\nHo"),
            Inspection::NeedMore
        );
        let hello = tls_client_hello("example.com", false);
        for end in 1..hello.len() {
            assert_eq!(inspect_protocol(&hello[..end]), Inspection::NeedMore);
        }
        assert_eq!(
            inspect_protocol(&hello),
            Inspection::Hostname("example.com".to_string())
        );
    }

    #[test]
    fn tls_inspection_rejects_ech_and_missing_or_raw_sni() {
        assert!(matches!(
            inspect_protocol(&tls_client_hello("example.com", true)),
            Inspection::Reject(_)
        ));
        assert!(matches!(
            inspect_protocol(&tls_client_hello("93.184.216.34", false)),
            Inspection::Reject(_)
        ));
    }

    #[test]
    fn dns_response_returns_only_a_records_with_a_thirty_second_ttl() {
        let request = dns_query("example.com", 1);
        let question = parse_dns_question(&request).unwrap();
        assert_eq!(question.hostname, "example.com");
        assert_eq!(question.query_type, 1);
        assert_eq!(question.question_end, request.len());
    }

    #[test]
    fn listener_manifest_receiver_completes_a_fragmented_stream_frame() {
        let manifest = MediatedDirectListenerManifest::new(vec![80, 443])
            .unwrap()
            .encode();
        let mut payload = vec![0_u8; 6 + MAX_MEDIATED_DIRECT_PORTS * 2];
        payload[..2].copy_from_slice(&manifest[..2]);
        let mut remainder = &manifest[2..];

        let length = complete_listener_manifest(&mut remainder, &mut payload, 2).unwrap();

        assert_eq!(&payload[..length], manifest);
    }

    #[tokio::test]
    async fn dropping_an_unclaimed_broker_revokes_its_control_socket() {
        let allowed = vec!["example.com".to_string()];
        let proxy = crate::proxy::build_proxy(
            Some(&allowed),
            &[],
            None,
            &Arc::new(crate::secret::SecretStore::default()),
        )
        .await
        .unwrap()
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        let broker = MediatedDirectBroker::start(root.path(), proxy.state, vec![443]).unwrap();
        let socket = broker.socket_path().to_path_buf();
        assert!(std::os::unix::fs::FileTypeExt::is_socket(
            &socket.symlink_metadata().unwrap().file_type()
        ));

        drop(broker);

        assert!(!socket.exists());
    }

    #[tokio::test]
    async fn broker_fails_closed_when_the_helper_omits_listener_descriptors() {
        let allowed = vec!["example.com".to_string()];
        let proxy = crate::proxy::build_proxy(
            Some(&allowed),
            &[],
            None,
            &Arc::new(crate::secret::SecretStore::default()),
        )
        .await
        .unwrap()
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        let broker = MediatedDirectBroker::start(root.path(), proxy.state, vec![443]).unwrap();
        let socket = broker.socket_path().to_path_buf();
        let mut peer = StdUnixStream::connect(&socket).unwrap();
        peer.write_all(
            &MediatedDirectListenerManifest::new(vec![443])
                .unwrap()
                .encode(),
        )
        .unwrap();
        drop(peer);

        tokio::time::timeout(Duration::from_secs(1), async {
            while !broker.task.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("broker must reject the malformed helper frame");
        assert!(!socket.exists());
    }

    fn tls_client_hello(host: &str, ech: bool) -> Vec<u8> {
        let mut sni = Vec::new();
        sni.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host.as_bytes());
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0_u16.to_be_bytes());
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni);
        if ech {
            extensions.extend_from_slice(&0xfe0d_u16.to_be_bytes());
            extensions.extend_from_slice(&1_u16.to_be_bytes());
            extensions.push(0);
        }
        let mut hello = Vec::new();
        hello.extend_from_slice(&0x0303_u16.to_be_bytes());
        hello.extend_from_slice(&[0; 32]);
        hello.push(0);
        hello.extend_from_slice(&2_u16.to_be_bytes());
        hello.extend_from_slice(&0x1301_u16.to_be_bytes());
        hello.push(1);
        hello.push(0);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);
        let mut handshake = vec![
            1,
            ((hello.len() >> 16) & 0xff) as u8,
            ((hello.len() >> 8) & 0xff) as u8,
            (hello.len() & 0xff) as u8,
        ];
        handshake.extend_from_slice(&hello);
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn dns_query(host: &str, query_type: u16) -> Vec<u8> {
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in host.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&query_type.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        query
    }
}
