use crate::support::*;

#[cfg(target_os = "linux")]
#[test]
fn mediated_direct_tcp_uses_an_outer_setup_namespace() {
    let script = r#"import errno, glob, os, socket, subprocess
with open('/proc/self/status', encoding='ascii') as status:
    fields = dict(line.split(':', 1) for line in status if ':' in line)
assert int(fields['CapEff'].strip(), 16) == 0
pids = sorted(int(pid) for pid in os.listdir('/proc') if pid.isdigit())
assert 1 in pids and os.getpid() in pids, pids
assert subprocess.run(['unshare', '-Ur', '/bin/true'], capture_output=True).returncode != 0
assert subprocess.run(['ip', '-4', 'route', 'add', '198.51.100.0/24', 'dev', 'lo'], capture_output=True).returncode != 0
try:
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as ipv6:
        ipv6.settimeout(2)
        ipv6.connect(('2606:4700:4700::1111', 443, 0, 0))
except OSError:
    pass
else:
    raise AssertionError('IPv6 direct egress escaped mediation')
with socket.create_connection(('203.0.113.10', 443), 2) as connection:
    connection.settimeout(2)
    connection.sendall(b'\x00')
    assert connection.recv(1) == b''
with socket.socket() as replacement:
    try:
        replacement.bind(('0.0.0.0', 443))
    except OSError as error:
        assert error.errno in (errno.EADDRINUSE, errno.EPERM, errno.EACCES), error
    else:
        raise AssertionError('mediated listener replaced')
for fd in os.listdir('/proc/self/fd'):
    try:
        target = os.readlink('/proc/self/fd/' + fd)
    except FileNotFoundError:
        continue
    assert not target.startswith('socket:'), (fd, target)
assert not glob.glob('/dev/.zerobox-proxy/m-*.sock')
print('mediated-boundary-ok')
"#;
    let output = run(&[
        "--profile=analysis-strict",
        "--allow-read=/usr",
        "--allow-net=example.com",
        "--mediated-direct-tcp-port=443",
        "--",
        "/usr/bin/python3",
        "-c",
        script,
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "mediated-boundary-ok\n");
}

#[cfg(target_os = "linux")]
#[test]
fn mediated_direct_tcp_preserves_managed_loopback_bridge() {
    let (port, host) = local_http_server(std::net::Ipv4Addr::LOCALHOST.into());
    let output = run(&[
        "--profile=analysis-strict",
        "--allow-read=/usr",
        "--allow-local-binding",
        &format!("--allow-net=localhost:{port}"),
        "--mediated-direct-tcp-port=443",
        "--",
        "curl",
        "-fsS",
        "--max-time",
        "3",
        &format!("http://localhost:{port}"),
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "OK");
    assert!(host.join().unwrap());
}

#[cfg(target_os = "linux")]
#[test]
fn mediated_direct_tcp_allows_proxy_bypassing_tls_for_an_allowed_hostname() {
    let output = run(&[
        "--profile=analysis-strict",
        "--allow-read=/usr",
        "--allow-net=example.com",
        "--mediated-direct-tcp-port=443",
        "--",
        "curl",
        "--proxy",
        "",
        "-fsS",
        "--max-time",
        "8",
        "https://example.com",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("Example Domain"));
}

#[cfg(target_os = "linux")]
#[test]
fn mediated_direct_tcp_does_not_turn_a_host_route_into_public_dns_access() {
    let script = r#"import socket
try:
    socket.gethostbyname('example.com')
except socket.gaierror:
    print('host-route-stayed-local')
else:
    raise AssertionError('host-only grant resolved a public direct destination')
"#;
    let output = run(&[
        "--profile=analysis-strict",
        "--allow-read=/usr",
        "--allow-host-net=example.com:443",
        "--mediated-direct-tcp-port=443",
        "--",
        "/usr/bin/python3",
        "-c",
        script,
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "host-route-stayed-local\n");
}

#[cfg(target_os = "linux")]
#[test]
fn mediated_direct_tcp_allows_proxy_bypassing_http_for_an_allowed_hostname() {
    let output = run(&[
        "--profile=analysis-strict",
        "--allow-read=/usr",
        "--allow-net=example.com:80",
        "--mediated-direct-tcp-port=80",
        "--",
        "curl",
        "--proxy",
        "",
        "-fsS",
        "--max-time",
        "8",
        "http://example.com",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("Example Domain"));
}

#[cfg(target_os = "linux")]
#[test]
fn mediated_direct_tcp_denies_raw_ip_and_wrong_http_host_without_leaking_the_path() {
    let script = r#"import socket
address = socket.gethostbyname('example.com')
for host in (address, 'not-allowed.invalid'):
    connection = socket.create_connection((address, 80), 3)
    connection.sendall(('GET /private?token=secret HTTP/1.1\r\nHost: ' + host + '\r\nConnection: close\r\n\r\n').encode('ascii'))
    connection.settimeout(3)
    try:
        data = connection.recv(1)
    except ConnectionResetError:
        data = b''
    assert data == b'', (host, data)
    connection.close()
print('denied')
"#;
    let output = run(&[
        "--profile=analysis-strict",
        "--allow-read=/usr",
        "--allow-net=example.com:80",
        "--mediated-direct-tcp-port=80",
        "--",
        "/usr/bin/python3",
        "-c",
        script,
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "denied\n");
    assert!(!stderr(&output).contains("private"), "{}", stderr(&output));
    assert!(!stderr(&output).contains("secret"), "{}", stderr(&output));
}

#[cfg(target_os = "linux")]
#[test]
fn mediated_direct_tcp_denies_private_destinations_even_when_domain_allowed() {
    let script = r#"import socket
connection = socket.create_connection(('127.0.0.1', 80), 2)
connection.sendall(b'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
connection.settimeout(2)
try:
    data = connection.recv(1)
except ConnectionResetError:
    data = b''
assert data == b'', data
print('private-denied')
"#;
    let output = run(&[
        "--profile=analysis-strict",
        "--allow-read=/usr",
        "--allow-net=localhost:80",
        "--mediated-direct-tcp-port=80",
        "--",
        "/usr/bin/python3",
        "-c",
        script,
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "private-denied\n");
}

#[cfg(target_os = "linux")]
#[test]
fn mediated_direct_dns_udp_cannot_escape_the_network_namespace() {
    let host = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    host.set_read_timeout(Some(std::time::Duration::from_millis(300)))
        .unwrap();
    let probe = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    probe.connect(("8.8.8.8", 53)).unwrap();
    let host_ip = probe.local_addr().unwrap().ip();
    let host_port = host.local_addr().unwrap().port();
    let script = format!(
        r#"import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
    client.sendto(b'must-stay-private', ('{host_ip}', {host_port}))
print('udp-sent')
"#
    );
    let output = run(&[
        "--profile=analysis-strict",
        "--allow-read=/usr",
        "--allow-net=example.com",
        "--mediated-direct-tcp-port=443",
        "--",
        "/usr/bin/python3",
        "-c",
        &script,
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "udp-sent\n");
    assert_eq!(
        host.recv_from(&mut [0_u8; 64]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[cfg(target_os = "linux")]
#[test]
fn mediated_direct_serves_policy_filtered_tcp_dns() {
    let script = r#"import socket, struct
def query(host):
    packet = bytearray(b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00')
    for label in host.split('.'):
        packet.append(len(label)); packet.extend(label.encode('ascii'))
    packet.extend(b'\x00\x00\x01\x00\x01')
    with socket.create_connection(('8.8.8.8', 53), 2) as dns:
        dns.sendall(struct.pack('!H', len(packet)) + packet)
        size = struct.unpack('!H', dns.recv(2))[0]
        response = b''
        while len(response) < size:
            response += dns.recv(size - len(response))
    return struct.unpack('!H', response[6:8])[0]
assert query('example.com') > 0
assert query('not-allowed.invalid') == 0
print('tcp-dns-ok')
"#;
    let output = run(&[
        "--profile=analysis-strict",
        "--allow-read=/usr",
        "--allow-net=example.com",
        "--mediated-direct-tcp-port=443",
        "--",
        "/usr/bin/python3",
        "-c",
        script,
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "tcp-dns-ok\n");
}

#[cfg(target_os = "linux")]
#[test]
fn mediated_direct_caps_concurrent_tcp_connections() {
    let script = r#"import socket
connections = [socket.create_connection(('203.0.113.10', 443), 2) for _ in range(65)]
connections[-1].settimeout(2)
assert connections[-1].recv(1) == b''
for connection in connections:
    connection.close()
print('connection-cap-ok')
"#;
    let output = run(&[
        "--profile=analysis-strict",
        "--allow-read=/usr",
        "--allow-net=example.com",
        "--mediated-direct-tcp-port=443",
        "--",
        "/usr/bin/python3",
        "-c",
        script,
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "connection-cap-ok\n");
}

#[tokio::test]
async fn private_listeners_reject_unproxied_host_network_access() {
    let error = zerobox::Sandbox::command("/bin/true")
        .no_profile()
        .allow_read("/")
        .allow_net(&[] as &[&str])
        .allow_local_binding(true)
        .linux_sandbox_exe(zerobox_exec())
        .run()
        .await
        .err()
        .expect("private listeners cannot run in the host network namespace");
    assert!(error.to_string().contains("managed proxy"), "{error}");
}

#[cfg(target_os = "linux")]
#[test]
fn private_loopback_refusals_report_the_cause_and_preserve_target_failure() {
    let host = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = host.local_addr().unwrap().port();
    let script = format!(
        r#"import socket, sys
c = socket.create_connection(('127.0.0.1', {port}), 2)
try:
    assert c.recv(1) == b'', 'denied connection returned data'
except ConnectionResetError:
    pass
c.close()
print('target-output')
sys.stderr.write('target-failure\n')
sys.exit(37)
"#
    );
    let output = run(&[
        "--profile=analysis-strict",
        "--allow-read=/usr",
        "--allow-local-binding",
        &format!("--allow-net=localhost:{port}"),
        &format!("--deny-net=localhost:{port}"),
        "--",
        "/usr/bin/python3",
        "-c",
        &script,
    ]);
    assert_eq!(output.status.code(), Some(37), "{}", stderr(&output));
    assert_eq!(stdout(&output), "target-output\n");
    assert!(stderr(&output).contains("target-failure\n"));
    assert!(
        stderr(&output)
            .contains("private loopback connection failed: loopback proxy refused CONNECT"),
        "proxy failure was hidden: {}",
        stderr(&output)
    );
    host.set_nonblocking(true).unwrap();
    assert_eq!(
        host.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[cfg(target_os = "linux")]
#[test]
fn private_loopback_client_disconnect_preserves_the_target_result_without_relay_noise() {
    use std::io::{Read, Write};

    let host = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = host.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        host.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut stream = loop {
            match host.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "client did not connect"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => panic!("accept: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        stream.write_all(b"response-prefix").unwrap();
        // Keep the response open until the client aborts it.
        let _ = stream.read(&mut [0; 1]);
    });
    let script = format!(
        r#"import socket, struct, sys, time
c = socket.create_connection(('127.0.0.1', {port}), 2)
prefix = b''
while len(prefix) < 15:
    chunk = c.recv(15 - len(prefix))
    assert chunk, 'response ended before prefix'
    prefix += chunk
assert prefix == b'response-prefix'
c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
c.close()
# Let the bridge report the reset before the target process exits.
time.sleep(0.2)
print('target-output')
sys.stderr.write('target-error\n')
sys.exit(37)
"#
    );
    let output = run(&[
        "--profile=analysis-strict",
        "--allow-read=/usr",
        "--allow-local-binding",
        &format!("--allow-net=localhost:{port}"),
        "--",
        "/usr/bin/python3",
        "-c",
        &script,
    ]);
    assert_eq!(output.status.code(), Some(37), "{}", stderr(&output));
    server.join().unwrap();
    assert_eq!(stdout(&output), "target-output\n");
    let diagnostic = stderr(&output);
    assert_eq!(diagnostic, "target-error\n");
}

#[cfg(target_os = "linux")]
#[test]
fn local_test_listeners_preserve_explicit_host_loopback_grants() {
    let (port, host) = local_http_server(std::net::Ipv4Addr::LOCALHOST.into());
    let output = run(&[
        "--profile=analysis-strict",
        "--allow-read=/usr",
        "--allow-local-binding",
        &format!("--allow-net=localhost:{port}"),
        "--",
        "curl",
        "-fsS",
        "--max-time",
        "3",
        &format!("http://localhost:{port}"),
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "OK");
    assert!(host.join().unwrap());
}

#[cfg(target_os = "linux")]
#[test]
fn local_binding_is_opt_in_and_stays_inside_the_network_namespace() {
    let host = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = host.local_addr().unwrap().port();
    let script = format!(
        r#"import socket, threading
s = socket.socket()
s.bind(('127.0.0.1', {port}))
s.listen(1)
def serve():
    c, _ = s.accept()
    c.sendall(b'private-server')
    c.close()
t = threading.Thread(target=serve); t.start()
c = socket.create_connection(('127.0.0.1', {port}), 2)
assert c.recv(128) == b'private-server'
c.close(); t.join(); s.close()
print('private-listener-ok')
"#
    );
    for outbound in [false, true] {
        let mut args = vec![
            "--profile=analysis-strict",
            "--allow-read=/usr",
            "--allow-local-binding",
        ];
        if outbound {
            args.push("--allow-net=example.com");
        }
        args.extend(["--", "/usr/bin/python3", "-c", &script]);
        let out = run(&args);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), "private-listener-ok\n");
        args.retain(|arg| *arg != "--allow-local-binding");
        let denied = run(&args);
        assert!(!denied.status.success());
        assert!(
            stderr(&denied).contains("Operation not permitted"),
            "{}",
            stderr(&denied)
        );
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn proxy_routed_private_stream_socketpairs_work_without_host_unix_sockets() {
    let out = zerobox::Sandbox::command("/usr/bin/python3").args(&["-c",
        r#"import errno, socket
for flags in [0, socket.SOCK_CLOEXEC, socket.SOCK_NONBLOCK, socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK]:
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM | flags, 0)
    a.sendall(b'private child output')
    assert b.recv(128) == b'private child output'
    a.close(); b.close()
for create in [lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM), lambda: socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)]:
    try: create()
    except OSError as e: assert e.errno == errno.EPERM, e
    else: raise AssertionError('host socket-capable operation allowed')
print('private-ipc-ok')
"#,
    ]).no_profile().allow_read("/").allow_net(&["example.com"])
        .linux_sandbox_exe(zerobox_exec()).run().await.expect("start sandbox");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"private-ipc-ok\n");
}

#[cfg(target_os = "linux")]
fn local_http_server(ip: std::net::IpAddr) -> (u16, std::thread::JoinHandle<bool>) {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::time::{Duration, Instant};

    let listener = TcpListener::bind(SocketAddr::new(ip, 0)).expect("bind loopback HTTP server");
    let port = listener.local_addr().expect("local server address").port();
    listener
        .set_nonblocking(true)
        .expect("make local server nonblocking");
    let handle = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .expect("set request timeout");
                    let mut request = [0_u8; 2048];
                    let _ = stream.read(&mut request);
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                        )
                        .expect("write local response");
                    return true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept local HTTP connection: {error}"),
            }
        }
    });
    (port, handle)
}

#[cfg(target_os = "linux")]
fn loopback_rule(host: &str, port: u16) -> String {
    if host == "::1" {
        format!("[::1]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(target_os = "linux")]
fn loopback_url(host: &str, port: u16) -> String {
    if host == "::1" {
        format!("http://[::1]:{port}/")
    } else {
        format!("http://{host}:{port}/")
    }
}

#[cfg(target_os = "linux")]
fn loopback_ip(host: &str) -> std::net::IpAddr {
    if host == "::1" {
        std::net::Ipv6Addr::LOCALHOST.into()
    } else {
        std::net::Ipv4Addr::LOCALHOST.into()
    }
}

#[cfg(target_os = "linux")]
fn curl_local(rule: &str, destination: &str) -> Output {
    Command::new(zerobox_exec())
        .current_dir("/tmp")
        .args([
            "--debug".to_string(),
            format!("--allow-net={rule}"),
            "--".to_string(),
            "/usr/bin/curl".to_string(),
            "--fail".to_string(),
            "--silent".to_string(),
            "--show-error".to_string(),
            "--max-time".to_string(),
            "3".to_string(),
            destination.to_string(),
        ])
        .output()
        .expect("run local loopback request")
}

#[cfg(target_os = "linux")]
#[test]
fn loopback_aliases_are_symmetric_at_the_same_port() {
    for rule_host in ["localhost", "127.0.0.1", "::1"] {
        for destination_host in ["localhost", "127.0.0.1", "::1"] {
            let (port, server) = local_http_server(loopback_ip(destination_host));
            let out = curl_local(
                &loopback_rule(rule_host, port),
                &loopback_url(destination_host, port),
            );
            assert!(
                out.status.success(),
                "rule={rule_host} destination={destination_host}: {}",
                stderr(&out)
            );
            assert!(server.join().expect("join local server"));
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn loopback_alias_rules_do_not_include_other_ipv4_loopback_addresses() {
    let (port, server) = local_http_server(std::net::Ipv4Addr::new(127, 0, 0, 2).into());
    for rule_host in ["localhost", "127.0.0.1", "::1"] {
        let out = curl_local(
            &loopback_rule(rule_host, port),
            &loopback_url("127.0.0.2", port),
        );
        assert!(
            !out.status.success(),
            "rule={rule_host} unexpectedly included 127.0.0.2"
        );
    }
    assert!(!server.join().expect("join noncanonical loopback server"));
}

#[cfg(target_os = "linux")]
#[test]
fn loopback_rules_reject_denied_destinations_and_wrong_ports() {
    let (denied_port, denied_server) = local_http_server(std::net::Ipv4Addr::LOCALHOST.into());
    let denied = Command::new(zerobox_exec())
        .args([
            "--allow-net".to_string(),
            format!("--deny-net=localhost:{denied_port}"),
            "--".to_string(),
            "/usr/bin/curl".to_string(),
            "--fail".to_string(),
            "--silent".to_string(),
            "--max-time".to_string(),
            "2".to_string(),
            loopback_url("127.0.0.1", denied_port),
        ])
        .output()
        .expect("run denied loopback request");
    assert!(
        !denied.status.success(),
        "denied request unexpectedly succeeded"
    );
    assert!(!denied_server.join().expect("join denied server"));

    let (destination_port, destination_server) =
        local_http_server(std::net::Ipv4Addr::LOCALHOST.into());
    let unlisted_port = if destination_port == u16::MAX {
        destination_port - 1
    } else {
        destination_port + 1
    };
    let wrong_port = curl_local(
        &loopback_rule("localhost", unlisted_port),
        &loopback_url("127.0.0.1", destination_port),
    );
    assert!(
        !wrong_port.status.success(),
        "wrong-port request unexpectedly succeeded"
    );
    assert!(!destination_server.join().expect("join wrong-port server"));
}

#[cfg(target_os = "linux")]
#[test]
fn direct_http_connect_and_socks5_cannot_bypass_a_denied_destination() {
    let (direct_port, direct_server) = local_http_server(std::net::Ipv4Addr::LOCALHOST.into());
    let direct_script = format!(
        "env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy /usr/bin/curl --fail --silent --max-time 2 {}",
        loopback_url("127.0.0.1", direct_port)
    );
    let direct = run(&[
        "--allow-net=example.com",
        "--",
        "/bin/sh",
        "-c",
        &direct_script,
    ]);
    assert!(
        !direct.status.success(),
        "direct bypass unexpectedly succeeded"
    );
    assert!(!direct_server.join().expect("join direct server"));

    let (connect_port, connect_server) = local_http_server(std::net::Ipv4Addr::LOCALHOST.into());
    let connect_script = format!(
        "/usr/bin/curl --proxy \"$HTTP_PROXY\" --proxytunnel --fail --silent --max-time 2 {}",
        loopback_url("127.0.0.1", connect_port)
    );
    let connect = run(&[
        "--allow-net=example.com",
        "--",
        "/bin/sh",
        "-c",
        &connect_script,
    ]);
    assert!(
        !connect.status.success(),
        "HTTP CONNECT bypass unexpectedly succeeded"
    );
    assert!(!connect_server.join().expect("join CONNECT server"));

    let (socks_port, socks_server) = local_http_server(std::net::Ipv4Addr::LOCALHOST.into());
    let socks_script = format!(
        "/usr/bin/curl --proxy \"$ALL_PROXY\" --fail --silent --max-time 2 {}",
        loopback_url("127.0.0.1", socks_port)
    );
    let socks = run(&[
        "--allow-net=example.com",
        "--",
        "/bin/sh",
        "-c",
        &socks_script,
    ]);
    assert!(
        !socks.status.success(),
        "SOCKS5 bypass unexpectedly succeeded"
    );
    assert!(!socks_server.join().expect("join SOCKS5 server"));
}

#[test]
fn allow_net_full_permits_outbound() {
    let (code, ok) = curl_status(&["--allow-net"], "https://example.com");
    assert!(ok, "expected 200, got {code}");
}

mod allow_net_domains {
    use super::*;

    #[test]
    fn blocked_connect_reports_the_denied_authority() {
        let output = run(&[
            "--allow-net=example.com",
            "--",
            "curl",
            "--silent",
            "--show-error",
            "--max-time",
            "2",
            "https://blocked.invalid",
        ]);

        assert!(
            !output.status.success(),
            "blocked request unexpectedly succeeded"
        );
        assert!(
            stderr(&output).contains("zerobox: Network access denied for blocked.invalid:443:"),
            "denied authority was hidden: {}",
            stderr(&output)
        );
    }

    #[test]
    fn single_domain_allowed() {
        let (code, ok) = curl_status(&["--allow-net=example.com"], "https://example.com");
        assert!(ok, "expected 200, got {code}");
    }

    #[test]
    fn unlisted_domain_blocked() {
        let (code, ok) = curl_status(&["--allow-net=example.com"], "https://google.com");
        assert!(!ok, "expected blocked, got {code}");
    }

    #[test]
    fn multiple_domains_allowed() {
        let (code, ok) = curl_status(
            &["--allow-net=example.com,google.com"],
            "https://example.com",
        );
        assert!(ok, "expected 200, got {code}");
    }

    #[test]
    fn wildcard_subdomain_allows_subdomains() {
        let (code, ok) = curl_status(&["--allow-net=*.example.com"], "https://example.com");
        assert!(
            !ok,
            "*.example.com should NOT match apex example.com, got {code}"
        );
    }

    #[test]
    fn allowed_domain_passes_unlisted_fails() {
        let (code, ok) = curl_status(&["--allow-net=example.com"], "https://example.com");
        assert!(ok, "allowed domain should pass, got {code}");
        let (code, ok) = curl_status(&["--allow-net=example.com"], "https://google.com");
        assert!(!ok, "unlisted domain should fail, got {code}");
    }

    #[test]
    fn apex_and_wildcard_combined() {
        let (code, ok) = curl_status(
            &["--allow-net=example.com,*.example.com"],
            "https://example.com",
        );
        assert!(ok, "expected 200, got {code}");
    }
}

mod deny_net_domains {
    use super::*;

    #[test]
    fn deny_blocks_specific_domain() {
        let (code, ok) = curl_status(
            &["--allow-net", "--deny-net=google.com"],
            "https://google.com",
        );
        assert!(!ok, "expected blocked, got {code}");
    }

    #[test]
    fn deny_does_not_affect_other_domains() {
        let (code, ok) = curl_status(
            &["--allow-net", "--deny-net=google.com"],
            "https://example.com",
        );
        assert!(ok, "expected 200, got {code}");
    }

    #[test]
    fn deny_overrides_allow() {
        let (code, ok) = curl_status(
            &["--allow-net=example.com", "--deny-net=example.com"],
            "https://example.com",
        );
        assert!(!ok, "deny should override allow, got {code}");
    }

    #[test]
    fn deny_wildcard_blocks_subdomains() {
        let (code, ok) = curl_status(
            &["--allow-net", "--deny-net=*.google.com"],
            "https://example.com",
        );
        assert!(ok, "example.com should still work, got {code}");
    }

    #[test]
    fn deny_multiple_domains() {
        let (code, ok) = curl_status(
            &["--allow-net", "--deny-net=google.com,example.com"],
            "https://example.com",
        );
        assert!(!ok, "example.com should be denied, got {code}");
    }
}
