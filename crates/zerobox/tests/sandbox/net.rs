use crate::support::*;

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
