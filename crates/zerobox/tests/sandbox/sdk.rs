use crate::support::zerobox_exec;
use zerobox::{Sandbox, TcpPublication, TcpPublicationScope};

fn missing_target() -> Sandbox {
    Sandbox::command("/definitely/missing/zerobox-target")
        .no_profile()
        .allow_read("/")
        .linux_sandbox_exe(zerobox_exec())
}

#[tokio::test]
async fn sdk_empty_read_only_files_keep_observing_host_writes() {
    let root = tempfile::tempdir().unwrap();
    let protected = root.path().join("real-empty-file");
    std::fs::write(&protected, "").unwrap();
    let sandbox = Sandbox::command("/bin/sh")
        .args(&[
            "-c",
            "touch ready; while ! test -e go; do sleep 0.01; done; cat real-empty-file",
        ])
        .cwd(root.path())
        .no_profile()
        .allow_read("/")
        .allow_write(root.path())
        .deny_write(&protected)
        .linux_sandbox_exe(zerobox_exec());
    let run = tokio::spawn(async move { sandbox.run().await });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !root.path().join("ready").exists() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("sandbox ready");
    std::fs::write(&protected, "host-update").unwrap();
    std::fs::write(root.path().join("go"), "").unwrap();
    let output = run.await.unwrap().unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    assert_eq!(output.stdout, b"host-update");
    assert_eq!(std::fs::read(protected).unwrap(), b"host-update");
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk_concurrent_missing_denies_do_not_lose_mount_sources_or_real_files() {
    let root = tempfile::tempdir().expect("workspace");
    let existing = root.path().join("real-empty-file");
    std::fs::write(&existing, "").unwrap();
    let missing = root.path().join("missing-denied-file");
    for _ in 0..8 {
        let mut runs = tokio::task::JoinSet::new();
        for i in 0..6 {
            let sandbox = Sandbox::command("/bin/sh")
                .args(&["-c", if i % 2 == 0 { "sleep 0.02" } else { "true" }])
                .cwd(root.path())
                .no_profile()
                .allow_read("/")
                .allow_write(root.path())
                .deny_write(&missing)
                .deny_write(&existing)
                .linux_sandbox_exe(zerobox_exec());
            runs.spawn(async move { sandbox.run().await });
        }
        let mut errors = Vec::new();
        while let Some(result) = runs.join_next().await {
            match result.unwrap() {
                Ok(output) if output.status.success() => {}
                Ok(output) => errors.push(String::from_utf8_lossy(&output.stderr).into_owned()),
                Err(error) => errors.push(error.to_string()),
            }
        }
        assert!(errors.is_empty(), "concurrent setup failures: {errors:#?}");
    }
    assert_eq!(std::fs::read(&existing).unwrap(), b"");
    assert!(
        !missing.exists(),
        "synthetic target leaked into host workspace"
    );
}

#[tokio::test]
async fn sdk_run_reports_final_exec_failure_as_setup_error() {
    let error = match missing_target().run().await {
        Ok(_) => panic!("missing target must fail before returning output"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("ERR:"), "error: {error}");
}

#[tokio::test]
async fn sdk_spawn_reports_final_exec_failure_as_setup_error() {
    let error = match missing_target().spawn().await {
        Ok(_) => panic!("missing target must fail before returning a child"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("ERR:"), "error: {error}");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn sdk_preserves_helper_stderr_when_setup_pipe_closes() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().expect("helper fixture");
    let helper = root.path().join("helper");
    std::fs::write(
        &helper,
        "#!/bin/sh\nprintf 'mount source disappeared: ENOENT\\n' >&2\nexit 73\n",
    )
    .expect("write helper");
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700))
        .expect("executable helper");
    let error = match Sandbox::command("/bin/true")
        .no_profile()
        .allow_read("/")
        .linux_sandbox_exe(helper)
        .run()
        .await
    {
        Ok(_) => panic!("failed helper must not become a target result"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("mount source disappeared: ENOENT\n"),
        "lost setup diagnostic: {error}"
    );
}

#[tokio::test]
async fn sdk_status_reports_final_exec_failure_as_setup_error() {
    let error = missing_target()
        .status()
        .await
        .expect_err("missing target must fail before returning a status");
    assert!(error.to_string().contains("ERR:"), "error: {error}");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn rust_sdk_explicit_strict_path_matches_cli_contract() {
    let output = Sandbox::command("/bin/sh")
        .args(&["-c", "printf %s \"$PATH\""])
        .profile("analysis-strict")
        .env("PATH", "/opt/sdk/bin:/usr/bin")
        .allow_env(&["PATH"])
        .secret("PATH", "must-not-win")
        .linux_sandbox_exe(zerobox_exec())
        .run()
        .await
        .expect("run strict SDK PATH check");

    assert!(output.status.success());
    assert_eq!(output.stdout, b"/opt/sdk/bin:/usr/bin");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn sdk_tcp_publication_revocation_closes_listener_without_killing_target() {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::time::{Duration, Instant};

    fn unused_loopback_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("reserve loopback test port")
            .local_addr()
            .expect("read loopback test port")
            .port()
    }

    let workspace = tempfile::tempdir().expect("create revocation fixture");
    let host = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
    let publication = TcpPublication {
        scope: TcpPublicationScope::Host,
        listen: host,
        target,
    };
    let script = format!(
        r#"import socket, time
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(({ip:?}, {port}))
server.listen(1)
connection, _ = server.accept()
connection.sendall(b"ready")
assert connection.recv(4) == b"ping"
connection.sendall(b"pong")
time.sleep(10)
"#,
        ip = target.ip().to_string(),
        port = target.port(),
    );
    let mut child = Sandbox::command("/usr/bin/python3")
        .args(&["-c", script.as_str()])
        .cwd(workspace.path())
        .no_profile()
        .allow_read("/usr")
        .allow_read(workspace.path())
        .publish_tcp(publication)
        .linux_sandbox_exe(zerobox_exec())
        .spawn()
        .await
        .expect("spawn revocable TCP publication");

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut admitted = loop {
        match TcpStream::connect_timeout(&host, Duration::from_millis(100)) {
            Ok(stream) => break stream,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => panic!("host publication never became reachable: {error}"),
        }
    };
    let mut ready = [0_u8; 5];
    admitted
        .read_exact(&mut ready)
        .expect("confirm admitted connection reached the target");
    assert_eq!(&ready, b"ready");
    child
        .revoke_tcp_publications()
        .expect("revoke host TCP publication");
    admitted.write_all(b"ping").expect("write admitted request");
    let mut response = [0_u8; 4];
    admitted
        .read_exact(&mut response)
        .expect("drain admitted connection");
    assert_eq!(&response, b"pong");

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match TcpStream::connect_timeout(&host, Duration::from_millis(100)) {
            Err(_) => break,
            Ok(stream) if Instant::now() < deadline => {
                drop(stream);
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(stream) => {
                drop(stream);
                panic!("revoked host publication remained reachable");
            }
        }
    }
    let status = child.kill_and_wait().await.expect("stop retained target");
    assert!(
        !status.success(),
        "test cleanup should terminate the retained target"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn sdk_tcp_publication_revocation_forces_a_stalled_relay_to_close_within_bound() {
    use std::io::Read;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::time::{Duration, Instant};

    fn unused_loopback_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("reserve loopback test port")
            .local_addr()
            .expect("read loopback test port")
            .port()
    }

    let workspace = tempfile::tempdir().expect("create stalled revocation fixture");
    let host = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
    let script = format!(
        r#"import socket, time
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(({ip:?}, {port}))
server.listen(1)
connection, _ = server.accept()
connection.sendall(b"ready")
time.sleep(30)
"#,
        ip = target.ip().to_string(),
        port = target.port(),
    );
    let mut child = Sandbox::command("/usr/bin/python3")
        .args(&["-c", script.as_str()])
        .cwd(workspace.path())
        .no_profile()
        .allow_read("/usr")
        .allow_read(workspace.path())
        .publish_tcp(TcpPublication {
            scope: TcpPublicationScope::Host,
            listen: host,
            target,
        })
        .linux_sandbox_exe(zerobox_exec())
        .spawn()
        .await
        .expect("spawn revocable TCP publication");

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut admitted = loop {
        match TcpStream::connect_timeout(&host, Duration::from_millis(100)) {
            Ok(stream) => break stream,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => panic!("host publication never became reachable: {error}"),
        }
    };
    let mut ready = [0_u8; 5];
    admitted
        .read_exact(&mut ready)
        .expect("confirm stalled relay reached the target");
    assert_eq!(&ready, b"ready");
    admitted
        .set_read_timeout(Some(Duration::from_secs(7)))
        .expect("set bounded read timeout");
    let started = Instant::now();
    child
        .revoke_tcp_publications()
        .expect("revoke host TCP publication");
    let mut byte = [0_u8; 1];
    assert_eq!(
        admitted.read(&mut byte).expect("stalled relay must close"),
        0,
        "revocation must close the stalled host stream"
    );
    assert!(
        started.elapsed() <= Duration::from_secs(6),
        "stalled relay exceeded drain bound: {:?}",
        started.elapsed()
    );
    let status = child.kill_and_wait().await.expect("stop retained target");
    assert!(!status.success(), "test cleanup should terminate target");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn sdk_tcp_publication_closes_host_listener_when_supervisor_is_killed() {
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::time::{Duration, Instant};

    fn unused_loopback_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("reserve loopback test port")
            .local_addr()
            .expect("read loopback test port")
            .port()
    }

    let workspace = tempfile::tempdir().expect("create supervisor cleanup fixture");
    let host = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
    let script = format!(
        r#"import socket, time
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(({ip:?}, {port}))
server.listen(1)
time.sleep(30)
"#,
        ip = target.ip().to_string(),
        port = target.port(),
    );
    let child = Sandbox::command("/usr/bin/python3")
        .args(&["-c", script.as_str()])
        .cwd(workspace.path())
        .no_profile()
        .allow_read("/usr")
        .allow_read(workspace.path())
        .publish_tcp(TcpPublication {
            scope: TcpPublicationScope::Host,
            listen: host,
            target,
        })
        .linux_sandbox_exe(zerobox_exec())
        .spawn()
        .await
        .expect("spawn TCP publication");

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match TcpStream::connect_timeout(&host, Duration::from_millis(100)) {
            Ok(stream) => {
                drop(stream);
                break;
            }
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => panic!("host publication never became reachable: {error}"),
        }
    }
    let status = child
        .kill_and_wait()
        .await
        .expect("kill supervisor process");
    assert!(!status.success(), "kill must end target process");

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match TcpStream::connect_timeout(&host, Duration::from_millis(100)) {
            Err(_) => break,
            Ok(stream) if Instant::now() < deadline => {
                drop(stream);
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(stream) => {
                drop(stream);
                panic!("killed supervisor left host publication reachable");
            }
        }
    }
}
