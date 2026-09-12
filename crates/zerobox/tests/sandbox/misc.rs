use crate::support::*;

#[cfg(unix)]
fn run_with_status_fd(args: &[&str]) -> (Output, String) {
    let mut command = Command::new(zerobox_exec());
    command.args(args);
    run_command_with_status_fd(command)
}

#[cfg(unix)]
fn run_command_with_status_fd(mut command: Command) -> (Output, String) {
    if command.get_current_dir().is_none() {
        command.current_dir("/tmp");
    }
    use std::io::Read;
    use std::os::fd::FromRawFd;
    use std::os::unix::process::CommandExt;

    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    let read_fd = fds[0];
    let write_fd = fds[1];
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(write_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if write_fd != 3 && libc::close(write_fd) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command.output().expect("failed to spawn zerobox");
    unsafe { libc::close(write_fd) };
    let mut status = String::new();
    unsafe { std::fs::File::from_raw_fd(read_fd) }
        .read_to_string(&mut status)
        .expect("read status");
    (output, status)
}

#[cfg(target_os = "linux")]
#[test]
fn runtime_artifacts_survive_workspace_mounts_and_dynamic_denies() {
    let workspace = temp_dir();
    let zerobox_home = workspace.path().join(".zerobox");
    let staged_bin_dir = workspace.path().join("bin");
    let staged_zerobox = staged_bin_dir.join("zerobox");
    std::fs::create_dir_all(&staged_bin_dir).expect("create staged binary directory");
    std::fs::hard_link(zerobox_exec(), &staged_zerobox).expect("hard-link zerobox into workspace");

    let allow_write = format!("--allow-write={}", workspace.path().display());
    let mut command = Command::new(&staged_zerobox);
    command
        .current_dir(workspace.path())
        .env("ZEROBOX_HOME", &zerobox_home)
        .args([
            "--status-fd=3",
            "--profile=analysis-strict",
            "--allow-read=/",
            allow_write.as_str(),
            "--deny-write-glob=*.pem",
            "--",
            "/bin/sh",
            "-c",
            "printf allowed > allowed.txt && ! printf blocked > secret.pem 2>/dev/null && test ! -e secret.pem",
        ]);

    let (output, status) = run_command_with_status_fd(command);
    assert!(
        output.status.success(),
        "stderr: {}\nstatus: {status}",
        stderr(&output)
    );
    assert_eq!(
        std::fs::read_to_string(workspace.path().join("allowed.txt")).unwrap(),
        "allowed"
    );
    assert!(!workspace.path().join("secret.pem").exists());

    assert!(output.stdout.is_empty());
    let events: Vec<serde_json::Value> = status
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSONL lifecycle event"))
        .collect();
    assert_eq!(events[0]["event"], "child_started");
    assert_eq!(events[1]["event"], "child_exit");
    assert_eq!(events[1]["code"], 0);
}

#[cfg(unix)]
#[test]
fn status_fd_rejects_read_only_descriptor_with_setup_exit() {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let read_only = std::fs::File::open("/dev/null").expect("open read-only");
    let fd = read_only.as_raw_fd();
    let mut command = Command::new(zerobox_exec());
    command.args(["--status-fd=3", "--", "true"]);
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = command.output().expect("spawn");
    assert_eq!(out.status.code(), Some(125), "stderr: {}", stderr(&out));
}

#[cfg(unix)]
#[test]
fn status_fd_accepts_nonblocking_pipe_for_atomic_records() {
    use std::os::unix::process::CommandExt;
    let mut fds = [0; 2];
    assert_eq!(
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
        0
    );
    let write_fd = fds[1];
    let mut command = Command::new(zerobox_exec());
    command.current_dir("/tmp");
    command.args(["--status-fd=3", "--", "true"]);
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(write_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = command.output().expect("spawn");
    unsafe {
        libc::close(fds[0]);
        libc::close(write_fd);
    }
    assert!(out.status.success(), "stderr: {}", stderr(&out));
}

#[cfg(unix)]
#[test]
fn invalid_cli_arguments_emit_setup_error_when_status_is_enabled() {
    let (out, status) = run_with_status_fd(&[
        "--status-fd=3",
        "--definitely-not-a-valid-option",
        "--",
        "/__zerobox/runtime/bin/probe",
        "--version",
    ]);
    assert_eq!(out.status.code(), Some(125), "stderr: {}", stderr(&out));
    let event: serde_json::Value = serde_json::from_str(status.trim()).expect("JSONL setup event");
    assert_eq!(event["event"], "setup_error");
    assert_eq!(event["code"], "cli_parse");
}

#[cfg(unix)]
#[test]
fn status_fd_accepts_unix_stream_used_by_node_spawn() {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;

    let (mut reader, writer) = UnixStream::pair().expect("create status socket pair");
    let write_fd = writer.as_raw_fd();
    let mut command = Command::new(zerobox_exec());
    command.args(["--status-fd=3", "--allow-all", "--", "true"]);
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(write_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = command.output().expect("spawn");
    drop(writer);
    let mut status = String::new();
    std::io::Read::read_to_string(&mut reader, &mut status).expect("read status socket");

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let events: Vec<serde_json::Value> = status
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSONL lifecycle event"))
        .collect();
    assert_eq!(events[0]["event"], "child_started");
    assert_eq!(events[1]["event"], "child_exit");
}

#[cfg(unix)]
#[test]
fn status_fd_rejects_tcp_stream_socket() {
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind TCP status listener");
    let client = TcpStream::connect(listener.local_addr().expect("TCP listener address"))
        .expect("connect TCP status client");
    let (_server, _) = listener.accept().expect("accept TCP status client");
    let write_fd = client.as_raw_fd();
    let mut command = Command::new(zerobox_exec());
    command.args(["--status-fd=3", "--allow-all", "--", "true"]);
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(write_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let out = command.output().expect("spawn TCP status check");
    assert_eq!(out.status.code(), Some(125), "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("AF_UNIX"), "stderr: {}", stderr(&out));
}

#[cfg(unix)]
#[test]
fn status_fd_rejects_non_stream_unix_socket() {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixDatagram;
    use std::os::unix::process::CommandExt;

    let (_reader, writer) = UnixDatagram::pair().expect("create datagram socket pair");
    let write_fd = writer.as_raw_fd();
    let mut command = Command::new(zerobox_exec());
    command.args(["--status-fd=3", "--allow-all", "--", "true"]);
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(write_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = command.output().expect("spawn datagram status check");
    assert_eq!(out.status.code(), Some(125), "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("SOCK_STREAM"));
}

#[cfg(unix)]
#[test]
fn full_status_pipe_does_not_block_after_target_start() {
    use std::io::Write;
    use std::os::fd::FromRawFd;
    use std::os::unix::process::CommandExt;

    let mut fds = [0; 2];
    assert_eq!(
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
        0
    );
    let read_fd = fds[0];
    let write_fd = fds[1];
    let mut writer = unsafe { std::fs::File::from_raw_fd(write_fd) };
    let block = [b'x'; 4096];
    loop {
        match writer.write_all(&block) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("fill status pipe: {error}"),
        }
    }
    let flags = unsafe { libc::fcntl(write_fd, libc::F_GETFL) };
    assert!(flags >= 0);
    assert_eq!(
        unsafe { libc::fcntl(write_fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) },
        0
    );

    let mut command = Command::new("timeout");
    command.args([
        "2s",
        zerobox_exec().to_str().expect("UTF-8 executable path"),
        "--status-fd=3",
        "--allow-all",
        "--",
        "sleep",
        "30",
    ]);
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(write_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = command.output().expect("spawn bounded status test");
    unsafe { libc::close(read_fd) };

    assert_eq!(out.status.code(), Some(125), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("child_started status event"),
        "expected an explicit status delivery failure: {}",
        stderr(&out)
    );
}

#[cfg(unix)]
#[test]
fn closed_status_reader_reaps_target_and_returns_setup_failure() {
    use std::os::unix::process::CommandExt;

    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    unsafe { libc::close(fds[0]) };
    let write_fd = fds[1];
    let mut command = Command::new("timeout");
    command.args([
        "2s",
        zerobox_exec().to_str().expect("UTF-8 executable path"),
        "--status-fd=3",
        "--allow-all",
        "--",
        "sleep",
        "30",
    ]);
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(write_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = command.output().expect("spawn");
    unsafe { libc::close(write_fd) };

    assert_eq!(out.status.code(), Some(125), "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("child_started status event"));
}

#[cfg(unix)]
#[test]
fn status_fd_reports_setup_error_as_jsonl_and_exit_125() {
    let (out, status) = run_with_status_fd(&[
        "--status-fd=3",
        "--strict-sandbox",
        "--allow-all",
        "--",
        "true",
    ]);
    assert_eq!(out.status.code(), Some(125), "stderr: {}", stderr(&out));
    let event: serde_json::Value = serde_json::from_str(status.trim()).expect("JSONL setup event");
    assert_eq!(event["version"], 1);
    assert_eq!(event["event"], "setup_error");
}

#[cfg(unix)]
#[test]
fn status_v2_keeps_the_child_lifecycle_protocol_and_uses_version_two() {
    let (out, status) = run_with_status_fd(&[
        "--status-fd=3",
        "--status-version=2",
        "--allow-all",
        "--",
        "true",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    let events: Vec<serde_json::Value> = status
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSONL lifecycle event"))
        .collect();
    assert_eq!(events[0]["version"], 2);
    assert_eq!(events[0]["event"], "child_started");
}

#[cfg(target_os = "linux")]
#[test]
fn admission_record_is_closed_and_advertised_before_a_child_can_start() {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    use std::os::fd::FromRawFd;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    use std::path::Path;

    let bundle = tempfile::tempdir().unwrap();
    let shell = bundle.path().join("components/shell/bin");
    let helper = bundle.path().join("helper");
    std::fs::create_dir_all(&shell).unwrap();
    std::fs::create_dir_all(bundle.path().join("components/shell/libexec")).unwrap();
    std::fs::create_dir(&helper).unwrap();
    std::fs::write(shell.join("bash"), b"bash").unwrap();
    std::fs::write(shell.join("env"), b"env").unwrap();
    std::fs::set_permissions(shell.join("bash"), std::fs::Permissions::from_mode(0o500)).unwrap();
    std::fs::set_permissions(shell.join("env"), std::fs::Permissions::from_mode(0o500)).unwrap();
    let static_helper = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/x86_64-unknown-linux-gnu/release/zerobox");
    assert!(
        static_helper.is_file(),
        "missing static helper: {}",
        static_helper.display()
    );
    std::fs::copy(&static_helper, helper.join("zerobox-linux-sandbox")).unwrap();
    std::fs::copy(&static_helper, shell.join("probe")).unwrap();
    std::fs::copy(
        &static_helper,
        bundle
            .path()
            .join("components/shell/libexec/zerobox-linux-sandbox"),
    )
    .unwrap();
    std::fs::set_permissions(
        helper.join("zerobox-linux-sandbox"),
        std::fs::Permissions::from_mode(0o500),
    )
    .unwrap();
    std::fs::set_permissions(shell.join("probe"), std::fs::Permissions::from_mode(0o500)).unwrap();
    let digest = |bytes: &[u8]| format!("{:x}", Sha256::digest(bytes));
    std::fs::write(
        bundle.path().join("manifest.json"),
        format!(
            r#"{{"schema":1,"target":"x86_64-unknown-linux-gnu","version":"test","components":{{"shell":{{"root":"components/shell","files":[{{"path":"bin/bash","sha256":"{}"}},{{"path":"bin/env","sha256":"{}"}},{{"path":"bin/probe","sha256":"{}"}},{{"path":"libexec/zerobox-linux-sandbox","sha256":"{}"}}]}},"analysis":{{"root":"components/analysis","files":[]}}}},"helper":{{"path":"helper/zerobox-linux-sandbox","sha256":"{}"}}}}"#,
            digest(b"bash"),
            digest(b"env"),
            digest(&std::fs::read(&static_helper).unwrap()),
            digest(&std::fs::read(&static_helper).unwrap()),
            digest(&std::fs::read(&static_helper).unwrap())
        ),
    )
    .unwrap();

    let run = |accept: bool| {
        use std::io::Write;
        let mut status_fds = [0; 2];
        let mut admission_fds = [0; 2];
        let mut ack_fds = [0; 2];
        for pipe in [&mut status_fds, &mut admission_fds, &mut ack_fds] {
            assert_eq!(
                unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
                0
            );
        }
        let mut command = Command::new(zerobox_exec());
        command
            .current_dir("/tmp")
            .args([
                "--status-fd=3",
                "--status-version=2",
                "--admission-fd=4",
                "--admission-ack-fd=5",
                "--runtime-bundle",
                bundle.path().to_str().unwrap(),
                "--runtime-component=shell",
                "--",
                "/__zerobox/runtime/bin/probe",
                "--version",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let status_write = status_fds[1];
        let admission_write = admission_fds[1];
        let ack_read = ack_fds[0];
        // Move the inherited inputs above the destination slots before dup2.
        // Otherwise assigning FD 3/4 can clobber the original FD 5 source.
        unsafe {
            command.pre_exec(move || {
                let inputs = [status_write, admission_write, ack_read]
                    .map(|fd| libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10));
                if inputs.iter().any(|fd| *fd < 0) {
                    return Err(std::io::Error::last_os_error());
                }
                for (source, target) in inputs.into_iter().zip([3, 4, 5]) {
                    if libc::dup2(source, target) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    libc::close(source);
                }
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        unsafe {
            libc::close(status_write);
            libc::close(admission_write);
            libc::close(ack_read);
        }
        let mut admission = Vec::new();
        unsafe { std::fs::File::from_raw_fd(admission_fds[0]) }
            .read_to_end(&mut admission)
            .unwrap();
        assert!(
            !admission.is_empty(),
            "engine must emit admission before waiting for acknowledgement"
        );
        let expected = if accept {
            format!("{:x}", Sha256::digest(&admission))
        } else {
            "0".repeat(64)
        };
        let mut ack = unsafe { std::fs::File::from_raw_fd(ack_fds[1]) };
        ack.write_all(format!("ACK:{expected}\n").as_bytes())
            .unwrap();
        drop(ack);
        let output = child.wait_with_output().unwrap();
        let mut status = String::new();
        unsafe { std::fs::File::from_raw_fd(status_fds[0]) }
            .read_to_string(&mut status)
            .unwrap();
        (output, status, admission)
    };
    let (rejected, rejection_status, _) = run(false);
    assert_eq!(rejected.status.code(), Some(125));
    assert!(
        rejected.stdout.is_empty(),
        "target ran before admission acknowledgement"
    );
    assert!(!rejection_status.contains("child_started"));
    let (output, status, admission) = run(true);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        String::from_utf8(output.stdout.clone()).unwrap(),
        format!("zerobox {}\n", env!("CARGO_PKG_VERSION"))
    );
    let events: Vec<serde_json::Value> = status
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        events[0]["event"],
        "sandbox_admitted",
        "{}",
        stderr(&output)
    );
    assert_eq!(
        events[0]["report_sha256"],
        format!("{:x}", Sha256::digest(&admission))
    );
    assert_eq!(events[1]["event"], "child_started");
    let receipt: serde_json::Value = serde_json::from_slice(&admission).unwrap();
    assert_eq!(receipt["runtime"]["component"], "shell");
    let observed = receipt["kernelMounts"]
        .as_array()
        .expect("kernel mount evidence");
    assert!(
        observed
            .iter()
            .any(|mount| mount["destination"] == "/__zerobox/runtime" && mount["access"] == "ro")
    );
    assert!(
        !observed
            .iter()
            .any(|mount| mount["destination"] == "/__zerobox/analysis")
    );
    assert_eq!(
        receipt["home"],
        serde_json::json!({"path":"/home/sandbox","namespace":"lease-private"})
    );
    assert_eq!(
        receipt["tmp"],
        serde_json::json!({"path":"/tmp","namespace":"lease-private"})
    );
    assert_eq!(receipt["environment"]["inherit"], serde_json::json!([]));
    assert_eq!(
        receipt["path"],
        serde_json::json!(["/__zerobox/runtime/bin"])
    );
}

#[cfg(target_os = "linux")]
#[test]
fn runtime_bundle_missing_manifest_fails_before_host_command_fallback() {
    let missing = tempfile::tempdir().unwrap();
    let output = run(&[
        "--runtime-bundle",
        missing.path().to_str().unwrap(),
        "--runtime-component=shell",
        "--",
        "true",
    ]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("runtime manifest"),
        "{}",
        stderr(&output)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn private_tmp_maps_session_storage_without_exposing_host_tmp() {
    let session = temp_dir();
    let sibling = temp_dir();
    let host_marker = session.path().join("host-only");
    std::fs::write(&host_marker, "host").unwrap();
    let private = session.path().join("private");
    std::fs::create_dir(&private).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
    let command = format!(
        "test \"$TMPDIR\" = /tmp && test ! -e '{}' && test ! -e '{}' && printf private >/tmp/owned && test \"$(cat /tmp/owned)\" = private",
        host_marker.display(),
        sibling.path().display(),
    );
    let out = run(&[
        "--profile=analysis-strict",
        "--allow-read=/",
        "--deny-read=/tmp",
        "-C",
        env!("CARGO_MANIFEST_DIR"),
        &format!("--private-tmp={}", private.display()),
        "--",
        "/bin/sh",
        "-c",
        &command,
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        std::fs::read_to_string(private.join("owned")).unwrap(),
        "private"
    );
    assert_eq!(std::fs::read_to_string(host_marker).unwrap(), "host");
    assert!(!sibling.path().join("owned").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn private_tmp_uses_preopened_source_when_lease_parent_is_denied() {
    let workspace = tempfile::Builder::new()
        .prefix("private-tmp-denied-parent-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("create workspace fixture");
    let project = workspace.path().join("project");
    let lease_parent = workspace.path().join("lease");
    let private = lease_parent.join("tmp");
    let sibling = lease_parent.join("sibling");
    std::fs::create_dir_all(&project).expect("create project");
    std::fs::create_dir_all(&private).expect("create private tmp");
    std::fs::create_dir_all(&sibling).expect("create sibling");
    std::fs::write(project.join("allowed"), "project").expect("write project fixture");
    std::fs::write(private.join("lease"), "lease").expect("write private fixture");
    std::fs::write(sibling.join("secret"), "secret").expect("write sibling fixture");

    let command = format!(
        "test \"$(cat /tmp/lease)\" = lease || {{ echo private-tmp >&2; exit 10; }}; \\
         test \"$(cat {}/allowed)\" = project || {{ echo project-read >&2; exit 11; }}; \\
         test ! -e {}/secret || {{ echo sibling-visible >&2; exit 12; }}; \\
         test ! -e {}/lease || {{ echo source-visible >&2; exit 13; }}; \\
         test -d /proc/$$/fd || {{ echo fd-inspection-unavailable >&2; exit 14; }}; \\
         for fd in /proc/$$/fd/*; do \\
             target=$(readlink \"$fd\") || {{ echo fd-readlink-failed:\"$fd\" >&2; exit 15; }}; \\
             test \"$target\" != {} || {{ echo fd-source-leaked:\"$fd\" >&2; exit 17; }}; \\
         done",
        project.display(),
        sibling.display(),
        private.display(),
        private.display(),
    );
    let allow_read = format!("--allow-read={},/usr", project.display());
    let deny_lease_parent = format!("--deny-read={}", lease_parent.display());
    let private_tmp = format!("--private-tmp={}", private.display());
    let out = run(&[
        "--profile=analysis-strict",
        "--allow-local-binding",
        allow_read.as_str(),
        deny_lease_parent.as_str(),
        "--deny-read-glob=*.pem",
        "-C",
        project.to_str().expect("UTF-8 project path"),
        private_tmp.as_str(),
        "--",
        "/bin/sh",
        "-c",
        &command,
    ]);

    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        std::fs::read_to_string(private.join("lease")).unwrap(),
        "lease"
    );
    assert_eq!(
        std::fs::read_to_string(sibling.join("secret")).unwrap(),
        "secret"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn private_home_uses_preopened_source_when_lease_parent_is_denied() {
    let workspace = tempfile::Builder::new()
        .prefix("private-home-denied-parent-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("create workspace fixture");
    let project = workspace.path().join("project");
    let lease_parent = project.join("lease");
    let private = lease_parent.join("home");
    let sibling = lease_parent.join("sibling");
    std::fs::create_dir_all(&project).expect("create project");
    std::fs::create_dir_all(&private).expect("create private home");
    std::fs::create_dir_all(&sibling).expect("create sibling");
    std::fs::write(project.join("allowed"), "project").expect("write project fixture");
    std::fs::write(private.join("lease"), "lease").expect("write private fixture");
    std::fs::write(sibling.join("secret"), "secret").expect("write sibling fixture");

    let command = format!(
        "test \"$(cat /home/sandbox/lease)\" = lease || {{ echo private-home >&2; exit 10; }}; \\
         test \"$(cat {}/allowed)\" = project || {{ echo project-read >&2; exit 11; }}; \\
         test ! -e {}/secret || {{ echo sibling-visible >&2; exit 12; }}; \\
         test ! -e {}/lease || {{ echo source-visible >&2; exit 13; }}; \\
         test -d /proc/$$/fd || {{ echo fd-inspection-unavailable >&2; exit 14; }}; \\
         for fd in /proc/$$/fd/*; do \\
             target=$(readlink \"$fd\") || {{ echo fd-readlink-failed:\"$fd\" >&2; exit 15; }}; \\
             test \"$target\" != {} || {{ echo fd-source-leaked:\"$fd\" >&2; exit 17; }}; \\
         done; \\
         mkdir -p /home/sandbox/.cache && printf 'cache\\n' > /home/sandbox/.cache/item",
        project.display(),
        sibling.display(),
        private.display(),
        private.display(),
    );
    let allow_read = format!("--allow-read={},/usr", project.display());
    let deny_lease_parent = format!("--deny-read={}", lease_parent.display());
    let private_home = format!("--private-home={}", private.display());
    let out = run(&[
        "--profile=analysis-strict",
        "--allow-local-binding",
        allow_read.as_str(),
        deny_lease_parent.as_str(),
        "--deny-read-glob=*.pem",
        "-C",
        project.to_str().expect("UTF-8 project path"),
        private_home.as_str(),
        "--",
        "/bin/sh",
        "-c",
        &command,
    ]);

    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        std::fs::read_to_string(private.join("lease")).unwrap(),
        "lease"
    );
    assert_eq!(
        std::fs::read_to_string(private.join(".cache/item")).unwrap(),
        "cache\n"
    );
    assert_eq!(
        std::fs::read_to_string(sibling.join("secret")).unwrap(),
        "secret"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn private_tmp_rejects_symlink_and_non_directory_sources() {
    let workspace = tempfile::Builder::new()
        .prefix("private-tmp-invalid-source-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("create workspace fixture");
    let directory = workspace.path().join("directory");
    let symlink = workspace.path().join("symlink");
    let file = workspace.path().join("file");
    std::fs::create_dir(&directory).expect("create source directory");
    std::os::unix::fs::symlink(&directory, &symlink).expect("create source symlink");
    std::fs::write(&file, "not a directory").expect("create source file");

    for source in [&symlink, &file] {
        let private_tmp = format!("--private-tmp={}", source.display());
        let out = run(&[
            "--profile=analysis-strict",
            "--allow-read=/usr",
            "-C",
            env!("CARGO_MANIFEST_DIR"),
            private_tmp.as_str(),
            "--",
            "/bin/true",
        ]);
        assert!(
            !out.status.success(),
            "unexpected success for {}",
            source.display()
        );
        assert!(
            stderr(&out).contains("private /tmp source")
                || stderr(&out).contains("private proxy directory"),
            "unexpected error for {}: {}",
            source.display(),
            stderr(&out)
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn private_home_rejects_symlink_and_non_directory_sources() {
    let workspace = tempfile::Builder::new()
        .prefix("private-home-invalid-source-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("create workspace fixture");
    let directory = workspace.path().join("directory");
    let symlink = workspace.path().join("symlink");
    let file = workspace.path().join("file");
    std::fs::create_dir(&directory).expect("create source directory");
    std::os::unix::fs::symlink(&directory, &symlink).expect("create source symlink");
    std::fs::write(&file, "not a directory").expect("create source file");
    for source in [&symlink, &file] {
        let private_home = format!("--private-home={}", source.display());
        let out = run(&[
            "--profile=analysis-strict",
            "--allow-read=/usr",
            "-C",
            env!("CARGO_MANIFEST_DIR"),
            private_home.as_str(),
            "--",
            "/bin/true",
        ]);
        assert!(
            !out.status.success(),
            "unexpected success for {}",
            source.display()
        );
        assert!(
            stderr(&out).contains("private HOME source"),
            "{}",
            stderr(&out)
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn exact_unix_socket_allows_its_service_but_not_a_neighbor_in_the_project() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let workspace = tempfile::Builder::new()
        .prefix("exact-unix-socket-")
        // sockaddr_un is capped at 108 bytes. This is a host-side fixture
        // directory only; the sandbox receives the project path explicitly.
        .tempdir()
        .expect("create workspace fixture");
    let project = workspace.path().join("project");
    let allowed = project.join("allowed.sock");
    let neighbor = project.join("neighbor.sock");
    let alias = project.join("allowed-alias.sock");
    std::fs::create_dir_all(&project).expect("create project");

    let listener = UnixListener::bind(&allowed).expect("bind allowed service socket");
    std::os::unix::fs::symlink(&allowed, &alias).expect("create socket alias");
    listener
        .set_nonblocking(true)
        .expect("make allowed listener nonblocking");
    let neighbor_listener = UnixListener::bind(&neighbor).expect("bind neighbor service socket");
    neighbor_listener
        .set_nonblocking(true)
        .expect("make neighbor listener nonblocking");
    let (served_tx, served_rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut request = [0_u8; 4];
                    stream
                        .read_exact(&mut request)
                        .expect("read allowed request");
                    assert_eq!(&request, b"ping");
                    stream.write_all(b"pong").expect("write allowed response");
                    served_tx.send(()).expect("report allowed service use");
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        panic!("allowed service was never reached");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept allowed service: {error}"),
            }
        }
    });
    let (neighbor_tx, neighbor_rx) = mpsc::channel();
    let neighbor_server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match neighbor_listener.accept() {
                Ok(_) => {
                    neighbor_tx.send(true).expect("report neighbor reception");
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        neighbor_tx.send(false).expect("report neighbor refusal");
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept neighbor service: {error}"),
            }
        }
    });

    let script = format!(
        r#"import os
import socket
allowed = {allowed:?}
neighbor = {neighbor:?}
alias = {alias:?}
for fd in os.listdir("/proc/self/fd"):
    try:
        inherited = os.readlink(f"/proc/self/fd/{{fd}}")
    except FileNotFoundError:
        continue
    if inherited == allowed:
        raise SystemExit("exact-socket-source-fd-leaked")
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(1)
s.connect(allowed)
s.sendall(b"ping")
assert s.recv(4) == b"pong"
s.close()
neighbor_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
neighbor_socket.settimeout(1)
try:
    neighbor_socket.connect(neighbor)
except OSError:
    print("neighbor-denied")
else:
    raise SystemExit("neighbor-reachable")
alias_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
alias_socket.settimeout(1)
try:
    alias_socket.connect(alias)
except OSError:
    print("alias-denied")
else:
    raise SystemExit("alias-reachable")
"#,
        allowed = allowed.display(),
        neighbor = neighbor.display(),
        alias = alias.display(),
    );
    let allow_read = format!("--allow-read={},/usr", project.display());
    let allow_socket = format!("--allow-unix-socket={}", allowed.display());
    let out = run(&[
        "--profile=analysis-strict",
        allow_read.as_str(),
        allow_socket.as_str(),
        "-C",
        project.to_str().expect("UTF-8 project path"),
        "--",
        "/usr/bin/python3",
        "-c",
        &script,
    ]);

    let neighbor_was_reached = neighbor_rx
        .recv_timeout(Duration::from_secs(4))
        .expect("neighbor listener result");
    neighbor_server.join().expect("neighbor service thread");
    served_rx
        .recv_timeout(Duration::from_secs(4))
        .expect("allowed service must exchange bytes");
    server.join().expect("allowed service thread");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "neighbor-denied\nalias-denied");
    assert!(
        !neighbor_was_reached,
        "neighbor socket received a connection"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn exact_unix_socket_keeps_host_tmp_neighbors_unreachable() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let workspace = tempfile::Builder::new()
        .prefix("exact-unix-socket-host-tmp-")
        // sockaddr_un is capped at 108 bytes. This is a host-side fixture
        // directory only; the sandbox receives the project path explicitly.
        .tempdir()
        .expect("create workspace fixture");
    let project = workspace.path().to_path_buf();
    let shared_tmp = project.parent().expect("shared host temp root");
    let allowed = project.join("allowed.sock");
    let neighbor = project.join("neighbor.sock");
    let alias = project.join("allowed-alias.sock");

    let listener = UnixListener::bind(&allowed).expect("bind allowed service socket");
    std::os::unix::fs::symlink(&allowed, &alias).expect("create socket alias");
    listener
        .set_nonblocking(true)
        .expect("make allowed listener nonblocking");
    let neighbor_listener = UnixListener::bind(&neighbor).expect("bind neighbor service socket");
    neighbor_listener
        .set_nonblocking(true)
        .expect("make neighbor listener nonblocking");
    let (served_tx, served_rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut request = [0_u8; 4];
                    stream
                        .read_exact(&mut request)
                        .expect("read allowed request");
                    assert_eq!(&request, b"ping");
                    stream.write_all(b"pong").expect("write allowed response");
                    served_tx.send(()).expect("report allowed service use");
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        panic!("allowed service was never reached");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept allowed service: {error}"),
            }
        }
    });
    let (neighbor_tx, neighbor_rx) = mpsc::channel();
    let neighbor_server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match neighbor_listener.accept() {
                Ok(_) => {
                    neighbor_tx.send(true).expect("report neighbor reception");
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        neighbor_tx.send(false).expect("report neighbor refusal");
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept neighbor service: {error}"),
            }
        }
    });

    let script = format!(
        r#"import socket
allowed = {allowed:?}
neighbor = {neighbor:?}
alias = {alias:?}
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(1)
s.connect(allowed)
s.sendall(b"ping")
assert s.recv(4) == b"pong"
s.close()
neighbor_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
neighbor_socket.settimeout(1)
try:
    neighbor_socket.connect(neighbor)
except OSError:
    print("neighbor-denied")
else:
    raise SystemExit("neighbor-reachable")
alias_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
alias_socket.settimeout(1)
try:
    alias_socket.connect(alias)
except OSError:
    print("alias-denied")
else:
    raise SystemExit("alias-reachable")
"#,
        allowed = allowed.display(),
        neighbor = neighbor.display(),
        alias = alias.display(),
    );
    let allow_read = format!("--allow-read={},/usr", shared_tmp.display());
    let allow_socket = format!("--allow-unix-socket={}", allowed.display());
    let out = run(&[
        "--profile=analysis-strict",
        allow_read.as_str(),
        allow_socket.as_str(),
        "-C",
        project.to_str().expect("UTF-8 project path"),
        "--",
        "/usr/bin/python3",
        "-c",
        &script,
    ]);

    let neighbor_was_reached = neighbor_rx
        .recv_timeout(Duration::from_secs(4))
        .expect("neighbor listener result");
    neighbor_server.join().expect("neighbor service thread");
    served_rx
        .recv_timeout(Duration::from_secs(4))
        .expect("allowed service must exchange bytes");
    server.join().expect("allowed service thread");
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "neighbor-denied\nalias-denied");
    assert!(
        !neighbor_was_reached,
        "neighbor socket received a connection"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn exact_unix_socket_keeps_host_abstract_unreachable_and_allows_private_streams() {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::net::UnixListener;

    fn bind_host_abstract(name: &[u8]) -> OwnedFd {
        assert!(!name.is_empty());
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        assert!(
            fd >= 0,
            "create host abstract listener: {}",
            std::io::Error::last_os_error()
        );
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (index, byte) in name.iter().enumerate() {
            address.sun_path[index + 1] = *byte as libc::c_char;
        }
        let length = (std::mem::size_of::<libc::sa_family_t>() + 1 + name.len()) as libc::socklen_t;
        assert_eq!(
            unsafe { libc::bind(fd, (&raw const address).cast(), length) },
            0,
            "bind host abstract listener: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(
            unsafe { libc::listen(fd, 1) },
            0,
            "listen host abstract listener: {}",
            std::io::Error::last_os_error()
        );
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert!(
            flags >= 0,
            "get listener flags: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0,
            "make host abstract listener nonblocking: {}",
            std::io::Error::last_os_error()
        );
        unsafe { OwnedFd::from_raw_fd(fd) }
    }

    let fixture_name = format!("abstract-private-{}", std::process::id());
    let project = setup_tmp(&fixture_name);
    let allowed = project.join("activation.sock");
    let activation_listener = UnixListener::bind(&allowed).expect("bind exact socket activation");
    let abstract_name = format!("zerobox-abstract-{}", std::process::id());
    let host_listener = bind_host_abstract(abstract_name.as_bytes());

    let script = format!(
        r#"import socket
name = "\0{abstract_name}"
host = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
host.setblocking(False)
if host.connect_ex(name) == 0:
    raise SystemExit("host-abstract-reachable")
print("host-abstract-denied")
private = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
private.bind(name)
private.listen(1)
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(1)
client.connect(name)
private.settimeout(1)
accepted, _ = private.accept()
client.sendall(b"ping")
assert accepted.recv(4) == b"ping"
accepted.sendall(b"pong")
assert client.recv(4) == b"pong"
try:
    socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
except OSError:
    print("unix-dgram-denied")
else:
    raise SystemExit("unix-dgram-created")
"#,
        abstract_name = abstract_name,
    );
    let allow_read = format!("--allow-read={},/usr", project.display());
    let allow_socket = format!("--allow-unix-socket={}", allowed.display());
    let out = run(&[
        "--profile=analysis-strict",
        allow_read.as_str(),
        allow_socket.as_str(),
        "-C",
        project.to_str().expect("UTF-8 project path"),
        "--",
        "/usr/bin/python3",
        "-c",
        &script,
    ]);

    let mut peer: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut peer_length = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    let accepted = unsafe {
        libc::accept4(
            host_listener.as_raw_fd(),
            (&raw mut peer).cast(),
            &raw mut peer_length,
            libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
        )
    };
    assert_eq!(accepted, -1, "sandbox reached the host abstract listener");
    assert_eq!(
        std::io::Error::last_os_error().kind(),
        std::io::ErrorKind::WouldBlock,
        "host abstract listener failure"
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        stdout(&out).trim(),
        "host-abstract-denied\nunix-dgram-denied"
    );
    drop(activation_listener);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn exact_unix_socket_replacement_fails_before_the_target_runs() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};
    use zerobox::Sandbox;

    let workspace = tempfile::tempdir().expect("create socket fixture");
    let project = workspace.path().join("project");
    let socket = project.join("service.sock");
    let marker = project.join("target-ran");
    std::fs::create_dir_all(&project).expect("create project");
    let listener = UnixListener::bind(&socket).expect("bind admitted service");
    listener
        .set_nonblocking(true)
        .expect("make admitted listener nonblocking");
    let original_listener = listener.try_clone().expect("clone admitted listener");
    let (original_tx, original_rx) = mpsc::channel();
    let original_server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_millis(750);
        loop {
            match original_listener.accept() {
                Ok((mut stream, _)) => {
                    let mut request = [0_u8; 4];
                    stream
                        .read_exact(&mut request)
                        .expect("read original request");
                    assert_eq!(&request, b"ping");
                    stream.write_all(b"pong").expect("write original response");
                    original_tx.send(true).expect("report original connection");
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        original_tx.send(false).expect("report original timeout");
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept original service: {error}"),
            }
        }
    });

    let script = format!(
        r#"from pathlib import Path
import socket
Path({marker:?}).write_text("ran")
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(1)
s.connect({socket:?})
s.sendall(b"ping")
assert s.recv(4) == b"pong"
"#,
        socket = socket.display(),
        marker = marker.display(),
    );
    let prepared = Sandbox::command("/usr/bin/python3")
        .args(&["-c", &script])
        .cwd(&project)
        .no_profile()
        .allow_read(&project)
        .allow_read("/usr")
        .allow_write(&project)
        .allow_unix_socket(&socket)
        .linux_sandbox_exe(zerobox_exec())
        .prepare()
        .await
        .expect("prepare exact socket sandbox");

    std::fs::remove_file(&socket).expect("unlink admitted service path");
    let replacement = UnixListener::bind(&socket).expect("bind replacement service");
    replacement
        .set_nonblocking(true)
        .expect("make replacement listener nonblocking");
    let (replacement_tx, replacement_rx) = mpsc::channel();
    let replacement_server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_millis(750);
        loop {
            match replacement.accept() {
                Ok(_) => {
                    replacement_tx
                        .send(true)
                        .expect("report replacement connection");
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        replacement_tx
                            .send(false)
                            .expect("report replacement refusal");
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept replacement service: {error}"),
            }
        }
    });

    let status = prepared
        .spawn()
        .await
        .expect("spawn prepared exact socket sandbox")
        .wait()
        .await
        .expect("wait for target");
    assert!(!status.success(), "target must not run after replacement");
    assert!(!marker.exists(), "target command ran after replacement");
    assert!(
        !replacement_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("replacement service result"),
        "replacement service received the request"
    );
    assert!(
        !original_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("original service result"),
        "removed service received the request"
    );
    original_server.join().expect("original service thread");
    replacement_server
        .join()
        .expect("replacement service thread");
    drop(listener);
}

#[cfg(target_os = "linux")]
#[test]
fn tcp_publication_forwards_host_loopback_without_network_egress() {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    fn unused_loopback_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("reserve loopback test port")
            .local_addr()
            .expect("read loopback test port")
            .port()
    }

    let workspace = tempfile::tempdir().expect("create publication fixture");
    let zerobox_home = workspace.path().join("zerobox-home");
    let project = workspace.path().join("project");
    std::fs::create_dir_all(&project).expect("create project");
    let host = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
    let publication = format!("host@{host}->{target}");
    let allow_read = format!("--allow-read={},/usr", project.display());
    let mut child = Command::new(zerobox_exec())
        .env("ZEROBOX_HOME", &zerobox_home)
        .args([
            "--profile=analysis-strict",
            allow_read.as_str(),
            "--publish-tcp",
            publication.as_str(),
            "-C",
            project.to_str().expect("UTF-8 project path"),
            "--",
            "/usr/bin/python3",
            "-c",
            &format!(
                r#"import socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(({target_ip:?}, {target_port}))
server.listen(1)
connection, _ = server.accept()
assert connection.recv(4) == b"ping"
connection.sendall(b"pong")
probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
probe.settimeout(.25)
try:
    probe.connect(("1.1.1.1", 53))
except OSError:
    print("egress-denied")
else:
    raise SystemExit("egress-reachable")
"#,
                target_ip = target.ip().to_string(),
                target_port = target.port(),
            ),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn publication candidate");

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut client = loop {
        match TcpStream::connect_timeout(&host, Duration::from_millis(100)) {
            Ok(stream) => break stream,
            Err(_) if Instant::now() < deadline => {
                if let Some(status) = child.try_wait().expect("inspect publication candidate") {
                    let output = child
                        .wait_with_output()
                        .expect("collect publication candidate");
                    panic!(
                        "publication exited before host listener became ready ({status}): {}",
                        stderr(&output)
                    );
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => {
                child.kill().expect("stop unpublished target");
                let output = child
                    .wait_with_output()
                    .expect("collect publication candidate");
                panic!(
                    "host publication never became reachable ({error}): {}",
                    stderr(&output)
                );
            }
        }
    };
    client
        .write_all(b"ping")
        .expect("write host publication request");
    let mut response = [0_u8; 4];
    client
        .read_exact(&mut response)
        .expect("read host publication response");
    assert_eq!(&response, b"pong");
    let output = child
        .wait_with_output()
        .expect("wait for publication target");
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output).trim(), "egress-denied");
}

#[cfg(target_os = "linux")]
#[test]
fn tcp_publication_propagates_server_eof_after_response() {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    fn unused_loopback_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("reserve loopback test port")
            .local_addr()
            .expect("read loopback test port")
            .port()
    }

    let workspace = tempfile::tempdir().expect("create EOF publication fixture");
    let zerobox_home = workspace.path().join("zerobox-home");
    let project = workspace.path().join("project");
    std::fs::create_dir_all(&project).expect("create project");
    let host = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
    let publication = format!("host@{host}->{target}");
    let allow_read = format!("--allow-read={},/usr", project.display());
    let mut child = Command::new(zerobox_exec())
        .env("ZEROBOX_HOME", &zerobox_home)
        .args([
            "--profile=analysis-strict",
            allow_read.as_str(),
            "--publish-tcp",
            publication.as_str(),
            "-C",
            project.to_str().expect("UTF-8 project path"),
            "--",
            "/usr/bin/python3",
            "-c",
            &format!(
                r#"import socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(({ip:?}, {port}))
server.listen(1)
connection, _ = server.accept()
assert connection.recv(4) == b"ping"
connection.sendall(b"pong")
connection.close()
server.close()
"#,
                ip = target.ip().to_string(),
                port = target.port(),
            ),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn EOF publication");

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut client = loop {
        match TcpStream::connect_timeout(&host, Duration::from_millis(100)) {
            Ok(stream) => break stream,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                child.kill().expect("stop unavailable EOF publication");
                let output = child.wait_with_output().expect("collect EOF publication");
                panic!(
                    "host publication never became reachable ({error}): {}",
                    stderr(&output)
                );
            }
        }
    };
    client
        .set_read_timeout(Some(Duration::from_millis(1500)))
        .expect("set EOF timeout");
    client.write_all(b"ping").expect("write EOF request");
    client
        .shutdown(std::net::Shutdown::Write)
        .expect("close client write side");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .expect("read response through EOF");
    assert_eq!(response, b"pong");
    let output = child.wait_with_output().expect("collect EOF publication");
    assert!(output.status.success(), "{}", stderr(&output));
}

#[cfg(target_os = "linux")]
#[test]
fn tcp_publication_does_not_reserve_the_host_port_before_private_listen() {
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};

    fn unused_loopback_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("reserve loopback test port")
            .local_addr()
            .expect("read loopback test port")
            .port()
    }

    let workspace = tempfile::tempdir().expect("create concurrent publication fixture");
    let zerobox_home = workspace.path().join("zerobox-home");
    let project = workspace.path().join("project");
    std::fs::create_dir_all(&project).expect("create project");
    let host = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
    let publication = format!("host@{host}->{target}");
    let allow_read = format!("--allow-read={},/usr", project.display());

    let spawn = |publication: String,
                 allow_read: String,
                 project: std::path::PathBuf,
                 zerobox_home: std::path::PathBuf| {
        std::thread::spawn(move || {
            Command::new(zerobox_exec())
                .env("ZEROBOX_HOME", zerobox_home)
                .args([
                    "--profile=analysis-strict",
                    allow_read.as_str(),
                    "--publish-tcp",
                    publication.as_str(),
                    "-C",
                    project.to_str().expect("UTF-8 project path"),
                    "--",
                    "/bin/pwd",
                ])
                .output()
                .expect("run unpublished publication candidate")
        })
    };

    let first = spawn(
        publication.clone(),
        allow_read.clone(),
        project.clone(),
        zerobox_home.clone(),
    );
    let second = spawn(publication, allow_read, project, zerobox_home);
    let first = first.join().expect("join first candidate");
    let second = second.join().expect("join second candidate");
    assert!(first.status.success(), "{}", stderr(&first));
    assert!(second.status.success(), "{}", stderr(&second));
}

#[cfg(target_os = "linux")]
#[test]
fn tcp_publication_two_independent_cli_runs_serve_concurrently() {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::process::{Child, Stdio};
    use std::time::{Duration, Instant};

    fn unused_loopback_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("reserve loopback test port")
            .local_addr()
            .expect("read loopback test port")
            .port()
    }

    fn stop(children: &mut [(Child, SocketAddr)]) {
        for (child, _) in children {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    for trial in 0..3 {
        let workspace = tempfile::tempdir().expect("create independent publication fixture");
        let mut children = Vec::new();
        for label in ["a", "b"] {
            let project = workspace.path().join(label).join("project");
            let zerobox_home = workspace.path().join(label).join("zerobox-home");
            std::fs::create_dir_all(&project).expect("create project");
            let host = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
            let target = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
            let publication = format!("host@{host}->{target}");
            let allow_read = format!("--allow-read={},/usr", project.display());
            let child = Command::new(zerobox_exec())
                .env("ZEROBOX_HOME", zerobox_home)
                .args([
                    "--profile=analysis-strict",
                    allow_read.as_str(),
                    "--publish-tcp",
                    publication.as_str(),
                    "-C",
                    project.to_str().expect("UTF-8 project path"),
                    "--",
                    "/usr/bin/python3",
                    "-c",
                    &format!(
                        r#"import socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(({ip:?}, {port}))
server.listen(1)
connection, _ = server.accept()
assert connection.recv(4) == b"ping"
connection.sendall(b"pong")
connection.close()
server.close()
"#,
                        ip = target.ip().to_string(),
                        port = target.port(),
                    ),
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn independent publication");
            children.push((child, host));
        }

        for index in 0..children.len() {
            let host = children[index].1;
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut client = loop {
                match TcpStream::connect_timeout(&host, Duration::from_millis(100)) {
                    Ok(stream) => break stream,
                    Err(_) if Instant::now() < deadline => {
                        if let Some(status) = children[index]
                            .0
                            .try_wait()
                            .expect("inspect independent publication")
                        {
                            stop(&mut children);
                            panic!(
                                "trial {trial} publication {index} exited before readiness ({status})"
                            );
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(error) => {
                        stop(&mut children);
                        panic!("trial {trial} publication {index} never became reachable: {error}");
                    }
                }
            };
            client
                .write_all(b"ping")
                .expect("write independent request");
            let mut response = [0_u8; 4];
            client
                .read_exact(&mut response)
                .expect("read independent response");
            assert_eq!(&response, b"pong");
        }
        for (child, _) in children {
            let output = child
                .wait_with_output()
                .expect("wait for independent publication");
            assert!(
                output.status.success(),
                "trial {trial} independent publication failed: {}",
                stderr(&output)
            );
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn tcp_publication_host_listener_conflict_stops_only_the_second_operation() {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    fn unused_loopback_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("reserve loopback test port")
            .local_addr()
            .expect("read loopback test port")
            .port()
    }

    let workspace = tempfile::tempdir().expect("create conflict publication fixture");
    let zerobox_home = workspace.path().join("zerobox-home");
    let project = workspace.path().join("project");
    std::fs::create_dir_all(&project).expect("create project");
    let host = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
    let first_target = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
    let second_target = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
    let allow_read = format!("--allow-read={},/usr", project.display());
    let first_publication = format!("host@{host}->{first_target}");
    let second_publication = format!("host@{host}->{second_target}");

    let mut first = Command::new(zerobox_exec())
        .env("ZEROBOX_HOME", &zerobox_home)
        .args([
            "--profile=analysis-strict",
            allow_read.as_str(),
            "--publish-tcp",
            first_publication.as_str(),
            "-C",
            project.to_str().expect("UTF-8 project path"),
            "--",
            "/usr/bin/python3",
            "-c",
            &format!(
                r#"import socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(({ip:?}, {port}))
server.listen(1)
connection, _ = server.accept()
assert connection.recv(4) == b"ping"
connection.sendall(b"pong")
"#,
                ip = first_target.ip().to_string(),
                port = first_target.port(),
            ),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn first publication");

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut first_client = loop {
        match TcpStream::connect_timeout(&host, Duration::from_millis(100)) {
            Ok(stream) => break stream,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                first.kill().expect("stop unavailable first publication");
                let output = first.wait_with_output().expect("collect first publication");
                panic!(
                    "first host publication never became reachable ({error}): {}",
                    stderr(&output)
                );
            }
        }
    };

    let mut second = Command::new(zerobox_exec())
        .env("ZEROBOX_HOME", &zerobox_home)
        .args([
            "--profile=analysis-strict",
            allow_read.as_str(),
            "--publish-tcp",
            second_publication.as_str(),
            "-C",
            project.to_str().expect("UTF-8 project path"),
            "--",
            "/usr/bin/python3",
            "-c",
            &format!(
                r#"import socket, time
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(({ip:?}, {port}))
server.listen(1)
time.sleep(5)
"#,
                ip = second_target.ip().to_string(),
                port = second_target.port(),
            ),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn conflicting publication");

    let deadline = Instant::now() + Duration::from_secs(3);
    let second_output = loop {
        if let Some(status) = second.try_wait().expect("inspect conflicting publication") {
            let output = second
                .wait_with_output()
                .expect("collect conflicting publication");
            assert!(
                !status.success(),
                "conflicting publication unexpectedly succeeded"
            );
            break output;
        }
        if Instant::now() >= deadline {
            second.kill().expect("stop conflicting publication");
            let output = second
                .wait_with_output()
                .expect("collect timed out conflicting publication");
            panic!(
                "conflicting publication did not stop after the host bind conflict: {}",
                stderr(&output)
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(
        !second_output.status.success(),
        "{}",
        stderr(&second_output)
    );

    first_client
        .write_all(b"ping")
        .expect("write first publication request");
    let mut response = [0_u8; 4];
    first_client
        .read_exact(&mut response)
        .expect("read first publication response");
    assert_eq!(&response, b"pong");
    let first_output = first.wait_with_output().expect("collect first publication");
    assert!(first_output.status.success(), "{}", stderr(&first_output));
}

#[cfg(target_os = "linux")]
#[test]
fn tcp_publication_closes_the_host_listener_after_private_listener_exits() {
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    fn unused_loopback_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("reserve loopback test port")
            .local_addr()
            .expect("read loopback test port")
            .port()
    }

    let workspace = tempfile::tempdir().expect("create cleanup publication fixture");
    let zerobox_home = workspace.path().join("zerobox-home");
    let project = workspace.path().join("project");
    std::fs::create_dir_all(&project).expect("create project");
    let host = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
    let publication = format!("host@{host}->{target}");
    let allow_read = format!("--allow-read={},/usr", project.display());
    let mut child = Command::new(zerobox_exec())
        .env("ZEROBOX_HOME", &zerobox_home)
        .args([
            "--profile=analysis-strict",
            allow_read.as_str(),
            "--publish-tcp",
            publication.as_str(),
            "-C",
            project.to_str().expect("UTF-8 project path"),
            "--",
            "/usr/bin/python3",
            "-c",
            &format!(
                r#"import socket, time
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(({ip:?}, {port}))
server.listen(1)
time.sleep(.5)
"#,
                ip = target.ip().to_string(),
                port = target.port(),
            ),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cleanup publication");

    let deadline = Instant::now() + Duration::from_secs(3);
    let initial_connection = loop {
        match TcpStream::connect_timeout(&host, Duration::from_millis(100)) {
            Ok(stream) => break stream,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                child.kill().expect("stop unavailable cleanup publication");
                let output = child
                    .wait_with_output()
                    .expect("collect cleanup publication");
                panic!(
                    "host publication never became reachable ({error}): {}",
                    stderr(&output)
                );
            }
        }
    };
    drop(initial_connection);
    let output = child
        .wait_with_output()
        .expect("collect cleanup publication");
    assert!(output.status.success(), "{}", stderr(&output));

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
                panic!("host publication remained reachable after the private listener exited");
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn tcp_publication_forwards_ipv6_loopback() {
    use std::io::{Read, Write};
    use std::net::{Ipv6Addr, SocketAddr, TcpListener, TcpStream};
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    fn unused_loopback_port() -> u16 {
        TcpListener::bind((Ipv6Addr::LOCALHOST, 0))
            .expect("reserve IPv6 loopback test port")
            .local_addr()
            .expect("read IPv6 loopback test port")
            .port()
    }

    let workspace = tempfile::tempdir().expect("create IPv6 publication fixture");
    let zerobox_home = workspace.path().join("zerobox-home");
    let project = workspace.path().join("project");
    std::fs::create_dir_all(&project).expect("create project");
    let host = SocketAddr::from((Ipv6Addr::LOCALHOST, unused_loopback_port()));
    let target = SocketAddr::from((Ipv6Addr::LOCALHOST, unused_loopback_port()));
    let publication = format!("host@{host}->{target}");
    let allow_read = format!("--allow-read={},/usr", project.display());
    let mut child = Command::new(zerobox_exec())
        .env("ZEROBOX_HOME", &zerobox_home)
        .args([
            "--profile=analysis-strict",
            allow_read.as_str(),
            "--publish-tcp",
            publication.as_str(),
            "-C",
            project.to_str().expect("UTF-8 project path"),
            "--",
            "/usr/bin/python3",
            "-c",
            &format!(
                r#"import socket
server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(({ip:?}, {port}))
server.listen(1)
connection, _ = server.accept()
assert connection.recv(2) == b"v6"
connection.sendall(b"ok")
"#,
                ip = target.ip().to_string(),
                port = target.port(),
            ),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn IPv6 publication");

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut client = loop {
        match TcpStream::connect_timeout(&host, Duration::from_millis(100)) {
            Ok(stream) => break stream,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                child.kill().expect("stop unavailable IPv6 publication");
                let output = child.wait_with_output().expect("collect IPv6 publication");
                panic!(
                    "IPv6 host publication never became reachable ({error}): {}",
                    stderr(&output)
                );
            }
        }
    };
    client.write_all(b"v6").expect("write IPv6 request");
    let mut response = [0_u8; 2];
    client
        .read_exact(&mut response)
        .expect("read IPv6 response");
    assert_eq!(&response, b"ok");
    let output = child.wait_with_output().expect("collect IPv6 publication");
    assert!(output.status.success(), "{}", stderr(&output));
}

#[cfg(target_os = "linux")]
#[test]
fn tcp_publications_activate_later_listener_without_misreading_first_traffic() {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    fn unused_loopback_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("reserve loopback test port")
            .local_addr()
            .expect("read loopback test port")
            .port()
    }

    let workspace = tempfile::tempdir().expect("create staged publication fixture");
    let zerobox_home = workspace.path().join("zerobox-home");
    let project = workspace.path().join("project");
    std::fs::create_dir_all(&project).expect("create project");
    let first_host = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
    let second_host = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
    let first_target = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
    let second_target = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
    let first_publication = format!("host@{first_host}->{first_target}");
    let second_publication = format!("host@{second_host}->{second_target}");
    let allow_read = format!("--allow-read={},/usr", project.display());
    let mut child = Command::new(zerobox_exec())
        .env("ZEROBOX_HOME", &zerobox_home)
        .args([
            "--profile=analysis-strict",
            allow_read.as_str(),
            "--publish-tcp",
            first_publication.as_str(),
            "--publish-tcp",
            second_publication.as_str(),
            "-C",
            project.to_str().expect("UTF-8 project path"),
            "--",
            "/usr/bin/python3",
            "-c",
            &format!(
                r#"import socket, threading, time
first = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
first.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
first.bind(({first_ip:?}, {first_port}))
first.listen(1)
first_connection, _ = first.accept()
time.sleep(.35)
second = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
second.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
second.bind(({second_ip:?}, {second_port}))
second.listen(1)
second_connection, _ = second.accept()
assert first_connection.recv(3) == b"one"
assert second_connection.recv(3) == b"two"
first_connection.sendall(b"1")
second_connection.sendall(b"2")
"#,
                first_ip = first_target.ip().to_string(),
                first_port = first_target.port(),
                second_ip = second_target.ip().to_string(),
                second_port = second_target.port(),
            ),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn staged publication");

    let deadline = Instant::now() + Duration::from_secs(3);
    let first_client = loop {
        match TcpStream::connect_timeout(&first_host, Duration::from_millis(100)) {
            Ok(stream) => break stream,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                child.kill().expect("stop unavailable staged publication");
                let output = child
                    .wait_with_output()
                    .expect("collect staged publication");
                panic!(
                    "first staged publication never became reachable ({error}): {}",
                    stderr(&output)
                );
            }
        }
    };

    let deadline = Instant::now() + Duration::from_secs(3);
    let second_client = loop {
        match TcpStream::connect_timeout(&second_host, Duration::from_millis(100)) {
            Ok(stream) => break stream,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                child.kill().expect("stop unavailable staged publication");
                let output = child
                    .wait_with_output()
                    .expect("collect staged publication");
                panic!(
                    "second staged publication never became reachable ({error}): {}",
                    stderr(&output)
                );
            }
        }
    };

    let mut first_client = first_client;
    let mut second_client = second_client;
    first_client
        .write_all(b"one")
        .expect("write first staged request");
    second_client
        .write_all(b"two")
        .expect("write second staged request");
    let mut first_response = [0_u8; 1];
    let mut second_response = [0_u8; 1];
    if let Err(error) = first_client.read_exact(&mut first_response) {
        let output = child
            .wait_with_output()
            .expect("collect failed staged publication");
        panic!(
            "read first staged response failed ({error}): {}",
            stderr(&output)
        );
    }
    second_client
        .read_exact(&mut second_response)
        .expect("read second staged response");
    assert_eq!(&first_response, b"1");
    assert_eq!(&second_response, b"2");
    let output = child
        .wait_with_output()
        .expect("collect staged publication");
    assert!(output.status.success(), "{}", stderr(&output));
}

#[cfg(target_os = "linux")]
#[test]
fn tcp_publication_unbinds_and_rebinds_one_listener_without_disrupting_another() {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    fn unused_loopback_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("reserve loopback test port")
            .local_addr()
            .expect("read loopback test port")
            .port()
    }

    fn wait_for_connection(address: SocketAddr, should_connect: bool) {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let connected =
                TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok();
            if connected == should_connect {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "publication {address} did not become {}",
                if should_connect {
                    "reachable"
                } else {
                    "closed"
                },
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn round_trip(address: SocketAddr, request: &[u8], expected: &[u8]) {
        let mut client = TcpStream::connect_timeout(&address, Duration::from_secs(1))
            .unwrap_or_else(|error| panic!("connect {address}: {error}"));
        client
            .write_all(request)
            .expect("write publication request");
        let mut response = vec![0_u8; expected.len()];
        client
            .read_exact(&mut response)
            .expect("read publication response");
        assert_eq!(response, expected);
    }

    let workspace = tempfile::tempdir().expect("create rebinding publication fixture");
    let zerobox_home = workspace.path().join("zerobox-home");
    let project = workspace.path().join("project");
    std::fs::create_dir_all(&project).expect("create project");
    let first_host = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
    let second_host = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
    let first_target = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
    let second_target = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()));
    let first_publication = format!("host@{first_host}->{first_target}");
    let second_publication = format!("host@{second_host}->{second_target}");
    let allow_read = format!("--allow-read={},/usr", project.display());
    let child = Command::new(zerobox_exec())
        .env("ZEROBOX_HOME", &zerobox_home)
        .args([
            "--profile=analysis-strict",
            allow_read.as_str(),
            "--publish-tcp",
            first_publication.as_str(),
            "--publish-tcp",
            second_publication.as_str(),
            "-C",
            project.to_str().expect("UTF-8 project path"),
            "--",
            "/usr/bin/python3",
            "-c",
            &format!(
                r#"import socket, threading, time
stop = threading.Event()

def serve(listener, reply):
    listener.settimeout(.05)
    while not stop.is_set():
        try:
            connection, _ = listener.accept()
        except (socket.timeout, OSError):
            continue
        try:
            connection.recv(1)
            connection.sendall(reply)
        finally:
            connection.close()

def listener(port):
    value = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    value.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    value.bind(("127.0.0.1", port))
    value.listen(16)
    return value

first = listener({first_port})
second = listener({second_port})
first_thread = threading.Thread(target=serve, args=(first, b"A"), daemon=True)
second_thread = threading.Thread(target=serve, args=(second, b"B"), daemon=True)
first_thread.start()
second_thread.start()
time.sleep(1)
first.close()
time.sleep(.4)
first = listener({first_port})
first_thread = threading.Thread(target=serve, args=(first, b"A"), daemon=True)
first_thread.start()
time.sleep(.4)
first.close()
time.sleep(.4)
first = listener({first_port})
first_thread = threading.Thread(target=serve, args=(first, b"A"), daemon=True)
first_thread.start()
time.sleep(6)
stop.set()
first.close()
second.close()
"#,
                first_port = first_target.port(),
                second_port = second_target.port(),
            ),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rebinding publication");

    wait_for_connection(first_host, true);
    wait_for_connection(second_host, true);
    round_trip(second_host, b"b", b"B");
    let mut old_first = TcpStream::connect_timeout(&first_host, Duration::from_secs(1))
        .expect("connect old first publication");
    old_first
        .set_read_timeout(Some(Duration::from_secs(8)))
        .expect("set old first read timeout");
    wait_for_connection(first_host, false);
    let second_deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < second_deadline {
        round_trip(second_host, b"b", b"B");
        std::thread::sleep(Duration::from_millis(100));
    }
    wait_for_connection(first_host, true);
    round_trip(first_host, b"a", b"A");
    round_trip(second_host, b"b", b"B");
    let mut closed = [0_u8; 1];
    assert_eq!(
        old_first.read(&mut closed).expect("drain old first relay"),
        0
    );

    let output = child
        .wait_with_output()
        .expect("collect rebinding publication");
    assert!(output.status.success(), "{}", stderr(&output));
}

#[cfg(target_os = "linux")]
#[test]
fn private_tmp_keeps_a_dynamic_view_when_its_root_is_not_readable() {
    let workspace = tempfile::Builder::new()
        .prefix("private-tmp-dynamic-view-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("create workspace fixture");
    let project = workspace.path().join("project");
    let restricted = workspace.path().join("restricted");
    let allowed = restricted.join("allowed");
    let blocked = restricted.join("blocked.pem");
    let private = workspace.path().join("lease/tmp");
    std::fs::create_dir_all(&project).expect("create project");
    std::fs::create_dir_all(&allowed).expect("create allowed descendant");
    std::fs::create_dir_all(&private).expect("create private tmp");
    std::fs::write(allowed.join("value"), "allowed").expect("write allowed fixture");
    std::fs::write(&blocked, "blocked").expect("write blocked fixture");

    let allow_read = format!("--allow-read={},/usr", allowed.display());
    let deny_glob = format!("--deny-read-glob={}/*.pem", restricted.display());
    let private_tmp = format!("--private-tmp={}", private.display());
    let command = format!(
        "test \"$(cat {}/value)\" = allowed && test ! -e {}",
        allowed.display(),
        blocked.display(),
    );
    let out = run(&[
        "--profile=analysis-strict",
        allow_read.as_str(),
        deny_glob.as_str(),
        "-C",
        project.to_str().expect("UTF-8 project path"),
        private_tmp.as_str(),
        "--",
        "/bin/sh",
        "-c",
        &command,
    ]);

    assert!(out.status.success(), "{}", stderr(&out));
}

#[cfg(target_os = "linux")]
#[test]
fn private_tmp_keeps_project_readable_and_writable_with_exact_policy_and_dynamic_denies() {
    let workspace = tempfile::Builder::new()
        .prefix("private-tmp-exact-dynamic-policy-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("create workspace fixture");
    let project = workspace.path().join("project");
    let home = workspace.path().join("home");
    let private = workspace.path().join("lease/tmp");
    std::fs::create_dir_all(&project).expect("create project");
    std::fs::create_dir_all(home.join(".ssh")).expect("create denied home path");
    std::fs::create_dir_all(&private).expect("create private tmp");
    std::fs::write(project.join("script"), "project-script").expect("write project file");
    std::fs::write(home.join(".ssh/key"), "secret").expect("write denied file");

    let allow_read = format!("--allow-read={},/usr", project.display());
    let allow_write = format!("--allow-write={}", project.display());
    let deny_read = format!("--deny-read={}", home.join(".ssh").display());
    let deny_read_glob = format!("--deny-read-glob={}/.aws/**", home.display());
    let deny_write_glob = format!("--deny-write-glob={}/.env", project.display());
    let private_tmp = format!("--private-tmp={}", private.display());
    let command = format!(
        "test \"$(cat {}/script)\" = project-script && printf written > {}/created && test ! -e {}/.ssh/key && test \"$(cat /tmp/owned 2>/dev/null || printf missing)\" = missing && printf private >/tmp/owned",
        project.display(),
        project.display(),
        home.display(),
    );
    let out = run(&[
        "--profile=analysis-strict",
        allow_read.as_str(),
        allow_write.as_str(),
        deny_read.as_str(),
        deny_read_glob.as_str(),
        deny_write_glob.as_str(),
        "-C",
        project.to_str().expect("UTF-8 project path"),
        private_tmp.as_str(),
        "--",
        "/bin/sh",
        "-c",
        &command,
    ]);

    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        std::fs::read_to_string(project.join("created")).unwrap(),
        "written"
    );
    assert_eq!(
        std::fs::read_to_string(private.join("owned")).unwrap(),
        "private"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn private_tmp_keeps_project_writable_when_a_wsl_home_dynamic_view_is_present() {
    let wsl_home = std::path::Path::new("/mnt/c/Users/winne");
    let linux_home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .expect("Linux home must be set for the Pi profile fixture");
    let bun_install = std::env::var_os("BUN_INSTALL")
        .map(std::path::PathBuf::from)
        .expect("BUN_INSTALL must be set for the Pi Bun fixture");
    let bun_bin = bun_install.join("bin");
    assert!(
        wsl_home.is_dir(),
        "this WSL fixture requires /mnt/c/Users/winne"
    );
    let workspace = tempfile::Builder::new()
        .prefix("private-tmp-wsl-dynamic-policy-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("create workspace fixture");
    let project = workspace.path().join("project");
    let private = workspace.path().join("lease/tmp");
    std::fs::create_dir_all(&project).expect("create project");
    std::fs::create_dir_all(&private).expect("create private tmp");
    for name in ["a", "b"] {
        let package = project.join("packages").join(name);
        std::fs::create_dir_all(package.join("node_modules"))
            .expect("create workspace package dependencies");
        std::fs::write(
            package.join("package.json"),
            serde_json::json!({
                "name": name,
                "scripts": { "probe": format!("printf workspace-{name}") },
            })
            .to_string(),
        )
        .expect("write workspace package manifest");
    }
    std::fs::write(
        project.join("package.json"),
        serde_json::json!({
            "name": "sandbox-fixture",
            "workspaces": ["packages/*"],
        })
        .to_string(),
    )
    .expect("write workspace root manifest");
    std::fs::write(project.join("script"), "project-script").expect("write project file");
    let zerobox_home = workspace.path().join("zerobox-home");
    std::fs::create_dir_all(zerobox_home.join("profiles")).expect("create profile directory");
    std::fs::write(
        zerobox_home.join("profiles/pi.json"),
        serde_json::json!({
            "description": "Pi exact dynamic policy",
            "strict_sandbox": true,
            "allow_read": [project, "/usr", bun_bin],
            "deny_read": [workspace.path().join("lease"), linux_home.join(".ssh"), wsl_home.join(".aws"), "/proc/1/root"],
            "deny_read_globs": [format!("{}/.aws", linux_home.display()), format!("{}/.gnupg", linux_home.display())],
            "allow_write": [project],
            "deny_write": [workspace.path().join("lease"), "/mnt/c", "/proc/1/root"],
            "deny_write_globs": [format!("{}/.env", project.display())],
            "set_env": { "PATH": format!("{}:/usr/bin:/bin", bun_bin.display()), "HOME": linux_home, "TMPDIR": "/tmp" },
        }).to_string(),
    ).expect("write profile");
    let private_tmp = format!("--private-tmp={}", private.display());
    let command = format!(
        "test \"$(/bin/pwd -P)\" = {} && test \"$(readlink /proc/self/cwd)\" = {} && test \"$(bun -e 'process.stdout.write(process.cwd())')\" = {} && test \"$(cat script)\" = project-script && /usr/bin/stat ../../package.json || true && bun run --filter './packages/*' probe && printf written > created && printf private >/tmp/owned",
        project.display(),
        project.display(),
        project.display(),
    );
    let mut runner = Command::new(zerobox_exec());
    runner
        .current_dir(&project)
        .env("ZEROBOX_HOME", &zerobox_home)
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .args([
            "--profile=pi",
            "--strict-sandbox",
            "--status-fd=3",
            private_tmp.as_str(),
            "--allow-local-binding",
            "-C",
            project.to_str().expect("UTF-8 project path"),
            "--",
            "/bin/bash",
            "-o",
            "pipefail",
            "-c",
            &command,
        ]);
    let (out, status) = run_command_with_status_fd(runner);
    assert!(
        out.status.success(),
        "status={:?}\nsetup={}\nstdout={}\nstderr={}",
        out.status,
        status,
        String::from_utf8_lossy(&out.stdout),
        stderr(&out)
    );
    assert_eq!(
        std::fs::read_to_string(project.join("created")).unwrap(),
        "written"
    );
    assert_eq!(
        std::fs::read_to_string(private.join("owned")).unwrap(),
        "private"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn restricted_command_cwd_never_falls_back_to_root() {
    let workspace = tempfile::Builder::new()
        .prefix("restricted-command-cwd-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("create workspace fixture");
    let project = workspace.path().join("project");
    let unavailable_cwd = workspace.path().join("unavailable");
    let marker = project.join("executed");
    std::fs::create_dir_all(&project).expect("create allowed project");
    std::fs::create_dir_all(&unavailable_cwd).expect("create unavailable cwd");

    let allow_read = format!("--allow-read={},/usr", project.display());
    let allow_write = format!("--allow-write={}", project.display());
    let deny_read = format!("--deny-read={}", unavailable_cwd.display());
    let command = format!("printf executed > {}", marker.display());
    let out = run(&[
        "--profile=analysis-strict",
        allow_read.as_str(),
        allow_write.as_str(),
        deny_read.as_str(),
        "-C",
        unavailable_cwd.to_str().expect("UTF-8 unavailable cwd"),
        "--",
        "/bin/sh",
        "-c",
        &command,
    ]);

    assert!(!out.status.success(), "command must not run from /");
    assert!(
        !marker.exists(),
        "command ran despite an unavailable requested cwd"
    );
    assert!(
        stderr(&out).contains("chdir"),
        "expected a cwd error, stderr: {}",
        stderr(&out)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn deny_write_does_not_reopen_an_unreadable_path() {
    let workspace = tempfile::Builder::new()
        .prefix("deny-write-read-leak-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("create workspace fixture");
    let project = workspace.path().join("project");
    let external = workspace.path().join("external");
    std::fs::create_dir_all(&project).expect("create project");
    std::fs::create_dir_all(&external).expect("create external directory");
    let secret = external.join("secret.txt");
    std::fs::write(&secret, "secret").expect("write external fixture");

    let allow_read = format!("--allow-read={},/usr", project.display());
    let deny_write = format!("--deny-write={}", external.display());
    let command = format!("! cat {} >/dev/null 2>&1", secret.display());
    let out = run(&[
        "--profile=analysis-strict",
        allow_read.as_str(),
        deny_write.as_str(),
        "-C",
        project.to_str().expect("UTF-8 project path"),
        "--",
        "/bin/sh",
        "-c",
        &command,
    ]);

    assert!(out.status.success(), "{}", stderr(&out));
}

#[cfg(target_os = "linux")]
#[test]
fn deny_write_downgrades_an_explicit_writable_descendant_without_reopening_siblings() {
    for parent_is_readable in [false, true] {
        let workspace = tempfile::Builder::new()
            .prefix("deny-write-descendant-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .expect("create workspace fixture");
        let project = workspace.path().join("project");
        let external = workspace.path().join("external");
        let allowed = external.join("allowed");
        let sibling = external.join("sibling.txt");
        std::fs::create_dir_all(&project).expect("create project");
        std::fs::create_dir_all(&allowed).expect("create allowed directory");
        std::fs::write(allowed.join("value.txt"), "allowed").expect("write allowed fixture");
        std::fs::write(&sibling, "sibling").expect("write sibling fixture");

        let allow_read = if parent_is_readable {
            format!(
                "--allow-read={},/usr,{}",
                project.display(),
                external.display()
            )
        } else {
            format!("--allow-read={},/usr", project.display())
        };
        let allow_write = format!("--allow-write={}", allowed.display());
        let deny_write = format!("--deny-write={}", external.display());
        let command = if parent_is_readable {
            format!(
                "test \"$(cat {}/value.txt)\" = allowed && ! printf denied > {}/new.txt 2>/dev/null",
                allowed.display(),
                allowed.display(),
            )
        } else {
            format!(
                "test \"$(cat {}/value.txt)\" = allowed && ! printf denied > {}/new.txt 2>/dev/null && ! cat {} >/dev/null 2>&1",
                allowed.display(),
                allowed.display(),
                sibling.display(),
            )
        };
        let out = run(&[
            "--profile=analysis-strict",
            allow_read.as_str(),
            allow_write.as_str(),
            deny_write.as_str(),
            "-C",
            project.to_str().expect("UTF-8 project path"),
            "--",
            "/bin/sh",
            "-c",
            &command,
        ]);

        assert!(
            out.status.success(),
            "parent_is_readable={parent_is_readable}: {}",
            stderr(&out)
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn deny_write_inside_a_denied_read_root_does_not_reopen_the_child() {
    let workspace = tempfile::Builder::new()
        .prefix("deny-read-write-precedence-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("create workspace fixture");
    let project = workspace.path().join("project");
    let external = workspace.path().join("external");
    let child = external.join("child");
    std::fs::create_dir_all(&project).expect("create project");
    std::fs::create_dir_all(&child).expect("create child directory");
    let secret = child.join("secret.txt");
    std::fs::write(&secret, "secret").expect("write child fixture");

    let allow_read = format!("--allow-read={},/usr", project.display());
    let deny_read = format!("--deny-read={}", external.display());
    let deny_write = format!("--deny-write={}", child.display());
    let command = format!("! cat {} >/dev/null 2>&1", secret.display());
    let out = run(&[
        "--profile=analysis-strict",
        allow_read.as_str(),
        deny_read.as_str(),
        deny_write.as_str(),
        "-C",
        project.to_str().expect("UTF-8 project path"),
        "--",
        "/bin/sh",
        "-c",
        &command,
    ]);

    assert!(out.status.success(), "{}", stderr(&out));
}

#[cfg(target_os = "linux")]
#[test]
fn invalid_strict_path_emits_setup_error_and_exit_125() {
    let (out, status) = run_with_status_fd(&[
        "--status-fd=3",
        "--profile=analysis-strict",
        "--env",
        "PATH=relative:/usr/bin",
        "--",
        "/bin/true",
    ]);
    assert_eq!(out.status.code(), Some(125), "stderr: {}", stderr(&out));
    let event: serde_json::Value = serde_json::from_str(status.trim()).expect("JSONL setup event");
    assert_eq!(event["version"], 1);
    assert_eq!(event["event"], "setup_error");
    assert_eq!(event["code"], "sandbox_setup");
}

#[cfg(target_os = "linux")]
#[test]
fn strict_sandbox_blocks_nested_namespace_and_mount_operations() {
    let temp = temp_dir();
    let mountpoint = temp.path().join("nested-mount");
    std::fs::create_dir(&mountpoint).expect("create nested mountpoint");
    let mountpoint = mountpoint.to_str().expect("UTF-8 mountpoint");
    let allow_read = format!("--allow-read={mountpoint}");
    let allow_write = format!("--allow-write={mountpoint}");

    let attempts: Vec<Vec<&str>> = vec![
        vec!["/usr/bin/unshare", "--user", "/bin/true"],
        vec!["/usr/bin/unshare", "--user", "--mount", "/bin/true"],
        vec!["/usr/bin/bwrap", "--ro-bind", "/", "/", "/bin/true"],
        vec!["/usr/bin/mount", "-t", "tmpfs", "tmpfs", mountpoint],
    ];

    for attempt in attempts {
        let mut args = vec![
            "--profile=analysis-strict",
            allow_read.as_str(),
            allow_write.as_str(),
            "--",
        ];
        args.extend(attempt.iter().copied());
        let out = run(&args);
        assert!(
            !out.status.success(),
            "nested operation unexpectedly succeeded: {attempt:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn status_fd_distinguishes_target_exit_125_and_does_not_leak() {
    let (out, status) = run_with_status_fd(&[
        "--status-fd=3",
        "--allow-all",
        "--",
        "sh",
        "-c",
        "test ! -e /proc/self/fd/3; result=$?; exit $([ $result -eq 0 ] && echo 125 || echo 7)",
    ]);
    assert_eq!(out.status.code(), Some(125), "stderr: {}", stderr(&out));
    let events: Vec<serde_json::Value> = status
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSONL lifecycle event"))
        .collect();
    assert_eq!(events[0]["event"], "child_started");
    assert_eq!(events[1]["event"], "child_exit");
    assert_eq!(events[1]["code"], 125);
}

#[cfg(target_os = "linux")]
#[test]
fn status_fd_reports_restricted_target_start_before_exit() {
    use std::io::{BufRead, BufReader, Read};
    use std::os::fd::FromRawFd;
    use std::os::unix::process::CommandExt;

    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    let read_fd = fds[0];
    let write_fd = fds[1];
    let mut command = Command::new(zerobox_exec());
    command.current_dir("/tmp");
    command.args([
        "--status-fd=3",
        "--allow-read=/tmp",
        "--allow-write=/tmp",
        "--",
        "sh",
        "-c",
        "test ! -e /proc/self/fd/3 && sleep 2",
    ]);
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(write_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if write_fd != 3 && libc::close(write_fd) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = command.spawn().expect("spawn restricted status target");
    unsafe { libc::close(write_fd) };
    let mut status = BufReader::new(unsafe { std::fs::File::from_raw_fd(read_fd) });
    let mut started = String::new();
    status.read_line(&mut started).expect("read child_started");
    let event: serde_json::Value = serde_json::from_str(started.trim()).expect("JSON event");
    assert_eq!(event["event"], "child_started");
    assert!(
        child.try_wait().expect("poll target").is_none(),
        "child_started must arrive while the restricted target is still running"
    );
    assert!(child.wait().expect("wait target").success());
    let mut remainder = String::new();
    status
        .read_to_string(&mut remainder)
        .expect("read child_exit");
    let exit: serde_json::Value = serde_json::from_str(remainder.trim()).expect("JSON exit");
    assert_eq!(exit["event"], "child_exit");
    assert_eq!(exit["code"], 0);
}

#[cfg(target_os = "linux")]
#[test]
fn status_fd_streams_partial_stdout_before_child_exit_and_then_eof() {
    use std::io::{BufRead, BufReader, Read};
    use std::os::fd::FromRawFd;
    use std::os::unix::process::CommandExt;

    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    let read_fd = fds[0];
    let write_fd = fds[1];
    let mut command = Command::new(zerobox_exec());
    command
        .args([
            "--status-fd=3",
            "--allow-all",
            "--",
            "/bin/sh",
            "-c",
            "printf partial; sleep 1; printf done",
        ])
        .stdout(std::process::Stdio::piped());
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(write_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = command.spawn().expect("spawn streaming status target");
    unsafe { libc::close(write_fd) };
    let mut status = BufReader::new(unsafe { std::fs::File::from_raw_fd(read_fd) });
    let mut started = String::new();
    status.read_line(&mut started).expect("read child_started");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(started.trim()).expect("started JSON")["event"],
        "child_started"
    );

    let mut partial = [0_u8; 7];
    child
        .stdout
        .as_mut()
        .expect("piped stdout")
        .read_exact(&mut partial)
        .expect("read partial stdout");
    assert_eq!(&partial, b"partial");
    assert!(child.try_wait().expect("poll zerobox").is_none());

    assert!(child.wait().expect("wait zerobox").success());
    let mut remainder = String::new();
    status
        .read_to_string(&mut remainder)
        .expect("read child_exit and EOF");
    let exit: serde_json::Value = serde_json::from_str(remainder.trim()).expect("exit JSON");
    assert_eq!(exit["event"], "child_exit");
    assert_eq!(exit["code"], 0);
}

#[cfg(target_os = "linux")]
fn assert_status_eof_after_outer_signal(signal: i32) {
    use std::io::{BufRead, BufReader, Read};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;

    let (reader, writer) = UnixStream::pair().expect("create signal status socket");
    let write_fd = writer.as_raw_fd();
    let mut command = Command::new(zerobox_exec());
    command.args([
        "--status-fd=3",
        "--allow-all",
        "--",
        "/bin/sh",
        "-c",
        "sleep 30",
    ]);
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) < 0 || libc::dup2(write_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = command.spawn().expect("spawn signal status target");
    let process_group = child.id() as i32;
    drop(writer);
    let mut reader = BufReader::new(reader);
    let mut started = String::new();
    reader.read_line(&mut started).expect("read child_started");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(started.trim()).expect("started JSON")["event"],
        "child_started"
    );

    assert_eq!(unsafe { libc::kill(process_group, signal) }, 0);
    let _ = child.wait().expect("wait signaled zerobox");
    unsafe {
        libc::kill(-process_group, libc::SIGKILL);
    }
    let mut remainder = String::new();
    reader
        .read_to_string(&mut remainder)
        .expect("read status EOF after signal");
}

#[cfg(target_os = "linux")]
#[test]
fn status_fd_reaches_eof_after_sigterm_and_sigint() {
    assert_status_eof_after_outer_signal(libc::SIGTERM);
    assert_status_eof_after_outer_signal(libc::SIGINT);
}

#[cfg(target_os = "linux")]
#[test]
fn status_fd_reaches_eof_after_timeout() {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;

    let (mut reader, writer) = UnixStream::pair().expect("create timeout status socket");
    let write_fd = writer.as_raw_fd();
    let mut command = Command::new("/usr/bin/timeout");
    command.args([
        "1s",
        zerobox_exec().to_str().expect("UTF-8 executable path"),
        "--status-fd=3",
        "--allow-all",
        "--",
        "/bin/sh",
        "-c",
        "sleep 30",
    ]);
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(write_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = command.output().expect("run bounded status target");
    drop(writer);
    assert!(!out.status.success());
    let mut status = String::new();
    reader
        .read_to_string(&mut status)
        .expect("read status through timeout EOF");
    assert!(status.contains("\"event\":\"child_started\""));
}

#[cfg(target_os = "linux")]
fn spawn_setup_supervisor_target(ignore_sigterm: bool) -> (std::process::Child, i32, i32) {
    use std::io::BufRead;
    use std::os::fd::FromRawFd;
    use std::os::unix::process::CommandExt;

    let mut status_fds = [0; 2];
    let mut ready_fds = [0; 2];
    assert_eq!(
        unsafe { libc::pipe2(status_fds.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    assert_eq!(
        unsafe { libc::pipe2(ready_fds.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    let status_source = unsafe { libc::fcntl(status_fds[1], libc::F_DUPFD_CLOEXEC, 64) };
    let ready_source = unsafe { libc::fcntl(ready_fds[1], libc::F_DUPFD_CLOEXEC, 64) };
    assert!(status_source >= 64);
    assert!(ready_source >= 64);
    let permission_profile =
        serde_json::to_string(&zerobox_protocol::models::PermissionProfile::read_only())
            .expect("serialize permission profile");
    let signal_handler = if ignore_sigterm {
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)"
    } else {
        "signal.signal(signal.SIGTERM, lambda *_: os._exit(42))"
    };
    let target_script = format!(
        "import ctypes, os, signal; value=ctypes.c_int(); ctypes.CDLL(None).prctl(2, ctypes.byref(value), 0, 0, 0); os.write(8, f'{{os.getpid()}} {{value.value}}\\n'.encode()); {signal_handler}; signal.pause()"
    );
    let mut command = Command::new(zerobox_exec());
    command.arg0("zerobox-linux-sandbox").args([
        "--sandbox-policy-cwd",
        "/",
        "--permission-profile",
        &permission_profile,
        "--use-legacy-landlock",
        "--setup-status-fd",
        "9",
        "--",
        "python3",
        "-c",
        &target_script,
    ]);
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(status_source, 9) < 0 || libc::dup2(ready_source, 8) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let supervisor = command.spawn().expect("spawn setup supervisor");
    unsafe {
        libc::close(status_fds[1]);
        libc::close(ready_fds[1]);
        libc::close(status_source);
        libc::close(ready_source);
    }
    let status_reader = std::thread::spawn(move || {
        let mut line = String::new();
        let file = unsafe { std::fs::File::from_raw_fd(status_fds[0]) };
        std::io::BufReader::new(file)
            .read_line(&mut line)
            .expect("read setup frame");
        line
    });
    let ready_reader = std::thread::spawn(move || {
        let mut line = String::new();
        let file = unsafe { std::fs::File::from_raw_fd(ready_fds[0]) };
        std::io::BufReader::new(file)
            .read_line(&mut line)
            .expect("read target PID");
        line
    });
    let status_frame = status_reader.join().expect("status reader thread");
    assert_eq!(status_frame, "STARTED\n");
    let ready = ready_reader.join().expect("ready reader thread");
    let mut ready = ready.split_whitespace();
    let target_pid: i32 = ready
        .next()
        .expect("target PID")
        .parse()
        .expect("numeric target PID");
    let parent_death_signal: i32 = ready
        .next()
        .expect("parent-death signal")
        .parse()
        .expect("numeric parent-death signal");

    (supervisor, target_pid, parent_death_signal)
}

#[cfg(target_os = "linux")]
#[test]
fn setup_supervisor_sets_parent_death_forwards_sigterm_and_reaps_target() {
    use std::time::{Duration, Instant};

    let (mut supervisor, target_pid, parent_death_signal) = spawn_setup_supervisor_target(false);
    assert_eq!(parent_death_signal, libc::SIGKILL);

    assert_eq!(
        unsafe { libc::kill(supervisor.id() as i32, libc::SIGTERM) },
        0
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    let supervisor_status = loop {
        if let Some(status) = supervisor.try_wait().expect("poll supervisor") {
            break status;
        }
        if Instant::now() >= deadline {
            unsafe {
                libc::kill(supervisor.id() as i32, libc::SIGKILL);
                libc::kill(target_pid, libc::SIGKILL);
                libc::kill(-target_pid, libc::SIGKILL);
            }
            let _ = supervisor.wait();
            panic!("setup supervisor did not terminate after SIGTERM");
        }
        std::thread::yield_now();
    };
    let target_alive = unsafe { libc::kill(target_pid, 0) } == 0;
    if target_alive {
        unsafe {
            libc::kill(target_pid, libc::SIGKILL);
            libc::kill(-target_pid, libc::SIGKILL);
        }
    }

    assert_eq!(supervisor_status.code(), Some(42));
    assert!(
        !target_alive,
        "target {target_pid} survived its setup supervisor"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn setup_target_dies_when_supervisor_is_killed_without_forwarding() {
    use std::os::unix::process::ExitStatusExt;
    use std::time::{Duration, Instant};

    let (mut supervisor, target_pid, parent_death_signal) = spawn_setup_supervisor_target(true);
    assert_eq!(parent_death_signal, libc::SIGKILL);
    assert_eq!(
        unsafe { libc::kill(supervisor.id() as i32, libc::SIGKILL) },
        0
    );
    let supervisor_status = supervisor.wait().expect("wait for killed supervisor");
    assert_eq!(supervisor_status.signal(), Some(libc::SIGKILL));

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if unsafe { libc::kill(target_pid, 0) } < 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        {
            break;
        }
        if Instant::now() >= deadline {
            unsafe {
                libc::kill(target_pid, libc::SIGKILL);
                libc::kill(-target_pid, libc::SIGKILL);
            }
            panic!("target {target_pid} survived its killed setup supervisor");
        }
        std::thread::yield_now();
    }
}

#[cfg(unix)]
#[test]
fn piped_stdin_streams_stdout_without_capture_replay() {
    use std::io::Write;
    let mut child = Command::new(zerobox_exec())
        .args(["--allow-all", "--", "sh", "-c", "cat; printf ':done'"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(b"streamed")
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "streamed:done");
}

#[cfg(unix)]
#[test]
fn non_socket_stdio_descriptors_are_inherited_directly() {
    let temp = temp_dir();
    let stdin_path = temp.path().join("stdin");
    let stdout_path = temp.path().join("stdout");
    let stderr_path = temp.path().join("stderr");
    std::fs::write(&stdin_path, "input").expect("write stdin fixture");
    let stdin_file = std::fs::File::open(&stdin_path).expect("open stdin fixture");
    let stdout_file = std::fs::File::create(&stdout_path).expect("create stdout fixture");
    let stderr_file = std::fs::File::create(&stderr_path).expect("create stderr fixture");

    let status = Command::new(zerobox_exec())
        .args([
            "--allow-all",
            "--",
            "sh",
            "-c",
            "readlink /proc/self/fd/0; readlink /proc/self/fd/1; readlink /proc/self/fd/2",
        ])
        .stdin(stdin_file)
        .stdout(stdout_file)
        .stderr(stderr_file)
        .status()
        .expect("run direct stdio probe");

    assert!(status.success());
    let descriptors = std::fs::read_to_string(&stdout_path).expect("read descriptor probe");
    assert!(
        descriptors
            .lines()
            .any(|line| line == stdin_path.to_string_lossy())
    );
    assert!(
        descriptors
            .lines()
            .any(|line| line == stdout_path.to_string_lossy())
    );
    assert!(
        descriptors
            .lines()
            .any(|line| line == stderr_path.to_string_lossy())
    );
}

#[cfg(unix)]
#[test]
fn unix_socket_stdio_relay_stops_after_direct_target_exit() {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    let temp = temp_dir();
    let background_pid = temp.path().join("background.pid");
    let (mut reader, writer) = UnixStream::pair().expect("create stdout socket pair");
    let writer: OwnedFd = writer.into();
    let command = format!(
        "sleep 30 & echo $! > {}; printf ready",
        background_pid.display()
    );
    let out = Command::new("timeout")
        .args([
            "2s",
            zerobox_exec().to_str().expect("UTF-8 executable path"),
            "--allow-all",
            "--",
            "sh",
            "-c",
            &command,
        ])
        .stdout(std::process::Stdio::from(writer))
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("run bounded socket relay probe");
    let mut relayed = String::new();
    std::io::Read::read_to_string(&mut reader, &mut relayed).expect("read relayed stdout");

    if let Ok(pid) = std::fs::read_to_string(&background_pid)
        .map(|pid| pid.trim().to_string())
        .and_then(|pid| pid.parse::<i32>().map_err(std::io::Error::other))
    {
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(relayed, "ready");
}

#[test]
fn default_read_succeeds() {
    std::fs::write("/tmp/zerobox-e2e-read", "hello").expect("setup");
    let out = run(&["--", "cat", "/tmp/zerobox-e2e-read"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "hello");
}

#[test]
fn default_write_blocked_outside_temp() {
    let home = std::env::var("HOME").expect("HOME not set");
    let target = format!("{}/zerobox-e2e-write-blocked", home);
    let out = run(&[
        "--",
        "sh",
        "-c",
        &format!("echo x > {} 2>/dev/null && echo OK || echo BLOCKED", target),
    ]);
    let _ = std::fs::remove_file(&target);
    assert!(
        stdout(&out).contains("BLOCKED"),
        "write to home should be blocked, got: {}",
        stdout(&out)
    );
}

#[test]
fn default_network_blocked() {
    let (code, ok) = curl_status(&[], "https://example.com");
    assert!(!ok, "network should be blocked, got {code}");
}

#[test]
fn allow_all_permits_everything() {
    let out = run(&[
        "--allow-all",
        "--",
        "node",
        "-e",
        "require('fs').writeFileSync('/tmp/zerobox-e2e-aa','x');console.log('ok')",
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "ok");
}

#[test]
fn no_sandbox_permits_everything() {
    let out = run(&[
        "--no-sandbox",
        "--",
        "node",
        "-e",
        "require('fs').writeFileSync('/tmp/zerobox-e2e-ns','x');console.log('ok')",
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "ok");
}

#[test]
fn allow_read_and_write_combined() {
    std::fs::write("/tmp/zerobox-e2e-rw-in", "input").expect("setup");
    let out = run(&[
        "--allow-read=/tmp",
        "--allow-write=/tmp",
        "--",
        "sh",
        "-c",
        "cat /tmp/zerobox-e2e-rw-in > /tmp/zerobox-e2e-rw-out && echo ok",
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "ok");
    let content = std::fs::read_to_string("/tmp/zerobox-e2e-rw-out").expect("read back");
    assert_eq!(content.trim(), "input");
}

#[cfg(target_os = "linux")]
#[test]
fn default_profile_starts_with_empty_credential_files_in_writable_home() {
    let tmp = temp_dir();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).expect("create home");
    for name in [".azure", ".gcloud", ".kube", ".git-credentials"] {
        std::fs::File::create(home.join(name)).expect("create empty credential file");
    }

    let out = Command::new(zerobox_exec())
        .current_dir(&home)
        .env("HOME", &home)
        .env("ZEROBOX_HOME", tmp.path().join("zerobox-home"))
        .args(["--allow-write=.", "--allow-write=/tmp", "--", "ls"])
        .output()
        .expect("failed to spawn zerobox");

    assert!(
        out.status.success(),
        "default profile should mask empty credential files without breaking startup, stderr: {}",
        stderr(&out)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn default_profile_starts_with_tmp_home_and_missing_nested_keyring_path() {
    let tmp = temp_dir();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).expect("create home");

    let out = Command::new(zerobox_exec())
        .current_dir(&home)
        .env("HOME", &home)
        .env("ZEROBOX_HOME", tmp.path().join("zerobox-home"))
        .args(["--allow-write=.", "--allow-write=/tmp", "--", "ls"])
        .output()
        .expect("failed to spawn zerobox");

    assert!(
        out.status.success(),
        "default profile should mask ~/.local/share/keyrings without replacing ~/.local, stderr: {}",
        stderr(&out)
    );
    assert!(
        !home.join(".local").exists(),
        "synthetic missing parents should be cleaned up after bwrap exits"
    );
}

#[test]
fn allow_read_and_net_combined() {
    let (code, ok) = curl_status(
        &[
            "--allow-read=/tmp,/run",
            "--allow-write=/tmp",
            "--allow-net",
        ],
        "https://example.com",
    );
    assert!(ok, "expected 200, got {code}");
}

#[test]
fn deny_read_and_deny_write_combined() {
    let dir = setup_tmp("combo");
    let secret = dir.join("secret");
    std::fs::create_dir_all(&secret).expect("setup");
    std::fs::write(dir.join("public"), "hello").expect("setup");

    let out = run(&[
        "--profile",
        "workspace",
        &format!("--allow-write={}", dir.display()),
        &format!("--deny-write={}", secret.display()),
        "--",
        "node",
        "-e",
        &format!(
            r#"
const fs = require('fs');
let r = [];
try {{ fs.writeFileSync('{}/new.txt','x'); r.push('write-pub:ok'); }} catch(e) {{ r.push('write-pub:blocked'); }}
try {{ fs.writeFileSync('{}/secret/evil','x'); r.push('write-sec:ok'); }} catch(e) {{ r.push('write-sec:blocked'); }}
console.log(r.join(','));
"#,
            dir.display(),
            dir.display()
        ),
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let result = stdout(&out).trim().to_string();
    assert!(result.contains("write-pub:ok"), "got: {result}");
    assert!(result.contains("write-sec:blocked"), "got: {result}");
}

#[test]
fn allow_net_domain_with_write_restriction() {
    let dir = setup_tmp("net-write");
    let (code, ok) = curl_status(
        &[
            "--allow-net=example.com",
            &format!("--allow-write={}", dir.display()),
        ],
        "https://example.com",
    );
    assert!(ok, "expected 200, got {code}");
}

#[test]
fn exit_code_zero_propagated() {
    let out = run(&[
        "--profile",
        "workspace",
        "--",
        "node",
        "-e",
        "process.exit(0)",
    ]);
    assert!(out.status.success());
}

#[test]
fn exit_code_nonzero_propagated() {
    let out = run(&[
        "--profile",
        "workspace",
        "--",
        "node",
        "-e",
        "process.exit(42)",
    ]);
    assert_eq!(out.status.code(), Some(42));
}

#[test]
fn relative_write_path_resolved() {
    let out = run(&[
        "--profile",
        "workspace",
        "-C",
        "/tmp",
        "--",
        "node",
        "-e",
        "require('fs').writeFileSync('/tmp/zerobox-e2e-rel','ok');console.log('ok')",
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
}

#[test]
fn default_profile_blocks_home_read() {
    let home = std::env::var("HOME").expect("HOME not set");
    let target = format!("{}/zerobox-e2e-read-test", home);
    std::fs::write(&target, "secret").expect("setup");
    let out = run(&["--", "cat", &target]);
    let _ = std::fs::remove_file(&target);
    assert!(
        !out.status.success(),
        "home files should not be readable with default profile"
    );
}

#[test]
fn default_profile_blocks_home_write() {
    let home = std::env::var("HOME").expect("HOME not set");
    let target = format!("{}/zerobox-e2e-write-test", home);
    let out = run(&[
        "--",
        "sh",
        "-c",
        &format!(
            "echo x > {} 2>/dev/null && echo WRITTEN || echo BLOCKED",
            target
        ),
    ]);
    assert!(
        !stdout(&out).contains("WRITTEN"),
        "writes to home should be blocked, got: {}",
        stdout(&out)
    );
    let _ = std::fs::remove_file(&target);
}

#[test]
fn workspace_profile_provides_cwd_read_write() {
    let dir = setup_tmp("ws-cwd");
    std::fs::write(dir.join("input.txt"), "hello").expect("setup");
    let out = run(&[
        "--profile",
        "workspace",
        "-C",
        &dir.display().to_string(),
        "--",
        "sh",
        "-c",
        "cat input.txt && echo world > output.txt && echo ok",
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(stdout(&out).contains("hello"));
    assert!(stdout(&out).contains("ok"));
    assert_eq!(
        std::fs::read_to_string(dir.join("output.txt"))
            .unwrap()
            .trim(),
        "world"
    );
}

#[test]
fn invalid_profile_name_rejected() {
    let out = run(&["--profile", "../../../etc/passwd", "--", "echo", "hello"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("invalid profile name"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn nonexistent_command_fails() {
    let out = run(&["--", "this-command-does-not-exist-zerobox"]);
    assert!(!out.status.success());
}

mod strict_flag {
    use super::*;

    #[test]
    fn strict_works_when_namespaces_available() {
        let out = run(&["--strict-sandbox", "--", "echo", "hello"]);
        assert!(
            out.status.success(),
            "strict should work when namespaces are available, stderr: {}",
            stderr(&out)
        );
        assert_eq!(stdout(&out).trim(), "hello");
    }

    #[test]
    fn strict_with_allow_write() {
        let out = run(&[
            "--strict-sandbox",
            "--allow-write=/tmp",
            "--",
            "sh",
            "-c",
            "echo ok > /tmp/zerobox-strict-test && cat /tmp/zerobox-strict-test",
        ]);
        assert!(out.status.success(), "stderr: {}", stderr(&out));
        assert_eq!(stdout(&out).trim(), "ok");
    }
}
