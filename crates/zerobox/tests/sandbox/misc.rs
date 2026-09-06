use crate::support::*;

#[cfg(unix)]
fn run_with_status_fd(args: &[&str]) -> (Output, String) {
    let mut command = Command::new(zerobox_exec());
    command.args(args);
    run_command_with_status_fd(command)
}

#[cfg(unix)]
fn run_command_with_status_fd(mut command: Command) -> (Output, String) {
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
        "true",
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
