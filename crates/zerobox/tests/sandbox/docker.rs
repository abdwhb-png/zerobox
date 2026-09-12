use std::os::unix::fs::PermissionsExt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use zerobox::{
    DockerAccessPolicy, DockerTargetGrant, DockerTargetSelector, Sandbox, UnixSocketPath,
};

use crate::support::{temp_dir, zerobox_exec};

#[tokio::test]
async fn sdk_disabled_docker_policy_removes_inherited_connection_settings() {
    let output = Sandbox::command("/bin/sh")
        .args(&[
            "-c",
            "test -z \"${DOCKER_HOST+x}${DOCKER_CONTEXT+x}${DOCKER_TLS_VERIFY+x}${DOCKER_CERT_PATH+x}\"",
        ])
        .no_profile()
        .allow_read("/")
        .env("DOCKER_HOST", "tcp://host.example:2375")
        .env("DOCKER_CONTEXT", "remote")
        .env("DOCKER_TLS_VERIFY", "1")
        .env("DOCKER_CERT_PATH", "/tmp/certs")
        .linux_sandbox_exe(zerobox_exec())
        .run()
        .await
        .expect("run with Docker disabled");

    assert!(output.status.success());
}

#[tokio::test]
async fn sdk_no_sandbox_keeps_local_docker_connection_settings() {
    let output = Sandbox::command("/bin/sh")
        .args(&["-c", "test \"$DOCKER_HOST\" = tcp://host.example:2375"])
        .no_profile()
        .no_sandbox()
        .env("DOCKER_HOST", "tcp://host.example:2375")
        .run()
        .await
        .expect("run locally");

    assert!(output.status.success());
}

#[tokio::test]
async fn sdk_full_docker_access_uses_only_the_private_namespace_bridge() {
    let root = temp_dir();
    let engine_path = root.path().join("engine.sock");
    let engine = UnixListener::bind(&engine_path).unwrap();
    std::fs::set_permissions(&engine_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let engine_task = tokio::spawn(async move {
        let (mut stream, _) = engine.accept().await.unwrap();
        let mut request = vec![0_u8; 1024];
        let read = stream.read(&mut request).await.unwrap();
        assert!(String::from_utf8_lossy(&request[..read]).starts_with("GET /_ping HTTP/1.1"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .await
            .unwrap();
    });
    let script = format!(
        concat!(
            "test ! -S '{}' && ",
            "test -z \"$(find /dev/.zerobox-proxy -type s -print -quit)\" && ",
            "endpoint=${{DOCKER_HOST#tcp://}} && ",
            "host=${{endpoint%:*}} && port=${{endpoint##*:}} && ",
            "exec 3<>/dev/tcp/$host/$port && ",
            "printf 'GET /_ping HTTP/1.1\\r\\nHost: docker\\r\\nConnection: close\\r\\n\\r\\n' >&3 && ",
            "IFS= read -r status <&3 && ",
            "while IFS= read -r header <&3; do test \"$header\" = $'\\r' && break; done && ",
            "IFS= read -r -N 2 body <&3 && printf '%s\\n%s' \"$status\" \"$body\""
        ),
        engine_path.display()
    );

    let output = Sandbox::command("/bin/bash")
        .args(&["-c", &script])
        .cwd(root.path())
        .no_profile()
        .allow_read("/")
        .deny_read(zerobox::zerobox_home())
        .deny_read_glob("*.pem")
        .docker_access(DockerAccessPolicy::Full {
            endpoint: UnixSocketPath::from_str(engine_path.to_str().unwrap()).unwrap(),
        })
        .linux_sandbox_exe(zerobox_exec())
        .run()
        .await
        .expect("run Docker broker sandbox");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("HTTP/1.1 200 OK"));
    assert!(stdout.ends_with("OK"));
    engine_task.await.unwrap();
}

#[tokio::test]
#[ignore = "requires a local Docker Engine and Docker CLI"]
async fn sdk_real_docker_cli_sees_no_containers_without_target_grants() {
    let output = Sandbox::command("/usr/bin/docker")
        .args(&["ps", "--format", "{{.ID}}"])
        .no_profile()
        .allow_read("/")
        .docker_access(DockerAccessPolicy::Targeted {
            endpoint: UnixSocketPath::from_str("/var/run/docker.sock").unwrap(),
            targets: Vec::new(),
        })
        .linux_sandbox_exe(zerobox_exec())
        .run()
        .await
        .expect("run real Docker client through an empty targeted broker");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
}

#[tokio::test]
async fn sdk_docker_bridge_propagates_stdin_eof_and_preserves_the_response() {
    assert_docker_bridge_half_close(false).await;
}

#[tokio::test]
async fn sdk_docker_bridge_propagates_server_eof_without_truncating_client_input() {
    assert_docker_bridge_half_close(true).await;
}

async fn assert_docker_bridge_half_close(server_first: bool) {
    let root = temp_dir();
    let engine_path = root.path().join("eof-engine.sock");
    let engine = UnixListener::bind(&engine_path).unwrap();
    std::fs::set_permissions(&engine_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let engine_task = tokio::spawn(async move {
        let (mut stream, _) = engine.accept().await.unwrap();
        if server_first {
            stream.write_all(b"response-after-eof").await.unwrap();
            stream.shutdown().await.unwrap();
        }
        let mut request = Vec::new();
        let eof = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            stream.read_to_end(&mut request),
        )
        .await;
        if matches!(eof, Ok(Ok(_))) && !server_first {
            stream.write_all(b"response-after-eof").await.unwrap();
            stream.shutdown().await.unwrap();
        }
        (matches!(eof, Ok(Ok(_))), request)
    });
    let output = Sandbox::command("/usr/bin/python3")
        .args(&[
            "-c",
            r#"
import os, socket, sys
host, port = os.environ['DOCKER_HOST'].removeprefix('tcp://').rsplit(':', 1)
with socket.create_connection((host, int(port)), timeout=3) as stream:
    if sys.argv[1] == 'client-first':
        stream.sendall(b'request')
        stream.shutdown(socket.SHUT_WR)
    response = b''
    while chunk := stream.recv(1024):
        response += chunk
    assert response == b'response-after-eof', repr(response)
    if sys.argv[1] == 'server-first':
        stream.sendall(b'request')
        stream.shutdown(socket.SHUT_WR)
"#,
            if server_first {
                "server-first"
            } else {
                "client-first"
            },
        ])
        .cwd(root.path())
        .no_profile()
        .allow_read("/")
        .docker_access(DockerAccessPolicy::Full {
            endpoint: UnixSocketPath::from_str(engine_path.to_str().unwrap()).unwrap(),
        })
        .linux_sandbox_exe(zerobox_exec())
        .run()
        .await
        .expect("run EOF bridge fixture");
    let (received_eof, request) = engine_task.await.unwrap();
    assert_eq!(request, b"request");
    assert!(
        received_eof,
        "the private Docker bridge did not forward client EOF"
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn sdk_docker_bridge_closes_the_transport_when_the_launcher_is_killed() {
    let root = tempfile::tempdir_in("/var/tmp").unwrap();
    std::fs::create_dir(root.path().join("home")).unwrap();
    let engine_path = root.path().join("cancel-engine.sock");
    let engine = UnixListener::bind(&engine_path).unwrap();
    std::fs::set_permissions(&engine_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let policy = serde_json::to_string(&DockerAccessPolicy::Full {
        endpoint: UnixSocketPath::from_str(engine_path.to_str().unwrap()).unwrap(),
    })
    .unwrap();
    let mut child = std::process::Command::new(zerobox_exec())
        .current_dir(root.path())
        .env("HOME", root.path().join("home"))
        .env("ZEROBOX_HOME", root.path().join("zerobox"))
        .args([
            "--allow-read",
            "/",
            "--docker-policy",
            &policy,
            "--",
            "/usr/bin/python3",
            "-c",
            r#"
import os, socket
host, port = os.environ['DOCKER_HOST'].removeprefix('tcp://').rsplit(':', 1)
with socket.create_connection((host, int(port))) as stream:
    stream.sendall(b'ready')
    stream.recv(1)
"#,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let connected = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let (mut stream, _) = engine.accept().await?;
        let mut request = [0_u8; 5];
        stream.read_exact(&mut request).await?;
        Ok::<_, std::io::Error>((stream, request))
    })
    .await;
    // Always reap the owned process before asserting on fixture setup.
    let _ = child.kill();
    let output = child.wait_with_output().unwrap();
    let (mut stream, request) = connected
        .unwrap_or_else(|error| {
            panic!(
                "bridge connection failed: {error}; {}",
                String::from_utf8_lossy(&output.stderr)
            )
        })
        .unwrap();
    assert_eq!(&request, b"ready");
    let mut remaining = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stream.read_to_end(&mut remaining),
    )
    .await
    .expect("engine transport closed after launcher cancellation")
    .unwrap();
}

struct DisposableContainers {
    names: Vec<String>,
}

impl DisposableContainers {
    fn new() -> Self {
        Self { names: Vec::new() }
    }

    fn track(&mut self, name: String) {
        self.names.push(name);
    }
}

impl Drop for DisposableContainers {
    fn drop(&mut self) {
        for name in &self.names {
            let _ = std::process::Command::new("docker")
                .args(["rm", "-fv", name])
                .output();
        }
    }
}

fn docker_test_identity() -> (String, String) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let suffix = format!("{}{}", std::process::id(), nonce);
    (format!("zerobox-e2e-{suffix}"), format!("zbe2e{suffix}"))
}

fn docker_test_endpoint() -> UnixSocketPath {
    UnixSocketPath::from_str(
        &std::env::var("ZEROBOX_DOCKER_TEST_ENDPOINT")
            .unwrap_or_else(|_| "/var/run/docker.sock".to_string()),
    )
    .expect("local Docker test endpoint")
}

fn create_test_container(
    cleanup: &mut DisposableContainers,
    name: &str,
    project: &str,
    service: &str,
    image: &str,
) {
    let output = std::process::Command::new("docker")
        .args([
            "create",
            "--name",
            name,
            "--network",
            "none",
            "--security-opt",
            "no-new-privileges",
            "--label",
            &format!("com.docker.compose.project={project}"),
            "--label",
            &format!("com.docker.compose.service={service}"),
            "--label",
            "com.docker.compose.oneoff=False",
            "--label",
            "com.docker.compose.container-number=1",
            "--label",
            "com.docker.compose.config-hash=zerobox-e2e",
            image,
        ])
        .output()
        .expect("create disposable Docker container");
    assert!(
        output.status.success(),
        "failed to create disposable container {name}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    cleanup.track(name.to_string());
}

#[tokio::test]
#[ignore = "mutates only uniquely named disposable containers on a local Docker Engine"]
async fn sdk_targeted_docker_cli_and_compose_matrix_is_confined_to_the_granted_service() {
    let image = std::env::var("ZEROBOX_DOCKER_TEST_IMAGE")
        .expect("set ZEROBOX_DOCKER_TEST_IMAGE to an existing local image");
    let (_, project) = docker_test_identity();
    let prefix = project.clone();
    let allowed = format!("{project}-api-1");
    let denied = format!("{project}-db-1");
    let root = temp_dir();
    std::fs::write(
        root.path().join("compose.yml"),
        format!("services:\n  api:\n    image: {image}\n  db:\n    image: {image}\n"),
    )
    .unwrap();
    let mut cleanup = DisposableContainers::new();
    create_test_container(&mut cleanup, &allowed, &project, "api", &image);
    create_test_container(&mut cleanup, &denied, &project, "db", &image);

    let policy = DockerAccessPolicy::Targeted {
        endpoint: docker_test_endpoint(),
        targets: vec![DockerTargetGrant {
            selector: DockerTargetSelector::ComposeService {
                project: project.clone(),
                service: "api".to_string(),
            },
            operations: None,
            allow_unsafe_target: false,
        }],
    };
    let script = format!(
        concat!(
            "set -eu; ",
            "docker ps -a --format '{{{{.Names}}}}' | grep -Fx '{allowed}'; ",
            "! docker ps -a --format '{{{{.Names}}}}' | grep -Fx '{denied}'; ",
            "docker inspect '{allowed}' >/dev/null; ",
            "! docker inspect '{denied}' >/dev/null 2>&1; ",
            "docker start '{allowed}' >/dev/null; ",
            "docker logs '{allowed}' >/dev/null; ",
            "docker stats --no-stream --format '{{{{.Name}}}}' '{allowed}' | grep -Fx '{allowed}'; ",
            "test \"$(docker exec '{allowed}' sh -c 'printf broker-ok')\" = broker-ok; ",
            "docker restart '{allowed}' >/dev/null; ",
            "docker stop '{allowed}' >/dev/null; ",
            "docker start '{allowed}' >/dev/null; ",
            "docker compose -p '{project}' -f compose.yml ps -a --format json >/dev/null; ",
            "docker compose -p '{project}' -f compose.yml logs --no-color api >/dev/null; ",
            "test \"$(docker compose -p '{project}' -f compose.yml exec -T api sh -c 'printf compose-ok')\" = compose-ok; ",
            "docker compose -p '{project}' -f compose.yml restart api >/dev/null; ",
            "docker compose -p '{project}' -f compose.yml stop api >/dev/null; ",
            "docker compose -p '{project}' -f compose.yml start api >/dev/null; ",
            "! docker rm -f '{allowed}' >/dev/null 2>&1; ",
            "! docker create --name '{prefix}-forbidden-create' --network none '{image}' >/dev/null 2>&1; ",
            "docker stop '{allowed}' >/dev/null"
        ),
        allowed = allowed,
        denied = denied,
        project = project,
        prefix = prefix,
        image = image,
    );

    let output = Sandbox::command("/bin/sh")
        .args(&["-c", &script])
        .cwd(root.path())
        .no_profile()
        .allow_read("/")
        .allow_write(root.path())
        .deny_read_glob("*.pem")
        .docker_access(policy)
        .linux_sandbox_exe(zerobox_exec())
        .run()
        .await
        .expect("run targeted Docker CLI matrix");

    assert!(
        output.status.success(),
        "targeted Docker matrix failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let denied_state = std::process::Command::new("docker")
        .args(["inspect", "--format", "{{.State.Status}}", &denied])
        .output()
        .expect("inspect denied disposable container");
    assert!(denied_state.status.success());
    assert_eq!(
        String::from_utf8_lossy(&denied_state.stdout).trim(),
        "created"
    );
}

#[tokio::test]
#[ignore = "mutates only one uniquely named disposable container on a local Docker Engine"]
async fn sdk_full_docker_mode_can_manage_only_the_named_e2e_container() {
    let image = std::env::var("ZEROBOX_DOCKER_TEST_IMAGE")
        .expect("set ZEROBOX_DOCKER_TEST_IMAGE to an existing local image");
    let (prefix, _) = docker_test_identity();
    let name = format!("{prefix}-full");
    let mut cleanup = DisposableContainers::new();
    cleanup.track(name.clone());
    let script = format!(
        concat!(
            "set -eu; ",
            "docker create --name '{name}' --network none --security-opt no-new-privileges '{image}' >/dev/null; ",
            "docker start '{name}' >/dev/null; ",
            "docker inspect '{name}' >/dev/null; ",
            "docker stop '{name}' >/dev/null; ",
            "docker rm -v '{name}' >/dev/null"
        ),
        name = name,
        image = image,
    );
    let output = Sandbox::command("/bin/sh")
        .args(&["-c", &script])
        .no_profile()
        .allow_read("/")
        .docker_access(DockerAccessPolicy::Full {
            endpoint: docker_test_endpoint(),
        })
        .linux_sandbox_exe(zerobox_exec())
        .run()
        .await
        .expect("run full Docker E2E");

    assert!(
        output.status.success(),
        "full Docker E2E failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let inspect = std::process::Command::new("docker")
        .args(["inspect", &name])
        .output()
        .expect("confirm full-mode test cleanup");
    assert!(!inspect.status.success());
}
