use crate::support::zerobox_exec;
use zerobox::Sandbox;

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
