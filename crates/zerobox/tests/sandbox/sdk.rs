use crate::support::zerobox_exec;
use zerobox::Sandbox;

fn missing_target() -> Sandbox {
    Sandbox::command("/definitely/missing/zerobox-target")
        .no_profile()
        .allow_read("/")
        .linux_sandbox_exe(zerobox_exec())
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
