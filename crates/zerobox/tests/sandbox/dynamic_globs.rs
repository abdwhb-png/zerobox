use crate::support::{Command, temp_dir, zerobox_exec};
use zerobox::Sandbox;

#[tokio::test]
async fn sdk_dynamic_globs_are_enforced_inside_bubblewrap() {
    let project = temp_dir();
    std::fs::create_dir_all(project.path().join("generated")).unwrap();
    std::fs::write(project.path().join("visible.txt"), "visible").unwrap();
    std::fs::write(project.path().join("secret.pem"), "secret").unwrap();
    std::fs::write(project.path().join("generated/out.txt"), "generated").unwrap();

    let output = Sandbox::command("/bin/sh")
        .args(&[
            "-c",
            concat!(
                "test \"$(cat visible.txt)\" = visible && ",
                "! cat secret.pem >/dev/null 2>&1 && ",
                "test \"$(cat generated/out.txt)\" = generated && ",
                "! printf changed >generated/out.txt 2>/dev/null && ",
                "printf allowed >allowed.txt && ",
                "! mv allowed.txt renamed.pem 2>/dev/null && ",
                "test -f allowed.txt && ",
                "! printf late >late.pem 2>/dev/null && ",
                "! ls -1 | grep -Fx secret.pem >/dev/null"
            ),
        ])
        .cwd(project.path())
        .no_profile()
        .allow_read("/")
        .allow_write(project.path())
        .deny_read_glob("*.pem")
        .deny_write_glob("generated/**")
        .linux_sandbox_exe(zerobox_exec())
        .run()
        .await
        .expect("run dynamic glob sandbox");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(project.path().join("generated/out.txt")).unwrap(),
        "generated"
    );
    assert_eq!(
        std::fs::read_to_string(project.path().join("allowed.txt")).unwrap(),
        "allowed"
    );
    assert!(!project.path().join("late.pem").exists());
    assert!(!project.path().join("renamed.pem").exists());
}

#[test]
fn cli_dynamic_globs_fail_closed_without_fusermount() {
    let project = temp_dir();
    let output = Command::new(zerobox_exec())
        .args([
            "--strict-sandbox",
            "--cwd",
            project.path().to_str().expect("UTF-8 temporary path"),
            "--deny-read-glob",
            "*.pem",
            "--",
            "/bin/true",
        ])
        .env("PATH", "/definitely/missing")
        .output()
        .expect("invoke zerobox");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("dynamic deny globs require fusermount3 on PATH"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
