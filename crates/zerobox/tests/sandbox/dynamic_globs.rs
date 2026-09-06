use crate::support::{Command, temp_dir, zerobox_exec};
use std::os::unix::fs::PermissionsExt;
use zerobox::Sandbox;

#[tokio::test]
async fn sdk_dynamic_globs_execute_shebang_scripts_without_weakening_denies() {
    let project = temp_dir();
    let denied = project.path().join("package/node_modules/blocked.txt");
    std::fs::create_dir_all(denied.parent().unwrap()).unwrap();
    let script = project.path().join("runner.sh");
    std::fs::write(&script, "#!/bin/sh\nprintf shebang-ok\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let output = Sandbox::command("/bin/sh")
        .args(&[
            "-c",
            "./runner.sh && ! printf blocked >package/node_modules/blocked.txt 2>/dev/null",
        ])
        .cwd(project.path())
        .no_profile()
        .allow_read("/")
        .allow_write(project.path())
        .deny_write_glob("*/node_modules/*")
        .linux_sandbox_exe(zerobox_exec())
        .run()
        .await
        .expect("run shebang script through dynamic glob sandbox");

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&output.stdout), "shebang-ok");
    assert!(!denied.exists());
}

#[tokio::test]
async fn sdk_dynamic_globs_preserve_shebang_process_errors() {
    let project = temp_dir();
    std::fs::create_dir_all(project.path().join("package/node_modules")).unwrap();
    let script = project.path().join("failure.sh");
    std::fs::write(
        &script,
        "#!/bin/sh\nprintf 'real-target-error\\n' >&2\nexit 37\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let output = Sandbox::command("/bin/sh")
        .args(&["-c", "./failure.sh"])
        .cwd(project.path())
        .no_profile()
        .allow_read("/")
        .allow_write(project.path())
        .deny_write_glob("*/node_modules/*")
        .linux_sandbox_exe(zerobox_exec())
        .run()
        .await
        .expect("run failing shebang script through dynamic glob sandbox");

    assert_eq!(output.status.code(), Some(37));
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "real-target-error\n"
    );
}

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
                "chmod 0600 allowed.txt && ",
                "test \"$(stat -c %a allowed.txt)\" = 600 && ",
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

#[tokio::test]
async fn sdk_dynamic_write_globs_block_mutations_through_symlinked_paths() {
    let project = temp_dir();
    let generated = project.path().join("generated");
    std::fs::create_dir_all(&generated).unwrap();
    std::fs::write(generated.join("remove.txt"), "keep").unwrap();
    std::fs::write(generated.join("chmod.txt"), "mode").unwrap();
    std::fs::write(generated.join("time.txt"), "time").unwrap();
    let original_time = std::fs::metadata(generated.join("time.txt"))
        .unwrap()
        .modified()
        .unwrap();
    std::fs::write(project.path().join("move.txt"), "move").unwrap();
    std::fs::write(project.path().join("link.txt"), "link").unwrap();
    std::os::unix::fs::symlink("generated", project.path().join("alias")).unwrap();
    std::os::unix::fs::symlink(
        "generated/new-via-link.txt",
        project.path().join("new-link"),
    )
    .unwrap();
    std::os::unix::fs::symlink("generated/remove.txt", project.path().join("write-link")).unwrap();
    std::os::unix::fs::symlink("generated/chmod.txt", project.path().join("chmod-link")).unwrap();
    std::os::unix::fs::symlink("generated/time.txt", project.path().join("time-link")).unwrap();

    let output = Sandbox::command("/bin/sh")
        .args(&[
            "-c",
            concat!(
                "blocked=0; ",
                "mkdir alias/new-dir 2>/dev/null && blocked=1; ",
                "printf created >alias/new.txt 2>/dev/null && blocked=1; ",
                "rm alias/remove.txt 2>/dev/null && blocked=1; ",
                "mv move.txt alias/moved.txt 2>/dev/null && blocked=1; ",
                "ln link.txt alias/hard.txt 2>/dev/null && blocked=1; ",
                "chmod 0777 alias/chmod.txt 2>/dev/null && blocked=1; ",
                "touch -t 200001010000 alias/time.txt 2>/dev/null && blocked=1; ",
                "printf created >new-link 2>/dev/null && blocked=1; ",
                "printf changed >write-link 2>/dev/null && blocked=1; ",
                "chmod 0777 chmod-link 2>/dev/null && blocked=1; ",
                "touch -t 200001010000 time-link 2>/dev/null && blocked=1; ",
                "test \"$blocked\" -eq 0"
            ),
        ])
        .cwd(project.path())
        .no_profile()
        .allow_read("/")
        .allow_write(project.path())
        .deny_write_glob("generated/**")
        .linux_sandbox_exe(zerobox_exec())
        .run()
        .await
        .expect("run symlink ancestor mutation sandbox");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!generated.join("new-dir").exists());
    assert!(!generated.join("new.txt").exists());
    assert!(generated.join("remove.txt").exists());
    assert!(!generated.join("moved.txt").exists());
    assert!(!generated.join("hard.txt").exists());
    assert!(!generated.join("new-via-link.txt").exists());
    assert_eq!(
        std::fs::read_to_string(generated.join("remove.txt")).unwrap(),
        "keep"
    );
    assert_ne!(
        std::fs::metadata(generated.join("chmod.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o777
    );
    assert_eq!(
        std::fs::metadata(generated.join("time.txt"))
            .unwrap()
            .modified()
            .unwrap(),
        original_time
    );
}

#[tokio::test]
async fn sdk_dynamic_globs_block_nofollow_metadata_through_symlinks() {
    for deny_read in [false, true] {
        let project = temp_dir();
        let generated = project.path().join("generated");
        std::fs::create_dir_all(&generated).unwrap();
        std::fs::write(generated.join("time.txt"), "time").unwrap();
        let original_time = std::fs::metadata(generated.join("time.txt"))
            .unwrap()
            .modified()
            .unwrap();
        std::os::unix::fs::symlink("generated/time.txt", project.path().join("time-link")).unwrap();

        let sandbox = Sandbox::command("/bin/sh")
            .args(&["-c", "! touch -h -t 200001010000 time-link 2>/dev/null"])
            .cwd(project.path())
            .no_profile()
            .allow_read("/")
            .allow_write(project.path());
        let sandbox = if deny_read {
            sandbox.deny_read_glob("generated/**")
        } else {
            sandbox.deny_write_glob("generated/**")
        };
        let output = sandbox
            .linux_sandbox_exe(zerobox_exec())
            .run()
            .await
            .expect("run nofollow symlink metadata sandbox");

        assert!(
            output.status.success(),
            "deny_read={deny_read}, stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::metadata(generated.join("time.txt"))
                .unwrap()
                .modified()
                .unwrap(),
            original_time
        );
    }
}

#[tokio::test]
async fn sdk_dynamic_globs_preserve_allowed_nofollow_symlink_metadata() {
    let project = temp_dir();
    std::fs::create_dir_all(project.path().join("blocked")).unwrap();
    std::fs::write(project.path().join("allowed.txt"), "allowed").unwrap();
    std::os::unix::fs::symlink("allowed.txt", project.path().join("allowed-link")).unwrap();
    let target_time = std::fs::metadata(project.path().join("allowed.txt"))
        .unwrap()
        .modified()
        .unwrap();

    let output = Sandbox::command("/bin/sh")
        .args(&["-c", "touch -h -t 200001010000 allowed-link"])
        .cwd(project.path())
        .no_profile()
        .allow_read("/")
        .allow_write(project.path())
        .deny_write_glob("blocked/**")
        .linux_sandbox_exe(zerobox_exec())
        .run()
        .await
        .expect("run allowed nofollow symlink metadata sandbox");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::metadata(project.path().join("allowed.txt"))
            .unwrap()
            .modified()
            .unwrap(),
        target_time
    );
    assert_ne!(
        std::fs::symlink_metadata(project.path().join("allowed-link"))
            .unwrap()
            .modified()
            .unwrap(),
        target_time
    );
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
