use crate::support::*;

#[test]
fn git_writes_follow_project_permissions() {
    let root = temp_dir();
    let repo = root.path().join("repo");
    let home = root.path().join("zerobox-home");
    std::fs::create_dir(&repo).unwrap();
    let init = Command::new("git")
        .args(["init", "-q"])
        .current_dir(&repo)
        .output()
        .unwrap();
    assert!(init.status.success(), "{}", stderr(&init));
    let output = Command::new(zerobox_exec())
        .current_dir(&repo)
        .env("ZEROBOX_HOME", &home)
        .args(["--profile", "workspace", "--allow-write", repo.to_str().unwrap(), "--", "bash", "-c",
            "set -eu; git checkout -b candidate; printf test > tracked; git add tracked; git -c user.name=Fixture -c user.email=fixture@example.test commit -qm initial; git worktree add .worktrees/one -b second; git -C .worktrees/one rev-parse --verify HEAD"])
        .output().unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(repo.join(".git/refs/heads/candidate").exists());
    assert!(repo.join(".worktrees/one/tracked").exists());
}

#[test]
fn git_explicit_denial_still_blocks_writes() {
    let root = temp_dir();
    let repo = root.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(&repo)
            .status()
            .unwrap()
            .success()
    );
    let output = Command::new(zerobox_exec())
        .current_dir(&repo)
        .env("ZEROBOX_HOME", root.path().join("home"))
        .args([
            "--profile",
            "workspace",
            "--allow-write",
            repo.to_str().unwrap(),
            "--deny-write",
            repo.join(".git").to_str().unwrap(),
            "--",
            "git",
            "config",
            "fixture.value",
            "denied",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{}", stdout(&output));
    assert!(
        !std::fs::read_to_string(repo.join(".git/config"))
            .unwrap()
            .contains("denied")
    );
}

#[test]
fn git_pointer_does_not_grant_external_metadata_writes() {
    let root = tempfile::tempdir_in("/var/tmp").unwrap();
    let repo = root.path().join("repo");
    let outside = root.path().join("outside");
    std::fs::create_dir(&repo).unwrap();
    assert!(
        Command::new("git")
            .args(["init", "--bare", "-q"])
            .arg(&outside)
            .status()
            .unwrap()
            .success()
    );
    std::fs::write(
        repo.join(".git"),
        format!("gitdir: {}\n", outside.display()),
    )
    .unwrap();
    let output = Command::new(zerobox_exec())
        .current_dir(&repo)
        .env("ZEROBOX_HOME", root.path().join("home"))
        .args([
            "--profile",
            "workspace",
            "--allow-write",
            repo.to_str().unwrap(),
            "--",
            "git",
            "config",
            "fixture.value",
            "escape",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{}", stdout(&output));
    assert!(
        !std::fs::read_to_string(outside.join("config"))
            .unwrap()
            .contains("escape")
    );
}

#[test]
fn git_symlink_does_not_grant_external_writes() {
    let root = tempfile::tempdir_in("/var/tmp").unwrap();
    let repo = root.path().join("repo");
    let outside = root.path().join("outside");
    std::fs::create_dir(&repo).unwrap();
    std::fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, repo.join(".git")).unwrap();
    let output = Command::new(zerobox_exec())
        .current_dir(&repo)
        .env("ZEROBOX_HOME", root.path().join("home"))
        .args([
            "--profile",
            "workspace",
            "--allow-write",
            repo.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            "printf escape > .git/intrusion",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success(), "{}", stdout(&output));
    assert!(!outside.join("intrusion").exists());
}
