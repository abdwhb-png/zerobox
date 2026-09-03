use crate::support::{Command, temp_dir};

fn git(repo: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .current_dir(repo)
        .args(args)
        .output()
        .expect("run git")
}

#[test]
fn no_argument_sync_rejects_a_moved_tag_before_cleaning_upstream() {
    let temp = temp_dir();
    let source = temp.path().join("source");
    let fork = temp.path().join("fork");
    std::fs::create_dir_all(source.join("codex-rs")).expect("create fake upstream");
    assert!(git(&source, &["init", "-q"]).status.success());
    assert!(
        git(&source, &["config", "user.email", "test@example.invalid"])
            .status
            .success()
    );
    assert!(
        git(&source, &["config", "user.name", "Zerobox Test"])
            .status
            .success()
    );
    std::fs::write(source.join("codex-rs/source.txt"), "first\n").expect("write source");
    assert!(git(&source, &["add", "."]).status.success());
    assert!(
        git(&source, &["commit", "-q", "-m", "first"])
            .status
            .success()
    );
    assert!(git(&source, &["tag", "moving-tag"]).status.success());
    let pinned = String::from_utf8(git(&source, &["rev-parse", "HEAD"]).stdout)
        .expect("UTF-8 SHA")
        .trim()
        .to_string();

    std::fs::write(source.join("codex-rs/source.txt"), "second\n").expect("move source");
    assert!(git(&source, &["add", "."]).status.success());
    assert!(
        git(&source, &["commit", "-q", "-m", "second"])
            .status
            .success()
    );
    assert!(git(&source, &["tag", "-f", "moving-tag"]).status.success());

    std::fs::create_dir_all(fork.join("scripts")).expect("create scripts directory");
    std::fs::create_dir_all(fork.join("upstream")).expect("create upstream directory");
    std::fs::copy(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/sync.sh"),
        fork.join("scripts/sync.sh"),
    )
    .expect("copy sync script");
    std::fs::write(
        fork.join("UPSTREAM_VERSION"),
        format!("moving-tag\n# commit: {pinned}\n"),
    )
    .expect("write version file");
    let sentinel = fork.join("upstream/must-survive");
    std::fs::write(&sentinel, "preserve\n").expect("write sentinel");

    let output = Command::new("bash")
        .arg(fork.join("scripts/sync.sh"))
        .current_dir(&fork)
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_VALUE_0", "https://github.com/openai/codex.git")
        .env(
            "GIT_CONFIG_KEY_0",
            format!("url.file://{}/.insteadOf", source.display()),
        )
        .output()
        .expect("run sync script");

    assert!(!output.status.success());
    assert!(
        sentinel.exists(),
        "sync cleaned upstream before checking the pinned SHA"
    );
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        diagnostic.contains("pinned commit"),
        "diagnostic: {diagnostic}"
    );
}
