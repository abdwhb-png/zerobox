pub use std::path::PathBuf;
pub use std::process::{Command, Output};

pub fn zerobox_exec() -> PathBuf {
    let path: PathBuf = std::env::var("ZEROBOX_EXEC")
        .map(PathBuf::from)
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_zerobox").into());
    if path.is_relative() {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root")
            .join(&path)
    } else {
        path
    }
}

fn declared_readable_cwd(args: &[&str]) -> PathBuf {
    let mut values = args.iter().copied();
    while let Some(value) = values.next() {
        let read_roots = value
            .strip_prefix("--allow-read=")
            .or_else(|| (value == "--allow-read").then(|| values.next()).flatten());
        if let Some(read_roots) = read_roots {
            if let Some(root) = read_roots
                .split(',')
                .map(PathBuf::from)
                .find(|root| root.is_absolute() && root.is_dir())
            {
                // The Linux sandbox deliberately ignores a system bwrap located
                // beneath its current directory. /usr would therefore hide
                // /usr/bin/bwrap even though it is an allowed working tree.
                // Use an equally readable descendant outside that executable
                // path for the fixtures that grant only /usr.
                if root == PathBuf::from("/usr") {
                    let share = root.join("share");
                    if share.is_dir() {
                        return share;
                    }
                }
                return root;
            }
        }
    }
    PathBuf::from("/tmp")
}

fn command_with_declared_readable_cwd(args: &[&str]) -> Command {
    let mut command = Command::new(zerobox_exec());
    command.current_dir(declared_readable_cwd(args)).args(args);
    command
}

fn zerobox_home_for_test() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("zerobox-integration-home-")
        .tempdir_in("/var/tmp")
        .expect("create test-local Zerobox home")
}

pub fn run(args: &[&str]) -> Output {
    let zerobox_home = zerobox_home_for_test();
    command_with_declared_readable_cwd(args)
        .env("ZEROBOX_HOME", zerobox_home.path())
        .output()
        .expect("failed to spawn zerobox")
}

pub fn run_with_home(home: &std::path::Path, args: &[&str]) -> Output {
    command_with_declared_readable_cwd(args)
        .env("ZEROBOX_HOME", home)
        .output()
        .expect("failed to spawn zerobox")
}

pub fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

pub fn temp_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("create temp dir")
}

pub fn setup_tmp(name: &str) -> PathBuf {
    let dir = PathBuf::from(format!("/tmp/zerobox-e2e-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("setup dir");
    dir
}

pub fn curl_status(args: &[&str], url: &str) -> (String, bool) {
    let mut full_args: Vec<&str> = args.to_vec();
    full_args.extend([
        "--",
        "curl",
        "-sL",
        "--max-time",
        "5",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        url,
    ]);
    let out = run(&full_args);
    let code = stdout(&out).trim().to_string();
    (code.clone(), code == "200")
}
