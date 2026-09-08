mod debug;
mod profile;
mod snapshot;

use debug::debug_log;

use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use clap::{Parser, Subcommand, error::ErrorKind};
#[cfg(target_os = "linux")]
use zerobox::arg0;
use zerobox::{DockerAccessPolicy, Sandbox};

#[derive(Parser, Debug)]
#[command(name = "zerobox", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub subcommand: Option<CliSubcommand>,

    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub allow_read: Option<Vec<PathBuf>>,

    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub deny_read: Option<Vec<PathBuf>>,

    #[arg(long = "deny-read-glob", action = clap::ArgAction::Append)]
    pub deny_read_glob: Vec<String>,

    #[arg(long, value_delimiter = ',', num_args = 0..)]
    pub allow_write: Option<Vec<PathBuf>>,

    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub deny_write: Option<Vec<PathBuf>>,

    #[arg(long = "deny-write-glob", action = clap::ArgAction::Append)]
    pub deny_write_glob: Vec<String>,

    #[arg(long, value_delimiter = ',', num_args = 0..)]
    pub allow_net: Option<Vec<String>>,

    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub allow_host_net: Option<Vec<String>>,

    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub deny_net: Option<Vec<String>>,

    /// Effective per-execution Docker policy supplied by a trusted launcher.
    #[arg(long, hide = true, value_parser = parse_docker_policy)]
    pub docker_policy: Option<DockerAccessPolicy>,

    #[arg(long, short = 'A')]
    pub allow_all: bool,

    #[arg(long, short = 'C')]
    pub cwd: Option<PathBuf>,

    #[arg(long)]
    pub no_sandbox: bool,

    #[arg(long)]
    pub strict_sandbox: bool,

    /// Use an owner-only session directory as private sandbox /tmp.
    #[arg(long)]
    pub private_tmp: Option<PathBuf>,

    /// Permit local TCP servers inside the isolated network namespace.
    #[arg(long)]
    pub allow_local_binding: bool,

    #[arg(long = "env", value_name = "KEY=VALUE")]
    pub set_env: Vec<String>,

    #[arg(long, value_delimiter = ',', num_args = 0..)]
    pub allow_env: Option<Vec<String>>,

    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub deny_env: Option<Vec<String>>,

    #[arg(long = "secret", value_name = "KEY=VALUE")]
    pub secret: Vec<String>,

    #[arg(long = "secret-host", value_name = "KEY=HOSTS")]
    pub secret_host: Vec<String>,

    #[arg(long)]
    pub debug: bool,

    /// Unix descriptor used by the outer supervisor for machine-readable
    /// setup and child lifecycle events.
    #[arg(
        long,
        help = "Writable Unix pipe or stream-socket FD for JSONL lifecycle records"
    )]
    pub status_fd: Option<i32>,

    #[arg(long = "profile", value_delimiter = ',')]
    pub profile: Vec<String>,

    #[arg(long)]
    pub snapshot: bool,

    #[arg(long)]
    pub restore: bool,

    #[arg(long = "snapshot-path", value_delimiter = ',', num_args = 1..)]
    pub snapshot_paths: Option<Vec<std::path::PathBuf>>,

    #[arg(long = "snapshot-exclude", value_delimiter = ',', num_args = 1..)]
    pub snapshot_exclude: Option<Vec<String>>,

    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum CliSubcommand {
    Snapshot {
        #[command(subcommand)]
        action: SnapshotAction,
    },
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum ProfileAction {
    List,
    Schema,
    Show { name: String },
}

#[derive(Subcommand, Debug)]
pub enum SnapshotAction {
    List,
    Diff {
        id: String,
    },
    Restore {
        id: String,
    },
    Clean {
        #[arg(long, default_value = "30")]
        older_than: u64,
    },
}

fn parse_docker_policy(value: &str) -> Result<DockerAccessPolicy, String> {
    serde_json::from_str(value).map_err(|error| format!("invalid Docker policy JSON: {error}"))
}

fn exit_code_from_status(status: std::process::ExitStatus) -> ExitCode {
    if let Some(code) = status.code() {
        return ExitCode::from(code as u8);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return ExitCode::from((128 + signal) as u8);
        }
    }
    ExitCode::from(1)
}

fn main() -> ExitCode {
    #[cfg(target_os = "linux")]
    arg0::dispatch_linux_sandbox_helper();

    let args: Vec<OsString> = std::env::args_os().collect();
    let advertised_status_fd = preparse_status_fd(&args);
    let mut status = match StatusReporter::new(advertised_status_fd) {
        Ok(status) => status,
        Err(error) => {
            eprintln!("error: {error}");
            return if advertised_status_fd.is_some() {
                ExitCode::from(125)
            } else {
                ExitCode::from(1)
            };
        }
    };
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let exit_code = error.exit_code();
            let informational = matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            );
            let message = error.to_string();
            let _ = error.print();
            if status.enabled() && !informational {
                let _ = status.setup_error("cli_parse", &message);
                return ExitCode::from(125);
            }
            return ExitCode::from(u8::try_from(exit_code).unwrap_or(1));
        }
    };

    #[cfg(target_os = "linux")]
    let arg0_guard = prepare_arg0_aliases(&cli);
    #[cfg(target_os = "linux")]
    let linux_sandbox_exe = arg0_guard
        .as_ref()
        .map(|guard| guard.zerobox_linux_sandbox_exe().to_path_buf());

    #[cfg(not(target_os = "linux"))]
    let linux_sandbox_exe = None;

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("error: failed to start async runtime: {e}");
            let _ = status.setup_error("runtime_start", &e.to_string());
            return status.setup_exit_code();
        }
    };

    runtime.block_on(tokio_main(cli, linux_sandbox_exe, status))
}

fn preparse_status_fd(args: &[OsString]) -> Option<i32> {
    let mut args = args.iter().skip(1);
    while let Some(arg) = args.next() {
        if arg == OsStr::new("--") {
            break;
        }
        if arg == OsStr::new("--status-fd") {
            return args.next().and_then(|value| value.to_str()?.parse().ok());
        }
        let Some(arg) = arg.to_str() else {
            continue;
        };
        if let Some(value) = arg.strip_prefix("--status-fd=") {
            return value.parse().ok();
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn prepare_arg0_aliases(cli: &Cli) -> Option<arg0::Arg0PathEntryGuard> {
    if cli.subcommand.is_some() || cli.command.is_empty() || cli.no_sandbox || cli.allow_all {
        return None;
    }

    match arg0::prepend_path_entry_for_zerobox_aliases() {
        Ok(guard) => Some(guard),
        Err(e) => {
            eprintln!("warning: proceeding without Linux sandbox helper alias: {e}");
            None
        }
    }
}

async fn tokio_main(
    cli: Cli,
    linux_sandbox_exe: Option<PathBuf>,
    mut status: StatusReporter,
) -> ExitCode {
    if cli.status_fd.is_some() && cli.subcommand.is_some() {
        let _ = status.setup_error(
            "unsupported_status_mode",
            "--status-fd is unavailable for subcommands",
        );
        return ExitCode::from(125);
    }
    if let Some(CliSubcommand::Snapshot { action }) = &cli.subcommand {
        return snapshot::handle_subcommand(action);
    }
    if let Some(CliSubcommand::Profile { action }) = &cli.subcommand {
        return profile::handle_subcommand(action);
    }

    if cli.command.is_empty() {
        eprintln!("error: no command specified");
        let _ = status.setup_error("missing_command", "no command specified");
        return status.setup_exit_code();
    }

    if cli.strict_sandbox && (cli.no_sandbox || cli.allow_all) {
        eprintln!("error: --strict-sandbox cannot be combined with --no-sandbox or --allow-all");
        let _ = status.setup_error(
            "invalid_configuration",
            "--strict-sandbox cannot be combined with --no-sandbox or --allow-all",
        );
        return status.setup_exit_code();
    }

    let dbg = cli.debug;
    if dbg {
        debug::init_tracing();
    }

    let mut sandbox = Sandbox::command(&cli.command[0])
        .args(&cli.command[1..])
        .linux_sandbox_exe_opt(linux_sandbox_exe)
        .setup_status(status.enabled());
    sandbox = sandbox.allow_local_binding(cli.allow_local_binding);

    if let Some(ref cwd) = cli.cwd {
        sandbox = sandbox.cwd(cwd);
    }
    if let Some(ref private_tmp) = cli.private_tmp {
        sandbox = sandbox.private_tmp(private_tmp);
    }

    if cli.no_sandbox {
        sandbox = sandbox.no_sandbox().no_profile();
    } else if cli.allow_all {
        sandbox = sandbox.full_access().no_profile();
    } else {
        if cli.strict_sandbox {
            sandbox = sandbox.strict();
        }
        if !cli.profile.is_empty() {
            sandbox = sandbox.profiles(&cli.profile);
        }
    }
    // else: default profile loads automatically

    if let Some(ref paths) = cli.allow_read {
        for p in paths {
            sandbox = sandbox.allow_read(p);
        }
    }
    if let Some(ref paths) = cli.deny_read {
        for p in paths {
            sandbox = sandbox.deny_read(p);
        }
    }
    for pattern in &cli.deny_read_glob {
        sandbox = sandbox.deny_read_glob(pattern);
    }
    if let Some(ref paths) = cli.allow_write {
        if paths.is_empty() {
            sandbox = sandbox.allow_write_all();
        } else {
            for p in paths {
                sandbox = sandbox.allow_write(p);
            }
        }
    }
    if let Some(ref paths) = cli.deny_write {
        for p in paths {
            sandbox = sandbox.deny_write(p);
        }
    }
    for pattern in &cli.deny_write_glob {
        sandbox = sandbox.deny_write_glob(pattern);
    }

    if let Some(ref domains) = cli.allow_net {
        if domains.is_empty() {
            sandbox = sandbox.allow_net_all();
        } else {
            sandbox = sandbox.allow_net(domains);
        }
    }
    if let Some(ref domains) = cli.allow_host_net {
        sandbox = sandbox.allow_host_net(domains);
    }
    if let Some(ref domains) = cli.deny_net {
        sandbox = sandbox.deny_net(domains);
    }
    if let Some(ref docker_policy) = cli.docker_policy {
        sandbox = sandbox.docker_access(docker_policy.clone());
    }

    for pair in &cli.set_env {
        if let Some((key, value)) = pair.split_once('=') {
            sandbox = sandbox.env(key, value);
        } else {
            eprintln!("error: invalid --env value '{pair}': expected KEY=VALUE format");
            let _ = status.setup_error("invalid_environment", "invalid --env value");
            return status.setup_exit_code();
        }
    }
    if let Some(ref keys) = cli.allow_env {
        if keys.is_empty() {
            sandbox = sandbox.inherit_env();
        } else {
            sandbox = sandbox.allow_env(keys);
        }
    }
    if let Some(ref keys) = cli.deny_env {
        sandbox = sandbox.deny_env(keys);
    }

    for pair in &cli.secret {
        if let Some((key, value)) = pair.split_once('=') {
            if key.is_empty() {
                eprintln!("error: invalid --secret value '{pair}': key cannot be empty");
                let _ = status.setup_error("invalid_secret", "secret key cannot be empty");
                return status.setup_exit_code();
            }
            sandbox = sandbox.secret(key, value);
        } else {
            eprintln!("error: invalid --secret value '{pair}': expected KEY=VALUE format");
            let _ = status.setup_error("invalid_secret", "invalid --secret value");
            return status.setup_exit_code();
        }
    }
    for pair in &cli.secret_host {
        if let Some((key, hosts)) = pair.split_once('=') {
            sandbox = sandbox.secret_host(key, hosts);
        } else {
            eprintln!("error: invalid --secret-host value '{pair}': expected KEY=HOSTS format");
            let _ = status.setup_error("invalid_secret", "invalid --secret-host value");
            return status.setup_exit_code();
        }
    }

    debug_log!(
        dbg,
        "cwd: {:?}",
        cli.cwd.as_deref().unwrap_or(Path::new("."))
    );

    let cwd = cli
        .cwd
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let do_snapshot = cli.snapshot || cli.restore;
    let snapshot_state = if do_snapshot {
        match snapshot::build_snapshot_state(&cli, &cwd) {
            Ok(mut state) => match state.manager.create_baseline() {
                Ok(baseline) => {
                    debug_log!(
                        dbg,
                        "snapshot: baseline captured ({} files)",
                        baseline.files.len()
                    );
                    Some((state, baseline))
                }
                Err(e) => {
                    if cli.restore {
                        eprintln!("error: --restore requires snapshot but baseline failed: {e:#}");
                        let _ = status.setup_error("snapshot_setup", "snapshot baseline failed");
                        return status.setup_exit_code();
                    }
                    eprintln!("warning: snapshot baseline failed: {e:#}");
                    None
                }
            },
            Err(e) => {
                if cli.restore {
                    eprintln!("error: --restore requires snapshot but setup failed: {e:#}");
                    let _ = status.setup_error("snapshot_setup", "snapshot setup failed");
                    return status.setup_exit_code();
                }
                eprintln!("warning: snapshot setup failed: {e:#}");
                None
            }
        }
    } else {
        None
    };

    let relay_stdio = should_relay_stdio();
    let child = if relay_stdio {
        sandbox.spawn_streaming().await
    } else {
        sandbox.spawn_inherited().await
    };

    let (exit, raw_exit_code) = match child {
        Ok(mut child) => {
            if let Err(error) = status.child_started(child.pid()) {
                eprintln!("error: failed to emit child_started status event: {error}");
                if let Err(kill_error) = child.kill_and_wait().await {
                    eprintln!(
                        "error: failed to reap target after status delivery failure: {kill_error:#}"
                    );
                }
                return ExitCode::from(125);
            }
            let child_status = if relay_stdio {
                let stdout = child.stdout();
                let stderr = child.stderr();
                let stdout_task = tokio::spawn(forward_stdout(stdout));
                let stderr_task = tokio::spawn(forward_stderr(stderr));
                let stdout_abort = stdout_task.abort_handle();
                let stderr_abort = stderr_task.abort_handle();
                let child_status = child.wait().await;
                if tokio::time::timeout(Duration::from_millis(250), async {
                    let _ = tokio::join!(stdout_task, stderr_task);
                })
                .await
                .is_err()
                {
                    stdout_abort.abort();
                    stderr_abort.abort();
                }
                child_status
            } else {
                child.wait().await
            };
            match child_status {
                Ok(child_status) => {
                    if let Err(error) = status.child_exit(child_status) {
                        eprintln!("error: failed to emit child_exit status event: {error}");
                        return ExitCode::from(125);
                    }
                    (exit_code_from_status(child_status), child_status.code())
                }
                Err(e) => {
                    eprintln!("error: {e:#}");
                    status.close();
                    (ExitCode::from(1), Some(1))
                }
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            let _ = status.setup_error("sandbox_setup", &e.to_string());
            (
                status.setup_exit_code(),
                Some(if status.enabled() { 125 } else { 1 }),
            )
        }
    };

    if let Some((mut state, baseline)) = snapshot_state {
        let incremental = state.manager.create_incremental(&baseline);

        if let Ok((_, ref changes)) = incremental {
            snapshot::print_summary_to(changes, &mut std::io::stderr());
        } else if let Err(ref e) = incremental {
            eprintln!("snapshot: incremental failed: {e:#}");
        }

        let mut meta = snapshot::build_session_metadata(&state, &cli, &baseline);
        meta.ended = Some(chrono::Utc::now().to_rfc3339());
        meta.exit_code = raw_exit_code;
        meta.snapshot_count = state.manager.snapshot_count();
        if let Ok((ref final_manifest, _)) = incremental {
            meta.merkle_roots.push(final_manifest.merkle_root);
        }
        if let Err(e) = state.manager.save_session(&meta) {
            eprintln!("snapshot: failed to save session: {e:#}");
        }

        if cli.restore {
            match state.manager.restore_to(&baseline) {
                Ok(applied) if !applied.is_empty() => {
                    eprintln!("snapshot: restored {} files", applied.len());
                }
                Err(e) => {
                    eprintln!("snapshot: restore failed: {e:#}");
                    return ExitCode::from(1);
                }
                _ => {}
            }
        }
    }

    exit
}

fn should_relay_stdio() -> bool {
    #[cfg(unix)]
    {
        descriptor_is_socket(libc::STDOUT_FILENO) || descriptor_is_socket(libc::STDERR_FILENO)
    }
    #[cfg(not(unix))]
    {
        !std::io::IsTerminal::is_terminal(&std::io::stdin())
    }
}

#[cfg(unix)]
fn descriptor_is_socket(fd: RawFd) -> bool {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, metadata.as_mut_ptr()) } != 0 {
        return false;
    }
    let file_type = unsafe { metadata.assume_init().st_mode & libc::S_IFMT };
    file_type == libc::S_IFSOCK
}

async fn forward_stdout(mut source: Option<tokio::process::ChildStdout>) {
    if let Some(source) = source.as_mut() {
        let _ = tokio::io::copy(source, &mut tokio::io::stdout()).await;
    }
}

async fn forward_stderr(mut source: Option<tokio::process::ChildStderr>) {
    if let Some(source) = source.as_mut() {
        let _ = tokio::io::copy(source, &mut tokio::io::stderr()).await;
    }
}

struct StatusReporter {
    enabled: bool,
    #[cfg(unix)]
    destination: Option<StatusDestination>,
}

#[cfg(unix)]
enum StatusDestination {
    Pipe(OwnedFd),
    StreamSocket(OwnedFd),
}

impl StatusReporter {
    fn new(fd: Option<i32>) -> std::result::Result<Self, String> {
        #[cfg(unix)]
        {
            let Some(fd) = fd else {
                return Ok(Self {
                    enabled: false,
                    destination: None,
                });
            };
            if fd < 3 {
                return Err("--status-fd must be at least 3".to_string());
            }
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags < 0 {
                return Err(format!(
                    "invalid --status-fd {fd}: {}",
                    std::io::Error::last_os_error()
                ));
            }
            // The descriptor has been proven valid. From this point onward the
            // reporter owns it, including on every validation error below.
            let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
            let fd = owned_fd.as_raw_fd();
            let access = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if access < 0 || access & libc::O_ACCMODE == libc::O_RDONLY {
                return Err(format!("--status-fd {fd} is not writable"));
            }
            let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
            if unsafe { libc::fstat(fd, metadata.as_mut_ptr()) } < 0 {
                return Err(format!(
                    "cannot inspect --status-fd {fd}: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let file_type = unsafe { metadata.assume_init().st_mode & libc::S_IFMT };
            let destination = match file_type {
                libc::S_IFIFO => {
                    if unsafe { libc::fcntl(fd, libc::F_SETFL, access | libc::O_NONBLOCK) } < 0 {
                        return Err(format!(
                            "cannot make --status-fd {fd} nonblocking: {}",
                            std::io::Error::last_os_error()
                        ));
                    }
                    StatusDestination::Pipe(owned_fd)
                }
                libc::S_IFSOCK => {
                    let mut socket_type = 0;
                    let mut socket_type_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
                    if unsafe {
                        libc::getsockopt(
                            fd,
                            libc::SOL_SOCKET,
                            libc::SO_TYPE,
                            (&mut socket_type as *mut libc::c_int).cast(),
                            &mut socket_type_len,
                        )
                    } < 0
                    {
                        return Err(format!(
                            "cannot inspect --status-fd {fd} socket type: {}",
                            std::io::Error::last_os_error()
                        ));
                    }
                    if socket_type != libc::SOCK_STREAM {
                        return Err("--status-fd Unix socket must use SOCK_STREAM".to_string());
                    }
                    let mut socket_address =
                        std::mem::MaybeUninit::<libc::sockaddr_storage>::zeroed();
                    let mut socket_address_len =
                        std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                    if unsafe {
                        libc::getsockname(
                            fd,
                            socket_address.as_mut_ptr().cast(),
                            &mut socket_address_len,
                        )
                    } < 0
                    {
                        return Err(format!(
                            "cannot inspect --status-fd {fd} socket address: {}",
                            std::io::Error::last_os_error()
                        ));
                    }
                    if unsafe { socket_address.assume_init().ss_family } as libc::c_int
                        != libc::AF_UNIX
                    {
                        return Err("--status-fd socket must use AF_UNIX".to_string());
                    }
                    StatusDestination::StreamSocket(owned_fd)
                }
                _ => {
                    return Err(
                        "--status-fd must be a writable Unix pipe or stream socket".to_string()
                    );
                }
            };
            if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
                return Err(format!(
                    "cannot protect --status-fd {fd}: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(Self {
                enabled: true,
                destination: Some(destination),
            })
        }
        #[cfg(not(unix))]
        {
            if fd.is_some() {
                return Err("--status-fd is supported only on Unix".to_string());
            }
            Ok(Self { enabled: false })
        }
    }

    fn setup_exit_code(&self) -> ExitCode {
        if self.enabled() {
            ExitCode::from(125)
        } else {
            ExitCode::from(1)
        }
    }
    fn enabled(&self) -> bool {
        self.enabled
    }
    fn setup_error(&mut self, code: &str, message: &str) -> std::io::Result<()> {
        // 512 code points stay below PIPE_BUF even when every character is
        // JSON-escaped as `\uXXXX`.
        let mut chars = message.chars();
        let mut message = chars.by_ref().take(512).collect::<String>();
        if chars.next().is_some() {
            message.push_str(" [truncated; full diagnostic on stderr]");
        }
        self.emit_terminal(
            serde_json::json!({"version":1,"event":"setup_error","code":code,"message":message}),
        )
    }
    fn child_started(&mut self, pid: u32) -> std::io::Result<()> {
        let result = self.emit(serde_json::json!({"version":1,"event":"child_started","pid":pid,"pid_scope":"supervisor"}));
        if result.is_err() {
            self.close();
        }
        result
    }
    fn child_exit(&mut self, status: std::process::ExitStatus) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            if let Some(signal) = status.signal() {
                return self.emit_terminal(serde_json::json!({"version":1,"event":"child_exit","code":128 + signal,"signal":signal}));
            }
        }
        self.emit_terminal(
            serde_json::json!({"version":1,"event":"child_exit","code":status.code().unwrap_or(1)}),
        )
    }
    fn emit_terminal(&mut self, value: serde_json::Value) -> std::io::Result<()> {
        let result = self.emit(value);
        self.close();
        result
    }
    fn close(&mut self) {
        #[cfg(unix)]
        {
            self.destination.take();
        }
    }
    fn emit(&self, value: serde_json::Value) -> std::io::Result<()> {
        #[cfg(unix)]
        if let Some(destination) = self.destination.as_ref() {
            let line = format!("{value}\n");
            if line.len() > libc::PIPE_BUF {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "status event exceeds PIPE_BUF",
                ));
            }
            let (fd, socket) = match destination {
                StatusDestination::Pipe(fd) => (fd.as_raw_fd(), false),
                StatusDestination::StreamSocket(fd) => (fd.as_raw_fd(), true),
            };
            let mut offset = 0;
            loop {
                let remaining = &line.as_bytes()[offset..];
                let written = if socket {
                    unsafe {
                        libc::send(
                            fd,
                            remaining.as_ptr().cast(),
                            remaining.len(),
                            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                        )
                    }
                } else {
                    unsafe { libc::write(fd, remaining.as_ptr().cast(), remaining.len()) }
                };
                if written > 0 {
                    offset += written as usize;
                    if offset == line.len() {
                        return Ok(());
                    }
                    continue;
                }
                let error = std::io::Error::last_os_error();
                if written < 0 && error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::os::fd::IntoRawFd;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    #[test]
    fn long_setup_diagnostics_explicitly_report_truncation() {
        let (reader, writer) = UnixStream::pair().unwrap();
        let mut reporter = StatusReporter::new(Some(writer.into_raw_fd())).unwrap();
        reporter.setup_error("setup", &"x".repeat(2000)).unwrap();
        let mut line = String::new();
        BufReader::new(reader).read_line(&mut line).unwrap();
        let event: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert!(
            event["message"]
                .as_str()
                .unwrap()
                .ends_with("[truncated; full diagnostic on stderr]")
        );
        assert!(line.len() < 4096);
    }

    #[test]
    fn status_fd_preparse_skips_non_utf8_arguments() {
        let args = vec![
            OsString::from("zerobox"),
            OsString::from_vec(vec![0xff]),
            OsString::from("--status-fd=3"),
        ];

        assert_eq!(preparse_status_fd(&args), Some(3));
    }

    #[test]
    fn terminal_status_event_closes_the_owned_descriptor() {
        let (reader, writer) = UnixStream::pair().expect("create status socket pair");
        reader
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("set read timeout");
        let mut reporter =
            StatusReporter::new(Some(writer.into_raw_fd())).expect("create reporter");

        reporter
            .setup_error("test_error", "terminal event")
            .expect("write terminal event");

        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        assert_ne!(reader.read_line(&mut line).expect("read terminal event"), 0);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&line).expect("parse event")["event"],
            "setup_error"
        );
        line.clear();
        assert_eq!(reader.read_line(&mut line).expect("read EOF"), 0);
    }

    #[test]
    fn glob_cli_arguments_preserve_brace_alternation() {
        let cli = Cli::try_parse_from([
            "zerobox",
            "--deny-read-glob",
            "**/*.{pem,key}",
            "--deny-write-glob",
            "build/{debug,release}/**",
            "--",
            "/bin/true",
        ])
        .expect("parse glob arguments");

        assert_eq!(cli.deny_read_glob, vec!["**/*.{pem,key}"]);
        assert_eq!(cli.deny_write_glob, vec!["build/{debug,release}/**"]);
    }

    #[test]
    fn host_network_cli_preserves_scoped_domain_routes() {
        let cli = Cli::try_parse_from([
            "zerobox",
            "--allow-host-net",
            "*.dev.test:443",
            "--",
            "/bin/true",
        ])
        .expect("parse host network route");

        assert_eq!(cli.allow_host_net, Some(vec!["*.dev.test:443".to_string()]));
    }

    #[test]
    fn docker_policy_cli_accepts_the_private_json_contract() {
        let cli = Cli::try_parse_from([
            "zerobox",
            "--docker-policy",
            r#"{"mode":"full","endpoint":"unix:///var/run/docker.sock"}"#,
            "--",
            "/bin/true",
        ])
        .expect("parse Docker policy");

        assert!(matches!(
            cli.docker_policy,
            Some(zerobox::DockerAccessPolicy::Full { .. })
        ));
    }
}
