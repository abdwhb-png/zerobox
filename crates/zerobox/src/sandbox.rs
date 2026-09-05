use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::process::Child;
use zerobox_protocol::config_types::WindowsSandboxLevel;
use zerobox_protocol::models::PermissionProfile;
use zerobox_protocol::permissions::{
    FileSystemAccessMode, FileSystemPath, FileSystemSandboxEntry, FileSystemSandboxPolicy,
    FileSystemSpecialPath, NetworkSandboxPolicy,
};
#[cfg(test)]
use zerobox_protocol::protocol::SandboxPolicy;
use zerobox_sandboxing::{
    SandboxCommand, SandboxManager, SandboxTransformRequest, SandboxType, get_platform_sandbox,
};
use zerobox_utils_absolute_path::AbsolutePathBuf;

use crate::proxy;
use crate::secret;

pub(crate) const DEFAULT_ENV_KEYS: &[&str] = &["PATH", "HOME", "USER", "SHELL", "TERM", "LANG"];
const STRICT_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
const TARGET_ENV_FILE_ENV: &str = "ZEROBOX_TARGET_ENV_FILE";
const RESERVED_CHILD_ENV_KEYS: &[&str] = &["ZEROBOX_HOME", "CODEX_HOME"];

pub struct SandboxOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// A typed failure that occurred before the sandboxed target crossed its final
/// setup boundary. Target exit statuses are always returned separately.
#[derive(Debug)]
pub enum SandboxSetupError {
    Preparation(anyhow::Error),
    Spawn(anyhow::Error),
    HelperExited { status: ExitStatus },
    HelperProtocol(String),
    HelperTimeout,
}

impl std::fmt::Display for SandboxSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Preparation(error) => write!(f, "sandbox preparation failed: {error:#}"),
            Self::Spawn(error) => write!(f, "sandbox spawn failed: {error:#}"),
            Self::HelperExited { status } => {
                write!(f, "Linux sandbox helper exited during setup: {status}")
            }
            Self::HelperProtocol(message) => {
                write!(f, "Linux sandbox helper setup protocol failed: {message}")
            }
            Self::HelperTimeout => write!(f, "Linux sandbox helper did not confirm target startup"),
        }
    }
}

impl std::error::Error for SandboxSetupError {}

impl From<anyhow::Error> for SandboxSetupError {
    fn from(error: anyhow::Error) -> Self {
        Self::Preparation(error)
    }
}

pub struct SandboxChild {
    inner: Child,
    started_pid: u32,
    _proxy_handle: Option<zerobox_network_proxy::NetworkProxyHandle>,
    _proxy: Option<zerobox_network_proxy::NetworkProxy>,
    _proxy_root: Option<PrivateProxyRoot>,
    _setup_channel: Option<PrivateSetupChannel>,
    _target_env_file: Option<PrivateTargetEnvironment>,
}

impl SandboxChild {
    pub fn pid(&self) -> u32 {
        self.started_pid
    }
    pub fn stdout(&mut self) -> Option<tokio::process::ChildStdout> {
        self.inner.stdout.take()
    }

    pub fn stderr(&mut self) -> Option<tokio::process::ChildStderr> {
        self.inner.stderr.take()
    }

    pub async fn wait(mut self) -> Result<ExitStatus> {
        Ok(self.inner.wait().await?)
    }

    #[doc(hidden)]
    pub async fn kill_and_wait(mut self) -> Result<ExitStatus> {
        if let Err(error) = self.inner.kill().await
            && error.kind() != std::io::ErrorKind::InvalidInput
        {
            return Err(error.into());
        }
        Ok(self.inner.wait().await?)
    }
}

pub struct Sandbox {
    program: String,
    args: Vec<String>,
    cwd: Option<PathBuf>,
    env: HashMap<String, String>,
    inherit_env: bool,
    allow_env: Option<Vec<String>>,
    deny_env: Vec<String>,
    allow_read: Vec<PathBuf>,
    deny_read: Vec<PathBuf>,
    allow_write: Vec<PathBuf>,
    deny_write: Vec<PathBuf>,
    full_write: bool,
    allow_net: Option<Vec<String>>,
    deny_net: Vec<String>,
    secrets: Vec<(String, String)>,
    secret_hosts: Vec<(String, String)>,
    disabled: bool,
    full_access: bool,
    strict: bool,
    profile_names: Vec<String>,
    use_profile: bool,
    linux_sandbox_exe: Option<PathBuf>,
    setup_status: bool,
}

impl Sandbox {
    pub fn command(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            cwd: None,
            env: HashMap::new(),
            inherit_env: false,
            allow_env: None,
            deny_env: Vec::new(),
            allow_read: Vec::new(),
            deny_read: Vec::new(),
            allow_write: Vec::new(),
            deny_write: Vec::new(),
            full_write: false,
            allow_net: None,
            deny_net: Vec::new(),
            secrets: Vec::new(),
            secret_hosts: Vec::new(),
            disabled: false,
            full_access: false,
            strict: false,
            profile_names: Vec::new(),
            use_profile: true,
            linux_sandbox_exe: None,
            setup_status: false,
        }
    }

    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn args(mut self, args: &[impl AsRef<str>]) -> Self {
        self.args
            .extend(args.iter().map(|s| s.as_ref().to_string()));
        self
    }

    pub fn cwd(mut self, path: impl Into<PathBuf>) -> Self {
        self.cwd = Some(path.into());
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    pub fn envs(
        mut self,
        vars: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        for (k, v) in vars {
            self.env.insert(k.into(), v.into());
        }
        self
    }

    pub fn inherit_env(mut self) -> Self {
        self.inherit_env = true;
        self
    }

    pub fn allow_env(mut self, keys: &[impl AsRef<str>]) -> Self {
        let list = self.allow_env.get_or_insert_with(Vec::new);
        list.extend(keys.iter().map(|s| s.as_ref().to_string()));
        self
    }

    pub fn deny_env(mut self, keys: &[impl AsRef<str>]) -> Self {
        self.deny_env
            .extend(keys.iter().map(|s| s.as_ref().to_string()));
        self
    }

    pub fn allow_read(mut self, path: impl Into<PathBuf>) -> Self {
        self.allow_read.push(path.into());
        self
    }

    pub fn deny_read(mut self, path: impl Into<PathBuf>) -> Self {
        self.deny_read.push(path.into());
        self
    }

    pub fn allow_write(mut self, path: impl Into<PathBuf>) -> Self {
        self.allow_write.push(path.into());
        self
    }

    pub fn deny_write(mut self, path: impl Into<PathBuf>) -> Self {
        self.deny_write.push(path.into());
        self
    }

    pub fn allow_write_all(mut self) -> Self {
        self.full_write = true;
        self
    }

    pub fn allow_net(mut self, domains: &[impl AsRef<str>]) -> Self {
        let list = self.allow_net.get_or_insert_with(Vec::new);
        list.extend(domains.iter().map(|s| s.as_ref().to_string()));
        self
    }

    pub fn allow_net_all(mut self) -> Self {
        self.allow_net = Some(Vec::new());
        self
    }

    pub fn deny_net(mut self, domains: &[impl AsRef<str>]) -> Self {
        self.deny_net
            .extend(domains.iter().map(|s| s.as_ref().to_string()));
        self
    }

    pub fn secret(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.secrets.push((key.into(), value.into()));
        self
    }

    pub fn secret_host(mut self, key: impl Into<String>, hosts: impl Into<String>) -> Self {
        self.secret_hosts.push((key.into(), hosts.into()));
        self
    }

    pub fn no_sandbox(mut self) -> Self {
        self.disabled = true;
        self
    }

    pub fn full_access(mut self) -> Self {
        self.full_access = true;
        self
    }

    pub fn strict(mut self) -> Self {
        self.strict = true;
        self
    }

    pub fn profile(mut self, name: impl Into<String>) -> Self {
        self.profile_names.push(name.into());
        self.use_profile = true;
        self
    }

    pub fn profiles(mut self, names: &[impl AsRef<str>]) -> Self {
        self.profile_names
            .extend(names.iter().map(|s| s.as_ref().to_string()));
        self.use_profile = true;
        self
    }

    pub fn no_profile(mut self) -> Self {
        self.use_profile = false;
        self
    }

    /// Set the Linux sandbox helper executable.
    ///
    /// This is only used on Linux. Embedders that call zerobox from their own
    /// Rust binary can create this path with
    /// `zerobox::arg0::prepend_path_entry_for_zerobox_aliases` after calling
    /// `zerobox::arg0::dispatch_linux_sandbox_helper` near process startup.
    pub fn linux_sandbox_exe(mut self, path: impl Into<PathBuf>) -> Self {
        self.linux_sandbox_exe = Some(path.into());
        self
    }

    #[doc(hidden)]
    pub fn linux_sandbox_exe_opt(mut self, path: Option<PathBuf>) -> Self {
        self.linux_sandbox_exe = path;
        self
    }

    #[doc(hidden)]
    pub fn setup_status(mut self, enabled: bool) -> Self {
        self.setup_status = enabled;
        self
    }

    pub async fn run(self) -> std::result::Result<SandboxOutput, SandboxSetupError> {
        let mut prepared = self.setup_status(true).prepare().await?;
        prepared.cmd.stdin(std::process::Stdio::null());
        prepared.cmd.stdout(std::process::Stdio::piped());
        prepared.cmd.stderr(std::process::Stdio::piped());
        let (child, _) = prepared.spawn_checked().await?;
        let output = child
            .wait_with_output()
            .await
            .context("failed to execute command")
            .map_err(SandboxSetupError::Spawn)?;
        Ok(SandboxOutput {
            status: output.status,
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    pub async fn spawn(self) -> std::result::Result<SandboxChild, SandboxSetupError> {
        let mut prepared = self.setup_status(true).prepare().await?;
        prepared.cmd.stdout(std::process::Stdio::piped());
        prepared.cmd.stderr(std::process::Stdio::piped());
        prepared.cmd.stdin(std::process::Stdio::null());
        let (child, started_pid) = prepared.spawn_checked().await?;
        Ok(SandboxChild {
            inner: child,
            started_pid,
            _proxy_handle: prepared._proxy_handle,
            _proxy: prepared._proxy,
            _proxy_root: prepared._proxy_root,
            _setup_channel: prepared._setup_channel,
            _target_env_file: prepared._target_env_file,
        })
    }

    /// Spawn with inherited stdin and piped output for a streaming CLI relay.
    #[doc(hidden)]
    pub async fn spawn_streaming(self) -> std::result::Result<SandboxChild, SandboxSetupError> {
        let mut prepared = self.prepare().await?;
        prepared.cmd.stdout(std::process::Stdio::piped());
        prepared.cmd.stderr(std::process::Stdio::piped());
        let (child, started_pid) = prepared.spawn_checked().await?;
        Ok(SandboxChild {
            inner: child,
            started_pid,
            _proxy_handle: prepared._proxy_handle,
            _proxy: prepared._proxy,
            _proxy_root: prepared._proxy_root,
            _setup_channel: prepared._setup_channel,
            _target_env_file: prepared._target_env_file,
        })
    }

    /// Spawn using the caller's inherited stdio. This is intended for CLI
    /// frontends that must stream pipes as well as terminals.
    #[doc(hidden)]
    pub async fn spawn_inherited(self) -> std::result::Result<SandboxChild, SandboxSetupError> {
        let mut prepared = self.prepare().await?;
        let (child, started_pid) = prepared.spawn_checked().await?;
        Ok(SandboxChild {
            inner: child,
            started_pid,
            _proxy_handle: prepared._proxy_handle,
            _proxy: prepared._proxy,
            _proxy_root: prepared._proxy_root,
            _setup_channel: prepared._setup_channel,
            _target_env_file: prepared._target_env_file,
        })
    }

    pub async fn status(self) -> std::result::Result<ExitStatus, SandboxSetupError> {
        let mut prepared = self.setup_status(true).prepare().await?;
        let (mut child, _) = prepared.spawn_checked().await?;
        child
            .wait()
            .await
            .context("failed to execute command")
            .map_err(SandboxSetupError::Spawn)
    }

    /// Re-exec the current binary inside a sandbox.
    pub fn wrap_self() -> Result<Self> {
        let exe = std::env::current_exe().context("cannot determine current executable")?;
        let args: Vec<String> = std::env::args().skip(1).collect();
        let mut sb = Self::command(exe.to_string_lossy());
        for arg in args {
            sb = sb.arg(arg);
        }
        Ok(sb)
    }

    pub fn is_sandboxed() -> bool {
        std::env::var("ZEROBOX_SANDBOXED").is_ok()
    }

    /// No-op if already sandboxed. Otherwise re-execs inside the sandbox and exits.
    pub async fn exec_or_continue(self) -> Result<()> {
        if Self::is_sandboxed() {
            return Ok(());
        }
        let sb = self.env("ZEROBOX_SANDBOXED", "1");
        let status = sb.status().await?;
        std::process::exit(status.code().unwrap_or(1));
    }

    pub async fn prepare(self) -> std::result::Result<PreparedCommand, SandboxSetupError> {
        init_home();

        let Sandbox {
            program,
            args,
            cwd,
            mut env,
            inherit_env,
            mut allow_env,
            mut deny_env,
            mut allow_read,
            mut deny_read,
            mut allow_write,
            mut deny_write,
            mut full_write,
            mut allow_net,
            mut deny_net,
            mut secrets,
            mut secret_hosts,
            mut disabled,
            mut full_access,
            strict,
            profile_names,
            use_profile,
            linux_sandbox_exe,
            setup_status,
        } = self;

        let cwd = match cwd {
            Some(p) => p,
            None => std::env::current_dir().context("cannot determine working directory")?,
        };

        let mut effective_strict = strict;

        if use_profile {
            let profile = if profile_names.is_empty() {
                crate::profile_core::load_profile("default", &cwd)?
            } else {
                crate::profile_core::load_profiles(&profile_names, &cwd)?
            };
            effective_strict = is_strict(effective_strict, &profile);
            if !disabled && !full_access {
                apply_profile(
                    &profile,
                    &mut allow_read,
                    &mut deny_read,
                    &mut allow_write,
                    &mut deny_write,
                    &mut full_write,
                    &mut allow_net,
                    &mut deny_net,
                    &mut env,
                    &mut allow_env,
                    &mut deny_env,
                    &mut secrets,
                    &mut secret_hosts,
                    &mut disabled,
                    &mut full_access,
                );
            }
        }

        validate_sandbox_configuration(effective_strict, disabled, full_access)?;

        #[cfg(unix)]
        if use_profile
            && !disabled
            && !full_access
            && profile_names.iter().any(|n| is_claude_invocation(n))
            && let Some(home) = validated_home()
        {
            apply_claude_json_redirect(&home);
        }

        validate_literal_deny_paths(&deny_read, &deny_write)?;
        if !full_access {
            validate_paths(&allow_read, &deny_read, &allow_write, &deny_write, &cwd)?;
        }

        let secret_store = Arc::new(
            secret::build_secret_store(&secrets, &secret_hosts).map_err(|e| anyhow::anyhow!(e))?,
        );

        if secret_store.requires_mitm()
            && let Some(ca_path) = secret::mitm_ca_cert_path()
        {
            allow_read.push(ca_path);
        }

        let strict_path =
            select_strict_path(effective_strict, env.get("PATH").map(String::as_str))?;
        let child_env = finalize_child_env(
            build_env(inherit_env, allow_env.as_deref(), &deny_env, &env),
            secret_store.get_env_overrides(),
            strict_path.as_deref(),
        );

        let net_enabled = allow_net.is_some() || !secret_store.is_empty();
        let (sandbox_type, use_legacy_landlock) = if disabled || full_access {
            (SandboxType::None, false)
        } else {
            select_sandbox_type(effective_strict)?
        };

        #[cfg(target_os = "linux")]
        let target_env_file = if sandbox_type == SandboxType::LinuxSeccomp {
            let file = PrivateTargetEnvironment::create(&child_env)?;
            allow_read.push(file.read_root().to_path_buf());
            Some(file)
        } else {
            None
        };
        #[cfg(not(target_os = "linux"))]
        let target_env_file: Option<PrivateTargetEnvironment> = None;

        let command_env = target_env_file
            .as_ref()
            .map(|file| linux_helper_environment(file.path()))
            .unwrap_or(child_env);

        let linux_sandbox_exe: Option<PathBuf> = if cfg!(target_os = "linux") {
            linux_sandbox_exe.or_else(|| std::env::current_exe().ok())
        } else {
            None
        };

        #[cfg(target_os = "linux")]
        let setup_channel = if setup_status && sandbox_type == SandboxType::LinuxSeccomp {
            Some(PrivateSetupChannel::create()?)
        } else {
            None
        };
        #[cfg(not(target_os = "linux"))]
        let setup_channel: Option<PrivateSetupChannel> = None;

        let fs_policy = build_fs_policy(
            &allow_read,
            &deny_read,
            &allow_write,
            &deny_write,
            full_write,
            full_access,
            net_enabled,
            &cwd,
        );
        let fs_policy = with_linux_helper_read_root(fs_policy, linux_sandbox_exe.as_deref(), &cwd);

        let net_policy = if net_enabled {
            NetworkSandboxPolicy::Enabled
        } else {
            NetworkSandboxPolicy::Restricted
        };

        zerobox_utils_rustls_provider::ensure_rustls_crypto_provider();
        let deny_slice = if deny_net.is_empty() {
            None
        } else {
            Some(deny_net.as_slice())
        };
        let proxy = proxy::build_proxy(allow_net.as_deref(), deny_slice, &secret_store).await?;

        let _proxy_handle = match proxy {
            Some(ref p) => Some(p.run().await.context("failed to start network proxy")?),
            None => None,
        };

        let proxy_root = if proxy.is_some() && sandbox_type == SandboxType::LinuxSeccomp {
            Some(PrivateProxyRoot::create()?)
        } else {
            None
        };

        let cwd_abs = AbsolutePathBuf::from_absolute_path(&cwd)
            .context("working directory must be absolute")?;

        let permissions = PermissionProfile::from_runtime_permissions(&fs_policy, net_policy);
        let manager = SandboxManager::new();
        let exec_request = manager
            .transform(SandboxTransformRequest {
                command: SandboxCommand {
                    program: program.into(),
                    args,
                    cwd: cwd_abs,
                    env: command_env,
                    additional_permissions: None,
                },
                permissions: &permissions,
                sandbox: sandbox_type,
                enforce_managed_network: proxy.is_some(),
                network: proxy.as_ref(),
                proxy_root: proxy_root.as_ref().map(PrivateProxyRoot::path),
                setup_status_fd: setup_channel.as_ref().map(PrivateSetupChannel::write_fd),
                sandbox_policy_cwd: &cwd,
                zerobox_linux_sandbox_exe: linux_sandbox_exe.as_deref(),
                use_legacy_landlock,
                windows_sandbox_level: WindowsSandboxLevel::default(),
                windows_sandbox_private_desktop: false,
            })
            .map_err(|e| anyhow::anyhow!("sandbox transform failed: {e}"))?;

        let mut cmd = tokio::process::Command::new(&exec_request.command[0]);
        cmd.args(&exec_request.command[1..]);
        cmd.current_dir(&cwd);
        cmd.env_clear();
        cmd.kill_on_drop(true);

        #[cfg(unix)]
        {
            #[allow(unused_imports)]
            use std::os::unix::process::CommandExt;
            if let Some(ref arg0) = exec_request.arg0 {
                cmd.arg0(arg0);
            }
        }

        let mut final_env = exec_request.env;
        if let Some(ref proxy) = proxy {
            proxy.apply_to_env(&mut final_env);
            for key in zerobox_network_proxy::NO_PROXY_ENV_KEYS {
                final_env.remove(*key);
            }
        }
        if !net_enabled {
            final_env.insert(
                "CODEX_SANDBOX_NETWORK_DISABLED".to_string(),
                "1".to_string(),
            );
        }
        if secret_store.requires_mitm()
            && let Some(ca_path) = secret::mitm_ca_cert_path()
        {
            let ca = ca_path.to_string_lossy().to_string();
            for var in &[
                "CURL_CA_BUNDLE",
                "SSL_CERT_FILE",
                "NODE_EXTRA_CA_CERTS",
                "REQUESTS_CA_BUNDLE",
                "CARGO_HTTP_CAINFO",
                "GIT_SSL_CAINFO",
                "GOOSE_CA_CERT_PATH",
            ] {
                final_env.insert(var.to_string(), ca.clone());
            }
        }
        remove_reserved_child_env(&mut final_env);
        cmd.envs(&final_env);

        Ok(PreparedCommand {
            cmd,
            _proxy_handle,
            _proxy: proxy,
            _proxy_root: proxy_root,
            _setup_channel: setup_channel,
            _target_env_file: target_env_file,
        })
    }
}

pub struct PreparedCommand {
    cmd: tokio::process::Command,
    _proxy_handle: Option<zerobox_network_proxy::NetworkProxyHandle>,
    _proxy: Option<zerobox_network_proxy::NetworkProxy>,
    _proxy_root: Option<PrivateProxyRoot>,
    _setup_channel: Option<PrivateSetupChannel>,
    _target_env_file: Option<PrivateTargetEnvironment>,
}

/// A prepared command cannot be detached while it owns resources that must
/// remain alive for the child process.
#[derive(Debug, thiserror::Error)]
#[error("resource-managed prepared commands must be spawned through PreparedCommand::spawn")]
pub struct PreparedCommandIntoCommandError;

impl PreparedCommand {
    /// Borrow the raw Tokio command to customize stdio or other spawn options.
    pub fn command_mut(&mut self) -> &mut tokio::process::Command {
        &mut self.cmd
    }

    /// Recover the raw command when no managed resources are attached.
    ///
    /// # Errors
    ///
    /// Returns [`PreparedCommandIntoCommandError`] when detaching the raw
    /// command would drop a proxy, private proxy root, or setup channel needed
    /// by the child.
    pub fn into_command(
        self,
    ) -> std::result::Result<tokio::process::Command, PreparedCommandIntoCommandError> {
        if self._proxy_handle.is_some()
            || self._proxy.is_some()
            || self._proxy_root.is_some()
            || self._setup_channel.is_some()
            || self._target_env_file.is_some()
        {
            return Err(PreparedCommandIntoCommandError);
        }
        Ok(self.cmd)
    }

    /// Spawn the prepared command while transferring all managed resources to
    /// the returned child.
    ///
    /// This preserves the preparation mode selected by [`Sandbox::prepare`].
    /// Unlike [`Sandbox::spawn`], a directly prepared command does not request
    /// Linux helper confirmation of the final target execution by default.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxSetupError`] if spawning fails, or if a setup channel
    /// was explicitly attached and the helper rejects the final execution.
    pub async fn spawn(mut self) -> std::result::Result<SandboxChild, SandboxSetupError> {
        let (inner, started_pid) = self.spawn_checked().await?;
        Ok(SandboxChild {
            inner,
            started_pid,
            _proxy_handle: self._proxy_handle,
            _proxy: self._proxy,
            _proxy_root: self._proxy_root,
            _setup_channel: self._setup_channel,
            _target_env_file: self._target_env_file,
        })
    }

    async fn spawn_checked(&mut self) -> std::result::Result<(Child, u32), SandboxSetupError> {
        #[cfg(target_os = "linux")]
        if let Some(channel) = self._setup_channel.as_ref() {
            let fd = channel.write_fd();
            unsafe {
                self.cmd.pre_exec(move || clear_cloexec(fd));
            }
        }
        let mut child = self
            .cmd
            .spawn()
            .context("failed to spawn command")
            .map_err(SandboxSetupError::Spawn)?;
        let host_pid = child.id();
        if let Some(channel) = self._setup_channel.as_mut() {
            channel.close_parent_write();
        }
        let started_pid = if let Some(channel) = self._setup_channel.as_ref() {
            let _inner_pid = channel.wait_for_started(&mut child).await?;
            host_pid.ok_or_else(|| {
                SandboxSetupError::HelperProtocol(
                    "spawned helper has no host process id".to_string(),
                )
            })?
        } else {
            child.id().ok_or_else(|| {
                SandboxSetupError::HelperProtocol("spawned target has no process id".to_string())
            })?
        };
        Ok((child, started_pid))
    }
}

#[cfg(target_os = "linux")]
struct PrivateSetupChannel {
    read: std::fs::File,
    write: Option<std::fs::File>,
}

#[cfg(target_os = "linux")]
impl PrivateSetupChannel {
    fn create() -> Result<Self> {
        use std::os::fd::FromRawFd;
        let mut fds = [0; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } < 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to create private setup pipe");
        }
        Ok(Self {
            read: unsafe { std::fs::File::from_raw_fd(fds[0]) },
            write: Some(unsafe { std::fs::File::from_raw_fd(fds[1]) }),
        })
    }

    fn write_fd(&self) -> i32 {
        use std::os::fd::AsRawFd;
        self.write.as_ref().expect("setup pipe is open").as_raw_fd()
    }

    fn close_parent_write(&mut self) {
        self.write.take();
    }

    async fn wait_for_started(
        &self,
        child: &mut Child,
    ) -> std::result::Result<u32, SandboxSetupError> {
        let wait_for_message = async {
            let mut pending = Vec::new();
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {
                        let mut reader = &self.read;
                        match read_setup_frame(&mut reader, &mut pending) {
                            Ok(Some(frame)) if frame == "STARTED" => return Ok(0),
                            Ok(Some(frame)) if frame.starts_with("ERR:") => {
                                return Err(SandboxSetupError::HelperProtocol(frame));
                            }
                            Ok(Some(_)) => return Err(SandboxSetupError::HelperProtocol("unexpected setup frame".to_string())),
                            Ok(None) => {}
                            Err(error) if matches!(error.kind(), std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::InvalidData) => {
                                return Err(SandboxSetupError::HelperProtocol(error.to_string()));
                            }
                            Err(error) => return Err(SandboxSetupError::Spawn(anyhow::Error::from(error))),
                        }
                        if let Some(status) = child.try_wait().context("failed to poll Linux sandbox helper").map_err(SandboxSetupError::Spawn)? {
                            return Err(SandboxSetupError::HelperExited { status });
                        }
                    }
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(30), wait_for_message)
            .await
            .map_err(|_| SandboxSetupError::HelperTimeout)?
    }
}

#[cfg(target_os = "linux")]
fn read_setup_frame<R: std::io::Read + ?Sized>(
    reader: &mut R,
    pending: &mut Vec<u8>,
) -> std::io::Result<Option<String>> {
    loop {
        if let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
            let frame = pending.drain(..=newline).collect::<Vec<_>>();
            let frame = std::str::from_utf8(&frame[..newline]).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "non-UTF-8 setup frame")
            })?;
            return Ok(Some(frame.to_string()));
        }
        if pending.len() >= 128 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "setup frame exceeds 128 bytes",
            ));
        }

        let mut bytes = [0u8; 128];
        match reader.read(&mut bytes[..128 - pending.len()]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "setup pipe closed before a complete frame",
                ));
            }
            Ok(size) => pending.extend_from_slice(&bytes[..size]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(error),
        }
    }
}

#[cfg(not(target_os = "linux"))]
struct PrivateSetupChannel;

#[cfg(not(target_os = "linux"))]
impl PrivateSetupChannel {
    fn write_fd(&self) -> i32 {
        unreachable!("Linux setup channel unavailable")
    }

    fn close_parent_write(&mut self) {}

    async fn wait_for_started(
        &self,
        _child: &mut Child,
    ) -> std::result::Result<u32, SandboxSetupError> {
        Err(SandboxSetupError::HelperProtocol(
            "Linux setup channel unavailable".to_string(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn clear_cloexec(fd: i32) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Owner-only snapshot of the final target environment. Linux helper stages
/// receive only this path plus a fixed search path, so target-controlled
/// variables cannot affect Zerobox or bubblewrap before isolation is active.
#[derive(Debug)]
struct PrivateTargetEnvironment {
    root: PathBuf,
    path: PathBuf,
}

impl PrivateTargetEnvironment {
    #[cfg(target_os = "linux")]
    fn create(environment: &HashMap<String, String>) -> Result<Self> {
        Self::create_in(environment, &crate::zerobox_home().join("tmp").join("env"))
    }

    #[cfg(target_os = "linux")]
    fn create_in(environment: &HashMap<String, String>, root: &Path) -> Result<Self> {
        use std::io::Write;
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

        ensure_private_proxy_directory(root)?;

        for _ in 0..128 {
            let mut random = [0u8; 8];
            getrandom::fill(&mut random).context("failed to generate target env nonce")?;
            let nonce = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let candidate = root.join(format!("e-{nonce}"));
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&candidate) {
                Ok(()) => ensure_private_proxy_directory(&candidate)?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "failed to create target environment directory {}",
                            candidate.display()
                        )
                    });
                }
            }
            let path = candidate.join("environment.json");
            let mut file = match std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => file,
                Err(error) => {
                    let _ = std::fs::remove_dir_all(&candidate);
                    return Err(error).with_context(|| {
                        format!(
                            "failed to create target environment file {}",
                            path.display()
                        )
                    });
                }
            };
            let encoded =
                serde_json::to_vec(environment).context("failed to encode target environment")?;
            if let Err(error) = file.write_all(&encoded).and_then(|()| file.sync_all()) {
                let _ = std::fs::remove_dir_all(&candidate);
                return Err(error).with_context(|| {
                    format!("failed to persist target environment {}", path.display())
                });
            }
            return Ok(Self {
                root: candidate,
                path,
            });
        }

        anyhow::bail!("could not allocate a unique target environment file")
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn read_root(&self) -> &Path {
        &self.root
    }
}

impl Drop for PrivateTargetEnvironment {
    fn drop(&mut self) {
        if ensure_private_proxy_directory(&self.root).is_ok() {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

fn linux_helper_environment(target_env_file: &Path) -> HashMap<String, String> {
    HashMap::from([
        ("PATH".to_string(), STRICT_PATH.to_string()),
        (
            TARGET_ENV_FILE_ENV.to_string(),
            target_env_file.display().to_string(),
        ),
    ])
}

/// A per-execution owner-only directory used by the Linux helper's host-side
/// proxy bridge. Keeping this handle with the prepared command (and then the
/// child) prevents cleanup before the helper has consumed `--proxy-root`.
#[derive(Debug)]
struct PrivateProxyRoot {
    path: PathBuf,
}

impl PrivateProxyRoot {
    fn create() -> Result<Self> {
        Self::create_in(&crate::zerobox_home().join("tmp").join("runs"))
    }

    fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(unix)]
    fn create_in(runs_root: &Path) -> Result<Self> {
        use std::os::unix::fs::DirBuilderExt;

        ensure_private_proxy_directory(runs_root)?;

        for _ in 0..128 {
            // Keep this component short: Linux AF_UNIX paths are limited to
            // 107 bytes and the helper adds its own socket-directory names.
            let mut random = [0u8; 4];
            getrandom::fill(&mut random).context("failed to generate proxy root nonce")?;
            let nonce = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let candidate = runs_root.join(format!("p-{nonce}"));
            validate_linux_proxy_socket_path_budget(&candidate)?;

            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&candidate) {
                Ok(()) => {
                    ensure_private_proxy_directory(&candidate)?;
                    return Ok(Self { path: candidate });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "failed to create private proxy root {}",
                            candidate.display()
                        )
                    });
                }
            }
        }

        anyhow::bail!("could not allocate a unique private proxy root")
    }

    #[cfg(not(unix))]
    fn create_in(_runs_root: &Path) -> Result<Self> {
        anyhow::bail!("managed proxy roots require Unix filesystem permissions")
    }
}

#[cfg(unix)]
fn validate_linux_proxy_socket_path_budget(proxy_root: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;

    // The helper creates `p-<pid>-<attempt>/r-<index>.sock` below this root.
    // Reserve for the widest numeric forms so every generated AF_UNIX path
    // remains below Linux's 108-byte sun_path including its trailing NUL.
    let worst_case = proxy_root.join(format!("p-{}-127/r-{}.sock", u32::MAX, usize::MAX));
    if worst_case.as_os_str().as_bytes().len() >= 108 {
        anyhow::bail!(
            "ZEROBOX_HOME is too long for private Linux proxy sockets: {}",
            proxy_root.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
impl Drop for PrivateProxyRoot {
    fn drop(&mut self) {
        if ensure_private_proxy_directory(&self.path).is_ok() {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(not(unix))]
impl Drop for PrivateProxyRoot {
    fn drop(&mut self) {}
}

#[cfg(unix)]
fn ensure_private_proxy_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(path).with_context(|| {
        format!(
            "failed to create private proxy directory {}",
            path.display()
        )
    })?;

    let metadata = std::fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to inspect private proxy directory {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "private proxy directory must be a non-symlink directory: {}",
            path.display()
        );
    }
    let current_uid = std::fs::metadata("/proc/self")
        .context("failed to determine current process owner")?
        .uid();
    if metadata.uid() != current_uid {
        anyhow::bail!(
            "private proxy directory is not owned by the current user: {}",
            path.display()
        );
    }

    let mut permissions = metadata.permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions).with_context(|| {
        format!(
            "failed to restrict private proxy directory {}",
            path.display()
        )
    })?;

    let metadata = std::fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to re-inspect private proxy directory {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != current_uid
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        anyhow::bail!(
            "private proxy directory failed ownership or mode validation: {}",
            path.display()
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_fs_policy(
    allow_read: &[PathBuf],
    deny_read: &[PathBuf],
    allow_write: &[PathBuf],
    deny_write: &[PathBuf],
    full_write: bool,
    full_access: bool,
    net_enabled: bool,
    cwd: &Path,
) -> FileSystemSandboxPolicy {
    if full_access {
        return FileSystemSandboxPolicy::unrestricted();
    }

    let mut entries: Vec<FileSystemSandboxEntry> = Vec::new();

    if allow_read.is_empty() {
        entries.push(FileSystemSandboxEntry {
            path: FileSystemPath::Special {
                value: FileSystemSpecialPath::Root,
            },
            access: FileSystemAccessMode::Read,
        });
    } else {
        #[cfg(target_os = "linux")]
        entries.push(FileSystemSandboxEntry {
            path: FileSystemPath::Special {
                value: FileSystemSpecialPath::Minimal,
            },
            access: FileSystemAccessMode::Read,
        });
        for path in allow_read {
            if let Ok(abs) = resolve_path(cwd, path) {
                entries.push(FileSystemSandboxEntry {
                    path: FileSystemPath::Path { path: abs },
                    access: FileSystemAccessMode::Read,
                });
            }
        }
        if let Ok(exe) = std::env::current_exe()
            && let Some(dir) = exe.parent()
            && let Ok(abs) = AbsolutePathBuf::try_from(dir.to_path_buf())
        {
            entries.push(FileSystemSandboxEntry {
                path: FileSystemPath::Path { path: abs },
                access: FileSystemAccessMode::Read,
            });
        }
        if net_enabled {
            if let Ok(abs) = AbsolutePathBuf::try_from(crate::zerobox_home().join("tmp")) {
                entries.push(FileSystemSandboxEntry {
                    path: FileSystemPath::Path { path: abs },
                    access: FileSystemAccessMode::Read,
                });
            }
            if let Ok(abs) = AbsolutePathBuf::try_from(PathBuf::from("/run")) {
                entries.push(FileSystemSandboxEntry {
                    path: FileSystemPath::Path { path: abs },
                    access: FileSystemAccessMode::Read,
                });
            }
        }
    }

    for path in deny_read {
        if let Ok(abs) = resolve_path(cwd, path) {
            entries.push(FileSystemSandboxEntry {
                path: FileSystemPath::Path { path: abs },
                access: FileSystemAccessMode::None,
            });
        }
    }

    if full_write {
        entries.push(FileSystemSandboxEntry {
            path: FileSystemPath::Special {
                value: FileSystemSpecialPath::Root,
            },
            access: FileSystemAccessMode::Write,
        });
    } else {
        for path in allow_write {
            if let Ok(abs) = resolve_path(cwd, path) {
                entries.push(FileSystemSandboxEntry {
                    path: FileSystemPath::Path { path: abs },
                    access: FileSystemAccessMode::Write,
                });
            }
        }
    }

    for path in deny_write {
        if let Ok(abs) = resolve_path(cwd, path) {
            entries.push(FileSystemSandboxEntry {
                path: FileSystemPath::Path { path: abs },
                access: FileSystemAccessMode::Read,
            });
        }
    }

    FileSystemSandboxPolicy::restricted(entries)
}

fn with_linux_helper_read_root(
    fs_policy: FileSystemSandboxPolicy,
    linux_sandbox_exe: Option<&Path>,
    cwd: &Path,
) -> FileSystemSandboxPolicy {
    let Some(helper_parent) = linux_sandbox_exe.and_then(Path::parent) else {
        return fs_policy;
    };
    let Ok(helper_root) = resolve_path(cwd, helper_parent) else {
        return fs_policy;
    };

    fs_policy.with_additional_readable_roots(cwd, &[helper_root])
}

#[cfg(test)]
fn build_legacy_policy(
    allow_write: &[PathBuf],
    full_access: bool,
    full_write: bool,
    net_enabled: bool,
    cwd: &Path,
) -> SandboxPolicy {
    if full_access || full_write {
        return SandboxPolicy::DangerFullAccess;
    }
    if !allow_write.is_empty() {
        let writable_roots: Vec<AbsolutePathBuf> = allow_write
            .iter()
            .filter_map(|p| resolve_path(cwd, p).ok())
            .collect();
        SandboxPolicy::WorkspaceWrite {
            writable_roots,
            network_access: net_enabled,
            exclude_tmpdir_env_var: false,
            exclude_slash_tmp: false,
        }
    } else {
        SandboxPolicy::ReadOnly {
            network_access: net_enabled,
        }
    }
}

fn build_env(
    inherit: bool,
    allow_env: Option<&[String]>,
    deny_env: &[String],
    overrides: &HashMap<String, String>,
) -> HashMap<String, String> {
    let parent: HashMap<String, String> = std::env::vars().collect();
    let mut env = if inherit {
        parent
    } else if let Some(keys) = allow_env {
        if keys.is_empty() {
            parent
        } else {
            let set: std::collections::HashSet<&str> = keys.iter().map(|s| s.as_str()).collect();
            parent
                .into_iter()
                .filter(|(k, _)| set.contains(k.as_str()))
                .collect()
        }
    } else {
        parent
            .into_iter()
            .filter(|(k, _)| DEFAULT_ENV_KEYS.contains(&k.as_str()))
            .collect()
    };
    for key in deny_env {
        env.remove(key);
    }
    env.extend(overrides.iter().map(|(k, v)| (k.clone(), v.clone())));
    env
}

#[allow(clippy::too_many_arguments)]
fn apply_profile(
    profile: &crate::profile_core::Profile,
    allow_read: &mut Vec<PathBuf>,
    deny_read: &mut Vec<PathBuf>,
    allow_write: &mut Vec<PathBuf>,
    deny_write: &mut Vec<PathBuf>,
    full_write: &mut bool,
    allow_net: &mut Option<Vec<String>>,
    deny_net: &mut Vec<String>,
    env: &mut HashMap<String, String>,
    allow_env: &mut Option<Vec<String>>,
    deny_env: &mut Vec<String>,
    secrets: &mut Vec<(String, String)>,
    secret_hosts: &mut Vec<(String, String)>,
    disabled: &mut bool,
    full_access: &mut bool,
) {
    fn merge_paths(target: &mut Vec<PathBuf>, source: &Option<Vec<String>>) {
        if let Some(paths) = source {
            for p in paths {
                let pb = PathBuf::from(p);
                if !target.contains(&pb) {
                    target.push(pb);
                }
            }
        }
    }

    fn merge_strings(target: &mut Vec<String>, source: &Option<Vec<String>>) {
        if let Some(items) = source {
            for s in items {
                if !target.contains(s) {
                    target.push(s.clone());
                }
            }
        }
    }

    fn merge_optional_strings(target: &mut Option<Vec<String>>, source: &Option<Vec<String>>) {
        if let Some(items) = source {
            let list = target.get_or_insert_with(Vec::new);
            for s in items {
                if !list.contains(s) {
                    list.push(s.clone());
                }
            }
        }
    }

    merge_paths(allow_read, &profile.allow_read);
    merge_paths(deny_read, &profile.deny_read);
    merge_paths(allow_write, &profile.allow_write);
    merge_paths(deny_write, &profile.deny_write);
    merge_strings(deny_net, &profile.deny_net);
    merge_strings(deny_env, &profile.deny_env);
    merge_optional_strings(allow_net, &profile.allow_net);
    merge_optional_strings(allow_env, &profile.allow_env);

    if let Some(ref profile_env) = profile.set_env {
        for (k, v) in profile_env {
            env.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }

    if let Some(ref hosts_map) = profile.secret_hosts {
        for (key, hosts) in hosts_map {
            secret_hosts.push((key.clone(), hosts.join(",")));
        }
    }

    if profile.allow_all == Some(true) {
        *full_access = true;
    }
    if profile.no_sandbox == Some(true) {
        *disabled = true;
    }
    let _ = (full_write, secrets);
}

fn validate_paths(
    allow_read: &[PathBuf],
    deny_read: &[PathBuf],
    allow_write: &[PathBuf],
    deny_write: &[PathBuf],
    cwd: &Path,
) -> Result<()> {
    for p in allow_read {
        resolve_path(cwd, p)
            .with_context(|| format!("invalid allow_read path: {}", p.display()))?;
    }
    for p in deny_read {
        validate_literal_deny_path("deny_read", p)?;
        resolve_path(cwd, p).with_context(|| format!("invalid deny_read path: {}", p.display()))?;
    }
    for p in allow_write {
        resolve_path(cwd, p)
            .with_context(|| format!("invalid allow_write path: {}", p.display()))?;
    }
    for p in deny_write {
        validate_literal_deny_path("deny_write", p)?;
        resolve_path(cwd, p)
            .with_context(|| format!("invalid deny_write path: {}", p.display()))?;
    }
    Ok(())
}

fn validate_literal_deny_paths(deny_read: &[PathBuf], deny_write: &[PathBuf]) -> Result<()> {
    for path in deny_read {
        validate_literal_deny_path("deny_read", path)?;
    }
    for path in deny_write {
        validate_literal_deny_path("deny_write", path)?;
    }
    Ok(())
}

fn validate_sandbox_configuration(strict: bool, disabled: bool, full_access: bool) -> Result<()> {
    if strict && (disabled || full_access) {
        anyhow::bail!("strict sandbox cannot be combined with no sandbox or full access");
    }
    Ok(())
}

fn is_strict(explicit_strict: bool, profile: &crate::profile_core::Profile) -> bool {
    explicit_strict || profile.strict_sandbox.unwrap_or(false)
}

fn validate_literal_deny_path(field: &str, path: &Path) -> Result<()> {
    let path = path.to_string_lossy();
    if let Some(character) = path
        .chars()
        .find(|c| matches!(c, '*' | '?' | '[' | ']' | '{' | '}'))
    {
        anyhow::bail!(
            "{field} paths must be literal; found glob character '{character}' in '{path}'"
        );
    }
    Ok(())
}

fn select_strict_path(strict: bool, configured: Option<&str>) -> Result<Option<String>> {
    if !strict {
        return Ok(None);
    }

    let raw = configured.unwrap_or(STRICT_PATH);
    let segments = std::env::split_paths(raw).collect::<Vec<_>>();
    if segments.is_empty()
        || segments
            .iter()
            .any(|segment| segment.as_os_str().is_empty())
    {
        anyhow::bail!("strict PATH must contain only non-empty absolute path segments");
    }
    if let Some(segment) = segments.iter().find(|segment| !segment.is_absolute()) {
        anyhow::bail!(
            "strict PATH segment must be absolute: {}",
            segment.display()
        );
    }

    let joined = std::env::join_paths(segments)
        .context("strict PATH contains a segment that cannot be represented")?;
    let joined = joined
        .into_string()
        .map_err(|_| anyhow::anyhow!("strict PATH must be valid UTF-8"))?;
    Ok(Some(joined))
}

fn finalize_child_env(
    mut env: HashMap<String, String>,
    secret_overrides: HashMap<String, String>,
    strict_path: Option<&str>,
) -> HashMap<String, String> {
    env.extend(secret_overrides);
    if let Some(path) = strict_path {
        env.insert("PATH".to_string(), path.to_string());
    }
    remove_reserved_child_env(&mut env);
    env
}

fn remove_reserved_child_env(env: &mut HashMap<String, String>) {
    for key in RESERVED_CHILD_ENV_KEYS {
        env.remove(*key);
    }
}

fn init_home() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let home = crate::zerobox_home();
        let _ = std::fs::create_dir_all(&home);
    });
}

/// True if `profile_name` is `"claude"` or transitively composes it via `use:`.
fn is_claude_invocation(profile_name: &str) -> bool {
    is_claude_invocation_with(profile_name, crate::profile_core::load_profile_uses)
}

fn is_claude_invocation_with<F>(profile_name: &str, load_uses: F) -> bool
where
    F: Fn(&str) -> Option<Vec<String>>,
{
    let mut visited: Vec<String> = Vec::new();
    let mut stack: Vec<String> = vec![profile_name.to_string()];
    while let Some(name) = stack.pop() {
        if name == "claude" {
            return true;
        }
        if visited.iter().any(|v| v == &name) {
            continue;
        }
        visited.push(name.clone());
        if let Some(uses) = load_uses(&name) {
            stack.extend(uses);
        }
    }
    false
}

/// `HOME` must be an absolute path; otherwise a malicious parent could
/// redirect filesystem operations by setting `HOME=.` or similar.
#[cfg(unix)]
fn validated_home() -> Option<PathBuf> {
    validate_home_str(std::env::var("HOME").ok().as_deref())
}

#[cfg(unix)]
fn validate_home_str(home: Option<&str>) -> Option<PathBuf> {
    let home = home?;
    if home.is_empty() {
        return None;
    }
    let path = PathBuf::from(home);
    if !path.is_absolute() {
        return None;
    }
    Some(path)
}

/// Claude Code writes `~/.claude.json` atomically via temp files named
/// `~/.claude.json.tmp.<pid>.<timestamp>`. Sandboxes grant access to fixed
/// paths, not patterns, so those temp writes are denied and auth-token
/// refresh silently breaks. Redirecting `~/.claude.json` through a symlink
/// into `~/.claude/` makes the temp files land in a directory that's
/// granted as a whole.
#[cfg(unix)]
fn apply_claude_json_redirect(home: &Path) {
    use std::os::unix::fs::OpenOptionsExt;

    let precreate = |path: &Path, is_dir: bool| {
        let result = if is_dir {
            std::fs::create_dir_all(path)
        } else {
            std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(path)
                .map(|_| ())
        };
        if let Err(e) = result
            && e.kind() != std::io::ErrorKind::AlreadyExists
        {
            eprintln!("warning: failed to pre-create {}: {e}", path.display());
        }
    };

    precreate(&home.join(".claude.json.lock"), false);
    precreate(&home.join(".cache/claude-cli-nodejs"), true);

    let claude_json = home.join(".claude.json");
    let claude_dir = home.join(".claude");
    let redirect_target = claude_dir.join("claude.json");

    if let Err(e) = std::fs::create_dir_all(&claude_dir) {
        eprintln!("warning: failed to create {}: {e}", claude_dir.display());
        return;
    }

    if claude_json.is_symlink() {
        return;
    }

    if claude_json.exists() {
        if redirect_target.exists() {
            eprintln!(
                "warning: cannot redirect claude config — both {} and {} exist \
                 with independent content. Compare the two, keep the current one, \
                 delete the other, then re-run.",
                claude_json.display(),
                redirect_target.display()
            );
            return;
        }
        if let Err(e) = std::fs::rename(&claude_json, &redirect_target) {
            eprintln!(
                "warning: failed to move {} to {}: {e}",
                claude_json.display(),
                redirect_target.display()
            );
            return;
        }
    } else {
        precreate(&redirect_target, false);
    }

    if let Err(e) = std::os::unix::fs::symlink(".claude/claude.json", &claude_json)
        && e.kind() != std::io::ErrorKind::AlreadyExists
    {
        eprintln!(
            "warning: failed to create symlink {}: {e}",
            claude_json.display()
        );
    }
}

pub(crate) fn resolve_path(base: &Path, p: &Path) -> Result<AbsolutePathBuf> {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    };
    AbsolutePathBuf::try_from(abs).context("failed to resolve path")
}

fn select_sandbox_type(strict: bool) -> Result<(SandboxType, bool)> {
    match get_platform_sandbox(false) {
        Some(SandboxType::LinuxSeccomp) => {
            if can_create_user_namespace() {
                Ok((SandboxType::LinuxSeccomp, false))
            } else if strict {
                anyhow::bail!(
                    "strict sandbox requires bubblewrap but user namespaces are unavailable"
                )
            } else {
                Ok((SandboxType::LinuxSeccomp, true))
            }
        }
        other => Ok((other.unwrap_or(SandboxType::None), false)),
    }
}

#[cfg(target_os = "linux")]
fn can_create_user_namespace() -> bool {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        let exit_code = if unsafe { libc::unshare(libc::CLONE_NEWUSER) } == 0 {
            0
        } else {
            1
        };
        unsafe { libc::_exit(exit_code) };
    }

    wait_for_user_namespace_probe_with(pid, |status| {
        let waited = unsafe { libc::waitpid(pid, status, 0) };
        if waited < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(waited)
        }
    })
}

#[cfg(target_os = "linux")]
fn wait_for_user_namespace_probe_with(
    pid: libc::pid_t,
    mut wait: impl FnMut(&mut libc::c_int) -> std::io::Result<libc::pid_t>,
) -> bool {
    let mut status = 0;
    loop {
        match wait(&mut status) {
            Ok(waited) if waited == pid => break,
            Ok(_) => return false,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return false,
        }
    }
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

#[cfg(not(target_os = "linux"))]
fn can_create_user_namespace() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    struct InterruptedFragmentedReader {
        reads: usize,
    }

    #[cfg(target_os = "linux")]
    impl std::io::Read for InterruptedFragmentedReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.reads += 1;
            match self.reads {
                1 => Err(std::io::Error::from(std::io::ErrorKind::Interrupted)),
                2 => {
                    buffer[..3].copy_from_slice(b"STA");
                    Ok(3)
                }
                3 => {
                    buffer[..5].copy_from_slice(b"RTED\n");
                    Ok(5)
                }
                _ => Ok(0),
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn setup_frame_reader_retries_eintr_and_assembles_fragments() {
        let mut reader = InterruptedFragmentedReader { reads: 0 };
        let mut pending = Vec::new();
        let frame = read_setup_frame(&mut reader, &mut pending)
            .expect("read setup frame")
            .expect("complete frame");

        assert_eq!(frame, "STARTED");
        assert!(pending.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn user_namespace_probe_wait_retries_eintr() {
        let mut waits = 0;
        let available = wait_for_user_namespace_probe_with(42, |status| {
            waits += 1;
            if waits == 1 {
                return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
            }
            *status = 0;
            Ok(42)
        });

        assert!(available);
        assert_eq!(waits, 2);
    }
    use std::path::PathBuf;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    fn fs(
        ar: &[&str],
        dr: &[&str],
        aw: &[&str],
        dw: &[&str],
        fw: bool,
        fa: bool,
        net: bool,
    ) -> FileSystemSandboxPolicy {
        let ar: Vec<_> = ar.iter().map(|s| p(s)).collect();
        let dr: Vec<_> = dr.iter().map(|s| p(s)).collect();
        let aw: Vec<_> = aw.iter().map(|s| p(s)).collect();
        let dw: Vec<_> = dw.iter().map(|s| p(s)).collect();
        build_fs_policy(&ar, &dr, &aw, &dw, fw, fa, net, Path::new("/work"))
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_helper_environment_does_not_expose_child_values() {
        let child_env = HashMap::from([
            ("PATH".to_string(), "/target/bin".to_string()),
            ("LD_PRELOAD".to_string(), "/target/inject.so".to_string()),
            ("CUSTOM".to_string(), "target-only".to_string()),
        ]);
        let env_file = Path::new("/private/child-env.json");

        let helper_env = linux_helper_environment(env_file);

        assert_eq!(
            helper_env,
            HashMap::from([
                ("PATH".to_string(), STRICT_PATH.to_string()),
                (
                    TARGET_ENV_FILE_ENV.to_string(),
                    env_file.display().to_string(),
                ),
            ])
        );
        for value in child_env.values() {
            assert!(!helper_env.values().any(|helper| helper == value));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn private_target_environment_uses_a_unique_read_root_and_cleans_it() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = tempfile::tempdir().expect("create target environment root");
        let environment = HashMap::from([("CUSTOM".to_string(), "target-only".to_string())]);
        let snapshot = PrivateTargetEnvironment::create_in(&environment, fixture.path())
            .expect("create target environment snapshot");
        let read_root = snapshot.read_root().to_path_buf();
        let path = snapshot.path().to_path_buf();

        assert_eq!(read_root.parent(), Some(fixture.path()));
        assert_eq!(path, read_root.join("environment.json"));
        assert_eq!(
            std::fs::symlink_metadata(&read_root)
                .expect("inspect snapshot directory")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::symlink_metadata(&path)
                .expect("inspect snapshot file")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            serde_json::from_slice::<HashMap<String, String>>(
                &std::fs::read(&path).expect("read snapshot")
            )
            .expect("decode snapshot"),
            environment
        );

        drop(snapshot);
        assert!(!read_root.exists());
    }

    #[test]
    fn profile_strictness_is_effective_without_explicit_strict_flag() {
        let strict_profile = crate::profile_core::Profile {
            strict_sandbox: Some(true),
            ..Default::default()
        };
        let relaxed_profile = crate::profile_core::Profile {
            strict_sandbox: Some(false),
            ..Default::default()
        };

        assert!(is_strict(false, &strict_profile));
        assert!(is_strict(true, &relaxed_profile));
        assert!(!is_strict(false, &relaxed_profile));
    }

    #[test]
    fn strict_profile_conflicts_are_rejected_after_profile_application() {
        let profile = crate::profile_core::Profile {
            strict_sandbox: Some(true),
            allow_all: Some(true),
            ..Default::default()
        };
        let mut allow_read = Vec::new();
        let mut deny_read = Vec::new();
        let mut allow_write = Vec::new();
        let mut deny_write = Vec::new();
        let mut full_write = false;
        let mut allow_net = None;
        let mut deny_net = Vec::new();
        let mut env = HashMap::new();
        let mut allow_env = None;
        let mut deny_env = Vec::new();
        let mut secrets = Vec::new();
        let mut secret_hosts = Vec::new();
        let mut disabled = false;
        let mut full_access = false;

        apply_profile(
            &profile,
            &mut allow_read,
            &mut deny_read,
            &mut allow_write,
            &mut deny_write,
            &mut full_write,
            &mut allow_net,
            &mut deny_net,
            &mut env,
            &mut allow_env,
            &mut deny_env,
            &mut secrets,
            &mut secret_hosts,
            &mut disabled,
            &mut full_access,
        );

        let error =
            validate_sandbox_configuration(is_strict(false, &profile), disabled, full_access)
                .expect_err("a strict profile must not downgrade itself to full access");
        assert!(error.to_string().contains("strict sandbox"));
    }

    #[test]
    fn explicit_strict_path_overrides_default_inherited_and_secret_paths() {
        let strict_path = select_strict_path(true, Some("/opt/tools/bin:/usr/bin"))
            .expect("explicit strict PATH should validate")
            .expect("strict mode should select a PATH");
        let env = finalize_child_env(
            HashMap::from([("PATH".to_string(), "/host/bin".to_string())]),
            HashMap::from([(
                "PATH".to_string(),
                "ZEROBOX_SECRET_PATH_PLACEHOLDER".to_string(),
            )]),
            Some(&strict_path),
        );

        assert_eq!(
            env.get("PATH"),
            Some(&"/opt/tools/bin:/usr/bin".to_string())
        );
    }

    #[test]
    fn strict_path_uses_minimal_default_without_a_configured_value() {
        assert_eq!(
            select_strict_path(true, None).unwrap(),
            Some(STRICT_PATH.to_string())
        );
        assert_eq!(select_strict_path(false, Some("relative")).unwrap(), None);
    }

    #[test]
    fn strict_path_rejects_empty_and_relative_segments() {
        for invalid in [
            "",
            ":/usr/bin",
            "/usr/bin:",
            "/usr/bin::/bin",
            "bin:/usr/bin",
        ] {
            assert!(
                select_strict_path(true, Some(invalid)).is_err(),
                "strict PATH should reject {invalid:?}"
            );
        }
    }

    #[test]
    fn reserved_home_variables_are_removed_after_inherit_and_explicit_overrides() {
        let env = finalize_child_env(
            HashMap::from([
                ("ZEROBOX_HOME".to_string(), "/inherited/zerobox".to_string()),
                ("CODEX_HOME".to_string(), "/inherited/codex".to_string()),
                ("SAFE".to_string(), "inherited".to_string()),
            ]),
            HashMap::from([
                ("ZEROBOX_HOME".to_string(), "/explicit/zerobox".to_string()),
                ("CODEX_HOME".to_string(), "/explicit/codex".to_string()),
                ("SAFE".to_string(), "secret".to_string()),
            ]),
            None,
        );

        assert!(!env.contains_key("ZEROBOX_HOME"));
        assert!(!env.contains_key("CODEX_HOME"));
        assert_eq!(env.get("SAFE"), Some(&"secret".to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn private_proxy_root_is_owner_only_and_removed_with_its_handle() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let temp = tempfile::tempdir().expect("create temporary run root");
        let path;
        {
            let root = PrivateProxyRoot::create_in(temp.path()).expect("create private root");
            path = root.path().to_path_buf();
            let metadata = std::fs::symlink_metadata(&path).expect("inspect private root");
            let current_uid = std::fs::metadata("/proc/self")
                .expect("inspect current process")
                .uid();

            assert!(metadata.is_dir());
            assert!(!metadata.file_type().is_symlink());
            assert_eq!(metadata.uid(), current_uid);
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        }
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn private_proxy_root_rejects_paths_that_cannot_fit_linux_unix_sockets() {
        let long_root = PathBuf::from("/").join("a".repeat(108));
        let error = validate_linux_proxy_socket_path_budget(&long_root)
            .expect_err("overlong private root must fail before helper launch");
        assert!(error.to_string().contains("too long"));
    }

    async fn prepare_error(sandbox: Sandbox) -> anyhow::Error {
        match sandbox.prepare().await {
            Ok(_) => panic!("sandbox preparation unexpectedly succeeded"),
            Err(error) => error.into(),
        }
    }

    #[tokio::test]
    async fn prepare_rejects_a_strict_profile_with_no_sandbox() {
        let error = prepare_error(
            Sandbox::command("/bin/true")
                .profile("analysis-strict")
                .no_sandbox(),
        )
        .await;

        assert!(error.to_string().contains("strict sandbox"));
    }

    #[tokio::test]
    async fn prepare_rejects_a_strict_profile_with_full_access() {
        let error = prepare_error(
            Sandbox::command("/bin/true")
                .profile("analysis-strict")
                .full_access(),
        )
        .await;

        assert!(error.to_string().contains("strict sandbox"));
    }

    #[tokio::test]
    async fn prepare_rejects_deny_read_globs_with_full_access() {
        let error = prepare_error(
            Sandbox::command("/bin/true")
                .no_profile()
                .full_access()
                .deny_read("/safe/deny*"),
        )
        .await;

        assert!(error.to_string().contains("deny_read"));
    }

    #[tokio::test]
    async fn prepare_rejects_deny_write_globs_with_full_access() {
        let error = prepare_error(
            Sandbox::command("/bin/true")
                .no_profile()
                .full_access()
                .deny_write("/safe/deny*"),
        )
        .await;

        assert!(error.to_string().contains("deny_write"));
    }

    #[test]
    fn deny_paths_reject_glob_metacharacters() {
        for path in ["/safe/deny*", "/safe/deny?", "/safe/[deny]", "/safe/{deny}"] {
            let error = validate_paths(&[], &[p(path)], &[], &[], Path::new("/work"))
                .expect_err("deny paths must be literal");
            assert!(error.to_string().contains("deny_read"), "error: {error:#}");
        }
    }

    // filesystem policy

    #[test]
    fn fs_default_full_read_no_write() {
        let pol = fs(&[], &[], &[], &[], false, false, false);
        assert!(pol.has_full_disk_read_access());
        assert!(!pol.has_full_disk_write_access());
    }

    #[test]
    fn fs_full_access_unrestricted() {
        let pol = fs(&[], &[], &[], &[], false, true, false);
        assert!(pol.has_full_disk_read_access());
        assert!(pol.has_full_disk_write_access());
    }

    #[test]
    fn fs_full_access_ignores_denies() {
        let pol = fs(&[], &["/secret"], &[], &["/protected"], false, true, false);
        assert!(pol.has_full_disk_read_access());
        assert!(pol.has_full_disk_write_access());
    }

    #[test]
    fn fs_allow_read_restricts() {
        let pol = fs(&["/src"], &[], &[], &[], false, false, false);
        assert!(!pol.has_full_disk_read_access());
    }

    #[test]
    fn fs_deny_read_carves_from_default() {
        let pol = fs(&[], &["/secret"], &[], &[], false, false, false);
        let cwd = Path::new("/work");
        assert!(!pol.has_full_disk_read_access());
        assert!(pol.can_read_path_with_cwd(Path::new("/other"), cwd));
        assert!(!pol.can_read_path_with_cwd(Path::new("/secret/key"), cwd));
    }

    #[test]
    fn fs_deny_read_within_allow_read() {
        let pol = fs(&["/src"], &["/src/private"], &[], &[], false, false, false);
        let cwd = Path::new("/work");
        assert!(pol.can_read_path_with_cwd(Path::new("/src/lib.rs"), cwd));
        assert!(!pol.can_read_path_with_cwd(Path::new("/src/private/key"), cwd));
    }

    #[test]
    fn fs_write_specific_path() {
        let cwd = Path::new("/project");
        let ar: Vec<PathBuf> = vec![];
        let aw = vec![p("/project/dist")];
        let pol = build_fs_policy(&ar, &[], &aw, &[], false, false, false, cwd);
        assert!(pol.can_write_path_with_cwd(Path::new("/project/dist/out.js"), cwd));
        assert!(!pol.can_write_path_with_cwd(Path::new("/project/src/main.rs"), cwd));
    }

    #[test]
    fn fs_full_write() {
        let pol = fs(&[], &[], &[], &[], true, false, false);
        assert!(pol.has_full_disk_write_access());
    }

    #[test]
    fn fs_deny_write_carves_from_allow() {
        let cwd = Path::new("/project");
        let aw = vec![p("/project")];
        let dw = vec![p("/project/.git")];
        let pol = build_fs_policy(&[], &[], &aw, &dw, false, false, false, cwd);
        assert!(pol.can_write_path_with_cwd(Path::new("/project/src/x"), cwd));
        assert!(!pol.can_write_path_with_cwd(Path::new("/project/.git/config"), cwd));
    }

    #[test]
    fn fs_deny_write_without_allow_is_noop() {
        let cwd = Path::new("/work");
        let pol = build_fs_policy(&[], &[], &[], &[p("/x")], false, false, false, cwd);
        assert!(!pol.can_write_path_with_cwd(Path::new("/x"), cwd));
        assert!(!pol.can_write_path_with_cwd(Path::new("/anywhere"), cwd));
    }

    #[test]
    fn fs_deny_read_and_deny_write_combined() {
        let cwd = Path::new("/work");
        let pol = build_fs_policy(
            &[],
            &[p("/secret")],
            &[p("/out")],
            &[p("/out/.git")],
            false,
            false,
            false,
            cwd,
        );
        assert!(!pol.can_read_path_with_cwd(Path::new("/secret/x"), cwd));
        assert!(pol.can_read_path_with_cwd(Path::new("/other"), cwd));
        assert!(pol.can_write_path_with_cwd(Path::new("/out/file"), cwd));
        assert!(!pol.can_write_path_with_cwd(Path::new("/out/.git/hooks"), cwd));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_helper_read_root_is_added_to_restricted_policy() {
        let cwd = Path::new("/work");
        let pol = fs(&["/usr/bin"], &[], &[], &[], false, false, false);
        let helper = Path::new("/home/me/.zerobox/tmp/arg0/zerobox-arg0abc/zerobox-linux-sandbox");

        let pol = with_linux_helper_read_root(pol, Some(helper), cwd);

        assert!(pol.can_read_path_with_cwd(helper, cwd));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_helper_read_root_resolves_relative_helper_against_cwd() {
        let cwd = Path::new("/work");
        let pol = fs(&["/usr/bin"], &[], &[], &[], false, false, false);
        let helper = Path::new(".zerobox/tmp/arg0/zerobox-arg0abc/zerobox-linux-sandbox");

        let pol = with_linux_helper_read_root(pol, Some(helper), cwd);

        assert!(pol.can_read_path_with_cwd(
            Path::new("/work/.zerobox/tmp/arg0/zerobox-arg0abc/zerobox-linux-sandbox"),
            cwd
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_helper_read_root_does_not_duplicate_existing_read_root() {
        let cwd = Path::new("/work");
        let pol = fs(
            &["/home/me/.zerobox/tmp/arg0"],
            &[],
            &[],
            &[],
            false,
            false,
            false,
        );
        let helper = Path::new("/home/me/.zerobox/tmp/arg0/zerobox-arg0abc/zerobox-linux-sandbox");
        let before = pol.entries.len();

        let pol = with_linux_helper_read_root(pol, Some(helper), cwd);

        assert_eq!(pol.entries.len(), before);
    }

    // legacy policy

    #[test]
    fn legacy_default_read_only_no_net() {
        let pol = build_legacy_policy(&[], false, false, false, Path::new("/tmp"));
        assert!(matches!(
            pol,
            SandboxPolicy::ReadOnly {
                network_access: false,
                ..
            }
        ));
    }

    #[test]
    fn legacy_net_flag_propagates() {
        let pol = build_legacy_policy(&[], false, false, true, Path::new("/tmp"));
        assert!(matches!(
            pol,
            SandboxPolicy::ReadOnly {
                network_access: true,
                ..
            }
        ));

        let pol = build_legacy_policy(&[p("/out")], false, false, true, Path::new("/tmp"));
        match pol {
            SandboxPolicy::WorkspaceWrite { network_access, .. } => assert!(network_access),
            other => panic!("expected WorkspaceWrite, got {other:?}"),
        }
    }

    #[test]
    fn legacy_write_paths_become_workspace_write() {
        let pol = build_legacy_policy(&[p("/tmp")], false, false, false, Path::new("/tmp"));
        assert!(matches!(pol, SandboxPolicy::WorkspaceWrite { .. }));
    }

    #[test]
    fn legacy_full_access_or_full_write_is_danger() {
        assert!(matches!(
            build_legacy_policy(&[], true, false, false, Path::new("/tmp")),
            SandboxPolicy::DangerFullAccess
        ));
        assert!(matches!(
            build_legacy_policy(&[], false, true, false, Path::new("/tmp")),
            SandboxPolicy::DangerFullAccess
        ));
        assert!(matches!(
            build_legacy_policy(&[], true, true, true, Path::new("/tmp")),
            SandboxPolicy::DangerFullAccess
        ));
    }

    // env

    #[test]
    fn env_default_filters_to_essentials() {
        let env = build_env(false, None, &[], &HashMap::new());
        for key in DEFAULT_ENV_KEYS {
            if std::env::var(key).is_ok() {
                assert!(env.contains_key(*key), "missing {key}");
            }
        }
        assert!(!env.contains_key("CARGO_MANIFEST_DIR"));
    }

    #[test]
    fn env_inherit_includes_all() {
        let env = build_env(true, None, &[], &HashMap::new());
        assert!(env.len() > DEFAULT_ENV_KEYS.len());
    }

    #[test]
    fn env_allow_env_specific_keys() {
        let keys = vec!["PATH".to_string()];
        let env = build_env(false, Some(&keys), &[], &HashMap::new());
        assert!(env.contains_key("PATH"));
        assert!(!env.contains_key("HOME"));
    }

    #[test]
    fn env_deny_removes_keys() {
        let deny = vec!["PATH".to_string()];
        let env = build_env(false, None, &deny, &HashMap::new());
        assert!(!env.contains_key("PATH"));
    }

    #[test]
    fn env_overrides_win() {
        let mut o = HashMap::new();
        o.insert("PATH".to_string(), "/custom".to_string());
        o.insert("NEW_VAR".to_string(), "val".to_string());
        let env = build_env(false, None, &[], &o);
        assert_eq!(env["PATH"], "/custom");
        assert_eq!(env["NEW_VAR"], "val");
    }

    // resolve_path

    #[test]
    fn resolve_absolute_unchanged() {
        let r = resolve_path(Path::new("/base"), Path::new("/abs/path")).unwrap();
        assert_eq!(r.as_path(), Path::new("/abs/path"));
    }

    #[test]
    fn resolve_relative_joined() {
        let r = resolve_path(Path::new("/base"), Path::new("child")).unwrap();
        assert_eq!(r.as_path(), Path::new("/base/child"));
    }

    // build_secret_store (separate code path from parse_secret_flags)

    #[test]
    fn secret_store_generates_placeholders() {
        let store = secret::build_secret_store(&[("K".into(), "v".into())], &[]).unwrap();
        let o = store.get_env_overrides();
        assert!(o["K"].starts_with("ZEROBOX_SECRET_"));
        assert_eq!(o["K"].len(), "ZEROBOX_SECRET_".len() + 64);
    }

    #[test]
    fn secret_store_host_binding() {
        let store = secret::build_secret_store(
            &[("K".into(), "v".into())],
            &[("K".into(), "a.com,b.com".into())],
        )
        .unwrap();
        let hosts = store.get_allowed_hosts();
        assert!(hosts.contains(&"a.com".to_string()));
        assert!(hosts.contains(&"b.com".to_string()));
    }

    #[test]
    fn secret_store_rejects_duplicate_keys() {
        assert!(
            secret::build_secret_store(&[("K".into(), "a".into()), ("K".into(), "b".into())], &[],)
                .is_err()
        );
    }

    #[test]
    fn secret_store_rejects_empty_key() {
        assert!(secret::build_secret_store(&[("".into(), "v".into())], &[],).is_err());
    }

    #[test]
    fn secret_store_rejects_unknown_host_key() {
        assert!(
            secret::build_secret_store(
                &[("A".into(), "v".into())],
                &[("B".into(), "x.com".into())],
            )
            .is_err()
        );
    }

    // builder

    #[test]
    fn builder_sets_all_fields() {
        let s = Sandbox::command("echo")
            .arg("hello")
            .args(&["world"])
            .cwd("/tmp")
            .env("K", "V")
            .envs([("A", "1")])
            .inherit_env()
            .allow_read("/src")
            .deny_read("/secret")
            .allow_write("/out")
            .deny_write("/out/.git")
            .allow_write_all()
            .allow_net(&["a.com"])
            .deny_net(&["evil.com"])
            .secret("KEY", "val")
            .secret_host("KEY", "api.com")
            .no_sandbox()
            .full_access()
            .profile("workspace")
            .no_profile();

        assert_eq!(s.program, "echo");
        assert_eq!(s.args, vec!["hello", "world"]);
        assert_eq!(s.cwd, Some(PathBuf::from("/tmp")));
        assert_eq!(s.env["K"], "V");
        assert_eq!(s.env["A"], "1");
        assert!(s.inherit_env);
        assert_eq!(s.allow_read, vec![p("/src")]);
        assert_eq!(s.deny_read, vec![p("/secret")]);
        assert_eq!(s.allow_write, vec![p("/out")]);
        assert_eq!(s.deny_write, vec![p("/out/.git")]);
        assert!(s.full_write);
        assert_eq!(s.allow_net, Some(vec!["a.com".to_string()]));
        assert_eq!(s.deny_net, vec!["evil.com".to_string()]);
        assert_eq!(s.secrets, vec![("KEY".into(), "val".into())]);
        assert_eq!(s.secret_hosts, vec![("KEY".into(), "api.com".into())]);
        assert!(s.disabled);
        assert!(s.full_access);
        assert_eq!(s.profile_names, vec!["workspace".to_string()]);
        assert!(!s.use_profile);
        assert_eq!(s.linux_sandbox_exe, None);
        assert!(!s.setup_status);
    }

    #[test]
    fn prepared_command_into_command_remains_available_without_managed_resources() {
        let prepared = PreparedCommand {
            cmd: tokio::process::Command::new("echo"),
            _proxy_handle: None,
            _proxy: None,
            _proxy_root: None,
            _setup_channel: None,
            _target_env_file: None,
        };
        let command = prepared.into_command().expect("unmanaged raw command");
        assert!(format!("{command:?}").contains("echo"));
    }

    #[cfg(unix)]
    #[test]
    fn prepared_command_into_command_does_not_panic_with_managed_resources() {
        let runs = tempfile::tempdir().expect("temporary runs root");
        let proxy_root = PrivateProxyRoot::create_in(runs.path()).expect("private proxy root");
        let prepared = PreparedCommand {
            cmd: tokio::process::Command::new("true"),
            _proxy_handle: None,
            _proxy: None,
            _proxy_root: Some(proxy_root),
            _setup_channel: None,
            _target_env_file: None,
        };

        let conversion =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prepared.into_command()));
        let conversion = conversion.expect("conversion must return an error, not panic");
        assert!(conversion.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn prepared_command_spawn_keeps_managed_resources_until_child_wait() {
        let runs = tempfile::tempdir().expect("temporary runs root");
        let proxy_root = PrivateProxyRoot::create_in(runs.path()).expect("private proxy root");
        let proxy_root_path = proxy_root.path().to_path_buf();
        let mut cmd = tokio::process::Command::new("sh");
        cmd.args(["-c", "test -d \"$MANAGED_ROOT\""])
            .env("MANAGED_ROOT", &proxy_root_path);
        let prepared = PreparedCommand {
            cmd,
            _proxy_handle: None,
            _proxy: None,
            _proxy_root: Some(proxy_root),
            _setup_channel: None,
            _target_env_file: None,
        };

        let child = prepared.spawn().await.expect("spawn prepared command");
        assert!(proxy_root_path.is_dir());
        let status = child.wait().await.expect("wait prepared command");

        assert!(status.success());
        assert!(!proxy_root_path.exists());
    }

    #[test]
    fn builder_allow_net_accumulates_across_calls() {
        let s = Sandbox::command("x")
            .allow_net(&["a.com"])
            .allow_net(&["b.com", "c.com"]);
        assert_eq!(
            s.allow_net,
            Some(vec!["a.com".into(), "b.com".into(), "c.com".into()])
        );
    }

    #[test]
    fn builder_allow_net_all_is_empty_some() {
        let s = Sandbox::command("x").allow_net_all();
        assert_eq!(s.allow_net, Some(vec![]));
    }

    #[test]
    fn builder_profile_accumulates_across_calls() {
        let s = Sandbox::command("x")
            .profile("workspace")
            .profile("git-config");
        assert_eq!(
            s.profile_names,
            vec!["workspace".to_string(), "git-config".to_string()]
        );
        assert!(s.use_profile);
    }

    #[test]
    fn builder_profiles_slice_extends() {
        let s = Sandbox::command("x").profiles(&["workspace", "git-config"]);
        assert_eq!(
            s.profile_names,
            vec!["workspace".to_string(), "git-config".to_string()]
        );
        assert!(s.use_profile);
    }

    #[test]
    fn builder_profile_and_profiles_compose() {
        let s = Sandbox::command("x")
            .profile("a")
            .profiles(&["b", "c"])
            .profile("d");
        assert_eq!(
            s.profile_names,
            vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string()
            ]
        );
    }

    #[test]
    fn builder_can_set_linux_sandbox_exe_override() {
        let s = Sandbox::command("x").linux_sandbox_exe(p("/tmp/zerobox-linux-sandbox"));

        assert_eq!(s.linux_sandbox_exe, Some(p("/tmp/zerobox-linux-sandbox")));
    }

    // apply_profile

    fn apply_default_profile() -> (Vec<PathBuf>, Vec<PathBuf>) {
        let cwd = std::env::current_dir().unwrap();
        let profile = crate::profile_core::load_profile("default", &cwd).unwrap();
        let mut ar = Vec::new();
        let mut dr = Vec::new();
        let mut aw = Vec::new();
        let mut dw = Vec::new();
        let mut fw = false;
        let mut an = None;
        let mut dn = Vec::new();
        let mut env = HashMap::new();
        let mut ae = None;
        let mut de = Vec::new();
        let mut sec = Vec::new();
        let mut sh = Vec::new();
        let mut dis = false;
        let mut fa = false;
        apply_profile(
            &profile, &mut ar, &mut dr, &mut aw, &mut dw, &mut fw, &mut an, &mut dn, &mut env,
            &mut ae, &mut de, &mut sec, &mut sh, &mut dis, &mut fa,
        );
        (ar, dr)
    }

    #[test]
    fn profile_default_adds_deny_rules() {
        let (allow_read, deny_read) = apply_default_profile();
        assert!(!deny_read.is_empty());
        assert!(!allow_read.is_empty());
        let home = dirs::home_dir().unwrap();
        assert!(deny_read.contains(&home.join(".ssh")));
    }

    #[test]
    fn profile_merges_with_existing_rules() {
        let cwd = std::env::current_dir().unwrap();
        let profile = crate::profile_core::load_profile("default", &cwd).unwrap();
        let mut allow_read = vec![p("/my/custom/path")];
        let mut deny_read = vec![p("/my/custom/deny")];
        let mut aw = Vec::new();
        let mut dw = Vec::new();
        let mut fw = false;
        let mut an = None;
        let mut dn = Vec::new();
        let mut env = HashMap::new();
        let mut ae = None;
        let mut de = Vec::new();
        let mut sec = Vec::new();
        let mut sh = Vec::new();
        let mut dis = false;
        let mut fa = false;
        apply_profile(
            &profile,
            &mut allow_read,
            &mut deny_read,
            &mut aw,
            &mut dw,
            &mut fw,
            &mut an,
            &mut dn,
            &mut env,
            &mut ae,
            &mut de,
            &mut sec,
            &mut sh,
            &mut dis,
            &mut fa,
        );
        assert!(allow_read.contains(&p("/my/custom/path")));
        assert!(deny_read.contains(&p("/my/custom/deny")));
        assert!(allow_read.len() > 1);
        assert!(deny_read.len() > 1);
    }

    // wrap_self / is_sandboxed

    #[test]
    fn wrap_self_captures_current_exe() {
        let sb = Sandbox::wrap_self().unwrap();
        let exe = std::env::current_exe().unwrap();
        assert_eq!(sb.program, exe.to_string_lossy().as_ref());
    }

    #[test]
    fn is_sandboxed_false_by_default() {
        assert!(!Sandbox::is_sandboxed());
    }

    // is_claude_invocation

    #[test]
    fn is_claude_invocation_matches_profile_name() {
        assert!(is_claude_invocation("claude"));
    }

    #[test]
    fn is_claude_invocation_rejects_other_profiles() {
        // Mock loader so the test doesn't depend on real profile content or
        // user-dir overrides.
        let loader = |name: &str| -> Option<Vec<String>> {
            match name {
                "codex" => Some(vec!["workspace".to_string(), "codex-macos".to_string()]),
                "claude-macos" => Some(vec![]),
                "default" => Some(vec!["system-read-linux".to_string()]),
                "workspace" | "codex-macos" | "system-read-linux" => Some(vec![]),
                _ => None,
            }
        };
        assert!(!is_claude_invocation_with("codex", loader));
        assert!(!is_claude_invocation_with("claude-macos", loader));
        assert!(!is_claude_invocation_with("default", loader));
    }

    #[test]
    fn is_claude_invocation_follows_transitive_use() {
        let loader = |name: &str| -> Option<Vec<String>> {
            match name {
                "my-claude" => Some(vec!["claude".to_string()]),
                "nested" => Some(vec!["my-claude".to_string()]),
                "cycle-a" => Some(vec!["cycle-b".to_string()]),
                "cycle-b" => Some(vec!["cycle-a".to_string()]),
                _ => None,
            }
        };
        assert!(is_claude_invocation_with("my-claude", loader));
        assert!(is_claude_invocation_with("nested", loader));
        assert!(!is_claude_invocation_with("cycle-a", loader));
        assert!(!is_claude_invocation_with("unknown", loader));
    }

    #[test]
    fn is_claude_invocation_detected_in_multi_profile_list() {
        // Mirrors the expression used in `prepare()` for the claude redirect
        // gate: the redirect fires when any profile in the list resolves to
        // claude, directly or transitively.
        let loader = |name: &str| -> Option<Vec<String>> {
            match name {
                "custom-wrapper" => Some(vec!["claude".to_string()]),
                _ => None,
            }
        };
        let with_claude = ["workspace", "custom-wrapper", "git-config"];
        let without_claude = ["workspace", "git-config"];
        assert!(
            with_claude
                .iter()
                .any(|n| is_claude_invocation_with(n, loader))
        );
        assert!(
            !without_claude
                .iter()
                .any(|n| is_claude_invocation_with(n, loader))
        );
    }

    // validate_home_str

    #[cfg(unix)]
    #[test]
    fn validate_home_str_requires_absolute_path() {
        assert!(validate_home_str(None).is_none());
        assert!(validate_home_str(Some("")).is_none());
        assert!(validate_home_str(Some("relative/path")).is_none());
        assert!(validate_home_str(Some(".")).is_none());
        assert_eq!(validate_home_str(Some("/tmp")), Some(PathBuf::from("/tmp")));
        assert_eq!(
            validate_home_str(Some("/home/user")),
            Some(PathBuf::from("/home/user"))
        );
    }

    // apply_claude_json_redirect

    #[cfg(unix)]
    #[test]
    fn claude_json_redirect_creates_symlink_when_file_absent() {
        let tmp = tempfile::tempdir().unwrap();
        apply_claude_json_redirect(tmp.path());

        let link = tmp.path().join(".claude.json");
        let target = tmp.path().join(".claude/claude.json");
        assert!(link.is_symlink(), "~/.claude.json should be a symlink");
        assert!(target.exists(), "redirect target should be pre-created");
        assert!(tmp.path().join(".claude.json.lock").exists());
        assert!(tmp.path().join(".cache/claude-cli-nodejs").is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn claude_json_redirect_moves_existing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let original = tmp.path().join(".claude.json");
        std::fs::write(&original, b"real-contents").unwrap();

        apply_claude_json_redirect(tmp.path());

        let target = tmp.path().join(".claude/claude.json");
        assert!(original.is_symlink());
        assert_eq!(std::fs::read(&target).unwrap(), b"real-contents");
    }

    #[cfg(unix)]
    #[test]
    fn claude_json_redirect_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        apply_claude_json_redirect(tmp.path());
        let target = tmp.path().join(".claude/claude.json");
        std::fs::write(&target, b"after-first-run").unwrap();

        apply_claude_json_redirect(tmp.path());

        assert!(tmp.path().join(".claude.json").is_symlink());
        assert_eq!(std::fs::read(&target).unwrap(), b"after-first-run");
    }

    #[cfg(unix)]
    #[test]
    fn claude_json_redirect_bails_when_both_exist() {
        let tmp = tempfile::tempdir().unwrap();
        let claude_json = tmp.path().join(".claude.json");
        let target_dir = tmp.path().join(".claude");
        let target = target_dir.join("claude.json");

        std::fs::create_dir_all(&target_dir).unwrap();
        std::fs::write(&claude_json, b"new-contents").unwrap();
        std::fs::write(&target, b"existing-contents").unwrap();

        apply_claude_json_redirect(tmp.path());

        assert!(!claude_json.is_symlink());
        assert!(claude_json.is_file());
        assert_eq!(std::fs::read(&claude_json).unwrap(), b"new-contents");
        assert_eq!(std::fs::read(&target).unwrap(), b"existing-contents");
    }
}
