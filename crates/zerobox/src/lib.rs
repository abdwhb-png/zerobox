//! Rust SDK for running commands with zerobox sandbox policies.
//!
//! [`Sandbox`] is a builder for a command plus the filesystem, network,
//! environment, profile, and secret rules that should apply to it.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> anyhow::Result<()> {
//! use zerobox::Sandbox;
//!
//! let output = Sandbox::command("echo")
//!     .arg("hello")
//!     .allow_write("/tmp")
//!     .run()
//!     .await?;
//!
//! assert!(output.status.success());
//! # Ok(())
//! # }
//! ```
//!
//! The crate also ships the `zerobox` CLI. See the package README for the CLI
//! flag reference, profile behavior, and platform notes.

#[cfg(target_os = "linux")]
pub mod arg0;
#[cfg(unix)]
mod docker_broker;
#[cfg(target_os = "linux")]
mod dynamic_fs;
#[cfg(target_os = "linux")]
mod linux_runtime;
#[cfg(unix)]
mod process_owner;
pub mod profile_core;
pub mod proxy;
mod sandbox;
pub mod secret;

pub use sandbox::PreparedCommand;
pub use sandbox::PreparedCommandIntoCommandError;
pub use sandbox::Sandbox;
pub use sandbox::SandboxChild;
pub use sandbox::SandboxOutput;
pub use sandbox::SandboxSetupError;
pub use sandbox::TcpPublication;
pub use sandbox::TcpPublicationScope;
pub use zerobox_protocol::docker::{
    DockerAccessPolicy, DockerOperation, DockerTargetGrant, DockerTargetSelector, UnixSocketPath,
};

pub fn zerobox_home() -> std::path::PathBuf {
    let path = std::env::var_os("ZEROBOX_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join(".zerobox")
        });
    if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(&path))
            .unwrap_or(path)
    }
}
