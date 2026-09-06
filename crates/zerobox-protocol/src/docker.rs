use std::fmt;
use std::path::Path;
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

const UNIX_SCHEME: &str = "unix://";

/// A local Unix-domain socket endpoint for the Docker Engine API.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String", into = "String")]
pub struct UnixSocketPath(String);

impl UnixSocketPath {
    pub const DEFAULT_DOCKER_SOCKET: &'static str = "unix:///var/run/docker.sock";

    pub fn as_path(&self) -> &Path {
        Path::new(self.0.strip_prefix(UNIX_SCHEME).unwrap_or(&self.0))
    }

    pub fn as_uri(&self) -> &str {
        &self.0
    }
}

impl Default for UnixSocketPath {
    fn default() -> Self {
        Self(Self::DEFAULT_DOCKER_SOCKET.to_string())
    }
}

impl FromStr for UnixSocketPath {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let path = if let Some(path) = value.strip_prefix(UNIX_SCHEME) {
            path
        } else if value.contains("://") {
            return Err("Docker endpoint must use a local unix:// socket".to_string());
        } else {
            value
        };

        if path.contains('\0') || !Path::new(path).is_absolute() {
            return Err("Docker Unix socket path must be absolute".to_string());
        }

        Ok(Self(format!("{UNIX_SCHEME}{path}")))
    }
}

impl TryFrom<String> for UnixSocketPath {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_str(&value)
    }
}

impl From<UnixSocketPath> for String {
    fn from(value: UnixSocketPath) -> Self {
        value.0
    }
}

impl fmt::Display for UnixSocketPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum DockerOperation {
    Ps,
    Inspect,
    Logs,
    Stats,
    Exec,
    Start,
    Stop,
    Restart,
}

impl DockerOperation {
    pub const ALL: &'static [Self] = &[
        Self::Ps,
        Self::Inspect,
        Self::Logs,
        Self::Stats,
        Self::Exec,
        Self::Start,
        Self::Stop,
        Self::Restart,
    ];
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DockerTargetSelector {
    ContainerName { name: String },
    ComposeService { project: String, service: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DockerTargetGrant {
    pub selector: DockerTargetSelector,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operations: Option<Vec<DockerOperation>>,
    #[serde(default)]
    pub allow_unsafe_target: bool,
}

impl DockerTargetGrant {
    pub fn effective_operations(&self) -> &[DockerOperation] {
        self.operations.as_deref().unwrap_or(DockerOperation::ALL)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub enum DockerAccessPolicy {
    #[default]
    Disabled,
    Targeted {
        endpoint: UnixSocketPath,
        targets: Vec<DockerTargetGrant>,
    },
    Full {
        endpoint: UnixSocketPath,
    },
}

impl DockerAccessPolicy {
    pub fn targets(&self) -> Option<&[DockerTargetGrant]> {
        match self {
            Self::Targeted { targets, .. } => Some(targets),
            Self::Disabled | Self::Full { .. } => None,
        }
    }

    pub fn endpoint(&self) -> Option<&UnixSocketPath> {
        match self {
            Self::Disabled => None,
            Self::Targeted { endpoint, .. } | Self::Full { endpoint } => Some(endpoint),
        }
    }
}
