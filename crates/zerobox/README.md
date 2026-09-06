# Zerobox Rust SDK

<p>
  <a href="https://crates.io/crates/zerobox" target="_blank">
    <img src="https://img.shields.io/crates/v/zerobox?style=for-the-badge&labelColor=000000&label=crates.io" alt="Zerobox crates.io version" />
  </a>
  <a href="https://github.com/afshinm/zerobox/blob/main/LICENSE" target="_blank">
    <img src="https://img.shields.io/github/license/afshinm/zerobox?style=for-the-badge&labelColor=000000" alt="Zerobox license" />
  </a>
</p>

Rust SDK for [zerobox](https://github.com/afshinm/zerobox). Sandbox any command with file, network, and credential controls.

This fork is Linux/WSL2 local-only. Upstream crates.io/package references in this document are for upstream only and are **not applicable** here.

```toml
[dependencies]
zerobox = "0.2"
```

The crate ships both a library (`zerobox::Sandbox`) and the `zerobox` binary.

> For CLI usage, secrets concepts, the full flag reference, performance numbers, and platform support see the [main README](https://github.com/afshinm/zerobox).

## Quick start

```rust
use zerobox::Sandbox;

let output = Sandbox::command("echo")
    .arg("hello")
    .allow_write("/tmp")
    .run()
    .await?;

println!("{}", String::from_utf8_lossy(&output.stdout));
println!("exit: {}", output.status);
```

## Execution modes

### Supervisor status channel

On Linux, `zerobox --status-fd=N` uses protocol version 1 and writes one JSON
object per line to a caller-owned writable pipe/FIFO or Unix `SOCK_STREAM`
socket. Pipe descriptors are made nonblocking and socket writes use
nonblocking send semantics. Setup failures emit `setup_error` and exit 125;
successful setup emits `child_started`, then `child_exit` when the target ends.
A target that exits 125 is therefore distinguishable from a setup failure.

The descriptor is marked `CLOEXEC`, is never inherited by the target, and is
closed after every terminal event and on timeout, interruption, or delivery
failure so the caller observes EOF. Failure to deliver `child_started` kills
and reaps the target before Zerobox exits 125. Status reporting does not buffer
or otherwise change the direct stdin/stdout/stderr streams. Regular files and
non-stream Unix sockets are rejected.

### Collect output

```rust
let output = Sandbox::command("cargo")
    .arg("build")
    .allow_write("/project/target")
    .run()
    .await?;
```

### Stream output

```rust
let mut child = Sandbox::command("cargo")
    .arg("build")
    .allow_write("/project/target")
    .allow_net(&["crates.io"])
    .spawn()
    .await?;

let stdout = child.stdout().unwrap();
let status = child.wait().await?;
```

### Inherit stdio (TTY passthrough)

```rust
let status = Sandbox::command("vim")
    .allow_write("/project")
    .status()
    .await?;
```

## Secrets

Pass API keys that the sandboxed process never sees. The proxy substitutes the real value only for approved hosts.

```rust
let output = Sandbox::command("node")
    .arg("agent.js")
    .secret("OPENAI_API_KEY", "sk-proj-123")
    .secret_host("OPENAI_API_KEY", "api.openai.com")
    .secret("GITHUB_TOKEN", "ghp-456")
    .secret_host("GITHUB_TOKEN", "api.github.com")
    .run()
    .await?;
```

See the [main README](https://github.com/afshinm/zerobox#secrets) for how placeholder substitution works.

## Environment variables

Strict mode always selects an explicit `PATH`. Precedence is the built-in
`/usr/local/bin:/usr/bin:/bin`, then profile `set_env.PATH`, then an explicit
caller `env`/`--env PATH=...`. Host `PATH` inherited with `allow_env` is ignored.
Every selected segment must be non-empty and absolute; directory existence is
not required. The selected value is applied after secrets, so a secret named
`PATH` cannot replace it. Invalid strict paths fail preparation (and emit
`setup_error`, then exit 125 when `--status-fd` is active).

```rust
let output = Sandbox::command("node")
    .arg("app.js")
    .env("NODE_ENV", "production")
    .allow_env(&["PATH", "HOME"])
    .deny_env(&["AWS_SECRET_ACCESS_KEY"])
    .run()
    .await?;
```

## Profiles

```rust
// Default profile loads automatically.
let output = Sandbox::command("npm test").run().await?;

// Use a different profile.
let output = Sandbox::command("npm test")
    .profile("workspace")
    .run()
    .await?;

// Combine multiple profiles (merged left-to-right).
let output = Sandbox::command("claude")
    .profiles(&["claude", "git-config"])
    .run()
    .await?;

// Opt out of profiles.
let output = Sandbox::command("npm test")
    .no_profile()
    .allow_read("/src")
    .run()
    .await?;
```

## Full access / no sandbox

```rust
let output = Sandbox::command("install.sh")
    .full_access()
    .run()
    .await?;

let output = Sandbox::command("ls")
    .no_sandbox()
    .run()
    .await?;
```

## Dynamic deny globs

Exact path APIs remain literal. Use the explicit glob APIs when late-created
or renamed matches must remain denied:

```rust
let output = Sandbox::command("make")
    .arg("build")
    .allow_write(".")
    .deny_read_glob("*.pem")
    .deny_write_glob("generated/**")
    .run()
    .await?;
```

Relative basename patterns match at every working-directory depth; relative
patterns containing `/` are working-directory anchored. Dynamic globs require
Linux FUSE and fail closed if their private guarded view cannot be mounted.
See the [main README](../../README.md#dynamic-deny-globs) for complete
semantics and the hardlink limit.

## Docker policy

Trusted launchers can pass an effective policy without exposing the real
Engine socket in the sandbox:

```rust
use std::str::FromStr;
use zerobox::{
    DockerAccessPolicy, DockerOperation, DockerTargetGrant,
    DockerTargetSelector, UnixSocketPath,
};

let output = Sandbox::command("docker")
    .args(&["logs", "app-api-1"])
    .docker_access(DockerAccessPolicy::Targeted {
        endpoint: UnixSocketPath::from_str("/var/run/docker.sock")?,
        targets: vec![DockerTargetGrant {
            selector: DockerTargetSelector::ComposeService {
                project: "app".into(),
                service: "api".into(),
            },
            operations: Some(vec![DockerOperation::Logs]),
            allow_unsafe_target: false,
        }],
    })
    .run()
    .await?;
```

`Full` forwards the complete Engine API and is equivalent to host control.
`exec` inherits the selected container's own mounts, network, and secrets.
Targeted startup fails closed if the initial Engine snapshot cannot be
transported or parsed. Non-streaming routes close after one request, and exec
streaming starts only after a valid Engine `101` TCP upgrade.
Use an external operator policy to decide grants; do not let an untrusted
repository construct its own Docker policy.

## Builder reference

| Method | Description |
| --- | --- |
| `command(cmd)` | Start a new builder for `cmd`. |
| `arg(x)` / `args(xs)` | Append arguments. |
| `cwd(path)` | Working directory. |
| `allow_read(path)` / `deny_read(path)` | Readable / blocked paths. |
| `deny_read_glob(pattern)` | Dynamically block matching reads, metadata, and mutations. |
| `allow_write(path)` / `deny_write(path)` | Writable / blocked paths. |
| `deny_write_glob(pattern)` | Dynamically block matching mutations while preserving reads. |
| `allow_net(domains)` / `deny_net(domains)` | Allowed / blocked domains. Pass `&[]` for all. |
| `env(k, v)` | Set an env var. |
| `allow_env(keys)` / `deny_env(keys)` | Inherit / block parent env vars. |
| `secret(k, v)` / `secret_host(k, hosts)` | Secret and its allowed hosts. |
| `profile(name)` / `profiles(names)` / `no_profile()` | Select or skip profiles. |
| `docker_access(policy)` | Apply a trusted per-execution disabled, targeted, or full Docker policy. |
| `full_access()` / `no_sandbox()` / `strict_sandbox()` | Coarse policy switches. |
| `snapshot()` / `restore()` | Record / roll back filesystem changes. |
| `run()` / `spawn()` / `status()` | Terminators (collect / stream / inherit stdio). |

## Other SDKs

- [TypeScript SDK](https://github.com/afshinm/zerobox/tree/main/packages/zerobox) (npm: `zerobox`)
- [Python SDK](https://github.com/afshinm/zerobox/tree/main/sdks/python) (PyPI: `zerobox`)

## License

Apache-2.0
