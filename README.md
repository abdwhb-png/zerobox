<div align="center">
  <h1>🫙 Zerobox</h1>
  <p><strong>Sandbox any command with file, network, and credential controls.</strong></p>
  <p>
    <a href="https://www.npmjs.com/package/zerobox" target="_blank">
      <img src="https://img.shields.io/npm/v/zerobox?style=for-the-badge&labelColor=000000&label=npm" alt="Zerobox npm version" />
    </a>
    <a href="https://pypi.org/project/zerobox/" target="_blank">
      <img src="https://img.shields.io/pypi/v/zerobox?style=for-the-badge&labelColor=000000&label=PyPI" alt="Zerobox PyPI version" />
    </a>
    <a href="https://crates.io/crates/zerobox" target="_blank">
      <img src="https://img.shields.io/crates/v/zerobox?style=for-the-badge&labelColor=000000&label=crates.io" alt="Zerobox crates.io version" />
    </a>
    <a href="https://github.com/afshinm/zerobox/blob/main/LICENSE" target="_blank">
      <img src="https://img.shields.io/github/license/afshinm/zerobox?style=for-the-badge&labelColor=000000" alt="Zerobox license" />
    </a>
    <a href="https://github.com/afshinm/zerobox/actions/workflows/ci.yml" target="_blank">
      <img src="https://img.shields.io/github/actions/workflow/status/afshinm/zerobox/ci.yml?style=for-the-badge&labelColor=000000&label=CI" alt="Zerobox CI status" />
    </a>
  </p>
</div>

Lightweight, cross-platform process sandboxing powered by [OpenAI Codex](https://github.com/openai/codex)'s sandbox runtime.

- **Deny by default:** Writes, network, and environment variables are blocked unless you allow them
- **Credential injection:** Pass API keys that the process never sees. Zerobox injects real values only for approved hosts
- **File access control:** Allow or deny reads and writes to specific paths
- **Network filtering:** Allow or deny outbound traffic by domain
- **Clean environment:** Only essential env vars (PATH, HOME, etc.) are inherited by default
- **SDKs for Rust, TypeScript, and Python** with a consistent API across languages
- **Scope:** Local Linux / WSL2 only for this fork
- **Single binary:** No Docker, no VMs, ~10ms overhead

<p align="center">
  <a href="https://www.youtube.com/watch?v=wZiPm9BOPCg" target="_blank" title="Watch the video">
    <img alt="Zerobox Sandbox Flow" src="packages/zerobox/assets/flow.svg" alt="Watch the video" style="width: 100%; max-width: 1135px;" />
  </a>
</p>

## Fork provenance

- Base upstream: Zerobox `0.3.3` at commit `9a7affd6c68fb2541c7c709559c40e08ba0a1872`
- Codex rust shim baseline: `rust-v0.131.0-alpha.22` at commit `9b8cf56cdefb09f54564ccc295fd42f6647f558f`
- Version identity for this fork: `0.3.3-fork.6` (Python: `0.3.3+fork.6`)

## Build and usage (local Linux / WSL2 only)

No published install artifacts are exposed in this fork.

Reproducible external install recipe:

```bash
git checkout --detach <commit>
./scripts/sync.sh
cargo build --locked --release -p zerobox
install -Dm755 target/release/zerobox "$DEST/zerobox"
```

Optional local verification commands:

```bash
cargo test --workspace --lib
cargo test -p zerobox --test integration
```

Run with no flags:

```bash
./target/release/zerobox -- node -e "console.log('hello')"
```

Limitations:

- No macOS or Windows packaging is published from this fork
- This fork is only intended for local Linux and WSL2 usage
- SDK docs reference upstream interfaces but behavior is local to this fork

## Quick start

Run a command with no writes and no network access:

```bash
./target/release/zerobox -- node -e "console.log('hello')"
```

Allow writes to a specific directory:

```bash
./target/release/zerobox --allow-write=. -- node script.js
```

Allow network to a specific domain:

```bash
./target/release/zerobox --allow-net=api.openai.com -- node agent.js
```

Pass a secret to a specific host and the inner process never sees the real value:

```bash
./target/release/zerobox --secret OPENAI_API_KEY=sk-proj-123 --secret-host OPENAI_API_KEY=api.openai.com -- node agent.js
```

Record filesystem changes and undo them after execution:

```bash
./target/release/zerobox --restore --allow-write=. -- npm install
```

Or record without restoring, then inspect and undo later:

```bash
./target/release/zerobox --snapshot --allow-write=. -- npm install
./target/release/zerobox snapshot list
./target/release/zerobox snapshot diff <session-id>
./target/release/zerobox snapshot restore <session-id>
```

For programmatic usage jump to the SDK that matches your stack:

- [Rust SDK](crates/zerobox/README.md)
- [TypeScript SDK](packages/zerobox/README.md)
- [Python SDK](sdks/python/README.md)

## Architecture

<p align="center">
  <img src="https://raw.githubusercontent.com/afshinm/zerobox/refs/heads/main/packages/zerobox/assets/sandbox-flow.png" alt="Zerobox architecture" width="800" />
</p>

## Secrets

Secrets are API keys, tokens, or credentials that should never be visible inside the sandbox. The sandboxed process sees a placeholder in the environment variable and the real value is substituted at the network proxy level only for requested hosts.

```
sandbox process: echo $OPENAI_API_KEY
  -> ZEROBOX_SECRET_a1b2c3d4e5...  (placeholder)

sandbox process: curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/...
  -> proxy intercepts, replaces placeholder with real key
  -> server receives: Authorization: Bearer sk-proj-123
```

Pass a secret with `--secret` and restrict it to a specific domain with `--secret-host`:

```bash
./target/release/zerobox --secret OPENAI_API_KEY=sk-proj-123 --secret-host OPENAI_API_KEY=api.openai.com -- node app.js
```

Without `--secret-host`, the secret is passed to all domains:

```bash
./target/release/zerobox --secret TOKEN=abc123 -- node app.js
```

Multiple secrets with different hosts:

```bash
./target/release/zerobox \
  --secret OPENAI_API_KEY=sk-proj-123 --secret-host OPENAI_API_KEY=api.openai.com \
  --secret GITHUB_TOKEN=ghp-456 --secret-host GITHUB_TOKEN=api.github.com \
  -- node app.js
```

> Node.js `fetch` does not respect `HTTPS_PROXY` by default. When running Node.js inside a sandbox with secrets, make sure to pass the `--use-env-proxy` argument.

For SDK code examples, see the [Rust](crates/zerobox/README.md#secrets), [TypeScript](packages/zerobox/README.md#secrets), or [Python](sdks/python/README.md#secrets) README.

## Environment variables

By default only essential variables are passed to the sandbox, e.g. `PATH`, `HOME`, `USER`, `SHELL`, `TERM`, `LANG`.

Inherit all parent env vars:

```bash
./target/release/zerobox --allow-env -- node app.js
```

Inherit specific env vars only:

```bash
./target/release/zerobox --allow-env=PATH,HOME,DATABASE_URL -- node app.js
```

Block specific env vars:

```bash
./target/release/zerobox --allow-env --deny-env=AWS_SECRET_ACCESS_KEY -- node app.js
```

Or set explicit variables:

```bash
./target/release/zerobox --env NODE_ENV=production --env DEBUG=false -- node app.js
```

In strict mode, `PATH` is always explicit. Precedence is the built-in
`/usr/local/bin:/usr/bin:/bin`, then profile `set_env.PATH`, then caller
`--env PATH=...`. A host `PATH` requested through `--allow-env` is ignored.
Segments must be non-empty absolute paths; they do not need to exist. The
selected value is restored after secret placeholders are prepared, so a secret
named `PATH` cannot replace it.

For network rules, `localhost`, `127.0.0.1`, and `::1` are the same loopback
class only when the rule names one of those three aliases and includes the
exact destination port. This does not allow the rest of `127.0.0.0/8` or any
other private address.

On Linux, `--status-fd=N` emits protocol-v1 JSONL lifecycle records to a
writable pipe/FIFO or Unix `SOCK_STREAM`: `setup_error`, or `child_started`
followed by `child_exit`. Writes are nonblocking, the FD is `CLOEXEC`, and the
channel reaches EOF after every terminal path. Status reporting does not
buffer stdin/stdout/stderr. Setup/delivery errors exit 125; a real target exit
125 remains identifiable because it follows `child_started`.

## Examples

### Run AI-generated code safely

Run AI-generated code without risking file corruption or data leaks:

```bash
./target/release/zerobox -- python3 /tmp/task.py
```

Or allow writes only to an output directory:

```bash
./target/release/zerobox --allow-write=/tmp/output -- python3 /tmp/task.py
```

### Restrict LLM tool calls

Each AI tool call can be sandboxed individually. The parent agent process runs normally and only some operations are sandboxed. Full working examples:

- [`examples/ai-agent-sandboxed`](examples/ai-agent-sandboxed) wraps the entire agent process with secrets so the API key is never visible
- [`examples/ai-agent`](examples/ai-agent) uses the Vercel AI SDK with per-tool sandboxing and secrets
- [`examples/workflow`](examples/workflow) runs [Vercel Workflow](https://useworkflow.dev/) with sandboxed durable steps

### Protect your repo during builds

Run a build with network access but writes confined to `./dist`:

```bash
./target/release/zerobox --allow-write=./dist --allow-net -- npm run build
```

Run tests with no network and catch accidental external calls:

```bash
./target/release/zerobox --allow-write=/tmp -- npm test
```

## Performance

Sandbox overhead is minimal, typically ~10ms and ~7MB:

| Command            | Bare | Sandboxed | Overhead | Bare Mem | Sandbox Mem |
| ------------------ | ---- | --------- | -------- | -------- | ----------- |
| `echo hello`       | <1ms | 10ms      | +10ms    | 1.2 MB   | 8.4 MB      |
| `node -e '...'`    | 10ms | 20ms      | +10ms    | 39.3 MB  | 39.1 MB     |
| `python3 -c '...'` | 10ms | 20ms      | +10ms    | 12.9 MB  | 13.0 MB     |
| `cat 10MB file`    | <1ms | 10ms      | +10ms    | 1.9 MB   | 8.4 MB      |
| `curl https://...` | 50ms | 60ms      | +10ms    | 7.2 MB   | 8.4 MB      |

<sub>Best of 10 runs with warmup on Apple M5 Pro. Run `./bench/run.sh` to reproduce.</sub>

## Platform support

| Platform | Backend                             | Status          |
| -------- | ----------------------------------- | --------------- |
| Linux    | Bubblewrap + Seccomp + Namespaces   | Fully supported |
| WSL2     | Same as Linux                        | Fully supported |
| macOS    | Seatbelt (`sandbox-exec`)           | Not supported   |
| Windows  | Restricted Tokens + ACLs + Firewall | Planned         |

## CLI reference

| Flag                            | Example                                | Description                                                                                                  |
| ------------------------------- | -------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `--allow-read <paths>`          | `--allow-read=/tmp,/data`              | Restrict readable user data to listed paths. System libraries remain accessible. Default: all reads allowed. |
| `--deny-read <paths>`           | `--deny-read=/secret`                  | Block reading from these paths. Takes precedence over `--allow-read`.                                        |
| `--allow-write [paths]`         | `--allow-write=.`                      | Allow writing to these paths. Without a value, allows writing everywhere. Default: no writes.                |
| `--deny-write <paths>`          | `--deny-write=./.git`                  | Block writing to these paths. Takes precedence over `--allow-write`.                                         |
| `--allow-net [domains]`         | `--allow-net=example.com`              | Allow outbound network. Without a value, allows all domains. Default: no network.                            |
| `--deny-net <domains>`          | `--deny-net=evil.com`                  | Block network to these domains. Takes precedence over `--allow-net`.                                         |
| `--env <KEY=VALUE>`             | `--env NODE_ENV=prod`                  | Set env var in the sandbox. Can be repeated.                                                                 |
| `--allow-env [keys]`            | `--allow-env=PATH,HOME`                | Inherit parent env vars. Without a value, inherits all. Default: only PATH, HOME, USER, SHELL, TERM, LANG.   |
| `--deny-env <keys>`             | `--deny-env=SECRET`                    | Drop these parent env vars. Takes precedence over `--allow-env`.                                             |
| `--secret <KEY=VALUE>`          | `--secret API_KEY=sk-123`              | Pass a secret. The process sees a placeholder. The real value is injected at the proxy for approved hosts.   |
| `--secret-host <KEY=HOSTS>`     | `--secret-host API_KEY=api.openai.com` | Restrict a secret to specific hosts. Without this, the secret is substituted for all hosts.                  |
| `-A`, `--allow-all`             | `-A`                                   | Grant all filesystem and network permissions. Env and secrets still apply.                                   |
| `--no-sandbox`                  | `--no-sandbox`                         | Disable the sandbox entirely.                                                                                |
| `--strict-sandbox`              | `--strict-sandbox`                     | Require full sandbox (bubblewrap). Fail instead of falling back to weaker isolation.                         |
| `--status-fd <fd>`              | `--status-fd=3`                        | Emit protocol-v1 JSONL lifecycle events to a writable Unix pipe/FIFO or stream socket.                       |
| `--debug`                       | `--debug`                              | Print sandbox config and proxy decisions to stderr.                                                          |
| `--snapshot`                    | `--snapshot`                           | Record filesystem changes during execution.                                                                  |
| `--restore`                     | `--restore`                            | Record and restore tracked files to pre-execution state after exit. Implies `--snapshot`.                    |
| `--snapshot-path <paths>`       | `--snapshot-path=./src`                | Paths to track for snapshots (default: cwd).                                                                 |
| `--snapshot-exclude <patterns>` | `--snapshot-exclude=build`             | Exclude patterns from snapshots.                                                                             |
| `-C <dir>`                      | `-C /workspace`                        | Set working directory for the sandboxed command.                                                             |
| `-V`, `--version`               | `--version`                            | Print version.                                                                                               |
| `-h`, `--help`                  | `--help`                               | Print help.                                                                                                  |

### Snapshot subcommands

| Command                                      | Description                                 |
| -------------------------------------------- | ------------------------------------------- |
| `./target/release/zerobox snapshot list`                      | List recorded sessions.                     |
| `./target/release/zerobox snapshot diff <id>`                 | Show changes from a session.                |
| `./target/release/zerobox snapshot restore <id>`              | Restore filesystem to a session's baseline. |
| `./target/release/zerobox snapshot clean --older-than=<days>` | Remove old snapshot sessions.               |

## SDKs

| Language | Package | README |
| --- | --- | --- |
| Rust | [`zerobox` on crates.io](https://crates.io/crates/zerobox) | [crates/zerobox/README.md](crates/zerobox/README.md) |
| TypeScript / Node | [`zerobox` on npm](https://www.npmjs.com/package/zerobox) | [packages/zerobox/README.md](packages/zerobox/README.md) |
| Python | [`zerobox` on PyPI](https://pypi.org/project/zerobox/) | [sdks/python/README.md](sdks/python/README.md) |

## License

Apache-2.0
