#!/usr/bin/env bash
#
# Sync sandbox crates from openai/codex, rename to zerobox-*.
#
# Usage:
#   ./sync.sh                    # use pinned ref from UPSTREAM_VERSION
#   ./sync.sh rust-v0.118.0      # specific tag/branch/SHA

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."

if sed --version >/dev/null 2>&1; then
    SED_INPLACE=(sed -i)
else
    SED_INPLACE=(sed -i '')
fi

UPSTREAM_DIR="$ROOT/upstream"
VERSION_FILE="$ROOT/UPSTREAM_VERSION"

if [ $# -ge 1 ]; then
    REF="$1"
    PINNED_COMMIT=""
else
    if [ ! -f "$VERSION_FILE" ]; then
        echo "error: no ref specified and no UPSTREAM_VERSION file found"
        echo "usage: $0 <release-tag|branch|SHA>"
        exit 1
    fi
    REF="$(head -1 "$VERSION_FILE" | tr -d '[:space:]')"
    PINNED_COMMIT="$(sed -n 's/^# commit: \([0-9a-fA-F]\{40,64\}\)$/\1/p' "$VERSION_FILE" | head -1)"
    if [ -z "$PINNED_COMMIT" ]; then
        echo "error: UPSTREAM_VERSION has no valid '# commit: <SHA>' pin"
        exit 1
    fi
fi

echo "==> Syncing from openai/codex @ $REF"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "==> Cloning (shallow) into $WORK_DIR ..."
git clone --depth 1 --branch "$REF" https://github.com/openai/codex.git "$WORK_DIR/codex" 2>&1 | tail -2

SRC="$WORK_DIR/codex/codex-rs"

if [ ! -d "$SRC" ]; then
    echo "error: $SRC does not exist. Is the ref correct?"
    exit 1
fi

COMMIT_SHA="$(git -C "$WORK_DIR/codex" rev-parse HEAD)"
echo "==> Resolved to commit $COMMIT_SHA"

if [ -n "$PINNED_COMMIT" ] && [ "$COMMIT_SHA" != "$PINNED_COMMIT" ]; then
    echo "error: ref '$REF' resolved to $COMMIT_SHA, not pinned commit $PINNED_COMMIT"
    echo "       pass an explicit ref to accept and record a new upstream commit"
    exit 1
fi

CRATES=(
    sandboxing
    linux-sandbox
    windows-sandbox-rs
    process-hardening
    network-proxy
)

UTILS=(
    absolute-path
    string
    pty
    rustls-provider
)

echo "==> Cleaning upstream/"
rm -rf "$UPSTREAM_DIR"
mkdir -p "$UPSTREAM_DIR/utils"

for crate in "${CRATES[@]}"; do
    echo "    $crate/"
    cp -r "$SRC/$crate" "$UPSTREAM_DIR/$crate"
done

for util in "${UTILS[@]}"; do
    echo "    utils/$util/"
    cp -r "$SRC/utils/$util" "$UPSTREAM_DIR/utils/$util"
done

if [ -d "$SRC/vendor" ]; then
    echo "    vendor/"
    cp -r "$SRC/vendor" "$UPSTREAM_DIR/vendor"
fi

# --- Inline error types into linux-sandbox (replace codex-core dep) ---

echo "==> Patching linux-sandbox..."

rm -rf "$UPSTREAM_DIR/linux-sandbox/tests"

cat > "$UPSTREAM_DIR/linux-sandbox/src/error.rs" <<'ERRS'
use std::io;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, CodexErr>;

#[derive(Error, Debug)]
pub enum SandboxErr {
    #[cfg(target_os = "linux")]
    #[error("seccomp setup error")]
    SeccompInstall(#[from] seccompiler::Error),

    #[cfg(target_os = "linux")]
    #[error("seccomp backend error")]
    SeccompBackend(#[from] seccompiler::BackendError),

    #[error("command was killed by a signal")]
    Signal(i32),

    #[error("Landlock was not able to fully enforce all sandbox rules")]
    LandlockRestrict,
}

#[derive(Error, Debug)]
pub enum CodexErr {
    #[error("sandbox error: {0}")]
    Sandbox(#[from] SandboxErr),

    #[error("unsupported operation: {0}")]
    UnsupportedOperation(String),

    #[error("Fatal error: {0}")]
    Fatal(String),

    #[error(transparent)]
    Io(#[from] io::Error),

    #[cfg(target_os = "linux")]
    #[error(transparent)]
    LandlockRuleset(#[from] landlock::RulesetError),

    #[cfg(target_os = "linux")]
    #[error(transparent)]
    LandlockPathFd(#[from] landlock::PathFdError),
}
ERRS

"${SED_INPLACE[@]}" '/^#\[cfg(target_os = "linux")\]/{
N
/mod bwrap;/{
a\
#[cfg(target_os = "linux")]\
pub mod error;
}
}' "$UPSTREAM_DIR/linux-sandbox/src/lib.rs"

find "$UPSTREAM_DIR/linux-sandbox/src" -name '*.rs' -exec "${SED_INPLACE[@]}" \
    -e 's/use codex_core::error::/use crate::error::/g' \
    -e 's/use codex_protocol::error::/use crate::error::/g' \
    -e 's/codex_core::error::/crate::error::/g' \
    -e 's/codex_protocol::error::/crate::error::/g' \
    {} +

"${SED_INPLACE[@]}" '/^codex-core = /d' "$UPSTREAM_DIR/linux-sandbox/Cargo.toml"
"${SED_INPLACE[@]}" '/^codex-config = /d' "$UPSTREAM_DIR/linux-sandbox/Cargo.toml"
"${SED_INPLACE[@]}" '/^clap = /a\
thiserror = { workspace = true }
' "$UPSTREAM_DIR/linux-sandbox/Cargo.toml"

# We don't expose protocol::error, so drop the upstream From impl that uses it.
SANDBOXING_LIB="$UPSTREAM_DIR/sandboxing/src/lib.rs"
"${SED_INPLACE[@]}" '/^use codex_protocol::error::CodexErr;$/d' "$SANDBOXING_LIB"
"${SED_INPLACE[@]}" '/^impl From<SandboxTransformError> for CodexErr {$/,/^}$/d' "$SANDBOXING_LIB"

# --- Patch windows-sandbox-rs (path dep -> workspace) ---

WIN_TOML="$UPSTREAM_DIR/windows-sandbox-rs/Cargo.toml"
if [ -f "$WIN_TOML" ] && grep -q 'path = "\.\./protocol"' "$WIN_TOML"; then
    echo "==> Patching windows-sandbox-rs..."
    "${SED_INPLACE[@]}" 's|\[dependencies\.codex-protocol\]|codex-protocol = { workspace = true }|' "$WIN_TOML"
    "${SED_INPLACE[@]}" '/^package = "codex-protocol"/d' "$WIN_TOML"
    "${SED_INPLACE[@]}" '/^path = "\.\.\/protocol"/d' "$WIN_TOML"
fi

# --- Rename codex-* → zerobox-* ---

echo "==> Renaming codex-* → zerobox-*..."

RENAME_PAIRS=(
    "codex-linux-sandbox:zerobox-linux-sandbox"
    "codex-network-proxy:zerobox-network-proxy"
    "codex-otel:zerobox-otel"
    "codex-process-hardening:zerobox-process-hardening"
    "codex-protocol:zerobox-protocol"
    "codex-sandboxing:zerobox-sandboxing"
    "codex-windows-sandbox:zerobox-windows-sandbox"
    "codex-utils-absolute-path:zerobox-utils-absolute-path"
    "codex-utils-pty:zerobox-utils-pty"
    "codex-utils-string:zerobox-utils-string"
    "codex-utils-home-dir:zerobox-utils-home-dir"
    "codex-utils-rustls-provider:zerobox-utils-rustls-provider"
    "codex-command-runner:zerobox-command-runner"
    "codex-windows-sandbox-setup:zerobox-windows-sandbox-setup"
    "find-codex-home:find-home"
)

SED_ARGS=()
for pair in "${RENAME_PAIRS[@]}"; do
    old="${pair%%:*}"
    new="${pair##*:}"
    SED_ARGS+=(-e "s/${old}/${new}/g")
    old_us="${old//-/_}"
    new_us="${new//-/_}"
    SED_ARGS+=(-e "s/${old_us}/${new_us}/g")
done

find "$UPSTREAM_DIR" \( -name '*.rs' -o -name '*.toml' \) \
    -exec "${SED_INPLACE[@]}" "${SED_ARGS[@]}" {} +

find "$UPSTREAM_DIR" -name '*.rs' -exec "${SED_INPLACE[@]}" \
    -e 's/CODEX_LINUX_SANDBOX_ARG0/ZEROBOX_LINUX_SANDBOX_ARG0/g' \
    {} +

# Add workspace metadata inheritance for crates.io publishing.
find "$UPSTREAM_DIR" -name 'Cargo.toml' -exec "${SED_INPLACE[@]}" \
    '/^license.workspace/a\
description.workspace = true\
repository.workspace = true\
homepage.workspace = true
' {} +

set_docs_url() {
    local manifest="$1"
    local url="$2"
    if [ -f "$manifest" ]; then
        "${SED_INPLACE[@]}" "/^homepage.workspace = true/a\\
documentation = \"$url\"
" "$manifest"
    fi
}

# Crates.io only auto-links docs.rs after a successful docs.rs build. Keep the
# links explicit so each published crate has a stable Documentation URL.
set_docs_url "$UPSTREAM_DIR/linux-sandbox/Cargo.toml" "https://docs.rs/zerobox-linux-sandbox"
set_docs_url "$UPSTREAM_DIR/network-proxy/Cargo.toml" "https://docs.rs/zerobox-network-proxy"
set_docs_url "$UPSTREAM_DIR/process-hardening/Cargo.toml" "https://docs.rs/zerobox-process-hardening"
set_docs_url "$UPSTREAM_DIR/sandboxing/Cargo.toml" "https://docs.rs/zerobox-sandboxing"
set_docs_url "$UPSTREAM_DIR/windows-sandbox-rs/Cargo.toml" "https://docs.rs/zerobox-windows-sandbox"
set_docs_url "$UPSTREAM_DIR/utils/absolute-path/Cargo.toml" "https://docs.rs/zerobox-utils-absolute-path"
set_docs_url "$UPSTREAM_DIR/utils/pty/Cargo.toml" "https://docs.rs/zerobox-utils-pty"
set_docs_url "$UPSTREAM_DIR/utils/rustls-provider/Cargo.toml" "https://docs.rs/zerobox-utils-rustls-provider"
set_docs_url "$UPSTREAM_DIR/utils/string/Cargo.toml" "https://docs.rs/zerobox-utils-string"

cat >> "$UPSTREAM_DIR/linux-sandbox/Cargo.toml" <<'TOML'

[package.metadata.docs.rs]
targets = ["x86_64-unknown-linux-gnu"]
TOML

# --- Apply patches ---

echo "==> Applying patches..."

cd "$ROOT"

PATCH="$SCRIPT_DIR/upstream-secret-substitution.patch"
if [ -f "$PATCH" ]; then
    echo "    secret-substitution"
    patch --fuzz=0 -p1 < "$PATCH"
    if command -v cargo >/dev/null 2>&1 && command -v rustfmt >/dev/null 2>&1; then
        cargo fmt -- \
            upstream/network-proxy/src/certs.rs \
            upstream/network-proxy/src/http_proxy.rs \
            upstream/network-proxy/src/lib.rs \
            upstream/network-proxy/src/mitm.rs \
            upstream/network-proxy/src/runtime.rs \
            2>/dev/null || true
    fi
fi

PLATFORM_PATCH="$SCRIPT_DIR/upstream-platform-defaults.patch"
if [ -f "$PLATFORM_PATCH" ]; then
    echo "    platform-defaults"
    patch --fuzz=0 -p0 < "$PLATFORM_PATCH"
fi

DENY_WRITE_PATCH="$SCRIPT_DIR/upstream-deny-default-write.patch"
if [ -f "$DENY_WRITE_PATCH" ]; then
    echo "    deny-default-write"
    patch --fuzz=0 -p0 < "$DENY_WRITE_PATCH"
fi

CODEX_PROTECT_PATCH="$SCRIPT_DIR/upstream-no-preemptive-codex-protect.patch"
if [ -f "$CODEX_PROTECT_PATCH" ]; then
    echo "    no-preemptive-codex-protect"
    patch --fuzz=0 -p0 < "$CODEX_PROTECT_PATCH"
    if command -v cargo >/dev/null 2>&1 && command -v rustfmt >/dev/null 2>&1; then
        cargo fmt -- \
            upstream/sandboxing/src/seatbelt_tests.rs \
            upstream/linux-sandbox/src/bwrap.rs \
            2>/dev/null || true
    fi
fi

HOME_ENV_PATCH="$SCRIPT_DIR/upstream-zerobox-home-env.patch"
if [ -f "$HOME_ENV_PATCH" ]; then
    echo "    zerobox-home-env"
    patch --fuzz=0 -p0 < "$HOME_ENV_PATCH"
fi

NODE_PROXY_PATCH="$SCRIPT_DIR/upstream-node-env-proxy.patch"
if [ -f "$NODE_PROXY_PATCH" ]; then
    echo "    node-env-proxy"
    patch --fuzz=0 -p0 < "$NODE_PROXY_PATCH"
fi

PROXY_ZOMBIE_PATCH="$SCRIPT_DIR/upstream-proxy-zombie-cleanup.patch"
if [ -f "$PROXY_ZOMBIE_PATCH" ]; then
    echo "    proxy-zombie-cleanup"
    patch --fuzz=0 -p0 < "$PROXY_ZOMBIE_PATCH"
fi

BWRAP_FIXES_PATCH="$SCRIPT_DIR/upstream-bwrap-fixes.patch"
if [ -f "$BWRAP_FIXES_PATCH" ]; then
    echo "    bwrap-fixes"
    patch --fuzz=0 -p0 < "$BWRAP_FIXES_PATCH"
fi

STRICT_BWRAP_PATCH="$SCRIPT_DIR/upstream-strict-bwrap.patch"
if [ -f "$STRICT_BWRAP_PATCH" ]; then
    echo "    strict-bwrap"
    patch --fuzz=0 -p0 < "$STRICT_BWRAP_PATCH"
fi

NETWORK_HARDENING_PATCH="$SCRIPT_DIR/upstream-network-hardening.patch"
if [ -f "$NETWORK_HARDENING_PATCH" ]; then
    echo "    network-hardening"
    patch --fuzz=0 -p0 < "$NETWORK_HARDENING_PATCH"
fi

PROXY_ROOT_PLUMBING_PATCH="$SCRIPT_DIR/upstream-proxy-root-plumbing.patch"
if [ -f "$PROXY_ROOT_PLUMBING_PATCH" ]; then
    echo "    proxy-root-plumbing"
    patch --fuzz=0 -p0 < "$PROXY_ROOT_PLUMBING_PATCH"
fi

SETUP_STATUS_PATCH="$SCRIPT_DIR/upstream-setup-status.patch"
if [ -f "$SETUP_STATUS_PATCH" ]; then
    echo "    setup-status"
    patch --fuzz=0 -p0 < "$SETUP_STATUS_PATCH"
fi

SETUP_SUPERVISOR_HARDENING_PATCH="$SCRIPT_DIR/upstream-setup-supervisor-hardening.patch"
if [ -f "$SETUP_SUPERVISOR_HARDENING_PATCH" ]; then
    echo "    setup-supervisor-hardening"
    patch --fuzz=0 -p0 < "$SETUP_SUPERVISOR_HARDENING_PATCH"
fi

SETUP_PROTOCOL_TESTING_PATCH="$SCRIPT_DIR/upstream-setup-protocol-testing.patch"
if [ -f "$SETUP_PROTOCOL_TESTING_PATCH" ]; then
    echo "    setup-protocol-testing"
    patch --fuzz=0 -p0 < "$SETUP_PROTOCOL_TESTING_PATCH"
fi

SETUP_POSTFORK_ERRORS_PATCH="$SCRIPT_DIR/upstream-setup-postfork-errors.patch"
if [ -f "$SETUP_POSTFORK_ERRORS_PATCH" ]; then
    echo "    setup-postfork-errors"
    patch --fuzz=0 -p0 < "$SETUP_POSTFORK_ERRORS_PATCH"
fi

SETUP_SIGNAL_ORDER_TEST_PATCH="$SCRIPT_DIR/upstream-setup-signal-order-test.patch"
if [ -f "$SETUP_SIGNAL_ORDER_TEST_PATCH" ]; then
    echo "    setup-signal-order-test"
    patch --fuzz=0 -p0 < "$SETUP_SIGNAL_ORDER_TEST_PATCH"
fi

SETUP_SIGNAL_WINDOW_PATCH="$SCRIPT_DIR/upstream-setup-signal-window.patch"
if [ -f "$SETUP_SIGNAL_WINDOW_PATCH" ]; then
    echo "    setup-signal-window"
    patch --fuzz=0 -p0 < "$SETUP_SIGNAL_WINDOW_PATCH"
fi

PROXY_ROUTED_SOCKET_FILTER_PATCH="$SCRIPT_DIR/upstream-proxy-routed-socket-filter.patch"
if [ -f "$PROXY_ROUTED_SOCKET_FILTER_PATCH" ]; then
    echo "    proxy-routed-socket-filter"
    patch --fuzz=0 -p0 < "$PROXY_ROUTED_SOCKET_FILTER_PATCH"
fi

READABLE_CARVEOUTS_PATCH="$SCRIPT_DIR/upstream-readable-carveouts.patch"
if [ -f "$READABLE_CARVEOUTS_PATCH" ]; then
    echo "    readable-carveouts"
    patch --fuzz=0 -p0 < "$READABLE_CARVEOUTS_PATCH"
fi

TARGET_ENV_ISOLATION_PATCH="$SCRIPT_DIR/upstream-target-env-isolation.patch"
if [ -f "$TARGET_ENV_ISOLATION_PATCH" ]; then
    echo "    target-env-isolation"
    patch --fuzz=0 -p0 < "$TARGET_ENV_ISOLATION_PATCH"
fi

READABLE_CARVEOUT_FD_PATCH="$SCRIPT_DIR/upstream-readable-carveout-fd.patch"
if [ -f "$READABLE_CARVEOUT_FD_PATCH" ]; then
    echo "    readable-carveout-fd"
    patch --fuzz=0 -p0 < "$READABLE_CARVEOUT_FD_PATCH"
fi

PRIVATE_BIND_MOUNTS_PATCH="$SCRIPT_DIR/upstream-private-bind-mounts.patch"
if [ -f "$PRIVATE_BIND_MOUNTS_PATCH" ]; then
    echo "    private-bind-mounts"
    patch --fuzz=0 -p0 < "$PRIVATE_BIND_MOUNTS_PATCH"
fi

DOCKER_BROKER_ROUTE_PATCH="$SCRIPT_DIR/upstream-docker-broker-route.patch"
if [ -f "$DOCKER_BROKER_ROUTE_PATCH" ]; then
    echo "    docker-broker-route"
    patch --fuzz=0 -p0 < "$DOCKER_BROKER_ROUTE_PATCH"
fi

DOCKER_BROKER_HIDDEN_ROUTE_PATCH="$SCRIPT_DIR/upstream-docker-broker-hidden-route.patch"
if [ -f "$DOCKER_BROKER_HIDDEN_ROUTE_PATCH" ]; then
    echo "    docker-broker-hidden-route"
    patch --fuzz=0 -p0 < "$DOCKER_BROKER_HIDDEN_ROUTE_PATCH"
fi

DOCKER_BROKER_RESOURCE_LIMITS_PATCH="$SCRIPT_DIR/upstream-docker-broker-resource-limits.patch"
if [ -f "$DOCKER_BROKER_RESOURCE_LIMITS_PATCH" ]; then
    echo "    docker-broker-resource-limits"
    patch --fuzz=0 -p0 < "$DOCKER_BROKER_RESOURCE_LIMITS_PATCH"
fi

DOCKER_BROKER_CONNECTION_PERMIT_PATCH="$SCRIPT_DIR/upstream-docker-broker-connection-permit.patch"
if [ -f "$DOCKER_BROKER_CONNECTION_PERMIT_PATCH" ]; then
    echo "    docker-broker-connection-permit"
    git apply -p0 "$DOCKER_BROKER_CONNECTION_PERMIT_PATCH"
fi

SETUP_ARTIFACT_ERRORS_PATCH="$SCRIPT_DIR/upstream-setup-artifact-errors.patch"
if [ -f "$SETUP_ARTIFACT_ERRORS_PATCH" ]; then
    echo "    setup-artifact-errors"
    patch --fuzz=0 -p0 < "$SETUP_ARTIFACT_ERRORS_PATCH"
fi

# Keep generated Rust sources canonical after all local patches have landed.
if command -v cargo >/dev/null 2>&1 && command -v rustfmt >/dev/null 2>&1; then
    cargo fmt -- \
        upstream/linux-sandbox/src/linux_run_main.rs \
        upstream/linux-sandbox/src/landlock.rs \
        upstream/linux-sandbox/src/proxy_routing.rs \
        upstream/network-proxy/src/config.rs
fi

cd -

{
    echo "$REF"
    echo "# commit: $COMMIT_SHA"
} > "$VERSION_FILE"

echo "==> Done. Synced to $REF ($COMMIT_SHA)"
