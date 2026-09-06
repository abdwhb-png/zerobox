# Zerobox Security Review Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close C1, H1-H3, M1-M3, and L1 with fail-closed broker/FUSE behavior and executable regressions.

**Architecture:** Keep the targeted Docker broker as the sole authorization and forwarding boundary, but make authorization return a rewritten request whose container segment is the frozen snapshot ID. Compile filesystem globs and the policy cwd against the same canonical namespace used by the FUSE lower root, and validate lexical plus fd-resolved paths for metadata operations. Bound broker connections and I/O with Tokio primitives owned by the broker task.

**Tech Stack:** Rust 2024, Tokio, fuser/openat2, Bun/TypeScript for the Pi sandbox policy layer.

## Global Constraints

- Preserve the existing uncommitted C1 change in `crates/zerobox/src/docker_broker.rs`.
- Use RED -> GREEN -> REFACTOR for every new production behavior.
- Do not edit `upstream/` directly, disable incremental compilation, or clean `target/`.
- Keep Pi changes limited to sandbox policy/tests and release provenance while preserving unrelated dirty files.
- Do not create a release tag until its exact target and dependency contract are verified.

---

### Task 1: HTTP framing and pinned Docker targets

**Files:**
- Modify: `crates/zerobox/src/docker_broker.rs`

**Interfaces:**
- Consumes: `TargetSnapshot.aliases`, decoded route segments, `HttpRequest::serialize`.
- Produces: `TargetedAction::Forward { request }` and exec actions carrying a request rewritten to the canonical container ID.

- [ ] Add a fake-Engine test proving LF/control-byte smuggling yields HTTP 400 and zero Engine bytes; run `cargo test -p zerobox targeted_parser_never_forwards_control_byte_smuggling -- --exact` and retain the existing implementation only if it passes.
- [ ] Add a recreation-race test that grants alias `api` to ID `A`, sends `/containers/api/...`, and asserts the Engine request line contains `/containers/A/...`, not the alias.
- [ ] Run the recreation-race test and confirm it fails because `authorize_request` currently returns `Forward` without a rewritten request.
- [ ] Add `HttpRequest::with_rewritten_target(...) -> Result<HttpRequest>` or equivalent internal request construction, preserving the API-version prefix and query string while replacing only the decoded container segment.
- [ ] Change authorization actions to carry the rewritten request and relay that request after permission checks.
- [ ] Run both focused tests and the existing targeted broker tests.

### Task 2: Unsafe namespaces and attached exec

**Files:**
- Modify: `crates/zerobox/src/docker_broker.rs`

**Interfaces:**
- Consumes: Docker inspect `HostConfig` and exec-create JSON.
- Produces: fail-closed `is_unsafe_target` and `safe_exec_create_body` decisions.

- [ ] Add table-driven tests for `NetworkMode`, `PidMode`, and `IpcMode` values of `container:<id>` and confirm they fail under the current literal-`host` check.
- [ ] Reject any case-insensitive `host` value and any `container:` value for namespace-sharing keys.
- [ ] Add a request-level test whose exec-create body contains `DetachKeys` and confirm it currently reaches the Engine.
- [ ] Reject any present non-null `DetachKeys` field in exec creation while preserving attached non-privileged exec.
- [ ] Run the focused unsafe-target and exec-body tests.

### Task 3: Broker admission, deadlines, and ownership

**Files:**
- Modify: `crates/zerobox/src/docker_broker.rs`

**Interfaces:**
- Consumes: accepted Unix streams and broker task lifetime.
- Produces: bounded concurrent handlers, request/response idle deadlines, and child-task cancellation on broker drop.

- [ ] Add a saturation test using a test-sized connection limit; assert an additional incomplete-header client receives no handler capacity until a permit is released.
- [ ] Add an idle-header test and confirm a partial request currently waits indefinitely.
- [ ] Introduce shared constants for production connection capacity and header/body/stream idle deadlines, plus an internal start helper accepting test limits.
- [ ] Acquire an owned semaphore permit before spawning each connection handler, wrap bounded request reads and relays in Tokio timeouts, and keep handlers in the broker-owned task scope so aborting the broker cancels the join set.
- [ ] Run saturation, timeout, drop-cleanup, and full/targeted relay tests.

### Task 4: Canonical dynamic-glob matching

**Files:**
- Modify: `crates/zerobox/src/dynamic_fs.rs`
- Modify: `/home/abdwhb/.pi/agent/extensions/sandbox/runtime/policies.ts`
- Test: existing Rust dynamic FUSE tests and Pi sandbox policy tests.

**Interfaces:**
- Consumes: lexical cwd, absolute/relative dynamic globs, canonical FUSE lower root.
- Produces: canonical matcher paths/mount roots while retaining the lexical Bubblewrap destination separately.

- [ ] Add Rust public-boundary tests for symlinked cwd and absolute globs with symlinked static prefixes, covering `denyRead` and `denyWrite`; confirm the current matcher misses them.
- [ ] Canonicalize the non-glob static prefix, append the glob suffix unchanged, and store a canonical cwd for policy evaluation without changing the bind destination.
- [ ] Add Pi tests showing dynamic globs are normalized against `realpath(cwd)` and absolute static prefixes are canonicalized before invoking Zerobox.
- [ ] Update `splitDenyPaths` through a filesystem-aware async normalization seam already used by policy loading; do not canonicalize nonexistent wildcard suffixes.
- [ ] Run focused Rust and Bun policy tests.

### Task 5: FUSE metadata confidentiality

**Files:**
- Modify: `crates/zerobox/src/dynamic_fs.rs`

**Interfaces:**
- Consumes: relative requested paths and descriptors opened beneath the FUSE lower root.
- Produces: checks of both lexical and fd-resolved paths before metadata or directory data is returned.

- [ ] Add tests for `readlink`, `opendir`/`readdir`, `stat`/`access` through a symlinked ancestor, and a directory swapped after lookup; confirm the denied subtree leaks under current code.
- [ ] Add helpers that open the target or parent beneath the lower fd, obtain `/proc/self/fd/<n>` resolution, and call `check_read(requested, resolved)` before replying.
- [ ] Apply the helper to lookup/getattr, readlink, opendir/readdir, and access without following the final symlink when the operation's contract requires `lstat`/`readlink` semantics.
- [ ] Run all focused dynamic FUSE tests, including existing write/mutation symlink regressions.

### Task 6: Sync, integration, and provenance

**Files:**
- Verify: Zerobox and Pi diffs, `agent/extensions/sandbox/runtime/zerobox-provenance.json`, and `agent/extensions/sandbox/dependency-contract.test.ts`.

**Interfaces:**
- Consumes: completed source fixes and immutable Git release identity.
- Produces: reproducible source/test result and a dependency-contract result; installed-service validation remains separate.

- [ ] Run `cargo fmt --check`, `cargo test -p zerobox --lib`, and the focused integration tests that exercise Docker/FUSE when the host supports them.
- [ ] Run `git diff --check` in both repositories and the focused Bun sandbox tests from `/home/abdwhb/.pi/agent`.
- [ ] Verify whether `v0.3.3-fork.9` is absent and whether `84a203615e987acb0b8876640b29a0420c1e8f5f` is the provenance commit; create only that exact local tag if both checks hold.
- [ ] Run the dependency contract and report source, runtime, FUSE/Docker host prerequisites, release build, installed binary, and post-restart gates separately.
