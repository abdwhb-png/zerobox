# Scope instructions for this repo fork

- Do not edit any files under `upstream/` directly.
- Apply repository metadata changes through standard patches in the scoped files only.
- Keep CI logic unchanged for Rust behavior; CI can be Linux-only for this fork.
- Do not publish binaries/packages from this fork.
- Prefer `./scripts/sync.sh` as the upstream sync entry point when updating sync points.

## TDD build cache and disk budget

This workspace's generated `target/` artifacts have exceeded 17 GiB on a
space-constrained WSL host. Preserve fast TDD feedback without letting debug
artifacts grow unchecked:

- Keep the root `Cargo.toml` development profile at `debug = 1` and
  `incremental = true`. Tests inherit this profile. Limited debug information
  saves disk space while incremental compilation preserves reuse; do not
  disable assertions or overflow checks to save space.
- Reuse the existing target directory and keep the toolchain, feature set and
  profile consistent across agents working on the same task. Avoid ad hoc
  `RUSTFLAGS`, `CARGO_PROFILE_*`, `CARGO_INCREMENTAL` or target-directory
  overrides unless the task requires them. Profile changes trigger rebuilds
  and do not remove old artifacts automatically.
- During RED/GREEN cycles, run the smallest relevant test, for example
  `cargo test -p zerobox <test_filter>`, and verify that it actually ran tests.
  Broaden to the relevant package/workspace suites before handoff; filtering
  during TDD does not replace the required regression checks.
- Do not run `cargo clean` or delete `target/` between TDD cycles. If space is
  tight, measure `du -sh target` and `df -h .`, then propose scoped cleanup
  rather than repeatedly rebuilding from scratch. Obtain user approval before
  deleting build artifacts and ensure no build/test is using them.
- Before an approved full cleanup, preserve any required release executable
  outside `target/` and verify that its consumer uses that installed copy.
  Running the installed binary does not need the build cache; cleaning
  `target/` also removes any executable still located there.
