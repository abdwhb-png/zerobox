# Scope instructions for this repo fork

- Do not edit any files under `upstream/` directly.
- Apply repository metadata changes through standard patches in the scoped files only.
- Keep CI logic unchanged for Rust behavior; CI can be Linux-only for this fork.
- Do not publish binaries/packages from this fork.
- Prefer `./scripts/sync.sh` as the upstream sync entry point when updating sync points.
