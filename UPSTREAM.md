# Zerobox fork provenance

This fork is derived from Zerobox `0.3.3` and the Codex rust shim baseline.

- Zerobox upstream commit: `9a7affd6c68fb2541c7c709559c40e08ba0a1872`
- Codex rust shim commit: `9b8cf56cdefb09f54564ccc295fd42f6647f558f` (`rust-v0.131.0-alpha.22`)

## Local workflow

- Fork scope: Linux/WSL2 only.
- Rebase/update path:
  - Run `./scripts/sync.sh` for upstream sync points used by this repository.
  - Validate workspace metadata changes only; do not edit generated `upstream/` artifacts directly.

## Build-only policy

- No package publication (npm / PyPI / Cargo) from this fork.
- Source builds are the supported distribution model for local use.
