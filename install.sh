#!/bin/sh
# Install Zerobox - Lightweight, cross-platform process sandboxing. This fork does not ship install artifacts.
#
# Run this file from a source checkout to see the supported build recipe.

set -eu

echo "Install script is disabled in this fork."
echo "This repository is Linux/WSL2 local-only and does not publish or consume install.sh binaries."
echo "From a detached source checkout, use this build flow instead:"
echo "git checkout --detach <commit>"
echo "./scripts/sync.sh"
echo "cargo build --locked --release -p zerobox"
echo 'install -Dm755 target/release/zerobox "$DEST/zerobox"'
exit 1
