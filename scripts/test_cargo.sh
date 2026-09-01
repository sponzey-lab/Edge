#!/usr/bin/env sh

# Test adapters use an installed Cargo when available. A Docker-only Linux host instead builds
# the same source-controlled binaries with the pinned Rust image before the host executes them.
if ! command -v cargo >/dev/null 2>&1; then
  cargo() {
    docker run --rm -v "$PWD:/workspace" -w /workspace rust:1.94.0-bookworm cargo "$@"
  }
fi
