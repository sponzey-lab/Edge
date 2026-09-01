#!/usr/bin/env sh

# Test adapters use an installed Cargo when available. A Docker-only Linux host instead builds
# the same source-controlled binaries with the pinned Rust image before the host executes them.
if ! command -v cargo >/dev/null 2>&1; then
  cargo() {
    docker run --rm \
      -v sponzey-edge-test-cargo-registry:/usr/local/cargo/registry \
      -v sponzey-edge-test-cargo-git:/usr/local/cargo/git \
      -v "$PWD:/workspace" \
      -w /workspace \
      rust:1.94.0-bookworm cargo "$@"
  }
fi

# The fixed Linux evidence host is intentionally Docker-only. Preserve every adapter's
# secret-evidence check when ripgrep is absent; all current adapter calls use grep-compatible
# flags (-n, -i, -q, -c, and -F). Recursive traversal preserves `rg`'s directory behavior, so a
# missing search binary can never turn a failed scan green.
if ! command -v rg >/dev/null 2>&1; then
  rg() {
    grep -r "$@"
  }
fi
