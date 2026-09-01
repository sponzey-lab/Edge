#!/usr/bin/env sh
set -eu
. ./scripts/test_cargo.sh

case "$(uname -s)" in
  Darwin)
    platform=macos
    ;;
  Linux)
    platform=linux
    ;;
  *)
    printf '%s\n' "memory manifest supports only macOS and Linux" >&2
    exit 2
    ;;
esac

case "$(uname -m)" in
  arm64|aarch64)
    architecture=aarch64
    ;;
  x86_64|amd64)
    architecture=x86_64
    ;;
  *)
    printf '%s\n' "memory manifest architecture is unsupported" >&2
    exit 2
    ;;
esac

. ./scripts/source_identity.sh

input_dir=${1:-artifacts/memory-evidence/task048-profile}
output_dir=${2:-artifacts/memory-evidence/task048-current}
manifest="$output_dir/phase011-steady-manifest-v1.json"
digest="$output_dir/phase011-steady-manifest-v1.sha256"

for path in "$input_dir" "$output_dir" "$manifest" "$digest"; do
  if [ -L "$path" ]; then
    printf '%s\n' "memory manifest path must not be a symlink: $path" >&2
    exit 1
  fi
done
test -d "$input_dir" || {
  printf '%s\n' "memory manifest input directory is missing: $input_dir" >&2
  exit 1
}
mkdir -p "$output_dir"

cargo build --release -p edge-memory-harness --bin edge-memory-manifest
build_identity=$(source_tree_build_id)

./target/release/edge-memory-manifest collect \
  --input-dir "$input_dir" \
  --build-identity "$build_identity" \
  --platform "$platform" \
  --architecture "$architecture" \
  --repetitions 1 \
  --status partial \
  --output "$manifest" \
  --digest-output "$digest"

./target/release/edge-memory-manifest validate \
  --input-dir "$input_dir" \
  --build-identity "$build_identity" \
  --platform "$platform" \
  --architecture "$architecture" \
  --repetitions 1 \
  --status partial \
  --manifest "$manifest" \
  --digest "$digest"

if rg -ni 'authorization|cookie|private_key|client_key|passphrase|secret|"pid"|/tmp/|BEGIN CERTIFICATE|BEGIN PRIVATE' \
  "$manifest" "$digest"; then
  printf '%s\n' "memory manifest contains forbidden material" >&2
  exit 1
fi

printf '%s\n' "Phase 011 partial memory manifest passed"
