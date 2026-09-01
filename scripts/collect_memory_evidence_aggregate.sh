#!/usr/bin/env sh
set -eu

case "$(uname -s)" in
  Darwin)
    platform=macos
    ;;
  Linux)
    platform=linux
    ;;
  *)
    printf '%s\n' "memory aggregate supports only macOS and Linux" >&2
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
    printf '%s\n' "memory aggregate architecture is unsupported" >&2
    exit 2
    ;;
esac

. ./scripts/source_identity.sh

input_root=${1:-artifacts/memory-evidence/task049-three-run/runs}
output_dir=${2:-artifacts/memory-evidence/task049-three-run/aggregate}
aggregate="$output_dir/phase011-steady-3run-v1.json"
digest="$output_dir/phase011-steady-3run-v1.sha256"

for path in "$input_root" "$output_dir" "$aggregate" "$digest"; do
  if [ -L "$path" ]; then
    printf '%s\n' "memory aggregate path must not be a symlink: $path" >&2
    exit 1
  fi
done
test -d "$input_root" || {
  printf '%s\n' "memory aggregate input root is missing: $input_root" >&2
  exit 1
}
mkdir -p "$output_dir"

cargo build --release -p edge-memory-harness --bin edge-memory-aggregate
build_identity=$(source_tree_build_id)

./target/release/edge-memory-aggregate collect \
  --input-root "$input_root" \
  --build-identity "$build_identity" \
  --platform "$platform" \
  --architecture "$architecture" \
  --output "$aggregate" \
  --digest-output "$digest"

./target/release/edge-memory-aggregate validate \
  --input-root "$input_root" \
  --build-identity "$build_identity" \
  --platform "$platform" \
  --architecture "$architecture" \
  --aggregate "$aggregate" \
  --digest "$digest"

./target/release/edge-memory-aggregate inspect \
  --build-identity "$build_identity" \
  --aggregate "$aggregate" \
  --digest "$digest"

if rg -ni 'authorization|cookie|private_key|client_key|passphrase|secret|"pid"|/tmp/|BEGIN CERTIFICATE|BEGIN PRIVATE' \
  "$aggregate" "$digest"; then
  printf '%s\n' "memory aggregate contains forbidden material" >&2
  exit 1
fi

printf '%s\n' "Phase 011 partial three-run memory aggregate passed"
