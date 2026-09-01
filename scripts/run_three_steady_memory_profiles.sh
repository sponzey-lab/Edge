#!/usr/bin/env sh
set -eu

. ./scripts/source_identity.sh

artifact_root=${1:-artifacts/memory-evidence/task049-three-run}
runs_root="$artifact_root/runs"
aggregate_dir="$artifact_root/aggregate"

for path in "$artifact_root" "$runs_root" "$aggregate_dir"; do
  if [ -L "$path" ]; then
    printf '%s\n' "three-run memory path must not be a symlink: $path" >&2
    exit 1
  fi
done
if [ -e "$artifact_root" ]; then
  printf '%s\n' "three-run memory artifact root must be new: $artifact_root" >&2
  exit 1
fi
mkdir -p "$runs_root"

initial_build_identity=$(source_tree_build_id)
run_index=1
while [ "$run_index" -le 3 ]; do
  run_name=$(printf 'run-%03d' "$run_index")
  run_root="$runs_root/$run_name"
  profile_dir="$run_root/profile"
  manifest_dir="$run_root/manifest"
  mkdir -p "$profile_dir"

  printf 'memory three-run start run=%s profile=phase011-steady-v1\n' "$run_index"
  ./scripts/smoke_http_steady_memory.sh "$profile_dir"
  ./scripts/smoke_https_steady_memory.sh "$profile_dir"
  ./scripts/smoke_mtls_steady_memory.sh "$profile_dir"
  ./scripts/collect_memory_evidence_manifest.sh "$profile_dir" "$manifest_dir"

  current_build_identity=$(source_tree_build_id)
  if [ "$current_build_identity" != "$initial_build_identity" ]; then
    printf '%s\n' "source identity changed during three-run memory profile" >&2
    exit 1
  fi
  printf 'memory three-run completed run=%s profile=phase011-steady-v1\n' "$run_index"
  run_index=$((run_index + 1))
done

./scripts/collect_memory_evidence_aggregate.sh "$runs_root" "$aggregate_dir"

final_build_identity=$(source_tree_build_id)
if [ "$final_build_identity" != "$initial_build_identity" ]; then
  printf '%s\n' "source identity changed before aggregate completion" >&2
  exit 1
fi

printf 'Phase 011 three-run steady profile passed build_identity=%s\n' "$final_build_identity"
