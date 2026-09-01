#!/bin/sh
set -eu

[ "$#" -eq 1 ] || { echo "usage: $0 <new-output-directory>" >&2; exit 2; }
output=$1
[ ! -e "$output" ] || { echo "output directory must be new" >&2; exit 2; }
mkdir -p "$(dirname -- "$output")"
output_parent=$(CDPATH= cd -- "$(dirname -- "$output")" && pwd)
output_name=$(basename -- "$output")

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
. ./scripts/source_identity.sh
mkdir "$output"
runtime=artifacts/performance/edge-perf-runtime
cleanup() {
  docker compose --profile performance -f docker-compose.test.yml rm -s -f edge-perf node-upstream >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM
node tests/performance/bin/prepare-pki-runtime.mjs --clean --output "$runtime" >/dev/null 2>&1 || true
node tests/performance/bin/prepare-pki-runtime.mjs --output "$runtime"
docker compose --profile performance -f docker-compose.test.yml up -d --build --wait edge-perf node-upstream
pid=$(docker inspect --format '{{.State.Pid}}' sponzey-edge-test-edge-perf-1)
[ "$pid" -gt 0 ] 2>/dev/null || { echo "Edge container PID is unavailable" >&2; exit 1; }
build_identity=$(source_tree_build_id)
config_sha256=$(shasum -a 256 tests/performance/config/edge-perf.toml | awk '{print $1}')
run_harness() {
  docker run --rm --pid=host -v "$root:/workspace" -v "$output_parent:/evidence" \
    -w /workspace rust:1.94.0-bookworm \
    cargo run -p edge-memory-harness --bin edge-memory-evidence -- "$@"
}
run_harness sample \
  --pid "$pid" --scenario idle --scenario-version phase011-idle-v2 \
  --build-identity "$build_identity" --config-sha256 "$config_sha256" \
  --samples 3 --interval-ms 1000 --output "/evidence/$output_name/idle-v2.json" \
  --digest-output "/evidence/$output_name/idle-v2.sha256"
run_harness validate \
  --scenario idle --scenario-version phase011-idle-v2 \
  --build-identity "$build_identity" --config-sha256 "$config_sha256" \
  --report "/evidence/$output_name/idle-v2.json" --digest "/evidence/$output_name/idle-v2.sha256"
