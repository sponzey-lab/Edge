#!/bin/sh
set -eu

[ "$#" -eq 1 ] || { echo "usage: $0 <new-output-directory>" >&2; exit 2; }
output=$1
[ ! -e "$output" ] || { echo "output directory must be new" >&2; exit 2; }

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
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
build_identity="source-tree-sha256:$(git archive --format=tar HEAD | shasum -a 256 | awk '{print $1}')"
config_sha256=$(shasum -a 256 tests/performance/config/edge-perf.toml | awk '{print $1}')
cargo run -p edge-memory-harness --bin edge-memory-evidence -- sample \
  --pid "$pid" --scenario idle --scenario-version phase011-idle-v2 \
  --build-identity "$build_identity" --config-sha256 "$config_sha256" \
  --samples 3 --interval-ms 1000 --output "$output/idle-v2.json" --digest-output "$output/idle-v2.sha256"
cargo run -p edge-memory-harness --bin edge-memory-evidence -- validate \
  --scenario idle --scenario-version phase011-idle-v2 \
  --build-identity "$build_identity" --config-sha256 "$config_sha256" \
  --report "$output/idle-v2.json" --digest "$output/idle-v2.sha256"
