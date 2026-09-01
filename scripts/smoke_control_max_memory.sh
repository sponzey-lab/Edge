#!/usr/bin/env sh
set -eu

case "$(uname -s)" in Darwin|Linux) ;; *) exit 2 ;; esac
command -v python3 >/dev/null 2>&1 || exit 2
. ./scripts/source_identity.sh

output_dir=${1:-artifacts/memory-evidence/task044-current}
reused_fixture=${2:-}
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/sponzey-control-max.XXXXXX")
holder_pid=

cleanup() {
  status=$?
  test -z "$holder_pid" || kill "$holder_pid" 2>/dev/null || true
  wait "$holder_pid" 2>/dev/null || true
  if [ "$status" -ne 0 ]; then
    mkdir -p "$output_dir/diagnostics"
    test ! -f "$tmp_dir/holder.log" || cp "$tmp_dir/holder.log" "$output_dir/diagnostics/holder.log"
  fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT HUP INT TERM

wait_ready() {
  python3 -c '
import os, sys, time
path, pid = sys.argv[1], int(sys.argv[2])
deadline = time.time() + 120
while time.time() < deadline:
    try: os.kill(pid, 0)
    except OSError: raise SystemExit("control-max holder exited before readiness")
    if os.path.exists(path) and open(path, encoding="ascii").read().strip() == "100000 16384": break
    time.sleep(0.1)
else: raise SystemExit("control-max readiness timed out")
' "$1" "$2"
}

mkdir -p "$output_dir"
rm -rf "$output_dir/diagnostics"
cargo build --release -p edge-memory-harness --bin edge-control-max --bin edge-memory-evidence
build_identity=$(source_tree_build_id)

if [ -n "$reused_fixture" ]; then
  fixture_data="$reused_fixture/data"
  fixture_manifest="$reused_fixture/manifest.json"
  test -d "$fixture_data"
  test -f "$fixture_manifest"
else
  fixture_data="$tmp_dir/fixture/data"
  fixture_manifest="$tmp_dir/fixture/manifest.json"
  ./target/release/edge-control-max prepare \
    --data-dir "$fixture_data" \
    --manifest-output "$fixture_manifest" >"$tmp_dir/prepare.log" 2>&1
fi

manifest_sha256=$(source_identity_hash_file "$fixture_manifest" | awk '{ print $1 }')
cp "$fixture_manifest" "$output_dir/control-max-fixture-manifest.json"

./target/release/edge-control-max hold \
  --data-dir "$fixture_data" \
  --manifest "$fixture_manifest" \
  --ready-output "$tmp_dir/ready" \
  --stop-file "$tmp_dir/stop" \
  --summary-output "$tmp_dir/holder-summary.json" \
  --timeout-ms 120000 >"$tmp_dir/holder.log" 2>&1 &
holder_pid=$!
wait_ready "$tmp_dir/ready" "$holder_pid"

report="$output_dir/control-max-v1.json"
digest="$output_dir/control-max-v1.sha256"
./target/release/edge-memory-evidence sample \
  --pid "$holder_pid" \
  --scenario control-max \
  --scenario-version phase011-v1 \
  --build-identity "$build_identity" \
  --config-sha256 "$manifest_sha256" \
  --samples 5 \
  --interval-ms 200 \
  --output "$report" \
  --digest-output "$digest"
./target/release/edge-memory-evidence validate \
  --scenario control-max \
  --scenario-version phase011-v1 \
  --build-identity "$build_identity" \
  --config-sha256 "$manifest_sha256" \
  --report "$report" \
  --digest "$digest"

python3 -c '
import json, sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
assert report["peak_rss_bytes"] <= 536870912
' "$report"

touch "$tmp_dir/stop"
wait "$holder_pid"
holder_pid=
cp "$tmp_dir/holder-summary.json" "$output_dir/control-max-holder-summary.json"

python3 -c '
import json, sys
summary = json.load(open(sys.argv[1], encoding="utf-8"))
assert summary["schema_version"] == 1
assert summary["audit_records"] == 100000
assert summary["audit_head_sequence"] == 100000
assert summary["audit_page_records"] == 100
assert summary["metric_series"] == 16384
assert summary["cumulative_metric_series"] == 12288
assert summary["metric_rejection"] == "series_limit"
assert summary["metric_estimated_encoded_bytes"] <= 4194304
assert summary["metrics_counters"] == 500
assert summary["metrics_gauges"] == 500
assert summary["metrics_histograms"] == 0
assert summary["query_cycles"] == 3
assert summary["state"] == "completed"
' "$output_dir/control-max-holder-summary.json"

peak_rss=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["peak_rss_bytes"])' "$report")
fixture_digest=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["fixture_sha256"])' "$output_dir/control-max-holder-summary.json")
summary="$output_dir/control-max-summary.txt"
printf '%s\n' "control max passed audit_records=100000 audit_page=100 metric_series=16384 cumulative_series=12288 rejection=series_limit query_cycles=3 peak_rss_bytes=$peak_rss fixture_sha256=$fixture_digest" > "$summary"

if rg -ni 'authorization|cookie|private_key|config_file|passphrase|secret|"pid"|/tmp/' \
  "$report" "$digest" "$output_dir/control-max-fixture-manifest.json" \
  "$output_dir/control-max-holder-summary.json" "$summary"; then
  printf '%s\n' "control-max evidence contains a forbidden field" >&2
  exit 1
fi

cat "$summary"
printf '%s\n' "Phase 011 control-max memory smoke passed"
