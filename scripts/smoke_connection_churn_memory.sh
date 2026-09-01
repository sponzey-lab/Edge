#!/usr/bin/env sh
set -eu
. ./scripts/test_cargo.sh

case "$(uname -s)" in
  Darwin|Linux) ;;
  *) printf '%s\n' "connection churn supports macOS and Linux" >&2; exit 2 ;;
esac

command -v python3 >/dev/null 2>&1 || {
  printf '%s\n' "python3 is required for the loopback upstream" >&2
  exit 2
}

. ./scripts/source_identity.sh

output_dir=${1:-artifacts/memory-evidence/task042-current}
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/sponzey-connection-churn.XXXXXX")
proxy_pid=
upstream_pid=

cleanup() {
  status=$?
  if [ -n "$proxy_pid" ]; then kill "$proxy_pid" 2>/dev/null || true; fi
  if [ -n "$upstream_pid" ]; then kill "$upstream_pid" 2>/dev/null || true; fi
  wait "$proxy_pid" 2>/dev/null || true
  wait "$upstream_pid" 2>/dev/null || true
  if [ "$status" -ne 0 ]; then
    mkdir -p "$output_dir/diagnostics"
    test ! -f "$tmp_dir/proxy.log" || cp "$tmp_dir/proxy.log" "$output_dir/diagnostics/proxy.log"
    test ! -f "$tmp_dir/upstream.log" || cp "$tmp_dir/upstream.log" "$output_dir/diagnostics/upstream.log"
  fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT HUP INT TERM

reserve_distinct_ports() {
  python3 -c '
import socket
sockets = []
try:
    for _ in range(int(__import__("sys").argv[1])):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sockets.append(sock)
    print(" ".join(str(sock.getsockname()[1]) for sock in sockets))
finally:
    for sock in sockets:
        sock.close()
' "$1"
}

wait_port() {
  python3 -c '
import os, socket, sys, time
port = int(sys.argv[1])
pid = int(sys.argv[2])
component = sys.argv[3]
deadline = time.time() + 20
while time.time() < deadline:
    try:
        os.kill(pid, 0)
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            break
    except OSError:
        time.sleep(0.1)
else:
    raise SystemExit(component + " did not become ready")
' "$1" "$2" "$3"
}

set -- $(reserve_distinct_ports 3)
proxy_port=$1
upstream_port=$2
admin_port=$3
config_file="$tmp_dir/current.toml"
data_dir="$tmp_dir/data"
mkdir -p "$data_dir/config" "$output_dir"
rm -rf "$output_dir/diagnostics"

cat > "$config_file" <<EOF
schema_version = 1

[admin]
bind = "127.0.0.1:$admin_port"
enabled = true

[logging]
mode = "product"

[storage]
data_dir = "$data_dir"

[runtime]
max_connections = 1024
max_inflight_payload_bytes = 134217728

[[listeners]]
name = "steady-http"
bind = "127.0.0.1:$proxy_port"
protocol = "http"

[[services]]
name = "steady-upstream"

[[services.upstreams]]
url = "http://127.0.0.1:$upstream_port"

[[routes]]
name = "steady-route"
hosts = ["localhost"]
paths = ["/"]
service = "steady-upstream"
EOF

cargo build --release -p edge-proxy -p edge-memory-harness \
  --bin edge-proxy --bin edge-connection-churn
build_identity=$(source_tree_build_id)
config_sha256=$(source_identity_hash_file "$config_file" | awk '{ print $1 }')

python3 ./scripts/steady_http_upstream.py "$upstream_port" plain >"$tmp_dir/upstream.log" 2>&1 &
upstream_pid=$!
wait_port "$upstream_port" "$upstream_pid" upstream

SPONZEY_DATA_DIR="$data_dir" \
SPONZEY_CONFIG_FILE="$config_file" \
SPONZEY_ADMIN_BIND="127.0.0.1:$admin_port" \
SPONZEY_LOG_MODE=product \
SPONZEY_ACME_CLIENT=fake \
  ./target/release/edge-proxy serve >"$tmp_dir/proxy.log" 2>&1 &
proxy_pid=$!
wait_port "$proxy_port" "$proxy_pid" proxy
wait_port "$admin_port" "$proxy_pid" admin

report="$output_dir/connection-churn-50k-v1.json"
digest="$output_dir/connection-churn-50k-v1.sha256"
summary="$output_dir/connection-churn-summary.txt"
validation="$output_dir/connection-churn-validation.txt"

./target/release/edge-connection-churn run \
  --pid "$proxy_pid" \
  --proxy-address "127.0.0.1:$proxy_port" \
  --admin-address "127.0.0.1:$admin_port" \
  --host localhost \
  --cycles 5 \
  --requests-per-cycle 10000 \
  --timeout-ms 5000 \
  --max-response-bytes 65536 \
  --expected-revision bootstrap-seed \
  --ceiling-bytes 402653184 \
  --cooldown-interval-ms 1000 \
  --scenario connection-churn-50k \
  --scenario-version phase011-v1 \
  --build-identity "$build_identity" \
  --config-sha256 "$config_sha256" \
  --output "$report" \
  --digest-output "$digest" > "$summary"

./target/release/edge-connection-churn validate \
  --scenario connection-churn-50k \
  --scenario-version phase011-v1 \
  --build-identity "$build_identity" \
  --config-sha256 "$config_sha256" \
  --report "$report" \
  --digest "$digest" > "$validation"

rg -qF 'cycles=5 expected=50000 succeeded=50000 failed=0' "$summary"
rg -qF 'validated cycles=5 expected=50000' "$validation"
test "$(rg -cF '"active_connections": 0' "$report")" -eq 5
test "$(rg -cF '"used_payload_bytes": 0' "$report")" -eq 5
test "$(rg -cF '"pressure": "normal"' "$report")" -eq 5
rg -qF '"outcome": "passed"' "$report"

python3 -c '
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    report = json.load(source)
assert len(report["cycles"]) == 5
assert [item["cycle"] for item in report["cycles"]] == [1, 2, 3, 4, 5]
assert all(item["requests"] == {"expected": 10000, "succeeded": 10000, "failed": 0} for item in report["cycles"])
assert report["requests"] == {"expected": 50000, "succeeded": 50000, "failed": 0}
assert report["rss"]["observed_peak_bytes"] <= report["policy"]["absolute_ceiling_bytes"]
assert report["rss"]["last_cooldown_median_bytes"] <= report["rss"]["first_cooldown_median_bytes"] + report["rss"]["plateau_tolerance_bytes"]
' "$report"

stale_build_identity="source-tree-sha256:$(printf '%064d' 0)"
if ./target/release/edge-connection-churn validate \
  --scenario connection-churn-50k \
  --scenario-version phase011-v1 \
  --build-identity "$stale_build_identity" \
  --config-sha256 "$config_sha256" \
  --report "$report" \
  --digest "$digest" >/dev/null 2>&1; then
  printf '%s\n' "stale churn identity unexpectedly passed" >&2
  exit 1
fi

python3 -c '
import hashlib, json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    report = json.load(source)
report["unknown"] = True
encoded = (json.dumps(report, indent=2, separators=(",", ": ")) + "\n").encode("utf-8")
with open(sys.argv[2], "wb") as target:
    target.write(encoded)
with open(sys.argv[3], "w", encoding="ascii") as target:
    target.write(hashlib.sha256(encoded).hexdigest() + "\n")
' "$report" "$tmp_dir/unknown.json" "$tmp_dir/unknown.sha256"
if ./target/release/edge-connection-churn validate \
  --scenario connection-churn-50k \
  --scenario-version phase011-v1 \
  --build-identity "$build_identity" \
  --config-sha256 "$config_sha256" \
  --report "$tmp_dir/unknown.json" \
  --digest "$tmp_dir/unknown.sha256" >/dev/null 2>&1; then
  printf '%s\n' "unknown churn evidence field unexpectedly passed" >&2
  exit 1
fi

if rg -ni 'authorization|cookie|private_key|config_file|passphrase|secret|"pid"|/tmp/' \
  "$report" "$digest" "$summary" "$validation"; then
  printf '%s\n' "connection churn evidence contains a forbidden field" >&2
  exit 1
fi

python3 -c '
import socket, sys
port = int(sys.argv[1])
request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
with socket.create_connection(("127.0.0.1", port), timeout=5) as stream:
    stream.sendall(request)
    response = b""
    while True:
        chunk = stream.recv(4096)
        if not chunk: break
        response += chunk
status = response.split(b"\r\n", 1)[0].split()
assert len(status) >= 2 and status[0] in (b"HTTP/1.0", b"HTTP/1.1") and status[1] == b"200", response[:128]
' "$proxy_port"

cat "$summary"
cat "$validation"
printf '%s\n' "Phase 011 connection churn memory smoke passed"
