#!/usr/bin/env sh
set -eu
. ./scripts/test_cargo.sh

case "$(uname -s)" in
  Darwin|Linux) ;;
  *) printf '%s\n' "connection capacity smoke supports macOS and Linux" >&2; exit 2 ;;
esac

command -v python3 >/dev/null 2>&1 || {
  printf '%s\n' "python3 is required for Admin status polling" >&2
  exit 2
}

fd_limit=$(ulimit -n)
case "$fd_limit" in
  ''|*[!0-9]*) printf '%s\n' "numeric FD soft limit is required" >&2; exit 2 ;;
esac
if [ "$fd_limit" -lt 4096 ]; then
  printf '%s\n' "FD soft limit below 4096 cannot validate 1024 connections" >&2
  exit 2
fi

. ./scripts/source_identity.sh

output_dir=${1:-artifacts/memory-evidence/task032-current}
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/sponzey-capacity.XXXXXX")
proxy_pid=
holder_pid=
upstream_pid=

cleanup() {
  status=$?
  test ! -n "$holder_pid" || touch "$tmp_dir/holder.stop"
  test ! -n "$holder_pid" || kill "$holder_pid" 2>/dev/null || true
  test ! -n "$proxy_pid" || kill "$proxy_pid" 2>/dev/null || true
  test ! -n "$upstream_pid" || kill "$upstream_pid" 2>/dev/null || true
  wait "$holder_pid" 2>/dev/null || true
  wait "$proxy_pid" 2>/dev/null || true
  wait "$upstream_pid" 2>/dev/null || true
  if [ "$status" -ne 0 ]; then
    mkdir -p "$output_dir/diagnostics"
    test ! -f "$config_file" || cp "$config_file" "$output_dir/diagnostics/current.toml"
    test ! -f "$tmp_dir/proxy.log" || cp "$tmp_dir/proxy.log" "$output_dir/diagnostics/proxy.log"
    test ! -f "$tmp_dir/upstream.log" || cp "$tmp_dir/upstream.log" "$output_dir/diagnostics/upstream.log"
    test ! -f "$tmp_dir/holder.log" || cp "$tmp_dir/holder.log" "$output_dir/diagnostics/holder.log"
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
port, pid = int(sys.argv[1]), int(sys.argv[2])
deadline = time.time() + 20
while time.time() < deadline:
    try:
        os.kill(pid, 0)
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            break
    except OSError:
        time.sleep(0.1)
else:
    raise SystemExit("proxy did not become ready")
' "$1" "$2"
}

poll_status() {
  python3 -c '
import http.client, json, sys, time
port, expected, output = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
deadline = time.time() + 30
last = None
while time.time() < deadline:
    connection = None
    try:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        connection.request("GET", "/api/v1/status", headers={"Host": "localhost", "Connection": "close"})
        response = connection.getresponse()
        body = response.read(65536)
        if response.status == 200:
            status = json.loads(body)
            live = status.get("live_resource_status")
            revision = status.get("active_revision_id", "")
            if live:
                last = live
                cleanup_ok = expected != 0 or live.get("used_payload_bytes") == 0
                if (revision and live.get("revision_id") == revision
                        and live.get("active_connections") == expected
                        and live.get("pressure") == "normal" and cleanup_ok):
                    with open(output, "w", encoding="ascii") as target:
                        target.write("{} {} {}\n".format(
                            revision,
                            live["active_connections"],
                            live["used_payload_bytes"],
                        ))
                    break
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    finally:
        if connection is not None:
            connection.close()
    time.sleep(0.1)
else:
    raise SystemExit(f"Admin resource status did not converge: {last}")
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
  --bin edge-proxy --bin edge-connection-holder --bin edge-memory-evidence
build_identity=$(source_tree_build_id)
config_sha256=$(source_identity_hash_file "$config_file" | awk '{ print $1 }')

python3 ./scripts/steady_http_upstream.py "$upstream_port" plain >"$tmp_dir/upstream.log" 2>&1 &
upstream_pid=$!
wait_port "$upstream_port" "$upstream_pid"

SPONZEY_DATA_DIR="$data_dir" \
SPONZEY_CONFIG_FILE="$config_file" \
SPONZEY_ADMIN_BIND="127.0.0.1:$admin_port" \
SPONZEY_LOG_MODE=product \
SPONZEY_ACME_CLIENT=fake \
  ./target/release/edge-proxy serve >"$tmp_dir/proxy.log" 2>&1 &
proxy_pid=$!
wait_port "$proxy_port" "$proxy_pid"

./target/release/edge-connection-holder \
  --address "127.0.0.1:$proxy_port" \
  --connections 1024 \
  --timeout-ms 5000 \
  --hold-timeout-ms 60000 \
  --ready-output "$tmp_dir/holder.ready" \
  --stop-file "$tmp_dir/holder.stop" >"$tmp_dir/holder.log" 2>&1 &
holder_pid=$!

deadline=0
while [ ! -f "$tmp_dir/holder.ready" ]; do
  if ! kill -0 "$holder_pid" 2>/dev/null; then
    printf '%s\n' "connection holder exited before ready" >&2
    exit 1
  fi
  deadline=$((deadline + 1))
  if [ "$deadline" -gt 600 ]; then
    printf '%s\n' "connection holder did not reach 1024" >&2
    exit 1
  fi
  sleep 0.1
done
test "$(tr -d '\n' < "$tmp_dir/holder.ready")" = "1024"
poll_status "$admin_port" 1024 "$tmp_dir/held.status"

held_report="$output_dir/held-1024-v2.json"
held_digest="$output_dir/held-1024-v2.sha256"
./target/release/edge-memory-evidence sample \
  --pid "$proxy_pid" \
  --scenario connection-capacity-held-1024 \
  --scenario-version phase011-v1 \
  --build-identity "$build_identity" \
  --config-sha256 "$config_sha256" \
  --samples 5 \
  --interval-ms 100 \
  --output "$held_report" \
  --digest-output "$held_digest"
./target/release/edge-memory-evidence validate \
  --scenario connection-capacity-held-1024 \
  --scenario-version phase011-v1 \
  --build-identity "$build_identity" \
  --config-sha256 "$config_sha256" \
  --report "$held_report" \
  --digest "$held_digest"

touch "$tmp_dir/holder.stop"
wait "$holder_pid"
holder_pid=
rg -qF 'connection holder released held=1024 remaining=0' "$tmp_dir/holder.log"
poll_status "$admin_port" 0 "$tmp_dir/released.status"

cooldown_report="$output_dir/released-cooldown-v2.json"
cooldown_digest="$output_dir/released-cooldown-v2.sha256"
./target/release/edge-memory-evidence sample \
  --pid "$proxy_pid" \
  --scenario connection-capacity-released \
  --scenario-version phase011-v1 \
  --build-identity "$build_identity" \
  --config-sha256 "$config_sha256" \
  --samples 5 \
  --interval-ms 100 \
  --output "$cooldown_report" \
  --digest-output "$cooldown_digest"
./target/release/edge-memory-evidence validate \
  --scenario connection-capacity-released \
  --scenario-version phase011-v1 \
  --build-identity "$build_identity" \
  --config-sha256 "$config_sha256" \
  --report "$cooldown_report" \
  --digest "$cooldown_digest"

python3 -c '
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    held = json.load(source)
with open(sys.argv[2], encoding="utf-8") as source:
    released = json.load(source)
held_revision, held_connections, held_payload = open(sys.argv[3], encoding="ascii").read().split()
released_revision, released_connections, released_payload = open(sys.argv[4], encoding="ascii").read().split()
if held_revision != released_revision or held_connections != "1024":
    raise SystemExit("capacity status identity/count mismatch")
if released_connections != "0" or released_payload != "0":
    raise SystemExit("capacity cleanup did not reach zero")
if held["peak_rss_bytes"] > 268435456 or released["peak_rss_bytes"] > 268435456:
    raise SystemExit("capacity smoke ceiling exceeded")
with open(sys.argv[5], "w", encoding="ascii") as target:
    target.write(
        "connection capacity passed held=1024 held_payload={} "
        "held_peak_rss_bytes={} released=0 released_payload=0 "
        "cooldown_peak_rss_bytes={} revision={}\n".format(
            held_payload,
            held["peak_rss_bytes"],
            released["peak_rss_bytes"],
            held_revision,
        )
    )
' "$held_report" "$cooldown_report" "$tmp_dir/held.status" "$tmp_dir/released.status" \
  "$output_dir/capacity-summary.txt"

if rg -ni 'authorization|cookie|private_key|config_file|passphrase|secret|"pid"|/tmp/' \
  "$held_report" "$held_digest" "$cooldown_report" "$cooldown_digest" \
  "$output_dir/capacity-summary.txt"; then
  printf '%s\n' "connection capacity evidence contains a forbidden field" >&2
  exit 1
fi

cat "$output_dir/capacity-summary.txt"
printf '%s\n' "Phase 011 connection capacity smoke passed"
