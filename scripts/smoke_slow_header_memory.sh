#!/usr/bin/env sh
set -eu

case "$(uname -s)" in Darwin|Linux) ;; *) exit 2 ;; esac
command -v python3 >/dev/null 2>&1 || exit 2
. ./scripts/source_identity.sh

output_dir=${1:-artifacts/memory-evidence/task035-current}
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/sponzey-slow-header.XXXXXX")
proxy_pid=
upstream_pid=
driver_pid=

cleanup() {
  status=$?
  test ! -n "$driver_pid" || kill "$driver_pid" 2>/dev/null || true
  test ! -n "$proxy_pid" || kill "$proxy_pid" 2>/dev/null || true
  test ! -n "$upstream_pid" || kill "$upstream_pid" 2>/dev/null || true
  wait "$driver_pid" 2>/dev/null || true
  wait "$proxy_pid" 2>/dev/null || true
  wait "$upstream_pid" 2>/dev/null || true
  if [ "$status" -ne 0 ]; then
    mkdir -p "$output_dir/diagnostics"
    for file in proxy upstream driver; do
      test ! -f "$tmp_dir/$file.log" || cp "$tmp_dir/$file.log" "$output_dir/diagnostics/$file.log"
    done
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
    raise SystemExit("listener did not become ready")
' "$1" "$2"
}

poll_status() {
  python3 -c '
import http.client, json, sys, time
port, expected, require_payload, output = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
deadline = time.time() + 30
last = None
while time.time() < deadline:
    connection = None
    try:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        connection.request("GET", "/api/v1/status", headers={"Host": "localhost", "Connection": "close"})
        response = connection.getresponse()
        status = json.loads(response.read(65536)) if response.status == 200 else {}
        live = status.get("live_resource_status")
        revision = status.get("active_revision_id", "")
        if live:
            last = live
            payload = live.get("used_payload_bytes")
            payload_ok = payload > 0 if require_payload else payload == 0
            if (revision and live.get("revision_id") == revision
                    and live.get("active_connections") == expected
                    and live.get("pressure") == "normal" and payload_ok):
                with open(output, "w", encoding="ascii") as target:
                    target.write("{} {} {}\n".format(revision, expected, payload))
                break
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    finally:
        if connection is not None:
            connection.close()
    time.sleep(0.1)
else:
    raise SystemExit("Admin status did not converge: {}".format(last))
' "$1" "$2" "$3" "$4"
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
  --bin edge-proxy --bin edge-slow-header --bin edge-slow-header-cycles --bin edge-memory-evidence
build_identity=$(source_tree_build_id)
config_sha256=$(source_identity_hash_file "$config_file" | awk '{ print $1 }')

python3 ./scripts/steady_http_upstream.py "$upstream_port" plain >"$tmp_dir/upstream.log" 2>&1 &
upstream_pid=$!
wait_port "$upstream_port" "$upstream_pid"

SPONZEY_DATA_DIR="$data_dir" SPONZEY_CONFIG_FILE="$config_file" \
SPONZEY_ADMIN_BIND="127.0.0.1:$admin_port" SPONZEY_LOG_MODE=product SPONZEY_ACME_CLIENT=fake \
  ./target/release/edge-proxy serve >"$tmp_dir/proxy.log" 2>&1 &
proxy_pid=$!
wait_port "$proxy_port" "$proxy_pid"

cycle=0
while [ "$cycle" -le 5 ]; do
  if [ "$cycle" -eq 0 ]; then
    label=warmup
    artifact_dir=$tmp_dir
  else
    label="cycle-$cycle"
    artifact_dir=$output_dir
  fi
  ready="$tmp_dir/$label.ready"
  driver_log="$tmp_dir/$label-driver.log"
  held_status="$tmp_dir/$label-held.status"
  final_status="$tmp_dir/$label-final.status"
  ./target/release/edge-slow-header \
    --address "127.0.0.1:$proxy_port" \
    --connections 256 \
    --connect-timeout-ms 5000 \
    --terminal-timeout-ms 40000 \
    --max-response-bytes 4096 \
    --ready-output "$ready" >"$driver_log" 2>&1 &
  driver_pid=$!

  attempts=0
  while [ ! -f "$ready" ]; do
    kill -0 "$driver_pid" 2>/dev/null || { printf '%s\n' "slow header driver exited before ready" >&2; exit 1; }
    attempts=$((attempts + 1))
    test "$attempts" -le 600 || { printf '%s\n' "slow header driver ready timeout" >&2; exit 1; }
    sleep 0.1
  done
  test "$(tr -d '\n' < "$ready")" = "256"
  poll_status "$admin_port" 256 1 "$held_status"

  python3 -c '
import http.client, sys
connection = http.client.HTTPConnection("127.0.0.1", int(sys.argv[1]), timeout=5)
connection.request("GET", "/", headers={"Host": "localhost", "Connection": "close"})
response = connection.getresponse(); body = response.read(65536); connection.close()
assert response.status == 200 and body
' "$proxy_port"

  held_report="$artifact_dir/slow-header-$label-held-v2.json"
  held_digest="$artifact_dir/slow-header-$label-held-v2.sha256"
  ./target/release/edge-memory-evidence sample \
    --pid "$proxy_pid" --scenario "slow-header-$label-held-256" --scenario-version phase011-v1 \
    --build-identity "$build_identity" --config-sha256 "$config_sha256" \
    --samples 3 --interval-ms 100 --output "$held_report" --digest-output "$held_digest"
  ./target/release/edge-memory-evidence validate \
    --scenario "slow-header-$label-held-256" --scenario-version phase011-v1 \
    --build-identity "$build_identity" --config-sha256 "$config_sha256" \
    --report "$held_report" --digest "$held_digest"

  wait "$driver_pid"
  driver_pid=
  rg -qF 'slow header completed expected=256 succeeded=256 failed=0' "$driver_log"
  poll_status "$admin_port" 0 0 "$final_status"

  python3 -c '
import http.client, sys
connection = http.client.HTTPConnection("127.0.0.1", int(sys.argv[1]), timeout=5)
connection.request("GET", "/", headers={"Host": "localhost", "Connection": "close"})
response = connection.getresponse(); body = response.read(65536); connection.close()
assert response.status == 200 and body
' "$proxy_port"

  cooldown_report="$artifact_dir/slow-header-$label-cooldown-v2.json"
  cooldown_digest="$artifact_dir/slow-header-$label-cooldown-v2.sha256"
  ./target/release/edge-memory-evidence sample \
    --pid "$proxy_pid" --scenario "slow-header-$label-cooldown" --scenario-version phase011-v1 \
    --build-identity "$build_identity" --config-sha256 "$config_sha256" \
    --samples 3 --interval-ms 100 --output "$cooldown_report" --digest-output "$cooldown_digest"
  ./target/release/edge-memory-evidence validate \
    --scenario "slow-header-$label-cooldown" --scenario-version phase011-v1 \
    --build-identity "$build_identity" --config-sha256 "$config_sha256" \
    --report "$cooldown_report" --digest "$cooldown_digest"

  python3 -c '
import sys
held = open(sys.argv[1], encoding="ascii").read().split()
final = open(sys.argv[2], encoding="ascii").read().split()
assert held[1] == "256" and int(held[2]) >= 10496
assert final[1:] == ["0", "0"]
' "$held_status" "$final_status"
  cycle=$((cycle + 1))
done

python3 -c '
import json, os, sys
output_dir, tmp_dir, build, config, target = sys.argv[1:]
observations=[]
for cycle in range(1,6):
    label=f"cycle-{cycle}"
    held=json.load(open(os.path.join(output_dir,f"slow-header-{label}-held-v2.json")))
    cooldown=json.load(open(os.path.join(output_dir,f"slow-header-{label}-cooldown-v2.json")))
    status=open(os.path.join(tmp_dir,f"{label}-held.status"),encoding="ascii").read().split()
    final=open(os.path.join(tmp_dir,f"{label}-final.status"),encoding="ascii").read().split()
    assert held["identity"]["process_start_identity"] == cooldown["identity"]["process_start_identity"]
    assert status[1] == "256" and int(status[2]) >= 10496 and final[1:] == ["0","0"]
    observations.append({"cycle_index":cycle,"build_identity":build,"config_sha256":config,
      "process_start_identity":held["identity"]["process_start_identity"],"expected":256,
      "succeeded":256,"failed":0,"held_payload_bytes":int(status[2]),
      "peak_rss_bytes":max(held["peak_rss_bytes"],cooldown["peak_rss_bytes"]),
      "cooldown_rss_bytes":cooldown["cooldown_rss_bytes"],
      "cleanup_connections":0,"cleanup_payload_bytes":0,"cleanup_pressure":"normal","recovery_status":200})
json.dump({"observations":observations},open(target,"w",encoding="utf-8"),separators=(",",":"))
' "$output_dir" "$tmp_dir" "$build_identity" "$config_sha256" "$tmp_dir/cycles.json"

cycle_report="$output_dir/slow-header-5cycle-v1.json"
cycle_digest="$output_dir/slow-header-5cycle-v1.sha256"
./target/release/edge-slow-header-cycles collect --input "$tmp_dir/cycles.json" \
  --output "$cycle_report" --digest-output "$cycle_digest"
./target/release/edge-slow-header-cycles validate --build-identity "$build_identity" \
  --report "$cycle_report" --digest "$cycle_digest"

if rg -ni 'authorization|cookie|private_key|config_file|passphrase|secret|"pid"|/tmp/' \
  "$output_dir"; then
  exit 1
fi
printf '%s\n' "Phase 011 slow header warm-up and five-cycle memory smoke passed"
