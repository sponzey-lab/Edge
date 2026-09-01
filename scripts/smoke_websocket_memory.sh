#!/usr/bin/env sh
set -eu

case "$(uname -s)" in Darwin|Linux) ;; *) exit 2 ;; esac
command -v python3 >/dev/null 2>&1 || exit 2
fd_limit=$(ulimit -n)
case "$fd_limit" in
  ''|*[!0-9]*) exit 2 ;;
esac
test "$fd_limit" -ge 1024 || exit 2
. ./scripts/source_identity.sh

output_dir=${1:-artifacts/memory-evidence/task041-current}
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/sponzey-websocket-memory.XXXXXX")
proxy_pid=
upstream_pid=
driver_pid=

cleanup() {
  status=$?
  test ! -n "$driver_pid" || touch "$tmp_dir/driver.stop"
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
port, pid, component = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
deadline = time.time() + 20
while time.time() < deadline:
    try:
        os.kill(pid, 0)
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            break
    except OSError:
        time.sleep(0.1)
else:
    raise SystemExit("{} listener did not become ready".format(component))
' "$1" "$2" "$3"
}

poll_status() {
  python3 -c '
import http.client, json, sys, time
port, expected, minimum, output = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
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
            payload = live.get("used_payload_bytes", -1)
            if (revision and live.get("revision_id") == revision
                    and live.get("active_connections") == expected
                    and payload >= minimum and live.get("pressure") == "normal"):
                open(output, "w", encoding="ascii").write(
                    "{} {} {} normal\n".format(revision, expected, payload)
                )
                break
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    finally:
        if connection is not None:
            connection.close()
    time.sleep(0.1)
else:
    raise SystemExit("WebSocket Admin status did not converge: {}".format(last))
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

cat > "$tmp_dir/websocket_upstream.py" <<'PY'
import socket
import sys
import threading

FLOOD_FRAME = bytes([0x82, 125]) + (b"x" * 125)
FLOOD = FLOOD_FRAME * ((2 * 1024 * 1024) // len(FLOOD_FRAME) + 1)
SWITCHING = (
    b"HTTP/1.1 101 Switching Protocols\r\n"
    b"Connection: Upgrade\r\n"
    b"Upgrade: websocket\r\n"
    b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
)

def receive_exact(connection, count):
    result = bytearray()
    while len(result) < count:
        chunk = connection.recv(count - len(result))
        if not chunk:
            raise OSError("peer closed")
        result.extend(chunk)
    return bytes(result)

def handle(connection):
    try:
        connection.settimeout(60)
        header = bytearray()
        while not header.endswith(b"\r\n\r\n") and len(header) < 8192:
            header.extend(receive_exact(connection, 1))
        if b"Upgrade: websocket\r\n" not in header:
            body = b"websocket-memory-ok"
            connection.sendall(
                b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "
                + str(len(body)).encode("ascii") + b"\r\n\r\n" + body
            )
            return
        connection.sendall(SWITCHING)
        first = receive_exact(connection, 2)
        length = first[1] & 0x7f
        if first[1] & 0x80 == 0 or length > 125:
            return
        mask = receive_exact(connection, 4)
        encoded = receive_exact(connection, length)
        payload = bytes(value ^ mask[index % 4] for index, value in enumerate(encoded))
        connection.sendall(bytes([0x82, length]) + payload)
        connection.sendall(FLOOD)
        while connection.recv(4096):
            pass
    except OSError:
        pass
    finally:
        connection.close()

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", int(sys.argv[1])))
server.listen(256)
while True:
    client, _ = server.accept()
    threading.Thread(target=handle, args=(client,), daemon=True).start()
PY

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
  --bin edge-proxy --bin edge-websocket-driver --bin edge-websocket-cycles --bin edge-memory-evidence
build_identity=$(source_tree_build_id)
config_sha256=$(source_identity_hash_file "$config_file" | awk '{ print $1 }')

python3 "$tmp_dir/websocket_upstream.py" "$upstream_port" >"$tmp_dir/upstream.log" 2>&1 &
upstream_pid=$!
wait_port "$upstream_port" "$upstream_pid" upstream

SPONZEY_DATA_DIR="$data_dir" SPONZEY_CONFIG_FILE="$config_file" \
SPONZEY_ADMIN_BIND="127.0.0.1:$admin_port" SPONZEY_LOG_MODE=product SPONZEY_ACME_CLIENT=fake \
  ./target/release/edge-proxy serve >"$tmp_dir/proxy.log" 2>&1 &
proxy_pid=$!
wait_port "$proxy_port" "$proxy_pid" proxy

recovery_request() {
  python3 -c '
import http.client, sys
connection = http.client.HTTPConnection("127.0.0.1", int(sys.argv[1]), timeout=5)
connection.request("GET", "/", headers={"Host": "localhost", "Connection": "close"})
response = connection.getresponse()
body = response.read(65536)
connection.close()
if response.status != 200 or body != b"websocket-memory-ok":
    raise SystemExit("HTTP recovery failed")
' "$1"
}

cycle=0
while [ "$cycle" -le 5 ]; do
  rm -f "$tmp_dir/driver.ready" "$tmp_dir/driver.stop"
  held_status="$tmp_dir/cycle-$cycle-held.status"
  final_status="$tmp_dir/cycle-$cycle-final.status"
  recovery_status="$tmp_dir/cycle-$cycle-recovery.status"

  ./target/release/edge-websocket-driver \
    --address "127.0.0.1:$proxy_port" --connections 128 --timeout-ms 5000 \
    --hold-timeout-ms 60000 --max-header-bytes 4096 \
    --ready-output "$tmp_dir/driver.ready" --stop-file "$tmp_dir/driver.stop" \
    >"$tmp_dir/driver.log" 2>&1 &
  driver_pid=$!

  attempts=0
  while [ ! -f "$tmp_dir/driver.ready" ]; do
    kill -0 "$driver_pid" 2>/dev/null || exit 1
    attempts=$((attempts + 1))
    test "$attempts" -le 600 || exit 1
    sleep 0.1
  done
  test "$(tr -d '\n' < "$tmp_dir/driver.ready")" = "128"
  poll_status "$admin_port" 128 8388608 "$held_status"

  held_report="$output_dir/websocket-cycle-$cycle-held-v2.json"
  held_digest="$output_dir/websocket-cycle-$cycle-held-v2.sha256"
  ./target/release/edge-memory-evidence sample \
    --pid "$proxy_pid" --scenario "websocket-cycle-$cycle-held-128" \
    --scenario-version phase011-v1 --build-identity "$build_identity" \
    --config-sha256 "$config_sha256" --samples 3 --interval-ms 100 \
    --output "$held_report" --digest-output "$held_digest"
  ./target/release/edge-memory-evidence validate \
    --scenario "websocket-cycle-$cycle-held-128" --scenario-version phase011-v1 \
    --build-identity "$build_identity" --config-sha256 "$config_sha256" \
    --report "$held_report" --digest "$held_digest"

  touch "$tmp_dir/driver.stop"
  wait "$driver_pid"
  driver_pid=
  rg -qF 'WebSocket driver released held=128 remaining=0' "$tmp_dir/driver.log"
  poll_status "$admin_port" 0 0 "$final_status"
  recovery_request "$proxy_port"
  poll_status "$admin_port" 0 0 "$recovery_status"

  cooldown_report="$output_dir/websocket-cycle-$cycle-cooldown-v2.json"
  cooldown_digest="$output_dir/websocket-cycle-$cycle-cooldown-v2.sha256"
  ./target/release/edge-memory-evidence sample \
    --pid "$proxy_pid" --scenario "websocket-cycle-$cycle-cooldown" \
    --scenario-version phase011-v1 --build-identity "$build_identity" \
    --config-sha256 "$config_sha256" --samples 3 --interval-ms 100 \
    --output "$cooldown_report" --digest-output "$cooldown_digest"
  ./target/release/edge-memory-evidence validate \
    --scenario "websocket-cycle-$cycle-cooldown" --scenario-version phase011-v1 \
    --build-identity "$build_identity" --config-sha256 "$config_sha256" \
    --report "$cooldown_report" --digest "$cooldown_digest"
  cycle=$((cycle + 1))
done

python3 -c '
import json, os, sys
output_dir, tmp_dir, build, config, target = sys.argv[1:]
observations=[]
for cycle in range(1,6):
    held=json.load(open(os.path.join(output_dir,f"websocket-cycle-{cycle}-held-v2.json")))
    cooldown=json.load(open(os.path.join(output_dir,f"websocket-cycle-{cycle}-cooldown-v2.json")))
    status=open(os.path.join(tmp_dir,f"cycle-{cycle}-held.status"),encoding="ascii").read().split()
    final=open(os.path.join(tmp_dir,f"cycle-{cycle}-final.status"),encoding="ascii").read().split()
    recovery=open(os.path.join(tmp_dir,f"cycle-{cycle}-recovery.status"),encoding="ascii").read().split()
    assert held["identity"]["process_start_identity"] == cooldown["identity"]["process_start_identity"]
    assert status[1] == "128" and int(status[2]) >= 8388608 and status[3] == "normal"
    assert final[1:] == ["0","0","normal"] and recovery[1:] == ["0","0","normal"]
    assert status[0] == final[0] == recovery[0]
    observations.append({"cycle_index":cycle,"build_identity":build,"config_sha256":config,
      "process_start_identity":held["identity"]["process_start_identity"],"expected":128,
      "upgraded":128,"echoed":128,"held":128,"released":128,"failed":0,
      "held_payload_bytes":int(status[2]),
      "peak_rss_bytes":max(held["peak_rss_bytes"],cooldown["peak_rss_bytes"]),
      "cooldown_rss_bytes":cooldown["cooldown_rss_bytes"],"cleanup_connections":0,
      "cleanup_payload_bytes":0,"cleanup_pressure":"normal","recovery_status":200})
json.dump({"observations":observations},open(target,"w",encoding="utf-8"),separators=(",",":"))
' "$output_dir" "$tmp_dir" "$build_identity" "$config_sha256" "$tmp_dir/cycles.json"

cycle_report="$output_dir/websocket-5cycle-v1.json"
cycle_digest="$output_dir/websocket-5cycle-v1.sha256"
./target/release/edge-websocket-cycles collect --input "$tmp_dir/cycles.json" \
  --output "$cycle_report" --digest-output "$cycle_digest"
./target/release/edge-websocket-cycles validate --build-identity "$build_identity" \
  --report "$cycle_report" --digest "$cycle_digest"

if rg -ni 'authorization|cookie|private_key|config_file|passphrase|secret|"pid"|/tmp/' \
  "$output_dir"; then
  exit 1
fi
printf '%s\n' "Phase 011 WebSocket five-cycle memory smoke passed"
