#!/usr/bin/env sh
set -eu

case "$(uname -s)" in Darwin|Linux) ;; *) exit 2 ;; esac
command -v python3 >/dev/null 2>&1 || exit 2
. ./scripts/source_identity.sh

output_dir=${1:-artifacts/memory-evidence/task043-current}
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/sponzey-slow-response.XXXXXX")
proxy_pid=
upstream_pid=
holder_pid=

cleanup() {
  status=$?
  test -z "$holder_pid" || kill "$holder_pid" 2>/dev/null || true
  test -z "$proxy_pid" || kill "$proxy_pid" 2>/dev/null || true
  test -z "$upstream_pid" || kill "$upstream_pid" 2>/dev/null || true
  wait "$holder_pid" 2>/dev/null || true
  wait "$proxy_pid" 2>/dev/null || true
  wait "$upstream_pid" 2>/dev/null || true
  if [ "$status" -ne 0 ]; then
    mkdir -p "$output_dir/diagnostics"
    for file in proxy upstream holder; do
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
        with socket.create_connection(("127.0.0.1", port), timeout=0.5): pass
        break
    except OSError: time.sleep(0.1)
else: raise SystemExit(component + " did not become ready")
' "$1" "$2" "$3"
}

wait_file() {
  python3 -c '
import os, sys, time
path, pid, expected = sys.argv[1], int(sys.argv[2]), sys.argv[3]
deadline = time.time() + 30
while time.time() < deadline:
    try: os.kill(pid, 0)
    except OSError: raise SystemExit("slow response driver exited before readiness")
    if os.path.exists(path) and open(path, encoding="ascii").read().strip() == expected: break
    time.sleep(0.1)
else: raise SystemExit("slow response readiness timed out")
' "$1" "$2" "$3"
}

poll_status() {
  python3 -c '
import http.client, json, sys, time
port, expected, minimum_payload, output = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
deadline = time.time() + 30
last = None
while time.time() < deadline:
    connection = None
    try:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        connection.request("GET", "/api/v1/status", headers={"Connection": "close"})
        response = connection.getresponse(); body = response.read()
        status = json.loads(body).get("live_resource_status") if response.status == 200 else None
        if status:
            last = status
            payload = int(status.get("used_payload_bytes", -1))
            if (status.get("active_connections") == expected
                    and payload >= minimum_payload
                    and status.get("pressure") == "normal"):
                with open(output, "w", encoding="ascii") as target:
                    target.write("%d %d normal\n" % (expected, payload))
                break
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    finally:
        if connection is not None: connection.close()
    time.sleep(0.1)
else: raise SystemExit("slow response status did not converge: %r" % (last,))
' "$1" "$2" "$3" "$4"
}

recovery_request() {
  python3 -c '
import http.client, sys
connection = http.client.HTTPConnection("127.0.0.1", int(sys.argv[1]), timeout=5)
connection.request("GET", "/", headers={"Host": "localhost", "Connection": "close"})
response = connection.getresponse(); body = response.read(); connection.close()
assert response.status == 200 and body == b"slow-response-ok"
' "$1"
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
  --bin edge-proxy --bin edge-slow-response --bin edge-slow-response-cycles --bin edge-memory-evidence
build_identity=$(source_tree_build_id)
config_sha256=$(source_identity_hash_file "$config_file" | awk '{ print $1 }')

python3 -c '
import socketserver, sys
PORT = int(sys.argv[1])
BODY_BYTES = 4 * 1024 * 1024
class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        request = b""
        try:
            while b"\r\n\r\n" not in request and len(request) < 8192:
                chunk = self.request.recv(1024)
                if not chunk: return
                request += chunk
            first = request.split(b"\r\n", 1)[0].split()
            slow = len(first) >= 2 and first[1] == b"/slow-response"
            size = BODY_BYTES if slow else len(b"slow-response-ok")
            self.request.sendall(("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % size).encode("ascii"))
            payload = b"x" * 16384 if slow else b"slow-response-ok"
            left = size
            while left:
                chunk = payload[:min(left, len(payload))]
                self.request.sendall(chunk)
                left -= len(chunk)
        except (BrokenPipeError, ConnectionResetError, socketserver.socket.timeout, OSError):
            pass
class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True
with Server(("127.0.0.1", PORT), Handler) as server:
    server.serve_forever()
' "$upstream_port" >"$tmp_dir/upstream.log" 2>&1 &
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

cycle=1
while [ "$cycle" -le 5 ]; do
  ready="$tmp_dir/cycle-$cycle.ready"
  stop="$tmp_dir/cycle-$cycle.stop"
  holder_log="$tmp_dir/holder.log"
  held_status="$tmp_dir/cycle-$cycle-held.status"
  final_status="$tmp_dir/cycle-$cycle-final.status"

  ./target/release/edge-slow-response \
    --address "127.0.0.1:$proxy_port" \
    --host localhost \
    --connections 128 \
    --timeout-ms 5000 \
    --hold-timeout-ms 60000 \
    --max-header-bytes 8192 \
    --receive-buffer-bytes 4096 \
    --ready-output "$ready" \
    --stop-file "$stop" >"$holder_log" 2>&1 &
  holder_pid=$!
  wait_file "$ready" "$holder_pid" 128
  poll_status "$admin_port" 128 8388608 "$held_status"

  held_report="$output_dir/slow-response-cycle-$cycle-held-v2.json"
  held_digest="$output_dir/slow-response-cycle-$cycle-held-v2.sha256"
  ./target/release/edge-memory-evidence sample \
    --pid "$proxy_pid" --scenario "slow-response-cycle-$cycle-held-128" \
    --scenario-version phase011-v1 --build-identity "$build_identity" \
    --config-sha256 "$config_sha256" --samples 3 --interval-ms 200 \
    --output "$held_report" --digest-output "$held_digest"
  ./target/release/edge-memory-evidence validate \
    --scenario "slow-response-cycle-$cycle-held-128" --scenario-version phase011-v1 \
    --build-identity "$build_identity" --config-sha256 "$config_sha256" \
    --report "$held_report" --digest "$held_digest"

  touch "$stop"
  wait "$holder_pid"
  holder_pid=
  rg -qF 'slow response released held=128 released=128 remaining=0' "$holder_log"
  poll_status "$admin_port" 0 0 "$final_status"
  recovery_request "$proxy_port"

  cooldown_report="$output_dir/slow-response-cycle-$cycle-cooldown-v2.json"
  cooldown_digest="$output_dir/slow-response-cycle-$cycle-cooldown-v2.sha256"
  ./target/release/edge-memory-evidence sample \
    --pid "$proxy_pid" --scenario "slow-response-cycle-$cycle-cooldown" \
    --scenario-version phase011-v1 --build-identity "$build_identity" \
    --config-sha256 "$config_sha256" --samples 3 --interval-ms 200 \
    --output "$cooldown_report" --digest-output "$cooldown_digest"
  ./target/release/edge-memory-evidence validate \
    --scenario "slow-response-cycle-$cycle-cooldown" --scenario-version phase011-v1 \
    --build-identity "$build_identity" --config-sha256 "$config_sha256" \
    --report "$cooldown_report" --digest "$cooldown_digest"
  cycle=$((cycle + 1))
done

python3 -c '
import json, os, sys
output_dir, tmp_dir, build, config, target = sys.argv[1:]
observations=[]
for cycle in range(1,6):
    held=json.load(open(os.path.join(output_dir,f"slow-response-cycle-{cycle}-held-v2.json")))
    cooldown=json.load(open(os.path.join(output_dir,f"slow-response-cycle-{cycle}-cooldown-v2.json")))
    status=open(os.path.join(tmp_dir,f"cycle-{cycle}-held.status"),encoding="ascii").read().split()
    final=open(os.path.join(tmp_dir,f"cycle-{cycle}-final.status"),encoding="ascii").read().split()
    assert held["identity"]["process_start_identity"] == cooldown["identity"]["process_start_identity"]
    assert status[0] == "128" and int(status[1]) >= 8388608 and status[2] == "normal"
    assert final == ["0","0","normal"]
    observations.append({"cycle_index":cycle,"build_identity":build,"config_sha256":config,
      "process_start_identity":held["identity"]["process_start_identity"],"expected":128,
      "held":128,"released":128,"failed":0,"held_payload_bytes":int(status[1]),
      "peak_rss_bytes":max(held["peak_rss_bytes"],cooldown["peak_rss_bytes"]),
      "cooldown_rss_bytes":cooldown["cooldown_rss_bytes"],"cleanup_connections":0,
      "cleanup_payload_bytes":0,"cleanup_pressure":"normal","recovery_status":200})
json.dump({"observations":observations},open(target,"w",encoding="utf-8"),separators=(",",":"))
' "$output_dir" "$tmp_dir" "$build_identity" "$config_sha256" "$tmp_dir/cycles.json"

cycle_report="$output_dir/slow-response-5cycle-v1.json"
cycle_digest="$output_dir/slow-response-5cycle-v1.sha256"
./target/release/edge-slow-response-cycles collect --input "$tmp_dir/cycles.json" \
  --output "$cycle_report" --digest-output "$cycle_digest"
./target/release/edge-slow-response-cycles validate --build-identity "$build_identity" \
  --report "$cycle_report" --digest "$cycle_digest"

if rg -ni 'authorization|cookie|private_key|config_file|passphrase|secret|"pid"|/tmp/' \
  "$output_dir"; then
  printf '%s\n' "slow response evidence contains a forbidden field" >&2
  exit 1
fi

printf '%s\n' "Phase 011 slow response five-cycle memory smoke passed"
