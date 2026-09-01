#!/usr/bin/env sh
set -eu
. ./scripts/test_cargo.sh

case "$(uname -s)" in
  Darwin|Linux) ;;
  *) printf '%s\n' "private HTTPS idle capacity smoke supports macOS and Linux" >&2; exit 2 ;;
esac
for command in python3 openssl curl; do
  command -v "$command" >/dev/null 2>&1 || {
    printf '%s\n' "$command is required for private HTTPS idle capacity smoke" >&2
    exit 2
  }
done

fd_limit=$(ulimit -n)
case "$fd_limit" in
  ''|*[!0-9]*) printf '%s\n' "numeric FD soft limit is required" >&2; exit 2 ;;
esac
if [ "$fd_limit" -lt 2048 ]; then
  printf '%s\n' "FD soft limit below 2048 cannot validate 512 TLS connections" >&2
  exit 2
fi

. ./scripts/source_identity.sh

output_dir=${1:-artifacts/memory-evidence/task039-current}
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/sponzey-private-https-idle.XXXXXX")
proxy_pid=
upstream_pid=
holder_pid=

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
    for file in proxy upstream holder openssl; do
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
port, expected, output = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
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
            cleanup_ok = expected != 0 or payload == 0
            if (revision and live.get("revision_id") == revision
                    and live.get("active_connections") == expected
                    and live.get("pressure") == "normal" and cleanup_ok):
                with open(output, "w", encoding="ascii") as target:
                    target.write("{} {} {} normal\n".format(revision, expected, payload))
                break
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    finally:
        if connection is not None:
            connection.close()
    time.sleep(0.1)
else:
    raise SystemExit("Admin TLS resource status did not converge: {}".format(last))
' "$1" "$2" "$3"
}

set -- $(reserve_distinct_ports 4)
https_port=$1
http_port=$2
upstream_port=$3
admin_port=$4
config_file="$tmp_dir/current.toml"
data_dir="$tmp_dir/data"
cert_dir="$data_dir/certs/tls-local"
mkdir -p "$data_dir/config" "$cert_dir" "$output_dir"
rm -rf "$output_dir/diagnostics"

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -sha256 \
  -subj '/CN=Sponzey Test Root' -keyout "$tmp_dir/root.key" -out "$tmp_dir/root.pem" \
  >"$tmp_dir/openssl.log" 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost' -keyout "$cert_dir/privkey.pem" \
  -out "$tmp_dir/leaf.csr" >>"$tmp_dir/openssl.log" 2>&1
openssl x509 -req -days 2 -sha256 -copy_extensions copy \
  -in "$tmp_dir/leaf.csr" -CA "$tmp_dir/root.pem" -CAkey "$tmp_dir/root.key" \
  -CAcreateserial -out "$cert_dir/fullchain.pem" >>"$tmp_dir/openssl.log" 2>&1
chmod 600 "$cert_dir/privkey.pem"
cat > "$cert_dir/metadata.toml" <<'EOF'
certificate_ref = "tls-local"
domains = ["localhost"]
not_after_epoch_seconds = 4102444800
source = "private-test"
EOF

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
name = "private-http"
bind = "127.0.0.1:$http_port"
protocol = "http"
[[listeners]]
name = "private-https"
bind = "127.0.0.1:$https_port"
protocol = "https"
[[services]]
name = "private-upstream"
[[services.upstreams]]
url = "http://127.0.0.1:$upstream_port"
[[routes]]
name = "private-route"
hosts = ["localhost"]
paths = ["/"]
service = "private-upstream"
certificate_ref = "tls-local"
EOF

cargo build --release -p edge-proxy -p edge-memory-harness \
  --bin edge-proxy --bin edge-tls-connection-holder --bin edge-memory-evidence
build_identity=$(source_tree_build_id)
config_sha256=$(source_identity_hash_file "$config_file" | awk '{ print $1 }')

python3 ./scripts/steady_http_upstream.py "$upstream_port" plain >"$tmp_dir/upstream.log" 2>&1 &
upstream_pid=$!
wait_port "$upstream_port" "$upstream_pid"

SPONZEY_DATA_DIR="$data_dir" SPONZEY_CONFIG_FILE="$config_file" \
SPONZEY_ADMIN_BIND="127.0.0.1:$admin_port" SPONZEY_LOG_MODE=product SPONZEY_ACME_CLIENT=fake \
  ./target/release/edge-proxy serve >"$tmp_dir/proxy.log" 2>&1 &
proxy_pid=$!
wait_port "$http_port" "$proxy_pid"

./target/release/edge-tls-connection-holder \
  --address "127.0.0.1:$https_port" \
  --connections 512 \
  --server-name localhost \
  --root-pem "$tmp_dir/root.pem" \
  --timeout-ms 5000 \
  --hold-timeout-ms 60000 \
  --ready-output "$tmp_dir/holder.ready" \
  --stop-file "$tmp_dir/holder.stop" >"$tmp_dir/holder.log" 2>&1 &
holder_pid=$!

attempts=0
while [ ! -f "$tmp_dir/holder.ready" ]; do
  kill -0 "$holder_pid" 2>/dev/null || {
    printf '%s\n' "TLS connection holder exited before ready" >&2
    exit 1
  }
  attempts=$((attempts + 1))
  test "$attempts" -le 600 || {
    printf '%s\n' "TLS connection holder did not reach 512" >&2
    exit 1
  }
  sleep 0.1
done
test "$(tr -d '\n' < "$tmp_dir/holder.ready")" = "512"
poll_status "$admin_port" 512 "$tmp_dir/held.status"

held_report="$output_dir/private-https-idle-512-v2.json"
held_digest="$output_dir/private-https-idle-512-v2.sha256"
./target/release/edge-memory-evidence sample \
  --pid "$proxy_pid" --scenario private-https-idle-512 --scenario-version phase011-v1 \
  --build-identity "$build_identity" --config-sha256 "$config_sha256" \
  --samples 3 --interval-ms 100 --output "$held_report" --digest-output "$held_digest"
./target/release/edge-memory-evidence validate \
  --scenario private-https-idle-512 --scenario-version phase011-v1 \
  --build-identity "$build_identity" --config-sha256 "$config_sha256" \
  --report "$held_report" --digest "$held_digest"

touch "$tmp_dir/holder.stop"
wait "$holder_pid"
holder_pid=
rg -qF 'TLS holder released held=512 remaining=0' "$tmp_dir/holder.log"
poll_status "$admin_port" 0 "$tmp_dir/final.status"

curl -fsS --max-time 5 --cacert "$tmp_dir/root.pem" \
  --resolve "localhost:$https_port:127.0.0.1" "https://localhost:$https_port/" \
  -o "$tmp_dir/recovery.body"
test -s "$tmp_dir/recovery.body"

python3 -c '
import json, sys
held = open(sys.argv[1], encoding="ascii").read().split()
final = open(sys.argv[2], encoding="ascii").read().split()
with open(sys.argv[3], encoding="utf-8") as source:
    report = json.load(source)
if held[1] != "512" or held[3] != "normal":
    raise SystemExit("TLS held Admin status is invalid")
if final[1:] != ["0", "0", "normal"]:
    raise SystemExit("TLS cleanup did not converge to 0/0 normal")
if held[0] != final[0]:
    raise SystemExit("TLS status revision changed during scenario")
if report["peak_rss_bytes"] > 402653184:
    raise SystemExit("private HTTPS idle RSS ceiling exceeded")
with open(sys.argv[4], "w", encoding="ascii") as target:
    target.write(
        "private HTTPS idle capacity passed held=512 held_payload={} "
        "released=512 final_connections=0 final_payload=0 final_pressure=normal "
        "recovery_status=200 peak_rss_bytes={} revision={}\n".format(
            held[2], report["peak_rss_bytes"], held[0]
        )
    )
' "$tmp_dir/held.status" "$tmp_dir/final.status" "$held_report" \
  "$output_dir/private-https-idle-summary.txt"

if rg -ni 'authorization|cookie|private_key|config_file|passphrase|secret|"pid"|/tmp/|BEGIN CERTIFICATE|BEGIN PRIVATE' \
  "$held_report" "$held_digest" "$output_dir/private-https-idle-summary.txt"; then
  printf '%s\n' "private HTTPS idle evidence contains a forbidden field" >&2
  exit 1
fi

cat "$output_dir/private-https-idle-summary.txt"
printf '%s\n' "Phase 011 private HTTPS idle capacity smoke passed"
