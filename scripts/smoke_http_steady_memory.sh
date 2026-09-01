#!/usr/bin/env sh
set -eu

case "$(uname -s)" in Darwin|Linux) ;; *) exit 2 ;; esac
command -v python3 >/dev/null 2>&1 || exit 2
. ./scripts/source_identity.sh

python_exec=$(python3 -c 'import sys; print(sys.executable)')

output_dir=${1:-artifacts/memory-evidence/task045-current}
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/sponzey-http-steady.XXXXXX")
proxy_pid=
upstream_pid=
driver_pid=
sampler_pid=
monitor_pid=

cleanup() {
  status=$?
  for pid in "$monitor_pid" "$sampler_pid" "$driver_pid" "$proxy_pid" "$upstream_pid"; do
    test -z "$pid" || kill "$pid" 2>/dev/null || true
    test -z "$pid" || wait "$pid" 2>/dev/null || true
  done
  if [ "$status" -ne 0 ]; then
    mkdir -p "$output_dir/diagnostics"
    for file in proxy upstream driver monitor sampler; do
      test ! -f "$tmp_dir/$file.log" || cp "$tmp_dir/$file.log" "$output_dir/diagnostics/$file.log"
    done
    test ! -f "$tmp_dir/driver-summary.json" || cp "$tmp_dir/driver-summary.json" "$output_dir/diagnostics/driver-summary.json"
    test ! -f "$tmp_dir/status.txt" || cp "$tmp_dir/status.txt" "$output_dir/diagnostics/status.txt"
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
import os,socket,sys,time
port,pid=int(sys.argv[1]),int(sys.argv[2]); deadline=time.time()+20
while time.time()<deadline:
    try:
        os.kill(pid,0)
        with socket.create_connection(("127.0.0.1",port),timeout=.5): pass
        break
    except OSError: time.sleep(.1)
else: raise SystemExit("process did not become ready")
' "$1" "$2"
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

cargo build --release -p edge-proxy -p edge-memory-harness --bin edge-proxy --bin edge-http-steady --bin edge-memory-evidence
build_identity=$(source_tree_build_id)
config_sha256=$(source_identity_hash_file "$config_file" | awk '{ print $1 }')

"$python_exec" ./scripts/steady_http_upstream.py "$upstream_port" plain >"$tmp_dir/upstream.log" 2>&1 &
upstream_pid=$!
wait_port "$upstream_port" "$upstream_pid"

SPONZEY_DATA_DIR="$data_dir" SPONZEY_CONFIG_FILE="$config_file" \
SPONZEY_ADMIN_BIND="127.0.0.1:$admin_port" SPONZEY_LOG_MODE=product SPONZEY_ACME_CLIENT=fake \
  ./target/release/edge-proxy serve >"$tmp_dir/proxy.log" 2>&1 &
proxy_pid=$!
wait_port "$proxy_port" "$proxy_pid"
wait_port "$admin_port" "$proxy_pid"

./target/release/edge-http-steady \
  --address "127.0.0.1:$proxy_port" --host localhost --requests 100000 --workers 100 \
  --timeout-ms 15000 --max-response-bytes 4096 --ready-output "$tmp_dir/ready" \
  --start-file "$tmp_dir/start" --summary-output "$tmp_dir/driver-summary.json" \
  --start-timeout-ms 30000 >"$tmp_dir/driver.log" 2>&1 &
driver_pid=$!
python3 -c '
import os,sys,time
path,pid=sys.argv[1],int(sys.argv[2]); deadline=time.time()+30
while time.time()<deadline:
  try: os.kill(pid,0)
  except OSError: raise SystemExit("steady driver exited before ready")
  if os.path.exists(path) and open(path).read().strip()=="100000 100": break
  time.sleep(.05)
else: raise SystemExit("steady driver readiness timed out")
' "$tmp_dir/ready" "$driver_pid"

report="$output_dir/http-steady-v1.json"
digest="$output_dir/http-steady-v1.sha256"
./target/release/edge-memory-evidence sample --pid "$proxy_pid" --scenario http-steady \
  --scenario-version phase011-v1 --build-identity "$build_identity" --config-sha256 "$config_sha256" \
  --samples 100 --interval-ms 100 --output "$report" --digest-output "$digest" \
  >"$tmp_dir/sampler.log" 2>&1 &
sampler_pid=$!

python3 -c '
import http.client,json,os,sys,time
port,pid,summary,output=int(sys.argv[1]),int(sys.argv[2]),sys.argv[3],sys.argv[4]
max_active=max_charge=0; samples=0; deadline=time.time()+600
while time.time()<deadline:
  try:
    c=http.client.HTTPConnection("127.0.0.1",port,timeout=2); c.request("GET","/api/v1/status",headers={"Connection":"close"}); r=c.getresponse(); d=json.loads(r.read()); c.close()
    live=d["live_resource_status"]
    if r.status==200 and live:
      samples+=1; max_active=max(max_active,live["active_connections"]); max_charge=max(max_charge,live["used_payload_bytes"])
      if os.path.exists(summary) and live["active_connections"]==0 and live["used_payload_bytes"]==0 and live["pressure"]=="normal":
        open(output,"w").write(f"{samples} {max_active} {max_charge} 0 0 normal\n"); break
  except OSError: pass
  time.sleep(.05)
else: raise SystemExit("steady status monitor timed out")
' "$admin_port" "$driver_pid" "$tmp_dir/driver-summary.json" "$tmp_dir/status.txt" >"$tmp_dir/monitor.log" 2>&1 &
monitor_pid=$!

touch "$tmp_dir/start"
wait "$driver_pid"; driver_pid=
wait "$sampler_pid"; sampler_pid=
wait "$monitor_pid"; monitor_pid=

./target/release/edge-memory-evidence validate --scenario http-steady --scenario-version phase011-v1 \
  --build-identity "$build_identity" --config-sha256 "$config_sha256" --report "$report" --digest "$digest"
cp "$tmp_dir/driver-summary.json" "$output_dir/http-steady-driver-summary.json"

python3 -c '
import json,sys
d=json.load(open(sys.argv[1])); r=json.load(open(sys.argv[2])); s=open(sys.argv[3]).read().split()
assert (d["expected"],d["succeeded"],d["failed"],d["workers"],d["state"])==(100000,100000,0,100,"completed")
assert r["peak_rss_bytes"]<=402653184
assert int(s[1])>0 and int(s[2])<=134217728 and s[5]=="normal"
' "$output_dir/http-steady-driver-summary.json" "$report" "$tmp_dir/status.txt"

python3 -c '
import http.client,sys
c=http.client.HTTPConnection("127.0.0.1",int(sys.argv[1]),timeout=5); c.request("GET","/",headers={"Host":"localhost","Connection":"close"}); r=c.getresponse(); b=r.read(); c.close(); assert r.status==200 and b==b"steady-ok"
' "$proxy_port"

peak=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["peak_rss_bytes"])' "$report")
set -- $(cat "$tmp_dir/status.txt")
summary="$output_dir/http-steady-summary.txt"
printf '%s\n' "HTTP steady passed expected=100000 succeeded=100000 failed=0 workers=100 samples=$1 max_active=$2 max_charge=$3 final=0/0/normal recovery=200 peak_rss_bytes=$peak" > "$summary"
if rg -ni 'authorization|cookie|private_key|config_file|passphrase|secret|"pid"|/tmp/' "$report" "$digest" "$output_dir/http-steady-driver-summary.json" "$summary"; then exit 1; fi
cat "$summary"
printf '%s\n' "Phase 011 HTTP steady memory smoke passed"
