#!/usr/bin/env sh
set -eu
. ./scripts/test_cargo.sh

case "$(uname -s)" in Darwin|Linux) ;; *) exit 2 ;; esac
for command in python3 openssl curl; do command -v "$command" >/dev/null 2>&1 || exit 2; done
. ./scripts/source_identity.sh

python_exec=$(python3 -c 'import sys; print(sys.executable)')

output_dir=${1:-artifacts/memory-evidence/task047-current}
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/sponzey-mtls-steady.XXXXXX")
proxy_pid=
upstream_pid=
driver_pid=
sampler_pid=
monitor_pid=

cleanup() {
  exit_code=$?
  for pid in "$monitor_pid" "$sampler_pid" "$driver_pid" "$proxy_pid" "$upstream_pid"; do
    test -z "$pid" || kill "$pid" 2>/dev/null || true
    test -z "$pid" || wait "$pid" 2>/dev/null || true
  done
  if [ "$exit_code" -ne 0 ]; then
    mkdir -p "$output_dir/diagnostics"
    for file in proxy upstream driver monitor sampler openssl; do
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

set -- $(reserve_distinct_ports 4)
https_port=$1
http_port=$2
upstream_port=$3
admin_port=$4
config_file="$tmp_dir/current.toml"
data_dir="$tmp_dir/data"
cert_dir="$data_dir/certs/tls-steady"
trust_dir="$data_dir/trust-bundles/client-root"
mkdir -p "$data_dir/config" "$cert_dir" "$trust_dir" "$output_dir"
rm -rf "$output_dir/diagnostics"

make_root() {
  name=$1
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -sha256 -subj "/CN=$name" \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout "$tmp_dir/$name.key" -out "$tmp_dir/$name.pem" >>"$tmp_dir/openssl.log" 2>&1
}
sign_leaf() {
  name=$1 common_name=$2 root=$3 extensions=$4
  openssl req -newkey rsa:2048 -nodes -sha256 -subj "/CN=$common_name" \
    -keyout "$tmp_dir/$name.key" -out "$tmp_dir/$name.csr" >>"$tmp_dir/openssl.log" 2>&1
  printf '%s\n' "$extensions" >"$tmp_dir/$name.ext"
  openssl x509 -req -days 2 -sha256 -extfile "$tmp_dir/$name.ext" \
    -in "$tmp_dir/$name.csr" -CA "$tmp_dir/$root.pem" -CAkey "$tmp_dir/$root.key" \
    -CAcreateserial -out "$tmp_dir/$name.pem" >>"$tmp_dir/openssl.log" 2>&1
}
: >"$tmp_dir/openssl.log"
make_root server-root
make_root client-root
make_root wrong-client-root
sign_leaf server-leaf localhost server-root 'basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost'
sign_leaf client-leaf trusted-client client-root 'basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth'
sign_leaf wrong-client-leaf wrong-client wrong-client-root 'basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth'
cp "$tmp_dir/server-leaf.pem" "$cert_dir/fullchain.pem"
cp "$tmp_dir/server-leaf.key" "$cert_dir/privkey.pem"
cat > "$cert_dir/metadata.toml" <<'EOF'
certificate_ref = "tls-steady"
domains = ["localhost"]
not_after_epoch_seconds = 4102444800
source = "private-test"
EOF
cp "$tmp_dir/client-root.pem" "$trust_dir/roots.pem"
trust_sha256=$(source_identity_hash_file "$trust_dir/roots.pem" | awk '{ print $1 }')
cat > "$trust_dir/metadata.toml" <<EOF
trust_bundle_ref = "client-root"
certificate_count = 1
imported_at_epoch_seconds = 1
content_sha256 = "$trust_sha256"
EOF
cat "$tmp_dir/client-leaf.pem" "$tmp_dir/client-root.pem" >"$tmp_dir/client-chain.pem"
cat "$tmp_dir/wrong-client-leaf.pem" "$tmp_dir/wrong-client-root.pem" >"$tmp_dir/wrong-chain.pem"
chmod 600 "$cert_dir/privkey.pem" "$trust_dir/roots.pem" "$trust_dir/metadata.toml" \
  "$tmp_dir/client-leaf.key" "$tmp_dir/wrong-client-leaf.key"

cat > "$config_file" <<EOF
schema_version = 2
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
name = "steady-http-bootstrap"
bind = "127.0.0.1:$http_port"
protocol = "http"
[[listeners]]
name = "steady-mtls"
bind = "127.0.0.1:$https_port"
protocol = "https"
client_auth = "required"
client_trust_bundle_ref = "client-root"
[[services]]
name = "steady-upstream"
[[services.upstreams]]
url = "http://127.0.0.1:$upstream_port"
[[routes]]
name = "steady-route"
hosts = ["localhost"]
paths = ["/"]
service = "steady-upstream"
certificate_ref = "tls-steady"
EOF

cargo build --release -p edge-proxy -p edge-memory-harness \
  --bin edge-proxy --bin edge-mtls-steady --bin edge-memory-evidence
build_identity=$(source_tree_build_id)
config_sha256=$(source_identity_hash_file "$config_file" | awk '{ print $1 }')

"$python_exec" ./scripts/steady_http_upstream.py "$upstream_port" counted >"$tmp_dir/upstream.log" 2>&1 &
upstream_pid=$!
wait_port "$upstream_port" "$upstream_pid"

SPONZEY_DATA_DIR="$data_dir" SPONZEY_CONFIG_FILE="$config_file" \
SPONZEY_ADMIN_BIND="127.0.0.1:$admin_port" SPONZEY_LOG_MODE=product SPONZEY_ACME_CLIENT=fake \
  ./target/release/edge-proxy serve >"$tmp_dir/proxy.log" 2>&1 &
proxy_pid=$!
wait_port "$http_port" "$proxy_pid"
wait_port "$admin_port" "$proxy_pid"

./target/release/edge-mtls-steady \
  --address "127.0.0.1:$https_port" --host localhost --server-name localhost \
  --root-pem "$tmp_dir/server-root.pem" --client-chain-pem "$tmp_dir/client-chain.pem" \
  --client-key-pem "$tmp_dir/client-leaf.key" --requests 25000 --workers 64 \
  --timeout-ms 30000 --max-response-bytes 4096 --ready-output "$tmp_dir/ready" \
  --start-file "$tmp_dir/start" --summary-output "$tmp_dir/driver-summary.json" \
  --start-timeout-ms 30000 >"$tmp_dir/driver.log" 2>&1 &
driver_pid=$!
python3 -c '
import os,sys,time
path,pid=sys.argv[1],int(sys.argv[2]); deadline=time.time()+30
while time.time()<deadline:
  try: os.kill(pid,0)
  except OSError: raise SystemExit("mTLS steady driver exited before ready")
  if os.path.exists(path) and open(path).read().strip()=="25000 64": break
  time.sleep(.05)
else: raise SystemExit("mTLS steady driver readiness timed out")
' "$tmp_dir/ready" "$driver_pid"

report="$output_dir/mtls-steady-v1.json"
digest="$output_dir/mtls-steady-v1.sha256"
./target/release/edge-memory-evidence sample --pid "$proxy_pid" --scenario mtls-steady \
  --scenario-version phase011-v1 --build-identity "$build_identity" --config-sha256 "$config_sha256" \
  --samples 100 --interval-ms 100 --output "$report" --digest-output "$digest" \
  >"$tmp_dir/sampler.log" 2>&1 &
sampler_pid=$!

python3 -c '
import http.client,json,os,sys,time
port,summary,output=int(sys.argv[1]),sys.argv[2],sys.argv[3]
max_active=max_charge=0; samples=0; deadline=time.time()+1200
while time.time()<deadline:
  try:
    c=http.client.HTTPConnection("127.0.0.1",port,timeout=2); c.request("GET","/api/v1/status",headers={"Connection":"close"}); r=c.getresponse(); d=json.loads(r.read()); c.close()
    live=d["live_resource_status"]
    if r.status==200 and live:
      samples+=1; max_active=max(max_active,live["active_connections"]); max_charge=max(max_charge,live["used_payload_bytes"])
      if os.path.exists(summary) and live["active_connections"]==0 and live["used_payload_bytes"]==0 and live["pressure"]=="normal":
        open(output,"w").write(f"{samples} {max_active} {max_charge} 0 0 normal\n"); break
  except (OSError,ValueError,KeyError): pass
  time.sleep(.05)
else: raise SystemExit("mTLS steady status monitor timed out")
' "$admin_port" "$tmp_dir/driver-summary.json" "$tmp_dir/status.txt" >"$tmp_dir/monitor.log" 2>&1 &
monitor_pid=$!

touch "$tmp_dir/start"
wait "$driver_pid"; driver_pid=
wait "$sampler_pid"; sampler_pid=
wait "$monitor_pid"; monitor_pid=

./target/release/edge-memory-evidence validate --scenario mtls-steady --scenario-version phase011-v1 \
  --build-identity "$build_identity" --config-sha256 "$config_sha256" --report "$report" --digest "$digest"
cp "$tmp_dir/driver-summary.json" "$output_dir/mtls-steady-driver-summary.json"

trusted_forwarded=$(python3 -c '
import http.client,sys
c=http.client.HTTPConnection("127.0.0.1",int(sys.argv[1]),timeout=5); c.request("GET","/__count",headers={"Connection":"close"}); r=c.getresponse(); print(r.read().decode()); c.close(); assert r.status==200
' "$upstream_port")
test "$trusted_forwarded" -eq 25000

rejected_negatives=0
if curl -fsS --max-time 5 --cacert "$tmp_dir/server-root.pem" --resolve "localhost:$https_port:127.0.0.1" \
  "https://localhost:$https_port/" -o /dev/null 2>/dev/null; then exit 1; else rejected_negatives=$((rejected_negatives + 1)); fi
if curl -fsS --max-time 5 --cacert "$tmp_dir/server-root.pem" --cert "$tmp_dir/wrong-chain.pem" \
  --key "$tmp_dir/wrong-client-leaf.key" --resolve "localhost:$https_port:127.0.0.1" \
  "https://localhost:$https_port/" -o /dev/null 2>/dev/null; then exit 1; else rejected_negatives=$((rejected_negatives + 1)); fi
test "$rejected_negatives" -eq 2
after_negatives=$(python3 -c '
import http.client,sys
c=http.client.HTTPConnection("127.0.0.1",int(sys.argv[1]),timeout=5); c.request("GET","/__count",headers={"Connection":"close"}); r=c.getresponse(); print(r.read().decode()); c.close(); assert r.status==200
' "$upstream_port")
test "$after_negatives" -eq 25000

curl -fsS --max-time 10 --cacert "$tmp_dir/server-root.pem" --cert "$tmp_dir/client-chain.pem" \
  --key "$tmp_dir/client-leaf.key" \
  --resolve "localhost:$https_port:127.0.0.1" "https://localhost:$https_port/" \
  -o "$tmp_dir/recovery.body"
test "$(cat "$tmp_dir/recovery.body")" = "steady-ok"

python3 -c '
import json,sys
d=json.load(open(sys.argv[1])); r=json.load(open(sys.argv[2])); s=open(sys.argv[3]).read().split()
assert (d["expected"],d["succeeded"],d["failed"],d["workers"],d["state"])==(25000,25000,0,64,"completed")
assert r["peak_rss_bytes"]<=402653184
assert int(s[1])>0 and int(s[2])<=134217728 and s[5]=="normal"
' "$output_dir/mtls-steady-driver-summary.json" "$report" "$tmp_dir/status.txt"

peak=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["peak_rss_bytes"])' "$report")
set -- $(cat "$tmp_dir/status.txt")
summary="$output_dir/mtls-steady-summary.txt"
printf '%s\n' "mTLS steady passed expected=25000 succeeded=25000 failed=0 workers=64 rejected_negatives=2 forwarded=25000 samples=$1 max_active=$2 max_charge=$3 final=0/0/normal recovery=200 peak_rss_bytes=$peak" > "$summary"
if rg -ni 'authorization|cookie|private_key|client_key|root.pem|config_file|passphrase|secret|"pid"|/tmp/|BEGIN CERTIFICATE|BEGIN PRIVATE' \
  "$report" "$digest" "$output_dir/mtls-steady-driver-summary.json" "$summary"; then exit 1; fi
cat "$summary"
printf '%s\n' "Phase 011 mTLS steady memory smoke passed"
