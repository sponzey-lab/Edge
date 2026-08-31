# Sponzey Edge Proxy

[한국어](README.ko.md)

Sponzey Edge Proxy is a Rust/mio-based self-hosted reverse proxy with an optional
Admin Web UI.

## Final Goal

Build a predictable, memory-safe edge gateway that combines:

- a small Rust/mio data plane for HTTP, HTTPS, routing, health, and backpressure
- safe configuration validation, acknowledged apply, revision history, and rollback
- an optional Admin Web UI that operates only through a stable Admin API
- secure private-PKI operation, observable failures, encrypted recovery, and durable audit
- clean boundaries that allow future discovery, identity, protocol, and multi-node features

  without coupling them to the proxy hot path

Correctness, safety, operability, simplicity, and performance take priority over
feature count.

## Currently Supported Features

### Reverse Proxy And Routing

- HTTP/1.1 and HTTPS reverse proxy on a unified mio runtime
- Host, exact path, and path-prefix routing
- HTTP-to-HTTPS redirect
- `X-Forwarded-*` and hop-by-hop header handling
- chunked responses, request/response timeouts, slow-client handling, and backpressure
- WebSocket upgrade and bidirectional tunnel

### Upstreams And Availability

- single or multiple upstreams per service
- deterministic round-robin selection
- active HTTP/HTTPS health checks and passive transport-failure ejection
- administrative drain with generation fencing
- one safe retry for eligible GET/HEAD requests
- explicit `502`, `503`, `504`, and timeout behavior

### TLS And Private Trust

- rustls TLS termination and SNI certificate selection
- manual/file-backed certificates and certificate hot install for new connections
- self-signed and Root/Intermediate private-PKI validation
- strict private upstream HTTPS with managed Root trust, verified SNI, and explicit HTTP Host
- required inbound mTLS with managed client Root trust
- generation-atomic config, TLS, and health activation with rollback compensation

External Let's Encrypt staging/production issuance and operational renewal validation are
deferred to Post-MVP work. Current TLS operation uses manual or private-PKI certificates.

## Support bundle

Authenticated Admin users can create a bounded diagnostic bundle from the Admin UI or
`POST /api/v1/support-bundles` with CSRF protection. The request accepts no path or
artifact selection. It produces a fixed-path private tar archive and exposes only a
secret-free receipt (archive ID, digest, artifact summary, omissions, and size).
Private keys, secrets, headers, cookies, bodies, queries, and filesystem paths are not
included in the API/UI result. This is not a backup replacement.

### Configuration And Administration

- declarative TOML configuration
- parse, normalize, validate, diff, plan, apply, revision commit, audit flow
- safe apply and rollback that preserve the previous runtime state on failure
- optional same-origin Admin Web UI
- authenticated Admin API with setup, login/logout, CSRF protection, Proxy Host CRUD,

  configuration lifecycle, certificate/trust management, health, metrics, logs, and audit search
- headless operation without the Admin Web UI

### Operations And Recovery

- Product, Field Debug, and Development log modes
- process-wide connection and in-flight payload admission with explicit pressure/cleanup accounting
- optional loopback-only Prometheus metrics and authenticated Admin metric summary
- bounded, restart-safe, file-backed audit ledger with authenticated Admin search
- encrypted offline backup, authenticated verification, fresh restore, replace, rollback,

  and crash recovery
- backup schema v1/v2 compatibility and schema v3 trust/audit preservation
- Docker and Docker Compose packaging

The authoritative implemented and deferred scope is in
[`docs/current-state.md`](docs/current-state.md). Detailed product direction and development
evidence are in [`PROJECT.md`](PROJECT.md).

## Installation

### Build From Source

Requirements:

- a Rust toolchain with Cargo
- macOS or Linux

Build the release binary:

```bash
cargo build --release -p edge-proxy
```

The binary is created at:

```text
target/release/edge-proxy
```

### Docker Compose

Requirements:

- Docker
- Docker Compose

Official releases run a published Linux image identified by both a SemVer tag and
its immutable manifest digest. From the extracted release package, install and
start it with:

```bash
sudo ./compose/install.sh \
  --image-tag vX.Y.Z \
  --image-digest RELEASE_MANIFEST_IMAGE_SHA256_WITHOUT_PREFIX
sudo docker compose --project-directory /etc/sponzey-edge/compose \
  --env-file /etc/sponzey-edge/compose/runtime.env \
  --file /etc/sponzey-edge/compose/docker-compose.yml up -d --wait
```

For local source development only, use the explicit override:

```bash
docker compose -f docker-compose.yml -f docker-compose.local.yml --profile local-build up --build
```

See [`docs/install.md`](docs/install.md) and [`docs/deployment.md`](docs/deployment.md) for
runtime paths, permissions, backup, supported-platform boundaries, and deployment details.

### Reusable Test Container

Start the isolated test container once and reuse its Cargo dependency and target caches:

```bash
docker compose -f docker-compose.test.yml up -d --build
docker compose -f docker-compose.test.yml exec edge-test \
  bash -c 'cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace -- --test-threads=1'
```

The test container exposes no host port and does not mount runtime data or secrets. See
[`docs/testing.md`](docs/testing.md) for focused tests, lifecycle commands, and safety boundaries.

### Release Performance Test Environment

The long-lived Compose performance boundary is separate from `edge-test`: it builds the production
`edge-perf` image and sends k6 traffic through it to a deterministic Node.js upstream. Start with
the functional gate:

```bash
node tests/performance/bin/run.mjs smoke
```

Run a real profile only from a clean Git worktree; the runner rejects source changes before it
creates artifacts, prepares PKI, builds images, or changes Compose services. The runner recreates
only the performance services, generates ignored test PKI, and publishes raw
results under `artifacts/performance/<run-id>/`. It exposes only the read-only Node dashboard at
`127.0.0.1:3000`; Edge Admin has no host port and Docker socket access is never mounted into a
container. See [`docs/testing.md`](docs/testing.md#release-performance-test-environment) before
running the longer baseline, stress, or soak profiles.

## Usage

### 1. Prepare An Upstream

The sample configuration expects an HTTP service at:

```text
http://127.0.0.1:3000
```

### 2. Review The Sample Configuration

[`examples/minimal.toml`](examples/minimal.toml) listens on `0.0.0.0:8080`, matches the
`localhost` Host, and forwards requests to the upstream on port `3000`.

```toml
schema_version = 1

[admin]
bind = "127.0.0.1:9443"
enabled = true

[logging]
mode = "product"

[storage]
data_dir = ".sponzey"

[runtime]
max_connections = 1024
max_inflight_payload_bytes = 134217728
upstream_read_timeout_ms = 30000

[[listeners]]
name = "http"
bind = "0.0.0.0:8080"
protocol = "http"

[[services]]
name = "example"

[[services.upstreams]]
url = "http://127.0.0.1:3000"

[[routes]]
name = "example"
hosts = ["localhost"]
paths = ["/"]
service = "example"
```

### 3. Start The Proxy

Run from source:

```bash
SPONZEY_DATA_DIR=.sponzey \
SPONZEY_CONFIG_FILE=examples/minimal.toml \
SPONZEY_ADMIN_BIND=127.0.0.1:9443 \
SPONZEY_LOG_MODE=product \
cargo run -p edge-proxy
```

Or run the release binary:

```bash
SPONZEY_DATA_DIR=.sponzey \
SPONZEY_CONFIG_FILE=examples/minimal.toml \
SPONZEY_ADMIN_BIND=127.0.0.1:9443 \
SPONZEY_LOG_MODE=product \
target/release/edge-proxy
```

Environment variables are bootstrap-only. After startup, change runtime configuration through
the Admin Web UI or the validated Admin API config lifecycle.

### 4. Verify Proxy Routing

```bash
curl -i -H 'Host: localhost' http://127.0.0.1:8080/
```

### 5. Open The Admin Web UI

Open:

```text
http://127.0.0.1:9443/
```

On a fresh data directory, complete the initial Admin setup and log in. Use Proxy Hosts to
create or update domains, paths, upstreams, health checks, and HTTPS policy. The UI applies
changes through `/api/v1`; opening `apps/admin-web/index.html` directly does not operate the
proxy.

### 6. Apply Headless Configuration

The primary configuration file is an initial seed for an empty revision repository. After a
current revision exists, use the Admin API validate, diff, apply, and rollback endpoints rather
than editing the seed file or changing process environment variables.

Configuration fields and API examples are documented in:

- [`docs/config-schema.md`](docs/config-schema.md)
- [`docs/admin-curl.md`](docs/admin-curl.md)
- [`docs/admin-api.md`](docs/admin-api.md)
- [`docs/nginx-migration.md`](docs/nginx-migration.md)
