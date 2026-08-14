# Config Schema

## Failure-Aware Service Policy

`[services.retry]` supports `enabled` (default `false`), `max_retries` (supported
value `1`) and `max_replay_bytes` (`0..=1048576`, default `32768`). Runtime retry
still requires GET/HEAD, no body, no upstream bytes written and no response.

`[services.passive_health]` supports `enabled` (default `false`),
`failure_threshold` (`1..=10`) and `ejection_ms` (`1000..=86400000`). Each
`[[services.upstreams]]` accepts `administrative_state = "active" | "draining"`;
omission means active and a service must retain at least one active target.
Transient counters, ejection state and drain progress are never persisted.

This document describes the current MVP config surface implemented by
`edge_application::parse_mvp_config`.

The parser is intentionally small and TOML-like. It is not a full TOML parser
yet. Unknown fields are recorded and rejected by the default validator.

## Current Supported Fields

Schema v1 remains the HTTP/no-client-auth compatibility format. Schema v2 adds
typed private-trust references but does not by itself make referenced material
available to the runtime; managed trust import and runtime activation are the
next Phase 009 boundaries.

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

# Optional. Omission keeps metrics disabled.
[metrics]
enabled = true
bind = "127.0.0.1:9464"

[[listeners]]
name = "http"
bind = "0.0.0.0:8080"
protocol = "http"

[[services]]
name = "example"
load_balancer = "round_robin"

[services.health_check]
enabled = true
path = "/health"
interval_ms = 10000
timeout_ms = 2000
healthy_threshold = 2
unhealthy_threshold = 3
status_min = 200
status_max = 399

[[services.upstreams]]
name = "example-a"
url = "http://127.0.0.1:3000"

[[services.upstreams]]
name = "example-b"
url = "http://127.0.0.1:3001"

[[routes]]
name = "example"
hosts = ["localhost"]
paths = ["/"]
service = "example"
priority = 0 # Higher values win before path-prefix specificity.
certificate_ref = "cert-example"
enabled = true
redirect_http_to_https = false
```

Schema v2 TLS fields are additive:

```toml
schema_version = 2

[[listeners]]
name = "private-https"
bind = "0.0.0.0:8443"
protocol = "https"
client_auth = "required"
client_trust_bundle_ref = "private-client-root"

[[services]]
name = "private-backend"

[[services.upstreams]]
name = "private-backend-a"
url = "https://127.0.0.1:9443"
tls_server_name = "backend.private.test"
upstream_http_host = "backend.private.test"
tls_trust_bundle_ref = "private-server-root"
```

The connect address remains a literal IP. `tls_server_name` is a DNS identity
used for SNI/SAN verification, `upstream_http_host` is only the HTTP authority,
and `tls_trust_bundle_ref` selects managed Root trust. The parser never derives
one from another. HTTPS requires all three fields. HTTP rejects all three. A
required client-auth listener must be HTTPS and have a client trust ref; disabled
client auth rejects a ref. Schema v1 rejects these TLS fields and is not
automatically rewritten as v2.

## Implemented Rules

- `schema_version` is required.
- Unknown fields are rejected by default.
- Listener bind addresses must parse as socket addresses.
- Listener ids must be unique.
- Admin bind must parse as a socket address.
- Admin bind must not conflict with listener bind.
- External admin bind requires auth.
- `runtime.max_connections` defaults to `1024` and must be in `1..=4096`.
  `runtime.max_inflight_payload_bytes` is measured in bytes, defaults to
  `134217728` (128 MiB), and must be in `16777216..=536870912` (16..=512 MiB).
  The payload budget must also cover at least 80 KiB of fixed request-header
  and response-buffer reserve per allowed connection. Invalid combinations are
  rejected as `CONFIG_RESOURCE_LIMIT_INVALID` during validation, before listener
  or revision side effects. Both values are parsed once into the immutable
  config snapshot; runtime code does not re-read environment variables. A change
  to either value commits a restart-required desired revision and sends no hot
  command to the running core. The old policy remains active until process
  restart loads the repository current revision; rolling back before restart
  also sends no resource-policy hot command.
- Metrics are disabled when `[metrics]` is omitted. When enabled, `bind` must
  be a loopback socket address. Metrics enable/bind changes require restart;
  runtime environment variables cannot toggle this listener.
- Services must have at least one upstream.
- `load_balancer` currently accepts only `round_robin`.
- A single unnamed legacy upstream receives the stable id `<service-name>-primary`.
- Every upstream in a service with two or more upstreams requires an explicit,
  unique `name`. Duplicate normalized endpoints within a service are rejected.
- Upstream URLs support `http://` in schema v1/v2 and `https://` in schema v2
  with a literal IPv4 address or bracketed IPv6 address. Hostnames require the
  deferred resolver boundary. Runtime HTTPS request, health probe, and WebSocket
  traffic use the configured managed Root, SNI, and HTTP Host with no native-root
  or plaintext fallback.
- Required inbound client authentication is prepared per HTTPS listener from the
  managed `client_trust_bundle_ref`. Missing or invalid trust fails before proxy
  listeners start. Policy changes currently follow the listener restart-required
  path; route/upstream apply and certificate install preserve the active policy
  through a bind-keyed server TLS registry. Request and health client registries
  activate in the same acknowledged runtime generation. None of these values is
  injected through environment or request-time file reads.
- Upstream userinfo, query, fragment, control characters, invalid ports, and
  ambiguous unbracketed IPv6 addresses are rejected during validation.
- The optional upstream base path is normalized once and joined with the
  proxied request path by the shared typed endpoint contract.
- Metadata upstream targets are blocked.
- Health checks are disabled when `[services.health_check]` is absent or
  `enabled = false`. When enabled, `path` must be an absolute path no longer
  than 2,048 characters and must not contain a query, fragment, or control
  character.
- `interval_ms` is `1000..=86400000`; `timeout_ms` is `100..=30000` and must
  be less than `interval_ms`; both thresholds are `1..=10`; status bounds are
  ordered values in `100..=599`. Omitted enabled-policy values use `/health`,
  `10000`, `2000`, `2`, `3`, `200`, and `399` respectively.
- Routes must have at least one host and one path.
- Route ids must be unique.
- Normalized host/path pairs must be unique.
- Routes must reference an existing service.
- Route `certificate_ref` is parsed into the domain `CertificateRef` and is
  rendered back by `render_mvp_config_snapshot`.
- HTTPS redirect routes require a certificate ref or resolver in the domain
  model.
- ACME production requires explicit opt-in in validation.
- HTTP-01 certificate resolvers require an HTTP listener.
- Log mode must be one of `product`, `field-debug`, or `dev`.

## Current Runtime Limits

- The current binary runs HTTP and HTTPS listeners from one immutable loaded
  config snapshot in the unified mio runtime.
- Host/path route selection, timeout, backpressure, access logs, metrics, and
  WebSocket handling use the same pipeline for HTTP and HTTPS traffic.
- Each service dispatches new HTTP and HTTPS requests across its configured
  upstreams in deterministic round-robin order. Active health snapshots exclude
  `Unhealthy` targets from new requests; `Unknown`, `Healthy`, and health-disabled
  targets remain eligible. If every target is `Unhealthy`, the runtime returns
  `503 Service Unavailable` without attempting an upstream connection.
- The snapshot mio runtime has regression gates for backend reset to `502 Bad
  Gateway`, upstream connect timeout to `504 Gateway Timeout`, upstream read
  timeout to `504 Gateway Timeout`, and slow client header timeout to `408
  Request Timeout`.
- Chunked upstream responses are passed through without waiting for upstream
  close and have a snapshot mio runtime regression gate.
- Client backpressure pauses upstream read interest when the response buffer
  reaches the typed runtime limit and has a snapshot mio runtime regression
  gate; this limit is not exposed as MVP file schema yet.
- WebSocket tunnel handling after upstream `101 Switching Protocols` has a
  snapshot mio runtime regression gate.
- Optional passive health excludes transport-failing targets after the configured
  threshold and recovers them after the explicit ejection interval. Optional
  retry permits one replay only for safe GET/HEAD requests before any upstream
  bytes or response bytes; administrative draining excludes new selections while
  preserving generation-fenced existing references.
- HTTPS listener config and route `certificate_ref` are parsed. Startup
  preloads matching file-backed certificates into rustls server configs before
  runtime start, and local self-signed HTTPS forwarding is covered through the
  edge-proxy HTTPS adapter smoke. Multi-cert SNI selection, fragmented handshake
  progress, timeout, hot certificate install, and HTTP forwarding are handled
  by the unified mio TLS connection state machine and covered by regression gates.
- ACME resolver config is modeled in domain/application code but not fully
  exposed by the MVP file parser. External Let's Encrypt staging is deferred to
  Post-MVP work in `docs/acme-staging.md`.

## Canonical Flow

Runtime config changes must use:

```text
parse
  -> normalize
  -> validate
  -> diff
  -> plan
  -> apply
  -> commit revision
  -> audit
```

Admin Web UI must use Admin API and must not edit config files directly.
Environment variables are bootstrap-only and must not be used for runtime
policy changes.
On process startup, `data/config/current` is the authoritative pointer when the
revision repository contains any revision or pointer state. The primary config
file is a bootstrap seed only when the repository is completely empty. A valid
seed is validated, including TLS preflight, before it is imported as revision
`bootstrap-seed`; an absent seed leaves a fresh installation unconfigured. A
missing or dangling current pointer in a non-empty repository fails closed with
`CONFIG_CURRENT_REVISION_MISSING` and never falls back to the seed. Invalid
current or seed content also fails before listener startup and preserves the
repository. Internal modules receive the seed reader and repository explicitly
and do not reread environment variables.

`secrets/admin-password-hash.secret` is written atomically. On Unix, both the
temporary file and published file use owner-only mode `0600`; secret contents,
paths, and config payloads are excluded from startup logs.
