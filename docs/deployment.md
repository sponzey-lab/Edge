# Deployment Guide

Failure-aware policy comes from canonical config revisions. Bootstrap environment
is read once; runtime env mutation cannot change retry, passive health, drain or
log mode. Use Admin apply/rollback. Restart resets transient passive counters and
drain counts to zero while desired administrative state remains configured.

## Local operational probes and termination

The unauthenticated operational endpoints expose only a status value; they do
not return routes, revisions, upstreams, or configuration. Call them on the
loopback Admin bind only:

```text
GET /api/v1/health/live   -> 200 {"status":"live"} while the process event loop is alive
GET /api/v1/health/ready  -> 200 {"status":"ready"} only with an active listener/config/command path
                              503 {"status":"not_ready"} while starting or draining
```

The equivalent CLI requires an explicit loopback address and returns `0` for a
successful probe, `1` for a `503` not-ready result, and `2` for invalid bind,
connection, timeout, or protocol errors:

```sh
edge-proxy probe live --admin-bind 127.0.0.1:9443
edge-proxy probe ready --admin-bind 127.0.0.1:9443
```

On Unix, `SIGTERM` first changes readiness to draining and sends a bounded Core
drain command. New client connections are no longer accepted; existing work is
allowed up to 30 seconds before the runtime exits. The signal handler itself
only writes an atomic flag, and command delivery happens outside signal context.

## Support bundle

An authenticated Admin session can create a bounded diagnostic bundle with
`POST /api/v1/support-bundles`; the bundled Admin UI uses the same CSRF-protected
endpoint. The request accepts no artifact list, filesystem path, or service-control
argument. The server reads only its fixed support layout, rejects sensitive content
and unsafe paths, and writes a private tar archive at the bootstrap-selected
`data/support/latest.tar` path. The API/UI expose only archive identity, digest,
artifact summary, omissions, and size—never the archive path or source contents.

For an offline deep collection, acquire the data-directory exclusive lock first.
Missing, symlinked, stale, or bound-exceeding artifacts are omitted; secret-bearing
content fails collection before publication. This is a diagnostic artifact, not a
backup or a way to export certificates, private keys, headers, cookies, bodies, or
queries.

## Local Build

```bash
cargo build --release -p edge-proxy
```

## Local Run

```bash
SPONZEY_DATA_DIR=.sponzey \
SPONZEY_CONFIG_FILE=examples/minimal.toml \
SPONZEY_ADMIN_BIND=127.0.0.1:9443 \
SPONZEY_LOG_MODE=product \
target/release/edge-proxy
```

Environment variables are read only at bootstrap. Runtime changes must go through the Admin API/config apply path.

## Offline Encrypted Backup Create

Stop the serving process first because serve and maintenance commands require
exclusive ownership of the same data directory. Create a passphrase file owned
and readable only by the invoking user, then run:

```bash
chmod 600 /secure/path/backup.passphrase
target/release/edge-proxy backup create \
  --data-dir /var/lib/sponzey-edge \
  --output /secure/off-host/sponzey-edge.age \
  --passphrase-file /secure/path/backup.passphrase
```

The command never accepts a passphrase in argv or environment. It prints one
safe JSON receipt to stdout and Product events to stderr; neither contains
paths, passphrases, PEM, config bodies, or password verifiers. The final archive
is authenticated-encrypted and mode `0600` on Unix. Copy it and the passphrase
through separate protected channels.

Verify the copied archive before any restore work:

```bash
target/release/edge-proxy backup verify \
  --input /secure/off-host/sponzey-edge.age \
  --passphrase-file /secure/path/backup.passphrase
```

New archives use schema v3 and contain the verified audit segment set. Verification
authenticates and bounded-streams the archive, validates schema,
manifest relations, logical paths, counts, sizes, and SHA-256 digests, and emits
only a payload-free JSON report. Wrong passphrase and authenticated-stream
tampering use the same error code. Successful verification is still not
restorability evidence until a restore drill is complete.

Restore to a path that does not exist:

```bash
target/release/edge-proxy backup restore \
  --input /secure/off-host/sponzey-edge.age \
  --target-data-dir /var/lib/sponzey-edge-restored \
  --passphrase-file /secure/path/backup.passphrase
```

The command holds the target identity lock, extracts only fixed logical artifact
kinds into an owner-only sibling stage, validates repository current,
certificates, Admin verifier presence, and the audit chain, syncs the stage, and publishes it by
one rename. The target must not already exist.

After publication, restore appends one `maintenance.restore_imported` record that
links the operation ID and archive ID. If this append fails, the verified target is
already committed and is not rolled back; the command reports audit degradation.
Replace keeps its journal until provenance succeeds so recovery has an authoritative
operation identity.

For an existing offline target, add `--replace`. The command syncs an owner-only
sibling transaction journal before moving the old target to rollback. On
success it verifies the new target and removes rollback and journal state.

If interrupted, do not alter target, stage, rollback, or journal paths. Run:

```bash
target/release/edge-proxy backup restore-recover \
  --target-data-dir /var/lib/sponzey-edge \
  --operation-id OPERATION_ID
```

Startup never guesses. Recovery validates the operation-bound journal and
observed repositories, then completes commit, restores rollback, or aborts a
prepared transaction. Ambiguous state preserves all paths and returns
`RESTORE_TRANSACTION_AMBIGUOUS`.

The config file is the intended headless entrypoint. One-off listener/upstream
environment shortcuts are development smoke helpers only and must not become a
runtime policy mechanism.

## Docker Compose

Official Compose runs a published Linux image only. Set the SemVer tag and its
matching immutable GHCR manifest digest from the release manifest, then start:

```bash
sudo ./compose/install.sh \
  --image-tag vX.Y.Z \
  --image-digest RELEASE_MANIFEST_IMAGE_SHA256_WITHOUT_PREFIX
sudo docker compose --project-directory /etc/sponzey-edge/compose \
  --file /etc/sponzey-edge/compose/docker-compose.yml up -d --wait
```

The service uses Linux host networking so the Admin API remains reachable only
at host `127.0.0.1:9443`; it has a read-only root filesystem, no capabilities,
and its healthcheck runs `edge-proxy probe ready` locally. Do not expose the
Admin port through a Docker port mapping. Its named volume owns
`/var/lib/sponzey-edge`: the application state stays under `data/`, while the
exclusive data-directory lock is deliberately kept beside that directory so it
remains writable with the image root filesystem read-only.

For local source development only, use the explicit override and profile:

```bash
docker compose -f docker-compose.yml -f docker-compose.local.yml --profile local-build up --build
```

Current image packages:

- `edge-proxy` release binary
- `examples/minimal.toml`
- static Admin Web UI assets

## Certificate automation status

Manual certificates and private PKI are the supported certificate paths. Fake
ACME/HTTP-01 tests remain implementation boundaries only. Let’s Encrypt or other
external CA issuance and renewal automation are explicitly deferred and must not
be enabled, scheduled, or represented as available until separately approved and
verified.

## Data Paths

Recommended runtime layout:

```text
data/
  config/
    current
    current.toml
    revisions/
  certs/
  secrets/
  logs/
    audit/
  backups/
```

The config-file startup path injects a file-backed `CertificateStore` rooted at
`data/certs`. Certificate issue/renew writes:

```text
data/certs/{certificate_ref}/fullchain.pem
data/certs/{certificate_ref}/privkey.pem
data/certs/{certificate_ref}/metadata.toml
```

The private key file is owner-readable/writable only on Unix platforms. API
responses and logs must continue to expose only the certificate ref and masked
private key marker, never PEM material.
The rustls server config loader is adapter-tested against valid and invalid PEM.
`edge-proxy` registers HTTP and HTTPS listeners in one mio poll loop and creates
TLS byte sessions through the adapter-owned factory. Local self-signed HTTPS,
multi-cert SNI, idle handshake timeout, malformed input isolation, WebSocket,
and certificate hot install are covered by automatic smoke gates.
When a config snapshot contains an HTTPS listener, startup preloads every enabled
route `certificate_ref` from `data/certs` and fails before runtime start if a
referenced certificate is missing or invalid. Failed TLS preflight does not
import or set the current config revision.

## Current Runtime Scope And Limits

- HTTP and HTTPS data plane supports Host/path route selection from the loaded
  immutable config snapshot through one mio runtime.
- Each service uses deterministic round-robin across eligible configured
  `http://` upstreams. Active probes run through bounded workers outside mio;
  `Unhealthy` targets are skipped and an all-unhealthy pool returns `503`.
  Optional passive transport ejection, replay-safe one-shot GET/HEAD retry, and
  generation-fenced administrative drain are implemented. Weighted balancing,
  hostname resolution, and upstream keep-alive pooling remain deferred.
- The snapshot mio runtime has regression gates for upstream connect timeout
  and slow upstream response to `504 Gateway Timeout`, plus slow client header
  timeout to `408 Request Timeout`.
- Chunked upstream response pass-through without waiting for upstream close is
  covered against the snapshot mio runtime.
- Client backpressure pausing upstream read interest is covered against the
  snapshot mio runtime.
- WebSocket upgrade tunneling after upstream `101 Switching Protocols` is
  covered against the snapshot mio runtime.
- Local self-signed HTTPS forwarding and multi-cert SNI selection are covered
  through the unified mio runtime. HTTP-01/fake-ACME tests remain legacy
  implementation boundaries only; they are not an operator path, release
  evidence, or a certificate-issuance capability. External CA staging and
  renewal remain deferred until a separately approved scope reopens them.
- Runtime hot certificate install loads the target certificate through the
  file-backed certificate store outside the event loop, validates the rustls
  config at the adapter boundary, and replaces the TLS runtime snapshot only
  after the `InstallCertificate` command acknowledgement succeeds. Failed
  certificate file writes preserve the previous certificate; failed hot install
  preserves the previous TLS runtime snapshot. SNI domain conflicts are rejected
  before the core command is sent. Unified mio TLS connection-state integration
  is implemented; remaining TLS hardening items are tracked separately from the
  deferred external Let's Encrypt staging workflow in
  `docs/tls-runtime-next.md`.
- Admin API status, health, upstream-health, metrics, setup/login/logout, config
  get/validate/diff/apply/rollback, proxy host CRUD, certificate
  issue/renew/import through the selected boundary, file-backed certificate
  status, and recent log endpoints are bound over local TCP by `edge-proxy`
  during config-file startup.
- Data-plane access logs are handed from the snapshot mio runtime to the Admin
  recent access buffer through a bounded nonblocking queue. Data-plane 502/504
  errors are handed to the Admin recent error buffer through the same boundary.
  Bound Admin mutation runtime command failures are also recorded in the recent
  error buffer. Runtime log queue-full drops are counted and exposed in recent
  error feeds only in `field-debug` and `dev` modes.
- Runtime request counters, request duration values, active connection gauge,
  upstream failure counters, and active-health transition/selection/dispatch
  counters are handed through a bounded nonblocking queue to a single-writer
  registry. When `[metrics]` is enabled, exact `GET /metrics` is exposed on the
  configured loopback address; authenticated `GET /api/v1/metrics` and the
  Admin dashboard read the same immutable snapshot. Remote exposition and
  retention are not supported.
- Admin password hash is loaded once at startup from
  `data/secrets/admin-password-hash.secret` through `SecretStore`; if absent,
  Admin API enters setup-required mode and `POST /api/v1/setup` writes it.
- Config lifecycle apply/rollback has an integration smoke through
  `CoreCommandClient` and `CoreRuntime`; startup imports a valid primary config
  into the file-backed revision store before runtime listener start.
- Admin Web UI is static and is served by the Admin HTTP listener from the
  bin/adapter boundary. It calls same-origin `/api/v1/*` for real runtime state
  and enters a visible `UI smoke only` fallback only when opened without a
  reachable Admin API.

## Runtime Resource Capacity

`[runtime].max_connections`, `[runtime].max_inflight_payload_bytes`, and
`[runtime].upstream_read_timeout_ms` form one typed startup policy. The bootstrap boundary reads
configuration and environment once, validates bounds before listener or revision effects, and
passes an immutable active policy into the core. A changed resource policy is
desired-but-restart-required; Admin status must not present it as active until a successful restart
loads that revision.

The default policy is 1,024 connections and 134,217,728 bytes of managed in-flight payload. The
payload value is logical owner accounting for budgeted request, response, retry, TLS and WebSocket
buffers, not a hard process RSS or kernel socket-memory limit. New admission can fail under pressure
without terminating existing connections; writable drain, timeout and exact cleanup continue.
The upstream read timeout defaults to 30 seconds (bounded to 10ms..=120 seconds) and returns 504
when an upstream sends no response bytes in time. Set it from the canonical config only; it is not a
request-time environment override.

Capacity planning must preserve file-descriptor headroom for listeners, upstreams, Admin, logs and
test tooling. Before promoting a changed release candidate, run the source-bound full profile on
the target OS/architecture. The accepted 2026-07-20 checkpoint covered macOS arm64 and native Linux
x86_64, but any later tracked change requires fresh evidence. Do not lower scenario counts, raise
checked-in ceilings, inject allocator environment settings, or reuse a stale report to force a pass.

## Verified MVP Baseline

The completed plans are archived through `.tasks/phase007/`. A deployment
candidate is acceptable only when the following checks pass on that candidate;
archived success is historical evidence, not a waiver. The old `scripts/`
test helpers have been removed, so current verification must use Cargo,
direct `edge-proxy` execution, Docker Compose, Admin API calls, and explicit
manual evidence rather than deleted script wrappers:

- config file startup validates before listener bind
- bound Admin API HTTP server can apply and rollback revisions
- official Docker Compose installation uses the published tag+digest package path;
  the local-build override is development-only
- local HTTPS self-signed smoke passes
- private key permissions remain covered by automated tests or an explicit manual check
- product logs exclude secrets and request/response bodies
- two-upstream round-robin, health exclusion, all-unhealthy `503`, and
  authenticated operational status evidence pass
- the Post-MVP Let's Encrypt staging checklist in `docs/acme-staging.md` is used
  only when that deferred feature resumes with an approved public test domain

Before release, run `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace -- --test-threads=1`, then record the required runtime, Admin API,
Docker Compose, TLS, backup/restore, audit, and memory/resource observations for the candidate.
The three Cargo commands may run in the reusable `edge-test` container documented in
`docs/testing.md`; its named caches improve iteration speed but do not replace actual production
image startup, Admin/API, TLS, backup/restore, or platform-specific release evidence.
See `docs/current-state.md` for supported and deferred scope.

## Runtime Manual Certificate Import

Use `POST /api/v1/certificates/{id}/import`; do not edit `data/certs` while the
process runs. Environment variables remain bootstrap-only. Validation and
rustls loading occur outside mio, then bounded `InstallCertificate`
acknowledgement controls active TLS replacement. Rejection compensates the
store and preserves previous active TLS; compensation failure is
operator-visible and must be reconciled before retry.
