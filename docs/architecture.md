# Architecture

## Failure-Aware Boundary

The mio data plane emits typed terminal observations through a bounded
nonblocking port. Application reducers own retry/passive/effective policy and
drain accounting. Core publishes immutable operational snapshots through a port;
Admin reads the port and never locks connection tables. Config replacement and
generation fencing isolate stale observations and leases.

Sponzey Edge Proxy follows Layered Architecture and Clean Architecture.

## Layers

```text
bin/apps
  -> adapters
  -> ports
  -> application
  -> domain
```

## Crates

- `edge-domain`: pure domain model and policy. No network, filesystem, TLS, API, UI, runtime, or environment access.
- `edge-ports`: traits for external systems and runtime boundaries, including config revisions, audit, logs, metrics, certificates, secrets, clocks, ACME, and CoreCommand delivery.
- `edge-application`: use cases and orchestration through ports.
- `edge-adapters`: concrete external-system adapters.
- `edge-core`: mio-based data plane and command boundary.
- `edge-admin-api`: Admin API adapter.
- `apps/edge-proxy`: process bootstrap, environment read-once boundary, dependency wiring.
- `apps/admin-web`: optional Admin Web UI, implemented as an Admin API client.

## Performance Test Boundary

`tests/performance/` is a test-tool boundary, not a workspace member or a
production dependency. Its traffic path is `k6 load-generator -> edge-perf
release image -> deterministic node-upstream`; k6 is given only the Edge
endpoint. The host-side runner owns Docker CLI resource sampling, generated
test PKI, raw ignored artifacts, summary/audit, and profile orchestration.
Neither the production Core nor the containers receive a Docker socket, and
Admin remains loopback-only inside the shared Edge network. Performance
evidence is supplemental characterization and does not enter the data-plane
dependency graph or replace the Phase 011 release/memory boundary.

## Runtime Boundary

Runtime resource status crosses the data-plane/control-plane boundary through
`RuntimeResourceStatusPublisher` and `RuntimeResourceStatusReader`. The mio event loop
builds an immutable, revision-scoped aggregate after startup and meaningful ledger,
connection, pressure, or active-revision changes. Its publisher uses a nonblocking
latest-only handoff; Admin reads the mirrored snapshot and never receives a reference
to the connection table or payload ledger. Publication failure is observability loss,
not a reason to roll back authoritative runtime state.

The Core data plane is based on `mio`. Admin API and Admin Web UI must not
mutate Core internals directly. Runtime changes go through validated application
use cases and the `CoreCommandClient` port. Config lifecycle smoke tests cover
apply success, runtime command rejection without current revision mutation, and
rollback through a real `CoreRuntime` command handler. Admin API contract helpers
call `ConfigLifecycle::apply_with_core` and `rollback_with_core` so revision
commit, audit, and command acknowledgement use the same application boundary.
The Admin API TCP listener lives in the `edge-proxy` bin boundary and reuses the
socket-free `edge-admin-api` HTTP contract. Bundled Admin Web UI assets are
served by that same bin/adapter boundary and call same-origin `/api/v1/*`; they
are not part of the core hot path. Admin API code must not import
`ConnectionTable`, listener registry, TLS runtime state, or other Core internals.

Core connection lifecycle is modeled with explicit states and events. Route
selection has its own `SelectingRoute` state, and each state exposes the
client/upstream read/write interest that the mio runtime must register.
Incremental request reads use a socket-free buffer model before they are wired
to the runtime. Upstream write progress, client write progress, response
streaming buffers, and timeout decisions are also modeled without socket I/O.
The config-file startup path now uses the snapshot mio runtime for HTTP request
forwarding. The snapshot mio runtime has deadline regression gates that map
stalled upstream connects to `504 Gateway Timeout`, slow upstream responses to
`504 Gateway Timeout`, and slow client headers to `408 Request Timeout`. It also
passes chunked upstream responses through from HTTP chunk framing without
waiting for upstream close and pauses upstream read interest when client
backpressure fills the response buffer. HTTP and HTTPS share this runtime,
including TLS handshake, close-notify, access/metric queues, and WebSocket
`101 Switching Protocols` tunnel handling. No blocking HTTPS helper remains.

WebSocket tunnel ownership is directional: pending client-to-upstream and
upstream-to-client bytes are charged independently and released together with the connection.
Each direction advances its connection-owned `WriteBuffer` through
`advance_and_clear_if_complete`: a partial write preserves only the unsent tail, while a complete
write resets the logical length to zero and reuses capacity. Consumed history is therefore not
retained for the lifetime of a long-lived tunnel, and no unbudgeted staging copy is introduced.
Once a tunnel becomes terminal, `close_after_write` stops further interest registration. A
terminal WebSocket is therefore removed by cleanup even when client output is still pending;
waiting for a buffer that can no longer drain would leak both the connection and its payload
charge. Ordinary HTTP response connections retain their existing drain-before-cleanup rule.

Connection-churn measurement remains outside the product graph. The test-tool application creates
a fresh bounded HTTP driver per cycle, then reads only the public Admin status after load. A cycle
cannot advance until active connections and logical payload are zero and pressure is normal. OS
RSS sampling, process identity checks and canonical report publication stay in harness adapters;
the event loop does not sample RSS or write evidence files.

During an ordinary HTTP response, a client request-side half-close is not a response terminal: the
client may still be waiting to read the response. The event loop therefore preserves read-closed
connections but treats mio `write_closed` or socket error as proof that response output cannot
drain. That terminal drops the upstream and removes the connection so all pending response charge
is released. This distinction is event metadata, not a boolean inferred from an empty request read.

## Durable Audit Boundary

Typed record and operation/admission/reconciliation states live in `edge-domain`.
`edge-application` orchestrates intent-before-effect mutation, startup verification,
reconciliation and bounded query through `edge-ports`. Canonical framing, SHA-256
chain verification, owner-only segment I/O and restore provenance are
`edge-adapters` responsibilities. `edge-proxy` opens one process-wide verified
`SharedFileAuditLedger` after the data-directory lock and injects it into Admin
composition; `edge-core` has no audit or filesystem dependency.

Admin handlers never read segment files. `GET /api/v1/audit` calls the reader port
and returns a safe metadata projection. Persistent mutation is admitted only in
`Healthy`; degraded audit keeps the data plane and authenticated read-only status,
query and verification available while rejecting new persistent control-plane effects.

Control-max measurement remains outside the product composition. The memory harness directly
constructs production `FileAuditLedger` and `MetricRegistry` adapters, but accesses resident data
through `AuditLedgerReader`, immutable `MetricSnapshot`, and the production Admin handler
contracts. Fixture preparation is a separate process phase so durable append and filesystem cache
cost are not confused with the held resident RSS sample. No fixture command, hidden endpoint,
environment switch or sampler dependency enters `edge-proxy`, application, domain or mio core.

HTTP steady measurement also remains a test-tool composition. A typed 100-worker driver reuses the
bounded HTTP codec, while process RSS and Admin status are observed by separate adapters after an
explicit ready/start barrier. Workers know only proxy address, Host and immutable request bounds;
they cannot inspect runtime connection tables. Exact aggregate counters and public final resource
status are combined only in release evidence, never fed back into routing policy.

HTTPS steady measurement remains a test-tool composition. The driver reads one private Root at its
filesystem boundary before readiness, builds one immutable rustls client config, and shares it with
bounded workers. TLS sockets, certificate fixtures, process RSS and Admin observations remain
outside domain/application/core. The driver reuses only the crate-private bounded HTTP response
validator; no product endpoint, runtime environment switch or connection-table hook is added.

mTLS steady measurement remains a test-tool composition. The adapter reads server Root, complete
client-auth chain and private key once before readiness, constructs one immutable rustls client
config, and injects it into the shared HTTPS steady driver. Quotient/remainder distribution is
checked independently of TLS. Client material, filesystem/process sampling and Admin observation
remain outside product domain/application/core and are forbidden from evidence.

## Phase 004 TLS Runtime ADR

Status: implemented and verified locally. Phase 004 replaced the Phase 003
compatibility bridge with a unified mio HTTP/HTTPS data plane:

```text
apps/edge-proxy
  -> reads env once
  -> loads config/certificate material outside the event loop
  -> builds immutable config and TLS runtime snapshots
  -> wires edge-core runtime with edge-ports TLS session factory

edge-core
  -> owns mio listeners, accepted sockets, tokens, readiness, deadlines
  -> owns plaintext/ciphertext buffers and connection capacity
  -> drives TLS progress through an edge-ports byte-oriented session port
  -> reuses the existing HTTP route/proxy pipeline after TLS establishment

edge-ports
  -> exposes TLS session factory/session traits without rustls, mio, socket,
     filesystem, PEM, or private key types

edge-adapters
  -> owns rustls ServerConfig/ServerConnection, X.509/PEM parsing, SNI
     certificate selection, and TLS runtime snapshot construction
  -> does not poll sockets, bind listeners, or spawn per-connection threads
```

The selected TLS session port capability is byte oriented rather than socket
oriented. Core will pass encrypted bytes read from mio sockets into the session,
pull decrypted plaintext for the existing HTTP pipeline, pass plaintext response
bytes back into the session, and drain pending encrypted bytes to the client
socket. The port exposes progress as a mutually exclusive state such as
`Handshaking`, `Established`, `PeerClosed`, or `Failed`, plus read/write interest
hints and normalized SNI once available. It must not expose rustls concrete
types or certificate private material.

Snapshot ownership for Phase 004 is event-loop-owned after preparation:

1. Bootstrap or a worker loads files and builds candidate immutable snapshots
   outside the mio event loop.
2. The event loop receives a bounded command/event containing prepared runtime
   payloads, not file paths or PEM bytes.
3. The event loop validates compatibility, swaps the active pointer in one
   short operation, and acknowledges only after activation succeeds.
4. Failed preparation or activation keeps the previous config and TLS snapshots.
5. Accepted connections keep the immutable config/TLS snapshot captured at
   accept time; only later connections see the new snapshot.

Current architecture fitness invariants:

- production HTTPS must not contain a connection-per-thread listener path
- `edge-core` must not import rustls
- `edge-domain`, `edge-application`, and `edge-ports` must not import mio or
  rustls
- event-loop modules must not read certificate files, parse PEM/X.509, call
  ACME, or read environment variables
- Admin API and Admin Web UI must not directly mutate listener registry, TLS
  snapshot, config files, or core connection state
- production request/TLS handling must not use unstructured `println!` or
  `eprintln!`

Let's Encrypt external staging/production evidence is not a Phase 004 blocker.
Fake ACME and existing HTTP-01 regression coverage remain part of the safety
net, while public-domain ACME validation stays deferred.

## Environment Boundary

Environment variables are read only in `apps/edge-proxy/src/bootstrap.rs`. Lower layers receive typed arguments.

## Phase 008 Startup Config Authority

Startup config selection is an application use case, not a filesystem policy in
the binary. `ResolveStartupConfigUseCase` receives `ConfigRevisionRepository`,
`BootstrapConfigSeed`, and `StartupConfigPreflight` ports explicitly. The file
adapters own revision-pointer reads, seed-file reads, and certificate I/O.

The state machine resolves repository current first. A completely empty
repository may import one validated bootstrap seed; an absent seed reaches the
explicit `Unconfigured` terminal state. Any revision or pointer state makes the
repository authoritative. A missing or dangling current pointer then fails
closed and cannot trigger a seed read or mtime-based recovery. TLS preflight
completes before a seed revision is committed, so failed startup cannot publish
partial config state.

Product startup logging contains only the selected origin and revision ID.
Config bodies, source paths, certificate material, and secrets are not logged.
The file secret adapter applies owner-only permissions before atomic rename and
verifies the final Unix mode through adapter tests.

## Phase 008 Process And Ownership Boundary

`apps/edge-proxy` parses process arguments once into `ProcessMode`. No arguments
and explicit `serve` preserve the existing serve path. Backup create, verify,
restore, and restore-recover have immutable typed option structures; until their
use cases are implemented they return `PROCESS_COMMAND_NOT_IMPLEMENTED` before
reading serve environment or wiring listeners.

Serve creates the minimum data layout and then acquires an exclusive
`DataDirectoryLockGuard` before config, Admin, metrics, or mio listener startup.
The guard is held by the outer serve scope. Domain owns only the lock state
machine, ports own manager/guard traits, and the file adapter owns target
canonicalization and `fs4`. The lock file is a non-policy coordination artifact
in the canonical target parent, so a future restore rename cannot move the held
lock. Ownership is determined only by the held OS lock, never file existence.

## Phase 008 Backup Domain Contract

`edge-domain::backup` defines schema v1/v2 logical artifact kinds, descriptors,
manifest relations, immutable resource limits, redacted sensitive strings, and
backup/restore reducers. It does not import filesystem, archive, cipher, clock,
logger, or runtime APIs. Logical `/` paths are public schema identities and are
validated independently from physical store paths.

Manifest validation requires exactly one current pointer and its referenced
revision, complete certificate chain/key/metadata triples, exact Admin verifier
presence, owner-only secret modes, unique paths/identities, checked byte sums,
and strict schema v1 compatibility. State reducers make authentication,
artifact verification, config/certificate/secret validation, runtime preflight,
transaction persistence, publish verification, rollback, and cleanup order
explicit. Invalid and post-terminal events leave state unchanged.

## Phase 008 Encrypted Backup Creation Boundary

`CreateBackupUseCase` owns the offline create sequence through explicit ports:
exclusive data-directory lock, allowlisted inventory, manifest validation and
digest, encrypted record writes, authenticated finalize, file sync, and atomic
publish. It receives limits, sensitive passphrase, clock, ID generator, and log
sink explicitly and does not import filesystem or crypto implementations.

`FileBackupArtifactSource` maps only repository revisions/current,
certificate triples, and the optional Admin verifier to logical schema paths.
It rejects unknown managed files, symlinks, malformed identities, and source
identity changes. `AgeBackupArchiveWriter` creates only an owner-only encrypted
temporary file, writes a bounded canonical binary stream, finalizes
authentication, syncs, and atomically renames it. No plaintext archive or
staging tree exists.

`edge-proxy backup create` reads the passphrase once from an owner-only regular
file opened with no-follow semantics, wires adapters, emits a safe JSON receipt,
and never starts proxy/Admin listeners. `VerifyBackupUseCase` reads through a
`BackupArchiveReader` port and compares manifest/record digest relations before
returning a payload-free report. The adapter bounded-streams age plaintext,
rejects unsafe paths/trailing data, and never creates a target directory.
New-target restore is now implemented through `RestoreArchiveExtractor`,
`RestorePreflight`, and `RestorePublisher` ports. Application orchestration uses
`RestoreStateMachine`; the domain has an explicit new-target commit transition
that bypasses the replace-only transaction journal. The file adapter maps each
logical artifact kind to one fixed physical path under an owner-only sibling
stage, validates the staged repository/certificates/secrets, syncs directories,
and performs one target rename.

Existing-target replace persists an owner-only transaction through a
`RestoreTransactionStore` port and uses `RestoreReplacePublisher` for
identity-checked renames, rollback, and cleanup. Application updates
`Prepared`, `TargetMoved`, and `StagePublished` after durable boundaries and
drives rollback/recovery reducer transitions. Explicit recovery combines the
journal enum with validated target/rollback presence; ambiguous combinations
preserve every path and fail closed.

## Phase 007 Metrics Boundary

Production metrics preserve the same inward dependency direction:

```text
edge-core / health runtime / bin startup
  -> MetricPublisher port (bounded, nonblocking)
  -> adapter channel
  -> single-writer application registry
  -> immutable MetricSnapshot
       -> loopback Prometheus adapter
       -> MetricSnapshotReaderPort -> authenticated Admin API -> Admin Web UI
```

The typed descriptor contract lives in `edge-ports`; aggregation limits,
generation reconciliation, and snapshot models live in `edge-application`.
Channel, collector thread, Prometheus text encoding, and loopback socket serving
live in `edge-adapters`. Process startup and dependency wiring live in
`apps/edge-proxy`. Core never imports an encoder, registry lock, HTTP exporter,
or Admin type. Admin handlers read immutable snapshots through a port and cannot
mutate collector state.

Metrics config is part of the canonical config snapshot. It is disabled when
omitted, accepts only loopback bind addresses, and requires restart when the
listener setting changes. No request path or internal module rereads process
environment to alter metrics behavior.

## Phase 006 Failure-Aware Routing ADR

The accepted design for passive transport observations, replay-safe single retry, upstream administrative drain,
state ownership, resource bounds, and TDD insertion order is documented in
`docs/failure-aware-routing.md`. Phase 006 keeps these policies in domain/application contracts and uses the
existing unified mio runtime only as the outer execution adapter.

## Fitness Checks

`scripts/check_architecture.sh` enforces the current minimum boundary rules:

- domain does not import adapter/runtime/framework APIs
- application does not use concrete file/network/framework APIs
- env access stays at the edge-proxy bootstrap boundary
- core/domain/application do not depend on Admin Web UI
- Admin API does not access Core runtime internals
- Admin Web UI does not write config files directly
- metric HTTP/socket/encoder implementations remain outside domain, application,
  and core hot-path policy
- post-bootstrap crates do not access process environment

Release source scans and this architecture gate enforce the unified runtime
boundaries together.

## Phase 011 Memory Manifest Boundary

```text
fixed scenario files
  -> test-only parser/evaluator
  -> immutable canonical manifest
  -> atomic report adapter
  -> separate-process validator/inspector
  -> optional release-evidence copy
```

The manifest model and fixed contracts live only in `tests/memory-harness`. Filesystem metadata,
CLI parsing, atomic publication, and process exit behavior are outer test/release adapters. Domain,
application, ports, core, Admin API, and the mio event loop do not import this model or read RSS
reports. HTTP, HTTPS, and mTLS steady measurement remains a test-tool composition around the release
proxy binary; results do not become runtime policy.

The lifecycle is `Created -> Collected -> Validated -> Published`, with invalid input terminating as
`Failed`. Validation completes before output replacement, and release evidence accepts the
manifest/digest only as an explicit pair. Command inputs are parsed once and passed as immutable
typed values; no runtime environment mutation is introduced.

HTTP client TCP half-close after a complete request is not a transport failure. The mio adapter
continues the selected upstream and writes the response; only `event.is_error()` aborts the
post-request client side immediately. This keeps transport readiness interpretation in the adapter
and preserves the HTTP timeout policy owned by the state machine.

### Three-run aggregate boundary

```text
three fixed run roots
  -> child manifest/source revalidation adapter
  -> pure repeatability evaluator
  -> immutable canonical aggregate
  -> atomic report adapter
  -> separate-process validator/inspector
```

`MemoryEvidenceAggregate` and its evaluator remain inside `edge-memory-harness`. The evaluator owns
cardinality, stable build/profile identity equality, duplicate-run rejection, checked threshold arithmetic, and
canonical encoding. Filesystem allowlists, symlink rejection, child report reads, process identity
hashing, CLI parsing, and atomic publication are test/release adapters. Product domain,
application, ports, core, Admin API, and mio code have no dependency on either layer.

The aggregate lifecycle is `Created -> RunsValidated -> Evaluated -> Published` or terminal
`Failed`. Validation completes before any target is replaced. Inputs are explicit immutable CLI
values; the collector performs no latest-directory discovery, process-environment reread, or
runtime configuration mutation.

## Phase 011 Final Memory Release Boundary

```text
physical full-profile inventory/readiness + physical diagnostic soak
  -> release adapter digest and canonical checks
  -> pure full-profile re-evaluation and soak validation
  -> immutable phase011-memory-release-v1 binding
  -> atomic report publication
  -> independent source-bound checker and transcript marker
```

`Phase011MemoryReleaseReport`, its evaluator, and the explicit
`Created -> InputsVerified -> ReportsValidated -> Bound -> Published|Failed` lifecycle live only in
`edge-memory-harness`. Filesystem metadata, SHA-256 I/O, CLI parsing, output allowlists, process
execution, and transcript publication remain outer test/release adapters. No product domain,
application, port, core, Admin API, or mio module imports the release model.

The expected source identity, platform, and architecture are read once by the shell/CLI boundary
and passed as immutable typed input. Scenario count, soak duration, workload counts, ceiling, and
plateau rules are source-controlled and have no environment or runtime override. Generated
`target`, `node_modules`, `.tasks`, and `artifacts` trees are excluded from source identity so test
execution cannot mutate the identity being measured.

Raw per-run config digests are not compared across runs because fresh ports and temporary storage
paths are part of independent execution. Each digest remains validated against its child report and
manifest; the typed steady profile contract defines cross-run semantic equivalence.

## Phase 011 macOS Deep Diagnostic Boundary

The `macos_leaks` model and lifecycle are test/release-tool code. Parsing and acceptance are pure;
filesystem permission and digest checks belong to the CLI adapter, while process launch, temporary
codesigning, workload execution, Admin cleanup observation, and `/usr/bin/leaks` invocation belong
to shell/system adapters. Product domain, application, ports, adapters, and the mio event loop do
not depend on this graph.

The runner hashes the unmodified release proxy and then signs only an ephemeral copy for task-port
inspection. The report binds both hashes plus source, config, and process identities. No Admin
handler reaches into connection state, no event-loop policy changes, and no runtime configuration
mutation are introduced. The diagnostic lifecycle is explicit and terminal failures cannot publish
a success marker.
