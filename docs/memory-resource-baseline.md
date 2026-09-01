# Memory And Resource Ownership Baseline

## Purpose

This inventory is the Phase 011 starting authority for production-owned dynamic memory. It is
not a byte-exact heap inventory. It identifies the owner, current bound, duplication points,
and the mechanism that must enforce or measure each class.

Classification:

- `bounded`: a current production limit or bounded queue is enforced before unbounded growth.
- `budget candidate`: proxy-owned logical payload that must join the process-wide payload ledger.
- `excluded`: not charged to the logical payload ledger; the reason and alternate control are explicit.

## Data Plane Owners

| Owner | Source authority | Current bound/behavior | Class | Phase 011 action |
| --- | --- | --- | --- | --- |
| active client connections | `edge_core::runtime::SnapshotMioRuntime::accept_ready`, `connections` | `ResourceLimits.max_connections`, default 1,024 | bounded | validate 1..=4,096 and preserve existing connections at admission failure |
| incomplete request | `ClientRequestBuffer.bytes` | header 16 KiB plus body 1 MiB | budget candidate | charge logical bytes before growth |
| completed request clone | `ClientRequestBuffer::push`, `RequestReadOutcome::Complete(self.bytes.clone())` | duplicates the completed request transiently | budget candidate | characterize, then move ownership or charge the copy |
| parsed request | `HttpRequest` strings, headers, body | derived from a bounded request but allocates separate strings/body | budget candidate | include in ownership transfer/copy inventory |
| upstream request write | `HttpConnectionIo.upstream_write`, `SnapshotMioConnection.pending_upstream_output` | request-derived; no process-wide aggregate | budget candidate | reserve before wire-format construction/queueing |
| pending upstream request | `SnapshotMioConnection.pending_upstream_request` | clone retained across connect/TLS progression | budget candidate | charge retained replay ownership |
| retry replay | `RetryContext.upstream_request` and `RetryContext.original_request` | one retry, replay policy up to 1 MiB | budget candidate | require separate admission for simultaneous copy |
| client response | `HttpConnectionIo.client_write`, `pending_client_output` | readable backpressure at 64 KiB per connection | budget candidate | charge append/pull/transfer and release after drain |
| WebSocket upgrade response | `SnapshotMioConnection.websocket_response` | header completion guarded, no global aggregate | budget candidate | charge until transfer to client output |
| WebSocket client-to-upstream | `tunnel_client_to_upstream` | per-direction flow control uses request-body bound | budget candidate | charge before append and pause ingress at pressure |
| WebSocket upstream-to-client | `tunnel_upstream_to_client` | per-direction flow control uses response-buffer bound | budget candidate | charge before append and pause ingress at pressure |
| TLS adapter plaintext/ciphertext | `RustlsTlsSession.decrypted`, `RustlsTlsSession.encrypted` | drained in bounded chunks but no process-wide aggregate | budget candidate | charge bytes explicitly exposed between adapter and core |
| rustls internal session state | `rustls::Connection` inside `RustlsTlsSession` | library-owned and not observable byte-exactly | excluded | connection cap plus HTTPS/mTLS RSS profiles |
| kernel socket buffers | OS TCP stack | OS-owned | excluded | connection cap, FD preflight, process RSS claim boundary |

`WriteBuffer` keeps the full backing allocation until the buffer is replaced or dropped. Advancing
`written` reduces pending logical bytes but does not necessarily reduce allocator capacity. Phase 011
therefore reports logical charge and process RSS separately.

## Control Plane And Resident Owners

| Owner | Source authority | Current bound/behavior | Class | Phase 011 action |
| --- | --- | --- | --- | --- |
| runtime command queue | `runtime_command_channel(128)` in `edge-proxy` | bounded sync channel, 128 | bounded | preserve nonblocking command boundary |
| access/error/metric channels | `edge-proxy::main` composition | bounded sync channels, 1,024 each | bounded | measure saturation; no payload charge |
| health/TLS observation channels | `edge-proxy::main` composition | bounded sync channels, 256 each | bounded | preserve drop/nonblocking policy |
| passive health observations | `PASSIVE_OBSERVATION_CAPACITY` | bounded sync channel, 1,024 | bounded | no change |
| health worker queue/results | `HealthProbeWorkerPool` | shared outstanding capacity and bounded completion channel | bounded | no change; measure resident cost with control profile |
| recent Admin access/error logs | `RecentAccessLogBuffer`, `RecentErrorBuffer` | composition default 100 entries | bounded | keep request/body/secret excluded |
| bounded structured logs | `BoundedLogQueue` | constructor capacity, drops oldest | bounded | retain explicit capacity at composition |
| TLS failure sampling keys | `TlsFailureProductSampler` | composition capacity 256, TTL 60 seconds | bounded | no change |
| metric registry | `METRIC_MAX_SERIES`, `METRIC_MAX_CUMULATIVE_SERIES` | 16,384 total; 12,288 cumulative; encoded response 4 MiB | bounded | include maximum-cardinality RSS scenario |
| audit record index | `FileAuditLedger.records`, `MAX_SCAN_RECORDS` | up to 100,000 resident views | bounded | include maximum-record RSS scenario |
| audit segment metadata/storage | `MAX_SEGMENTS`, `MAX_SEGMENT_BYTES`, `MAX_TOTAL_BYTES` | 32 segments, 4 MiB each, 128 MiB total | bounded | measure resident index; disk bytes are not payload charge |
| config snapshots/revision operation results | `ConfigSnapshot` collections and file revision adapter | operation-scoped clones; no hot-path payload ownership | excluded | measure startup/Admin lifecycle separately; do not charge data-plane payload |
| backup/restore buffers | `edge-adapters::backup` | offline command mode and artifact-specific checks | excluded | retain separate process-mode limits and backup tests |

## Foundation And Test-Only Structures

- `WorkerEventQueue` in `edge-core` is used by foundation unit tests and is not the production
  unified mio runtime command path. It must not be cited as a production unbounded queue.
- Unbounded `mpsc::channel` calls under adapter/core test helpers are test synchronization channels.
- Test fixture `Vec` collections are excluded from production resident-memory claims.

The architecture fitness gate must continue to distinguish these from production composition
before rejecting or replacing a queue.

## Known Amplification Paths

1. `ClientRequestBuffer::push` retains `self.bytes` and clones it into `Complete(Vec<u8>)`.
2. Parsing allocates `HttpRequest` fields and body from the completed request bytes.
3. Building an upstream request creates a new wire-format `Vec<u8>`.
4. `pending_upstream_request`, `RetryContext.upstream_request`, and `pending_upstream_output` can
   retain copies during connect, TLS handshake, and retry planning.
5. TLS sessions hold library state plus adapter-owned decrypted/encrypted buffers.

The global ledger must model ownership transfer where possible and separate copy admission where
simultaneous residency is required. Removing a clone is a Tidy First change only after wire output,
retry eligibility, and state progression characterization tests exist.

## Claim Boundary

- Logical payload charge is not `Vec::capacity()`, allocator arena size, kernel memory, or total RSS.
- Process RSS evidence includes allocator/library/runtime effects but cannot identify every heap owner.
- A cooldown RSS plateau plus zero active logical charge is evidence of bounded operation, not a
  mathematical proof that every allocation was released to the OS.
- macOS and Linux evidence are compared only inside their declared OS/architecture profiles.

## Platform-Neutral Harness Foundation

Phase 011 Task 024 adds a test/release-only Clean Architecture boundary above the Task 001
mini sampler. `scenario` owns the closed lifecycle and typed operational/evidence failures,
`ports` owns process supervision, RSS sampling, load driving and monotonic clock contracts,
and `orchestrator` coordinates only those interfaces. Product crates do not import these types.

The explicit lifecycle is `Created -> Preflight -> StartingProcesses -> Warming -> Loading ->
Cooling -> Analyzing -> Passed|Failed|InvalidEvidence`. Out-of-order or duplicate events are
terminal invalid evidence. Fake-port tests prove success, early process exit, sampler loss,
PID start-identity change, the one-percent missing-sample rule and exact-once child cleanup.
The existing schema v1 baseline report and `edge-memory-sample` CLI remain compatible.

Task 024 alone did not provide platform adapters, release-process composition, schema v2 evidence
or load scenarios; Tasks 025 through 030 incrementally add those boundaries without moving them
into the product dependency graph.

Task 025 implements the first test-tool system adapters. macOS uses checked `ps` RSS and process
start identity; Linux uses checked `/proc/<pid>/status` `VmRSS` and `/proc/<pid>/stat` start ticks.
Both reject zero, malformed, duplicate and overflowing fixture values. An explicit immutable child
command spec drives a `NotStarted | Running | Stopped` supervisor, and current-host smoke verifies
positive RSS, stable start identity, liveness and child cleanup. These adapters still do not launch
the proxy release scenario or produce approval evidence.

Task 026 adds canonical schema v2 report evidence. The schema requires source/build identity,
64-hex config digest, scenario identity/version, platform/architecture, process start identity,
expected/missing sample counts, typed terminal outcome and derived baseline/peak/cooldown RSS.
Unknown fields, noncanonical JSON, zero/reordered/inconsistent samples and mismatched terminal state
are rejected. A separate outer adapter writes same-directory temporary bytes, syncs and atomically
renames them, returns a SHA-256 digest, and independently rejects tamper or stale identity. The
Task 001 schema v1 codec remains unchanged. Ceiling/plateau evaluation and release collection are
still pending.

Task 027 encodes the acceptance arithmetic as a pure test-tool evaluator. It applies an inclusive
absolute ceiling and the five-cycle cooldown rule: median of the first two cycles, median of the
last two cycles, and tolerance `max(16 MiB, first / 10)`. Checked overflow, fewer than five cycles,
ceiling+1 and plateau+1 fail with closed reasons. A low RSS cannot hide process death, request
count/failure mismatch, nonzero active connections or nonzero logical payload after cooldown.
Task 030 now supplies a small current-host HTTP observation, but the evaluator is not yet embedded
in a source-bound canonical full-profile report.

Task 028 adds `edge-memory-evidence sample|validate` and
`scripts/smoke_memory_evidence.sh <new-output-directory>`. On a Linux Docker host, the smoke
prepares the fixed private-PKI runtime, builds and starts the performance release composition,
attaches only to the Edge container PID, publishes a schema v2 report/digest atomically, and invokes
validation in a separate process. Source identity is a SHA-256 of the tracked Git archive and the
config digest is computed from the fixed performance configuration. The trap removes only its
dedicated Compose services on all terminals. The accepted 2026-07-16 current-host macOS arm64 smoke recorded three idle samples,
all at 9,338,880 bytes RSS, with no missing samples. This short smoke proves Gate C composition,
not the Phase 011 ceiling, plateau, Linux or load scenarios.

Task 029 adds a test-tool-only bounded HTTP load adapter. Its immutable specification fixes the
loopback target, Host, request count, timeout and maximum response bytes before execution. The
driver opens one connection per churn request and follows the closed state sequence `Ready ->
Warming -> Loading -> Cooling -> Completed`; duplicate or out-of-order operations enter `Failed`.
It accepts only HTTP 200 responses with one valid `Content-Length` and an exactly matching bounded
body, while malformed, mismatched and over-limit responses remain failed requests in the counters.
The same adapter parses the Admin status projection with a required active/live revision match and
closed pressure enum. Loopback contract tests pass.

Task 030 composes these ports against a real release proxy without importing product internals. Its
explicit lifecycle is `Created -> Attached -> Baseline -> Warming -> Loading -> Cooling ->
Analyzing -> Passed|Failed|InvalidEvidence`; process identity/sample failures are invalid evidence,
while request, ceiling, plateau, pressure and cleanup failures are failed acceptance. The accepted
2026-07-16 macOS arm64 small smoke opened 100 new HTTP connections and received 100 valid responses
with no failures. The final verification run's peak and all five cooldown RSS observations were
9,830,400 bytes, below the
conservative 256 MiB smoke ceiling. Admin reported active/live revision `bootstrap-seed`, normal
pressure, zero active connections and zero charged payload after cooldown. This is a small
composition smoke, not schema-bound full evidence or a Linux/1024-connection/slow-path claim.

Task 031 adds a separate canonical HTTP memory evidence schema without changing the idle schema v2
contract. A passing report binds source/build/config/scenario/platform/architecture/process-start
identity to request counters, ordered baseline/load/cooldown RSS, the absolute ceiling and plateau
arithmetic, active runtime revision/pressure, and zero connection/payload cleanup. Unknown fields,
noncanonical encoding, failed counters/evaluation, nonzero cleanup, stale identity and digest
tampering are terminal rejection. `scripts/smoke_http_memory_scenario.sh` now publishes
`http-churn-v1.json` plus a SHA-256 sidecar and validates them in a separate process; it also proves
stale build identity and a digest-recomputed unknown-field report are rejected. The authoritative
current-host values are the fresh files under `artifacts/memory-evidence/task030-current/`; observed
Task 030/031 small-run peaks remain approximately 9.7-9.9 MiB. This evidence is still a macOS arm64
small profile and is not the Phase 011 cross-platform/full-pressure release marker.

Task 032 adds a test-tool-only bounded connection holder with explicit `Ready -> Ramping -> Held ->
Releasing -> Released|Failed` transitions. It progressively opens 64, 256, 512 and 1,024 loopback
connections, writes one incomplete-header byte per socket, and owns every client socket until an
explicit stop signal. Invalid, decreasing, duplicate or partial ramps close all held sockets and
fail closed. `scripts/smoke_connection_capacity.sh` requires an FD soft limit of at least 4,096,
then compares the holder's exact count with the public Admin live-resource projection. The accepted
macOS arm64 run observed 1,024 active connections and 1,024 charged logical payload bytes. Proxy RSS
was approximately 12.2 MiB while held and 12.3 MiB after release, below the 256 MiB smoke ceiling;
release converged to zero active connections, zero charged payload and normal pressure. Held and
released schema v2 reports have separate SHA-256 sidecars under
`artifacts/memory-evidence/task032-current/`. This result does not prove Linux capacity, the 1,025th
connection rejection contract, slow payload behavior, TLS/mTLS capacity or a long-running plateau.

Task 033 adds a pure rejection-decision state model and a separate bounded socket adapter. The model
accepts only `TerminalClosed` after `Ready -> Connecting -> AwaitingTerminal`; timeout-open,
application bytes, I/O failure and duplicate transitions fail closed. The release smoke holds 1,024
connections, attempts the 1,025th connection, and requires four independent observations: terminal
close, Admin count remaining 1,024, a `connection/connection_limit` rejection counter increment, and
one sampled Product event containing only the approved bounded fields. The accepted macOS arm64 run
observed metric value 1 and one Product event. Releasing the original holder reached connection and
payload zero, a new one-connection holder was admitted, and its release returned to final zero. The
source-bound held RSS report/digest and bounded summary are under
`artifacts/memory-evidence/task033-current/`. This proves actual plaintext admission preservation and
recovery for this profile, not payload pressure, Linux, TLS/mTLS or soak behavior.

Task 034 closes a test-environment execution gap in the Task 028/031 shell adapters. The local
Python shim returns success without executing code supplied as `python3 -`, so legacy readiness and
unknown-field fixture blocks could be skipped. Both memory smokes now use explicit `python3 -c`
arguments, and the release-doc gate rejects reintroduction of stdin Python execution in these files.
The HTTP negative gate separately proves that the mutated JSON and digest files exist, the JSON
contains `"unknown": true`, and the sidecar equals the SHA-256 of those exact bytes before invoking
the validator. Fresh idle and 100-request HTTP release smokes pass after the correction. This
restores the claimed readiness and recomputed-unknown-field test path; it does not alter product
runtime behavior or complete any new pressure profile.

Task 035 adds a test-tool-only slow-header driver with explicit `Ready -> Opening -> Holding ->
Collecting -> Completed|Failed` progression and bounded 408 response parsing. The accepted macOS
arm64 release smoke held 64 incomplete HTTP headers while Admin reported 64 active connections and
2,624 charged logical bytes. A separate complete request returned HTTP 200 during the hold. After
the production 30-second idle deadline, all 64 clients received bounded 408 responses, and Admin
converged to zero connections, zero charged payload and normal pressure. Held proxy peak RSS was
10,043,392 bytes, below the 256 MiB smoke ceiling. The report/digest and summary are under
`artifacts/memory-evidence/task035-current/`. This profile does not cover slow bodies, response
backpressure, TLS/mTLS, Linux or long soak behavior.

Task 036 adds a test-tool-only slow-body driver with the same explicit terminal state discipline,
strictly requiring `declared_body_bytes > sent_body_bytes > 0`. The accepted macOS arm64 release
smoke held 32 incomplete POST bodies, each with 32,768 body bytes sent against a declared 65,536
bytes. Admin reported 32 active connections and 1,051,072 charged logical bytes, which is above the
1,048,576-byte body-only minimum. A separate complete request returned HTTP 200 during the hold.
After the production 30-second idle deadline, all 32 clients received bounded 408 responses, and
Admin converged to zero connections, zero charged payload and normal pressure. Held proxy peak RSS
was approximately 11 MiB, below the 256 MiB smoke ceiling. The source/config-bound report, digest and
summary are under `artifacts/memory-evidence/task036-current/`. This proves the bounded partial-body
timeout and cleanup path for this profile; it does not prove payload-budget exhaustion, response
backpressure, TLS/mTLS, Linux or long soak behavior.

Task 037 verifies the proactive payload-pressure boundary with actual sockets. The canonical test
config uses the supported 16 MiB payload minimum with 64 maximum connections; pairing that payload
limit with 1,024 connections is invalid because it is below the fixed connection reserve and is
correctly rejected at bootstrap. Thirteen partial bodies charged 13,625,040 logical bytes, above the
13,421,773-byte 80% threshold, and Admin entered `pressured` with all 13 connections preserved. A
new connection closed at admission, the rejection metric classified it as
`payload/payload_pressure`, and one bounded Product event reported the same classification. The 13
holders then received 13/13 bounded 408 responses; Admin returned to normal with zero connections
and payload, and a fresh request returned HTTP 200. Held peak RSS was approximately 23 MiB, below
the 256 MiB smoke ceiling. Source/config-bound evidence is under
`artifacts/memory-evidence/task037-current/`. The event loop intentionally pauses reads and rejects
new admissions at 80%, so normal socket flow should not be forced through the 100% hard limit. Exact
fit and max+1 exhaustion remain verified by the pure ledger tests. This profile does not cover
response backpressure, TLS/mTLS, Linux or long soak behavior.

Task 038 establishes the first private-PKI HTTPS memory profile without ACME or external network
access. A temporary Root and localhost SAN leaf are placed in the production managed certificate
store before bootstrap, with the private key owner-only. The production mio/rustls listener
forwarded 100/100 trusted correct-SNI requests, rejected both untrusted-Root and wrong-SNI clients,
then served another trusted request. Admin converged to zero connections, zero charged payload and
normal pressure. Peak RSS was approximately 10.7 MiB, below the 256 MiB smoke ceiling. The
source/config-bound report, digest and aggregate summary are under
`artifacts/memory-evidence/task038-current/`; certificate/key bytes and paths are excluded. This
profile does not prove HTTPS idle capacity, mTLS, WebSocket, Linux or long-soak behavior.

Task 039 extends the private-PKI profile to 512 fully established idle TLS connections. A
test-tool-only rustls client parses the temporary Root and SNI once, then ramps through
64/128/256/512 successful handshakes before publishing readiness. Admin reported exactly 512
active connections with normal pressure. Logical payload was zero after the completed handshakes;
this is expected because rustls session objects and kernel socket buffers are outside the
byte-exact proxy payload ledger. Their cost is covered by the process RSS envelope instead. The
macOS arm64 run peaked at approximately 16.7 MiB, below the 384 MiB candidate ceiling. Explicit
client `close_notify` and socket shutdown released all 512 sessions, Admin converged to 0/0 normal,
and a fresh trusted HTTPS request returned 200. Source/config-bound report, digest and aggregate
summary are under `artifacts/memory-evidence/task039-current/`, with certificate/key bytes and paths
excluded. This profile does not prove mTLS, WebSocket, Linux or long-soak behavior.

Task 040 adds required client authentication using a separate private client Root. The managed
client trust bundle is complete before bootstrap, and a test-tool-only rustls client loads the
server Root plus client chain/key once. The holder completed progressive 64/128/256 handshakes;
Admin reported 256 active connections, zero logical payload and normal pressure. Both a client with
no certificate and a client signed by an unrelated Root were rejected without reducing the 256
accepted sessions. Explicit close-notify/socket shutdown released all sessions, Admin converged to
0/0 normal, and an authenticated recovery request returned 200. The macOS arm64 peak RSS was
approximately 14.9 MiB, below the 384 MiB candidate ceiling. Source/config-bound evidence is under
`artifacts/memory-evidence/task040-current/`; server/client certificate/key bytes, identities and
paths are excluded. This profile does not prove revocation, WebSocket, Linux or long-soak behavior.

Task 041 exercises 128 plaintext WebSocket tunnels through the production `101` upgrade path. A
bounded test client verified one masked binary frame and one unmasked echo per tunnel, then stopped
reading while the loopback upstream sent bounded server frames. Admin reported 128 active tunnels,
8,504,064 charged logical bytes and normal pressure. The first run exposed a terminal cleanup bug:
`close_after_write` stopped tunnel interest registration while cleanup still waited for pending
client output that could no longer drain. A Core regression test now requires terminal WebSockets
to release the connection and all directional charges even when client output is pending; ordinary
HTTP response drain behavior is unchanged. The corrected run released all 128 tunnels, converged
to 0/0 normal and served an ordinary HTTP recovery request with 200. The macOS arm64 peak RSS was
approximately 106 MiB, below the 384 MiB candidate ceiling. Source/config-bound evidence is under
`artifacts/memory-evidence/task041-current/`. This short plaintext profile does not prove TLS
WebSocket capacity, fragmentation/extensions, Linux or long-soak plateau behavior.

Task 055 extends the plaintext WebSocket capacity profile to one verified warm-up followed by five
ordered measured cycles in one proxy and upstream process. Every cycle requires 128 successful upgrades and echoes, 128 held and released
tunnels, at least 8 MiB logical payload, 0/0 normal cleanup, HTTP recovery 200, and a 384 MiB peak
ceiling. The first cooldown-pair median and last cooldown-pair median use the fixed 16 MiB/10%
plateau rule. Changed identity, count, payload, cleanup, ceiling, or threshold fails publication.

Task 042 runs the canonical plaintext connection-churn count as five independent cycles of 10,000
new connect/request/200-response/close operations. The test-tool runner does not begin the next
cycle until the authenticated Admin status reports zero active connections, zero charged logical
payload and normal pressure. All 50,000 requests succeeded. Repeated macOS arm64 runs observed
approximately 9.5 MiB across the startup and five cooldown samples; the last cooldown pair remained
within the fixed 16 MiB plateau tolerance and below the 384 MiB candidate ceiling. Exact values are
bound to each current report rather than generalized as a stable allocator constant. Each cycle's counters, runtime aggregate and
cooldown RSS are recorded in the canonical report under
`artifacts/memory-evidence/task042-current/`, with source/config identity and SHA-256 validation.
This is a churn plateau result, not a throughput benchmark: RSS is sampled at startup and after
each load cycle, so it does not claim to capture sub-cycle transient peaks. Linux reference,
steady concurrent HTTP, control-max and long-soak evidence remain incomplete.

Task 043 exercises 128 plaintext HTTP clients that read only the response headers and then stop.
The test-only driver fixes each client receive buffer at 4 KiB while a threaded loopback upstream
sends a bounded 4 MiB body. Admin observed all 128 active connections, approximately 12-13 MiB of
charged response bytes and normal pressure; the macOS arm64 held RSS was approximately 36.4 MiB, below the 512 MiB
candidate ceiling. The first actual run exposed that response-state client readability ignored a
full peer close, leaving pending output and charges behind. The Core now distinguishes a normal
request-side half-close from mio `write_closed`/error: only the latter terminates the response,
drops the upstream and releases all connection-owned charge. The corrected run released all 128,
converged to 0/0 normal and served recovery 200. Source/config-bound evidence is under
`artifacts/memory-evidence/task043-current/`. This short profile does not prove sub-cycle RSS peak,
TLS slow clients, five-cycle plateau, Linux or long-soak behavior.

Task 054 turns this into a same-process five-cycle contract without changing product buffer policy.
Each cycle must hold and release exactly 128 clients, observe at least 8 MiB of logical payload,
return to 0/0 normal, serve recovery 200, and stay below 512 MiB. The evaluator compares the median
of cooldown cycles 1-2 with cycles 4-5 using `max(16 MiB, first median / 10)`. It rejects changed
source/config/process identity, incorrect counts, dirty cleanup, ceiling breach, and threshold+1.

Task 057 applies the same fail-closed plateau shape to slow-header: one verified warm-up followed by
five measured 256-connection cycles in one proxy process, with a 10,496-byte logical payload floor,
384 MiB peak ceiling, exact cleanup/recovery, and the fixed first/last cooldown median rule.

Task 044 defines `control-max` as a test-tool process that owns the production
`FileAuditLedger` and `MetricRegistry` types together. Its prepare stage creates exactly 100,000
durable security-observation records through the normal append contract, closes the ledger, and
publishes a manifest containing the aggregate segment digest. The resident stage rejects a stale
or altered manifest, reopens and verifies the complete hash chain, then holds
100,000 `AuditRecordView` values together with 16,384 metric series, including the 12,288
cumulative-series
maximum. The 16,385th series must fail with `series_limit`.

The resident process calls the production Admin audit and metrics handlers three times through
their public reader contracts. Each audit response contains exactly the configured maximum page of
100 records, while metric counters and gauges are independently capped at 500 and the immutable
response is identical across cycles. `scripts/smoke_control_max_memory.sh` samples that process,
requires a 512 MiB RSS ceiling, validates source/manifest/report identities and then requires a
clean terminal summary. A prebuilt fixture may be supplied as the second script argument only when
its manifest and aggregate segment digest validate; this avoids repeating the intentionally durable
100,000 `fsync` preparation during focused reruns. The fixture process is not the `edge-proxy`
binary, so this scenario characterizes the production collections and Admin projections plus
test-process overhead. It does not claim proxy composition byte-exactness, disk-cache cost,
Linux parity, plateau or long-soak behavior.

The accepted macOS arm64 run prepared the 100,000 durable records in 537.75 seconds and occupied
approximately 52 MiB on disk. The held process reported 16,384 total and 12,288 cumulative metric
series, `series_limit` for max+1, and a peak RSS of 46,727,168 bytes (approximately 44.6 MiB), below
the 512 MiB candidate ceiling. The authoritative source/manifest/report identities remain in
`artifacts/memory-evidence/task044-current/`; preparation time is not an audit append throughput
SLO.

Task 045 runs `http-steady` through `scripts/smoke_http_steady_memory.sh` with 100 test-tool workers
and exactly 1,000 new plaintext HTTP
connections per worker. The driver publishes readiness before any request and waits for an explicit
start file, allowing the external proxy RSS sampler and public Admin status monitor to start first.
The accepted macOS arm64 run completed 100,000/100,000 responses with zero failures. Across 930
Admin observations, maximum active connections were 100 and maximum logical payload charge was
18,620 bytes; final state was 0/0 normal and a recovery request returned 200. The 100-sample load
window observed peak RSS 10,764,288 bytes, below the 384 MiB ceiling. Source/config/report evidence
is under `artifacts/memory-evidence/task045-current/`.

This scenario uses one connection per request and a threaded loopback upstream. It verifies a
sustained concurrent correctness/resource envelope, not keep-alive throughput or latency. The RSS
window covers the first load interval rather than every instant of the full run; Linux, three
independent reference runs and long soak remain incomplete.

Task 046 extends the same external-driver boundary through private-PKI HTTPS with
`scripts/smoke_https_steady_memory.sh`. The root certificate is read and parsed once before driver
readiness, then one immutable rustls client config is shared by 100 workers. Each worker completes
500 new TLS connection/request/response/close cycles after a common start barrier. The accepted
macOS arm64 run completed 50,000/50,000 responses, rejected wrong-root and wrong-SNI clients 2/2,
and confirmed exactly 50,000 trusted requests reached the upstream before recovery. Across 593
Admin observations, maximum active connections were 101 and maximum logical payload charge was
27,041 bytes. Final state was 0/0 normal, trusted recovery returned 200, and the 100-sample load
window peak RSS was 13,320,192 bytes, below the 384 MiB ceiling. Source/config/report evidence is
under `artifacts/memory-evidence/task046-current/`.

This is a connection-per-request private-PKI profile. It includes repeated full handshake and
encryption costs but does not claim keep-alive throughput, latency, session-resumption behavior,
public-CA readiness, mTLS steady coverage, Linux parity, plateau or long-soak completion.

Task 047 runs `scripts/smoke_mtls_steady_memory.sh` with required client authentication. A server
Root, a separate client Root, complete client-auth chain and key are generated before process start;
the driver reads them once and shares one immutable client-auth config. Quotient/remainder
distribution assigns exactly 25,000 requests across 64 workers. The accepted macOS arm64 run
completed 25,000/25,000 responses, rejected no-cert and unrelated-client-Root handshakes 2/2, and
kept the trusted upstream count at 25,000 before recovery. Across 335 Admin observations, max active
was 64 and max logical charge 14,069 bytes. Final state was 0/0 normal and authenticated recovery
returned 200. Peak RSS was 13,352,960 bytes, below 384 MiB. Evidence is under
`artifacts/memory-evidence/task047-current/`. CRL/OCSP, rotation under load, keep-alive performance,
Linux, plateau and soak remain outside this claim.

## Task 048 Steady Profile Manifest

`scripts/collect_memory_evidence_manifest.sh` combines Task 045-047 after all three steady scenarios
have been rerun for one identical source tree. For each of `http-steady`, `https-steady`, and
`mtls-steady`, one report, report digest, driver summary, and terminal summary are required. The
collector does not scan earlier task directories or select a newest file.

Every entry binds scenario/version, config and file digests, exact request arithmetic, worker count,
TLS negative and upstream counts, observed Admin maxima, final 0/0 normal state, recovery 200, peak
RSS, and the fixed 402,653,184-byte candidate ceiling. Source mismatch, unknown/missing files,
symlinks, noncanonical JSON, arithmetic or threshold failure, forbidden credential/path material,
and tampering are rejected before publication. `validate` rereads all 12 files; `inspect` validates
a copied canonical manifest and digest against its source identity.

The manifest is `partial` even when every entry passes. Linux x86_64, three independent repetitions,
and long-soak/deep-diagnostic work remain approval blockers. It is not a heap hard-cap proof, kernel
socket accounting, latency benchmark, or full Phase 011 approval.

The three steady scripts share `scripts/steady_http_upstream.py`, a bounded fixture with 128
long-lived accept workers and a listener backlog of 256. This replaced request-per-thread Python
servers after repeated 100,000-request runs lost 51 and 23 responses while proxy RSS sampling and
cleanup remained healthy. The fixed worker pool removes unbounded test-infrastructure thread
creation without lowering request counts, proxy concurrency, correctness criteria, or RSS ceilings.

Manifest `max_active_connections` is checked against the configured 1,024 connection limit, not the
driver worker count. Readiness, sampling, connection turnover, and recovery can overlap a driver
wave, so worker count is not a valid runtime active-connection ceiling.

## Task 049 Three-Run Repeatability Aggregate

`scripts/run_three_steady_memory_profiles.sh` creates a new artifact root and executes the complete
Task 048 steady profile three times. Every run has a separate profile directory, child manifest,
temporary data/config/certificate set, proxy process, and process-start identity. The script rejects
an existing output root and source identity changes during execution, preventing stale-file merging.

`edge-memory-aggregate` validates all child files again and emits one
`phase011-steady-3run-v1` canonical document plus SHA-256 sidecar. The run fingerprints are hashes of
the three scenario process-start identities; raw process identifiers and temporary paths are not
published. Duplicate fingerprints, mixed build/platform/architecture, missing or extra paths,
symlinks, child tampering, nonzero cleanup, and threshold failures fail closed.

Each run intentionally has a different raw config digest because listener ports and temporary data
paths are fresh. The digest is validated inside that run's child manifest; cross-run equivalence is
the fixed profile/scenario contract rather than byte equality of ephemeral config files.

The provisional repeatability envelope is source-controlled: each scenario's peak and cooldown
range must be no greater than `max(16 MiB, minimum peak RSS / 10)`. Every run must also satisfy the
402,653,184-byte ceiling and exact correctness contracts. Passing this aggregate proves repeatable
macOS steady behavior for these three scenarios only. It does not prove Linux behavior, heap or
kernel hard caps, the full scenario matrix, long-soak stability, or deep leak diagnostics.

The executable steady adapters are `scripts/smoke_http_steady_memory.sh`,
`scripts/smoke_https_steady_memory.sh`, `scripts/smoke_mtls_steady_memory.sh`, and
`scripts/run_three_steady_memory_profiles.sh`. They allocate distinct ephemeral loopback ports as
one set per scenario so a repeated profile cannot accidentally reuse its own listener address.

The same isolated adapter boundary applies to `scripts/smoke_connection_capacity.sh`: it requires a
soft file-descriptor limit of at least 4,096, holds exactly 1,024 plaintext HTTP connections, then
validates both held and released evidence before publishing `held-1024-v2.json`.

`scripts/smoke_slow_header_memory.sh` uses the same isolated bootstrap and bounded upstream fixture
for one warm-up plus five 256-connection partial-header cycles. It publishes the registry-named
`slow-header-5cycle-v1.json` only after every hold, cleanup, recovery, source identity, and plateau
check succeeds.

`scripts/smoke_slow_body_memory.sh` runs five exact 128-connection partial-body cycles with 65,536
declared and 32,768 transmitted bytes per connection. It publishes `slow-body-5cycle-v1.json` only
after the 4MiB minimum held payload, cleanup, recovery, source identity, and plateau checks pass.

`scripts/smoke_slow_response_memory.sh` runs five exact 128-connection cycles against a test-only
4MiB response fixture while clients retain only a 4KiB receive buffer. It publishes
`slow-response-5cycle-v1.json` only after its 8MiB held-payload, cleanup, recovery, source identity,
and plateau checks pass.

`scripts/smoke_connection_churn_memory.sh` runs five exact 10,000-request connect/request/close
cycles. It publishes `connection-churn-50k-v1.json` only after every cycle reaches 0/0 normal
cleanup and the source identity, ceiling, plateau, stale-identity, and tamper checks pass.

## Task 051 Canonical Slow Request Capacity Contract

`CanonicalSlowRequestProfile` fixes slow-header at 256 connections and slow-body at 128 connections.
The body relationship is 65,536 declared bytes and 32,768 transmitted bytes, producing a checked
minimum held logical payload of 4,194,304 bytes. Changed counts, body relationships, scenario
identity, or ceilings are invalid test contracts rather than runtime overrides.

The release scripts create fresh proxy/config/data processes, preserve a healthy request during the
hold, validate canonical report/digest identity, require every slow request to reach its expected
terminal, and wait for 0 active connections and 0 charged payload. Slow-header uses the 384 MiB
candidate ceiling and slow-body uses 512 MiB. This single-run capacity evidence does not satisfy the
three-cycle/five-cycle plateau or long-soak requirements.

## Task 052/053 Slow-Body Repeatability And Plateau Contract

One proxy process owns ordered slow-body load/cooldown cycles. The evaluator rejects a changed
source, config, or process-start identity, wrong cycle order/count, failed request, dirty cleanup,
or RSS over 512 MiB. Arithmetic is checked and the canonical public report hashes rather than
exposes process identity.

Cycle input is explicit and temporary; the published report/digest contains bounded counts, held
payload, peak/cooldown RSS and the plateau decision. It contains no PID, temporary path, request
body, or secret.

Task 052's three cycles establish same-process repeatability and exact cleanup. Task 053 is the
formal plateau contract: exactly five ordered cycles, the median of cooldown cycles 1-2 as the first
window, the median of cycles 4-5 as the last window, and a maximum increase of
`max(16 MiB, first median / 10)`. The cycle count and threshold are source-controlled and have no
runtime or CLI relaxation.

## Final Phase 011 Reference Checkpoint

The earlier task sections intentionally retain their point-in-time partial conclusions. The
2026-07-20 final checkpoint closes those listed Phase 011 blockers for source identity
`source-tree-sha256:2c2bcbf580ed60fe18c330340236ecccf0936d7e5a2d18822e1c36f0fb970862`.

- native Linux x86_64 and macOS arm64 full profiles each verified all 12 scenarios with no blocker
- the macOS 7,200-second soak produced 121 observations, 60,000 HTTP churn requests, 7,680
  WebSocket lifecycles, zero correctness/cleanup failures, and a passing plateau
- peak soak RSS was 9,633,792 bytes; first/last five-window medians were
  9,043,968/9,011,200 bytes
- the authorized macOS deep diagnostic reported zero definite leaked allocations and bytes
- the independent exact nine-file release binding digest is
  `78d453e0568c069e68c5e563535f2f2497ab42b80d765845a5568bacb7cbcf09`

Task 074 removed retained consumed history from both directions of plaintext WebSocket tunnel
output. Complete drains reset logical length while preserving reusable capacity; partial drains
preserve the unsent tail. The fixed ceiling, plateau tolerance, workloads, and product allocator
were not changed to obtain the accepted results.

These values are a process RSS and logical-owner envelope for the exact source, platform, build,
configuration, and scenarios. They do not include all kernel socket memory or prove a heap hard cap
for arbitrary traffic. Any tracked change requires regenerated source-bound evidence for a new
release candidate.
