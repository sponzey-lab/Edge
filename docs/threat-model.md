# Threat Model

Failure-aware routing never accepts request-selected upstreams and does not
persist passive/drain runtime state. Retry requires a safe method, zero body,
zero upstream bytes written, no response, one retry and bounded replay memory.
Status/logs omit endpoints, connection identities, auth, cookies, bodies, secrets
and keys. Administrative drain changes use the authenticated revision lifecycle.

This is the initial MVP threat model. It is intentionally short and must be expanded as features are implemented.

## Assets

- TLS private keys
- ACME account keys
- proxy configuration
- config revisions
- Admin API session secrets
- upstream service addresses
- access and audit logs

## Trust Boundaries

- Internet client to Core listener
- Core to upstream service
- Admin Web UI to Admin API
- Admin API to Core command boundary
- Core/application to filesystem adapters
- ACME client to certificate authority

## MVP Threats

- malformed HTTP requests
- HTTP request smuggling via ambiguous headers
- slow client and slow upstream resource exhaustion
- admin interface exposure
- config apply breaking active traffic
- private key leakage through logs, API, or diffs
- runtime environment mutation
- Admin Web UI bypassing Admin API
- health probes used for SSRF or metadata-service access
- stale probe results changing a newer config generation
- unbounded probe workers, logs, metrics labels, or debug sampler keys causing
  memory/resource exhaustion
- health status responses leaking upstream URLs, probe paths, or raw errors
- metrics cardinality growth, slow scrape exhaustion, or topology/secret label leakage
- a rogue or misdirected HTTPS upstream presenting an untrusted or wrong-name
  certificate
- an unauthenticated client reaching an mTLS-protected listener, or a client
  presenting a server-only, expired, incomplete, or unrelated certificate chain
- trust-store poisoning through path traversal, symlink replacement, partial
  writes, duplicate material, non-CA certificates, or same-ref overwrite
- plaintext downgrade after TLS failure or HTTP bytes crossing the boundary before
  authentication completes
- connect-address, TLS SNI, and HTTP Host confusion changing the authenticated
  identity or request destination
- stale or partially prepared TLS factories becoming active with a newer config
  generation
- handshake-failure floods exhausting product logs, sampler keys, or metric series
- backup schema/version or trust-reference mismatch publishing an unrecoverable
  target
- audit segment corruption, truncation, unsafe link/permission replacement, disk
  exhaustion, query amplification, or leakage through API/UI/release evidence
- a local privileged writer replacing the ledger and attempting to present the
  local hash chain as hostile-admin non-repudiation

## MVP Mitigations

- reject ambiguous Transfer-Encoding and Content-Length requests
- strip `Connection`, `Keep-Alive`, legacy `Proxy-Connection`, and
  `Connection`-nominated hop-by-hop fields from normal proxy requests and
  non-WebSocket upstream responses; retain chunked `Transfer-Encoding` only
  while forwarding its validated framing bytes
- set request header/body/time limits
- bind admin interface to localhost or unix socket by default
- require config validation, plan, apply, and rollback flow
- mask secrets in logs, diffs, and API responses
- read environment only at bootstrap
- enforce architecture checks in `scripts/check_architecture.sh`
- validate all proxy/probe endpoints through the same typed literal-IP parser,
  block metadata targets, and perform probe network I/O only in an adapter worker
- generation-fence probe results and publish immutable availability snapshots;
  late results cannot mutate the active generation
- use bounded worker/log/metric queues with nonblocking handoff, bounded reason
  enums, a 60-second Field Debug sampling window, and an 8,192-key sampler cap
- expose operational health only through the authenticated read-only Admin API;
  return stable identities and bounded states without URL, path, body, header,
  credential, or raw failure detail
- use a fixed typed metric descriptor/label registry, 16,384-series and 4 MiB
  budgets, two bounded scrape workers, 5-second socket timeouts, and an 8 KiB
  request limit; unauthenticated exposition binds to loopback only
- prohibit raw paths, URLs, queries, headers, bodies, request IDs, revision IDs,
  credentials, and private-key material from metric labels and release evidence
- require literal-IP connect addresses plus separate validated DNS SNI, HTTP Host,
  and immutable managed trust refs; never use system trust or CN/IP fallback
- require rustls chain, validity, EKU, and SAN verification for upstream TLS and
  required inbound mTLS; never fall back to plaintext or optional authentication
- publish trust bundles create-only through bounded CA-profile validation,
  no-follow owner-controlled files, fsync, atomic rename, and directory sync;
  reject deletion while any rollback-capable revision references the bundle
- prepare all TLS material outside the mio loop and atomically activate one
  immutable config/TLS/health generation only after bounded command acknowledgement
- key the inbound runtime factory registry by validated unique listener bind because
  mio owns listeners by socket bind; retain `ListenerId` as config/log identity, key
  outbound registries by `(ServiceId, UpstreamId)`, and keep connect address, SNI,
  and HTTP Host as distinct typed values
- release HTTP plaintext only after the relevant TLS handshake reaches its
  authenticated terminal state; make handshake timeout/failure explicit states
- sample Product handshake failures once per bounded key per 60 seconds, use a
  bounded nonblocking queue, and prohibit trust refs, names, identities, raw TLS
  errors, or certificate material from metric labels and logs
- authenticate and validate backup schema v2 trust artifacts against every retained
  revision before target publication, while retaining schema v1 verify/restore
- use bounded owner-only append-only audit segments, fsync-before-ack, startup chain
  verification, whole-segment checkpointed retention and fail-closed mutation admission;
  expose only authenticated bounded metadata queries
- include verified segments in backup schema v3, validate them before publication,
  and append operation-linked restore provenance only after successful publication
- treat the hash chain as local integrity detection for accidental corruption and
  non-privileged tampering. It does not provide hostile-host tamper proofing,
  non-repudiation, remote attestation, immutable export, or RBAC separation
- measure established TLS capacity with a private-PKI test client outside the product graph;
  require complete handshakes, bounded FD preflight, source/config-bound process RSS, explicit
  close-notify/socket shutdown, final Admin 0/0 normal, and certificate/key evidence exclusion
- verify required-mTLS capacity with a separately managed client Root, complete client-auth
  handshakes, no-certificate and unrelated-Root rejection, accepted-session preservation, and
  owner-only ephemeral client keys; do not interpret this local profile as CRL/OCSP coverage
- charge WebSocket directions independently, pause ingress at bounded per-direction limits, and
  remove terminal tunnels with all charges even when pending client output cannot drain; verify
  this with 128 public-boundary upgrade/echo/backpressure/cleanup sessions
- verify connection lifecycle exhaustion with five independent 10,000-request churn cycles; require
  zero connection and payload ownership after every cycle, normal pressure, unchanged process
  identity, bounded evidence fields and a fixed cooldown plateau rule
- bound slow-response clients with per-connection and global response charges; preserve legitimate
  request half-close semantics, but release upstream/connection ownership on response write-close
  or socket error so an unreachable client cannot retain charged output indefinitely
- characterize control-plane resident maxima with the production audit ledger and metric registry
  in a test-only composition; require exact 100,000/16,384/12,288 counts, max+1 rejection, bounded
  Admin projections, aggregate fixture digest and source-bound RSS evidence. Never add a product
  fixture endpoint or trust a reused fixture without reopening and verifying its hash chain.
- verify sustained plaintext load with an external 100-worker driver, ready/start sampling barrier,
  exact 100,000 response counter, public resource observations and terminal cleanup. Keep request
  material and PID out of evidence and do not interpret a loopback connection-per-request run as a
  throughput, latency, keep-alive, Linux or soak claim.
- verify sustained private-PKI HTTPS load with a root parsed once before readiness, immutable shared
  client configuration, 100-worker barrier and exact trusted upstream count. Require wrong-root and
  wrong-SNI rejection before forwarding, terminal 0/0 ownership and source-bound RSS evidence;
  exclude Root/private-key material and do not treat this as public-CA or mTLS evidence.
- verify sustained required-mTLS load with server and client trust roots separated, complete
  clientAuth material parsed once, exact 64-worker/25,000-request distribution, and no-cert plus
  unrelated-client rejection before forwarding. Require terminal cleanup and exclude every client
  certificate/key/path from evidence; this does not claim revocation or rotation coverage.

## Memory Evidence Manifest Threats

Selected or incomplete reports can misrepresent release safety. Task 048 therefore uses fixed
scenario/filename allowlists, rejects discovery and symlinks, and requires source, platform,
architecture, scenario, config, report, driver, and terminal-summary identities to agree. Digest
verification precedes parsing, and publication occurs only after every entry passes.

Evidence excludes credentials, certificate/key material, authorization/cookies, process IDs, and
temporary physical paths. The release collector accepts only an explicit manifest/digest pair and
checks its source identity. A macOS one-run result is `partial`; treating it as Linux, repeated,
soak, leak-free, heap-hard-cap, or kernel-memory evidence is a release-integrity error.

## Final Memory Release Evidence Threats

A copied `ready=true` value, old soak, or manually written success transcript could falsely claim
Phase 011 completion. The final collector therefore accepts only explicit physical report/digest
pairs, independently recalculates full-profile readiness, canonical-validates every soak window,
and binds all source/platform/architecture identities into one report. The checker regenerates that
report from copied inputs and requires byte equality plus the exact success marker.

Unknown files, symlinks, digest tampering, prior-source evidence, mixed platforms, blockers,
shortened workload, threshold/correctness/cleanup failures, raw PID, temporary path, and credential
fields fail closed. The marker remains scoped to its recorded platform and architecture; presenting
macOS evidence as Linux evidence or a bounded RSS plateau as proof of all heap leak absence is an
integrity violation.

## macOS Deep Diagnostic Evidence Threats

Raw `leaks` output can expose process IDs, addresses, stacks, image paths, and temporary paths. The
raw file is therefore a mode-0600 restricted artifact in a mode-0700 directory and is excluded from
public summaries. The canonical report stores only SHA-256 identities and fixed verdict fields;
the public report/log forbidden-field scan rejects credentials, PID fields, and temporary paths.

An entitled binary is also a security-sensitive diagnostic mechanism. The runner copies and hashes
the release proxy, signs only that disposable copy with get-task-allow, verifies the original digest
again, and never publishes the copy. Host SIP, privilege settings, the product binary, and runtime
policy remain unchanged. Stale source, digest substitution, process replacement, malformed or
ambiguous tool output, nonzero leaks, incomplete workload, or dirty cleanup fails before success
publication.
