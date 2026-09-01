# Troubleshooting

## Audit Is Degraded Or Verification Fails

- Stop persistent Admin mutations and run `edge-proxy audit verify --data-dir DATA_DIR`
  while holding exclusive process ownership. Do not delete, truncate, reorder or edit
  `logs/audit/segment-*.audit`.
- `AUDIT_RECONCILIATION_UNKNOWN` means the authoritative repository/runtime fact could
  not prove committed or not committed. Preserve the data directory and inspect the
  stable operation/action/target metadata; never guess a terminal outcome.
- Capacity errors require preserving the checkpoint and whole-segment retention order.
  Do not raise bounds through an environment variable or private config file.
- A restore provenance append error means publication already committed. For replace,
  retain the journal and run `backup restore-recover` with the same operation ID.
- Authenticated read-only status and audit query remain available when admission is
  degraded; the proxy data plane remains active. New persistent mutations fail closed.

## Metrics Are Empty Or Unavailable

- Confirm `[metrics]` is present, `enabled = true`, and `bind` is a loopback
  socket. Omission intentionally opens no listener.
- Query `GET /metrics` from the same process/network namespace. Query strings,
  POST, and remote binds are rejected.
- Use authenticated `GET /api/v1/metrics` to compare `desired_generation`,
  `applied_generation`, `ready`, and bounded `dropped` reasons.
- A generation lag means current-state reconciliation is degraded; it does not
  change the authoritative Core config snapshot.
- `series_limit` or `response_budget` drops require reducing configured route
  or upstream cardinality. Do not enlarge queues or mutate environment values
  while the process is running.
- Run `scripts/smoke_control_max_memory.sh` to reproduce the maximum resident collection check.
  The default run creates 100,000 durable audit records and can take several minutes because every
  append follows the production persistence contract. A previously prepared fixture directory may
  be passed as the second argument only for a focused rerun; digest mismatch, record-count mismatch,
  chain verification failure, metric max+1 acceptance, changed query output or RSS above 512 MiB is
  a failure. Do not edit segment files, weaken the limits or treat a fixture-process result as full
  `edge-proxy` RSS.
- Run `scripts/smoke_http_steady_memory.sh` for the 100-worker/100,000-request plaintext profile.
  Any worker failure, process identity change, max active of zero, charge above the configured
  limit, final state other than 0/0 normal, recovery mismatch or RSS above 384 MiB is a failure.
  Preserve driver/sampler/monitor diagnostics. Increasing the timeout may address a demonstrably
  overloaded loopback fixture, but do not reduce request count/concurrency or omit failed counters.
- Run `scripts/smoke_https_steady_memory.sh` for the private-PKI 100-worker/50,000-request profile.
  A missing bootstrap HTTP listener, root/leaf generation failure, any trusted request failure,
  accepted wrong-root/wrong-SNI client, changed upstream count, nonzero terminal charge, recovery
  mismatch or RSS above 384 MiB is a failure. Preserve diagnostics and distinguish fixture backlog
  or connect timeout from a product TLS failure before changing a bound. Never place generated Root
  or private-key material in evidence.
- Run `scripts/smoke_mtls_steady_memory.sh` for required-mTLS concurrency 64 and exact 25,000
  requests. Trust-store permissions, complete clientAuth chain/key, no-cert/untrusted rejection,
  upstream count, terminal 0/0 normal and authenticated recovery are mandatory. Do not lower the
  count to make it divisible; use exact quotient/remainder distribution. Never copy generated
  client material into evidence.
- Listener bind failure is a startup failure. Fix the occupied/invalid address
  and restart; never expose the endpoint on a public wildcard address.

## Failure-Aware Routing

- A safe GET/HEAD retries at most once, only before upstream request or response
  bytes. POST and body-bearing requests never retry.
- Diagnose ejection using active health plus passive transition events; stale
  revision/generation observations are ignored.
- `draining (N)` in `/api/v1/upstream-health` means existing HTTP/WebSocket
  references remain while new selection is excluded. Force drain is unsupported.
- If WebSocket clients close during response backpressure, `/api/v1/status` must converge to the
  expected lower `active_connections` count and release the corresponding payload charge. A
  persistent count with no live clients is a failed cleanup regression; capture source-bound
  evidence and run the terminal WebSocket cleanup test rather than restarting to hide the state.
  For the five-cycle smoke, changed process identity, any dirty cooldown, or median plateau failure
  is terminal; do not drop a failed cycle or relax the checked-in threshold.
- For repeated HTTP lifecycle checks, run `scripts/smoke_connection_churn_memory.sh`. A failed
  request, nonzero connection/payload after any cycle, abnormal pressure, changed process identity,
  or plateau violation is a failure. Do not delete a failed cycle or raise the checked-in ceiling;
  retain diagnostics and identify the first dirty cycle.
- For slow response cleanup, run `scripts/smoke_slow_response_memory.sh`. If clients were closed but
  status remains nonzero, distinguish normal request `read_closed` from response `write_closed`;
  do not weaken ordinary HTTP drain-before-cleanup or reuse the WebSocket terminal exception. A
  failed cycle, changed process identity, or first/last cooldown median violation is a failure; do
  not remove the failed cycle or relax the checked-in threshold.
- On queue pressure, use the authenticated status API and Field/Dev drop counter.
  Sink pressure does not change routing.
- Change policy through Admin validation/apply/rollback, never runtime env mutation.

## Config Validation Fails

Check:

- duplicate listener id
- duplicate normalized host/path route
- route references a missing service
- service has no upstream
- multiple upstreams have a missing or duplicate `name`
- two upstream URLs normalize to the same endpoint
- upstream URL does not start with `http://`
- health interval/timeout, threshold, status range, or path is outside the
  bounds in `docs/config-schema.md`
- Admin bind conflicts with a listener bind
- a deferred certificate-automation field is enabled; current operation supports
  manual certificates and private PKI only

## Admin UI Does Not Reach API

The static UI can be opened directly. If `/api/v1` is unavailable, it enters a
visible `UI smoke only` fallback for screen checks. Fallback state is not
runtime config and is never promoted into the revision store.

For a real Admin API integration, verify:

- Admin API server is bound to localhost or a protected address
- session cookie is present
- CSRF token is sent for mutation requests
- API path starts with `/api/v1`
- UI-visible errors include the Admin API `code/message/hint/request_id`

## Logs

Use the smallest useful log mode:

- `product`: minimal operational logs
- `field-debug`: route/upstream decisions
- `dev`: state machine and parser details

Product logs must not contain request body, cookie, authorization header, or private key material.

## All Upstreams Are Unhealthy

An all-unhealthy service returns `503 Service Unavailable` without connecting
to a target. Diagnose and recover through the control-plane boundary:

1. Read the current config and operational state with an authenticated session:

   ```bash
   ADMIN=http://127.0.0.1:9443/api/v1
   curl -sS -b /tmp/sponzey-admin.cookies "$ADMIN/config"
   curl -sS -b /tmp/sponzey-admin.cookies "$ADMIN/upstream-health"
   ```

2. Confirm that `revision_id` identifies the expected applied revision and
   record `generation`. Locate the affected `service_id` and verify whether all
   of its entries are `unhealthy`. Do not treat a previous generation as current.
3. Probe each configured endpoint's health path from the same network namespace
   as Edge. Check the configured status range, timeout, and threshold. Do not
   place credentials or private data in the health endpoint response.
4. If the current revision introduced the failure, roll back to a known-good
   revision using the authenticated session and login-issued CSRF token:

   ```bash
   curl -i -b /tmp/sponzey-admin.cookies \
     -X POST "$ADMIN/config/rollback" \
     -H 'Content-Type: application/json' \
     -H "X-CSRF-Token: $CSRF" \
     --data '{"revision_id":"KNOWN_GOOD_REVISION"}'
   ```

5. Re-read `/config` and `/upstream-health`. Completion requires the intended
   revision, a new matching health generation, at least one eligible target,
   and a successful proxied request. A rejected apply/rollback leaves the prior
   current revision and runtime snapshot active.

Never change process environment, edit `data/config/current`, or write runtime
health state files to recover traffic. Use `docs/admin-curl.md` for setup/login
and CSRF acquisition.

## Health Observability Queue Saturation

- Product state transitions continue to be reflected by
  `/api/v1/upstream-health` even if a log sink is full.
- `sponzey_edge_metric_events_dropped_total` uses bounded reasons to report
  queue pressure, stopped consumers, stale generations, and registry admission
  rejection without exposing raw errors or request values.
- A bounded stale-generation reason means a late result was intentionally
  discarded after activation changed.
- Do not increase queues without load evidence. First verify probe interval,
  target count, worker availability, and sink latency.

## Manual Certificate Import Fails

- `CERTIFICATE_INVALID`: verify chain PEM, key PEM, key/cert match, domains,
  and leaf expiry.
- `CERTIFICATE_STORE_FAILED`: verify data directory writes and owner-only key
  permissions.
- `RUNTIME_COMMAND_REJECTED`: active TLS was not replaced; check runtime queue
  health before retry.
- If compensation failed, reconcile through Admin API. Never mutate process
  environment or directly edit files as runtime control.

Product logs contain request/revision/certificate ref, source, and error code.
PEM, key, cookie, authorization, and request body are forbidden.

## HTTPS Handshake Fails

- `TLS_HANDSHAKE_FAILED`: verify the client uses TLS 1.2/1.3 and sends a valid
  SNI hostname covered by an installed certificate.
- `TLS_HANDSHAKE_TIMEOUT`: verify the client completes the handshake before the
  configured idle deadline and that no middlebox sends partial records only.
- Confirm HTTP on another listener remains available; malformed TLS closes only
  the offending connection.
- Check `sponzey_edge_tls_handshake_failures_total` by stable `error_code` and bounded
  recent errors. Product logs intentionally omit SNI, TLS record bytes, PEM,
  private keys, authorization, cookies, and bodies.
- Certificate changes must use Admin API import/install. Do not edit runtime
  environment variables or mutate listener state directly.

## Memory Manifest Collection Fails

Run `scripts/collect_memory_evidence_manifest.sh` only after HTTP, HTTPS, and mTLS steady scripts
write all outputs into one explicit input directory. Exactly 12 known files are required. Remove
diagnostics, certificates, nested directories, and stale files; do not replace them with symlinks.

A source mismatch requires rerunning all three scenarios after the last source or documentation
change. Do not edit identities or digests. For peak, arithmetic, TLS negative count, forwarding,
cleanup, or recovery failures, inspect that scenario and fix the behavior. Do not raise the
402,653,184-byte ceiling or claim `approved` to bypass failure.

Both `SPONZEY_MEMORY_MANIFEST_FILE` and `SPONZEY_MEMORY_MANIFEST_DIGEST_FILE` are required for
release binding. A missing pair means `memory_manifest_status=not-collected`, not a successful
memory gate.

## Three-Run Memory Aggregate Fails

Use a new artifact root with `scripts/run_three_steady_memory_profiles.sh`. Existing roots are
rejected because stale run files cannot be distinguished safely. Do not rename run directories;
only `run-001`, `run-002`, and `run-003`, each containing physical `profile` and `manifest`
directories, are accepted.

A duplicate process fingerprint means one run or its reports were copied instead of independently
executed. A mixed identity error means source, platform, architecture, or fixed profile changed
between runs; discard all three and rerun after the source is stable. For a repeatability failure,
inspect the scenario peak and cooldown RSS values and process cleanup. Do not widen the 16 MiB/10%
envelope, edit a digest, or reuse a previous manifest to force success.

The aggregate's `partial` status is expected. It is not evidence that Linux, the full scenario
matrix, long-soak behavior, allocator retention, or kernel socket memory has passed.

## Canonical Slow Request Capacity Fails

Do not lower 256 slow-header or 128 slow-body connections to reuse earlier evidence. First verify
the host file-descriptor limit, then inspect the script's failure-only diagnostics for proxy,
upstream, and driver termination. A hold mismatch, non-408 terminal, healthy-request failure,
ceiling breach, or nonzero final resource state is a failed capacity run.

Discard artifacts after any source or documentation change and rerun with a new output directory.
Do not edit report identities or digests. A passing capacity run is still not the required
slow-body/slow-response cycle plateau or long-soak result.
