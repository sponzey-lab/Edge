# MVP Release Gate

## Current Automatic Gate

The old local `scripts/` smoke runners and release evidence collectors have been removed from the
working tree as of 2026-07-21. Historical sections in this document still name those scripts to
explain accepted Phase evidence, but those names are no longer current runnable commands.

Current source-level verification starts with:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --test-threads=1
```

The same source-level gate can run in the persistent test-only container:

```bash
docker compose -f docker-compose.test.yml up -d --build
docker compose -f docker-compose.test.yml exec edge-test \
  bash -c 'cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace -- --test-threads=1'
```

`docker compose -f docker-compose.test.yml config` is the test-container configuration contract
check. A pass inside this container is Linux source-level evidence only; it does not replace the
production image runtime smoke or platform-specific memory/resource evidence. The lifecycle and
secret-isolation rules are defined in `docs/testing.md`.

For a new release candidate, collect fresh evidence manually or with a newly reviewed gate outside
the deleted helper set. The evidence must record the source/build identity, platform, exact
commands, runtime configuration, Admin/API or proxy observations, memory/resource measurements where
applicable, pass/fail criteria, and secret-exclusion review.

## Supplemental Performance Characterization

The current release Compose performance boundary is separate from the canonical
memory/release gate. Its automatic smoke and manual profiles use the production
Edge image but do not satisfy Phase 011's 7,200-second/platform evidence.
Record only audited, non-partial artifacts:

```bash
node tests/performance/bin/run.mjs smoke
node tests/performance/bin/audit.mjs artifacts/performance/<run-id>
```

Baseline, stress, and soak are manual characterization profiles; until a
separate approval defines regression limits, their numeric results are not
merge or release blocking thresholds.

The historical collector used an explicit `SPONZEY_EVIDENCE_BUILD_OR_COMMIT` first, then git commit
metadata, then a `source-tree-sha256:<digest>` value derived from release-relevant source files when
git metadata was unavailable. Preserve that identity discipline in any replacement release process.

Phase 006 release evidence is not satisfied by the workspace test count alone.
The smoke transcript must contain its fixed retry, passive-health, drain,
Admin-contract, and observability test snippets plus this terminal marker:

```text
phase 006 failure-aware routing smoke passed
```

Phase 008 evidence additionally requires the backup restore reducer, durable
replace/recovery, private PKI trust matrix, and full encrypted recovery E2E
focused snippets plus this marker:

```text
phase 008 encrypted recovery and private PKI smoke passed
```

The collector records each required snippet in `snippet-check.txt`; the
validator independently cross-checks every snippet against `smoke_mvp.log`.
Missing the Phase 008 marker or claiming a focused snippet only in
`snippet-check.txt` rejects the evidence.

Phase 009 additionally requires schema v2 trust-reference validation, strict
upstream private TLS, required inbound mTLS, atomic generation compensation, and
trust-aware disaster recovery, bounded TLS failure sampling, server-registry
collision, and injected-time certificate-validity focused snippets plus this marker:

```text
phase 009 managed trust and bidirectional TLS smoke passed
```

The independent validator rejects a missing Phase 009 marker or any snippet that
is present only in `snippet-check.txt` and absent from `smoke_mvp.log`.

Phase 010 additionally requires durable frame reopen, intent-before-effect Admin
wiring, strict query rejection, explicit restore provenance state, backup schema
v3 history continuation, and the source-security checker, plus this marker:

```text
phase 010 durable audit and safe search smoke passed
```

The collector and independent validator both require these focused snippets in
the current `smoke_mvp.log`. A marker or snippet claimed only by
`snippet-check.txt`, or copied from a stale source identity, is rejected.

The accepted Phase 010 evidence path is
`artifacts/release-evidence/phase010-20260716-final-r2`. Its build identity is
recorded in `environment.txt`; all three automatic gate exit codes are `0`, and
the independent validator passes.

The accepted Phase 009 evidence path is historical baseline evidence:
`artifacts/release-evidence/phase009-20260715-final-r2`; it is valid only with
its current-source collector transcript and independent validation. Earlier
Phase 008 evidence remains historical evidence and does not prove the current source.

The historical evidence collector wrote command transcripts, environment details, Docker
version, `.tasks/` git evidence, required output snippet status, and a summary
under `artifacts/release-evidence/`. It does not run external Let's Encrypt
staging because that feature is deferred to Post-MVP work.
`scripts/smoke_release_evidence_collector.sh` verifies the
collector summary path with fake gate commands so release documentation checks
do not need to run the full release gate just to test the collector itself.
Before writing transcripts, the collector refuses pre-existing symlink required
output files, any pre-existing symlink inside the evidence tree, and any
unknown or stale path outside the collector's known output filenames. Required
snippets are matched only against the current gate
transcripts with source-specific provenance, such as `check.log`,
`check_release_docs.log`, or `smoke_mvp.log`.
`scripts/check_release_evidence.sh` validates a generated evidence directory,
including automatic `environment.txt` `release_id`/`build_or_commit` identity
and `utc_started_at` in `YYYYMMDDTHHMMSSZ` format, rejecting duplicate automatic environment and status keys,
requiring the automatic evidence directory tree to contain no symlinks. The
directory may contain only known collector output files, and the validator cross-checks each required snippet
against its expected current automatic gate transcript instead of trusting
`snippet-check.txt` alone.
Any `missing in <log>` snippet marker rejects the automatic evidence,
and `scripts/smoke_release_evidence_validator.sh` verifies the validator's
accept/reject behavior.
MVP release sign-off requires the automatic evidence collector output to pass
`scripts/check_release_evidence.sh`. The external ACME staging evidence flow is
kept as a Post-MVP Let's Encrypt readiness check. When that later evidence is
recorded, `scripts/check_mvp_release_ready.sh` can validate the automatic
release evidence directory and the ACME staging evidence directory together.
Those directories must be separate physical evidence directories, not the same
path with different spelling or a symlink alias. The checker validates both
evidence sets, requires the same `RELEASE_ID` basename, compares `release_id`
and `build_or_commit` between automatic `environment.txt` and ACME
`metadata.env`, and rejects `build_or_commit=not-recorded`. The script name is
historical and no longer makes Let's Encrypt an MVP blocker.
Use `scripts/init_acme_staging_from_release_evidence.sh` to initialize pending
ACME staging evidence from a validated automatic evidence directory so the
`release_id` and `build_or_commit` fields are copied instead of retyped.
The helper appends an `Automatic Evidence Binding` section to ACME `README.md`
so reviewers can see which automatic evidence directory produced the pending
manual evidence layout. The final readiness checker requires that ACME
`README.md` binding section, verifies its `automatic_release_evidence_dir`
matches the automatic evidence directory passed to the checker, and verifies its
`release_id` and `build_or_commit` lines match ACME `metadata.env`. Each
binding key must appear exactly once in ACME `README.md`. A trailing slash on
the automatic evidence path is normalized before writing or checking the
binding. The `Automatic Evidence Binding` section itself must also appear
exactly once, and the binding keys must be recorded inside that section.
The evidence-bound initializer inherits the lower initializer overwrite policy:
without `SPONZEY_STAGING_EVIDENCE_OVERWRITE=true`, it fails before appending the
binding when any fixed evidence file already exists; with overwrite enabled, it
rewrites the pending README before appending exactly one binding section.
Release evidence is acceptable only when the generated summary and
`environment.txt` show `test_command_overrides_used` as `false` and
`test_command_overrides_allowed` as `false`, and the generated summary does
not include override `true` values or smoke-only release evidence warnings.
The `summary.md` Automatic Gates table must also report exit code `0` for
`./scripts/check_release_docs.sh`, `./scripts/check.sh`, and
`./scripts/smoke_mvp.sh`, matching the required `status.env` values, and the
summary must include `Build/Commit` matching automatic `environment.txt`
`build_or_commit`.

The historical gate checks:

The implemented unified TLS runtime boundary and its detailed regression gates
are recorded in `docs/tls-runtime-next.md`.

Phase 011 control-plane memory characterization uses
`scripts/smoke_control_max_memory.sh`. It prepares and verifies 100,000 durable audit records,
holds them with the production maximum metric cardinality, performs three bounded Admin handler
query cycles and publishes source/manifest-bound RSS evidence under
`artifacts/memory-evidence/task044-current/`. This long-running profile is supplemental until it is
included in the final Phase 011 collector; a reused fixture is acceptable only when its aggregate
segment digest validates before sampling.

Phase 011 plaintext steady characterization uses `scripts/smoke_http_steady_memory.sh`. The driver
waits at an explicit start barrier until proxy RSS and Admin monitors are running, then requires
100 workers to complete exactly 100,000 bounded 200 responses. The gate requires observed live
concurrency, final 0/0 normal, recovery 200, a 384 MiB ceiling and source/config/report digest
binding under `artifacts/memory-evidence/task045-current/`.

Phase 011 private-PKI HTTPS steady characterization uses
`scripts/smoke_https_steady_memory.sh`. It requires 100 workers to complete exactly 50,000 trusted
responses after an explicit barrier, rejects wrong-root and wrong-SNI clients without increasing
the upstream count, and verifies public Admin peak/terminal state plus trusted recovery. The gate
uses a 384 MiB ceiling and source/config/report digest binding under
`artifacts/memory-evidence/task046-current/`; generated certificate material and paths are forbidden
from evidence. This supplemental profile does not replace the later Linux/repetition/soak gate.

Phase 011 required-mTLS steady characterization uses `scripts/smoke_mtls_steady_memory.sh`. It
requires exact quotient/remainder distribution of 25,000 authenticated responses across 64 workers,
no-cert and unrelated-client-Root rejection without upstream forwarding, final 0/0 normal and
authenticated recovery. The 384 MiB source/config/report-bound evidence lives under
`artifacts/memory-evidence/task047-current/`; client certificate/key/path material is forbidden.

- format
- unit tests for domain/application/core/Admin API/adapters
- snapshot mio HTTP multi-route forwarding test
- snapshot mio backend reset to `502 Bad Gateway` test
- snapshot mio upstream read timeout to `504 Gateway Timeout` test
- snapshot mio chunked response pass-through without upstream close test
- snapshot mio client backpressure pauses upstream reads test
- snapshot mio slow client header timeout to `408 Request Timeout` test
- snapshot mio upstream connect timeout to `504 Gateway Timeout` test
- snapshot mio WebSocket tunnel after `101 Switching Protocols` test
- snapshot mio nonblocking access log producer test
- product access log secret/body/auth/cookie/full-query exclusion and revision id test
- core TLS handshake state machine tests for SNI selection, unknown SNI failure,
  read/write interest, explicit events, and timeout failure
- adapter HTTPS listener multi-cert SNI selection test in `edge-proxy`
- config schema route `certificate_ref` parse/render round-trip test
- snapshot mio 502/504 recent error producer tests
- snapshot mio nonblocking request/active connection/upstream failure metrics tests
- active payload charge/limit and closed-label resource admission rejection
  metrics, including full/stopped publisher cleanup progression tests
- exact-field resource policy/pressure/rejection Product logs, Field bounded
  buckets, 60-second/8,192-key sampling, and saturated queue progression tests
- typed descriptor/aggregation limits and deterministic Prometheus encoder tests
- loopback metrics listener exact GET, query/method rejection, oversized header,
  concurrent scrape, disabled/public-bind rejection, and bounded shutdown tests
- authenticated Admin metrics summary and 500-series-per-kind bounds tests
- static Admin Web metrics API/status contract smoke
- deterministic HTTP and HTTPS multi-upstream round-robin tests
- generation-fenced active-health selection, all-unhealthy `503`, and recovery tests
- authenticated ordered `/api/v1/upstream-health` contract and bound TCP tests
- health transition Product log, bounded health metrics, Field Debug sampling,
  and saturated nonblocking observability queue tests
- daemon config lifecycle apply/rollback through `CoreCommandClient` and `CoreRuntime` test
- Admin API contract helpers apply/rollback through `ConfigLifecycle` and `CoreCommandClient`
- Admin API framework-free HTTP status/setup/login/logout/auth preflight contract tests
- bound Admin API TCP status/setup/login/logout/auth preflight tests in `edge-proxy`,
  including `admin_http_listener_logs_in_and_logs_out_over_tcp`,
  `admin_http_listener_sets_up_first_password_over_tcp`, and
  `admin_http_listener_rejects_mutation_without_session_over_tcp`
- Admin API config get/validate/diff/apply/rollback and proxy host CRUD contract tests
- bound Admin API TCP config/proxy-host/certificate issue/renew/certificate read/log read tests in `edge-proxy`
- bound Admin API TCP certificate issue product log success/failure tests in `edge-proxy`
- file-backed CertificateStore layout, metadata round-trip, failed temp-write preservation, and private key permission tests
- bound Admin API TCP certificate issue persists through the file-backed CertificateStore
- rustls server config loader accepts valid PEM and rejects invalid private key without panic
- rustls server stream wrapper creates a server-side TLS stream without doing file/network IO
- snapshot HTTP handler accepts generic `Read + Write` streams and preserves `X-Forwarded-Proto`
  for HTTPS injection
- bound Admin API TCP access log receiver queue test in `edge-proxy`
- bound Admin API TCP error log receiver queue test in `edge-proxy`
- bound Admin API TCP runtime command failure recent error test in `edge-proxy`
- queue-full drop observability tests in `edge-core` and `edge-proxy`
- file-backed SecretStore admin password hash load test
- startup HTTPS TLS config preflight succeeds with a valid file-backed certificate and fails before
  runtime start without importing current revision when the referenced certificate is missing
- snapshot mio runtime rollback apply preserves the previous working route for new requests
- snapshot mio HTTP to HTTPS redirect preserves the original host authority
- snapshot mio runtime serves HTTP-01 challenge tokens from the injected token store and returns
  404 for unknown tokens
- listener bind changes are reported as restart-required instead of hot-applied
- startup valid primary config imports into file-backed revision store test
- startup invalid primary config leaves revision store untouched test
- workspace tests
- architecture fitness rules
- release documentation consistency through `./scripts/check_release_docs.sh`
- release evidence collector summary smoke through `./scripts/smoke_release_evidence_collector.sh`
- release evidence validator smoke through `./scripts/smoke_release_evidence_validator.sh`
- combined automatic/ACME evidence readiness smoke through `./scripts/smoke_mvp_release_ready.sh`
- ACME staging evidence checker smoke through `./scripts/smoke_acme_staging_evidence.sh`
- ACME staging evidence initializer creates pending evidence and checker rejects it until real output is recorded
- local manual-preflight evidence in release collector snippets for Admin Web
  static smoke, minimal config parsing, data directory layout, and Docker
  Compose runtime smoke
- core headless smoke through `./scripts/smoke_core_headless.sh`
- Admin Web UI static contract smoke through `./scripts/smoke_admin_web.sh`
- bound Admin HTTP static Admin Web asset test in `edge-proxy`
- live Admin Web UI browser smoke against a local `edge-proxy` daemon through
  `./scripts/smoke_admin_web_live.mjs`
- Docker Compose runtime smoke through `./scripts/smoke_docker_compose.sh`
- local HTTPS self-signed reverse proxy smoke in `edge-proxy`
- HTTPS SNI selects the expected certificate among multiple loaded configs in `edge-proxy`
- HTTPS idle TLS handshake timeout closes the connection without poisoning the listener
- hot certificate install replaces the TLS runtime snapshot only after command acknowledgement,
  preserves the previous snapshot on missing certificate/core rejection/SNI conflict, and new
  HTTPS connections use the installed certificate
- bound Admin API certificate issue receives an HTTP-01 token from the selected ACME adapter,
  verifies it through the runtime HTTP listener, installs the fake ACME
  certificate with `fake-acme-staging` source in automatic smoke mode, and
  clears the token in `edge-proxy`
- HTTP-01 runtime probe uses bounded retry so listener readiness and transient probe races do not
  fail the gate spuriously
- stdout JSON product log adapter and process-start product log contract tests
- certificate renewal decision and retry/fatal classification tests
- Dockerfile and Docker Compose files

## Remaining Automatic Gate Items

The active root plan records completed Phase 008 encrypted backup,
crash-recoverable restore, and private PKI recovery. Private-PKI-testable mTLS,
upstream TLS, wildcard/SNI selection, TLS passthrough, and certificate lifecycle
work remain planned rather than explicitly excluded. Current MVP regressions
are discovered by the gates below:

- No automatic MVP blocker is currently identified beyond keeping `./scripts/smoke_mvp.sh`
  green. Add a named item here when a new required smoke or contract gap is found.

External Let's Encrypt staging is no longer an MVP release blocker. It remains
deferred Post-MVP work that must use an approved-domain run with
`SPONZEY_ACME_CLIENT=letsencrypt-staging` and an Admin API issue response that
returns `letsencrypt_staging`. The default fake ACME adapter remains sufficient
only for automatic HTTP-01 lifecycle smoke and must not be presented as real
Let's Encrypt evidence.

## Supplemental Manual Checks

These checks are useful operator walkthroughs, but they are not separate MVP
release blockers when the automatic collector snippets are present and
`scripts/check_release_evidence.sh` passes.

- open `apps/admin-web/index.html` for manual static layout inspection if a reviewer requires it
- run the curl-based Admin API control-plane flow in `docs/admin-curl.md` if a
  command-line operator walkthrough is needed
- run Docker Compose demo if a reviewer requires a separate human demo
- inspect generated data directory layout if a reviewer requires retained manual evidence
- review `examples/minimal.toml` if a reviewer requires separate human review
- record release evidence with `docs/release-evidence-template.md`

## Post-MVP External ACME Gate

- run the Post-MVP Let's Encrypt staging checklist in `docs/acme-staging.md` only with an approved test domain;
  initialize the evidence directory with `scripts/init_acme_staging_evidence.sh`;
  if `SPONZEY_STAGING_EVIDENCE_DIR` is supplied, its basename must match
  `SPONZEY_STAGING_RELEASE_ID`;
  the ACME staging evidence initializer and checker require the evidence
  directory tree to contain no symlinks and only fixed evidence filenames plus
  the initializer `README.md`;
  do not set `SPONZEY_STAGING_EVIDENCE_OVERWRITE=true` unless replacing every
  pending evidence file intentionally;
  use `scripts/acme_staging_preflight.sh` to verify approved-domain inputs,
  valid hostname/public target characters, `production=false`, explicit terms acceptance, HTTP-01 unknown-token `404`,
  and optional post-issue HTTPS reachability; validate the recorded evidence
  directory with `scripts/check_acme_staging_evidence.sh`, including matching
  preflight success markers and rejecting contradictory preflight markers,
  a valid JSON Admin API issue response with top-level field-value pairs for
  `request_id` tied to `admin_api_request_id`, `certificate_ref`, `domains`, `source=letsencrypt_staging`, and numeric
  `not_after_epoch_seconds`, matching evidence directory basename/`release_id`,
  and product log excerpt lines that are valid JSON objects with exactly one structured JSON object product log line
  with matching field-value pairs for `event=certificate.issue.success`,
  `component=admin-api`, `revision_id` tied to `config_revision_after`,
  `certificate_ref`, `request_id` tied to `admin_api_request_id`, and
  `status_code=200`; `admin_api_request_id` must be the stable `X-Request-Id`
  supplied on the authenticated Admin API issue request,
  `required-statements.txt` must state that this request used `X-Request-Id`
  matching `metadata.env admin_api_request_id`,
  non-empty `config_revision_after`, and metadata evidence file references matching
  the fixed evidence filenames, rejecting symlink evidence directories,
  required evidence file symlinks, non-required symlinks inside the evidence tree,
  and unknown or stale paths outside the fixed evidence filenames,
  `build_or_commit=not-recorded`,
  duplicate metadata keys, and unsupported metadata identity characters, with no authorization/cookie JSON keys or
  certificate PEM/private key PEM fields or bearer/basic token strings in required, non-required, or hidden evidence files, and requiring challenge/HTTPS curl logs
  to mention the approved domain, the challenge path where applicable, and the
  Let's Encrypt staging issuer, without echoing matched secret-bearing evidence
  lines when sensitive material is rejected; then run
  `scripts/check_mvp_release_ready.sh` against separate physical automatic
  release evidence and external ACME staging evidence directories with matching
  `RELEASE_ID` and `build_or_commit`

The latest local automatic-gate audit is recorded in
`docs/mvp-completion-audit.md`. It separates passed MVP automatic evidence from
deferred Post-MVP Let's Encrypt evidence.

External ACME staging is deferred while local MVP development and release
preparation continue. That deferral is now part of MVP scope control: MVP
completion uses automatic evidence only, and Let's Encrypt validation resumes
as Post-MVP work.

`./scripts/check_release_docs.sh` verifies that release documents, the Post-MVP
ACME staging checklist, the release evidence template, the TLS next-slice plan,
required examples, Docker files, release evidence collector, and `.tasks/`
ignore policy are present and linked. It does not replace the approved-domain
Post-MVP staging run. External ACME staging remains a Post-MVP ACME readiness
gate until an approved public test domain is available.

Phase 011 private-PKI memory checks are local automatic evidence and do not depend on external
ACME. `scripts/smoke_private_https_memory.sh` verifies trusted/negative HTTPS correctness;
`scripts/smoke_private_https_idle_capacity.sh` verifies 512 complete idle TLS handshakes, the
384 MiB candidate RSS ceiling, exact release, Admin 0/0 normal cleanup, trusted HTTPS recovery,
source/config identity, digest validation, and certificate/key evidence exclusion.
`scripts/smoke_private_mtls_idle_capacity.sh` separately verifies 256 required-mTLS handshakes,
no-client-certificate and unrelated-Root rejection, accepted-session preservation, the 384 MiB
candidate RSS ceiling, exact cleanup, authenticated recovery, and client identity/key exclusion.
`scripts/smoke_websocket_memory.sh` verifies one warm-up plus five ordered measured cycles of 128 plaintext upgrades and
frame echoes in one proxy process, at least 8 MiB bounded tunnel charge under client backpressure,
the 384 MiB candidate RSS ceiling, terminal pending-output cleanup, Admin 0/0 normal, HTTP recovery,
the checked cooldown median plateau, source/config/process identity and canonical digest.
`scripts/smoke_connection_churn_memory.sh` verifies five independent 10,000-request HTTP lifecycle
cycles, exact 50,000 success, per-cycle Admin 0/0 normal, the checked-in cooldown plateau rule,
384 MiB candidate ceiling, recovery 200, source/config identity, canonical digest and negative
evidence validation. Its RSS samples are cycle-boundary observations, not a throughput or
sub-cycle transient-peak claim.
`scripts/smoke_slow_response_memory.sh` verifies five ordered cycles of 128 plaintext slow readers
in one proxy process with a test-only 4 KiB receive buffer. It requires at least 8 MiB response
charge per hold, exact 128 release, the 512 MiB candidate ceiling, Admin 0/0 normal, recovery 200,
the checked first/last cooldown median plateau, source/config/process identity, canonical digest and
evidence secret scan.

`edge-full-profile-readiness` is the Phase 011 inventory gate. It requires the fixed 12-scenario
allowlist with the expected single-run, three-run, or five-cycle evidence kind, a current source
identity, canonical digest, and successful scenario-specific validation. Missing, stale, wrong-kind,
or failed entries produce a valid partial report but never an approved readiness result.

`scripts/smoke_slow_header_memory.sh` now performs one verified warm-up plus five measured
256-connection slow-header cycles in one proxy process. It publishes `slow-header-5cycle-v1.json`
and its SHA-256 sidecar only after exact 256/256/0 terminals, at least 10,496 held payload bytes,
hold-time and recovery HTTP 200, final 0/0 normal cleanup, the fixed 384 MiB ceiling, unchanged
source/config/process identity, and the first/last cooldown median plateau all pass. The warm-up is
validated but excluded from the five measured observations.

Run the complete current-host profile only into a new root:

```bash
./scripts/run_full_memory_profile.sh \
  artifacts/memory-evidence/phase011-full-macos-arm64
```

The fixed runner executes ten jobs covering all twelve scenarios. It does not accept command,
scenario, evidence-kind, or artifact-path overrides. Each job must exit successfully and leave the
expected physical canonical report/digest with the startup source identity. Only then are
`inventory-v1.json`, `readiness-v1.json`, and their digest sidecars published. Child diagnostics may
remain after failure, but their presence is not success evidence and no readiness file is produced.

The separate long-soak gate requires `phase011-diagnostic-soak-2h-v1`: 121 observations spanning
exactly 7,200 seconds, alternating sixty churn and sixty WebSocket windows in one process. Validate
the final canonical pair with `edge-diagnostic-soak validate`; a short smoke, synthetic timestamps,
or a report with dirty cleanup, missing intervals, stale identity, ceiling breach, or plateau breach
cannot satisfy this release condition.

The one-window runner boundary is `SoakWindowRunner`. Its public production load adapter fixes odd
windows at 1,000 HTTP churn requests and even windows at 128 verified WebSocket lifecycles. It checks
the attached process identity before and after load, samples positive RSS, and requires Admin 0/0
normal cleanup plus an HTTP 200 recovery before returning an observation. Unit fakes and the existing
current-source WebSocket product smoke validate the boundary only; neither is accepted as the wall-clock gate.
The future orchestration must keep one release proxy and immutable source/config/process identity for
all 121 observations and must not expose duration or count overrides.

Run the fixed wall-clock composition only with a new output root:

```bash
./scripts/run_diagnostic_soak.sh \
  artifacts/memory-evidence/phase011-diagnostic-soak-macos-arm64
```

The wrapper keeps one release proxy and one bounded dual HTTP/WebSocket upstream alive. The runner
uses target seconds 0, 60, ..., 7,200 and rejects a target observed early or more than five seconds
late. No duration, interval, workload count, ceiling, or tolerance override exists. Success requires
the runner publication, a separate `edge-diagnostic-soak validate`, unchanged source identity, and
the evidence forbidden-field scan. Merely building the runner or passing fake-clock tests is not
long-soak evidence.

## Deferred Product Scope

These are not MVP blockers. They must stay out of the automatic MVP completion
claim unless a new reviewed plan explicitly moves them back into scope.

- weighted/least-connections/sticky balancing
- upstream keep-alive pool
- Docker provider
- DNS-01 and wildcard certificate automation
- additional TLS features beyond the implemented unified mio state machine
- remote metrics exposure, retention/history, and bundled Prometheus/Grafana
- HTTP/2, HTTP/3, and gRPC
- static file serving
- WAF/rate limiting
- multi-user, RBAC, and OIDC
- plugin system

## Phase 011 Partial Memory Manifest Binding

After all three steady scripts write one fixed input directory, run:

```bash
./scripts/collect_memory_evidence_manifest.sh \
  artifacts/memory-evidence/task048-profile \
  artifacts/memory-evidence/task048-current
```

To attach the partial manifest to automatic release evidence, provide both files:

```bash
SPONZEY_MEMORY_MANIFEST_FILE=artifacts/memory-evidence/task048-current/phase011-steady-manifest-v1.json \
SPONZEY_MEMORY_MANIFEST_DIGEST_FILE=artifacts/memory-evidence/task048-current/phase011-steady-manifest-v1.sha256 \
  ./scripts/collect_release_evidence.sh
```

The collector rejects one-sided, symlinked, stale-source, noncanonical, or digest-mismatched input.
It records `memory_manifest_status=partial`, the digest, and source-tree identity.
`scripts/check_release_evidence.sh` independently inspects the copied pair. Omitting it remains valid
for the existing MVP gate but means memory evidence was not collected. The profile cannot be
`approved` until Linux, three repetitions, and long-soak/deep-diagnostic blockers are satisfied.

## Phase 011 Three-Run Partial Aggregate

Generate three independent steady runs and the standalone review bundle with a new output root:

```bash
./scripts/run_three_steady_memory_profiles.sh \
  artifacts/memory-evidence/task049-three-run

./scripts/collect_memory_evidence_aggregate.sh \
  artifacts/memory-evidence/task049-three-run/runs \
  artifacts/memory-evidence/task049-three-run/aggregate
```

The first command already invokes the second after all child manifests pass. Re-running the
collector is an independent source-file validation. The input root must contain exactly three
physical run directories; each run contains only `profile` and `manifest` with fixed file sets. The
output is `phase011-steady-3run-v1.json` plus its `.sha256` sidecar.

Passing removes only the single-run repeatability blocker for the covered macOS steady scenarios.
The aggregate remains `partial`, is not yet an automatic MVP release-gate input, and cannot be called
`approved` while Linux x86_64, full-scenario, and long-soak/deep-diagnostic blockers remain.

## Phase 011 Canonical Slow Request Capacity

Run each script into a new explicit output directory:

```bash
./scripts/smoke_slow_header_memory.sh artifacts/memory-evidence/task051-slow-header
./scripts/smoke_slow_body_memory.sh artifacts/memory-evidence/task051-slow-body
```

The accepted profile is fixed at 256 partial headers and 128 partial bodies. Evidence produced by
the former 64/32 scripts is historical and cannot satisfy this gate. Passing both commands proves
current-source capacity, expected timeout terminals, hold-time health, ceiling, and cleanup for one
run. It does not prove cycle plateau, Linux, soak, or deep diagnostic completion.

For Task 057 and later source revisions, the slow-header command additionally proves its five-cycle
same-process plateau contract. The slow-body command remains independently governed by its own
five-cycle report and 512 MiB ceiling.

## Phase 011 Final Memory Release Gate

Generate the full profile and fixed wall-clock soak from an unchanged source tree, then bind them
into a new directory:

```bash
./scripts/run_full_memory_profile.sh <new-full-profile-root>
./scripts/run_diagnostic_soak.sh <new-soak-root>
./scripts/collect_phase011_memory_release.sh \
  <new-full-profile-root> \
  <new-soak-root>/diagnostic-soak-2h-v1.json \
  <new-soak-root>/diagnostic-soak-2h-v1.sha256 \
  <new-memory-release-root>
./scripts/check_phase011_memory_release.sh <new-memory-release-root>
```

The final directory must contain exactly these nine non-empty physical regular files and no other
path:

```text
full-profile-inventory.json
full-profile-inventory.sha256
full-profile-readiness.json
full-profile-readiness.sha256
diagnostic-soak.json
diagnostic-soak.sha256
phase011-memory-release.json
phase011-memory-release.sha256
phase011-memory.log
```

The checker independently recalculates each digest, canonical-decodes the copied reports,
re-evaluates all 12 full-profile scenarios, requires zero readiness blockers, revalidates all 121
soak observations and regenerates the binding report byte for byte. It also requires the literal
`phase 011 quantitative memory and resource safety passed` transcript marker. Missing, symlinked,
unknown, non-canonical, stale, wrong-platform, tampered, non-ready, short-soak, threshold-failed,
correctness-failed, cleanup-failed, raw-PID, temporary-path, or credential-bearing evidence fails
closed before approval.

This gate approves quantitative memory/resource evidence only for the report's exact source,
platform, and architecture. Phase 011 completion additionally requires an accepted native Linux
x86_64 full profile and an authorized reference deep diagnostic bound to that same source.

## Phase 011 macOS Deep Diagnostic Gate

Run the actual diagnostic and independent checker against a new root on macOS:

```bash
./scripts/run_macos_leaks_diagnostic.sh <new-macos-leaks-root>
./scripts/check_macos_leaks_diagnostic.sh <new-macos-leaks-root>
```

The directory must be mode 0700 and contain exactly five non-empty physical files:

```text
macos-leaks.raw
macos-leaks.raw.sha256
macos-leaks-v1.json
macos-leaks-v1.sha256
macos-leaks.log
```

`macos-leaks.raw` must be mode 0600 because the OS tool may expose PID, allocation addresses, stack
details, or temporary paths. It is a restricted diagnostic input, not public release evidence. The
JSON report and transcript must pass the forbidden-field scan and include only bound digests,
workload/cleanup results, and the zero-leak verdict.

The checker rebuilds the release proxy, verifies its digest against the report, validates current
source identity, recalculates raw/report digests, canonical-decodes and regenerates the verdict, and
requires the literal `phase 011 macos deep diagnostic passed` marker. A nonzero leak count or byte
count, tool failure, stale source, modified binary, malformed/duplicate summary, wrong permissions,
unknown path, workload failure, cleanup failure, identity drift, or report tampering fails closed.
The fixture-only contract can be checked quickly with `scripts/smoke_macos_leaks_evidence.sh`.

The runner signs only a disposable diagnostic copy with get-task-allow. Adding that entitlement to
the distributed binary, changing SIP, using sudo as an acceptance mechanism, or publishing the
signed copy is prohibited. Passing this gate is a macOS reference diagnostic and does not satisfy
the Linux x86_64 quantitative gate. Any tracked source change also makes the existing final memory
release bundle stale; rerun the full profile, two-hour soak, and final binding afterward.

## Phase 011 Cross-Platform Closure

The phase is releasable only when all of the following artifacts share the current source identity:

1. macOS arm64 full-profile readiness with 12 verified scenarios and zero blockers.
2. Native Linux x86_64 full-profile readiness with 12 verified scenarios and zero blockers.
3. A 7,200-second, 121-observation reference soak with zero correctness/cleanup failures.
4. An authorized reference deep diagnostic with zero definite leaked allocations and bytes.
5. The exact nine-file final binding accepted by `check_phase011_memory_release.sh`.

The accepted final run is stored under `artifacts/memory-evidence/task073-*`. Generated artifacts
are excluded from source identity; tracked source or documentation changes are not. Any later
tracked change invalidates these bindings and requires the affected current-source gates to run
again. External Let's Encrypt validation is not part of this closure.

### Accepted Phase 011 Checkpoint

The 2026-07-20 checkpoint passed this closure at source identity
`source-tree-sha256:2c2bcbf580ed60fe18c330340236ecccf0936d7e5a2d18822e1c36f0fb970862`:

- native Linux x86_64 and macOS arm64: 10/10 jobs, 12/12 scenarios, ready, zero blockers
- fixed macOS soak: 7,200 seconds, 121 observations, 60,000 HTTP churn requests, 7,680 WebSocket
  lifecycles, zero correctness/cleanup failures, plateau passed
- macOS deep diagnostic: 1,000 successful requests, 0/0 normal cleanup, zero definite leaks/bytes
- exact nine-file final binding digest:
  `78d453e0568c069e68c5e563535f2f2497ab42b80d765845a5568bacb7cbcf09`

This is an accepted development checkpoint, not permission to reuse its artifacts after a tracked
change. This documentation refresh occurs after that binding; a formal release candidate based on
the refreshed tree must rerun the source-bound gates above.
