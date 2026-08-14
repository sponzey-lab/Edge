# MVP Release Evidence Template

Use this template when preparing an MVP release note. It records the evidence
needed to prove that the automatic release gates were actually run.

Do not mark a release as complete when a required evidence field is missing.
Let's Encrypt external staging is deferred to Post-MVP work and is not an MVP
completion field.

## Release Identity

```text
release_id:
build_or_commit:
utc_started_at:
utc_completed_at:
operator:
reviewer:
```

## Automatic Gate Evidence

The historical `scripts/collect_release_evidence.sh` and
`scripts/check_release_evidence.sh` helpers are no longer present. Record the
current source-level commands and their full transcripts for the target build:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --test-threads=1
```

Use `git rev-parse HEAD` and `git rev-parse HEAD^{tree}` for build/source
identity. A new release process must validate its own evidence structure; do
not claim this template or removed helpers performed that validation.

## Supplemental Performance Evidence

The Compose performance environment is functional characterization, not a
replacement for the canonical Phase 011 release/memory gate. Attach a completed
audited run only when it matches the release identity:

```bash
node tests/performance/bin/run.mjs smoke
node tests/performance/bin/audit.mjs artifacts/performance/<run-id>
```

For manual characterization, retain the three-run baseline summary or selected
stress/soak summary with its `metadata.json`, `summary.json`, resource samples,
and audit output. Never attach `*.partial` output or generated test PKI.

For Post-MVP Let's Encrypt readiness, validate automatic and ACME evidence
directories together. They must be separate physical evidence directories, not
the same path with different spelling or a symlink alias:

```bash
./scripts/check_mvp_release_ready.sh \
  artifacts/release-evidence/RELEASE_ID \
  artifacts/acme-staging-evidence/RELEASE_ID
```
Both evidence directories must use the same `RELEASE_ID` basename. The ACME
`metadata.env` must contain the same `release_id` as the automatic evidence
`environment.txt`, and both evidence files must contain the same
`build_or_commit` value. For MVP evidence, `build_or_commit` must identify a
concrete release build. `not-recorded` is allowed only for local automatic
audit notes. The Post-MVP combined ACME checker also rejects `not-recorded`.
If `source-tree-sha256:<digest>` is used, copy that exact value into ACME
staging `metadata.env` through `SPONZEY_STAGING_BUILD_OR_COMMIT`.
Prefer `scripts/init_acme_staging_from_release_evidence.sh` for manual staging
setup; it validates the automatic evidence first and copies `release_id` plus
`build_or_commit` into the ACME pending evidence initializer.
It also appends an `Automatic Evidence Binding` section to ACME `README.md`.
Post-MVP combined readiness requires that section, verifies its
`automatic_release_evidence_dir` line matches the automatic evidence directory
passed to the checker, and verifies its `release_id` plus `build_or_commit`
lines match ACME `metadata.env`. Each binding key must appear exactly once in
ACME `README.md`. A trailing slash on the automatic evidence path is normalized
before writing or checking the binding. The `Automatic Evidence Binding`
section itself must also appear exactly once, and the binding keys must be
recorded inside that section.
The evidence-bound initializer inherits the lower initializer overwrite policy:
without `SPONZEY_STAGING_EVIDENCE_OVERWRITE=true`, it fails before appending the
binding when any fixed evidence file already exists; with overwrite enabled, it
rewrites the pending README before appending exactly one binding section.
When `scripts/init_acme_staging_evidence.sh` is used with
`SPONZEY_STAGING_EVIDENCE_DIR`, the custom directory basename must match
`SPONZEY_STAGING_RELEASE_ID`; the initializer rejects a mismatch before pending
manual evidence is written.
Without explicit `SPONZEY_STAGING_EVIDENCE_OVERWRITE=true`, the initializer
also rejects any pre-existing required evidence file before writing new pending
files, so a partially populated manual evidence directory is not modified.
It also rejects unknown or stale paths outside the fixed evidence filenames, so
scratch files are not carried into manual release evidence.

The collector's summary path is checked by
`scripts/smoke_release_evidence_collector.sh` with fake gate commands; release
evidence for a real build still requires running the collector without test
command overrides. The collector rejects test command overrides unless
`SPONZEY_EVIDENCE_ALLOW_TEST_OVERRIDES=true` is explicitly set for collector
smoke testing. The validator's accept/reject behavior is checked by
`scripts/smoke_release_evidence_validator.sh`.

```text
cargo_fmt_check:
cargo_clippy_workspace_all_targets:
cargo_test_workspace:
check_architecture:
check_release_docs:
smoke_mvp:
```

Required output snippets:

```text
phase 006 failure-aware routing smoke passed
test backup::tests::restore_machine_requires_explicit_rollback_and_recovery_paths ... ok
test backup::tests::replace_restore_persists_each_crash_state_and_rolls_back_publish_failure ... ok
test tests::unified_mio_private_pki_requires_root_trust_and_correct_sni ... ok
test tests::private_pki_backup_restore_restarts_admin_and_trusted_https ... ok
phase 008 encrypted recovery and private PKI smoke passed
test tests::phase009_schema_normalizes_v1_client_auth_and_validates_v2_trust_reference ... ok
test tests::phase009_outbound_private_pki_mio_requires_managed_root_and_correct_sni ... ok
test tests::phase009_unified_mio_required_mtls_forwards_only_trusted_client ... ok
test tests::phase009_health_commit_failure_compensates_to_previous_runtime_generation ... ok
test tests::phase009_backup_v2_restores_bidirectional_private_tls_trust ... ok
phase 009 managed trust and bidirectional TLS smoke passed
test tests::snapshot_mio_runtime_retries_safe_get_once_on_distinct_upstream ... ok
test tests::snapshot_mio_runtime_does_not_retry_post_after_connect_failure ... ok
test tests::runtime_selector_tracks_drain_references_across_config_generations ... ok
test failure_observability::tests::product_transition_log_has_exact_safe_bounded_fields ... ok
test admin_http::runtime_status_publisher_emits_only_drain_transition_edges ... ok
architecture check passed
release docs check passed
acme staging evidence smoke passed
core headless smoke passed
admin web smoke passed
admin web live browser smoke deferred by release policy
test admin_http::tests::admin_http_listener_serves_static_admin_web_assets_over_tcp ... ok
test tests::http_status_route_returns_current_revision_json ... ok
test admin_http::tests::admin_http_listener_serves_status_over_tcp ... ok
test tests::http_health_route_returns_minimal_operational_json ... ok
test admin_http::tests::admin_http_listener_serves_health_over_tcp ... ok
test tests::service_policy_config_parses_and_renders_losslessly ... ok
test tests::round_robin_selection_skips_unhealthy_and_accepts_unknown ... ok
test tests::snapshot_mio_runtime_round_robins_new_requests_across_service_upstreams ... ok
test tests::snapshot_mio_runtime_round_robins_https_requests_across_service_upstreams ... ok
test tests::snapshot_mio_runtime_publishes_health_503_and_recovery_through_command_queue ... ok
test tests::snapshot_mio_runtime_keeps_selected_websocket_during_health_change ... ok
test health::tests::stale_duplicate_and_unknown_probe_results_are_ignored_without_state_change ... ok
test health::tests::reconciliation_preserves_matching_health_counter_and_resets_changed_endpoint ... ok
test tests::upstream_health_route_requires_session_and_returns_ordered_safe_status_items ... ok
test admin_http::tests::admin_http_listener_uses_injected_health_status_reader_over_tcp ... ok
test health::tests::health_transition_observability_has_exact_safe_product_fields_and_bounded_labels ... ok
test health::tests::field_debug_health_sampler_enforces_sixty_second_boundary_and_capacity ... ok
test health_runtime::tests::saturated_health_observability_queues_do_not_stop_state_progression ... ok
test tests::unified_mio_tls_apply_activates_config_health_and_tls_together ... ok
test tests::rejected_atomic_health_activation_preserves_current_runtime_and_mirror ... ok
phase 005 multi-upstream health smoke passed
test tests::http_login_before_setup_returns_setup_required ... ok
test tests::http_login_success_emits_secure_cookie_and_csrf_json ... ok
test tests::http_logout_requires_csrf_and_invalidates_session ... ok
test tests::http_mutation_without_csrf_returns_csrf_required_error ... ok
test admin_http::tests::admin_http_listener_rejects_mutation_without_session_over_tcp ... ok
test admin_http::tests::admin_http_listener_logs_in_and_logs_out_over_tcp ... ok
test admin_http::tests::admin_http_listener_sets_up_first_password_over_tcp ... ok
test tests::parses_minimal_toml_config ... ok
test bootstrap::tests::ensures_runtime_data_layout ... ok
test tests::config_schema_roundtrips_route_certificate_ref ... ok
test tests::snapshot_mio_runtime_routes_by_host_to_different_upstreams ... ok
test tests::path_prefix_match_succeeds ... ok
test tests::more_specific_path_prefix_wins_with_same_priority ... ok
test tests::snapshot_mio_runtime_maps_backend_reset_to_502 ... ok
test tests::snapshot_mio_runtime_maps_upstream_read_timeout_to_504 ... ok
test tests::snapshot_mio_runtime_maps_upstream_connect_timeout_to_504 ... ok
test tests::snapshot_mio_runtime_maps_slow_client_header_to_408 ... ok
test tests::snapshot_mio_runtime_passes_chunked_response_without_upstream_close ... ok
test tests::snapshot_mio_runtime_pauses_upstream_reads_when_client_backpressures ... ok
test tests::snapshot_mio_runtime_tunnels_websocket_upgrade_after_101_response ... ok
test tests::unified_mio_https_self_signed_proxy_forwards_without_connection_thread ... ok
test tests::https_listener_selects_certificate_by_sni_among_loaded_configs ... ok
test tests::tls_handshake_machine_selects_certificate_and_establishes ... ok
test tests::tls_handshake_machine_unknown_sni_fails_without_panic ... ok
test tests::tls_handshake_interest_follows_current_state ... ok
test tests::tls_handshake_events_drive_state_transitions ... ok
test tests::tls_handshake_event_timeout_sets_failed_state ... ok
test tests::tls_handshake_machine_timeout_is_explicit_failure ... ok
test tests::rustls_tls_session_completes_with_fragmented_client_hello ... ok
test tests::startup_preloads_https_tls_configs_before_runtime_start ... ok
test tests::startup_missing_https_certificate_fails_before_runtime_start ... ok
test tests::install_certificate_command_replaces_tls_runtime_snapshot_after_ack ... ok
test tests::install_certificate_missing_ref_rejects_without_core_command ... ok
test tests::install_certificate_core_rejection_preserves_tls_runtime_snapshot ... ok
test tests::install_certificate_rejects_sni_domain_conflict_without_core_command ... ok
test tests::unified_mio_https_hot_install_uses_new_certificate_for_new_connection ... ok
test tests::https_proxy_connection_closes_idle_tls_handshake_on_timeout ... ok
test tests::fake_acme_client_issues_staging_certificate ... ok
test tests::fake_acme_client_presents_http01_challenge_before_issuing ... ok
test tests::letsencrypt_http01_client_rejects_challengeless_issue ... ok
test tests::letsencrypt_staging_client_requires_terms_before_network_io ... ok
test tests::letsencrypt_staging_client_rejects_production_before_network_io ... ok
test bootstrap::tests::acme_client_mode_accepts_explicit_letsencrypt_staging ... ok
test bootstrap::tests::acme_client_mode_defaults_to_fake_for_automatic_smoke ... ok
test bootstrap::tests::acme_client_mode_rejects_unknown_values ... ok
test tests::production_acme_requires_opt_in ... ok
test tests::http01_token_store_matches_exact_token ... ok
test tests::http01_without_http_listener_fails ... ok
test tests::acme_challenge_path_bypasses_redirect_route_action ... ok
test tests::snapshot_mio_runtime_serves_http01_challenge_from_token_store ... ok
test tests::certificate_issue_with_http01_registers_probes_and_clears_token ... ok
test tests::certificate_issue_with_http01_clears_token_when_probe_fails ... ok
test tests::certificate_issue_with_http01_clears_token_when_acme_fails ... ok
test admin_http::tests::admin_http_listener_issues_certificate_after_runtime_http01_probe ... ok
test admin_http::tests::admin_http_listener_issues_certificate_over_tcp ... ok
test admin_http::tests::admin_http_listener_issues_certificate_to_file_store_over_tcp ... ok
test tests::http_certificate_renew_uses_existing_domains_and_sends_install_command ... ok
test admin_http::tests::admin_http_listener_renews_certificate_over_tcp ... ok
test tests::certificate_renew_missing_certificate_does_not_call_acme_or_core ... ok
test tests::certificate_renewal_is_due_inside_window ... ok
test tests::certificate_renewal_is_skipped_outside_window ... ok
test tests::certificate_renewal_retryable_failure_sets_next_retry ... ok
test tests::certificate_renewal_fatal_failure_has_no_retry ... ok
test tests::certificate_renewal_retryable_failure_stops_at_max_attempts ... ok
test admin_http::tests::admin_http_listener_records_certificate_issue_product_log_over_tcp ... ok
test admin_http::tests::admin_http_listener_records_certificate_issue_failure_product_log_over_tcp ... ok
test admin_http::tests::admin_http_listener_creates_proxy_host_through_lifecycle_over_tcp ... ok
test admin_http::tests::admin_http_listener_lists_and_gets_proxy_hosts_over_tcp ... ok
test admin_http::tests::admin_http_listener_updates_proxy_host_through_lifecycle_over_tcp ... ok
test admin_http::tests::admin_http_listener_deletes_proxy_host_through_lifecycle_over_tcp ... ok
test tests::http_config_get_requires_session ... ok
test tests::http_config_get_returns_rendered_current_config ... ok
test tests::http_config_validate_accepts_valid_raw_config_without_csrf ... ok
test admin_http::tests::admin_http_listener_gets_and_validates_config_over_tcp ... ok
test tests::http_config_diff_returns_route_and_upstream_changes ... ok
test admin_http::tests::admin_http_listener_diffs_and_applies_config_over_tcp ... ok
test tests::http_config_apply_goes_through_lifecycle_and_core_command ... ok
test tests::http_config_apply_invalid_candidate_does_not_send_command ... ok
test tests::http_config_rollback_goes_through_lifecycle_and_core_command ... ok
test admin_http::tests::admin_http_listener_rolls_back_config_through_lifecycle_over_tcp ... ok
test tests::config_lifecycle_apply_with_core_ack_failure_keeps_current_revision ... ok
test tests::config_lifecycle_listener_change_commits_restart_required_revision_without_hot_command ... ok
test daemon_config_lifecycle_applies_and_rolls_back_through_core_command_boundary ... ok
test daemon_config_lifecycle_runtime_rejection_preserves_current_revision ... ok
test tests::startup_imports_valid_primary_config_into_file_revision_store ... ok
test tests::startup_invalid_primary_config_does_not_import_revision ... ok
test tests::snapshot_mio_runtime_rollback_apply_preserves_previous_route ... ok
test tests::snapshot_runtime_redirect_preserves_host_authority ... ok
test tests::snapshot_http_handler_accepts_generic_read_write_stream ... ok
test tests::snapshot_http_scheme_aware_stream_sets_forwarded_proto ... ok
test tests::snapshot_mio_runtime_emits_access_log_without_blocking_runtime ... ok
test tests::snapshot_mio_runtime_counts_full_log_queue_drops_without_blocking_runtime ... ok
test tests::snapshot_mio_runtime_emits_error_log_for_upstream_timeout_without_blocking_runtime ... ok
test tests::snapshot_mio_runtime_emits_request_and_active_connection_metrics_without_blocking_runtime ... ok
test admin_http::tests::admin_http_listener_serves_access_log_received_from_runtime_queue ... ok
test admin_http::tests::admin_http_listener_serves_error_log_received_from_runtime_queue ... ok
test tests::http_access_logs_require_session_and_omit_raw_path ... ok
test tests::http_error_logs_return_recent_errors ... ok
test admin_http::tests::admin_http_listener_serves_recent_logs_over_tcp ... ok
test admin_http::tests::admin_http_listener_serves_certificates_over_tcp ... ok
test tests::product_access_log_excludes_sensitive_request_material_and_includes_revision ... ok
test tests::process_start_product_log_records_bootstrap_fields_without_secret_values ... ok
test tests::certificate_expiry_metric_omits_domain_and_private_key ... ok
test tests::http_certificate_list_masks_private_keys_and_marks_expiry ... ok
test tests::file_certificate_store_writes_private_key_owner_only ... ok
test tests::rustls_server_config_loader_rejects_invalid_private_key_without_panic ... ok
docker compose smoke passed
mvp smoke passed
```

Attach or reference:

- `scripts/collect_release_evidence.sh` output directory
- full command transcript
- operating system and architecture
- Docker version, if Docker Compose smoke was run
- any non-fatal browser or Docker warnings observed during smoke
- confirmation that `.tasks/` remained ignored and untracked
- confirmation that automatic `environment.txt` contains `release_id` matching
  the evidence directory basename
- confirmation that automatic `environment.txt` contains `utc_started_at` in
  `YYYYMMDDTHHMMSSZ` format
- confirmation that automatic `environment.txt` contains a non-empty
  `build_or_commit`
- confirmation that final release readiness uses a concrete `build_or_commit`,
  not `not-recorded`
- confirmation that automatic `summary.md` contains `Build/Commit` matching
  automatic `environment.txt` `build_or_commit`
- confirmation that required automatic `environment.txt` keys appear exactly once
- confirmation that automatic `status.env` exit-code keys appear exactly once
- confirmation that the `summary.md` Automatic Gates table reports exit code
  `0` for `./scripts/check_release_docs.sh`, `./scripts/check.sh`, and
  `./scripts/smoke_mvp.sh`, matching `status.env`
- confirmation that `test_command_overrides_used` and
  `test_command_overrides_allowed` are both `false` in the collector summary
  and `environment.txt`
- confirmation that the collector summary does not include override `true` values
  or smoke-only release evidence warnings
- confirmation that required snippets are matched from current automatic gate
  transcripts with source-specific provenance, not stale files already present
  in the evidence directory
- confirmation that `snippet-check.txt` claims are rejected when the matching
  text is missing from the expected current automatic gate transcript
- confirmation that any `missing in <log>` line in `snippet-check.txt` rejects
  the automatic release evidence
- confirmation that pre-existing required output paths are not symlink files
  before collection writes transcripts
- confirmation that the automatic evidence directory tree contains no symlinks
- confirmation that the automatic evidence directory contains only known collector output files
  and rejects unknown or stale paths
- confirmation that local manual-preflight evidence is present for static Admin
  Web UI, minimal config parsing, data directory layout, and Docker Compose
  runtime smoke

## Supplemental Manual Evidence

These checks are operator/reviewer walkthroughs. They are not separate MVP
blockers when the automatic evidence collector contains the required snippets
for static Admin Web UI, Docker Compose runtime smoke, data directory layout,
and minimal config parsing. Fill them in only when a release reviewer requires
separate human inspection.

### Static Admin Web UI Inspection

```text
performed:
required_by_reviewer:
viewport_or_browser:
result:
notes:
```

### Docker Compose Demo

```text
performed:
required_by_reviewer:
compose_file:
result:
service_url:
notes:
```

### Data Directory Layout

```text
performed:
required_by_reviewer:
data_dir:
config_current_present:
revision_store_present:
cert_store_present:
secret_store_present:
log_dir_present:
notes:
```

### Minimal Config Review

```text
performed:
required_by_reviewer:
config_file:
schema_version:
http_listener:
admin_bind:
routes:
services:
notes:
```

## Post-MVP External Manual Gate

### Let's Encrypt Staging

Follow `docs/acme-staging.md` when the deferred Let's Encrypt work resumes. Do
not mark this gate as passed unless an approved public test domain was used.
This section is not required for MVP completion.
Store the external-run evidence under `artifacts/acme-staging-evidence/RELEASE_ID`
and validate it with `scripts/check_acme_staging_evidence.sh` before sign-off.
Use `scripts/init_acme_staging_evidence.sh` to initialize the required file
layout before the external run; the initialized pending files are not valid
evidence until replaced with real command output.
The evidence checker requires the Let's Encrypt staging directory, a public
non-reserved target, `known_token_checked: true`, `https_checked: true`, and no
private key, authorization header, cookie, or session material in the evidence.
It rejects contradictory preflight markers such as `production_acme_used: true`,
`terms_accepted: false`, `unknown_token_result: 200`,
`known_token_checked: false`, or `https_checked: false`.
The approved test domain may contain only hostname letters, numbers, dot, and
dash; the public target may contain only letters, numbers, dot, colon, and dash.
It also requires a real `letsencrypt_staging` Admin API issue source and rejects
`fake-acme-*` sources. The Admin API issue response must be a valid JSON object
and include matching top-level field-value pairs for `request_id`,
`certificate_ref`, `domains`, `source=letsencrypt_staging`, and numeric
`not_after_epoch_seconds`; `request_id` must equal `metadata.env`
`admin_api_request_id`; values that
appear only in a nested object, message, or note field do not satisfy this gate. The evidence directory basename must equal
`metadata.env` `release_id`; `scripts/init_acme_staging_evidence.sh` enforces the same basename rule for custom
`SPONZEY_STAGING_EVIDENCE_DIR` paths and refuses pre-existing required evidence
files, any pre-existing symlink inside the evidence tree, or any unknown/stale
path outside the fixed evidence filenames before creating new pending files
unless overwrite is explicitly enabled.
The checker uses `python3` to parse JSON evidence files. The product log excerpt
must contain only valid JSON object lines and include exactly one structured JSON object product log line
with matching field-value pairs for `event=certificate.issue.success`,
`component=admin-api`, `revision_id` equal to `metadata.env`
`config_revision_after`, `certificate_ref` equal to the selected certificate
reference, and `request_id` equal to the `admin_api_request_id` from
`metadata.env`, and `status_code=200`. The `admin_api_request_id` must be the
stable `X-Request-Id` supplied on the authenticated Admin API certificate issue
request. Use the product log line emitted by that request, not an audit event or
hand-written summary. Values that appear only in a message or note field do not
satisfy this gate.
Each required `metadata.env` key must appear exactly once; duplicate metadata
keys are rejected.
The checker requires non-empty `config_revision_after` and requires the metadata
file references to equal the fixed evidence filenames:
`challenge-curl.log`, `https-curl.log`, `preflight.log`, and
`product-log-excerpt.log`.
The ACME staging evidence directory tree must contain no symlinks and only the fixed evidence filenames plus the initializer `README.md`; a symlinked evidence
directory, required evidence file, non-required symlink, unknown file, stale
file, or nested path inside the evidence tree is rejected before content
validation.
Metadata identity values must use stable characters: `release_id` may contain
only letters, numbers, dot, underscore, and dash; `build_or_commit`,
`certificate_ref`, `admin_api_request_id`, `config_revision_before`, and
`config_revision_after` may contain only letters, numbers, dot, underscore,
colon, and dash. External ACME staging evidence rejects
`build_or_commit=not-recorded`; use the same concrete build id as the automatic
release evidence. The top-level Admin API issue response `request_id` must equal
`metadata.env` `admin_api_request_id`.
The challenge curl evidence must include HTTP `200`, the approved test domain,
and the `/.well-known/acme-challenge/` path. The HTTPS curl evidence must
include the approved test domain, TLS handshake or certificate evidence, and a
successful or redirect HTTPS response. It must also include `Let's Encrypt` and
`(STAGING)` issuer text.

```text
performed:
release_id:
build_or_commit:
approved_test_domain:
dns_record_type:
public_ip_or_target:
acme_directory:
production_acme_used: false
terms_accepted:
certificate_ref:
admin_api_request_id:
issue_request_header: X-Request-Id used on the Admin API issue request
config_revision_before:
config_revision_after:
challenge_curl_result:
https_curl_result:
acme_staging_preflight_output_ref:
product_log_excerpt_ref:
acme_staging_evidence_check:
post_mvp_acme_readiness_check:
notes:
```

Required statements:

```text
HTTP-01 challenge was served by the runtime HTTP listener.
Unknown HTTP-01 token returned 404.
Certificate issue went through authenticated Admin API with CSRF.
Admin API issue request used X-Request-Id matching metadata.env admin_api_request_id.
Private key PEM was not included in API responses, logs, or diffs.
Previous runtime snapshot and current revision were preserved on failure, if a failure occurred.
```

## Known Limits Accepted For This Release

Record only limits already documented in `docs/release-gate.md` and
`docs/current-state.md`.

```text
advanced_balancing_deferred:
post_mvp_external_acme_staging:
remote_metrics_and_retention_deferred:
```

## Review Sign-off

```text
automatic_gates_verified_by:
post_mvp_external_acme_verified_by:
security_reviewed_by:
release_approved_by:
approval_utc:
```

## Rejection Criteria

Reject the release if any of the following are true:

- `./scripts/smoke_mvp.sh` did not pass on the release build.
- `./scripts/check_release_docs.sh` did not pass.
- Post-MVP only: `./scripts/check_acme_staging_evidence.sh` did not pass for
  the external staging evidence directory when claiming Let's Encrypt readiness.
- Post-MVP only: `./scripts/check_mvp_release_ready.sh` did not pass for the
  automatic and external ACME staging evidence directories when claiming
  Let's Encrypt readiness.
- Post-MVP only: automatic evidence and ACME staging evidence are the same physical evidence
  directory, including when one path is a symlink alias of the other.
- Post-MVP only: automatic evidence and ACME staging evidence use different `RELEASE_ID`
  basenames.
- Post-MVP only: ACME `metadata.env` `release_id` or `build_or_commit` does not match the
  automatic release evidence.
- Post-MVP only: automatic or ACME staging `build_or_commit` is `not-recorded`
  during combined ACME readiness.
- automatic `environment.txt` `release_id` does not match its evidence
  directory basename.
- automatic `environment.txt` omits `utc_started_at` or uses a value outside
  `YYYYMMDDTHHMMSSZ` format.
- automatic `environment.txt` omits `build_or_commit`.
- automatic `summary.md` Automatic Gates table is missing any required gate row
  with exit code `0` matching `status.env`.
- automatic `summary.md` omits `Build/Commit` matching automatic
  `environment.txt` `build_or_commit`.
- release evidence omits command output for an automatic gate.
- automatic required snippets are satisfied only by stale files outside the
  current automatic gate transcripts.
- `snippet-check.txt` claims a required snippet is present but the matching text
  is absent from the expected transcript among `check_release_docs.log`,
  `check.log`, and `smoke_mvp.log`.
- `snippet-check.txt` contains any `missing in <log>` marker.
- a pre-existing required automatic output path is a symlink before collection.
- the automatic release evidence directory tree contains any symlink.
- the automatic release evidence directory contains any unknown or stale path
  outside the collector's known output filenames.
- the ACME staging evidence directory tree contains any symlink.
- the ACME staging evidence directory contains any unknown or stale path outside
  the fixed evidence filenames and initializer `README.md`.
- collector output has `test_command_overrides_used` set to `true`.
- collector output has `test_command_overrides_allowed` set to `true`.
- external Let's Encrypt staging is marked passed without an approved public
  test domain.
- external staging evidence contains a `fake-acme-*` issue source instead of
  `letsencrypt_staging`.
- external staging Admin API issue response omits matching field-value pairs for
  `certificate_ref`, `domains`, `source=letsencrypt_staging`, or numeric
  `not_after_epoch_seconds`.
- external staging product log evidence omits one structured success event line
  containing matching `event`, `component=admin-api`,
  `revision_id=<config_revision_after>`, `certificate_ref`, `request_id`, and
  `status_code=200` field-value pairs for `certificate.issue.success`, the
  selected certificate reference, and the matching `admin_api_request_id`.
- external staging evidence contains certificate/private key PEM material,
  certificate PEM JSON fields, authorization material, cookie material, or
  bearer/basic token strings in required, non-required, or hidden evidence
  files.
- external staging metadata omits `config_revision_after` or points an evidence
  file reference at a filename other than the fixed evidence filename.
- any required external staging evidence file is a symlink instead of a regular
  file in the evidence directory.
- external staging evidence contains an unknown file, stale file, or nested path
  outside the fixed evidence filenames and initializer `README.md`.
- production ACME was used for the staging gate.
- any log, API response, or diff contains a private key, authorization header,
  cookie, request body, response body, or full query string.
- any required, non-required, or hidden evidence file contains JSON
  `authorization`, `cookie`, or `set-cookie` keys, or bearer/basic token
  strings.
- ACME staging sensitive-material rejection echoes the matched secret-bearing
  evidence line into terminal output.
- `.tasks/` is tracked by git.
