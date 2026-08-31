# Edge application

This crate orchestrates domain rules through typed ports and does not perform concrete I/O.

| Path | Responsibility | Boundary / side effects |
| --- | --- | --- |
| `backup.rs` | Backup, verify, restore, and recovery use cases. | Uses lock/archive/log ports only. |
| `access_observability.rs` | Access-log projection and bounded-label request metrics. | Uses typed log and metrics ports only; excludes request body, headers, and Product-mode path data. |
| `audit.rs` | Audit operation orchestration, admission, query, and security-observation use cases. | Uses typed audit ports only; preserves append/terminal ordering and does not access concrete ledger I/O. |
| `config_apply_policy.rs` | Immutable config diff, restart classification, and atomic Core apply-command planning policy. | Pure domain configuration logic; hot applies emit one `ApplyConfigSnapshot` command so revision activation is not split across acknowledgements; neither persists nor sends commands. |
| `config_command_dispatch.rs` | Ordered bounded Core-command acknowledgement dispatch for config activation plans. | Uses only the typed Core command port; does not validate, persist revisions, audit, execute runtime I/O, or mutate configuration. |
| `config_revision_record.rs` | Immutable config snapshot projection into typed revision repository records. | Creates revision metadata and checksums from supplied values only; does not validate, persist, select current revisions, audit, perform I/O, or access environment state. |
| `config_validation_error.rs` | Stable validation error-list to application-error projection. | Converts supplied typed errors only; does not validate config, persist revisions, audit, perform I/O, or access environment state. |
| `config_validation.rs` | Config source/snapshot validation and stable validation-error report. | Pure configuration policy; validates compatibility and safety without I/O, runtime mutation, or certificate issuance/renewal. |
| `config_rendering.rs` | Canonical MVP config snapshot rendering. | Pure immutable snapshot-to-text conversion; neither parses nor reads/writes configuration files. |
| `config_scalar_parser.rs` | Primitive quoted-string, array, numeric, and boolean decoding for MVP config input. | Pure in-memory scalar conversion with stable config errors; no file/environment/network I/O or secret logging. |
| `mvp_config_parser.rs` | Canonical MVP config source output, draft representation, section/value parsing, and normalization. | Pure in-memory snapshot construction with stable defaults and errors; does not read/write files, access environment state, issue certificates, or perform I/O. |
| `http_route_action.rs` | HTTP proxy/redirect/not-found action selection and challenge-bypass precedence. | Pure immutable snapshot read; does not issue certificates, mutate routing/configuration, perform I/O, or access environment state. |
| `health.rs` | Health generation, probe scheduling, and reconciliation. | Uses supplied health-probe ports only; Field Debug, transition, and runtime-metric projection live in dedicated modules. |
| `health_runtime_coordinator.rs` | Dispatcher-facing health activation, tick, completion, and shutdown lifecycle. | Composes the health supervisor through the supplied probe-dispatch port; does not own worker I/O, clocks, observability policy, or runtime configuration. |
| `drain.rs` | Upstream drain generation, lease tracking, and runtime-status projection. | Pure typed snapshot/status coordination; does not own sockets, clocks, or runtime I/O. |
| `failure_observability.rs` | Bounded TLS failure sampling and fixed-label observability projection. | Produces secret-free supplied-event logs/metrics without transport, health scheduling, or runtime I/O. |
| `health_probe_observability.rs` | Field Debug health-probe log projection and bounded sampler. | Converts supplied probe outcomes to secret-free structured logs with a fixed 60-second/key sampling boundary; no scheduling, reconciliation, runtime I/O, or certificate automation. |
| `health_transition_observability.rs` | Health state-transition event and bounded log/metric projection. | Converts supplied state changes to secret-free structured logs and fixed-label metrics; no scheduling, reconciliation, runtime I/O, or certificate automation. |
| `health_runtime_metrics.rs` | Availability, selection, and dropped-health-result metric projection. | Produces fixed descriptors and bounded labels from supplied health state/results; no scheduling, reconciliation, runtime I/O, or certificate automation. |
| `http01_challenge_state.rs` | Legacy HTTP-01 challenge token state and cleanup runtime. | Uses only supplied typed challenge-store/probe ports; does not create ACME orders, issue/renew/install certificates, access concrete I/O, or enable certificate automation. |
| `failure_policy_normalization.rs` | Retry and passive-health config draft normalization. | Pure snapshot policy conversion through domain constructors; no probe dispatch, upstream I/O, persistence, or certificate automation. |
| `config_lifecycle.rs` | Config revision apply and rollback orchestration. | Uses typed revision, audit, and bounded Core command ports; persists current revision only after accepted commands. |
| `certificate_import_state.rs` | Manual certificate import values, input normalization, and compensation state machine. | Pure input/state validation; does not load, store, install, or log certificate material. |
| `certificate_issuance.rs` | Legacy certificate issuance, optional HTTP-01 challenge cleanup, and Core installation orchestration. | Uses supplied typed certificate, audit, challenge, and Core ports only; preserves compatibility but does not schedule, enable, or expand certificate automation. |
| `certificate_status_decision.rs` | Certificate status projection and renewal due/skip/retry decisions. | Pure in-memory decision logic over stored metadata and error codes; does not issue, renew, install, persist, audit, or log certificate material. |
| `manual_certificate_import.rs` | Manual certificate validation, store/audit, Core install, and failure compensation use case. | Uses typed certificate, audit, and Core ports only; preserves the primary error and separately returns compensation failure. |
| `metrics.rs` | Bounded in-memory metric registry, reconciliation, and rendering. | Owns supplied metric state only; does not open listeners, scrape network data, or access environment state. |
| `operational_upgrade.rs` | Offline upgrade preflight, journaled transitions, receipt, rollback, and interrupted recovery. | Uses typed deployment/journal ports only; returns secret-free operation identity/state and has no direct data/Core/Admin mutation or secret value. |
| `observability_buffer.rs` | Bounded request ID, structured-log, access-log, and error-log in-memory state. | Retains values only; no log sink, file, network, or runtime I/O. |
| `operational_events.rs` | Secret-free config, certificate, and admin-auth operational event projection. | Uses typed audit port only for recording; no concrete log/audit I/O or certificate material. |
| `passive_health.rs` | Passive upstream health supervision and delivery-state transitions. | Pure supplied observation/config state coordination; does not dispatch probes, open sockets, or mutate Core directly. |
| `proxy_host_config.rs` | Proxy-host-to-config conversion and immutable route/service snapshot updates. | Pure domain configuration logic; neither persists nor sends commands. |
| `resource_observability.rs` | Bounded resource-pressure log and metric projection. | Converts supplied resource policy/state to secret-free observability only; does not allocate resources or perform runtime I/O. |
| `runtime_metrics.rs` | Runtime-state and failure metric projection. | Pure metric values with bounded labels; does not record metrics or expose certificate domain/key data. |
| `support_bundle.rs` | Bounded support-bundle collection use case. | Calls only the typed collector port and fail-closes unrequested/duplicate artifacts, invalid log metadata, and bound violations. |
| `trust.rs` | Trust-bundle import/list/delete validation and retained-revision protection use cases. | Uses typed trust store/validation/event ports; never exposes trust material or accesses concrete I/O. |
| `upstream_tls.rs` | Typed upstream TLS preparation requirement planning. | Pure snapshot validation and requirement projection; does not build TLS sessions, read stores, or perform I/O. |
| `startup_config.rs` | Startup revision-or-seed resolution use case and explicit state machine. | Selects persisted revision before an optional bootstrap seed through typed revision, seed, and preflight ports; no direct I/O. |
| `lib.rs` | Public application use-case exports and application policy composition. | Pure orchestration and validation; config source parsing belongs to `mvp_config_parser.rs`. |
