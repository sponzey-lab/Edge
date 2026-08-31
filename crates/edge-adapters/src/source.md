# Edge adapters

This crate implements external I/O behind `edge-ports`; it must not move blocking
filesystem, process, or service-manager work into the Core event loop.

| Path | Responsibility | Boundary / side effects |
| --- | --- | --- |
| `data_directory_lock.rs` | Exclusive ownership lock for one configured data directory. | Canonicalizes the configured filesystem target, holds an advisory OS file lock, and preserves typed lock state/error outcomes. |
| `audit_ledger.rs` | File-backed append-only audit ledger adapter and integrity verification. | Persists and verifies typed audit records through bounded filesystem I/O; does not decide audit policy or mutate application state. |
| `backup.rs` | Encrypted backup/archive, restore transaction, and backup support adapters. | Owns bounded filesystem/archive/crypto I/O behind typed ports; does not decide backup policy or expose secrets. |
| `file_secret_store.rs` | File-backed secret-store port adapter. | Owns secret-name-to-file mapping and owner-only atomic persistence through shared file helpers; preserves typed errors and never logs or exposes secret values. |
| `file_revision_repository.rs` | File-backed config revision repository and bootstrap-seed adapters. | Owns revision/current-marker file layout and seed reads through typed ports; preserves revision format and typed errors without changing config policy, lifecycle, Core state, or certificate automation. |
| `file_trust_bundle_store.rs` | File-backed trust-bundle store identity and path mapping. | Maps typed references to the configured root only; concrete read/write/delete operations retain their existing trust-store security boundary. |
| `health_probe_tls_registry.rs` | Prepared outbound TLS session factories for health probe transport. | Holds only caller-prepared typed TLS factories and creates client sessions by upstream health key; does not open sockets, schedule probes, access files, or issue/renew certificates. |
| `health_probe_worker_pool.rs` | Bounded health-probe work queue, completion handoff, and worker shutdown lifecycle. | Owns worker threads and supplied probe transport calls outside the Core loop; does not schedule policy, access environment/files, or mutate health/Core state. |
| `health_probe_transport.rs` | Synchronous HTTP/HTTPS health-probe transport. | Owns bounded socket I/O, TLS handshake/session pumping, and HTTP response-header decoding for a supplied probe request; does not schedule probes, modify health policy/Core state, access stores, or issue/renew certificates. |
| `metrics_runtime.rs` | Loopback Prometheus listener, bounded collector, renderer, and channel publisher. | Owns bounded TCP scrape handling and worker lifecycle; validates loopback bind, exposes no secrets, and does not enter the Core event loop. |
| `operational_upgrade.rs` | Fixed-format upgrade journal, typed command mapper, and fixed systemd/Compose helper process runners. | Performs bounded no-follow file I/O and invokes only packaged absolute helper paths with allowlisted artifact/path and fixed Compose project/file arguments, fixed PATH, cleared environment, and bounded UTF-8 output; never stores a secret or accepts arbitrary argv/environment. |
| `support_bundle.rs` | Fixed-layout support archive collector. | Writes only allowlisted regular files into a private tar archive; rejects unsafe output paths and sensitive content, omits symlinks/missing/bound-exceeding files, and returns a digest-backed redaction receipt. |
| `structured_log_json.rs` | Structured-log JSON line rendering and string escaping. | Pure supplied-event conversion; does not write to a sink, access environment state, or add log fields/secret values. |
| `trust_bundle_metadata_codec.rs` | Trust-bundle metadata parser and digest rendering codec. | Pure supplied metadata conversion with typed store errors; does not access files, validate certificate material, mutate trust policy, or expose material values. |
| `trust_bundle_safe_file.rs` | Owner-only atomic write and no-follow trust-bundle file operations. | Concrete bounded file I/O with typed store errors; rejects unsafe paths/permissions and does not parse metadata, validate certificate material, or expose it. |
| `lib.rs` | Public adapter exports, concrete sink I/O, and shared file helpers. | Concrete I/O boundary; `JsonLineLogSink` delegates JSON rendering to `structured_log_json.rs`, and callers depend on typed port traits. |
