# Edge domain model

This directory contains the pure Sponzey Edge domain model. It has no network,
filesystem, process, TLS, API, or UI dependency; adapters supply facts through
application and port boundaries.

| Path | Responsibility | Boundary / Side effects |
| --- | --- | --- |
| `lib.rs` | Shared configuration, routing, error, resource, and command value contracts. | Pure values and validation only. |
| `audit.rs` | Audit identifiers, record/query contracts, and operation-state transitions. | Pure validation and value transitions; no ledger, clock, or external I/O. |
| `backup.rs` | Backup manifest/artifact contracts and schema validation. | Pure archive inventory and restore-safety policy; no filesystem, crypto, or external I/O. |
| `operational_lifecycle.rs` | Safe liveness/readiness facts, runtime-fact value contract, and process lifecycle transitions. | Does not own signals, clocks, listeners, or process shutdown. |
| `operational_upgrade.rs` | Validated offline-upgrade identity, local artifact/passphrase-file references, transition state, and recovery-journal values. | Contains path references only; never contains, reads, or logs a secret value. |
| `support_bundle.rs` | Closed support-bundle artifact and omission allowlists, bounded collection policy, and published-archive receipt. | Pure policy; receipt exposes only identity, digest, and redaction fact; it cannot represent paths, secret values, request/response bodies, headers, cookies, queries, or unbounded collection. |
| `backup/` | Backup and restore domain contracts. | Pure archive lifecycle and validation rules. |
| `audit/` | Audit record and verification domain contracts. | Pure integrity and operation-state rules. |
