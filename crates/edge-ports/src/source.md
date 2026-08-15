# Edge ports

This crate defines dependency-inverted contracts for adapters and application/runtime boundaries.

| Path | Responsibility | Boundary / side effects |
| --- | --- | --- |
| `lib.rs` | Repository, command, metrics, runtime status, support-bundle, and external-service traits. | Contains only typed contracts; implementations live in adapters or process wiring. |

Operational readiness uses `OperationalRuntimeStatusPublisher` and
`OperationalRuntimeStatusReader`: Core publishes listener-registration facts once,
and Admin consumes them read-only.

`OfflineUpgradeDeployment`, `OfflineUpgradeCommandRunner`, and
`OfflineUpgradeJournalStore` receive validated upgrade identity, a root-owned local artifact
path, and a passphrase-file reference only. They cannot receive arbitrary argv, environment values, a passphrase value,
or direct Core/Admin state.

`SupportBundleCollector` accepts only a closed artifact allowlist and returns typed,
secret-free omission metadata plus bounded size and log-age facts. It never carries paths,
raw logs, headers, cookies, query strings, request/response bodies, or secret values.
