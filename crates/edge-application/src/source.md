# Edge application

This crate orchestrates domain rules through typed ports and does not perform concrete I/O.

| Path | Responsibility | Boundary / side effects |
| --- | --- | --- |
| `backup.rs` | Backup, verify, restore, and recovery use cases. | Uses lock/archive/log ports only. |
| `operational_upgrade.rs` | Offline upgrade preflight, journaled transitions, receipt, rollback, and interrupted recovery. | Uses typed deployment/journal ports only; returns secret-free operation identity/state and has no direct data/Core/Admin mutation or secret value. |
| `support_bundle.rs` | Bounded support-bundle collection use case. | Calls only the typed collector port and fail-closes unrequested/duplicate artifacts, invalid log metadata, and bound violations. |
| `lib.rs` | Public application use-case exports and config policy. | Pure orchestration and validation. |
