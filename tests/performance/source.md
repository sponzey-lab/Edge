# Performance test boundary

This boundary contains long-lived Compose performance tooling around the production Edge image. It is
not a Rust workspace member and its outputs do not become runtime policy or Phase 011 memory evidence.

| Path | Responsibility | Boundary / Side effects |
| --- | --- | --- |
| `contract/compose-contract.test.mjs` | Verifies Compose service, exposure, and pinned-image contracts. | Invokes Docker Compose configuration only. |
| `node-upstream/` | Deterministic upstream application and dashboard. | See [`node-upstream/source.md`](node-upstream/source.md); no Edge config mutation. |
| `k6/` | Versioned functional and performance workloads. | One-shot load process; targets Edge only. |
| `config/` | Non-secret Edge test configuration and PKI generation profile. | Generated keys and runtime values stay outside source control. |
| `results/` | Small approved baseline schemas and fixtures. | Raw run data remains under ignored `artifacts/performance/`. |
