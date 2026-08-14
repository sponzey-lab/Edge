# Performance test boundary

This boundary contains long-lived Compose performance tooling around the production Edge image. It is
not a Rust workspace member and its outputs do not become runtime policy or Phase 011 memory evidence.

| Path | Responsibility | Boundary / Side effects |
| --- | --- | --- |
| `contract/compose-contract.test.mjs` | Verifies Compose service, exposure, and pinned-image contracts. | Invokes Docker Compose configuration only. |
| `contract/edge-perf.integration.test.mjs` | Verifies release Edge HTTP Host routing, trusted HTTPS/SNI, malformed/body-limit responses, and configured upstream-read 504 behavior. | Recreates only performance services after explicit PKI preparation and sends no request body or credentials. |
| `bin/prepare-pki-runtime.mjs` | Generates and deletes fixed-SAN PKI, Edge certificate-store seed, and client trust at an explicit artifact path. | Requires `artifacts/performance/`, keeps private keys owner-only, and never prints PEM material. |
| `bin/run.mjs` | Runs fixed profiles and host-side Edge CPU/memory sampling through the explicit fail-closed lifecycle. | Uses host Docker CLI only; raw summary, metadata, and samples are written atomically under ignored `artifacts/performance/`. |
| `bin/summary.mjs` | Normalizes k6 RPS/latency/error/bytes evidence and compares the three baseline runs. | Rejects missing metrics or any failed k6 gate before artifact publish. |
| `node-upstream/` | Deterministic upstream application and dashboard. | See [`node-upstream/source.md`](node-upstream/source.md); no Edge config mutation. |
| `k6/` | Versioned smoke plus fixed baseline (1m+5m), stress step-up, and 30m soak workloads. | One-shot load process; targets Edge only; its runtime credential is a read-only Compose secret. |
| `config/` | Non-secret Edge test configuration, including literal-upstream Host/prefix/exact/priority route fixtures, and PKI generation profile. | Generated keys and runtime values stay outside source control. |
| `results/` | Small approved baseline schemas and fixtures. | Raw run data remains under ignored `artifacts/performance/`. |
