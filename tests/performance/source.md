# Performance test boundary

This boundary contains long-lived Compose performance tooling around the production Edge image. It is
not a Rust workspace member and its outputs do not become runtime policy or Phase 011 memory evidence.

| Path | Responsibility | Boundary / Side effects |
| --- | --- | --- |
| `contract/compose-contract.test.mjs` | Verifies Compose service, exposure, and pinned-image contracts. | Invokes Docker Compose configuration only. |
| `contract/edge-perf.integration.test.mjs` | Verifies release Edge HTTP Host routing and trusted HTTPS/SNI routing to the fixed Node upstream. | Recreates only performance services after explicit PKI preparation and sends no request body or credentials. |
| `bin/prepare-pki-runtime.mjs` | Generates and deletes fixed-SAN PKI, Edge certificate-store seed, and client trust at an explicit artifact path. | Requires `artifacts/performance/`, keeps private keys owner-only, and never prints PEM material. |
| `node-upstream/` | Deterministic upstream application and dashboard. | See [`node-upstream/source.md`](node-upstream/source.md); no Edge config mutation. |
| `k6/` | Versioned functional/performance workloads, including Admin lifecycle and the 30-second HTTP/HTTPS/WebSocket/header/POST smoke profile. | One-shot load process; targets Edge only; its runtime credential is a read-only Compose secret. |
| `config/` | Non-secret Edge test configuration, including literal-upstream Host/prefix/exact/priority route fixtures, and PKI generation profile. | Generated keys and runtime values stay outside source control. |
| `results/` | Small approved baseline schemas and fixtures. | Raw run data remains under ignored `artifacts/performance/`. |
