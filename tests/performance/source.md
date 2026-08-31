# Performance test boundary

This boundary contains long-lived Compose performance tooling around the production Edge image. It is
not a Rust workspace member and its outputs do not become runtime policy or Phase 011 memory evidence.

| Path | Responsibility | Boundary / Side effects |
| --- | --- | --- |
| `contract/compose-contract.test.mjs` | Verifies Compose service, exposure, pinned-image, and default/explicit loopback dashboard host-port contracts. | Invokes Docker Compose configuration only with a test-owned default dashboard port, so ignored local host metadata cannot alter source contracts. |
| `contract/edge-perf.integration.test.mjs` | Verifies release Edge HTTP Host routing, trusted HTTPS/SNI, malformed/body-limit responses, and configured upstream-read 504 behavior. | Recreates only performance services after explicit PKI preparation and sends no request body or credentials. |
| `bin/prepare-pki-runtime.mjs` | Generates and deletes fixed-SAN PKI, Edge certificate-store seed, and client trust at an explicit artifact path. | Requires `artifacts/performance/`, keeps private keys owner-only, and never prints PEM material. |
| `bin/run.mjs` | Runs fixed profiles and host-side Edge CPU/memory sampling through the explicit fail-closed lifecycle. | Dry-runs are side-effect free; real runs reject a dirty Git worktree before creating artifacts, preparing PKI, building images, or starting Compose services, then bind the verified commit/tree identity. Uses host Docker CLI only; runs k6 as the host UID to write its private result directory, and fails with bounded diagnostics if a summary is absent. |
| `bin/summary.mjs` | Normalizes k6 RPS/latency/error/bytes and Edge CPU/memory trend evidence; compares three baseline runs. | Rejects missing metrics, failed k6 gates, or invalid resource samples before artifact publish. |
| `bin/audit.mjs` | Validates a completed artifact's state, identity, profile summary, and resource evidence before reuse. | Refuses `*.partial` and inconsistent evidence; reads ignored artifacts only. |
| `node-upstream/` | Deterministic upstream application and dashboard. | See [`node-upstream/source.md`](node-upstream/source.md); no Edge config mutation. |
| `k6/` | Versioned smoke plus fixed baseline (1m+5m), stress step-up, and 30m soak workloads. | One-shot load process; targets Edge only; its runtime credential is a read-only Compose secret. |
| `config/` | Non-secret Edge test configuration, including literal-upstream Host/prefix/exact/priority route fixtures, and PKI generation profile. | Generated keys and runtime values stay outside source control. |
| `results/` | Small approved baseline schemas and fixtures. | Raw run data remains under ignored `artifacts/performance/`. |
