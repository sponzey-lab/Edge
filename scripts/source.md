# Test and release shell entrypoints

This directory contains thin, fail-closed shell entrypoints for test/release evidence. They invoke
only source-controlled `edge-memory-harness` binaries and do not alter the product runtime.

| Path | Responsibility | Boundary / Side effects |
| --- | --- | --- |
| `run_diagnostic_soak.sh` | Forwards explicit attached-process diagnostics to the fixed two-hour soak runner. | Builds/runs the test harness; CLI rejects missing, duplicate, or unsupported arguments. |
| `collect_phase011_memory_release.sh` | Forwards explicit evidence paths to the Phase 011 release collector. | Builds/runs the test harness; collection rejects invalid, stale, or unsafe inputs. |
| `check_phase011_memory_release.sh` | Forwards report validation to the Phase 011 release validator. | Builds/runs the test harness; validation is read-only over the supplied report/digest pair. |
| `smoke_memory_evidence.sh` | Builds the fixed performance release composition and publishes the idle evidence report/digest. | Requires a Linux Docker host; creates only a caller-named new output directory and removes its dedicated Compose services on exit. |
| `source_identity.sh` | Computes the stable source-tree identity used by Phase 011 report, manifest, and aggregate adapters. | Reads only Git-tracked or non-ignored source paths, excluding `.env`, task, artifact, and build outputs; does not change product runtime state. |
| `steady_http_upstream.py` | Runs the bounded 128-worker loopback upstream fixture for steady profiles. | Test-only local listener; no product data or configuration access. |
| `smoke_http_steady_memory.sh` | Runs the exact 100,000-request HTTP steady scenario and publishes its four manifest inputs. | Starts isolated local test processes with bootstrap-only configuration and removes them on exit. |
| `smoke_https_steady_memory.sh` | Runs the exact 50,000-request private-PKI HTTPS steady scenario and publishes its four manifest inputs. | Creates ephemeral private test PKI and isolated local test processes; credentials never enter published evidence. |
| `smoke_mtls_steady_memory.sh` | Runs the exact 25,000-request required-mTLS steady scenario and publishes its four manifest inputs. | Creates ephemeral private test PKI/trust data and isolated local test processes; credentials never enter published evidence. |
| `collect_memory_evidence_manifest.sh` | Collects and independently validates one exact three-scenario partial steady manifest. | Reads one explicit profile directory and publishes only its caller-selected manifest bundle. |
| `collect_memory_evidence_aggregate.sh` | Collects, validates, and inspects the canonical three-run steady aggregate. | Reads one explicit runs root and publishes only its caller-selected aggregate bundle. |
| `run_three_steady_memory_profiles.sh` | Performs three independent steady profiles and their final canonical aggregate. | Requires a new artifact root; fails closed on source identity change or any child failure. |
| `smoke_connection_capacity.sh` | Holds exactly 1,024 HTTP connections, validates held and released evidence, and publishes the full-profile idle report/digest. | Requires a sufficient file-descriptor limit; starts only isolated local test processes and cleans them up. |
