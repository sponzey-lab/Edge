# Test and release shell entrypoints

This directory contains thin, fail-closed shell entrypoints for test/release evidence. They invoke
only source-controlled `edge-memory-harness` binaries and do not alter the product runtime.

| Path | Responsibility | Boundary / Side effects |
| --- | --- | --- |
| `run_diagnostic_soak.sh` | Forwards explicit attached-process diagnostics to the fixed two-hour soak runner. | Builds/runs the test harness; CLI rejects missing, duplicate, or unsupported arguments. |
| `collect_phase011_memory_release.sh` | Forwards explicit evidence paths to the Phase 011 release collector. | Builds/runs the test harness; collection rejects invalid, stale, or unsafe inputs. |
| `check_phase011_memory_release.sh` | Forwards report validation to the Phase 011 release validator. | Builds/runs the test harness; validation is read-only over the supplied report/digest pair. |
