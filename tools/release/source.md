# Release tooling boundary

Release tooling validates package metadata and later assembles release-only artifacts. It is outside
the Sponzey Edge runtime dependency graph and must not read runtime secrets or mutate product data.

| Path | Responsibility | Boundary / Side effects |
| --- | --- | --- |
| `validate_release_metadata.py` | Validates canonical repository, exact SemVer tag, package version, and pinned Rust toolchain. | Reads supplied release metadata and writes one safe JSON result or stable error code. |
| `check_architecture.py` | Validates declared product-layer dependencies, bootstrap-only environment reads, and documented unsafe invariants. | Reads only the supplied workspace source and manifests; emits a stable pass result or boundary error codes without modifying product data. |
| `check_source_indexes.py` | Validates that a `source.md` index names each direct Rust source file exactly once and no stale direct Rust path. | Reads only source indexes and direct Rust filenames; emits stable structural error codes without modifying product data. |
| `test_check_source_indexes.py` | Deterministic fixture tests for the source-index validator. | Uses temporary source trees only; does not inspect or modify product data. |
| `validate_promotion_evidence.py` | Validates that one candidate's tracked evidence covers source quality, private-PKI scope, support bundle, and every clean-host matrix cell. | Reads one supplied JSON document and explicit immutable identities; fails closed without GitHub or product-data access. |
| `validate_release_manifest.py` | Validates the two Linux artifacts, SPDX SBOMs, SHA256SUMS, commit identity, and OCI image digest. | Reads only an allowlisted artifact directory; performs no registry or product-data access. |
| `assemble_release_artifacts.py` | Copies fixed Linux archives and writes deterministic SPDX 2.3 SBOMs, SHA256SUMS, and a release manifest. | Publishes a new output directory by atomic rename; rejects existing outputs and never contacts a registry. |
| `.github/workflows/build-binaries.yml` quality job | Runs formatting, lint, workspace tests, architecture fitness, and pinned RustSec audit before build artifacts exist. | Uses read-only repository permission; audit tool/advisory retrieval failure blocks downstream jobs. |
| `.github/workflows/build-binaries.yml` candidate job | On a strict `vMAJOR.MINOR.PATCH` tag only, publishes the Linux multi-architecture GHCR image, verifies an unauthenticated digest-pinned pull, assembles release assets, and creates a GitHub prerelease candidate. | The only tag workflow job with `packages: write`; PRs retain read-only permissions and no runtime secret is passed to the assembler. The anonymous pull gate prevents a private/unusable package from being presented as a candidate. |
| `.github/workflows/promote-release.yml` | Manually promotes a prerelease only after tracked clean-host evidence validates against the candidate's immutable identity. | Uses `contents: write` only in the explicit promotion job; it edits an existing GitHub prerelease and creates no tag or image. |
