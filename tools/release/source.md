# Release tooling boundary

Release tooling validates package metadata and later assembles release-only artifacts. It is outside
the Sponzey Edge runtime dependency graph and must not read runtime secrets or mutate product data.

| Path | Responsibility | Boundary / Side effects |
| --- | --- | --- |
| `validate_release_metadata.py` | Validates canonical repository, exact SemVer tag, package version, and pinned Rust toolchain. | Reads supplied release metadata and writes one safe JSON result or stable error code. |
| `validate_release_manifest.py` | Validates the two Linux artifacts, SPDX SBOMs, SHA256SUMS, commit identity, and OCI image digest. | Reads only an allowlisted artifact directory; performs no registry or product-data access. |
| `assemble_release_artifacts.py` | Copies fixed Linux archives and writes deterministic SPDX 2.3 SBOMs, SHA256SUMS, and a release manifest. | Publishes a new output directory by atomic rename; rejects existing outputs and never contacts a registry. |
| `.github/workflows/build-binaries.yml` release job | On a strict `vMAJOR.MINOR.PATCH` tag only, publishes the Linux multi-architecture GHCR image, verifies an unauthenticated digest-pinned pull, then assembles its binary release assets from the returned digest. | The only CI job with `packages: write`; PRs retain read-only permissions and no runtime secret is passed to the assembler. The anonymous pull gate prevents a private/unusable package from being released as the documented Compose image. |
