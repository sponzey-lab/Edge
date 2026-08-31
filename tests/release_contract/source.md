# Release contract tests

These Python tests validate source-controlled packaging, CI, release metadata,
and published-artifact contracts. They are test tooling only and must not import
or mutate the product runtime.

| Path | Responsibility | Boundary / Side effects |
| --- | --- | --- |
| `test_architecture_fitness.py` | Verifies the executable product-layer fitness gate and its workflow ordering. | Invokes the checker against temporary fixtures or the repository; does not alter product data. |
| `test_build_workflow.py` | Verifies read-only source-quality (including bounded HTTP-framing mutation smoke), pinned build, artifact, and public-release workflow contracts. | Reads workflow and test-container source only. |
| `test_compose_packaging.py` | Verifies Compose package contents and runtime deployment contract. | Reads packaging source only. |
| `test_compose_upgrade_packaging.py` | Verifies Compose installer/helper boundaries and that official operator commands load the fixed runtime image manifest. | Reads packaging and operator-document source only. |
| `test_dependency_advisories.py` | Pins RustSec-mandated lockfile minima that block release quality gates. | Reads Cargo.lock only. |
| `test_document_links.py` | Verifies current README and operator-document local Markdown links resolve within the repository. | Reads a fixed current-document set only; does not validate historical archives, external links, or mutate product data. |
| `test_manual_fuzz.py` | Verifies the bounded stable-toolchain manual HTTP framing mutation runner and its documentation contract. | Reads test-tool and documentation source only. |
| `test_product_scope_docs.py` | Verifies supported product scope and deferred certificate automation statements. | Reads product documents only. |
| `test_release_assembly.py` | Verifies deterministic release-asset assembly contracts. | Uses isolated temporary artifact fixtures. |
| `test_release_manifest.py` | Verifies release-manifest validation contracts. | Uses isolated temporary artifact fixtures. |
| `test_release_metadata.py` | Verifies tag, repository, and package metadata validation. | Reads repository metadata only. |
| `test_release_promotion.py` | Verifies prerelease candidate and evidence-validated product-promotion contracts. | Uses isolated JSON evidence fixtures and reads workflow/document source only. |
| `test_systemd_packaging.py` | Verifies systemd package contents and operational script contracts. | Reads packaging source only. |
| `test_upgrade_helper_packaging.py` | Verifies shared upgrade-helper packaging contracts. | Reads packaging source only. |
