# Product Release Evidence Template

Use this template for a candidate built from the current source tree. A release is
not complete until every required field has concrete evidence. Historical Phase
evidence and removed helper names are archive-only: they document prior work but
are not current commands or approval substitutes.

Certificate scope is manual certificates and private PKI only. External ACME or
Let's Encrypt issuance and renewal are deferred; do not collect, initialize, or
claim certificate-automation evidence unless the user explicitly reopens that
scope.

## Release Identity

```text
release_id:
semver_tag:
commit_sha:
source_tree_sha256:
utc_started_at:
utc_completed_at:
operator:
reviewer:
```

## Published Artifacts

```text
github_release_url:
linux_amd64_archive_sha256:
linux_arm64_archive_sha256:
sha256sums_sha256:
spdx_sbom_sha256:
ghcr_image_repository:
ghcr_manifest_digest:
oci_revision_label:
```

The tag, commit, archive checksums, SBOM, OCI label, and immutable image digest
must identify the same release. A mutable tag without its matching digest is not
sufficient.

## Source-Level Gate

Record the complete output and exit code for each command executed against the
release identity:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --test-threads=1
```

```text
cargo_fmt_check_exit:
cargo_clippy_exit:
cargo_test_exit:
architecture_api_contract_exit:
documentation_contract_exit:
```

The reusable `edge-test` container may provide Linux source-level evidence, but
it does not replace production-image or clean-host evidence.

## Compose Clean-Host Evidence

Use only a verified published image tag and its immutable digest. Do not replace
this with a local build, dummy image, or unverified tag.

```text
host_os_and_architecture:
docker_version:
compose_version:
image_tag:
image_digest:
install_command_transcript_ref:
readiness_probe_result:
proxy_smoke_result:
admin_loopback_result:
upgrade_result:
forced_rollback_result:
data_preservation_result:
cleanup_result:
secret_exclusion_review:
```

Record each command, its result, the input configuration digest, and the final
cleanup result. The Admin API must remain loopback-only. Compose evidence on one
architecture does not prove the other.

## Systemd Clean-Host Evidence

```text
host_os_and_architecture:
systemd_version:
archive_sha256:
install_start_probe_result:
sigterm_restart_result:
uninstall_result:
upgrade_result:
forced_rollback_result:
data_preservation_result:
cleanup_result:
secret_exclusion_review:
```

The host must run systemd as PID 1. Container simulation is not systemd
evidence.

## Support Bundle Verification

```text
support_bundle_api_or_ui_result:
archive_id:
archive_digest:
allowlist_bounds_result:
secret_scan_result:
path_and_symlink_rejection_result:
```

The receipt must not expose archive paths, private keys, secrets, request or
response bodies, authorization material, cookies, or full queries.

## Known Limits

```text
manual_or_private_pki_only: true
certificate_automation_deferred: true
official_clean_host_evidence_pending:
unsupported_platforms: macOS, Windows
```

## Review Sign-Off

```text
source_gate_verified_by:
artifact_identity_verified_by:
compose_evidence_verified_by:
systemd_evidence_verified_by:
security_reviewed_by:
release_approved_by:
approval_utc:
```

## Rejection Criteria

Reject the candidate if any source-level gate fails, any artifact identity is
missing or inconsistent, an image digest is mutable or absent, either required
clean-host path lacks evidence, Admin is publicly reachable, an upgrade/rollback
cannot preserve required data, or any evidence includes secret or private key
material. Historical archive-only evidence cannot waive these requirements.
