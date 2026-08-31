# Product Release Gate

This document is the current release gate for the active single-node product
plan. It replaces the removed local smoke-wrapper and certificate-automation
runbooks. Historical Phase evidence is archive-only; it never approves a
changed source tree or a new release.

## Product scope

Manual certificates and private PKI are the only supported certificate paths.
External ACME or Let’s Encrypt issuance and renewal automation is deferred until
the user explicitly reopens that scope. It is not a release prerequisite and
this document intentionally contains no command for it.

Official support also remains unclaimed until the same candidate has clean-host
Linux evidence for both Docker Compose and systemd. A containerized or macOS
source check is useful evidence, but is not a substitute for that matrix.

## Source gate

Run these commands against the exact commit being considered:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --test-threads=1
python3 tools/release/check_architecture.py --workspace .
python3 tools/release/check_source_indexes.py --workspace .
cargo install cargo-audit --version 0.22.2 --locked
cargo audit
```

The read-only `Source quality` CI job runs these checks before every artifact
build. The source-index gate rejects missing, stale, or duplicate direct Rust
paths in checked-in `source.md` indexes. Artifact build and release publish both
depend on these gates, and an audit tool installation or advisory database
failure remains fail-closed.

The reusable test-only container may provide Linux source-level evidence:

```bash
docker compose -f docker-compose.test.yml up -d --build
docker compose -f docker-compose.test.yml exec edge-test \
  bash -c 'cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace -- --test-threads=1'
```

Also record the architecture/API and documentation contract test results. The
test container's persistent compiler cache improves iteration only; it is not
the production image and cannot stand in for release runtime evidence.

## Published artifact gate

An official SemVer tag first creates a public GitHub prerelease candidate and
its immutable GHCR digest. It is not a product release or supported deployment
claim. Record and cross-check all of the following against that candidate:

- GitHub Release URL and tag-to-commit identity
- Linux `amd64` and `arm64` archive checksums and SPDX SBOM checksum
- GHCR repository, immutable multi-architecture manifest digest, and OCI
  revision label
- an anonymous pull of the exact digest before the prerelease is created

A mutable image tag without its matching immutable digest is insufficient. The
tag, archives, SBOM, OCI label, and digest must all identify one release.

## Runtime release matrix

Use only the published tag and matching digest—never a local build or dummy
image—to collect the following evidence.

| Deployment | Required clean-host evidence |
| --- | --- |
| Docker Compose, Linux `amd64` and `arm64` | install, readiness and proxy smoke, loopback-only Admin API, restart, upgrade, forced-failure rollback, data preservation, cleanup |
| systemd, Linux `amd64` and `arm64` | archive checksum, install/start/probe, SIGTERM/restart, uninstall, upgrade, forced-failure rollback, data preservation, cleanup |

The systemd host must run systemd as PID 1. Compose and systemd evidence must
also confirm non-root operation, read-only root filesystem where packaged,
fixed paths, and no Docker socket or privileged-container requirement.

## Support and performance evidence

Record a support-bundle request through `POST /api/v1/support-bundles` or the
equivalent UI action. Verify the receipt is secret-free and that allowlist,
byte/log-age bounds, and path/symlink rejection hold.

The Edge performance Compose boundary is a separate characterization tool. Its
smoke may run with:

```bash
node tests/performance/bin/run.mjs smoke
node tests/performance/bin/audit.mjs artifacts/performance/<run-id>
```

Run a real profile only from a clean Git worktree. The runner rejects source
changes before artifact, PKI, image-build, or Compose-service side effects, so
the recorded commit/tree identity describes the measured source.

Baseline, stress, and soak profiles are not release-blocking numeric thresholds
unless a separately approved contract defines those thresholds.

## Evidence record and decision

Use [the release evidence template](release-evidence-template.md) to bind the
source identity, release identity, exact commands, platform, configuration
digest, results, failure criteria, and secret-exclusion review. Do not copy
historical paths, transcripts, or success markers as evidence for a new tree.

The candidate is eligible for promotion only after every source, artifact,
Compose, systemd, support-bundle, and documentation item above is recorded for
that same release identity. Commit the secret-free machine-readable promotion
evidence as `release-evidence/<tag>/promotion.json`, then manually dispatch
`.github/workflows/promote-release.yml` with that tag and path. The workflow
rejects stale/missing identity, incomplete matrix, scope drift, and untracked
evidence before changing the same GitHub prerelease to a product release.
