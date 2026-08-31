# Compose package assets

This directory contains the Linux release-archive assets that install the fixed
Compose upgrade-helper boundary. It is a packaging adapter, not a Core runtime
component; it must not introduce Docker socket mounts or arbitrary operator
arguments.

| Path | Responsibility | Boundary / side effects |
| --- | --- | --- |
| `compose-upgrade-helper` | Validates the fixed Compose project/file prefix and typed upgrade command allowlist. | Runs fixed preflight, root-owned image admission/digest verification, staged/active/previous manifest transition with digest-checked rollback, checksum-backed secret-free backup receipts, no-pull lifecycle that recreates the stopped service when its immutable image changes, and readiness-probe invocations; rejects unsupported commands and arbitrary Docker arguments. |
| `install.sh` | Installs the packaged Compose files and helper into root-owned fixed host paths. | Requires validated image tag/digest, installs the packaged default primary config only when `/etc/sponzey-edge/current.toml` is absent, and atomically initializes the fixed runtime image manifest without overwriting operator config. |
| `docker-compose.upgrade.yml` | Fixed upgrade-only Compose override. | Runs only the short-lived backup/verify invocation as UID 0 so it can read the root-owned owner-only fixed passphrase bind mount; normal serving remains non-root and never uses this override. |
