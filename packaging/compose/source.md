# Compose package assets

This directory contains the Linux release-archive assets that install the fixed
Compose upgrade-helper boundary. It is a packaging adapter, not a Core runtime
component; it must not introduce Docker socket mounts or arbitrary operator
arguments.

| Path | Responsibility | Boundary / side effects |
| --- | --- | --- |
| `compose-upgrade-helper` | Validates the fixed Compose project/file prefix and typed upgrade command allowlist. | Runs fixed preflight, root-owned tagged image admission with OCI version/revision-label verification, staged/active/previous manifest transition with digest-checked rollback, checksum-backed secret-free backup receipts, no-pull lifecycle that recreates the stopped service when its immutable image changes, and readiness-probe invocations; rejects unsupported commands and arbitrary Docker arguments. |
| `install.sh` | Installs the packaged Compose files and helper into root-owned fixed host paths. | Requires validated image tag/digest, installs the packaged default primary config only when `/etc/sponzey-edge/current.toml` is absent, and atomically initializes the fixed immutable runtime image reference without overwriting operator config. |
| `prepare-upgrade.sh` | Updates only fixed Compose control-plane assets from a verified target archive. | Requires root and replaces the fixed Compose files and helper; the Compose template keeps the prior tag/digest manifest readable during the backup phase, and this script does not touch runtime image state, canonical primary config, or persistent data. |
| `docker-compose.upgrade.yml` | Fixed upgrade-only Compose override. | Runs only the short-lived backup/verify invocation as UID 0 with `DAC_OVERRIDE` and `FOWNER`, so it can read the root-owned owner-only passphrase and re-assert private mode on the edge-owned exclusive data lock; normal serving remains non-root and never uses this override. |
