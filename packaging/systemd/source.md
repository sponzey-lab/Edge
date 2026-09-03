# Systemd package assets

This directory packages a released Linux binary for a single-node systemd host.
Its fixed-path upgrade helper verifies a locally staged binary and uses same-directory
atomic renames to preserve a previous binary for rollback; artifact fetch remains separate.

| Path | Responsibility | Boundary / Side effects |
| --- | --- | --- |
| `sponzey-edge.service` | Dedicated-account service unit with local Admin bind and filesystem/capability hardening. | Starts the installed binary through systemd. |
| `install.sh` | Installs the binary and config from the archive root beside `systemd/`, or explicit supplied paths, then starts the service. | Requires root and writes only fixed system paths. |
| `uninstall.sh` | Stops and removes the service executable, unit, and fixed upgrade helper while preserving data and config. | Requires root; never removes product data or canonical config. |
| `preflight.sh` | Checks supported architecture, systemd as PID 1, account tooling, and local Admin port availability. | Read-only host inspection; performs no service or filesystem mutation. |
| `upgrade-helper` | Fixed-subcommand boundary for preflight, backup/verify, root-owned local artifact admission, drain, verified local stage, atomic switch, readiness, and rollback. | Reads only an owner-only passphrase-file reference through the existing CLI; admits root-owned absolute regular artifacts (including normal `0755` executables), while rejecting group/world-writable input, symlinks, digest mismatch, and unsafe replacement before service action. |
