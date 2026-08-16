# Edge proxy bootstrap

This directory wires typed bootstrap configuration and adapters to the mio Core.
It owns process and HTTP-server boundaries but not routing or policy decisions.

| Path | Responsibility | Boundary / Side effects |
| --- | --- | --- |
| `main.rs` | Process bootstrap, maintenance CLI, operational probe CLI, and Unix SIGTERM watcher. | Reads environment at bootstrap only; sends acknowledged Core commands outside signal context, runs upgrade/recovery through the explicitly selected fixed systemd or Compose helper/journaled controller boundary, and emits secret-free result JSON. |
| `process_mode.rs` | Typed maintenance-command parser. | Requires an explicit `systemd` or `compose` upgrade deployment plus identity, root-owned local artifact path, passphrase-file reference, and recovery operation ID; never reads or exposes secret values. |
| `admin_http.rs` | Loopback Admin HTTP server and runtime adapter wiring. | Bounded request handling and API adapter access; support-bundle paths are bootstrap-wired rather than request-supplied, and operational probes consume a read-only Core-published runtime-fact snapshot. |
| `bootstrap.rs` | Bootstrap-only environment parsing and data-layout setup. | Filesystem/environment boundary. |
| `process_mode.rs` | Typed CLI command parsing. | Parses arguments only; no network or filesystem I/O. |
