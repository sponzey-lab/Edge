# Edge adapters

This crate implements external I/O behind `edge-ports`; it must not move blocking
filesystem, process, or service-manager work into the Core event loop.

| Path | Responsibility | Boundary / side effects |
| --- | --- | --- |
| `operational_upgrade.rs` | Fixed-format upgrade journal, typed command mapper, and fixed systemd/Compose helper process runners. | Performs bounded no-follow file I/O and invokes only packaged absolute helper paths with allowlisted artifact/path and fixed Compose project/file arguments, fixed PATH, cleared environment, and bounded UTF-8 output; never stores a secret or accepts arbitrary argv/environment. |
| `support_bundle.rs` | Fixed-layout support archive collector. | Writes only allowlisted regular files into a private tar archive; rejects unsafe output paths and sensitive content, omits symlinks/missing/bound-exceeding files, and returns a digest-backed redaction receipt. |
| `lib.rs` | Public adapter exports and shared file helpers. | Concrete I/O boundary; callers depend on typed port traits. |
