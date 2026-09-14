# Reusable Nextcloud integration boundary

| Path | Responsibility | Boundary / side effects |
| --- | --- | --- |
| `edge-nextcloud.toml` | Fixed non-secret Edge route from `nextcloud.test`, `localhost`, and `127.0.0.1` to the private Compose Nextcloud address. | Bootstrap-only test configuration; no runtime config mutation. |
| `verify.mjs` | Verifies the Nextcloud root redirects only to the loopback-published Edge login URL. | Executes one bounded local HTTP request after Compose readiness; does not create or remove Compose resources. |
