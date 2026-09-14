# Reusable Nextcloud integration boundary

| Path | Responsibility | Boundary / side effects |
| --- | --- | --- |
| `edge-nextcloud.toml` | Fixed non-secret Edge route from `nextcloud.test` to the private Compose Nextcloud address. | Bootstrap-only test configuration; no runtime config mutation. |
| `verify.mjs` | Verifies the initialized Nextcloud status endpoint is reachable only through the loopback-published Edge listener. | Executes one bounded local HTTP request after Compose readiness; does not create or remove Compose resources. |
