# Node upstream boundary

This test-only Node process supplies fixed HTTP fixtures to the performance Compose network. It
does not read or modify Edge configuration, credentials, or runtime artifacts.

| Path | Responsibility | Boundary / Side effects |
| --- | --- | --- |
| `src/server.mjs` | Exposes fixed HTTP fixtures, allow-listed request-header projection, bounded POST digest, short/slow delay, reset, and WebSocket echo/close transport fixtures. | Binds a test-only HTTP listener when executed directly; request bodies are capped at 4KB and expected peer resets cannot terminate the process. |
| `src/observability.mjs` | Owns bounded safe request metrics and Prometheus rendering. | Stores only projected metadata in process memory. |
| `public/index.html` | Renders the read-only JSON stats projection. | Browser fetches only local `/api/stats`. |
| `test/server.test.mjs` | Verifies deterministic responses and rejection of arbitrary presets. | Opens loopback ephemeral listeners only. |
