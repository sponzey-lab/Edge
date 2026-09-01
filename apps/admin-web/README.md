# Admin Web UI

Optional static Admin Web UI for the MVP control plane.

Rules:

- The UI is an Admin API client.
- The UI calls `/api/v1/*` and never modifies config files directly.
- The UI must not link into the Core hot path.
- The UI may be opened directly for fallback smoke checks or served by the
  `edge-proxy` Admin HTTP listener from the bin/adapter boundary.

Files:

- `index.html`: dashboard, auth/setup, proxy host editor, config editor, certificate table, recent logs.
- `styles.css`: responsive operational UI styling.
- `app.js`: Admin API client with login, CSRF mutation headers, config lifecycle controls, proxy host CRUD, manual certificate/log reads, support bundle creation, and explicit local fallback for screen smoke checks.

Local check:

Run the current focused TCP/static-asset smoke:

```bash
cargo test -p edge-proxy admin_http_listener_serves_static_admin_web_assets_over_tcp
```

For an optional manual layout check, open `index.html` directly in a browser.
For same-origin API mode, run `edge-proxy` with a valid config file and open the
loopback Admin bind URL. Without a reachable Admin API, the UI enters a visible
`UI smoke only` mode. Fallback state is only for layout and interaction checks;
it is not canonical runtime config and must not be treated as applied proxy
state. Session/CSRF-protected support-bundle behavior is covered at the bound
Admin TCP endpoint by:

```bash
cargo test -p edge-proxy support_bundle_endpoint_uses_fixed_paths_and_requires_csrf
```
