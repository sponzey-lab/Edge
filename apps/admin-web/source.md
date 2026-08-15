# Admin web assets

| Path | Responsibility | Boundary / side effects |
| --- | --- | --- |
| `app.js` | Admin UI state, authenticated API client, and operational rendering. | Uses versioned Admin API only; support bundle uses CSRF-protected fixed server paths and displays only secret-free receipt facts. |
| `index.html` | Static Admin console structure. | Contains no runtime configuration or filesystem paths. |
