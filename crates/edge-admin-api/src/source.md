# Admin API contract

This directory defines versioned Admin API request, response, session, and
read-model contracts. It has no HTTP listener implementation.

| Path | Responsibility | Boundary / Side effects |
| --- | --- | --- |
| `lib.rs` | Admin handlers, schemas, authentication checks, operational probe payloads, and support-bundle read model. | Pure API adaptation over supplied ports and snapshots; support bundle creation uses a fixed allowlist/bounds and emits only a secret-free receipt. |
