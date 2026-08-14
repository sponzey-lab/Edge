# Install Guide

## Build From Source

```bash
cargo build --release -p edge-proxy
```

The release binary is:

```text
target/release/edge-proxy
```

## Runtime Layout

At startup, `edge-proxy` creates the required data directories under `SPONZEY_DATA_DIR`:

```text
config/
  current
  current.toml
  revisions/
certs/
secrets/
logs/
backups/
```

Certificates written by the Admin certificate issue/renew path are stored through
`CertificateStore` under:

```text
certs/
  {certificate_ref}/
    fullchain.pem
    privkey.pem
    metadata.toml
```

`privkey.pem` is written with owner-only permissions on Unix platforms. API
responses expose only the certificate ref, domains, source, expiry, and masked
private key marker.

Environment values are bootstrap-only. After startup, runtime changes must go through the config validation/apply path, not process environment mutation.
When a valid primary config file is present, startup imports it into the
file-backed revision store before the runtime listener starts. `config/current`
is the current revision pointer; `config/current.toml` is the default primary
config file path.

## Minimal Config Run

```bash
SPONZEY_DATA_DIR=.sponzey \
SPONZEY_CONFIG_FILE=examples/minimal.toml \
SPONZEY_ADMIN_BIND=127.0.0.1:9443 \
SPONZEY_LOG_MODE=product \
SPONZEY_ACME_CLIENT=fake \
target/release/edge-proxy
```

`examples/minimal.toml` currently starts an HTTP listener on `0.0.0.0:8080` and forwards to `http://127.0.0.1:3000`.

## Docker

```bash
docker compose up --build
```

The image packages:

- `/usr/local/bin/edge-proxy`
- `/etc/sponzey-edge/current.toml`
- `/usr/share/sponzey-edge/admin-web`

The production Compose file and reusable test container are separate contracts. For development,
start `docker-compose.test.yml` and run checks through its long-lived `edge-test` service; do not
mount production data or secrets into it. See `docs/testing.md` for the exact commands.

## Admin Password Bootstrap

The current MVP runtime loads the admin password hash once at startup through
`SecretStore` from:

```text
<data_dir>/secrets/admin-password-hash.secret
```

If the file is absent, the Admin API enters setup-required mode and
`POST /api/v1/setup` writes the first password hash through `SecretStore`. The
hash is not reread from environment during runtime.

Keep admin bind on localhost and do not expose admin endpoints externally
without authentication.
