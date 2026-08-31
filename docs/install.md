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
support/
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
target/release/edge-proxy
```

`examples/minimal.toml` currently starts an HTTP listener on `0.0.0.0:8080` and forwards to `http://127.0.0.1:3000`.

## Docker

Official releases require a tag and matching immutable GHCR digest:

```bash
sudo ./compose/install.sh \
  --image-tag vX.Y.Z \
  --image-digest RELEASE_MANIFEST_IMAGE_SHA256_WITHOUT_PREFIX
sudo docker compose --project-directory /etc/sponzey-edge/compose \
  --file /etc/sponzey-edge/compose/docker-compose.yml up -d --wait
```

Local builds are intentionally separate from the official image path:

```bash
docker compose -f docker-compose.yml -f docker-compose.local.yml --profile local-build up --build
```

The image packages:

- `/usr/local/bin/edge-proxy`
- `/etc/sponzey-edge/current.toml`
- `/usr/share/sponzey-edge/admin-web`

For official Compose, `compose/install.sh` copies the packaged default primary
config to `/etc/sponzey-edge/current.toml` only when that canonical host file
does not already exist. The official service mounts it read-only, so select an
available listener bind before first start and use the config validation/apply
lifecycle for later changes.

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

## Certificate scope

This release supports manual certificates and private PKI only. The bundled fake
ACME adapter is a test boundary, not an external certificate-issuance feature.
Do not enable or document Let’s Encrypt/ACME automation until it is explicitly
reopened as a separately verified scope.
