# Admin API Curl Runbook

This runbook shows the MVP control-plane flow without the Admin Web UI. It uses
the same Admin API validation, config lifecycle, runtime command, revision
commit, and audit boundaries as the UI.

Assumptions:

- `edge-proxy` is running from a valid config file.
- The Admin API is bound to `127.0.0.1:9443`.
- The first admin password hash for this local run is `hash`.
- `curl` is available.

Set the base URL:

```bash
export ADMIN=http://127.0.0.1:9443/api/v1
```

## 1. Check Status

```bash
curl -i "$ADMIN/status"
```

If the response says setup is required, run setup first.

## 2. Initial Setup

Use this only when the admin password hash does not exist yet:

```bash
curl -i \
  -X POST "$ADMIN/setup" \
  -H 'Content-Type: application/json' \
  --data '{"password_hash":"hash"}'
```

Setup writes `admin-password-hash` through `SecretStore`. It does not mutate
runtime config and does not require environment rereads.

## 3. Login

```bash
curl -i \
  -c /tmp/sponzey-admin.cookies \
  -X POST "$ADMIN/login" \
  -H 'Content-Type: application/json' \
  --data '{"password_hash":"hash"}'
```

Copy the `csrf_token` value from the JSON response:

```bash
export CSRF=copy-token-from-login-response
```

All mutation calls below use:

- `-b /tmp/sponzey-admin.cookies`
- `-H "X-CSRF-Token: $CSRF"`

## 4. Create Proxy Host

```bash
curl -i \
  -b /tmp/sponzey-admin.cookies \
  -X POST "$ADMIN/proxy-hosts" \
  -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $CSRF" \
  --data '{
    "id":"demo",
    "name":"Demo",
    "domains":["demo.localhost"],
    "path_prefix":"/",
    "upstreams":[
      {"id":"demo-a","url":"http://127.0.0.1:3000"},
      {"id":"demo-b","url":"http://127.0.0.1:3001"}
    ],
    "health_check":{
      "enabled":true,
      "path":"/health",
      "interval_ms":10000,
      "timeout_ms":2000,
      "healthy_threshold":2,
      "unhealthy_threshold":3,
      "status_min":200,
      "status_max":399
    },
    "https_enabled":false,
    "letsencrypt_enabled":false,
    "redirect_http_to_https":false,
    "enabled":true
  }'
```

Expected behavior:

- the request is authenticated and CSRF-protected.
- the candidate config is validated.
- runtime changes are sent through `CoreCommandClient`.
- the current revision is committed only after runtime acknowledgement.

## 5. List And Read Proxy Hosts

```bash
curl -i \
  -b /tmp/sponzey-admin.cookies \
  "$ADMIN/proxy-hosts"

curl -i \
  -b /tmp/sponzey-admin.cookies \
  "$ADMIN/proxy-hosts/demo"
```

## 6. Update Proxy Host

```bash
curl -i \
  -b /tmp/sponzey-admin.cookies \
  -X PATCH "$ADMIN/proxy-hosts/demo" \
  -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $CSRF" \
  --data '{
    "id":"demo",
    "name":"Demo",
    "domains":["demo.localhost"],
    "path_prefix":"/api",
    "upstreams":[
      {"id":"demo-a","url":"http://127.0.0.1:3000"},
      {"id":"demo-b","url":"http://127.0.0.1:3002"}
    ],
    "health_check":{
      "enabled":true,
      "path":"/health",
      "interval_ms":10000,
      "timeout_ms":2000,
      "healthy_threshold":2,
      "unhealthy_threshold":3,
      "status_min":200,
      "status_max":399
    },
    "https_enabled":false,
    "letsencrypt_enabled":false,
    "redirect_http_to_https":false,
    "enabled":true
  }'
```

The path id and body id must match. A mismatch is rejected before runtime
commands are sent.

## 7. Validate And Diff Raw Config

Validate a raw config without mutating runtime state:

```bash
curl -i \
  -b /tmp/sponzey-admin.cookies \
  -X POST "$ADMIN/config/validate" \
  -H 'Content-Type: text/plain' \
  --data-binary @examples/minimal.toml
```

Inspect a diff without applying it:

```bash
curl -i \
  -b /tmp/sponzey-admin.cookies \
  -X POST "$ADMIN/config/diff" \
  -H 'Content-Type: text/plain' \
  --data-binary @examples/minimal.toml
```

## 8. Apply Raw Config

```bash
curl -i \
  -b /tmp/sponzey-admin.cookies \
  -X POST "$ADMIN/config/apply" \
  -H 'Content-Type: text/plain' \
  -H "X-CSRF-Token: $CSRF" \
  --data-binary @examples/minimal.toml
```

Apply commits `current` only after the runtime command acknowledgement succeeds.

## 9. Roll Back Config

Use a revision id returned by apply/history-related responses:

```bash
curl -i \
  -b /tmp/sponzey-admin.cookies \
  -X POST "$ADMIN/config/rollback" \
  -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $CSRF" \
  --data '{"revision_id":"file-current"}'
```

Rollback uses the same validation, command acknowledgement, current revision
commit, and audit path as apply.

## 10. Read Certificates And Logs

```bash
curl -i \
  -b /tmp/sponzey-admin.cookies \
  "$ADMIN/certificates"

curl -i \
  -b /tmp/sponzey-admin.cookies \
  "$ADMIN/logs/access"

curl -i \
  -b /tmp/sponzey-admin.cookies \
  "$ADMIN/logs/errors"

curl -i \
  -b /tmp/sponzey-admin.cookies \
  "$ADMIN/upstream-health"
```

Certificate responses mask private key material. Access logs omit request body,
response body, authorization header, cookie, and full query string. Upstream
health returns only revision/generation, stable service/upstream ids, and the
bounded `disabled|unknown|healthy|unhealthy` state; it omits endpoint URLs and
probe failure detail.

## 11. Create A Support Bundle

Create a bounded support archive after login. The request accepts no source
path, artifact list, archive location, service action, or collection bound.

```bash
curl -i \
  -b /tmp/sponzey-admin.cookies \
  -X POST "$ADMIN/support-bundles" \
  -H "X-CSRF-Token: $CSRF"
```

The response is a secret-free receipt with `archive_id`, `digest_sha256`,
`collected_artifacts`, `omitted_artifacts`, and `total_bytes`. It never reveals
the archive path, private keys, secrets, request/response bodies, authorization
material, cookies, or full queries. A `401` means login is required, `403`
means the CSRF token is missing or invalid, and other failures return the stable
error response. Manual certificates and private PKI are the only supported
certificate path; certificate automation remains deferred.

## 12. Delete Proxy Host

```bash
curl -i \
  -b /tmp/sponzey-admin.cookies \
  -X DELETE "$ADMIN/proxy-hosts/demo" \
  -H "X-CSRF-Token: $CSRF"
```

Delete rejects missing proxy hosts without sending runtime commands.

## 13. Import A Manual Certificate

Read PEM from protected files at invocation time; do not paste private keys
into shell history.

```sh
FULLCHAIN_JSON=$(jq -Rs . < ./fullchain.pem)
PRIVATE_KEY_JSON=$(jq -Rs . < ./privkey.pem)
curl -sS "$ADMIN/certificates/proxy-host-demo/import" \
  -b "$COOKIE_JAR" -H "X-CSRF-Token: $CSRF" \
  -H 'Content-Type: application/json' -H 'X-Request-Id: req-manual-import' \
  -X POST \
  --data "{\"domains\":[\"demo.example.com\"],\"fullchain_pem\":$FULLCHAIN_JSON,\"private_key_pem\":$PRIVATE_KEY_JSON}"
```

Success contains `private_key: "***"`. `CERTIFICATE_INVALID` means validation
failed. `RUNTIME_COMMAND_REJECTED` leaves active TLS unchanged.
