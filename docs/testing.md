# Testing Guide

## Reusable Test Container

`Dockerfile.test` and `docker-compose.test.yml` define a test-only container that stays running
between test invocations. The project directory is bind-mounted at `/workspace`; Cargo registry,
git checkout, and build output use named volumes so repeated checks reuse downloaded dependencies
and compiled artifacts.

Start or rebuild the container:

```bash
docker compose -f docker-compose.test.yml up -d --build
```

Run the required source-level gate inside it:

```bash
docker compose -f docker-compose.test.yml exec edge-test \
  bash -c 'cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace -- --test-threads=1'
```

Run a focused test without rebuilding the container:

```bash
docker compose -f docker-compose.test.yml exec edge-test \
  cargo test -p edge-core snapshot_mio_runtime_routes_by_host_to_different_upstreams -- --test-threads=1
```

Open an interactive shell when investigating a failure:

```bash
docker compose -f docker-compose.test.yml exec edge-test bash
```

`stop` preserves the container and all named caches. `start` resumes it. `down` removes the
container and network but preserves the named caches; add `--volumes` only when a deliberately clean
Cargo cache and target directory are required.

```bash
docker compose -f docker-compose.test.yml stop
docker compose -f docker-compose.test.yml start
docker compose -f docker-compose.test.yml down
```

## Boundary And Safety Rules

- The test container is not a production image and must not be published as an `edge-proxy`
  runtime artifact.
- It exposes no host port and mounts no production data, certificate, secret, backup, or audit
  directory.
- Product bootstrap environment and runtime config are not injected by the Compose file. Tests must
  pass explicit typed fixtures or start `edge-proxy` with deliberate test-only bootstrap arguments.
- The source bind mount is writable so `cargo fmt` and developer tooling can be used deliberately;
  tests must not rewrite source files as part of normal execution.
- A container pass proves the Linux container boundary only. Platform-specific macOS and native
  Linux memory/release evidence remains a separate release requirement.

## Configuration Contract Check

Validate the Compose model without starting a container:

```bash
docker compose -f docker-compose.test.yml config
```
