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

## Release Performance Test Environment

`edge-perf`, `node-upstream`, and `load-generator` use the `performance` Compose profile. They are
not the persistent source-level `edge-test` container: `edge-perf` is rebuilt from the root
production Dockerfile and k6 receives only the Edge endpoint. The deterministic Node upstream and
its read-only dashboard make functional failures observable without exposing the Edge Admin API.

Run the 30-second functional gate before collecting a performance profile:

```bash
node tests/performance/bin/run.mjs smoke
```

The host-side runner performs this lifecycle: it safely recreates the ignored test PKI runtime,
builds and waits for the release image, runs k6, samples Edge CPU and memory through the host Docker
CLI, validates the k6 gate, and atomically publishes the result. It does not mount a Docker socket
or publish Admin. The only published test port is the Node dashboard at `127.0.0.1:3000`.

Longer profiles are deliberate manual operations:

```bash
# Three independent 1-minute warmup + 5-minute measurement runs (about 18 minutes).
node tests/performance/bin/run.mjs baseline

# 1 -> 10 -> 25 -> 50 VU step-up (about 4 minutes).
node tests/performance/bin/run.mjs stress

# 10 VU for 30 minutes.
node tests/performance/bin/run.mjs soak
```

Every successful run is published under `artifacts/performance/<run-id>/`, which is ignored by Git.
Inspect `metadata.json` for source/image/host identity, each k6 `*.json` for raw output,
`edge-resource-samples.json` for host-side CPU/memory observations, and `summary.json` for RPS,
p50/p95/p99, error, and bytes. A baseline summary additionally contains the min/median/max
distribution from exactly three runs. `*.partial` directories represent failed or interrupted runs
and must not be promoted as a baseline.

To stop the release performance services while preserving ignored evidence, run:

```bash
docker compose --profile performance -f docker-compose.test.yml rm -s -f edge-perf node-upstream
```

Node and k6 images are pinned by version and digest. When updating either pin or its Node lockfile,
run the smoke gate and create a new baseline candidate; do not compare results across different
source/image identities. These performance artifacts are supplemental characterization only. They
do not replace the canonical Phase 011 7,200-second memory/release evidence or its platform gates.

## Configuration Contract Check

Validate the Compose model without starting a container:

```bash
docker compose -f docker-compose.test.yml config
```
