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

Run a real profile only from a clean Git worktree. The runner rejects tracked or
untracked source changes before it creates an artifact, prepares test PKI,
builds the image, or changes the performance Compose services; `--dry-run`
remains side-effect free.

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
p50/p95/p99, error, bytes, and CPU/memory distribution with first/last memory delta. A baseline summary additionally contains the min/median/max
distribution from exactly three runs. `*.partial` directories represent failed or interrupted runs
and must not be promoted as a baseline.

Before reusing a completed artifact, run the same fail-closed audit used by the performance
boundary:

```bash
node tests/performance/bin/audit.mjs artifacts/performance/<run-id>
```

To stop the release performance services while preserving ignored evidence, run:

```bash
docker compose --profile performance -f docker-compose.test.yml rm -s -f edge-perf node-upstream
```

Node and k6 images are pinned by version and digest. When updating either pin or its Node lockfile,
run the smoke gate and create a new baseline candidate; do not compare results across different
source/image identities. These performance artifacts are supplemental characterization only. They
do not replace the canonical Phase 011 7,200-second memory/release evidence or its platform gates.

GitHub Actions runs the Compose/Node/profile contracts and this smoke profile for pull requests and
pushes to `main` or `develop`. `baseline`, `stress`, and `soak` are manual `workflow_dispatch`
choices only. CI retains only allow-listed non-secret summary, state, metadata, and resource sample
files for 14 days; generated test PKI and its private key are never uploaded.

### Persistent Remote Linux Reference Host

An operator may keep the selected external performance host in the ignored root `.env` file. It is
host-selection metadata only: the runner does not read this file, copy source to the host, or start a
remote profile automatically. Keep the file owner-only (`0600`) and use SSH key authentication rather
than a stored password:

```dotenv
SPONZEY_PERFORMANCE_HOST=192.0.2.10
SPONZEY_PERFORMANCE_SSH_PORT=22
SPONZEY_PERFORMANCE_SSH_USER=operator
SPONZEY_PERFORMANCE_SSH_AUTH=agent
```

Before a remote profile, explicitly check out the measured clean source revision on that Linux host,
then run the same profile command from that checkout. Do not record passwords, private-key material,
or a remote checkout path in Git. The resulting `metadata.json` must be retained with the measured
host identity; a remote host inventory alone is not performance evidence.

The read-only Node dashboard remains internal to the Compose network on port `3000`; its loopback
published host port defaults to `3000`. If that host port is occupied, set a different local value only
for that performance invocation, for example `SPONZEY_PERFORMANCE_DASHBOARD_PORT=3100`. This does not
change the Edge upstream target, the dashboard's container port, or its loopback-only exposure.

## Manual HTTP framing mutation fuzz

The source-quality CI job runs a bounded 1,000-case deterministic mutation smoke.
For an extended local parser/framer and connection-state mutation run on the
stable Rust toolchain, use the test-only example:

```bash
cargo run -p edge-core --example http_framing_mutation_fuzz -- 1000000
```

The optional case count is bounded from 1 through 1,000,000 (the default is
100,000). The runner performs no network I/O, writes no corpus or artifact, and
prints only the completed case count. It is not release evidence and does not
replace the Linux host, soak, or coverage-guided fuzzing evidence required for a
release candidate.

## Configuration Contract Check

Validate the Compose model without starting a container:

```bash
docker compose -f docker-compose.test.yml config
```
