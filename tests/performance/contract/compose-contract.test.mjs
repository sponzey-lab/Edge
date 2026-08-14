import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);

function composeConfig() {
  const output = execFileSync(
    "docker",
    [
      "compose",
      "--profile",
      "performance",
      "-f",
      "docker-compose.test.yml",
      "config",
      "--format",
      "json",
    ],
    {
      cwd: repositoryRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  return JSON.parse(output);
}

test("performance Compose keeps the development container isolated", () => {
  const config = composeConfig();
  const edgeTest = config.services["edge-test"];

  assert.ok(edgeTest, "edge-test must remain available for source-level checks");
  assert.deepEqual(edgeTest.ports ?? [], []);
  assert.equal(JSON.stringify(edgeTest.volumes).includes("docker.sock"), false);
  assert.equal(JSON.stringify(edgeTest.volumes).includes("/var/lib/sponzey-edge/data"), false);
});

test("performance Compose declares the four-service measurement boundary", () => {
  const config = composeConfig();

  assert.deepEqual(
    Object.keys(config.services).sort(),
    ["edge-perf", "edge-test", "load-generator", "node-upstream"],
  );
  assert.match(config.services["node-upstream"].image, /@sha256:/);
  assert.match(config.services["load-generator"].image, /@sha256:/);
  assert.deepEqual(config.services["edge-perf"].ports ?? [], []);
  assert.deepEqual(config.services["load-generator"].ports ?? [], []);
  assert.equal(config.services["load-generator"].network_mode, "service:edge-perf");
  assert.deepEqual(config.services["load-generator"].secrets, [{
    source: "performance-admin-credential",
    target: "admin-credential.secret",
  }]);
  assert.ok(config.services["load-generator"].volumes.some((volume) => (
    volume.source === path.join(repositoryRoot, "artifacts", "performance")
    && volume.target === "/results"
    && !volume.read_only
  )));

  for (const serviceName of ["edge-perf", "node-upstream", "load-generator"]) {
    const service = config.services[serviceName];
    assert.ok(service.healthcheck ?? serviceName === "load-generator");
    assert.deepEqual(service.logging, {
      driver: "local",
      options: { "max-file": "3", "max-size": "10m" },
    });
    assert.equal(JSON.stringify(service.volumes ?? []).includes("docker.sock"), false);
  }

  const [dashboardPort] = config.services["node-upstream"].ports;
  assert.equal(config.services["node-upstream"].ports.length, 1);
  assert.equal(dashboardPort.target, 3000);
  assert.equal(dashboardPort.published, "3000");
  assert.equal(dashboardPort.protocol, "tcp");
  assert.equal(dashboardPort.host_ip, "127.0.0.1");
});

test("edge-perf mounts a non-secret HTTP route config with a stable literal upstream", () => {
  const config = composeConfig();
  const edgePerf = config.services["edge-perf"];
  const routeConfig = readFileSync(
    path.join(repositoryRoot, "tests/performance/config/edge-perf.toml"),
    "utf8",
  );

  assert.equal(edgePerf.build.dockerfile, "Dockerfile");
  assert.ok(
    edgePerf.volumes.some((volume) => (
      volume.source === path.join(repositoryRoot, "tests/performance/config/edge-perf.toml")
      && volume.target === "/etc/sponzey-edge/current.toml"
      && volume.read_only
    )),
  );
  const upstream = config.services["node-upstream"];
  const network = config.networks["performance-net"];

  assert.deepEqual(network.ipam.config, [{ subnet: "172.30.0.0/24" }]);
  assert.equal(upstream.networks["performance-net"].ipv4_address, "172.30.0.3");
  assert.match(routeConfig, /url = "http:\/\/172\.30\.0\.3:3000"/);
  assert.match(routeConfig, /url = "http:\/\/172\.30\.0\.3:3000\/route\/api"/);
  assert.match(routeConfig, /url = "http:\/\/172\.30\.0\.3:3000\/route\/exact"/);
  assert.match(routeConfig, /max_connections = 1024/);
  assert.match(routeConfig, /hosts = \["edge\.test"\]/);
  assert.match(routeConfig, /priority = 20/);
  assert.match(routeConfig, /exact_paths = \["\/routing\/exact\/route-check"\]/);
  assert.match(routeConfig, /upstream_read_timeout_ms = 1000/);
  assert.match(routeConfig, /bind = "0\.0\.0\.0:8080"/);
  assert.match(routeConfig, /bind = "0\.0\.0\.0:8443"/);
  assert.match(routeConfig, /protocol = "https"/);
  assert.match(routeConfig, /certificate_ref = "edge-test-cert"/);
  assert.ok(
    edgePerf.volumes.some((volume) => (
      volume.target === "/test-runtime" && volume.read_only
    )),
  );
  assert.ok(
    upstream.volumes.some((volume) => (
      volume.target === "/test-pki/client-ca.pem" && volume.read_only
    )),
  );
});
