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

test("edge-perf mounts a non-secret HTTP route config for the production image", () => {
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
  assert.match(routeConfig, /url = "http:\/\/node-upstream:3000"/);
  assert.match(routeConfig, /hosts = \["edge\.test"\]/);
  assert.match(routeConfig, /bind = "0\.0\.0\.0:8080"/);
});
