import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
const runtime = path.join(repositoryRoot, "artifacts", "performance", "edge-perf-runtime");
const generator = path.join(repositoryRoot, "tests", "performance", "bin", "prepare-pki-runtime.mjs");

const composeArguments = [
  "compose",
  "--profile",
  "performance",
  "-f",
  "docker-compose.test.yml",
];

function compose(...arguments_) {
  return execFileSync("docker", [...composeArguments, ...arguments_], {
    cwd: repositoryRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function prepareRuntime() {
  if (existsSync(runtime)) {
    const removed = spawnSync(process.execPath, [generator, "--clean", "--output", runtime], {
      encoding: "utf8",
    });
    assert.equal(removed.status, 0, removed.stderr);
  }
  const prepared = spawnSync(process.execPath, [generator, "--output", runtime], {
    encoding: "utf8",
  });
  assert.equal(prepared.status, 0, prepared.stderr);
}

function startPerformanceServices() {
  compose("rm", "-s", "-f", "edge-perf", "node-upstream");
  compose("up", "-d", "--wait", "edge-perf", "node-upstream");
}

function rawHttpRequest(request) {
  const script = [
    "const net = require('node:net');",
    "const socket = net.createConnection({host:'172.30.0.2',port:8080});",
    "const chunks = [];",
    "socket.setTimeout(2000, () => { process.stderr.write('timeout'); process.exitCode = 1; socket.destroy(); });",
    "socket.on('connect', () => socket.write(Buffer.from(process.argv[1], 'base64')));",
    "socket.on('data', chunk => chunks.push(chunk));",
    "socket.on('end', () => process.stdout.write(Buffer.concat(chunks).toString('utf8')));",
    "socket.on('error', error => { process.stderr.write(error.message); process.exitCode = 1; });",
  ].join("");
  return compose(
    "exec", "-T", "node-upstream", "node", "-e", script,
    Buffer.from(request, "utf8").toString("base64"),
  );
}

test("release edge-perf proxies the fixed Host route to node-upstream", () => {
  prepareRuntime();
  startPerformanceServices();

  const output = compose(
    "exec",
    "-T",
    "node-upstream",
    "node",
    "-e",
    [
      "const http = require('node:http');",
      "const request = http.request({host:'172.30.0.2',port:8080,path:'/payload/small',headers:{Host:'edge.test'}}, response => {",
      "let body = '';",
      "response.on('data', chunk => { body += chunk; });",
      "response.on('end', () => { process.stdout.write(`${response.statusCode}:${body}`); });",
      "});",
      "request.on('error', error => { process.stderr.write(error.message); process.exitCode = 1; });",
      "request.end();",
    ].join(""),
  );

  assert.equal(output, "200:sponzey-edge-small-payload-v1\n");
});

test("release edge-perf rejects malformed framing and oversized declared bodies before upstream use", () => {
  prepareRuntime();
  startPerformanceServices();

  const malformed = rawHttpRequest([
    "POST /inspect/body HTTP/1.1",
    "Host: edge.test",
    "Content-Length: nope",
    "",
    "",
  ].join("\r\n"));
  assert.match(malformed, /^HTTP\/1\.1 400 Bad Request\r?\n/);

  const oversized = rawHttpRequest([
    "POST /inspect/body HTTP/1.1",
    "Host: edge.test",
    "Content-Length: 1048577",
    "",
    "",
  ].join("\r\n"));
  assert.match(oversized, /^HTTP\/1\.1 413 Payload Too Large\r?\n/);
});

test("release edge-perf terminates trusted TLS and rejects the wrong SNI", () => {
  prepareRuntime();
  startPerformanceServices();

  const output = compose(
    "exec", "-T", "node-upstream", "node", "-e",
    [
      "const fs = require('node:fs'); const https = require('node:https');",
      "const request = https.request({host:'172.30.0.2',port:8443,path:'/payload/small',servername:'edge.test',headers:{Host:'edge.test'},ca:fs.readFileSync('/test-pki/client-ca.pem')}, response => {",
      "let body = ''; response.on('data', chunk => { body += chunk; });",
      "response.on('end', () => { process.stdout.write(`${response.statusCode}:${body}`); });",
      "}); request.on('error', error => { process.stderr.write(error.message); process.exitCode = 1; }); request.end();",
    ].join(""),
  );
  assert.equal(output, "200:sponzey-edge-small-payload-v1\n");

  const rejected = compose(
    "exec", "-T", "node-upstream", "node", "-e",
    [
      "const fs = require('node:fs'); const https = require('node:https');",
      "const request = https.request({host:'172.30.0.2',port:8443,path:'/',servername:'wrong.edge.test',ca:fs.readFileSync('/test-pki/client-ca.pem')}, () => { process.exitCode = 1; });",
      "request.on('error', error => { process.stdout.write(error.code); }); request.end();",
    ].join(""),
  );
  assert.match(rejected, /^(ECONNRESET|ERR_TLS_CERT_ALTNAME_INVALID)$/);
});

test("load-generator performs Admin setup, login, validate, apply, and rollback over Edge loopback", () => {
  prepareRuntime();
  startPerformanceServices();

  const output = compose("run", "--rm", "load-generator", "run", "/scripts/admin-lifecycle.js");
  assert.doesNotMatch(output, /admin-credential|password_hash|PRIVATE KEY/);
});
