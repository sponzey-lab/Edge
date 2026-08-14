import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const smoke = path.join(repositoryRoot, "tests/performance/k6/smoke.js");

test("k6 smoke workload targets Edge only and keeps expected failures explicit", () => {
  const source = readFileSync(smoke, "utf8");

  assert.match(source, /duration:\s*"30s"/);
  assert.match(source, /http:\/\/edge\.test:8080/);
  assert.match(source, /https:\/\/edge\.test:8443/);
  assert.match(source, /\/payload\/small/);
  assert.match(source, /\/health/);
  assert.match(source, /\/status\/400/);
  assert.match(source, /\/status\/500/);
  assert.match(source, /\/delay\/short/);
  assert.match(source, /\/delay\/slow/);
  assert.match(source, /timeout: "10ms"/);
  assert.match(source, /expectedStatuses\(0\)/);
  assert.match(source, /slow upstream is an expected client timeout/);
  assert.match(source, /\/inspect\/headers/);
  assert.match(source, /\/inspect\/body/);
  assert.match(source, /X-Forwarded-For/);
  assert.match(source, /hop-by-hop header is removed/);
  assert.match(source, /POST body digest matches/);
  assert.match(source, /\/routing\/route-check/);
  assert.match(source, /\/routing\/priority\/route-check/);
  assert.match(source, /unmatched Host is rejected/);
  assert.match(source, /\/routing\/exact\/route-check/);
  assert.match(source, /exact route wins a same-priority prefix tie/);
  assert.match(source, /exact route excludes child paths/);
  assert.match(source, /\/stream\/chunks/);
  assert.match(source, /\/reset/);
  assert.match(source, /\/ws\/echo/);
  assert.match(source, /expectedStatuses\(0, 502\)/);
  assert.match(source, /active_connections === 0/);
  assert.match(source, /used_payload_bytes === 0/);
  assert.doesNotMatch(source, /node-upstream|:3000/);
});
