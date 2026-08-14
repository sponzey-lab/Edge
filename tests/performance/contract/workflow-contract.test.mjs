import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const workflow = readFileSync(path.join(root, ".github/workflows/performance-smoke.yml"), "utf8");

test("performance workflow keeps smoke automatic and longer profiles dispatch-only", () => {
  assert.match(workflow, /pull_request:/);
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /options: \[smoke, baseline, stress, soak\]/);
  assert.match(workflow, /github\.event_name != 'workflow_dispatch' \|\| inputs\.profile == 'smoke'/);
  assert.match(workflow, /github\.event_name == 'workflow_dispatch' && inputs\.profile != 'smoke'/);
  assert.match(workflow, /node tests\/performance\/bin\/run\.mjs smoke/);
});

test("performance workflow uploads only allow-listed non-secret evidence", () => {
  assert.match(workflow, /artifacts\/performance\/\*\/summary\.json/);
  assert.match(workflow, /artifacts\/performance\/\*\/edge-resource-samples\.json/);
  assert.doesNotMatch(workflow, /edge-perf-runtime/);
  assert.doesNotMatch(workflow, /docker\.sock/);
  assert.doesNotMatch(workflow, /cache-dependency-path/);
});
