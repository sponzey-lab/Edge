import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const runner = path.join(root, "tests/performance/bin/run.mjs");

test("performance runner fixes profile repetitions and fail-closed state order", async () => {
  const { RunState, buildRunPlan, transition } = await import(runner);
  assert.equal(buildRunPlan("baseline").repetitions, 3);
  assert.equal(buildRunPlan("smoke").script, "smoke.js");
  assert.deepEqual(buildRunPlan("soak").states, [RunState.Idle, RunState.Readiness, RunState.Warmup, RunState.Running, RunState.Cooldown, RunState.Validating, RunState.Published]);
  assert.throws(() => transition([RunState.Idle], RunState.Published), /invalid performance run transition/);
});

test("performance runner dry-run neither starts Docker nor publishes artifacts", () => {
  const output = execFileSync(process.execPath, [runner, "baseline", "--dry-run"], { cwd: root, encoding: "utf8" });
  const result = JSON.parse(output);
  assert.equal(result.dry_run, true);
  assert.equal(result.repetitions, 3);
  assert.equal(result.states.at(-1), "Published");
});

test("fixed k6 profiles preserve the planned durations and Edge-only target", () => {
  const k6 = path.join(root, "tests/performance/k6");
  const baseline = readFileSync(path.join(k6, "baseline.js"), "utf8");
  const stress = readFileSync(path.join(k6, "stress.js"), "utf8");
  const soak = readFileSync(path.join(k6, "soak.js"), "utf8");
  const common = readFileSync(path.join(k6, "profile-common.js"), "utf8");
  assert.match(baseline, /duration: "1m"/);
  assert.match(baseline, /duration: "5m"/);
  assert.match(stress, /target: 50/);
  assert.match(soak, /duration: "30m"/);
  assert.match(common, /http:\/\/edge\.test:8080/);
  assert.doesNotMatch(common, /node-upstream|:3000/);
});

test("runner keeps enough bounded process output for a full smoke summary", () => {
  const source = readFileSync(runner, "utf8");
  assert.match(source, /maxBuffer: 16 \* 1024 \* 1024/);
  assert.match(source, /renameSync\(tempDir, finalDir\)/);
});

test("failed k6 runs retain bounded diagnostics in their unpublishable artifact", () => {
  const source = readFileSync(runner, "utf8");
  const common = readFileSync(path.join(root, "tests/performance/k6/profile-common.js"), "utf8");
  assert.match(source, /load-generator\.log/);
  assert.match(source, /64 \* 1024/);
  assert.match(source, /failureEvents/);
  assert.match(source, /edge\\\.payload\\\.failed/);
  assert.match(common, /edge\.payload\.failed/);
  assert.match(common, /status_code/);
});

test("resource sampler normalizes Docker CPU and memory values", async () => {
  const { parseDockerStats } = await import(runner);
  assert.deepEqual(
    parseDockerStats('{"CPUPerc":"12.50%","MemUsage":"3.5MiB / 1GiB"}', "2026-08-14T00:00:00.000Z"),
    { sampled_at: "2026-08-14T00:00:00.000Z", cpu_percent: 12.5, memory_usage_bytes: 3670016 },
  );
  assert.throws(() => parseDockerStats('{"CPUPerc":"bad","MemUsage":"none"}', "now"), /invalid Docker stats sample/);
});
