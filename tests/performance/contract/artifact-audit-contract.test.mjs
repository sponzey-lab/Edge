import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { auditArtifact } from "../bin/audit.mjs";
import { fileURLToPath } from "node:url";

function fixture(directory) {
  const write = (name, value) => writeFileSync(path.join(directory, name), JSON.stringify(value));
  write("state.json", { history: ["Idle", "Readiness", "Warmup", "Running", "Cooldown", "Validating", "Published"] });
  write("metadata.json", {
    run_id: "r1", profile: "smoke", source_commit: "a".repeat(40), edge_image_id: `sha256:${"b".repeat(64)}`,
    host_identity: { kernel: "Linux", cpu_model: "test", cpu_governor: "performance", docker_version: "1", compose_version: "1" },
  });
  write("summary.json", { profile: "smoke", runs: [{}], resource_trend: { sample_count: 1 } });
  write("edge-resource-samples.json", [{ sampled_at: "2026-08-14T00:00:00.000Z" }]);
}

test("artifact audit accepts only coherent published evidence", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "edge-performance-audit-"));
  fixture(directory);
  assert.deepEqual(auditArtifact(directory), { run_id: "r1", profile: "smoke", source_commit: "a".repeat(40), sample_count: 1 });
  assert.throws(() => auditArtifact(`${directory}.partial`), /partial artifact/);
  const executable = fileURLToPath(new URL("../bin/audit.mjs", import.meta.url));
  assert.match(execFileSync(process.execPath, [executable, directory], { encoding: "utf8" }), /"run_id":"r1"/);
  writeFileSync(path.join(directory, "metadata.json"), JSON.stringify({ run_id: "r1", profile: "smoke", source_commit: "a".repeat(40), edge_image_id: `sha256:${"b".repeat(64)}` }));
  assert.throws(() => auditArtifact(directory), /host identity/);
});
