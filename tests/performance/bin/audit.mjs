#!/usr/bin/env node
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export function auditArtifact(directory) {
  if (directory.endsWith(".partial")) throw new Error("partial artifact cannot be published evidence");
  const read = (name) => JSON.parse(readFileSync(path.join(directory, name), "utf8"));
  const state = read("state.json");
  const metadata = read("metadata.json");
  const summary = read("summary.json");
  const samples = read("edge-resource-samples.json");
  const expected = ["Idle", "Readiness", "Warmup", "Running", "Cooldown", "Validating", "Published"];
  if (JSON.stringify(state.history) !== JSON.stringify(expected)) throw new Error("artifact state is not published");
  if (!/^[0-9a-f]{40}$/.test(metadata.source_commit) || !/^sha256:[0-9a-f]{64}$/.test(metadata.edge_image_id)) throw new Error("artifact identity is invalid");
  const host = metadata.host_identity;
  if (!host || ["kernel", "cpu_model", "cpu_governor", "docker_version", "compose_version"].some((key) => typeof host[key] !== "string" || host[key].trim() === "")) {
    throw new Error("artifact host identity is invalid");
  }
  if (summary.profile !== metadata.profile || !Array.isArray(summary.runs) || summary.runs.length === 0) throw new Error("artifact profile summary is inconsistent");
  if (!Array.isArray(samples) || summary.resource_trend?.sample_count !== samples.length || samples.length === 0) throw new Error("artifact resource evidence is inconsistent");
  return { run_id: metadata.run_id, profile: metadata.profile, source_commit: metadata.source_commit, sample_count: samples.length };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    process.stdout.write(`${JSON.stringify(auditArtifact(process.argv[2] ?? ""))}\n`);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
