#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const compose = ["compose", "--profile", "performance", "-f", "docker-compose.test.yml"];
const profiles = Object.freeze({
  smoke: { script: "smoke.js", repetitions: 1 },
  baseline: { script: "baseline.js", repetitions: 3 },
  stress: { script: "stress.js", repetitions: 1 },
  soak: { script: "soak.js", repetitions: 1 },
});

export const RunState = Object.freeze({
  Idle: "Idle", Readiness: "Readiness", Warmup: "Warmup", Running: "Running",
  Cooldown: "Cooldown", Validating: "Validating", Published: "Published", Failed: "Failed",
});

const transitions = Object.freeze({
  [RunState.Idle]: [RunState.Readiness, RunState.Failed],
  [RunState.Readiness]: [RunState.Warmup, RunState.Failed],
  [RunState.Warmup]: [RunState.Running, RunState.Failed],
  [RunState.Running]: [RunState.Cooldown, RunState.Failed],
  [RunState.Cooldown]: [RunState.Validating, RunState.Failed],
  [RunState.Validating]: [RunState.Published, RunState.Failed],
  [RunState.Published]: [],
  [RunState.Failed]: [],
});

export function transition(history, next) {
  const current = history.at(-1);
  if (!transitions[current]?.includes(next)) {
    throw new Error(`invalid performance run transition: ${current} -> ${next}`);
  }
  return [...history, next];
}

export function buildRunPlan(profile) {
  const spec = profiles[profile];
  if (!spec) throw new Error(`unknown performance profile: ${profile}`);
  return { profile, ...spec, states: [RunState.Idle, RunState.Readiness, RunState.Warmup, RunState.Running, RunState.Cooldown, RunState.Validating, RunState.Published] };
}

function command(program, args) {
  return execFileSync(program, args, {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    maxBuffer: 16 * 1024 * 1024,
  });
}

function runId() {
  return `${new Date().toISOString().replace(/[:.]/g, "-")}-${process.pid}`;
}

function metadata(profile, id) {
  return {
    run_id: id,
    profile,
    started_at: new Date().toISOString(),
    source_commit: command("git", ["rev-parse", "HEAD"]).trim(),
    source_tree: command("git", ["rev-parse", "HEAD^{tree}"]).trim(),
  };
}

export function runProfile(profile, { dryRun = false, artifactRoot = path.join(root, "artifacts", "performance") } = {}) {
  const plan = buildRunPlan(profile);
  if (dryRun) return { ...plan, dry_run: true };

  const id = runId();
  const finalDir = path.join(artifactRoot, id);
  const tempDir = `${finalDir}.partial`;
  let history = [RunState.Idle];
  rmSync(tempDir, { recursive: true, force: true });
  mkdirSync(tempDir, { recursive: true, mode: 0o700 });
  writeFileSync(path.join(tempDir, "metadata.json"), `${JSON.stringify(metadata(profile, id), null, 2)}\n`, { mode: 0o600 });
  try {
    history = transition(history, RunState.Readiness);
    command("docker", [...compose, "rm", "-s", "-f", "edge-perf", "node-upstream"]);
    const runtime = path.join(artifactRoot, "edge-perf-runtime");
    if (existsSync(runtime)) {
      command(process.execPath, ["tests/performance/bin/prepare-pki-runtime.mjs", "--clean", "--output", runtime]);
    }
    command(process.execPath, ["tests/performance/bin/prepare-pki-runtime.mjs", "--output", runtime]);
    command("docker", [...compose, "build", "edge-perf"]);
    command("docker", [...compose, "up", "-d", "--wait", "edge-perf", "node-upstream"]);
    history = transition(history, RunState.Warmup);
    history = transition(history, RunState.Running);
    for (let index = 1; index <= plan.repetitions; index += 1) {
      command("docker", [...compose, "run", "--rm", "load-generator", "run", "--summary-export", `/results/${id}.partial/${profile}-${index}.json`, `/scripts/${plan.script}`]);
    }
    history = transition(history, RunState.Cooldown);
    history = transition(history, RunState.Validating);
    writeFileSync(path.join(tempDir, "state.json"), `${JSON.stringify({ history }, null, 2)}\n`, { mode: 0o600 });
    renameSync(tempDir, finalDir);
    history = transition(history, RunState.Published);
    writeFileSync(path.join(finalDir, "state.json"), `${JSON.stringify({ history }, null, 2)}\n`, { mode: 0o600 });
    return { run_id: id, profile, artifact_dir: finalDir, history };
  } catch (error) {
    if (transitions[history.at(-1)]?.includes(RunState.Failed)) history = transition(history, RunState.Failed);
    writeFileSync(path.join(tempDir, "state.json"), `${JSON.stringify({ history, error: String(error.message) }, null, 2)}\n`, { mode: 0o600 });
    throw error;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [profile, ...flags] = process.argv.slice(2);
  try {
    process.stdout.write(`${JSON.stringify(runProfile(profile, { dryRun: flags.includes("--dry-run") }))}\n`);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
