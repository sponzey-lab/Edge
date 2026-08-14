#!/usr/bin/env node
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { compareBaseline, summarizeFiles, summarizeResources } from "./summary.mjs";

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
    host_platform: process.platform,
    host_arch: process.arch,
    edge_image_id: command("docker", ["image", "inspect", "--format", "{{.Id}}", "sponzey-edge-test-edge-perf"]).trim(),
  };
}

export function parseDockerStats(line, sampledAt) {
  const stats = JSON.parse(line);
  const cpu = Number.parseFloat(stats.CPUPerc);
  const memory = stats.MemUsage.split(" / ")[0].trim();
  const match = /^(\d+(?:\.\d+)?)(B|KiB|MiB|GiB)$/.exec(memory);
  if (!Number.isFinite(cpu) || !match) throw new Error("invalid Docker stats sample");
  const multiplier = { B: 1, KiB: 1024, MiB: 1024 ** 2, GiB: 1024 ** 3 }[match[2]];
  return { sampled_at: sampledAt, cpu_percent: cpu, memory_usage_bytes: Math.round(Number(match[1]) * multiplier) };
}

function sampleEdge() {
  const container = command("docker", [...compose, "ps", "-q", "edge-perf"]).trim();
  if (!container) throw new Error("edge-perf container is unavailable for sampling");
  return parseDockerStats(
    command("docker", ["stats", "--no-stream", "--format", "{{json .}}", container]).trim(),
    new Date().toISOString(),
  );
}

function runLoadGenerator(args, samples) {
  return new Promise((resolve, reject) => {
    let samplingError;
    let diagnostics = "";
    let failureEvents = "";
    const appendDiagnostics = (chunk) => {
      diagnostics = `${diagnostics}${chunk}`.slice(-(64 * 1024));
    };
    const sample = () => {
      try { samples.push(sampleEdge()); } catch (error) { samplingError ??= error; }
    };
    sample();
    const timer = setInterval(sample, 1_000);
    const captureDiagnostics = (chunk) => {
      const text = chunk.toString("utf8");
      appendDiagnostics(text);
      const events = text.match(/\{"event":"edge\.payload\.failed"[^\n]*\}/g) ?? [];
      if (events.length > 0) failureEvents = `${failureEvents}${events.join("\n")}\n`.slice(-(8 * 1024));
    };
    const child = spawn("docker", args, { cwd: root, stdio: ["ignore", "pipe", "pipe"] });
    child.stdout.on("data", captureDiagnostics);
    child.stderr.on("data", captureDiagnostics);
    child.once("error", (error) => { clearInterval(timer); reject(error); });
    child.once("close", (code) => {
      clearInterval(timer);
      sample();
      if (code !== 0) {
        const error = new Error(`load-generator exited with status ${code}`);
        error.diagnostics = `${failureEvents}--- k6 output tail ---\n${diagnostics}`;
        reject(error);
      }
      else if (samplingError || samples.length === 0) reject(samplingError ?? new Error("no Edge resource samples collected"));
      else resolve();
    });
  });
}

export async function runProfile(profile, { dryRun = false, artifactRoot = path.join(root, "artifacts", "performance") } = {}) {
  const plan = buildRunPlan(profile);
  if (dryRun) return { ...plan, dry_run: true };

  const id = runId();
  const finalDir = path.join(artifactRoot, id);
  const tempDir = `${finalDir}.partial`;
  let history = [RunState.Idle];
  rmSync(tempDir, { recursive: true, force: true });
  mkdirSync(tempDir, { recursive: true, mode: 0o700 });
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
    writeFileSync(path.join(tempDir, "metadata.json"), `${JSON.stringify(metadata(profile, id), null, 2)}\n`, { mode: 0o600 });
    history = transition(history, RunState.Warmup);
    history = transition(history, RunState.Running);
    const samples = [];
    for (let index = 1; index <= plan.repetitions; index += 1) {
      try {
        await runLoadGenerator([...compose, "run", "--rm", "load-generator", "run", "--summary-export", `/results/${id}.partial/${profile}-${index}.json`, `/scripts/${plan.script}`], samples);
      } catch (error) {
        writeFileSync(path.join(tempDir, `${profile}-${index}.load-generator.log`), error.diagnostics ?? String(error.message), { mode: 0o600 });
        throw error;
      }
    }
    history = transition(history, RunState.Cooldown);
    history = transition(history, RunState.Validating);
    const runs = summarizeFiles(Array.from({ length: plan.repetitions }, (_, index) => path.join(tempDir, `${profile}-${index + 1}.json`)));
    const resourceTrend = summarizeResources(samples);
    writeFileSync(path.join(tempDir, "summary.json"), `${JSON.stringify({ profile, runs, resource_trend: resourceTrend, baseline_comparison: profile === "baseline" ? compareBaseline(runs) : undefined }, null, 2)}\n`, { mode: 0o600 });
    writeFileSync(path.join(tempDir, "edge-resource-samples.json"), `${JSON.stringify(samples, null, 2)}\n`, { mode: 0o600 });
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
    const result = await runProfile(profile, { dryRun: flags.includes("--dry-run") });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
