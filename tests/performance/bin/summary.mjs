import { readFileSync } from "node:fs";

function number(value, name) {
  if (!Number.isFinite(value)) throw new Error(`missing or invalid k6 metric: ${name}`);
  return value;
}

function metric(metrics, name) {
  const value = metrics[name];
  if (!value) throw new Error(`missing k6 metric: ${name}`);
  return value;
}

function trend(metrics, name, percentile) {
  const values = metric(metrics, name);
  return number(values[percentile], `${name}.${percentile}`);
}

function median(values) {
  const sorted = [...values].sort((left, right) => left - right);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[middle - 1] + sorted[middle]) / 2 : sorted[middle];
}

function distribution(values) {
  return { min: Math.min(...values), median: median(values), max: Math.max(...values) };
}

export function summarizeK6(raw, runIndex) {
  const metrics = raw.metrics ?? {};
  const checks = number(metric(metrics, "checks").value, "checks.value");
  const failed = number(metric(metrics, "http_req_failed").value, "http_req_failed.value");
  if (checks !== 1 || failed !== 0) throw new Error("k6 gate failed: checks or HTTP failure rate is not zero");
  return {
    run_index: runIndex,
    rps: number(metric(metrics, "http_reqs").rate, "http_reqs.rate"),
    latency_ms: {
      p50: trend(metrics, "http_req_duration", "p(50)"),
      p95: trend(metrics, "http_req_duration", "p(95)"),
      p99: trend(metrics, "http_req_duration", "p(99)"),
    },
    error_rate: failed,
    bytes: {
      sent: number(metric(metrics, "data_sent").count, "data_sent.count"),
      received: number(metric(metrics, "data_received").count, "data_received.count"),
    },
  };
}

export function summarizeFiles(files) {
  return files.map((filename, index) => summarizeK6(JSON.parse(readFileSync(filename, "utf8")), index + 1));
}

export function compareBaseline(runs) {
  if (runs.length !== 3) throw new Error("baseline comparison requires exactly three successful runs");
  return {
    rps: distribution(runs.map((run) => run.rps)),
    latency_ms: {
      p50: distribution(runs.map((run) => run.latency_ms.p50)),
      p95: distribution(runs.map((run) => run.latency_ms.p95)),
      p99: distribution(runs.map((run) => run.latency_ms.p99)),
    },
    error_rate: distribution(runs.map((run) => run.error_rate)),
    bytes: {
      sent: distribution(runs.map((run) => run.bytes.sent)),
      received: distribution(runs.map((run) => run.bytes.received)),
    },
  };
}

export function summarizeResources(samples) {
  if (!Array.isArray(samples) || samples.length === 0) throw new Error("resource summary requires samples");
  let previous = -Infinity;
  for (const sample of samples) {
    const timestamp = Date.parse(sample.sampled_at);
    if (!Number.isFinite(timestamp) || timestamp <= previous) throw new Error("resource samples are not strictly ordered");
    number(sample.cpu_percent, "resource.cpu_percent");
    number(sample.memory_usage_bytes, "resource.memory_usage_bytes");
    if (sample.cpu_percent < 0 || sample.memory_usage_bytes < 0) throw new Error("resource sample is negative");
    previous = timestamp;
  }
  const first = samples[0];
  const last = samples.at(-1);
  return {
    sample_count: samples.length,
    cpu_percent: distribution(samples.map((sample) => sample.cpu_percent)),
    memory_usage_bytes: {
      ...distribution(samples.map((sample) => sample.memory_usage_bytes)),
      first: first.memory_usage_bytes,
      last: last.memory_usage_bytes,
      delta: last.memory_usage_bytes - first.memory_usage_bytes,
    },
    elapsed_ms: Date.parse(last.sampled_at) - Date.parse(first.sampled_at),
  };
}
