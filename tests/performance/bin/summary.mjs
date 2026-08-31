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

export const C8_POLICY = Object.freeze({
  minimum_rps_ratio: 0.95,
  maximum_p95_ratio: 1.1,
  maximum_p99_ratio: 1.1,
});

function distributionMedian(summary, path) {
  const value = path.reduce((current, key) => current?.[key], summary);
  if (!value || !Number.isFinite(value.median)) {
    throw new Error(`missing performance distribution: ${path.join(".")}`);
  }
  return value.median;
}

/**
 * Applies the fixed C8 relative performance policy to already-audited baseline summaries.
 * The caller owns host/source identity verification; this pure rule never invents a baseline.
 */
export function evaluateC8Gate(reference, candidate, policy = C8_POLICY) {
  const referenceRps = distributionMedian(reference, ["rps"]);
  const candidateRps = distributionMedian(candidate, ["rps"]);
  const referenceP95 = distributionMedian(reference, ["latency_ms", "p95"]);
  const candidateP95 = distributionMedian(candidate, ["latency_ms", "p95"]);
  const referenceP99 = distributionMedian(reference, ["latency_ms", "p99"]);
  const candidateP99 = distributionMedian(candidate, ["latency_ms", "p99"]);
  const referenceErrorRate = distributionMedian(reference, ["error_rate"]);
  const candidateErrorRate = distributionMedian(candidate, ["error_rate"]);
  if (referenceRps <= 0 || referenceP95 <= 0 || referenceP99 <= 0) {
    throw new Error("reference performance distribution must be positive");
  }
  const result = {
    rps_ratio: candidateRps / referenceRps,
    p95_ratio: candidateP95 / referenceP95,
    p99_ratio: candidateP99 / referenceP99,
    error_rate_delta: candidateErrorRate - referenceErrorRate,
  };
  const failures = [];
  if (result.rps_ratio < policy.minimum_rps_ratio) failures.push("C8_RPS_REGRESSION");
  if (result.p95_ratio > policy.maximum_p95_ratio) failures.push("C8_P95_REGRESSION");
  if (result.p99_ratio > policy.maximum_p99_ratio) failures.push("C8_P99_REGRESSION");
  if (result.error_rate_delta > 0) failures.push("C8_ERROR_RATE_INCREASE");
  return { passed: failures.length === 0, ...result, failures };
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
