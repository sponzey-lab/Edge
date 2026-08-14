import assert from "node:assert/strict";
import test from "node:test";
import { compareBaseline, summarizeK6, summarizeResources } from "../bin/summary.mjs";

function k6Summary({ checks = 1, failed = 0, rate = 100, p50 = 2, p95 = 5, p99 = 9 } = {}) {
  return { metrics: {
    checks: { value: checks }, http_req_failed: { value: failed }, http_reqs: { rate },
    http_req_duration: { "p(50)": p50, "p(95)": p95, "p(99)": p99 },
    data_sent: { count: 10 }, data_received: { count: 20 },
  } };
}

test("k6 summary normalizes the required performance evidence", () => {
  assert.deepEqual(summarizeK6(k6Summary(), 1), {
    run_index: 1, rps: 100, latency_ms: { p50: 2, p95: 5, p99: 9 }, error_rate: 0,
    bytes: { sent: 10, received: 20 },
  });
  assert.throws(() => summarizeK6(k6Summary({ failed: 0.01 }), 1), /k6 gate failed/);
});

test("baseline comparison requires three successful runs and reports distributions", () => {
  const runs = [100, 110, 90].map((rate, index) => summarizeK6(k6Summary({ rate, p95: 5 + index }), index + 1));
  assert.deepEqual(compareBaseline(runs).rps, { min: 90, median: 100, max: 110 });
  assert.deepEqual(compareBaseline(runs).latency_ms.p95, { min: 5, median: 6, max: 7 });
  assert.throws(() => compareBaseline(runs.slice(0, 2)), /exactly three/);
});

test("resource trend reports distributions without inventing an approval threshold", () => {
  const trend = summarizeResources([
    { sampled_at: "2026-08-14T00:00:00.000Z", cpu_percent: 1, memory_usage_bytes: 10 },
    { sampled_at: "2026-08-14T00:00:01.000Z", cpu_percent: 3, memory_usage_bytes: 15 },
    { sampled_at: "2026-08-14T00:00:02.000Z", cpu_percent: 2, memory_usage_bytes: 12 },
  ]);
  assert.deepEqual(trend.cpu_percent, { min: 1, median: 2, max: 3 });
  assert.deepEqual(trend.memory_usage_bytes, { min: 10, median: 12, max: 15, first: 10, last: 12, delta: 2 });
  assert.equal(trend.elapsed_ms, 2000);
  assert.throws(() => summarizeResources([]), /requires samples/);
  assert.throws(() => summarizeResources([
    { sampled_at: "2026-08-14T00:00:01.000Z", cpu_percent: 1, memory_usage_bytes: 1 },
    { sampled_at: "2026-08-14T00:00:00.000Z", cpu_percent: 1, memory_usage_bytes: 1 },
  ]), /strictly ordered/);
});
