import assert from "node:assert/strict";
import test from "node:test";
import { compareBaseline, summarizeK6 } from "../bin/summary.mjs";

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
