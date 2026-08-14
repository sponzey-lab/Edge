import http from "k6/http";
import { check, fail } from "k6";
import { Counter } from "k6/metrics";
import exec from "k6/execution";

const payloadFailures = new Counter("edge_payload_failures");

export const edgeOptions = {
  insecureSkipTLSVerify: true,
  hosts: { "edge.test": "127.0.0.1" },
  thresholds: { checks: ["rate==1"], http_req_failed: ["rate==0"] },
  summaryTrendStats: ["avg", "min", "med", "max", "p(50)", "p(90)", "p(95)", "p(99)"],
};

export function edgeRequest() {
  const response = http.get("http://edge.test:8080/payload/small", {
    tags: { performance_phase: exec.scenario.name },
  });
  if (!check(response, { "Edge payload succeeds": (item) => item.status === 200 })) {
    const failure = {
      event: "edge.payload.failed",
      status_code: response.status,
      error_code: response.error_code || "none",
    };
    payloadFailures.add(1, { status_code: String(failure.status_code), error_code: failure.error_code });
    console.error(JSON.stringify(failure));
    fail("Edge payload check failed");
  }
}
