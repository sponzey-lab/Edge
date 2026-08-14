import http from "k6/http";
import { check, fail } from "k6";
import exec from "k6/execution";

export const edgeOptions = {
  insecureSkipTLSVerify: true,
  hosts: { "edge.test": "127.0.0.1" },
  thresholds: { checks: ["rate==1"], http_req_failed: ["rate==0"] },
};

export function edgeRequest() {
  const response = http.get("http://edge.test:8080/payload/small", {
    tags: { performance_phase: exec.scenario.name },
  });
  if (!check(response, { "Edge payload succeeds": (item) => item.status === 200 })) {
    fail("Edge payload check failed");
  }
}
