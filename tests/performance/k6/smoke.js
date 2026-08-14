import http from "k6/http";
import { check, fail } from "k6";
import ws from "k6/ws";

const httpBaseUrl = "http://edge.test:8080";
const httpsBaseUrl = "https://edge.test:8443";
const fixtureDigest = "sha256:ede19c3fe66fe9de4bac5620355b00c4f6b6d48ab890f2d90e896d863f636220";
const requestBody = "edge-request-body-v1";
const requestBodyDigest = "sha256:bfcb757022c48360ee7ffe74943b9cc7a973e98f4b55732d86021ce1493a4ea3";

export const options = {
  insecureSkipTLSVerify: true,
  hosts: {
    "edge.test": "127.0.0.1",
  },
  scenarios: {
    smoke: {
      executor: "constant-vus",
      vus: 1,
      duration: "30s",
    },
  },
  thresholds: {
    checks: ["rate==1"],
    http_req_failed: ["rate==0"],
  },
};

function requireCheck(response, checks, description) {
  if (!check(response, checks)) {
    fail(`${description} failed`);
  }
}

function getExpected(url, statusCode) {
  return http.get(url, { responseCallback: http.expectedStatuses(statusCode) });
}

function responseHeader(response, name) {
  const key = Object.keys(response.headers).find((candidate) => candidate.toLowerCase() === name.toLowerCase());
  return key ? response.headers[key] : undefined;
}

function verifyWebSocket() {
  let echoed = false;
  const result = ws.connect("ws://edge.test:8080/ws/echo", {}, (socket) => {
    socket.on("open", () => socket.send("edge-smoke"));
    socket.on("message", (message) => {
      echoed = message === "edge-smoke";
      socket.close();
    });
    socket.setTimeout(() => socket.close(), 1000);
  });
  requireCheck(result, { "WebSocket handshake succeeds": (response) => response && response.status === 101 }, "WebSocket");
  if (!echoed) {
    fail("WebSocket echo failed");
  }
}

export default function () {
  requireCheck(http.get(`${httpBaseUrl}/health`), { "upstream health succeeds": (response) => response.status === 200 }, "health");
  const small = http.get(`${httpBaseUrl}/payload/small`);
  requireCheck(small, {
    "small payload succeeds": (response) => response.status === 200,
    "small payload digest matches": (response) => responseHeader(response, "X-Fixture-Digest") === fixtureDigest,
  }, "small payload");

  const secure = http.get(`${httpsBaseUrl}/payload/small`);
  requireCheck(secure, {
    "HTTPS payload succeeds": (response) => response.status === 200,
    "HTTPS payload digest matches": (response) => responseHeader(response, "X-Fixture-Digest") === fixtureDigest,
  }, "HTTPS payload");

  requireCheck(getExpected(`${httpBaseUrl}/status/400`, 400), { "expected 400 is preserved": (response) => response.status === 400 }, "status 400");
  requireCheck(getExpected(`${httpBaseUrl}/status/500`, 500), { "expected 500 is preserved": (response) => response.status === 500 }, "status 500");
  requireCheck(http.get(`${httpBaseUrl}/delay/short`), { "fixed delay succeeds": (response) => response.status === 200 }, "delay");
  const headerProjection = http.get(`${httpBaseUrl}/inspect/headers`, {
    headers: {
      "X-Sponzey-Fixture": "preserve-me",
      "X-Forwarded-For": "198.51.100.9",
      Connection: "keep-alive, X-Hop-By-Hop",
      "X-Hop-By-Hop": "remove-me",
    },
  });
  requireCheck(headerProjection, {
    "custom header is preserved": (response) => JSON.parse(response.body).fixture_header === "preserve-me",
    "forwarded client address is normalized": (response) => JSON.parse(response.body).forwarded_for === "127.0.0.1",
    "hop-by-hop header is removed": (response) => JSON.parse(response.body).hop_by_hop === null,
  }, "header projection");
  const bodyProjection = http.post(`${httpBaseUrl}/inspect/body`, requestBody, {
    headers: { "content-type": "text/plain" },
  });
  requireCheck(bodyProjection, {
    "POST body succeeds": (response) => response.status === 200,
    "POST body digest matches": (response) => JSON.parse(response.body).digest === requestBodyDigest,
  }, "body projection");
  requireCheck(http.get(`${httpBaseUrl}/route-check`), {
    "default Host route is selected": (response) => response.status === 200 && JSON.parse(response.body).route === "default",
  }, "default route");
  requireCheck(http.get(`${httpBaseUrl}/routing/route-check`), {
    "more specific prefix route is selected": (response) => response.status === 200 && JSON.parse(response.body).route === "api",
  }, "prefix route");
  requireCheck(http.get(`${httpBaseUrl}/routing/priority/route-check`), {
    "higher priority route wins over longer prefix": (response) => response.status === 200 && JSON.parse(response.body).route === "api",
  }, "priority route");
  requireCheck(http.get(`${httpBaseUrl}/routing/exact/route-check`), {
    "exact route wins a same-priority prefix tie": (response) => response.status === 200 && JSON.parse(response.body).route === "exact",
  }, "exact route");
  requireCheck(http.get(`${httpBaseUrl}/routing/exact/route-check/child`), {
    "exact route excludes child paths": (response) => response.status === 200 && JSON.parse(response.body).route === "api",
  }, "exact route child");
  requireCheck(http.get(`${httpBaseUrl}/route-check`, {
    headers: { Host: "unmatched.edge.test" },
    responseCallback: http.expectedStatuses(404),
  }), { "unmatched Host is rejected": (response) => response.status === 404 }, "host mismatch");
  requireCheck(http.get(`${httpBaseUrl}/stream/chunks`), { "chunk stream is preserved": (response) => response.status === 200 && response.body === "chunk-1\nchunk-2\nchunk-3\n" }, "stream");
  requireCheck(
    http.get(`${httpBaseUrl}/reset`, { responseCallback: http.expectedStatuses(0, 502) }),
    { "reset is classified as expected failure": (response) => response.status === 0 || response.status === 502 },
    "reset",
  );
  verifyWebSocket();
}

export function teardown() {
  const status = http.get("http://127.0.0.1:9443/api/v1/status");
  requireCheck(status, {
    "Edge status is healthy after smoke": (response) => response.status === 200,
    "Edge releases logical payload after smoke": (response) => JSON.parse(response.body).live_resource_status?.used_payload_bytes === 0,
    "Edge releases connections after smoke": (response) => JSON.parse(response.body).live_resource_status?.active_connections === 0,
  }, "cleanup");
}
