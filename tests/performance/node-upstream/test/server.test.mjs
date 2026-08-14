import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import http from "node:http";
import net from "node:net";
import test from "node:test";

import { createMetrics } from "../src/observability.mjs";
import { createUpstreamServer, observeConnection, payloadPresets } from "../src/server.mjs";

async function withServer(run, options = {}) {
  const server = createUpstreamServer(options);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();

  try {
    await run(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

function request(url, options = {}) {
  return new Promise((resolve, reject) => {
    const requestOptions = { agent: false, ...options };
    const body = requestOptions.body;
    delete requestOptions.body;
    const clientRequest = http.request(url, requestOptions, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolve({
        statusCode: response.statusCode,
        headers: response.headers,
        body: Buffer.concat(chunks),
      }));
    });
    clientRequest.on("error", reject);
    if (body !== undefined) {
      clientRequest.write(body);
    }
    clientRequest.end();
  });
}

function maskedTextFrame(text) {
  const payload = Buffer.from(text, "utf8");
  const mask = Buffer.from([0x11, 0x22, 0x33, 0x44]);
  const masked = Buffer.from(payload.map((byte, index) => byte ^ mask[index % mask.length]));
  return Buffer.concat([Buffer.from([0x81, 0x80 | payload.length]), mask, masked]);
}

async function webSocketEcho(port, text) {
  const socket = net.createConnection({ host: "127.0.0.1", port });
  await new Promise((resolve, reject) => {
    socket.once("connect", resolve);
    socket.once("error", reject);
  });
  socket.write([
    "GET /ws/echo HTTP/1.1",
    "Host: 127.0.0.1",
    "Connection: Upgrade",
    "Upgrade: websocket",
    "Sec-WebSocket-Version: 13",
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
    "",
    "",
  ].join("\r\n"));
  const handshake = await new Promise((resolve, reject) => {
    socket.once("data", resolve);
    socket.once("error", reject);
  });
  assert.match(handshake.toString("utf8"), /101 Switching Protocols/);

  socket.write(maskedTextFrame(text));
  const frame = await new Promise((resolve, reject) => {
    socket.once("data", resolve);
    socket.once("error", reject);
  });
  assert.equal(frame[0], 0x81);
  assert.equal(frame.subarray(2).toString("utf8"), text);

  socket.write(Buffer.from([0x88, 0x80, 0x00, 0x00, 0x00, 0x00]));
  await new Promise((resolve) => socket.once("close", resolve));
}

test("health endpoint reports a deterministic ready document", async () => {
  await withServer(async (baseUrl) => {
    const response = await request(`${baseUrl}/health`);

    assert.equal(response.statusCode, 200);
    assert.equal(response.headers["content-type"], "application/json; charset=utf-8");
    assert.deepEqual(JSON.parse(response.body.toString("utf8")), { status: "ok" });
  });
});

test("metrics stay bounded and expose stable Prometheus counters", async () => {
  const metrics = createMetrics({ recentCapacity: 2 });
  await withServer(async (baseUrl) => {
    await request(`${baseUrl}/payload/small`);
    await request(`${baseUrl}/payload/medium`);
    await request(`${baseUrl}/payload/large`);
    const response = await request(`${baseUrl}/metrics`);
    await new Promise((resolve) => setImmediate(resolve));

    assert.equal(response.statusCode, 200);
    assert.match(response.body.toString("utf8"), /sponzey_test_upstream_requests_total 3/);
    assert.match(response.body.toString("utf8"), /sponzey_test_upstream_response_bytes_total 278558/);
    assert.equal(metrics.snapshot().recent.length, 2);
    assert.equal(metrics.snapshot().activeConnections, 0);
  }, { metrics });
});

test("diagnostic log records redact request body, query, and credentials", async () => {
  const records = [];
  await withServer(async (baseUrl) => {
    await request(`${baseUrl}/payload/small?token=not-for-logs`, {
      headers: {
        authorization: "Bearer not-for-logs",
        cookie: "session=not-for-logs",
      },
    });
  }, {
    logMode: "diagnostic",
    logSink: (record) => records.push(record),
  });

  assert.deepEqual(records.length, 1);
  assert.deepEqual(records[0], {
    component: "node-upstream",
    event: "request.completed",
    method: "GET",
    path: "/payload/small",
    status_code: 200,
    response_bytes: payloadPresets.small.length,
  });
  assert.equal(JSON.stringify(records).includes("not-for-logs"), false);
});

test("payload presets return their exact body and digest", async () => {
  await withServer(async (baseUrl) => {
    for (const [name, expectedBody] of Object.entries(payloadPresets)) {
      const response = await request(`${baseUrl}/payload/${name}`);
      const digest = createHash("sha256").update(expectedBody).digest("hex");

      assert.equal(response.statusCode, 200);
      assert.deepEqual(response.body, expectedBody);
      assert.equal(response.headers["x-fixture-digest"], `sha256:${digest}`);
      assert.equal(response.headers["content-length"], String(expectedBody.length));
    }
  });
});

test("payload endpoint ignores query input and rejects unknown presets", async () => {
  await withServer(async (baseUrl) => {
    const fixed = await request(`${baseUrl}/payload/small?size=999999999`);
    const unknown = await request(`${baseUrl}/payload/arbitrary`);

    assert.deepEqual(fixed.body, payloadPresets.small);
    assert.equal(unknown.statusCode, 404);
    assert.deepEqual(JSON.parse(unknown.body.toString("utf8")), { code: "NOT_FOUND" });
  });
});

test("header fixture projects only the closed request header contract", async () => {
  await withServer(async (baseUrl) => {
    const response = await request(`${baseUrl}/inspect/headers`, {
      headers: {
        "x-sponzey-fixture": "preserve-me",
        "x-forwarded-for": "198.51.100.9",
        connection: "keep-alive, x-hop-by-hop",
        "x-hop-by-hop": "remove-me",
      },
    });

    assert.equal(response.statusCode, 200);
    assert.deepEqual(JSON.parse(response.body.toString("utf8")), {
      host: new URL(baseUrl).host,
      fixture_header: "preserve-me",
      forwarded_for: "198.51.100.9",
      hop_by_hop: "remove-me",
    });
  });
});

test("body fixture returns only the fixed POST body digest and rejects oversized input", async () => {
  await withServer(async (baseUrl) => {
    const body = "edge-request-body-v1";
    const response = await request(`${baseUrl}/inspect/body`, {
      method: "POST",
      headers: { "content-type": "text/plain", "content-length": Buffer.byteLength(body) },
      body,
    });
    const document = JSON.parse(response.body.toString("utf8"));

    assert.equal(response.statusCode, 200);
    assert.deepEqual(document, {
      bytes: Buffer.byteLength(body),
      digest: `sha256:${createHash("sha256").update(body).digest("hex")}`,
    });
    assert.equal(response.body.toString("utf8").includes(body), false);

    const oversized = await request(`${baseUrl}/inspect/body`, {
      method: "POST",
      headers: { "content-length": 4097 },
      body: "x".repeat(4097),
    });
    assert.equal(oversized.statusCode, 413);
    assert.deepEqual(JSON.parse(oversized.body.toString("utf8")), { code: "BODY_TOO_LARGE" });
  });
});

test("route fixture identifies only the configured upstream base path", async () => {
  await withServer(async (baseUrl) => {
    assert.deepEqual(
      JSON.parse((await request(`${baseUrl}/route/default/route-check`)).body.toString("utf8")),
      { route: "default" },
    );
    assert.deepEqual(
      JSON.parse((await request(`${baseUrl}/route/api/routing/route-check`)).body.toString("utf8")),
      { route: "api" },
    );
    assert.deepEqual(
      JSON.parse((await request(`${baseUrl}/route/exact/routing/exact/route-check`)).body.toString("utf8")),
      { route: "exact" },
    );
    assert.equal((await request(`${baseUrl}/route/unknown`)).statusCode, 404);
  });
});

test("status and delay fixtures accept only closed presets", async () => {
  await withServer(async (baseUrl) => {
    for (const statusCode of [200, 400, 500]) {
      const response = await request(`${baseUrl}/status/${statusCode}`);
      assert.equal(response.statusCode, statusCode);
      assert.deepEqual(JSON.parse(response.body.toString("utf8")), { status: statusCode });
    }

    const start = process.hrtime.bigint();
    const delayed = await request(`${baseUrl}/delay/short?milliseconds=999999`);
    const elapsedMilliseconds = Number(process.hrtime.bigint() - start) / 1_000_000;
    assert.equal(delayed.statusCode, 200);
    assert.deepEqual(JSON.parse(delayed.body.toString("utf8")), { delay: "short" });
    assert.ok(elapsedMilliseconds >= 20, `elapsed=${elapsedMilliseconds}`);
    assert.equal((await request(`${baseUrl}/delay/arbitrary`)).statusCode, 404);
  });
});

test("stream fixture uses a fixed chunked response body", async () => {
  await withServer(async (baseUrl) => {
    const response = await request(`${baseUrl}/stream/chunks`);

    assert.equal(response.statusCode, 200);
    assert.equal(response.headers["transfer-encoding"], "chunked");
    assert.equal(response.headers["content-length"], undefined);
    assert.equal(response.body.toString("utf8"), "chunk-1\nchunk-2\nchunk-3\n");
  });
});

test("reset fixture terminates the HTTP transport without a response", async () => {
  await withServer(async (baseUrl) => {
    await assert.rejects(
      request(`${baseUrl}/reset?body=not-for-logs`),
      (error) => error.code === "ECONNRESET" || error.message === "socket hang up",
    );
  });
});

test("expected peer resets do not terminate the upstream process", () => {
  const socket = new EventEmitter();
  const metrics = createMetrics();
  observeConnection(socket, metrics);

  assert.doesNotThrow(() => socket.emit("error", Object.assign(new Error("reset"), { code: "ECONNRESET" })));
  socket.emit("close");
  assert.equal(metrics.snapshot().activeConnections, 0);
});

test("WebSocket echo accepts one masked text frame and closes cleanly", async () => {
  await withServer(async (baseUrl) => {
    await webSocketEcho(Number(new URL(baseUrl).port), "edge-echo");
  });
});

test("metrics derive bounded latency percentiles and current RPS from one snapshot", () => {
  const metrics = createMetrics({ latencyCapacity: 3, now: () => 2_000 });
  for (const [durationMs, completedAt] of [[1, 1_100], [10, 1_200], [100, 1_300], [1_000, 1_400]]) {
    metrics.recordCompleted({
      method: "GET",
      path: "/payload/small",
      responseBytes: payloadPresets.small.length,
      statusCode: 200,
      durationMs,
      completedAt,
    });
  }

  assert.deepEqual(metrics.snapshot().latency_ms, { p50: 100, p95: 1_000, p99: 1_000 });
  assert.equal(metrics.snapshot().requests_per_second, 4);
});

test("read-only stats API and dashboard use the same metrics projection", async () => {
  const metrics = createMetrics();
  await withServer(async (baseUrl) => {
    await request(`${baseUrl}/payload/small`);
    const stats = await request(`${baseUrl}/api/stats`);
    const dashboard = await request(`${baseUrl}/`);

    assert.equal(stats.statusCode, 200);
    const snapshot = JSON.parse(stats.body.toString("utf8"));
    assert.equal(snapshot.requests_total, 1);
    assert.equal(snapshot.response_bytes_total, payloadPresets.small.length);
    assert.deepEqual(Object.keys(snapshot.latency_ms).sort(), ["p50", "p95", "p99"]);

    assert.equal(dashboard.statusCode, 200);
    assert.match(dashboard.body.toString("utf8"), /fetch\("\/api\/stats"\)/);
    assert.equal(dashboard.body.toString("utf8").includes("POST"), false);
  }, { metrics });
});
