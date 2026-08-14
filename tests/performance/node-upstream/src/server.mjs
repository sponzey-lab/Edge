/**
 * Test-only deterministic HTTP upstream. It accepts only fixed scenario paths
 * so a load profile cannot turn request input into unbounded response data.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";

import { createMetrics } from "./observability.mjs";

export const payloadPresets = Object.freeze({
  small: Buffer.from("sponzey-edge-small-payload-v1\n", "utf8"),
  medium: Buffer.from("m".repeat(16 * 1024), "utf8"),
  large: Buffer.from("l".repeat(256 * 1024), "utf8"),
});

const delayPresetsMilliseconds = Object.freeze({
  short: 25,
});
const maximumInspectableBodyBytes = 4096;
const webSocketAcceptGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const dashboardHtml = readFileSync(new URL("../public/index.html", import.meta.url), "utf8");

function sendJson(response, statusCode, document) {
  const body = Buffer.from(JSON.stringify(document), "utf8");
  response.statusCode = statusCode;
  response.setHeader("content-length", body.length);
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.end(body);
}

function sendPayload(response, body) {
  const digest = createHash("sha256").update(body).digest("hex");
  response.statusCode = 200;
  response.setHeader("content-length", body.length);
  response.setHeader("content-type", "application/octet-stream");
  response.setHeader("x-fixture-digest", `sha256:${digest}`);
  response.end(body);
}

function sendMetrics(response, metrics) {
  const body = Buffer.from(metrics.prometheus(), "utf8");
  response.statusCode = 200;
  response.setHeader("content-length", body.length);
  response.setHeader("content-type", "text/plain; version=0.0.4; charset=utf-8");
  response.end(body);
}

function sendDashboard(response) {
  const body = Buffer.from(dashboardHtml, "utf8");
  response.statusCode = 200;
  response.setHeader("content-length", body.length);
  response.setHeader("content-type", "text/html; charset=utf-8");
  response.end(body);
}

function inspectRequestHeaders(request) {
  return {
    host: request.headers.host ?? null,
    fixture_header: request.headers["x-sponzey-fixture"] ?? null,
    forwarded_for: request.headers["x-forwarded-for"] ?? null,
    hop_by_hop: request.headers["x-hop-by-hop"] ?? null,
  };
}

function inspectRequestBody(request, response) {
  const declaredBytes = Number(request.headers["content-length"] ?? 0);
  if (!Number.isSafeInteger(declaredBytes) || declaredBytes < 0 || declaredBytes > maximumInspectableBodyBytes) {
    request.resume();
    sendJson(response, 413, { code: "BODY_TOO_LARGE" });
    return;
  }

  const chunks = [];
  let receivedBytes = 0;
  let completed = false;
  request.on("data", (chunk) => {
    receivedBytes += chunk.length;
    if (receivedBytes > maximumInspectableBodyBytes) {
      completed = true;
      request.resume();
      sendJson(response, 413, { code: "BODY_TOO_LARGE" });
      return;
    }
    chunks.push(chunk);
  });
  request.on("end", () => {
    if (completed) {
      return;
    }
    const body = Buffer.concat(chunks);
    sendJson(response, 200, {
      bytes: body.length,
      digest: `sha256:${createHash("sha256").update(body).digest("hex")}`,
    });
  });
}

function sendWebSocketText(socket, payload) {
  if (payload.length > 125) {
    socket.destroy();
    return;
  }
  socket.write(Buffer.concat([Buffer.from([0x81, payload.length]), payload]));
}

function attachWebSocketEcho(socket, initialData) {
  let pending = Buffer.from(initialData);
  const consume = () => {
    while (pending.length >= 2) {
      const first = pending[0];
      const second = pending[1];
      const finalFrame = (first & 0x80) !== 0;
      const opcode = first & 0x0f;
      const masked = (second & 0x80) !== 0;
      const payloadLength = second & 0x7f;
      const frameLength = 2 + (masked ? 4 : 0) + payloadLength;
      if (!finalFrame || !masked || payloadLength > 125) {
        socket.destroy();
        return;
      }
      if (pending.length < frameLength) {
        return;
      }
      const mask = pending.subarray(2, 6);
      const payload = Buffer.from(pending.subarray(masked ? 6 : 2, frameLength));
      for (let index = 0; index < payload.length; index += 1) {
        payload[index] ^= mask[index % mask.length];
      }
      pending = pending.subarray(frameLength);
      if (opcode === 0x8) {
        socket.end(Buffer.from([0x88, 0x00]));
        return;
      }
      if (opcode !== 0x1) {
        socket.destroy();
        return;
      }
      sendWebSocketText(socket, payload);
    }
  };

  socket.on("data", (chunk) => {
    pending = Buffer.concat([pending, chunk]);
    if (pending.length > 1024) {
      socket.destroy();
      return;
    }
    consume();
  });
  consume();
}

function handleRequest(request, response, metrics) {
  let pathname = new URL(request.url, "http://node-upstream.invalid").pathname;
  const routeName = pathname.match(/^\/route\/(default|api|exact)(?=\/|$)/)?.[1];
  if (routeName) {
    pathname = pathname.slice(`/route/${routeName}`.length) || "/";
  }
  if (pathname.endsWith("/route-check") || pathname.includes("/route-check/")) {
    sendJson(response, 200, { route: routeName ?? "default" });
    return;
  }
  if (pathname === "/inspect/body" && request.method === "POST") {
    inspectRequestBody(request, response);
    return;
  }
  if (request.method !== "GET") {
    sendJson(response, 405, { code: "METHOD_NOT_ALLOWED" });
    return;
  }

  if (pathname === "/health") {
    sendJson(response, 200, { status: "ok" });
    return;
  }

  if (pathname === "/inspect/headers") {
    sendJson(response, 200, inspectRequestHeaders(request));
    return;
  }

  if (pathname === "/metrics") {
    sendMetrics(response, metrics);
    return;
  }

  if (pathname === "/api/stats") {
    sendJson(response, 200, metrics.json());
    return;
  }

  if (pathname === "/") {
    sendDashboard(response);
    return;
  }

  if (pathname === "/reset") {
    request.socket.destroy();
    return;
  }

  const statusCode = Number(pathname.match(/^\/status\/(200|400|500)$/)?.[1]);
  if (statusCode) {
    sendJson(response, statusCode, { status: statusCode });
    return;
  }

  const delayName = pathname.match(/^\/delay\/(short)$/)?.[1];
  if (delayName) {
    setTimeout(() => sendJson(response, 200, { delay: delayName }), delayPresetsMilliseconds[delayName]);
    return;
  }

  if (pathname === "/stream/chunks") {
    response.statusCode = 200;
    response.setHeader("content-type", "text/plain; charset=utf-8");
    response.write("chunk-1\n");
    response.write("chunk-2\n");
    response.end("chunk-3\n");
    return;
  }

  const presetName = pathname.match(/^\/payload\/(small|medium|large)$/)?.[1];
  if (presetName) {
    sendPayload(response, payloadPresets[presetName]);
    return;
  }

  sendJson(response, 404, { code: "NOT_FOUND" });
}

export function createUpstreamServer({
  logMode = "benchmark",
  logSink = () => {},
  metrics = createMetrics(),
} = {}) {
  if (!["benchmark", "diagnostic"].includes(logMode)) {
    throw new Error("logMode must be benchmark or diagnostic");
  }

  const server = createServer((request, response) => {
    const pathname = new URL(request.url, "http://node-upstream.invalid").pathname;
    const startedAt = process.hrtime.bigint();
    response.on("finish", () => {
      const responseBytes = Number(response.getHeader("content-length") ?? 0);
      const safeRecord = Object.freeze({
        component: "node-upstream",
        event: "request.completed",
        method: request.method,
        path: pathname,
        status_code: response.statusCode,
        response_bytes: responseBytes,
      });
      metrics.recordCompleted({
        method: safeRecord.method,
        path: safeRecord.path,
        responseBytes,
        statusCode: safeRecord.status_code,
        durationMs: Number(process.hrtime.bigint() - startedAt) / 1_000_000,
      });
      if (logMode === "diagnostic") {
        logSink(safeRecord);
      }
    });
    handleRequest(request, response, metrics);
  });
  server.on("connection", (socket) => observeConnection(socket, metrics));
  server.on("upgrade", (request, socket, head) => {
    let pathname = new URL(request.url, "http://node-upstream.invalid").pathname;
    const routeName = pathname.match(/^\/route\/(default|api|exact)(?=\/|$)/)?.[1];
    if (routeName) {
      pathname = pathname.slice(`/route/${routeName}`.length) || "/";
    }
    const key = request.headers["sec-websocket-key"];
    if (
      request.method !== "GET"
      || pathname !== "/ws/echo"
      || request.headers.upgrade?.toLowerCase() !== "websocket"
      || typeof key !== "string"
    ) {
      socket.end("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
      return;
    }
    const accept = createHash("sha1").update(`${key}${webSocketAcceptGuid}`).digest("base64");
    socket.write([
      "HTTP/1.1 101 Switching Protocols",
      "Connection: Upgrade",
      "Upgrade: websocket",
      `Sec-WebSocket-Accept: ${accept}`,
      "",
      "",
    ].join("\r\n"));
    attachWebSocketEcho(socket, head);
  });
  return server;
}

export function observeConnection(socket, metrics) {
  metrics.connectionOpened();
  socket.on("error", () => {});
  socket.on("close", () => metrics.connectionClosed());
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const server = createUpstreamServer();
  server.listen(3000, "0.0.0.0");
}
