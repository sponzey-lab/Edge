const DEFAULT_RECENT_CAPACITY = 128;

function asPositiveInteger(value, fieldName) {
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${fieldName} must be a positive integer`);
  }
  return value;
}

function percentile(samples, percentileValue) {
  if (samples.length === 0) {
    return 0;
  }
  const sorted = samples.slice().sort((left, right) => left - right);
  return sorted[Math.ceil((percentileValue / 100) * sorted.length) - 1];
}

/**
 * Bounded request observations for the test upstream. The collector receives
 * already-projected safe fields and never stores headers, query strings, or bodies.
 */
export function createMetrics({
  latencyCapacity = DEFAULT_RECENT_CAPACITY,
  now = () => Date.now(),
  recentCapacity = DEFAULT_RECENT_CAPACITY,
} = {}) {
  const capacity = asPositiveInteger(recentCapacity, "recentCapacity");
  const latencySampleCapacity = asPositiveInteger(latencyCapacity, "latencyCapacity");
  const recent = [];
  const latencySamples = [];
  const completionTimes = [];
  const responsesByStatus = new Map();
  let requestsTotal = 0;
  let responseBytesTotal = 0;
  let activeConnections = 0;

  return Object.freeze({
    connectionOpened() {
      activeConnections += 1;
    },
    connectionClosed() {
      activeConnections = Math.max(0, activeConnections - 1);
    },
    recordCompleted({
      method,
      path,
      responseBytes,
      statusCode,
      durationMs = 0,
      completedAt = now(),
    }) {
      requestsTotal += 1;
      responseBytesTotal += responseBytes;
      responsesByStatus.set(statusCode, (responsesByStatus.get(statusCode) ?? 0) + 1);
      recent.push(Object.freeze({ method, path, responseBytes, statusCode }));
      if (recent.length > capacity) {
        recent.shift();
      }
      latencySamples.push(durationMs);
      if (latencySamples.length > latencySampleCapacity) {
        latencySamples.shift();
      }
      completionTimes.push(completedAt);
      if (completionTimes.length > capacity) {
        completionTimes.shift();
      }
    },
    snapshot() {
      const currentTime = now();
      const requestsPerSecond = completionTimes.filter((completedAt) => completedAt >= currentTime - 1_000).length;
      return Object.freeze({
        activeConnections,
        latency_ms: Object.freeze({
          p50: percentile(latencySamples, 50),
          p95: percentile(latencySamples, 95),
          p99: percentile(latencySamples, 99),
        }),
        recent: recent.slice(),
        requests_per_second: requestsPerSecond,
        requestsTotal,
        responseBytesTotal,
        responsesByStatus: Object.fromEntries(responsesByStatus),
      });
    },
    json() {
      const snapshot = this.snapshot();
      return Object.freeze({
        active_connections: snapshot.activeConnections,
        latency_ms: snapshot.latency_ms,
        requests_per_second: snapshot.requests_per_second,
        requests_total: snapshot.requestsTotal,
        response_bytes_total: snapshot.responseBytesTotal,
        responses_by_status: snapshot.responsesByStatus,
      });
    },
    prometheus() {
      const snapshot = this.snapshot();
      const lines = [
        "# TYPE sponzey_test_upstream_requests_total counter",
        `sponzey_test_upstream_requests_total ${snapshot.requestsTotal}`,
        "# TYPE sponzey_test_upstream_response_bytes_total counter",
        `sponzey_test_upstream_response_bytes_total ${snapshot.responseBytesTotal}`,
        "# TYPE sponzey_test_upstream_active_connections gauge",
        `sponzey_test_upstream_active_connections ${snapshot.activeConnections}`,
      ];
      for (const [statusCode, count] of Object.entries(snapshot.responsesByStatus)) {
        lines.push(`sponzey_test_upstream_responses_total{status_code=\"${statusCode}\"} ${count}`);
      }
      return `${lines.join("\n")}\n`;
    },
  });
}
