class ApiError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = "ApiError";
    this.status = details.status || 0;
    this.code = details.code || (this.status === 0 ? "NETWORK_ERROR" : `HTTP_${this.status}`);
    this.hint = details.hint || "";
    this.requestId = details.requestId || "";
  }
}

const fallbackConfig = `schema_version = 1

[admin]
bind = "127.0.0.1:9443"
auth_required = true

[[listeners]]
id = "http"
bind = "0.0.0.0:8080"
protocol = "http"

[[services]]
id = "fallback-app"
upstreams = ["http://127.0.0.1:3000"]

[[routes]]
id = "proxy-host-fallback-app"
hosts = ["app.example.test"]
paths = ["/"]
service_id = "fallback-app"
enabled = true
`;

const fallbackState = {
  status: {
    current_revision_id: "rev-ui-smoke",
    desired_revision_id: "rev-ui-smoke",
    active_revision_id: "rev-ui-smoke",
    restart_required: false,
    activation_state: "aligned",
    desired_resource_policy: {
      max_connections: 1024,
      max_inflight_payload_bytes: 134217728,
    },
    active_resource_policy: {
      max_connections: 1024,
      max_inflight_payload_bytes: 134217728,
    },
    live_resource_status: {
      revision_id: "rev-ui-smoke",
      generation: 1,
      used_payload_bytes: 4096,
      payload_limit_bytes: 134217728,
      active_connections: 1,
      pressure: "normal",
    },
    routes: 1,
    services: 1,
    certificates: 1,
  },
  health: {
    status: "ui-smoke",
    current_revision_id: "rev-ui-smoke",
    routes: 1,
    services: 1,
  },
  upstreamHealth: {
    revision_id: "rev-ui-smoke",
    generation: 1,
    upstreams: [
      {
        service_id: "fallback-app",
        upstream_id: "fallback-app-primary",
        status: "disabled",
        drain_state: "active",
        connection_count: 0,
      },
    ],
  },
  metrics: {
    ready: true,
    desired_generation: 1,
    applied_generation: 1,
    dropped: {},
    counters: [],
    gauges: [],
    histograms: [],
  },
  config: {
    revision_id: "rev-ui-smoke",
    config: fallbackConfig,
  },
  hosts: [
    {
      id: "fallback-app",
      name: "fallback-app",
      domains: ["app.example.test"],
      path_prefix: "/",
      upstream_url: "http://127.0.0.1:3000",
      upstreams: [{ id: "fallback-app-primary", url: "http://127.0.0.1:3000", administrative_state: "active" }],
      health_check: { enabled: false },
      retry: { enabled: false, max_retries: 1, max_replay_bytes: 32768 },
      passive_health: { enabled: false },
      https_enabled: true,
      letsencrypt_enabled: false,
      redirect_http_to_https: true,
      enabled: true,
    },
  ],
  certificates: [
    {
      certificate_ref: "proxy-host-fallback-app",
      domains: ["app.example.test"],
      source: "manual",
      expired: false,
      expiring_soon: false,
      not_after_epoch_seconds: 1893456000,
      private_key: "***",
    },
  ],
  accessLogs: [
    {
      request_id: "req-ui-smoke",
      revision_id: "rev-ui-smoke",
      route_id: "proxy-host-fallback-app",
      upstream_id: "fallback-app-0",
      status_code: 200,
      duration_ms: 12,
    },
  ],
  errorLogs: [],
  trustBundles: [],
  trustBundleImportState: "ready",
  audit: {
    ledger: { generation: 1, sequence: 1, admission_state: "healthy" },
    records: [
      {
        sequence: 1,
        received_at_epoch_seconds: 1704067200,
        action: "config.apply",
        target_kind: "config_revision",
        target_id: "rev-ui-smoke",
        outcome: "succeeded",
        actor_kind: "bootstrap_admin",
        request_id: "req-ui-smoke",
      },
    ],
    next_cursor: null,
  },
};

const state = {
  mode: "connecting",
  authenticated: false,
  setupRequired: false,
  csrfToken: "",
  activePanel: "dashboard",
  activeHostId: "",
  certificateImportState: "ready",
  lastError: null,
  lastResult: "",
  diff: null,
  status: { ...fallbackState.status },
  health: { ...fallbackState.health },
  upstreamHealth: { revision_id: "", generation: 0, upstreams: [] },
  metrics: { ready: false, desired_generation: 0, applied_generation: 0, dropped: {} },
  config: { revision_id: "", config: "" },
  hosts: [],
  certificates: [],
  trustBundles: [],
  trustBundleImportState: "ready",
  accessLogs: [],
  errorLogs: [],
  audit: { ledger: { generation: 0, sequence: 0, admission_state: "starting" }, records: [], next_cursor: null },
  auditViewState: "idle",
  auditError: "",
  auditCursor: null,
  auditCursorStack: [],
  supportBundleState: "No bundle created in this session.",
};

let auditRequestGeneration = 0;

const api = {
  async request(path, options = {}) {
    const headers = {
      "X-Request-Id": requestId(),
      ...(options.headers || {}),
    };

    if (options.json !== undefined) {
      headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(options.json);
    } else if (typeof options.body === "string" && !headers["Content-Type"]) {
      headers["Content-Type"] = "text/plain";
    }

    if (options.csrf) {
      headers["X-CSRF-Token"] = state.csrfToken;
    }

    let response;
    try {
      response = await fetch(`/api/v1${path}`, {
        method: options.method || "GET",
        headers,
        body: options.body,
        credentials: "same-origin",
      });
    } catch (error) {
      throw new ApiError(error.message || "Admin API is unavailable");
    }

    const raw = await response.text();
    const body = raw ? safeJson(raw) : {};

    if (!response.ok) {
      throw new ApiError(body.message || `request failed: ${response.status}`, {
        status: response.status,
        code: body.code,
        hint: body.hint,
        requestId: body.request_id,
      });
    }

    return body;
  },
  status() {
    return this.request("/status");
  },
  health() {
    return this.request("/health");
  },
  upstreamHealth() {
    return this.request("/upstream-health");
  },
  metrics() {
    return this.request("/metrics");
  },
  setup(passwordHash) {
    return this.request("/setup", {
      method: "POST",
      json: { password_hash: passwordHash },
    });
  },
  login(passwordHash) {
    return this.request("/login", {
      method: "POST",
      json: { password_hash: passwordHash },
    });
  },
  logout() {
    return this.request("/logout", { method: "POST", csrf: true });
  },
  config() {
    return this.request("/config");
  },
  validateConfig(source) {
    return this.request("/config/validate", { method: "POST", body: source });
  },
  diffConfig(source) {
    return this.request("/config/diff", { method: "POST", body: source });
  },
  applyConfig(source) {
    return this.request("/config/apply", {
      method: "POST",
      body: source,
      csrf: true,
    });
  },
  rollback(revisionId) {
    return this.request("/config/rollback", {
      method: "POST",
      json: { revision_id: revisionId },
      csrf: true,
    });
  },
  createSupportBundle() {
    return this.request("/support-bundles", { method: "POST", csrf: true });
  },
  proxyHosts() {
    return this.request("/proxy-hosts");
  },
  createProxyHost(payload) {
    return this.request("/proxy-hosts", {
      method: "POST",
      json: payload,
      csrf: true,
    });
  },
  updateProxyHost(id, payload) {
    return this.request(`/proxy-hosts/${encodeURIComponent(id)}`, {
      method: "PATCH",
      json: payload,
      csrf: true,
    });
  },
  deleteProxyHost(id) {
    return this.request(`/proxy-hosts/${encodeURIComponent(id)}`, {
      method: "DELETE",
      csrf: true,
    });
  },
  certificates() {
    return this.request("/certificates");
  },
  certificate(id) {
    return this.request(`/certificates/${encodeURIComponent(id)}`);
  },
  importCertificate(id, payload) {
    return this.request(`/certificates/${encodeURIComponent(id)}/import`, {
      method: "POST",
      json: payload,
      csrf: true,
    });
  },
  trustBundles() {
    return this.request("/trust-bundles");
  },
  importTrustBundle(trustBundleRef, encodedMaterial) {
    return this.request("/trust-bundles", {
      method: "POST",
      json: { trust_bundle_ref: trustBundleRef, encoded_material: encodedMaterial },
      csrf: true,
    });
  },
  deleteTrustBundle(trustBundleRef) {
    return this.request(`/trust-bundles/${encodeURIComponent(trustBundleRef)}`, {
      method: "DELETE",
      csrf: true,
    });
  },
  accessLogs() {
    return this.request("/logs/access");
  },
  errorLogs() {
    return this.request("/logs/errors");
  },
  audit(parameters) {
    return this.request(`/audit?${parameters.toString()}`);
  },
};

const elements = {};

document.addEventListener("DOMContentLoaded", () => {
  cacheElements();
  bindEvents();
  resetHostForm();
  render();
  bootstrap();
});

function cacheElements() {
  for (const element of document.querySelectorAll("[id]")) {
    elements[element.getAttribute("id")] = element;
  }
}

function bindEvents() {
  document.querySelectorAll(".nav-tab").forEach((button) => {
    button.addEventListener("click", () => setPanel(button.dataset.panel));
  });

  elements.retryApiBtn.addEventListener("click", bootstrap);
  elements.logoutBtn.addEventListener("click", logout);
  elements.loginForm.addEventListener("submit", login);
  elements.setupForm.addEventListener("submit", setup);
  elements.proxyForm.addEventListener("submit", saveProxyHost);
  elements.addUpstreamBtn.addEventListener("click", () => addUpstreamRow());
  elements.upstreamRows.addEventListener("click", handleUpstreamRowAction);
  elements.healthCheckEnabled.addEventListener("change", syncHealthFields);
  elements.certificateImportForm.addEventListener("submit", importCertificate);
  elements.trustBundleImportForm.addEventListener("submit", importTrustBundle);
  elements.trustBundleRows.addEventListener("click", handleTrustBundleAction);
  elements.openTlsConfigBtn.addEventListener("click", () => {
    setPanel("config");
    elements.configEditor.focus();
  });
  elements.newHostBtn.addEventListener("click", () => resetHostForm());
  elements.validateBtn.addEventListener("click", validateConfig);
  elements.diffBtn.addEventListener("click", diffConfig);
  elements.applyBtn.addEventListener("click", applyConfig);
  elements.rollbackBtn.addEventListener("click", rollbackConfig);
  elements.createSupportBundleBtn.addEventListener("click", createSupportBundle);
  elements.refreshBtn.addEventListener("click", refreshAll);
  elements.hostRows.addEventListener("click", handleHostTableClick);
  elements.certRows.addEventListener("click", handleCertificateTableClick);
  elements.hostDomain.addEventListener("input", maybeFillHostId);
  elements.auditFilterForm.addEventListener("submit", applyAuditFilters);
  elements.auditResetBtn.addEventListener("click", resetAuditFilters);
  elements.auditPreviousBtn.addEventListener("click", previousAuditPage);
  elements.auditNextBtn.addEventListener("click", nextAuditPage);
  elements.auditRetryBtn.addEventListener("click", () => loadAudit());
}

async function bootstrap() {
  clearError();
  state.mode = "connecting";
  render();

  try {
    await refreshPublic();
    state.mode = "api";
    await refreshProtected();
    setResult("Admin API connected");
  } catch (error) {
    if (isApiUnavailable(error)) {
      enterFallbackMode();
      setResult("UI smoke mode active");
      return;
    }
    state.mode = "api";
    handleError(error);
  } finally {
    render();
  }
}

async function refreshAll() {
  if (isFallbackMode()) {
    setResult("Fallback data refreshed in UI memory only");
    render();
    return;
  }

  clearError();
  try {
    await refreshPublic();
    await refreshProtected();
    setResult("Admin data refreshed");
  } catch (error) {
    handleError(error);
  } finally {
    render();
  }
}

async function refreshPublic() {
  const [status, health] = await Promise.all([api.status(), api.health()]);
  state.status = unwrapData(status);
  state.health = unwrapData(health);
}

async function refreshProtected() {
  try {
    const [config, hosts, upstreamHealth, metrics, certs, trustBundles, accessLogs, errorLogs] = await Promise.all([
      api.config(),
      api.proxyHosts(),
      api.upstreamHealth(),
      api.metrics(),
      api.certificates(),
      api.trustBundles(),
      api.accessLogs(),
      api.errorLogs(),
    ]);

    state.authenticated = true;
    state.setupRequired = false;
    state.config = config;
    state.hosts = hosts.proxy_hosts || [];
    state.upstreamHealth = upstreamHealth;
    state.metrics = metrics;
    state.certificates = certs.certificates || [];
    state.trustBundles = trustBundles.trust_bundles || [];
    state.accessLogs = accessLogs.access_logs || [];
    state.errorLogs = errorLogs.error_logs || [];
    state.diff = null;
    await loadAudit({ reset: true, renderAfter: false });
  } catch (error) {
    if (error.status === 401 || error.code === "ADMIN_AUTH_REQUIRED") {
      state.authenticated = false;
      clearProtectedState();
      return;
    }
    if (error.code === "ADMIN_SETUP_REQUIRED") {
      state.authenticated = false;
      state.setupRequired = true;
      clearProtectedState();
      return;
    }
    throw error;
  }
}

function auditQueryParameters(cursor = state.auditCursor) {
  const parameters = new URLSearchParams();
  const exactValues = [
    ["action", elements.auditAction.value],
    ["outcome", elements.auditOutcome.value],
    ["target_kind", elements.auditTargetKind.value],
  ];
  for (const [name, value] of exactValues) {
    if (value) {
      parameters.set(name, value);
    }
  }
  const from = epochSecondsFromLocalInput(elements.auditFrom.value);
  const to = epochSecondsFromLocalInput(elements.auditTo.value);
  if (from !== null) {
    parameters.set("from", String(from));
  }
  if (to !== null) {
    parameters.set("to", String(to));
  }
  parameters.set("limit", elements.auditLimit.value);
  if (cursor) {
    parameters.set("cursor", cursor);
  }
  return parameters;
}

async function loadAudit({ reset = false, renderAfter = true } = {}) {
  if (!state.authenticated) {
    return;
  }
  if (reset) {
    state.auditCursor = null;
    state.auditCursorStack = [];
  }
  if (isFallbackMode()) {
    state.audit = {
      ...fallbackState.audit,
      ledger: { ...fallbackState.audit.ledger },
      records: fallbackState.audit.records.map((record) => ({ ...record })),
    };
    state.auditViewState = state.audit.records.length ? "ready" : "empty";
    if (renderAfter) render();
    return;
  }
  const generation = ++auditRequestGeneration;
  state.auditViewState = "loading";
  state.auditError = "";
  if (renderAfter) renderAudit();
  try {
    const page = await api.audit(auditQueryParameters());
    if (generation !== auditRequestGeneration) return;
    state.audit = page;
    state.auditViewState = (page.records || []).length ? "ready" : "empty";
  } catch (error) {
    if (generation !== auditRequestGeneration) return;
    state.auditViewState = "error";
    state.auditError = formatError(error);
  }
  if (renderAfter) renderAudit();
}

function applyAuditFilters(event) {
  event.preventDefault();
  loadAudit({ reset: true });
}

function resetAuditFilters() {
  elements.auditFilterForm.reset();
  loadAudit({ reset: true });
}

function nextAuditPage() {
  if (!state.audit.next_cursor || state.auditViewState === "loading") return;
  state.auditCursorStack.push(state.auditCursor);
  state.auditCursor = state.audit.next_cursor;
  loadAudit();
}

function previousAuditPage() {
  if (state.auditCursorStack.length === 0 || state.auditViewState === "loading") return;
  state.auditCursor = state.auditCursorStack.pop() || null;
  loadAudit();
}

function epochSecondsFromLocalInput(value) {
  if (!value) return null;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) ? Math.floor(milliseconds / 1000) : null;
}

async function login(event) {
  event.preventDefault();
  clearError();
  const passwordHash = elements.loginPasswordHash.value.trim();
  if (!passwordHash) {
    showErrorText("Password hash is required.");
    return;
  }

  try {
    const response = await api.login(passwordHash);
    state.csrfToken = response.csrf_token || "";
    state.authenticated = true;
    state.setupRequired = false;
    elements.loginPasswordHash.value = "";
    await refreshProtected();
    setResult("Logged in");
  } catch (error) {
    if (error.code === "ADMIN_SETUP_REQUIRED") {
      state.setupRequired = true;
      state.authenticated = false;
      setResult("Initial setup required");
    } else {
      handleError(error);
    }
  } finally {
    render();
  }
}

async function setup(event) {
  event.preventDefault();
  clearError();
  const passwordHash = elements.setupPasswordHash.value.trim();
  if (!passwordHash) {
    showErrorText("Password hash is required.");
    return;
  }

  try {
    await api.setup(passwordHash);
    const response = await api.login(passwordHash);
    state.csrfToken = response.csrf_token || "";
    state.authenticated = true;
    state.setupRequired = false;
    elements.setupPasswordHash.value = "";
    await refreshProtected();
    setResult("Initial setup complete");
  } catch (error) {
    handleError(error);
  } finally {
    render();
  }
}

async function logout() {
  if (isFallbackMode()) {
    state.authenticated = false;
    setResult("Fallback session cleared");
    render();
    return;
  }

  clearError();
  try {
    if (state.csrfToken) {
      await api.logout();
    }
  } catch (error) {
    handleError(error);
  } finally {
    state.csrfToken = "";
    state.authenticated = false;
    clearProtectedState();
    render();
  }
}

async function validateConfig() {
  const source = elements.configEditor.value;
  clearError();

  if (isFallbackMode()) {
    state.diff = { valid: true, errors: [], diff: emptyDiff() };
    setResult("Fallback validation passed in UI memory only");
    render();
    return;
  }

  try {
    const response = await api.validateConfig(source);
    state.diff = { ...response, diff: emptyDiff() };
    setResult(response.valid ? "Config is valid" : "Config validation failed");
  } catch (error) {
    handleError(error);
  } finally {
    render();
  }
}

async function diffConfig() {
  const source = elements.configEditor.value;
  clearError();

  if (isFallbackMode()) {
    state.diff = {
      valid: true,
      errors: [],
      diff: {
        added_routes: [],
        removed_routes: [],
        changed_upstreams: ["fallback-app"],
      },
    };
    setResult("Fallback diff calculated in UI memory only");
    render();
    return;
  }

  try {
    state.diff = await api.diffConfig(source);
    setResult(state.diff.valid ? "Config diff ready" : "Config diff has validation errors");
  } catch (error) {
    handleError(error);
  } finally {
    render();
  }
}

async function applyConfig() {
  const source = elements.configEditor.value;
  clearError();

  if (isFallbackMode()) {
    state.config.config = source;
    setResult("Fallback apply did not change runtime state");
    render();
    return;
  }

  try {
    const response = await api.applyConfig(source);
    setResult(applyResultText("Config applied", response));
    await refreshPublic();
    await refreshProtected();
  } catch (error) {
    handleError(error);
  } finally {
    render();
  }
}

async function rollbackConfig() {
  const revisionId = elements.rollbackRevision.value.trim();
  clearError();

  if (!revisionId) {
    showErrorText("Rollback revision is required.");
    return;
  }

  if (isFallbackMode()) {
    state.config.revision_id = revisionId;
    setResult("Fallback rollback did not change runtime state");
    render();
    return;
  }

  try {
    const response = await api.rollback(revisionId);
    setResult(applyResultText("Rollback applied", response));
    await refreshPublic();
    await refreshProtected();
  } catch (error) {
    handleError(error);
  } finally {
    render();
  }
}

async function saveProxyHost(event) {
  event.preventDefault();
  clearError();

  const payload = formPayload();
  const validationMessage = validateProxyHostPayload(payload);
  if (validationMessage) {
    showErrorText(validationMessage);
    return;
  }

  if (isFallbackMode()) {
    upsertFallbackHost(payload);
    state.activeHostId = payload.id;
    setResult("Fallback host saved in UI memory only");
    render();
    return;
  }

  try {
    const response = state.activeHostId
      ? await api.updateProxyHost(state.activeHostId, payload)
      : await api.createProxyHost(payload);
    state.activeHostId = payload.id;
    setResult(applyResultText("Proxy host saved", response));
    await refreshPublic();
    await refreshProtected();
  } catch (error) {
    handleError(error);
  } finally {
    render();
  }
}

async function deleteProxyHost(id) {
  clearError();
  const hostId = id || state.activeHostId;
  if (!hostId) {
    showErrorText("Select a proxy host before delete.");
    return;
  }
  if (!window.confirm(`Delete proxy host ${hostId}?`)) {
    return;
  }

  if (isFallbackMode()) {
    state.hosts = state.hosts.filter((host) => host.id !== hostId);
    if (state.activeHostId === hostId) {
      resetHostForm();
    }
    setResult("Fallback host deleted in UI memory only");
    render();
    return;
  }

  try {
    const response = await api.deleteProxyHost(hostId);
    setResult(applyResultText("Proxy host deleted", response));
    resetHostForm();
    await refreshPublic();
    await refreshProtected();
  } catch (error) {
    handleError(error);
  } finally {
    render();
  }
}

function handleHostTableClick(event) {
  const button = event.target.closest("button[data-action]");
  if (!button) {
    return;
  }
  const host = state.hosts.find((item) => item.id === button.dataset.id);
  if (button.dataset.action === "edit" && host) {
    selectHost(host);
    setPanel("proxy-hosts");
  } else if (button.dataset.action === "delete") {
    deleteProxyHost(button.dataset.id);
  }
}

async function handleCertificateTableClick(event) {
  const button = event.target.closest("button[data-certificate-id]");
  if (!button || isFallbackMode()) {
    return;
  }
  clearError();
  try {
    const certificate = await api.certificate(button.dataset.certificateId);
    setResult(
      `${certificate.certificate_ref} expires ${formatEpoch(certificate.not_after_epoch_seconds)}`,
    );
  } catch (error) {
    handleError(error);
  } finally {
    render();
  }
}

async function importCertificate(event) {
  event.preventDefault();
  clearError();
  if (state.certificateImportState === "importing") {
    return;
  }
  const certificateRef = elements.certificateRef.value.trim();
  const domains = elements.certificateDomains.value
    .split(",")
    .map((domain) => domain.trim())
    .filter(Boolean);
  const fullchainPem = elements.certificateFullchain.value.trim();
  const privateKeyPem = elements.certificatePrivateKey.value.trim();
  if (!certificateRef || domains.length === 0 || !fullchainPem || !privateKeyPem) {
    state.certificateImportState = "failed";
    showErrorText("Reference, domains, full chain, and private key are required.");
    render();
    return;
  }
  if (isFallbackMode()) {
    state.certificateImportState = "failed";
    elements.certificatePrivateKey.value = "";
    showErrorText("Certificate import requires an Admin API connection.");
    render();
    return;
  }

  state.certificateImportState = "importing";
  render();
  try {
    const result = await api.importCertificate(certificateRef, {
      domains,
      fullchain_pem: fullchainPem,
      private_key_pem: privateKeyPem,
    });
    state.certificateImportState = "succeeded";
    elements.certificateFullchain.value = "";
    elements.certificatePrivateKey.value = "";
    setResult(`Certificate imported: ${result.certificate_ref}`);
    await refreshPublic();
    await refreshProtected();
  } catch (error) {
    state.certificateImportState = "failed";
    elements.certificatePrivateKey.value = "";
    handleError(error);
  } finally {
    render();
  }
}

async function importTrustBundle(event) {
  event.preventDefault();
  clearError();
  if (state.trustBundleImportState === "submitting") {
    return;
  }
  const reference = elements.trustBundleRef.value.trim();
  const encodedMaterial = elements.trustBundlePem.value.trim();
  if (!reference || !encodedMaterial) {
    state.trustBundleImportState = "failed";
    showErrorText("Reference and Root certificates are required.");
    render();
    return;
  }
  if (isFallbackMode()) {
    elements.trustBundlePem.value = "";
    state.trustBundleImportState = "failed";
    showErrorText("Trust bundle import requires an Admin API connection.");
    render();
    return;
  }

  state.trustBundleImportState = "submitting";
  render();
  const pending = api.importTrustBundle(reference, encodedMaterial);
  elements.trustBundlePem.value = "";
  try {
    const result = await pending;
    state.trustBundleImportState = "succeeded";
    elements.trustBundleRef.value = "";
    setResult(`Trust bundle imported: ${result.trust_bundle_ref}`);
    await refreshProtected();
  } catch (error) {
    state.trustBundleImportState = "failed";
    handleError(error);
  } finally {
    render();
  }
}

async function handleTrustBundleAction(event) {
  const button = event.target.closest("button[data-trust-bundle-ref]");
  if (!button || isFallbackMode()) {
    return;
  }
  clearError();
  try {
    await api.deleteTrustBundle(button.dataset.trustBundleRef);
    setResult(`Trust bundle deleted: ${button.dataset.trustBundleRef}`);
    await refreshProtected();
  } catch (error) {
    handleError(error);
  } finally {
    render();
  }
}

function render() {
  renderShell();
  renderAuth();
  renderDashboard();
  renderProxyHosts();
  renderConfig();
  renderCertificates();
  renderTrustBundles();
  renderLogs();
  renderAudit();
  renderMessages();
}

function renderTrustBundles() {
  elements.trustBundleImportState.textContent = state.trustBundleImportState;
  elements.trustBundleImportBtn.disabled =
    state.trustBundleImportState === "submitting" || isFallbackMode() || !state.authenticated;
  elements.trustConfigRevision.textContent = `revision: ${currentRevision() || "none"}`;
  clearChildren(elements.trustBundleRows);
  if (state.trustBundles.length === 0) {
    appendEmptyRow(elements.trustBundleRows, 4, "No managed Roots");
    return;
  }
  for (const bundle of state.trustBundles) {
    const row = document.createElement("tr");
    appendCell(row, bundle.trust_bundle_ref);
    appendCell(row, String(bundle.certificate_count));
    appendCell(row, formatEpoch(bundle.imported_at_epoch_seconds));
    const actionCell = document.createElement("td");
    const button = actionButton("Delete", "delete-trust", bundle.trust_bundle_ref);
    button.dataset.trustBundleRef = bundle.trust_bundle_ref;
    button.disabled = isFallbackMode() || !state.authenticated;
    actionCell.appendChild(button);
    row.appendChild(actionCell);
    elements.trustBundleRows.appendChild(row);
  }
}

function renderShell() {
  document.querySelectorAll(".nav-tab").forEach((button) => {
    button.classList.toggle("active", button.dataset.panel === state.activePanel);
  });
  document.querySelectorAll(".panel").forEach((panel) => {
    panel.classList.toggle("active", panel.id === state.activePanel);
  });

  elements.modeLabel.textContent = modeLabel();
  elements.modeLabel.className = `mode-label ${state.mode}`;
  const desiredRevision = state.status.desired_revision_id || currentRevision() || "unknown";
  const activeRevision = state.status.active_revision_id || desiredRevision;
  elements.revisionLabel.textContent = `desired: ${desiredRevision} / active: ${activeRevision}`;
  elements.restartRequiredNotice.hidden = !state.status.restart_required;
  elements.fallbackBanner.hidden = !isFallbackMode();
  elements.logoutBtn.hidden = !state.authenticated && !isFallbackMode();
  elements.retryApiBtn.disabled = state.mode === "connecting";
}

function renderAuth() {
  elements.authPanel.hidden = isFallbackMode() || state.authenticated;
  elements.loginForm.hidden = state.setupRequired;
  elements.setupForm.hidden = !state.setupRequired;
}

function renderDashboard() {
  elements.createSupportBundleBtn.disabled = isFallbackMode() || !state.authenticated;
  elements.supportBundleState.textContent = state.supportBundleState;
  elements.routeCount.textContent = String(state.status.routes || state.hosts.length || 0);
  elements.serviceCount.textContent = String(state.status.services || 0);
  elements.certCount.textContent = String(
    state.status.certificates || state.certificates.length || 0,
  );
  elements.healthState.textContent = state.health.status || "unknown";
  elements.metricsReady.textContent = state.metrics.ready ? "ready" : "degraded";
  elements.metricsGeneration.textContent = `${state.metrics.applied_generation || 0} / ${state.metrics.desired_generation || 0}`;
  elements.metricsDrops.textContent = String(
    Object.values(state.metrics.dropped || {}).reduce((total, value) => total + Number(value || 0), 0),
  );
  elements.activeResourcePolicy.textContent = resourcePolicyText(
    state.status.active_resource_policy,
  );
  elements.desiredResourcePolicy.textContent = resourcePolicyText(
    state.status.desired_resource_policy,
  );
  elements.liveResourceStatus.textContent = liveResourceStatusText(
    state.status.live_resource_status,
  );
  elements.liveResourceRevision.textContent =
    state.status.live_resource_status?.revision_id || "unavailable";
  elements.resourceActivationState.textContent =
    state.status.activation_state || (state.status.restart_required ? "pending restart" : "aligned");
  elements.csrfState.textContent = state.csrfToken ? "present" : "none";
}

async function createSupportBundle() {
  try {
    const bundle = await api.createSupportBundle();
    state.supportBundleState = `Created ${bundle.archive_id}; ${bundle.total_bytes || 0} bytes; ${bundle.omitted_artifacts?.length || 0} omitted.`;
    setResult("Support bundle created");
  } catch (error) {
    handleError(error);
  } finally {
    render();
  }
}

function liveResourceStatusText(status) {
  if (!status) return "unavailable";
  const used = Number(status.used_payload_bytes || 0) / (1024 * 1024);
  const limit = Number(status.payload_limit_bytes || 0) / (1024 * 1024);
  const format = (value) => (Number.isInteger(value) ? value : value.toFixed(1));
  return `${Number(status.active_connections || 0)} conn / ${format(used)} of ${format(limit)} MiB / ${status.pressure || "unknown"}`;
}

function resourcePolicyText(policy = {}) {
  const connections = Number(policy.max_connections || 0);
  const bytes = Number(policy.max_inflight_payload_bytes || 0);
  const mebibytes = bytes / (1024 * 1024);
  return `${connections} conn / ${Number.isInteger(mebibytes) ? mebibytes : mebibytes.toFixed(1)} MiB`;
}

function renderProxyHosts() {
  clearChildren(elements.hostRows);
  if (state.hosts.length === 0) {
    appendEmptyRow(elements.hostRows, 7, "No proxy hosts");
    return;
  }

  for (const host of state.hosts) {
    const row = document.createElement("tr");
    appendCell(row, host.id);
    appendCell(row, host.domains.join(", "));
    appendCell(row, host.path_prefix);
    const upstreams = normalizedUpstreams(host);
    appendCell(row, upstreams.length === 1 ? upstreams[0].url : `${upstreams.length} upstreams`);
    appendOperationalHealthCell(row, host.id, upstreams);
    appendStateCell(row, host.enabled ? "enabled" : "disabled", host.enabled);
    const actionCell = document.createElement("td");
    actionCell.className = "row-actions";
    actionCell.appendChild(actionButton("Edit", "edit", host.id));
    actionCell.appendChild(actionButton("Delete", "delete", host.id));
    row.appendChild(actionCell);
    elements.hostRows.appendChild(row);
  }
}

function renderConfig() {
  if (document.activeElement !== elements.configEditor) {
    elements.configEditor.value = state.config.config || "";
  }
  elements.configRevision.textContent = state.config.revision_id || currentRevision() || "none";
  elements.rollbackRevision.placeholder = currentRevision() || "revision id";
  renderDiff();
}

function renderDiff() {
  clearChildren(elements.diffRows);
  if (!state.diff) {
    appendEmptyRow(elements.diffRows, 3, "No validation or diff result");
    return;
  }

  if (state.diff.errors && state.diff.errors.length > 0) {
    for (const error of state.diff.errors) {
      const row = document.createElement("tr");
      appendCell(row, error.code || "VALIDATION_ERROR");
      appendCell(row, error.message || "");
      appendCell(row, error.hint || "");
      elements.diffRows.appendChild(row);
    }
    return;
  }

  const diff = state.diff.diff || emptyDiff();
  appendDiffRow("Added routes", diff.added_routes);
  appendDiffRow("Removed routes", diff.removed_routes);
  appendDiffRow("Changed upstreams", diff.changed_upstreams);
}

function renderCertificates() {
  elements.certificateImportState.textContent = state.certificateImportState;
  elements.certificateImportBtn.disabled =
    state.certificateImportState === "importing" || isFallbackMode() || !state.authenticated;
  clearChildren(elements.certRows);
  if (state.certificates.length === 0) {
    appendEmptyRow(elements.certRows, 6, "No certificates");
    return;
  }

  for (const cert of state.certificates) {
    const row = document.createElement("tr");
    appendCell(row, cert.certificate_ref);
    appendCell(row, (cert.domains || []).join(", "));
    appendCell(row, cert.source);
    appendStateCell(row, certificateState(cert), !cert.expired);
    appendCell(row, formatEpoch(cert.not_after_epoch_seconds));
    const actionCell = document.createElement("td");
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "Details";
    button.dataset.certificateId = cert.certificate_ref;
    button.disabled = isFallbackMode();
    actionCell.appendChild(button);
    row.appendChild(actionCell);
    elements.certRows.appendChild(row);
  }
}

function renderLogs() {
  clearChildren(elements.accessLogRows);
  if (state.accessLogs.length === 0) {
    appendEmptyRow(elements.accessLogRows, 6, "No access log events");
  } else {
    for (const event of state.accessLogs) {
      const row = document.createElement("tr");
      appendCell(row, event.request_id);
      appendCell(row, event.revision_id || "");
      appendCell(row, event.route_id || "");
      appendCell(row, event.upstream_id || "");
      appendCell(row, String(event.status_code));
      appendCell(row, `${event.duration_ms} ms`);
      elements.accessLogRows.appendChild(row);
    }
  }

  clearChildren(elements.errorLogRows);
  if (state.errorLogs.length === 0) {
    appendEmptyRow(elements.errorLogRows, 3, "No recent errors");
  } else {
    for (const event of state.errorLogs) {
      const row = document.createElement("tr");
      appendCell(row, event.request_id || "");
      appendCell(row, event.error_code);
      appendCell(row, event.message);
      elements.errorLogRows.appendChild(row);
    }
  }
}

function renderAudit() {
  const ledger = state.audit.ledger || {};
  const admission = ledger.admission_state || "unknown";
  const displayState = ["ready", "empty"].includes(state.auditViewState)
    ? admission
    : state.auditViewState;
  elements.auditState.textContent = displayState.replaceAll("_", " ");
  elements.auditState.className = `audit-state ${displayState.replaceAll("_", "-")}`;
  elements.auditHead.textContent = state.auditViewState === "error"
    ? state.auditError
    : `generation ${ledger.generation || 0}, sequence ${ledger.sequence || 0}`;
  elements.auditRetryBtn.hidden = state.auditViewState !== "error";
  elements.auditPreviousBtn.disabled =
    state.auditViewState === "loading" || state.auditCursorStack.length === 0;
  elements.auditNextBtn.disabled =
    state.auditViewState === "loading" || !state.audit.next_cursor;

  clearChildren(elements.auditRows);
  if (state.auditViewState === "loading") {
    appendEmptyRow(elements.auditRows, 7, "Loading audit records");
    return;
  }
  if (state.auditViewState === "error") {
    appendEmptyRow(elements.auditRows, 7, "Audit records are unavailable");
    return;
  }
  if ((state.audit.records || []).length === 0) {
    appendEmptyRow(elements.auditRows, 7, "No audit records match the filters");
    return;
  }
  for (const record of state.audit.records) {
    const row = document.createElement("tr");
    appendAuditCell(row, formatEpoch(record.received_at_epoch_seconds));
    appendAuditCell(row, record.action);
    appendAuditCell(row, `${record.target_kind}: ${record.target_id}`);
    appendAuditCell(row, record.outcome || "pending");
    appendAuditCell(row, record.actor_kind);
    appendAuditCell(row, record.request_id);
    appendAuditCell(row, record.sequence);
    elements.auditRows.appendChild(row);
  }
}

function appendAuditCell(row, value) {
  const cell = appendCell(row, value);
  cell.title = value == null ? "" : String(value);
  return cell;
}

function renderMessages() {
  elements.apiError.hidden = !state.lastError;
  elements.apiError.textContent = state.lastError || "";
  elements.resultMessage.hidden = !state.lastResult;
  elements.resultMessage.textContent = state.lastResult || "";
}

function enterFallbackMode() {
  state.mode = "fallback";
  state.authenticated = true;
  state.setupRequired = false;
  state.csrfToken = "";
  state.status = { ...fallbackState.status };
  state.health = { ...fallbackState.health };
  state.upstreamHealth = {
    ...fallbackState.upstreamHealth,
    upstreams: fallbackState.upstreamHealth.upstreams.map((item) => ({ ...item })),
  };
  state.metrics = { ...fallbackState.metrics, dropped: { ...fallbackState.metrics.dropped } };
  state.config = { ...fallbackState.config };
  state.hosts = fallbackState.hosts.map((host) => ({ ...host, domains: [...host.domains] }));
  state.certificates = fallbackState.certificates.map((cert) => ({
    ...cert,
    domains: [...cert.domains],
  }));
  state.trustBundles = [];
  state.accessLogs = fallbackState.accessLogs.map((event) => ({ ...event }));
  state.errorLogs = fallbackState.errorLogs.map((event) => ({ ...event }));
  state.audit = {
    ...fallbackState.audit,
    ledger: { ...fallbackState.audit.ledger },
    records: fallbackState.audit.records.map((record) => ({ ...record })),
  };
  state.auditViewState = "ready";
  state.auditError = "";
  state.auditCursor = null;
  state.auditCursorStack = [];
  state.diff = null;
  resetHostForm();
}

function clearProtectedState() {
  auditRequestGeneration += 1;
  state.config = { revision_id: "", config: "" };
  state.hosts = [];
  state.upstreamHealth = { revision_id: "", generation: 0, upstreams: [] };
  state.metrics = { ready: false, desired_generation: 0, applied_generation: 0, dropped: {} };
  state.certificates = [];
  state.trustBundles = [];
  state.trustBundleImportState = "ready";
  state.accessLogs = [];
  state.errorLogs = [];
  state.audit = {
    ledger: { generation: 0, sequence: 0, admission_state: "starting" },
    records: [],
    next_cursor: null,
  };
  state.auditViewState = "idle";
  state.auditError = "";
  state.auditCursor = null;
  state.auditCursorStack = [];
  state.diff = null;
  state.activeHostId = "";
}

function setPanel(panelId) {
  state.activePanel = panelId;
  render();
}

function selectHost(host) {
  state.activeHostId = host.id;
  elements.hostId.value = host.id;
  elements.hostId.readOnly = true;
  elements.hostName.value = host.name || host.id;
  elements.hostDomain.value = (host.domains || [])[0] || "";
  elements.pathPrefix.value = host.path_prefix || "/";
  renderUpstreamRows(normalizedUpstreams(host));
  setHealthForm(host.health_check);
  setFailurePolicyForm(host);
  elements.httpsEnabled.checked = Boolean(host.https_enabled);
  elements.redirectEnabled.checked = Boolean(host.redirect_http_to_https);
  elements.hostEnabled.checked = Boolean(host.enabled);
  elements.hostFormMode.textContent = `editing: ${host.id}`;
}

function resetHostForm() {
  state.activeHostId = "";
  elements.hostId.value = "";
  elements.hostId.readOnly = false;
  elements.hostName.value = "";
  elements.hostDomain.value = "";
  elements.pathPrefix.value = "/";
  renderUpstreamRows([{ id: "primary", url: "http://127.0.0.1:3000" }]);
  setHealthForm({ enabled: false });
  setFailurePolicyForm({});
  elements.httpsEnabled.checked = false;
  elements.redirectEnabled.checked = false;
  elements.hostEnabled.checked = true;
  elements.hostFormMode.textContent = "new host";
}

function formPayload() {
  const domain = elements.hostDomain.value.trim();
  const id = (elements.hostId.value.trim() || slugify(domain)).toLowerCase();
  const upstreams = collectUpstreamRows();
  return {
    id,
    name: elements.hostName.value.trim() || id,
    domains: [domain],
    path_prefix: elements.pathPrefix.value.trim() || "/",
    upstream_url: upstreams[0]?.url || "",
    upstreams,
    health_check: healthCheckPayload(),
    retry: {
      enabled: elements.retryEnabled.checked,
      max_retries: 1,
      max_replay_bytes: Number(elements.retryReplayBytes.value),
    },
    passive_health: elements.passiveHealthEnabled.checked
      ? {
          enabled: true,
          failure_threshold: Number(elements.passiveFailureThreshold.value),
          ejection_ms: Number(elements.passiveEjectionMs.value),
        }
      : { enabled: false },
    https_enabled: elements.httpsEnabled.checked,
    letsencrypt_enabled: false,
    redirect_http_to_https: elements.redirectEnabled.checked,
    enabled: elements.hostEnabled.checked,
  };
}

function validateProxyHostPayload(payload) {
  if (!payload.id) {
    return "Proxy host id is required.";
  }
  if (!payload.domains[0]) {
    return "Domain is required.";
  }
  if (payload.upstreams.length === 0) {
    return "At least one upstream is required.";
  }
  const ids = new Set();
  for (const upstream of payload.upstreams) {
    if (!upstream.id) {
      return "Every upstream requires an id.";
    }
    if (ids.has(upstream.id)) {
      return `Upstream id must be unique: ${upstream.id}`;
    }
    ids.add(upstream.id);
    if (!upstream.url.startsWith("http://")) {
      return `Upstream ${upstream.id} URL must start with http://.`;
    }
  }
  if (payload.upstreams.every((upstream) => upstream.administrative_state === "draining")) {
    return "At least one upstream must remain active.";
  }
  if (!Number.isInteger(payload.retry.max_replay_bytes) || payload.retry.max_replay_bytes < 0 || payload.retry.max_replay_bytes > 1048576) {
    return "Retry replay bytes must be an integer between 0 and 1048576.";
  }
  if (payload.passive_health.enabled) {
    if (!Number.isInteger(payload.passive_health.failure_threshold) || payload.passive_health.failure_threshold < 1 || payload.passive_health.failure_threshold > 10) {
      return "Passive failure threshold must be an integer between 1 and 10.";
    }
    if (!Number.isInteger(payload.passive_health.ejection_ms) || payload.passive_health.ejection_ms < 1000 || payload.passive_health.ejection_ms > 86400000) {
      return "Passive ejection must be an integer between 1000 and 86400000 ms.";
    }
  }
  if (!payload.path_prefix.startsWith("/")) {
    return "Path prefix must start with /.";
  }
  if (payload.health_check.enabled) {
    const health = payload.health_check;
    if (!health.path.startsWith("/") || health.path.includes("?") || health.path.includes("#")) {
      return "Health path must be an absolute path without query or fragment.";
    }
    const boundedIntegers = [
      [health.interval_ms, 1000, 300000, "Health interval"],
      [health.timeout_ms, 100, 30000, "Health timeout"],
      [health.healthy_threshold, 1, 10, "Healthy threshold"],
      [health.unhealthy_threshold, 1, 10, "Unhealthy threshold"],
      [health.status_min, 100, 599, "Health status minimum"],
      [health.status_max, 100, 599, "Health status maximum"],
    ];
    for (const [value, minimum, maximum, label] of boundedIntegers) {
      if (!Number.isInteger(value) || value < minimum || value > maximum) {
        return `${label} must be an integer between ${minimum} and ${maximum}.`;
      }
    }
    if (health.timeout_ms >= health.interval_ms) {
      return "Health timeout must be less than the interval.";
    }
    if (health.status_min > health.status_max) {
      return "Health status minimum must not exceed maximum.";
    }
  }
  return "";
}

function normalizedUpstreams(host) {
  if (Array.isArray(host.upstreams) && host.upstreams.length > 0) {
    return host.upstreams.map((upstream) => ({
      id: upstream.id,
      url: upstream.url,
      administrative_state: upstream.administrative_state || "active",
    }));
  }
  return [
    {
      id: `${host.id || "proxy"}-primary`,
      url: host.upstream_url || "http://127.0.0.1:3000",
      administrative_state: "active",
    },
  ];
}

function renderUpstreamRows(upstreams) {
  clearChildren(elements.upstreamRows);
  for (const upstream of upstreams) {
    addUpstreamRow(upstream);
  }
}

function addUpstreamRow(upstream = {}) {
  const row = document.createElement("div");
  row.className = "upstream-row";
  const id = document.createElement("input");
  id.className = "upstream-id";
  id.placeholder = "upstream-id";
  id.value = upstream.id || `upstream-${elements.upstreamRows.children.length + 1}`;
  id.setAttribute("aria-label", "Upstream id");
  const url = document.createElement("input");
  url.className = "upstream-url";
  url.placeholder = "http://127.0.0.1:3000";
  url.value = upstream.url || "http://127.0.0.1:3000";
  url.setAttribute("aria-label", "Upstream URL");
  const administrativeState = document.createElement("select");
  administrativeState.className = "upstream-administrative-state";
  administrativeState.setAttribute("aria-label", "Upstream administrative state");
  for (const value of ["active", "draining"]) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value;
    administrativeState.appendChild(option);
  }
  administrativeState.value = upstream.administrative_state || "active";
  row.append(id, url, administrativeState);
  for (const [action, label, title] of [
    ["up", "↑", "Move upstream up"],
    ["down", "↓", "Move upstream down"],
    ["remove", "×", "Remove upstream"],
  ]) {
    const button = document.createElement("button");
    button.type = "button";
    button.dataset.action = action;
    button.textContent = label;
    button.title = title;
    row.appendChild(button);
  }
  elements.upstreamRows.appendChild(row);
}

function handleUpstreamRowAction(event) {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  const row = button.closest(".upstream-row");
  if (button.dataset.action === "remove") {
    if (elements.upstreamRows.children.length > 1) row.remove();
  } else if (button.dataset.action === "up" && row.previousElementSibling) {
    elements.upstreamRows.insertBefore(row, row.previousElementSibling);
  } else if (button.dataset.action === "down" && row.nextElementSibling) {
    elements.upstreamRows.insertBefore(row.nextElementSibling, row);
  }
}

function collectUpstreamRows() {
  return Array.from(elements.upstreamRows.querySelectorAll(".upstream-row")).map((row) => ({
    id: row.querySelector(".upstream-id").value.trim(),
    url: row.querySelector(".upstream-url").value.trim(),
    administrative_state: row.querySelector(".upstream-administrative-state").value,
  }));
}

function setFailurePolicyForm(host) {
  elements.retryEnabled.checked = Boolean(host.retry?.enabled);
  elements.retryReplayBytes.value = host.retry?.max_replay_bytes ?? 32768;
  elements.passiveHealthEnabled.checked = Boolean(host.passive_health?.enabled);
  elements.passiveFailureThreshold.value = host.passive_health?.failure_threshold ?? 3;
  elements.passiveEjectionMs.value = host.passive_health?.ejection_ms ?? 30000;
}

function setHealthForm(health = { enabled: false }) {
  elements.healthCheckEnabled.checked = Boolean(health?.enabled);
  elements.healthPath.value = health?.path || "/health";
  elements.healthInterval.value = health?.interval_ms || 10000;
  elements.healthTimeout.value = health?.timeout_ms || 2000;
  elements.healthyThreshold.value = health?.healthy_threshold || 2;
  elements.unhealthyThreshold.value = health?.unhealthy_threshold || 3;
  elements.healthStatusMin.value = health?.status_min || 200;
  elements.healthStatusMax.value = health?.status_max || 399;
  syncHealthFields();
}

function syncHealthFields() {
  elements.healthCheckFields.hidden = !elements.healthCheckEnabled.checked;
}

function healthCheckPayload() {
  if (!elements.healthCheckEnabled.checked) return { enabled: false };
  return {
    enabled: true,
    path: elements.healthPath.value.trim(),
    interval_ms: Number(elements.healthInterval.value),
    timeout_ms: Number(elements.healthTimeout.value),
    healthy_threshold: Number(elements.healthyThreshold.value),
    unhealthy_threshold: Number(elements.unhealthyThreshold.value),
    status_min: Number(elements.healthStatusMin.value),
    status_max: Number(elements.healthStatusMax.value),
  };
}

function upsertFallbackHost(payload) {
  state.hosts = state.hosts.filter((host) => host.id !== payload.id);
  state.hosts.push(payload);
  state.status.routes = state.hosts.length;
  state.status.services = state.hosts.length;
}

function maybeFillHostId() {
  if (state.activeHostId || elements.hostId.value.trim()) {
    return;
  }
  elements.hostId.value = slugify(elements.hostDomain.value.trim());
}

function appendDiffRow(label, values) {
  const row = document.createElement("tr");
  appendCell(row, label);
  appendCell(row, values.length ? values.join(", ") : "none");
  appendCell(row, "");
  elements.diffRows.appendChild(row);
}

function appendCell(row, value) {
  const cell = document.createElement("td");
  cell.textContent = value == null ? "" : String(value);
  row.appendChild(cell);
  return cell;
}

function appendStateCell(row, value, ok) {
  const cell = appendCell(row, value);
  const span = document.createElement("span");
  span.className = ok ? "state-ok" : "state-off";
  span.textContent = value;
  cell.textContent = "";
  cell.appendChild(span);
}

function appendOperationalHealthCell(row, serviceId, upstreams) {
  const cell = document.createElement("td");
  const list = document.createElement("div");
  list.className = "operational-health-list";
  for (const upstream of upstreams) {
    const operational = (state.upstreamHealth.upstreams || []).find(
      (item) => item.service_id === serviceId && item.upstream_id === upstream.id,
    );
    const status = operational?.status || "unknown";
    const drainState = operational?.drain_state;
    const connectionCount = operational?.connection_count;
    const badge = document.createElement("span");
    badge.className = `upstream-health-status health-${status}`;
    const drainDetail = drainState
      ? ` / ${drainState}${Number.isInteger(connectionCount) ? ` (${connectionCount})` : ""}`
      : "";
    badge.textContent = `${upstream.id}: ${status}${drainDetail}`;
    list.appendChild(badge);
  }
  cell.appendChild(list);
  row.appendChild(cell);
}

function appendEmptyRow(body, colspan, message) {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = colspan;
  cell.className = "empty-cell";
  cell.textContent = message;
  row.appendChild(cell);
  body.appendChild(row);
}

function actionButton(label, action, id) {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  button.dataset.action = action;
  button.dataset.id = id;
  return button;
}

function clearChildren(element) {
  while (element.firstChild) {
    element.removeChild(element.firstChild);
  }
}

function handleError(error) {
  state.lastError = formatError(error);
  state.lastResult = "";
}

function showErrorText(message) {
  state.lastError = message;
  state.lastResult = "";
  renderMessages();
}

function clearError() {
  state.lastError = null;
}

function setResult(message) {
  state.lastResult = message;
  state.lastError = null;
}

function applyResultText(prefix, response) {
  return `${prefix}: ${response.revision_id || "unknown"} (${response.commands_sent || 0} commands)`;
}

function modeLabel() {
  if (state.mode === "connecting") {
    return "connecting";
  }
  if (state.mode === "fallback") {
    return "ui smoke only";
  }
  return state.authenticated ? "api authenticated" : "api connected";
}

function currentRevision() {
  return (
    state.config.revision_id ||
    state.status.current_revision_id ||
    state.health.current_revision_id ||
    ""
  );
}

function certificateState(cert) {
  if (cert.expired) {
    return "expired";
  }
  if (cert.expiring_soon) {
    return "expiring soon";
  }
  return "valid";
}

function formatEpoch(value) {
  if (!value) {
    return "";
  }
  return new Date(Number(value) * 1000).toISOString().slice(0, 10);
}

function formatError(error) {
  if (error instanceof ApiError) {
    const parts = [error.code || "API_ERROR", error.message];
    if (error.hint) {
      parts.push(error.hint);
    }
    if (error.requestId) {
      parts.push(`request_id=${error.requestId}`);
    }
    return parts.filter(Boolean).join(" - ");
  }
  return error.message || String(error);
}

function isApiUnavailable(error) {
  return (
    error instanceof ApiError &&
    (error.status === 0 || (error.status === 404 && error.code === "HTTP_404"))
  );
}

function isFallbackMode() {
  return state.mode === "fallback";
}

function emptyDiff() {
  return {
    added_routes: [],
    removed_routes: [],
    changed_upstreams: [],
  };
}

function unwrapData(response) {
  return response && response.data ? response.data : response;
}

function safeJson(raw) {
  try {
    return JSON.parse(raw);
  } catch (_) {
    return {};
  }
}

function requestId() {
  if (window.crypto && typeof window.crypto.randomUUID === "function") {
    return window.crypto.randomUUID();
  }
  return `ui-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function slugify(value) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}
