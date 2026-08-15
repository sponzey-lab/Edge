//! Admin API adapter boundary.
//!
//! This crate defines the API contract, authentication/session rules, and the
//! CoreCommand boundary. A concrete HTTP server can wrap these handlers later.

use std::collections::BTreeMap;

use edge_application::{
    add_proxy_host, certificate_status, config_activation_state, default_support_bundle_bounds,
    diff_config, import_manual_certificate_and_install, issue_certificate_for_ref_and_install,
    issue_certificate_for_ref_with_http01_and_install, parse_mvp_config, query_audit,
    remove_proxy_host, render_mvp_config_snapshot, renew_certificate_for_ref_and_install,
    update_proxy_host, AccessLogEvent, CertificateIssueOutcome, CertificateIssuer,
    CertificateRenewRequest, CertificateStatus, CollectSupportBundleUseCase, ConfigActivationState,
    ConfigDiff, ConfigLifecycle, ConfigValidator, ManualCertificateImportOutcome,
    ManualCertificateImportRequest, MetricSeriesValue, MetricSnapshot, MetricSnapshotReaderPort,
    RecentErrorEvent, ValidationReport,
};
use edge_domain::{
    AppError, AuditAction, AuditAdmissionState, AuditCursor, AuditOutcome, AuditPage, AuditQuery,
    AuditTargetKind, CertificateRef, ConfigRevisionId, ConfigSnapshot, ErrorCode,
    HealthAvailabilitySnapshot, HealthCheckPolicy, HostMatch, HttpHealthCheckPolicy,
    OperationalLifecycle, PassiveHealthMode, PathMatch, ProbeStatus, ProxyHost, ProxyHostId,
    RetryPolicy, Route, SupportBundleArtifact, TrustBundleRef, Upstream,
    UpstreamAdministrativeState, UpstreamAvailability, UpstreamId, ValidationError,
};
use edge_ports::{
    AcmeClient, AcmeOrderRequest, AuditLedgerReader, AuditSink, CertificateMaterialValidator,
    CertificateStore, ConfigRevisionRepository, CoreCommandClient, HealthStatusReader,
    Http01ChallengeProbe, Http01ChallengeStore, RuntimeDrainState, RuntimeUpstreamStatusReader,
    RuntimeUpstreamStatusSnapshot, SecretRecord, SecretStore, SupportBundleCollector,
    SupportBundleRequest, TrustBundleMetadata,
};

/// Foundation smoke helper.
pub fn crate_name() -> &'static str {
    "edge-admin-api"
}

pub const API_VERSION_PREFIX: &str = "/api/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportBundleResponse {
    pub archive_id: String,
    pub digest_sha256: String,
    pub collected_artifacts: Vec<String>,
    pub omitted_artifacts: Vec<String>,
    pub total_bytes: u64,
}

/// Creates a bundle with the fixed product allowlist; caller-controlled paths,
/// artifact lists, bounds, service actions, and archive locations are not accepted.
pub fn create_support_bundle<C: SupportBundleCollector>(
    sessions: &SessionStore,
    session_id: Option<&str>,
    csrf_token: Option<&str>,
    collector: C,
) -> Result<SupportBundleResponse, AppError> {
    require_session(sessions, session_id)?;
    let session_id = session_id.expect("session checked above");
    require_csrf(sessions, session_id, csrf_token)?;
    let mut use_case = CollectSupportBundleUseCase::new(collector);
    let report = use_case.execute(SupportBundleRequest {
        artifacts: vec![
            SupportBundleArtifact::VersionManifest,
            SupportBundleArtifact::MaskedConfig,
            SupportBundleArtifact::BoundedProductLog,
            SupportBundleArtifact::HealthSummary,
            SupportBundleArtifact::ResourceSummary,
            SupportBundleArtifact::AuditSummary,
        ],
        bounds: default_support_bundle_bounds(),
    })?;
    Ok(SupportBundleResponse {
        archive_id: report.archive.archive_id,
        digest_sha256: hex_encode(&report.archive.digest_sha256),
        collected_artifacts: report
            .collected_artifacts
            .into_iter()
            .map(support_artifact_name)
            .map(str::to_string)
            .collect(),
        omitted_artifacts: report
            .omissions
            .into_iter()
            .map(|omission| support_artifact_name(omission.artifact).to_string())
            .collect(),
        total_bytes: report.total_bytes,
    })
}

pub fn handle_support_bundle_http<C: SupportBundleCollector>(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    collector: C,
) -> AdminHttpResponse {
    match create_support_bundle(sessions, request.session_id.as_deref(), request.csrf_token.as_deref(), collector) {
        Ok(response) => AdminHttpResponse::json(200, format!(
            "{{\"archive_id\":\"{}\",\"digest_sha256\":\"{}\",\"collected_artifacts\":[{}],\"omitted_artifacts\":[{}],\"total_bytes\":{}}}",
            json_escape(&response.archive_id), response.digest_sha256,
            response.collected_artifacts.iter().map(|value| format!("\"{}\"", json_escape(value))).collect::<Vec<_>>().join(","),
            response.omitted_artifacts.iter().map(|value| format!("\"{}\"", json_escape(value))).collect::<Vec<_>>().join(","), response.total_bytes)),
        Err(error) => {
            let status = match error.code { ErrorCode::AdminAuthRequired => 401, ErrorCode::AdminCsrfRequired => 403, _ => 422 };
            AdminHttpResponse::from_error(status, error, &request.request_id)
        }
    }
}

fn support_artifact_name(artifact: SupportBundleArtifact) -> &'static str {
    match artifact {
        SupportBundleArtifact::VersionManifest => "version_manifest",
        SupportBundleArtifact::MaskedConfig => "masked_config",
        SupportBundleArtifact::BoundedProductLog => "bounded_product_log",
        SupportBundleArtifact::HealthSummary => "health_summary",
        SupportBundleArtifact::ResourceSummary => "resource_summary",
        SupportBundleArtifact::AuditSummary => "audit_summary",
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiErrorResponse {
    pub code: String,
    pub message: String,
    pub hint: String,
    pub request_id: String,
}

impl ApiErrorResponse {
    pub fn from_error(error: AppError, request_id: impl Into<String>) -> Self {
        let code = error.code.as_str().to_string();
        let hint = error.code.default_user_message().to_string();
        Self {
            code,
            message: error.message,
            hint,
            request_id: request_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiResponse<T> {
    pub request_id: String,
    pub data: T,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub session_id: String,
    pub csrf_token: String,
}

#[derive(Debug, Default, Clone)]
pub struct SessionStore {
    sessions: BTreeMap<String, String>,
}

impl SessionStore {
    pub fn insert(&mut self, session: Session) {
        self.sessions.insert(session.session_id, session.csrf_token);
    }

    pub fn remove(&mut self, session_id: &str) {
        self.sessions.remove(session_id);
    }

    pub fn verify(&self, session_id: &str) -> bool {
        self.sessions.contains_key(session_id)
    }

    pub fn verify_csrf(&self, session_id: &str, csrf_token: &str) -> bool {
        self.sessions
            .get(session_id)
            .is_some_and(|known| known == csrf_token)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminAuthenticator {
    password_hash: String,
    next_session: u64,
    failed_attempts: u32,
    max_failed_attempts: u32,
}

impl AdminAuthenticator {
    pub fn new(password_hash: impl Into<String>) -> Self {
        Self {
            password_hash: password_hash.into(),
            next_session: 1,
            failed_attempts: 0,
            max_failed_attempts: 5,
        }
    }

    pub fn login(
        &mut self,
        password_hash: &str,
        sessions: &mut SessionStore,
    ) -> Result<Session, AppError> {
        if self.failed_attempts >= self.max_failed_attempts {
            return Err(AppError::new(
                ErrorCode::AdminInvalidCredentials,
                "too many failed attempts",
            ));
        }

        if password_hash != self.password_hash {
            self.failed_attempts += 1;
            return Err(AppError::new(
                ErrorCode::AdminInvalidCredentials,
                "invalid credentials",
            ));
        }

        self.failed_attempts = 0;
        let session = Session {
            session_id: format!("session-{}", self.next_session),
            csrf_token: format!("csrf-{}", self.next_session),
        };
        self.next_session += 1;
        sessions.insert(session.clone());
        Ok(session)
    }
}

pub fn require_session(sessions: &SessionStore, session_id: Option<&str>) -> Result<(), AppError> {
    let Some(session_id) = session_id else {
        return Err(AppError::new(
            ErrorCode::AdminAuthRequired,
            "admin session is required",
        ));
    };

    if sessions.verify(session_id) {
        Ok(())
    } else {
        Err(AppError::new(
            ErrorCode::AdminAuthRequired,
            "admin session is invalid",
        ))
    }
}

pub fn require_csrf(
    sessions: &SessionStore,
    session_id: &str,
    csrf_token: Option<&str>,
) -> Result<(), AppError> {
    let Some(csrf_token) = csrf_token else {
        return Err(AppError::new(
            ErrorCode::AdminCsrfRequired,
            "csrf token is required",
        ));
    };

    if sessions.verify_csrf(session_id, csrf_token) {
        Ok(())
    } else {
        Err(AppError::new(
            ErrorCode::AdminCsrfRequired,
            "csrf token is invalid",
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusResponse {
    pub version_prefix: String,
    pub current_revision_id: String,
    pub desired_revision_id: String,
    pub active_revision_id: String,
    pub restart_required: bool,
    pub activation_state: String,
    pub desired_resource_policy: ResourcePolicyResponse,
    pub active_resource_policy: ResourcePolicyResponse,
    pub live_resource_status: Option<LiveResourceStatusResponse>,
    pub routes: usize,
    pub services: usize,
    pub certificates: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveResourceStatusResponse {
    pub revision_id: String,
    pub generation: u64,
    pub used_payload_bytes: usize,
    pub payload_limit_bytes: usize,
    pub active_connections: usize,
    pub pressure: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourcePolicyResponse {
    pub max_connections: usize,
    pub max_inflight_payload_bytes: usize,
}

pub fn status_response(snapshot: &ConfigSnapshot) -> StatusResponse {
    status_response_with_active(snapshot, snapshot)
}

pub fn status_response_with_active(
    desired: &ConfigSnapshot,
    active: &ConfigSnapshot,
) -> StatusResponse {
    status_response_with_active_and_resource(desired, active, None)
}

pub fn status_response_with_active_and_resource(
    desired: &ConfigSnapshot,
    active: &ConfigSnapshot,
    live_resource_status: Option<edge_ports::RuntimeResourceStatusSnapshot>,
) -> StatusResponse {
    let activation_state = config_activation_state(active, desired);
    StatusResponse {
        version_prefix: API_VERSION_PREFIX.to_string(),
        current_revision_id: desired.revision_id.as_str().to_string(),
        desired_revision_id: desired.revision_id.as_str().to_string(),
        active_revision_id: active.revision_id.as_str().to_string(),
        restart_required: activation_state == ConfigActivationState::PendingRestart,
        activation_state: activation_state.as_str().to_string(),
        desired_resource_policy: ResourcePolicyResponse {
            max_connections: desired.runtime.max_connections,
            max_inflight_payload_bytes: desired.runtime.max_inflight_payload_bytes,
        },
        active_resource_policy: ResourcePolicyResponse {
            max_connections: active.runtime.max_connections,
            max_inflight_payload_bytes: active.runtime.max_inflight_payload_bytes,
        },
        live_resource_status: live_resource_status.map(|status| LiveResourceStatusResponse {
            revision_id: status.revision_id.as_str().to_string(),
            generation: status.generation,
            used_payload_bytes: status.used_payload_bytes,
            payload_limit_bytes: status.payload_limit_bytes,
            active_connections: status.active_connections,
            pressure: status.pressure.as_str().to_string(),
        }),
        routes: desired.routes.len(),
        services: desired.services.len(),
        certificates: desired
            .routes
            .iter()
            .filter(|route| route.certificate_ref.is_some())
            .count(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthResponse {
    pub status: String,
    pub current_revision_id: String,
    pub routes: usize,
    pub services: usize,
}

pub fn health_response(snapshot: &ConfigSnapshot) -> HealthResponse {
    HealthResponse {
        status: "ok".to_string(),
        current_revision_id: snapshot.revision_id.as_str().to_string(),
        routes: snapshot.routes.len(),
        services: snapshot.services.len(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamHealthStatusItem {
    pub service_id: String,
    pub upstream_id: String,
    pub status: UpstreamAvailability,
    pub drain_state: Option<RuntimeDrainState>,
    pub connection_count: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamHealthStatusResponse {
    pub revision_id: String,
    pub generation: u64,
    pub upstreams: Vec<UpstreamHealthStatusItem>,
}

pub fn upstream_health_status_response(
    snapshot: HealthAvailabilitySnapshot,
    runtime: Option<RuntimeUpstreamStatusSnapshot>,
) -> UpstreamHealthStatusResponse {
    let runtime = runtime.map(|snapshot| {
        snapshot
            .upstreams
            .into_iter()
            .map(|item| (item.key, (item.state, item.connection_count)))
            .collect::<BTreeMap<_, _>>()
    });
    UpstreamHealthStatusResponse {
        revision_id: snapshot.revision_id.as_str().to_string(),
        generation: snapshot.generation.0,
        upstreams: snapshot
            .entries
            .into_iter()
            .map(|(key, status)| {
                let drain = runtime.as_ref().and_then(|items| items.get(&key)).copied();
                UpstreamHealthStatusItem {
                    service_id: key.service_id.as_str().to_string(),
                    upstream_id: key.upstream_id.as_str().to_string(),
                    status,
                    drain_state: drain.map(|value| value.0),
                    connection_count: drain.map(|value| value.1),
                }
            })
            .collect(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminHttpMethod {
    Get,
    Post,
    Patch,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminHttpRequest {
    pub method: AdminHttpMethod,
    pub path: String,
    pub request_id: String,
    pub session_id: Option<String>,
    pub csrf_token: Option<String>,
    pub body: String,
}

impl AdminHttpRequest {
    pub fn new(
        method: AdminHttpMethod,
        path: impl Into<String>,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            method,
            path: path.into(),
            request_id: request_id.into(),
            session_id: None,
            csrf_token: None,
            body: String::new(),
        }
    }

    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    pub fn with_csrf_token(mut self, csrf_token: impl Into<String>) -> Self {
        self.csrf_token = Some(csrf_token.into());
        self
    }

    pub fn with_body(mut self, body: impl Into<String>) -> Self {
        self.body = body.into();
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminHttpResponse {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub error_code: Option<String>,
}

impl AdminHttpResponse {
    pub fn from_error(status_code: u16, error: AppError, request_id: &str) -> Self {
        error_response(status_code, error, request_id)
    }

    fn json(status_code: u16, body: String) -> Self {
        Self {
            status_code,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body,
            error_code: None,
        }
    }

    fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    fn with_error_code(mut self, error_code: impl Into<String>) -> Self {
        self.error_code = Some(error_code.into());
        self
    }
}

pub fn parse_admin_http_request(
    raw: &str,
    fallback_request_id: impl Into<String>,
) -> Result<AdminHttpRequest, AppError> {
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw, ""));
    let mut lines = head.lines();
    let request_line = lines.next().ok_or_else(|| {
        AppError::new(ErrorCode::HttpMalformedRequest, "missing HTTP request line")
    })?;
    let mut request_parts = request_line.split_whitespace();
    let method = parse_http_method(request_parts.next())?;
    let path = request_parts
        .next()
        .ok_or_else(|| AppError::new(ErrorCode::HttpMalformedRequest, "missing HTTP path"))?;
    let version = request_parts
        .next()
        .ok_or_else(|| AppError::new(ErrorCode::HttpMalformedRequest, "missing HTTP version"))?;
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(AppError::new(
            ErrorCode::HttpMalformedRequest,
            "unsupported HTTP version",
        ));
    }

    let mut request_id = fallback_request_id.into();
    let mut session_id = None;
    let mut csrf_token = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(AppError::new(
                ErrorCode::HttpMalformedRequest,
                "malformed HTTP header",
            ));
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("x-request-id") && !value.is_empty() {
            request_id = value.to_string();
        } else if name.eq_ignore_ascii_case("x-csrf-token") && !value.is_empty() {
            csrf_token = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("cookie") {
            session_id = cookie_value(value, "sponzey_session").map(str::to_string);
        }
    }

    Ok(AdminHttpRequest {
        method,
        path: path.to_string(),
        request_id,
        session_id,
        csrf_token,
        body: body.to_string(),
    })
}

pub fn render_admin_http_response(response: &AdminHttpResponse) -> String {
    let mut rendered = format!(
        "HTTP/1.1 {} {}\r\ncontent-length: {}\r\n",
        response.status_code,
        status_reason(response.status_code),
        response.body.len()
    );
    for (name, value) in &response.headers {
        rendered.push_str(name);
        rendered.push_str(": ");
        rendered.push_str(value);
        rendered.push_str("\r\n");
    }
    rendered.push_str("\r\n");
    rendered.push_str(&response.body);
    rendered
}

fn parse_http_method(method: Option<&str>) -> Result<AdminHttpMethod, AppError> {
    match method {
        Some("GET") => Ok(AdminHttpMethod::Get),
        Some("POST") => Ok(AdminHttpMethod::Post),
        Some("PATCH") => Ok(AdminHttpMethod::Patch),
        Some("DELETE") => Ok(AdminHttpMethod::Delete),
        Some(_) => Err(AppError::new(
            ErrorCode::HttpMalformedRequest,
            "unsupported HTTP method",
        )),
        None => Err(AppError::new(
            ErrorCode::HttpMalformedRequest,
            "missing HTTP method",
        )),
    }
}

fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|part| {
        let (candidate, value) = part.trim().split_once('=')?;
        (candidate == name).then_some(value)
    })
}

fn status_reason(status_code: u16) -> &'static str {
    match status_code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        500 => "Internal Server Error",
        _ => "Error",
    }
}

pub struct AdminHttpContext<'a> {
    pub snapshot: &'a ConfigSnapshot,
    pub sessions: &'a SessionStore,
}

pub struct AdminHttpRuntimeContext<'a> {
    pub snapshot: &'a ConfigSnapshot,
    pub sessions: &'a mut SessionStore,
    pub authenticator: &'a mut Option<AdminAuthenticator>,
    pub secrets: &'a mut dyn SecretStore,
}

pub fn handle_stateful_http_request(
    request: &AdminHttpRequest,
    context: AdminHttpRuntimeContext<'_>,
) -> AdminHttpResponse {
    match (request.method, request.path.as_str()) {
        (AdminHttpMethod::Post, "/api/v1/setup") => {
            handle_setup(request, context.authenticator, context.secrets)
        }
        (AdminHttpMethod::Post, "/api/v1/login") => {
            let Some(authenticator) = context.authenticator.as_mut() else {
                return setup_required_response(&request.request_id);
            };
            handle_login(request, authenticator, context.sessions)
        }
        (AdminHttpMethod::Post, "/api/v1/logout") => {
            if context.authenticator.is_none() {
                return setup_required_response(&request.request_id);
            }
            handle_logout(request, context.sessions)
        }
        _ if context.authenticator.is_none()
            && is_mutation_route(request.method, &request.path) =>
        {
            setup_required_response(&request.request_id)
        }
        _ => handle_http_request(
            request,
            AdminHttpContext {
                snapshot: context.snapshot,
                sessions: context.sessions,
            },
        ),
    }
}

pub fn handle_http_request(
    request: &AdminHttpRequest,
    context: AdminHttpContext<'_>,
) -> AdminHttpResponse {
    match (request.method, request.path.as_str()) {
        (AdminHttpMethod::Get, "/api/v1/status") => {
            handle_status_http(context.snapshot, context.snapshot)
        }
        (AdminHttpMethod::Get, "/api/v1/health") => handle_health_http(request, context.snapshot),
        (AdminHttpMethod::Get, "/api/v1/config") => {
            handle_config_get_http(request, context.sessions, context.snapshot)
        }
        (AdminHttpMethod::Post, "/api/v1/config/validate") => {
            handle_config_validate_http(request, context.sessions)
        }
        (AdminHttpMethod::Post, "/api/v1/config/diff") => {
            handle_config_diff_http(request, context.sessions, context.snapshot)
        }
        (AdminHttpMethod::Get, "/api/v1/proxy-hosts") => {
            handle_proxy_host_list_http(request, context.sessions, context.snapshot)
        }
        (AdminHttpMethod::Get, path) if path.starts_with("/api/v1/proxy-hosts/") => {
            handle_proxy_host_get_http(request, context.sessions, context.snapshot)
        }
        _ if is_mutation_route(request.method, &request.path) => {
            if let Err(error) = require_session(context.sessions, request.session_id.as_deref()) {
                return error_response(401, error, &request.request_id);
            }
            if let Err(error) = require_csrf(
                context.sessions,
                request.session_id.as_deref().unwrap_or_default(),
                request.csrf_token.as_deref(),
            ) {
                return error_response(403, error, &request.request_id);
            }
            error_response(
                501,
                AppError::new(
                    ErrorCode::AdminEndpointNotImplemented,
                    "http mutation route is not bound yet",
                ),
                &request.request_id,
            )
        }
        _ => error_response(
            404,
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found"),
            &request.request_id,
        ),
    }
}

pub fn handle_status_http(desired: &ConfigSnapshot, active: &ConfigSnapshot) -> AdminHttpResponse {
    handle_status_http_with_resource(desired, active, None)
}

pub fn handle_status_http_with_resource(
    desired: &ConfigSnapshot,
    active: &ConfigSnapshot,
    live_resource_status: Option<edge_ports::RuntimeResourceStatusSnapshot>,
) -> AdminHttpResponse {
    AdminHttpResponse::json(
        200,
        status_response_json(&status_response_with_active_and_resource(
            desired,
            active,
            live_resource_status,
        )),
    )
}

fn handle_setup(
    request: &AdminHttpRequest,
    authenticator: &mut Option<AdminAuthenticator>,
    secrets: &mut dyn SecretStore,
) -> AdminHttpResponse {
    if authenticator.is_some() {
        return error_response(
            409,
            AppError::new(
                ErrorCode::AdminSetupAlreadyComplete,
                "admin setup is already complete",
            ),
            &request.request_id,
        );
    }
    match secrets.load_secret("admin-password-hash") {
        Ok(Some(_)) => {
            return error_response(
                409,
                AppError::new(
                    ErrorCode::AdminSetupAlreadyComplete,
                    "admin setup is already complete",
                ),
                &request.request_id,
            );
        }
        Ok(None) => {}
        Err(error) => return error_response(500, error, &request.request_id),
    }

    let Some(password_hash) = json_string_field(&request.body, "password_hash") else {
        return error_response(
            400,
            AppError::new(
                ErrorCode::HttpMalformedRequest,
                "setup request requires password_hash",
            ),
            &request.request_id,
        );
    };
    if let Err(error) = secrets.save_secret(SecretRecord {
        name: "admin-password-hash".to_string(),
        value: password_hash.clone(),
    }) {
        return error_response(500, error, &request.request_id);
    }
    *authenticator = Some(AdminAuthenticator::new(password_hash));
    AdminHttpResponse::json(200, "{\"setup_complete\":true}".to_string())
}

fn handle_login(
    request: &AdminHttpRequest,
    authenticator: &mut AdminAuthenticator,
    sessions: &mut SessionStore,
) -> AdminHttpResponse {
    let Some(password_hash) = json_string_field(&request.body, "password_hash") else {
        return error_response(
            400,
            AppError::new(
                ErrorCode::HttpMalformedRequest,
                "login request requires password_hash",
            ),
            &request.request_id,
        );
    };
    match authenticator.login(&password_hash, sessions) {
        Ok(session) => {
            let body = login_response_json(&session);
            AdminHttpResponse::json(200, body)
                .with_header("set-cookie", session_cookie_header(&session.session_id))
        }
        Err(error) => error_response(401, error, &request.request_id),
    }
}

fn handle_logout(request: &AdminHttpRequest, sessions: &mut SessionStore) -> AdminHttpResponse {
    let Some(session_id) = request.session_id.as_deref() else {
        return error_response(
            401,
            AppError::new(ErrorCode::AdminAuthRequired, "admin session is required"),
            &request.request_id,
        );
    };
    if let Err(error) = require_session(sessions, Some(session_id)) {
        return error_response(401, error, &request.request_id);
    }
    if let Err(error) = require_csrf(sessions, session_id, request.csrf_token.as_deref()) {
        return error_response(403, error, &request.request_id);
    }
    sessions.remove(session_id);
    AdminHttpResponse::json(200, "{\"logged_out\":true}".to_string())
        .with_header("set-cookie", expired_session_cookie_header())
}

fn setup_required_response(request_id: &str) -> AdminHttpResponse {
    error_response(
        403,
        AppError::new(
            ErrorCode::AdminSetupRequired,
            "admin setup is required before login",
        ),
        request_id,
    )
}

fn is_mutation_route(method: AdminHttpMethod, path: &str) -> bool {
    matches!(
        (method, path),
        (AdminHttpMethod::Post, "/api/v1/config/apply")
            | (AdminHttpMethod::Post, "/api/v1/config/rollback")
            | (AdminHttpMethod::Post, "/api/v1/proxy-hosts")
            | (AdminHttpMethod::Post, "/api/v1/trust-bundles")
            | (AdminHttpMethod::Post, "/api/v1/logout")
            | (AdminHttpMethod::Patch, _)
            | (AdminHttpMethod::Delete, _)
    ) || (method == AdminHttpMethod::Post && is_certificate_mutation_path(path))
}

fn is_certificate_mutation_path(path: &str) -> bool {
    path.starts_with("/api/v1/certificates/")
        && (path.ends_with("/issue") || path.ends_with("/renew") || path.ends_with("/import"))
}

pub trait TrustBundleAdminService {
    fn import(
        &mut self,
        request_id: &str,
        trust_bundle_ref: TrustBundleRef,
        encoded_material: Vec<u8>,
    ) -> Result<TrustBundleMetadata, AppError>;
    fn list(&mut self) -> Result<Vec<TrustBundleMetadata>, AppError>;
    fn delete(&mut self, trust_bundle_ref: TrustBundleRef) -> Result<(), AppError>;
}

pub fn handle_trust_bundle_http<S: TrustBundleAdminService>(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    service: &mut S,
) -> AdminHttpResponse {
    if let Err(error) = require_session(sessions, request.session_id.as_deref()) {
        return error_response(401, error, &request.request_id);
    }
    let mutation = matches!(
        request.method,
        AdminHttpMethod::Post | AdminHttpMethod::Delete
    );
    if mutation {
        if let Err(error) = require_csrf(
            sessions,
            request.session_id.as_deref().unwrap_or_default(),
            request.csrf_token.as_deref(),
        ) {
            return error_response(403, error, &request.request_id);
        }
    }
    let result = match (request.method, request.path.as_str()) {
        (AdminHttpMethod::Get, "/api/v1/trust-bundles") => {
            service.list().map(|items| trust_bundle_list_json(&items))
        }
        (AdminHttpMethod::Post, "/api/v1/trust-bundles") => {
            let Some(reference) = json_string_field(&request.body, "trust_bundle_ref") else {
                return error_response(
                    400,
                    AppError::new(
                        ErrorCode::HttpMalformedRequest,
                        "trust bundle ref is required",
                    ),
                    &request.request_id,
                );
            };
            let Some(material) = json_string_field(&request.body, "encoded_material") else {
                return error_response(
                    400,
                    AppError::new(
                        ErrorCode::HttpMalformedRequest,
                        "trust bundle material is required",
                    ),
                    &request.request_id,
                );
            };
            if material.len() > 384 * 1024 {
                return error_response(
                    400,
                    AppError::new(
                        ErrorCode::TrustBundleLimitExceeded,
                        "trust bundle input is too large",
                    ),
                    &request.request_id,
                );
            }
            let reference = match TrustBundleRef::parse(&reference) {
                Ok(reference) => reference,
                Err(error) => {
                    return error_response(
                        400,
                        AppError::new(error.code, error.message),
                        &request.request_id,
                    )
                }
            };
            service
                .import(&request.request_id, reference, material.into_bytes())
                .map(|metadata| trust_bundle_metadata_json(&metadata))
        }
        (AdminHttpMethod::Delete, path) if path.starts_with("/api/v1/trust-bundles/") => {
            let raw = path.trim_start_matches("/api/v1/trust-bundles/");
            let reference = match TrustBundleRef::parse(raw) {
                Ok(reference) => reference,
                Err(error) => {
                    return error_response(
                        400,
                        AppError::new(error.code, error.message),
                        &request.request_id,
                    )
                }
            };
            service
                .delete(reference)
                .map(|()| "{\"deleted\":true}".to_string())
        }
        _ => Err(AppError::new(
            ErrorCode::AdminRouteNotFound,
            "admin http route not found",
        )),
    };
    match result {
        Ok(body) => AdminHttpResponse::json(200, body),
        Err(error) => error_response(http_status_for_error(&error), error, &request.request_id),
    }
}

fn trust_bundle_metadata_json(metadata: &TrustBundleMetadata) -> String {
    format!(
        "{{\"trust_bundle_ref\":\"{}\",\"certificate_count\":{},\"imported_at_epoch_seconds\":{}}}",
        json_escape(metadata.trust_bundle_ref.as_str()),
        metadata.certificate_count,
        metadata.imported_at_epoch_seconds
    )
}

fn trust_bundle_list_json(items: &[TrustBundleMetadata]) -> String {
    format!(
        "{{\"trust_bundles\":[{}]}}",
        items
            .iter()
            .map(trust_bundle_metadata_json)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn error_response(status_code: u16, error: AppError, request_id: &str) -> AdminHttpResponse {
    let error_code = error.code.as_str().to_string();
    AdminHttpResponse::json(
        status_code,
        error_response_json(&ApiErrorResponse::from_error(error, request_id)),
    )
    .with_error_code(error_code)
}

fn http_status_for_error(error: &AppError) -> u16 {
    match error.code {
        ErrorCode::AdminAuthRequired | ErrorCode::AdminInvalidCredentials => 401,
        ErrorCode::AdminCsrfRequired | ErrorCode::AdminSetupRequired => 403,
        ErrorCode::AdminRouteNotFound
        | ErrorCode::CertificateNotFound
        | ErrorCode::ConfigTrustBundleNotFound => 404,
        ErrorCode::AdminSetupAlreadyComplete
        | ErrorCode::ConfigRevisionNotFound
        | ErrorCode::TrustBundleAlreadyExists
        | ErrorCode::TrustBundleReferenced => 409,
        ErrorCode::AdminEndpointNotImplemented => 501,
        ErrorCode::AcmeTermsNotAccepted
        | ErrorCode::AuditCursorInvalid
        | ErrorCode::AuditRecordInvalid
        | ErrorCode::CertificateInvalid
        | ErrorCode::TrustBundleInvalid
        | ErrorCode::TrustBundleLimitExceeded => 400,
        ErrorCode::AcmeChallengeFailed => 500,
        ErrorCode::ConfigStoreFailed
        | ErrorCode::TrustBundleStoreFailed
        | ErrorCode::RuntimeCommandRejected
        | ErrorCode::RuntimeHealthUnavailable
        | ErrorCode::InternalBug => 500,
        code if code.as_str().starts_with("CONFIG_") => 400,
        code if code.as_str().starts_with("HTTP_") => 400,
        _ => 500,
    }
}

fn status_response_json(response: &StatusResponse) -> String {
    let live_resource_status = response.live_resource_status.as_ref().map_or_else(
        || "null".to_string(),
        |status| {
            format!(
                "{{\"revision_id\":\"{}\",\"generation\":{},\"used_payload_bytes\":{},\"payload_limit_bytes\":{},\"active_connections\":{},\"pressure\":\"{}\"}}",
                json_escape(&status.revision_id),
                status.generation,
                status.used_payload_bytes,
                status.payload_limit_bytes,
                status.active_connections,
                json_escape(&status.pressure),
            )
        },
    );
    format!(
        "{{\"version_prefix\":\"{}\",\"current_revision_id\":\"{}\",\"desired_revision_id\":\"{}\",\"active_revision_id\":\"{}\",\"restart_required\":{},\"activation_state\":\"{}\",\"desired_resource_policy\":{{\"max_connections\":{},\"max_inflight_payload_bytes\":{}}},\"active_resource_policy\":{{\"max_connections\":{},\"max_inflight_payload_bytes\":{}}},\"live_resource_status\":{},\"routes\":{},\"services\":{},\"certificates\":{}}}",
        json_escape(&response.version_prefix),
        json_escape(&response.current_revision_id),
        json_escape(&response.desired_revision_id),
        json_escape(&response.active_revision_id),
        response.restart_required,
        json_escape(&response.activation_state),
        response.desired_resource_policy.max_connections,
        response.desired_resource_policy.max_inflight_payload_bytes,
        response.active_resource_policy.max_connections,
        response.active_resource_policy.max_inflight_payload_bytes,
        live_resource_status,
        response.routes,
        response.services,
        response.certificates
    )
}

fn health_response_json(response: &HealthResponse) -> String {
    format!(
        "{{\"status\":\"{}\",\"current_revision_id\":\"{}\",\"routes\":{},\"services\":{}}}",
        json_escape(&response.status),
        json_escape(&response.current_revision_id),
        response.routes,
        response.services
    )
}

fn upstream_health_status_response_json(response: &UpstreamHealthStatusResponse) -> String {
    let upstreams = response
        .upstreams
        .iter()
        .map(|item| {
            format!(
                "{{\"service_id\":\"{}\",\"upstream_id\":\"{}\",\"status\":\"{}\",\"drain_state\":{},\"connection_count\":{}}}",
                json_escape(&item.service_id),
                json_escape(&item.upstream_id),
                upstream_availability_name(item.status),
                item.drain_state.map(runtime_drain_state_name).map(|value| format!("\"{value}\"")).unwrap_or_else(|| "null".to_string()),
                item.connection_count.map(|value| value.to_string()).unwrap_or_else(|| "null".to_string())
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"revision_id\":\"{}\",\"generation\":{},\"upstreams\":[{}]}}",
        json_escape(&response.revision_id),
        response.generation,
        upstreams
    )
}

fn runtime_drain_state_name(state: RuntimeDrainState) -> &'static str {
    match state {
        RuntimeDrainState::Active => "active",
        RuntimeDrainState::Draining => "draining",
        RuntimeDrainState::Drained => "drained",
        RuntimeDrainState::Removed => "removed",
    }
}

fn upstream_availability_name(status: UpstreamAvailability) -> &'static str {
    match status {
        UpstreamAvailability::Disabled => "disabled",
        UpstreamAvailability::Unknown => "unknown",
        UpstreamAvailability::Healthy => "healthy",
        UpstreamAvailability::Unhealthy => "unhealthy",
    }
}

fn login_response_json(session: &Session) -> String {
    format!(
        "{{\"csrf_token\":\"{}\"}}",
        json_escape(&session.csrf_token)
    )
}

fn error_response_json(response: &ApiErrorResponse) -> String {
    format!(
        "{{\"code\":\"{}\",\"message\":\"{}\",\"hint\":\"{}\",\"request_id\":\"{}\"}}",
        json_escape(&response.code),
        json_escape(&response.message),
        json_escape(&response.hint),
        json_escape(&response.request_id)
    )
}

fn apply_response_json(response: &ApplyResponse) -> String {
    format!(
        "{{\"revision_id\":\"{}\",\"commands_sent\":{},\"restart_required\":{}}}",
        json_escape(&response.revision_id),
        response.commands_sent,
        response.restart_required
    )
}

fn proxy_host_list_response_json(proxy_hosts: &[ProxyHostResponse]) -> String {
    let items = proxy_hosts
        .iter()
        .map(proxy_host_response_json)
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"proxy_hosts\":[{items}]}}")
}

fn proxy_host_response_json(proxy_host: &ProxyHostResponse) -> String {
    format!(
        "{{\"id\":\"{}\",\"name\":\"{}\",\"domains\":{},\"path_prefix\":\"{}\",\"upstream_url\":\"{}\",\"upstreams\":{},\"health_check\":{},\"retry\":{},\"passive_health\":{},\"https_enabled\":{},\"letsencrypt_enabled\":{},\"redirect_http_to_https\":{},\"enabled\":{}}}",
        json_escape(&proxy_host.id),
        json_escape(&proxy_host.name),
        json_string_array_json(&proxy_host.domains),
        json_escape(&proxy_host.path_prefix),
        json_escape(&proxy_host.upstream_url),
        proxy_host_upstreams_json(&proxy_host.upstreams),
        proxy_host_health_check_json(proxy_host.health_check.as_ref()),
        proxy_host_retry_json(proxy_host.retry),
        proxy_host_passive_health_json(proxy_host.passive_health),
        proxy_host.https_enabled,
        proxy_host.letsencrypt_enabled,
        proxy_host.redirect_http_to_https,
        proxy_host.enabled
    )
}

fn proxy_host_upstreams_json(upstreams: &[ProxyHostUpstreamRequest]) -> String {
    let items = upstreams
        .iter()
        .map(|upstream| {
            format!(
                "{{\"id\":\"{}\",\"url\":\"{}\",\"administrative_state\":\"{}\"}}",
                json_escape(&upstream.id),
                json_escape(&upstream.url),
                match upstream.administrative_state {
                    UpstreamAdministrativeState::Active => "active",
                    UpstreamAdministrativeState::Draining => "draining",
                }
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("[{items}]")
}

fn proxy_host_retry_json(policy: RetryPolicy) -> String {
    format!(
        "{{\"enabled\":{},\"max_retries\":{},\"max_replay_bytes\":{}}}",
        policy.enabled, policy.max_retries, policy.max_replay_bytes
    )
}

fn proxy_host_passive_health_json(mode: PassiveHealthMode) -> String {
    match mode {
        PassiveHealthMode::Disabled => "{\"enabled\":false}".to_string(),
        PassiveHealthMode::Enabled(policy) => format!(
            "{{\"enabled\":true,\"failure_threshold\":{},\"ejection_ms\":{}}}",
            policy.failure_threshold, policy.ejection_ms
        ),
    }
}

fn proxy_host_health_check_json(health: Option<&HttpHealthCheckPolicy>) -> String {
    match health {
        Some(health) => format!(
            "{{\"enabled\":true,\"path\":\"{}\",\"interval_ms\":{},\"timeout_ms\":{},\"healthy_threshold\":{},\"unhealthy_threshold\":{},\"status_min\":{},\"status_max\":{}}}",
            json_escape(&health.path),
            health.interval_ms,
            health.timeout_ms,
            health.healthy_threshold,
            health.unhealthy_threshold,
            health.status_min,
            health.status_max
        ),
        None => "{\"enabled\":false}".to_string(),
    }
}

fn json_string_array_json(values: &[String]) -> String {
    let items = values
        .iter()
        .map(|value| format!("\"{}\"", json_escape(value)))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{items}]")
}

fn certificate_list_response_json(certificates: &[CertificateStatus]) -> String {
    let items = certificates
        .iter()
        .map(certificate_status_json)
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"certificates\":[{items}]}}")
}

fn certificate_status_json(certificate: &CertificateStatus) -> String {
    format!(
        "{{\"certificate_ref\":\"{}\",\"domains\":{},\"source\":\"{}\",\"expired\":{},\"expiring_soon\":{},\"not_after_epoch_seconds\":{},\"private_key\":\"{}\"}}",
        json_escape(certificate.certificate_ref.as_str()),
        json_string_array_json(&certificate.domains),
        json_escape(&certificate.source),
        certificate.expired,
        certificate.expiring_soon,
        certificate.not_after_epoch_seconds,
        json_escape(certificate.private_key_masked)
    )
}

fn certificate_issue_outcome_json(outcome: &CertificateIssueOutcome, request_id: &str) -> String {
    format!(
        "{{\"request_id\":\"{}\",\"certificate_ref\":\"{}\",\"domains\":{},\"source\":\"{}\",\"not_after_epoch_seconds\":{},\"commands_sent\":{}}}",
        json_escape(request_id),
        json_escape(outcome.certificate_ref.as_str()),
        json_string_array_json(&outcome.domains),
        json_escape(&outcome.source),
        outcome.not_after_epoch_seconds,
        outcome.commands_sent
    )
}

fn certificate_import_outcome_json(
    outcome: &ManualCertificateImportOutcome,
    request_id: &str,
) -> String {
    format!(
        "{{\"request_id\":\"{}\",\"certificate_ref\":\"{}\",\"domains\":{},\"source\":\"{}\",\"not_after_epoch_seconds\":{},\"private_key\":\"{}\",\"state\":\"installed\",\"commands_sent\":{}}}",
        json_escape(request_id),
        json_escape(outcome.status.certificate_ref.as_str()),
        json_string_array_json(&outcome.status.domains),
        json_escape(&outcome.status.source),
        outcome.status.not_after_epoch_seconds,
        outcome.status.private_key_masked,
        outcome.commands_sent
    )
}

fn access_logs_response_json(events: &[AccessLogEvent]) -> String {
    let items = events
        .iter()
        .map(access_log_event_json)
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"access_logs\":[{items}]}}")
}

fn access_log_event_json(event: &AccessLogEvent) -> String {
    format!(
        "{{\"request_id\":\"{}\",\"revision_id\":\"{}\",\"route_id\":{},\"upstream_id\":{},\"status_code\":{},\"duration_ms\":{}}}",
        json_escape(&event.request_id),
        json_escape(&event.revision_id),
        json_optional_string_json(event.route_id.as_deref()),
        json_optional_string_json(event.upstream_id.as_deref()),
        event.status_code,
        event.duration_ms
    )
}

fn error_logs_response_json(events: &[RecentErrorEvent]) -> String {
    let items = events
        .iter()
        .map(error_log_event_json)
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"error_logs\":[{items}]}}")
}

fn error_log_event_json(event: &RecentErrorEvent) -> String {
    format!(
        "{{\"request_id\":{},\"error_code\":\"{}\",\"message\":\"{}\"}}",
        json_optional_string_json(event.request_id.as_deref()),
        json_escape(&event.error_code),
        json_escape(&event.message)
    )
}

fn json_optional_string_json(value: Option<&str>) -> String {
    match value {
        Some(value) => format!("\"{}\"", json_escape(value)),
        None => "null".to_string(),
    }
}

fn config_response_json(snapshot: &ConfigSnapshot) -> String {
    format!(
        "{{\"revision_id\":\"{}\",\"config\":\"{}\"}}",
        json_escape(snapshot.revision_id.as_str()),
        json_escape(&render_mvp_config_snapshot(snapshot))
    )
}

fn config_validation_response_json(errors: &[ValidationError]) -> String {
    let items = errors
        .iter()
        .map(validation_error_json)
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"valid\":{},\"errors\":[{}]}}", errors.is_empty(), items)
}

fn config_diff_response_json(diff: Option<&ConfigDiff>, errors: &[ValidationError]) -> String {
    let empty = ConfigDiff {
        added_routes: Vec::new(),
        removed_routes: Vec::new(),
        changed_upstreams: Vec::new(),
    };
    let diff = diff.unwrap_or(&empty);
    let errors_json = errors
        .iter()
        .map(validation_error_json)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"valid\":{},\"errors\":[{}],\"diff\":{{\"added_routes\":{},\"removed_routes\":{},\"changed_upstreams\":{}}}}}",
        errors.is_empty(),
        errors_json,
        json_string_array_json(&diff.added_routes),
        json_string_array_json(&diff.removed_routes),
        json_string_array_json(&diff.changed_upstreams)
    )
}

fn validation_error_json(error: &ValidationError) -> String {
    format!(
        "{{\"code\":\"{}\",\"message\":\"{}\",\"hint\":\"{}\"}}",
        json_escape(error.code.as_str()),
        json_escape(&error.message),
        json_escape(error.code.default_user_message())
    )
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::new();
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn json_string_field(body: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\"");
    let after_name = body.split_once(&needle)?.1;
    let after_colon = after_name.split_once(':')?.1.trim_start();
    let after_open = after_colon.strip_prefix('"')?;
    let mut output = String::new();
    let mut escaped = false;
    for character in after_open.chars() {
        if escaped {
            push_json_escaped_character(&mut output, character)?;
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            return Some(output);
        } else {
            output.push(character);
        }
    }
    None
}

fn json_bool_field(body: &str, field: &str) -> Option<bool> {
    let needle = format!("\"{field}\"");
    let after_name = body.split_once(&needle)?.1;
    let after_colon = after_name.split_once(':')?.1.trim_start();
    if after_colon.starts_with("true") {
        Some(true)
    } else if after_colon.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn json_string_array_field(body: &str, field: &str) -> Option<Vec<String>> {
    let needle = format!("\"{field}\"");
    let after_name = body.split_once(&needle)?.1;
    let mut input = after_name.split_once(':')?.1.trim_start();
    input = input.strip_prefix('[')?.trim_start();

    let mut values = Vec::new();
    loop {
        input = input.trim_start();
        if input.starts_with(']') {
            return Some(values);
        }
        let parsed = parse_json_string_prefix(input)?;
        values.push(parsed.0);
        input = parsed.1.trim_start();
        if let Some(remaining) = input.strip_prefix(',') {
            input = remaining;
        } else if input.starts_with(']') {
            return Some(values);
        } else {
            return None;
        }
    }
}

fn parse_json_string_prefix(input: &str) -> Option<(String, &str)> {
    let after_open = input.strip_prefix('"')?;
    let mut output = String::new();
    let mut escaped = false;
    for (index, character) in after_open.char_indices() {
        if escaped {
            push_json_escaped_character(&mut output, character)?;
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            return Some((output, &after_open[index + character.len_utf8()..]));
        } else {
            output.push(character);
        }
    }
    None
}

fn push_json_escaped_character(output: &mut String, character: char) -> Option<()> {
    output.push(match character {
        '"' => '"',
        '\\' => '\\',
        '/' => '/',
        'n' => '\n',
        'r' => '\r',
        't' => '\t',
        _ => return None,
    });
    Some(())
}

fn session_cookie_header(session_id: &str) -> String {
    format!(
        "sponzey_session={}; Path=/; HttpOnly; Secure; SameSite=Strict",
        json_escape(session_id)
    )
}

fn expired_session_cookie_header() -> &'static str {
    "sponzey_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict"
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyHostRequest {
    pub id: String,
    pub name: String,
    pub domains: Vec<String>,
    pub path_prefix: String,
    pub upstream_url: String,
    pub upstreams: Vec<ProxyHostUpstreamRequest>,
    pub health_check: Option<HttpHealthCheckPolicy>,
    pub retry: RetryPolicy,
    pub passive_health: PassiveHealthMode,
    pub https_enabled: bool,
    pub letsencrypt_enabled: bool,
    pub redirect_http_to_https: bool,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyHostResponse {
    pub id: String,
    pub name: String,
    pub domains: Vec<String>,
    pub path_prefix: String,
    pub upstream_url: String,
    pub upstreams: Vec<ProxyHostUpstreamRequest>,
    pub health_check: Option<HttpHealthCheckPolicy>,
    pub retry: RetryPolicy,
    pub passive_health: PassiveHealthMode,
    pub https_enabled: bool,
    pub letsencrypt_enabled: bool,
    pub redirect_http_to_https: bool,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyHostUpstreamRequest {
    pub id: String,
    pub url: String,
    pub administrative_state: UpstreamAdministrativeState,
}

pub fn proxy_host_from_request(request: ProxyHostRequest) -> ProxyHost {
    ProxyHost {
        id: ProxyHostId::new(request.id),
        name: request.name,
        domains: request.domains.iter().map(HostMatch::exact).collect(),
        path_prefix: PathMatch::prefix(request.path_prefix),
        upstream_url: request.upstream_url,
        upstreams: request
            .upstreams
            .into_iter()
            .map(|upstream| Upstream {
                id: UpstreamId::new(upstream.id),
                url: upstream.url,
                administrative_state: upstream.administrative_state,
                tls: edge_domain::UpstreamTlsPolicy::Disabled,
            })
            .collect(),
        health_check: request
            .health_check
            .map(HealthCheckPolicy::Http)
            .unwrap_or(HealthCheckPolicy::Disabled),
        retry: request.retry,
        passive_health: request.passive_health,
        https_enabled: request.https_enabled,
        letsencrypt_enabled: request.letsencrypt_enabled,
        redirect_http_to_https: request.redirect_http_to_https,
        enabled: request.enabled,
    }
}

pub fn proxy_host_request_from_json(body: &str) -> Result<ProxyHostRequest, AppError> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|_| malformed_json_field("body"))?;
    let upstreams = proxy_host_upstreams_from_json(&value)?;
    let upstream_url = json_string_field(body, "upstream_url")
        .or_else(|| upstreams.first().map(|upstream| upstream.url.clone()))
        .ok_or_else(|| malformed_json_field("upstream_url or upstreams"))?;
    Ok(ProxyHostRequest {
        id: required_json_string(body, "id")?,
        name: required_json_string(body, "name")?,
        domains: required_json_string_array(body, "domains")?,
        path_prefix: required_json_string(body, "path_prefix")?,
        upstream_url,
        upstreams,
        health_check: proxy_host_health_check_from_json(&value)?,
        retry: proxy_host_retry_from_json(&value)?,
        passive_health: proxy_host_passive_health_from_json(&value)?,
        https_enabled: required_json_bool(body, "https_enabled")?,
        letsencrypt_enabled: required_json_bool(body, "letsencrypt_enabled")?,
        redirect_http_to_https: required_json_bool(body, "redirect_http_to_https")?,
        enabled: required_json_bool(body, "enabled")?,
    })
}

fn proxy_host_upstreams_from_json(
    value: &serde_json::Value,
) -> Result<Vec<ProxyHostUpstreamRequest>, AppError> {
    let Some(items) = value.get("upstreams") else {
        return Ok(Vec::new());
    };
    let items = items
        .as_array()
        .ok_or_else(|| malformed_json_field("upstreams"))?;
    items
        .iter()
        .map(|item| {
            let id = item
                .get("id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| malformed_json_field("upstreams.id"))?;
            let url = item
                .get("url")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| malformed_json_field("upstreams.url"))?;
            Ok(ProxyHostUpstreamRequest {
                id: id.to_string(),
                url: url.to_string(),
                administrative_state: match item
                    .get("administrative_state")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("active")
                {
                    "active" => UpstreamAdministrativeState::Active,
                    "draining" => UpstreamAdministrativeState::Draining,
                    _ => return Err(malformed_json_field("upstreams.administrative_state")),
                },
            })
        })
        .collect()
}

fn proxy_host_retry_from_json(value: &serde_json::Value) -> Result<RetryPolicy, AppError> {
    let Some(policy) = value.get("retry") else {
        return Ok(RetryPolicy::default());
    };
    let enabled = policy
        .get("enabled")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| malformed_json_field("retry.enabled"))?;
    let max_retries = policy
        .get("max_retries")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| malformed_json_field("retry.max_retries"))?
        .try_into()
        .map_err(|_| malformed_json_field("retry.max_retries"))?;
    let max_replay_bytes = policy
        .get("max_replay_bytes")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| malformed_json_field("retry.max_replay_bytes"))?;
    Ok(RetryPolicy {
        enabled,
        max_retries,
        max_replay_bytes,
    })
}

fn proxy_host_passive_health_from_json(
    value: &serde_json::Value,
) -> Result<PassiveHealthMode, AppError> {
    let Some(policy) = value.get("passive_health") else {
        return Ok(PassiveHealthMode::Disabled);
    };
    let enabled = policy
        .get("enabled")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| malformed_json_field("passive_health.enabled"))?;
    if !enabled {
        return Ok(PassiveHealthMode::Disabled);
    }
    let failure_threshold = policy
        .get("failure_threshold")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| malformed_json_field("passive_health.failure_threshold"))?
        .try_into()
        .map_err(|_| malformed_json_field("passive_health.failure_threshold"))?;
    let ejection_ms = policy
        .get("ejection_ms")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| malformed_json_field("passive_health.ejection_ms"))?;
    edge_domain::PassiveHealthPolicy::new(failure_threshold, ejection_ms)
        .map(PassiveHealthMode::Enabled)
        .map_err(|error| AppError::new(error.code, error.message))
}

fn proxy_host_health_check_from_json(
    value: &serde_json::Value,
) -> Result<Option<HttpHealthCheckPolicy>, AppError> {
    let Some(health) = value.get("health_check") else {
        return Ok(None);
    };
    let enabled = health
        .get("enabled")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| malformed_json_field("health_check.enabled"))?;
    if !enabled {
        return Ok(None);
    }
    let string = |field: &str| {
        health
            .get(field)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| malformed_json_field(field))
    };
    let integer = |field: &str| {
        health
            .get(field)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| malformed_json_field(field))
    };
    let policy = HttpHealthCheckPolicy::new(
        string("path")?,
        integer("interval_ms")?,
        integer("timeout_ms")?,
        u32::try_from(integer("healthy_threshold")?)
            .map_err(|_| malformed_json_field("healthy_threshold"))?,
        u32::try_from(integer("unhealthy_threshold")?)
            .map_err(|_| malformed_json_field("unhealthy_threshold"))?,
        u16::try_from(integer("status_min")?).map_err(|_| malformed_json_field("status_min"))?,
        u16::try_from(integer("status_max")?).map_err(|_| malformed_json_field("status_max"))?,
    )
    .map_err(|error| AppError::new(error.code, error.message))?;
    Ok(Some(policy))
}

pub fn certificate_issue_request_from_json(body: &str) -> Result<AcmeOrderRequest, AppError> {
    let domains = required_json_string_array(body, "domains")?;
    if domains.is_empty() {
        return Err(AppError::new(
            ErrorCode::HttpMalformedRequest,
            "certificate issue request requires at least one domain",
        ));
    }

    Ok(AcmeOrderRequest {
        domains,
        account_email: required_json_string(body, "account_email")?,
        production: required_json_bool(body, "production")?,
        terms_accepted: required_json_bool(body, "terms_accepted")?,
    })
}

pub fn certificate_renew_request_from_json(
    body: &str,
) -> Result<CertificateRenewRequest, AppError> {
    Ok(CertificateRenewRequest {
        account_email: required_json_string(body, "account_email")?,
        production: required_json_bool(body, "production")?,
        terms_accepted: required_json_bool(body, "terms_accepted")?,
    })
}

fn manual_certificate_import_request_from_json(
    body: &str,
    certificate_ref: CertificateRef,
    request_id: &str,
    revision_id: &ConfigRevisionId,
) -> Result<ManualCertificateImportRequest, AppError> {
    Ok(ManualCertificateImportRequest {
        certificate_ref,
        domains: required_json_string_array(body, "domains")?,
        fullchain_pem: required_json_string(body, "fullchain_pem")?,
        private_key_pem: required_json_string(body, "private_key_pem")?,
        expected_not_after_epoch_seconds: optional_json_u64(
            body,
            "expected_not_after_epoch_seconds",
        )?,
        request_id: request_id.to_string(),
        revision_id: revision_id.clone(),
    })
}

fn optional_json_u64(body: &str, field: &str) -> Result<Option<u64>, AppError> {
    let needle = format!("\"{field}\"");
    let Some((_, after_name)) = body.split_once(&needle) else {
        return Ok(None);
    };
    let value = after_name
        .split_once(':')
        .map(|(_, value)| value.trim_start())
        .ok_or_else(|| malformed_json_field(field))?;
    let digits = value
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect::<String>();
    if digits.is_empty() {
        return Err(malformed_json_field(field));
    }
    digits
        .parse::<u64>()
        .map(Some)
        .map_err(|_| malformed_json_field(field))
}

pub fn proxy_hosts_from_snapshot(snapshot: &ConfigSnapshot) -> Vec<ProxyHostResponse> {
    let mut proxy_hosts: Vec<_> = snapshot
        .routes
        .iter()
        .filter_map(|route| proxy_host_response_from_generated_route(snapshot, route))
        .collect();
    proxy_hosts.sort_by(|left, right| left.id.cmp(&right.id));
    proxy_hosts
}

pub fn proxy_host_from_snapshot(
    snapshot: &ConfigSnapshot,
    id: &ProxyHostId,
) -> Result<ProxyHostResponse, AppError> {
    proxy_hosts_from_snapshot(snapshot)
        .into_iter()
        .find(|proxy_host| proxy_host.id == id.as_str())
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::AdminRouteNotFound,
                format!("proxy host not found: {}", id.as_str()),
            )
        })
}

fn proxy_host_response_from_generated_route(
    snapshot: &ConfigSnapshot,
    route: &Route,
) -> Option<ProxyHostResponse> {
    let id = route.id.as_str().strip_prefix("proxy-host-")?;
    if id.is_empty() {
        return None;
    }
    let service = snapshot
        .services
        .iter()
        .find(|service| service.id == route.service_id)?;
    let upstream = service.upstreams.first()?;
    let path_prefix = route.route_match.paths.first()?;

    Some(ProxyHostResponse {
        id: id.to_string(),
        name: id.to_string(),
        domains: route
            .route_match
            .hosts
            .iter()
            .map(|host| host.as_str().to_string())
            .collect(),
        path_prefix: path_prefix.as_str().to_string(),
        upstream_url: upstream.url.clone(),
        upstreams: service
            .upstreams
            .iter()
            .map(|upstream| ProxyHostUpstreamRequest {
                id: upstream.id.as_str().to_string(),
                url: upstream.url.clone(),
                administrative_state: upstream.administrative_state,
            })
            .collect(),
        health_check: match &service.policy.health_check {
            HealthCheckPolicy::Disabled => None,
            HealthCheckPolicy::Http(policy) => Some(policy.clone()),
        },
        retry: service.policy.retry,
        passive_health: service.policy.passive_health,
        https_enabled: route.certificate_ref.is_some(),
        letsencrypt_enabled: route.certificate_resolver_id.is_some(),
        redirect_http_to_https: route.redirect_http_to_https,
        enabled: route.enabled,
    })
}

fn required_json_string(body: &str, field: &str) -> Result<String, AppError> {
    json_string_field(body, field).ok_or_else(|| malformed_json_field(field))
}

fn required_json_string_array(body: &str, field: &str) -> Result<Vec<String>, AppError> {
    json_string_array_field(body, field).ok_or_else(|| malformed_json_field(field))
}

fn required_json_bool(body: &str, field: &str) -> Result<bool, AppError> {
    json_bool_field(body, field).ok_or_else(|| malformed_json_field(field))
}

fn malformed_json_field(field: &str) -> AppError {
    AppError::new(
        ErrorCode::HttpMalformedRequest,
        format!("request body requires JSON field `{field}`"),
    )
}

pub fn validate_config(snapshot: &ConfigSnapshot) -> ValidationReport {
    ConfigValidator::default().validate_snapshot(snapshot)
}

pub fn validate_config_source(source: &str) -> Vec<ValidationError> {
    match parse_valid_config_source(source, ConfigRevisionId::new("candidate")) {
        Ok(_) => Vec::new(),
        Err(errors) => errors,
    }
}

pub fn parse_valid_config_source(
    source: &str,
    revision_id: ConfigRevisionId,
) -> Result<ConfigSnapshot, Vec<ValidationError>> {
    let parsed = parse_mvp_config(source, revision_id)
        .map_err(|error| vec![ValidationError::new(error.code, error.message)])?;
    let report = validate_config(&parsed.snapshot);
    if report.is_valid() {
        Ok(parsed.snapshot)
    } else {
        Err(report.errors)
    }
}

fn validation_errors_to_app_error(errors: Vec<ValidationError>) -> AppError {
    let first = errors.into_iter().next().unwrap_or_else(|| {
        ValidationError::new(ErrorCode::InternalBug, "missing validation error")
    });
    AppError::new(first.code, first.message)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyResponse {
    pub revision_id: String,
    pub commands_sent: usize,
    pub restart_required: bool,
}

pub fn apply_config_source<R, A, C>(
    lifecycle: &mut ConfigLifecycle<R, A>,
    source: &str,
    client: &mut C,
) -> Result<ApplyResponse, AppError>
where
    R: ConfigRevisionRepository,
    A: AuditSink,
    C: CoreCommandClient + ?Sized,
{
    let current = lifecycle.revisions.current()?.ok_or_else(|| {
        AppError::new(
            ErrorCode::ConfigRevisionNotFound,
            "current revision missing",
        )
    })?;
    let next_revision_id =
        ConfigRevisionId::new(format!("{}-config-apply", current.revision.id.as_str()));
    let next = parse_valid_config_source(source, next_revision_id)
        .map_err(validation_errors_to_app_error)?;

    let result = lifecycle.apply_with_core(next, client)?;
    Ok(ApplyResponse {
        revision_id: result.revision_id.as_str().to_string(),
        commands_sent: result.plan.commands.len(),
        restart_required: result.plan.restart_required,
    })
}

pub fn create_proxy_host_and_apply<R, A, C>(
    lifecycle: &mut ConfigLifecycle<R, A>,
    request: ProxyHostRequest,
    client: &mut C,
) -> Result<ApplyResponse, AppError>
where
    R: ConfigRevisionRepository,
    A: AuditSink,
    C: CoreCommandClient + ?Sized,
{
    let current = lifecycle
        .revisions
        .current()?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::ConfigRevisionNotFound,
                "current revision missing",
            )
        })?
        .snapshot;
    let proxy_host = proxy_host_from_request(request);
    let mut next = add_proxy_host(&current, &proxy_host);
    next.revision_id = ConfigRevisionId::new(format!(
        "{}-proxy-host-{}",
        current.revision_id.as_str(),
        proxy_host.id.as_str()
    ));
    let report = validate_config(&next);
    if !report.is_valid() {
        let first = &report.errors[0];
        return Err(AppError::new(first.code, first.message.clone()));
    }

    let result = lifecycle.apply_with_core(next, client)?;
    Ok(ApplyResponse {
        revision_id: result.revision_id.as_str().to_string(),
        commands_sent: result.plan.commands.len(),
        restart_required: result.plan.restart_required,
    })
}

pub fn update_proxy_host_and_apply<R, A, C>(
    lifecycle: &mut ConfigLifecycle<R, A>,
    proxy_host_id: ProxyHostId,
    request: ProxyHostRequest,
    client: &mut C,
) -> Result<ApplyResponse, AppError>
where
    R: ConfigRevisionRepository,
    A: AuditSink,
    C: CoreCommandClient + ?Sized,
{
    if request.id != proxy_host_id.as_str() {
        return Err(AppError::new(
            ErrorCode::HttpMalformedRequest,
            "path proxy host id must match request body id",
        ));
    }

    let current = lifecycle
        .revisions
        .current()?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::ConfigRevisionNotFound,
                "current revision missing",
            )
        })?
        .snapshot;
    ensure_proxy_host_exists(&current, &proxy_host_id)?;
    let proxy_host = proxy_host_from_request(request);
    let mut next = update_proxy_host(&current, &proxy_host);
    next.revision_id = ConfigRevisionId::new(format!(
        "{}-update-proxy-host-{}",
        current.revision_id.as_str(),
        proxy_host_id.as_str()
    ));
    let report = validate_config(&next);
    if !report.is_valid() {
        let first = &report.errors[0];
        return Err(AppError::new(first.code, first.message.clone()));
    }

    let result = lifecycle.apply_with_core(next, client)?;
    Ok(ApplyResponse {
        revision_id: result.revision_id.as_str().to_string(),
        commands_sent: result.plan.commands.len(),
        restart_required: result.plan.restart_required,
    })
}

pub fn delete_proxy_host_and_apply<R, A, C>(
    lifecycle: &mut ConfigLifecycle<R, A>,
    proxy_host_id: ProxyHostId,
    client: &mut C,
) -> Result<ApplyResponse, AppError>
where
    R: ConfigRevisionRepository,
    A: AuditSink,
    C: CoreCommandClient + ?Sized,
{
    let current = lifecycle
        .revisions
        .current()?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::ConfigRevisionNotFound,
                "current revision missing",
            )
        })?
        .snapshot;
    ensure_proxy_host_exists(&current, &proxy_host_id)?;
    let mut next = remove_proxy_host(&current, &proxy_host_id);
    next.revision_id = ConfigRevisionId::new(format!(
        "{}-delete-proxy-host-{}",
        current.revision_id.as_str(),
        proxy_host_id.as_str()
    ));
    let report = validate_config(&next);
    if !report.is_valid() {
        let first = &report.errors[0];
        return Err(AppError::new(first.code, first.message.clone()));
    }

    let result = lifecycle.apply_with_core(next, client)?;
    Ok(ApplyResponse {
        revision_id: result.revision_id.as_str().to_string(),
        commands_sent: result.plan.commands.len(),
        restart_required: result.plan.restart_required,
    })
}

fn ensure_proxy_host_exists(
    snapshot: &ConfigSnapshot,
    proxy_host_id: &ProxyHostId,
) -> Result<(), AppError> {
    let generated = format!("proxy-host-{}", proxy_host_id.as_str());
    if snapshot
        .routes
        .iter()
        .any(|route| route.id.as_str() == generated)
    {
        Ok(())
    } else {
        Err(AppError::new(
            ErrorCode::AdminRouteNotFound,
            format!("proxy host not found: {}", proxy_host_id.as_str()),
        ))
    }
}

pub fn rollback<R, A, C>(
    revision_id: ConfigRevisionId,
    lifecycle: &mut ConfigLifecycle<R, A>,
    client: &mut C,
) -> Result<ApplyResponse, AppError>
where
    R: ConfigRevisionRepository,
    A: AuditSink,
    C: CoreCommandClient + ?Sized,
{
    let result = lifecycle.rollback_with_core(&revision_id, client)?;
    Ok(ApplyResponse {
        revision_id: result.revision_id.as_str().to_string(),
        commands_sent: result.plan.commands.len(),
        restart_required: result.plan.restart_required,
    })
}

pub fn proxy_host_id_from_delete_path(path: &str) -> Result<ProxyHostId, AppError> {
    proxy_host_id_from_member_path(path)
}

pub fn proxy_host_id_from_update_path(path: &str) -> Result<ProxyHostId, AppError> {
    proxy_host_id_from_member_path(path)
}

pub fn proxy_host_id_from_get_path(path: &str) -> Result<ProxyHostId, AppError> {
    proxy_host_id_from_member_path(path)
}

fn proxy_host_id_from_member_path(path: &str) -> Result<ProxyHostId, AppError> {
    let Some(id) = path.strip_prefix("/api/v1/proxy-hosts/") else {
        return Err(AppError::new(
            ErrorCode::AdminRouteNotFound,
            "admin http route not found",
        ));
    };
    if id.is_empty() || id.contains('/') {
        return Err(AppError::new(
            ErrorCode::AdminRouteNotFound,
            "proxy host route requires a single id segment",
        ));
    }
    Ok(ProxyHostId::new(id.to_string()))
}

pub fn rollback_request_revision_id_from_json(body: &str) -> Result<ConfigRevisionId, AppError> {
    Ok(ConfigRevisionId::new(required_json_string(
        body,
        "revision_id",
    )?))
}

fn certificate_ref_from_issue_path(path: &str) -> Result<CertificateRef, AppError> {
    certificate_ref_from_mutation_path(path, "/issue")
}

fn certificate_ref_from_renew_path(path: &str) -> Result<CertificateRef, AppError> {
    certificate_ref_from_mutation_path(path, "/renew")
}

fn certificate_ref_from_import_path(path: &str) -> Result<CertificateRef, AppError> {
    certificate_ref_from_mutation_path(path, "/import")
}

fn certificate_ref_from_mutation_path(
    path: &str,
    suffix: &str,
) -> Result<CertificateRef, AppError> {
    let Some(rest) = path.strip_prefix("/api/v1/certificates/") else {
        return Err(AppError::new(
            ErrorCode::AdminRouteNotFound,
            "admin http route not found",
        ));
    };
    let Some(id) = rest.strip_suffix(suffix) else {
        return Err(AppError::new(
            ErrorCode::AdminRouteNotFound,
            "admin http route not found",
        ));
    };
    if id.is_empty() || id.contains('/') {
        return Err(AppError::new(
            ErrorCode::AdminRouteNotFound,
            "certificate route requires a single id segment",
        ));
    }
    Ok(CertificateRef::new(id.to_string()))
}

pub fn handle_health_http(
    request: &AdminHttpRequest,
    snapshot: &ConfigSnapshot,
) -> AdminHttpResponse {
    if request.method != AdminHttpMethod::Get || request.path != "/api/v1/health" {
        return error_response(
            404,
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found"),
            &request.request_id,
        );
    }

    AdminHttpResponse::json(200, health_response_json(&health_response(snapshot)))
}

/// Renders the unauthenticated operational probe payload without exposing
/// routes, revisions, configuration, or upstream details.
pub fn handle_operational_probe_http(
    request: &AdminHttpRequest,
    lifecycle: OperationalLifecycle,
    has_active_snapshot: bool,
    has_listener: bool,
    has_command_path: bool,
) -> AdminHttpResponse {
    let status = match (request.method, request.path.as_str()) {
        (AdminHttpMethod::Get, "/api/v1/health/live") => lifecycle.liveness(),
        (AdminHttpMethod::Get, "/api/v1/health/ready") => {
            lifecycle.readiness(has_active_snapshot, has_listener, has_command_path)
        }
        _ => {
            return error_response(
                404,
                AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found"),
                &request.request_id,
            );
        }
    };
    let (status_code, body) = match status {
        ProbeStatus::Live => (200, r#"{"status":"live"}"#),
        ProbeStatus::Ready => (200, r#"{"status":"ready"}"#),
        ProbeStatus::NotLive => (503, r#"{"status":"not_live"}"#),
        ProbeStatus::NotReady => (503, r#"{"status":"not_ready"}"#),
    };
    AdminHttpResponse::json(status_code, body.to_string())
}

pub fn handle_upstream_health_http(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    reader: &dyn HealthStatusReader,
    runtime_reader: Option<&dyn RuntimeUpstreamStatusReader>,
) -> AdminHttpResponse {
    if request.method != AdminHttpMethod::Get || request.path != "/api/v1/upstream-health" {
        return error_response(
            404,
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found"),
            &request.request_id,
        );
    }
    if let Err(error) = require_session(sessions, request.session_id.as_deref()) {
        return error_response(401, error, &request.request_id);
    }
    match reader.read_health_status() {
        Ok(snapshot) => {
            let runtime = runtime_reader.and_then(|reader| reader.read_runtime_status().ok());
            AdminHttpResponse::json(
                200,
                upstream_health_status_response_json(&upstream_health_status_response(
                    snapshot, runtime,
                )),
            )
        }
        Err(error) => error_response(http_status_for_error(&error), error, &request.request_id),
    }
}

pub fn handle_metrics_http(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    reader: &dyn MetricSnapshotReaderPort,
) -> AdminHttpResponse {
    if request.method != AdminHttpMethod::Get {
        return error_response(
            404,
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found"),
            &request.request_id,
        );
    }
    if request.path != "/api/v1/metrics" {
        let error = if request.path.starts_with("/api/v1/metrics?") {
            AppError::new(
                ErrorCode::HttpMalformedRequest,
                "metrics query parameters are not supported",
            )
        } else {
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found")
        };
        return error_response(
            if error.code == ErrorCode::HttpMalformedRequest {
                400
            } else {
                404
            },
            error,
            &request.request_id,
        );
    }
    if let Err(error) = require_session(sessions, request.session_id.as_deref()) {
        return error_response(401, error, &request.request_id);
    }
    match reader.read_metric_snapshot() {
        Ok(snapshot) => AdminHttpResponse::json(200, metrics_summary_json(&snapshot)),
        Err(error) => error_response(http_status_for_error(&error), error, &request.request_id),
    }
}

pub fn handle_audit_query_http<R>(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    reader: &R,
) -> AdminHttpResponse
where
    R: AuditLedgerReader + ?Sized,
{
    if request.method != AdminHttpMethod::Get
        || !(request.path == "/api/v1/audit" || request.path.starts_with("/api/v1/audit?"))
    {
        return error_response(
            404,
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found"),
            &request.request_id,
        );
    }
    if let Err(error) = require_session(sessions, request.session_id.as_deref()) {
        return error_response(401, error, &request.request_id);
    }
    let query = match parse_audit_query(&request.path) {
        Ok(query) => query,
        Err(error) => return error_response(400, error, &request.request_id),
    };
    match query_audit(reader, true, &query) {
        Ok(page) => AdminHttpResponse::json(200, audit_page_json(&page)),
        Err(error) => error_response(http_status_for_error(&error), error, &request.request_id),
    }
}

fn parse_audit_query(path: &str) -> Result<AuditQuery, AppError> {
    let (_, raw_query) = path.split_once('?').unwrap_or((path, ""));
    let mut values = BTreeMap::new();
    if !raw_query.is_empty() {
        for pair in raw_query.split('&') {
            let (key, value) = pair.split_once('=').ok_or_else(audit_query_invalid)?;
            if key.is_empty()
                || value.is_empty()
                || value.contains('%')
                || !matches!(
                    key,
                    "action" | "outcome" | "target_kind" | "from" | "to" | "limit" | "cursor"
                )
                || values.insert(key, value).is_some()
            {
                return Err(audit_query_invalid());
            }
        }
    }
    let action = values
        .get("action")
        .map(|value| parse_audit_action(value))
        .transpose()?;
    let outcome = values
        .get("outcome")
        .map(|value| parse_audit_outcome(value))
        .transpose()?;
    let target_kind = values
        .get("target_kind")
        .map(|value| parse_audit_target_kind(value))
        .transpose()?;
    let from = parse_optional_u64(&values, "from")?;
    let to = parse_optional_u64(&values, "to")?;
    let limit = values
        .get("limit")
        .map(|value| value.parse::<u16>().map_err(|_| audit_query_invalid()))
        .transpose()?
        .unwrap_or(edge_domain::AUDIT_QUERY_DEFAULT_LIMIT);
    let mut query = AuditQuery::new(action, outcome, target_kind, from, to, limit)
        .map_err(|_| audit_query_invalid())?;
    if let Some(cursor) = values.get("cursor") {
        query = query.with_cursor(decode_audit_cursor(cursor)?);
    }
    Ok(query)
}

fn parse_optional_u64(values: &BTreeMap<&str, &str>, key: &str) -> Result<Option<u64>, AppError> {
    values
        .get(key)
        .map(|value| value.parse::<u64>().map_err(|_| audit_query_invalid()))
        .transpose()
}

fn parse_audit_action(value: &str) -> Result<AuditAction, AppError> {
    match value {
        "config.apply" => Ok(AuditAction::ConfigApply),
        "config.rollback" => Ok(AuditAction::ConfigRollback),
        "proxy_host.create" => Ok(AuditAction::ProxyHostCreate),
        "proxy_host.update" => Ok(AuditAction::ProxyHostUpdate),
        "proxy_host.delete" => Ok(AuditAction::ProxyHostDelete),
        "certificate.issue" => Ok(AuditAction::CertificateIssue),
        "certificate.renew" => Ok(AuditAction::CertificateRenew),
        "certificate.import" => Ok(AuditAction::CertificateImport),
        "certificate.install" => Ok(AuditAction::CertificateInstall),
        "trust_bundle.import" => Ok(AuditAction::TrustBundleImport),
        "trust_bundle.delete" => Ok(AuditAction::TrustBundleDelete),
        "admin.setup" => Ok(AuditAction::AdminSetup),
        "admin.login.success" => Ok(AuditAction::AdminLoginSuccess),
        "admin.logout" => Ok(AuditAction::AdminLogout),
        "admin.lockout" => Ok(AuditAction::AdminLockout),
        "admin.auth.failure_sampled" => Ok(AuditAction::AdminAuthFailureSampled),
        "maintenance.restore_imported" => Ok(AuditAction::MaintenanceRestoreImported),
        "system.trailing_recovery" => Ok(AuditAction::SystemTrailingRecovery),
        "audit.retention.checkpoint" => Ok(AuditAction::RetentionCheckpoint),
        _ => Err(audit_query_invalid()),
    }
}

fn parse_audit_outcome(value: &str) -> Result<AuditOutcome, AppError> {
    match value {
        "succeeded" => Ok(AuditOutcome::Succeeded),
        "failed" => Ok(AuditOutcome::Failed),
        "observed" => Ok(AuditOutcome::Observed),
        "reconciled_committed" => Ok(AuditOutcome::ReconciledCommitted),
        "reconciled_not_committed" => Ok(AuditOutcome::ReconciledNotCommitted),
        "reconciliation_unknown" => Ok(AuditOutcome::ReconciliationUnknown),
        _ => Err(audit_query_invalid()),
    }
}

fn parse_audit_target_kind(value: &str) -> Result<AuditTargetKind, AppError> {
    match value {
        "config_revision" => Ok(AuditTargetKind::ConfigRevision),
        "proxy_host" => Ok(AuditTargetKind::ProxyHost),
        "certificate" => Ok(AuditTargetKind::Certificate),
        "trust_bundle" => Ok(AuditTargetKind::TrustBundle),
        "admin_account" => Ok(AuditTargetKind::AdminAccount),
        "restore" => Ok(AuditTargetKind::Restore),
        "audit_ledger" => Ok(AuditTargetKind::AuditLedger),
        _ => Err(audit_query_invalid()),
    }
}

fn audit_query_invalid() -> AppError {
    AppError::new(
        ErrorCode::HttpMalformedRequest,
        "audit query does not match the supported contract",
    )
}

fn encode_audit_cursor(cursor: AuditCursor) -> String {
    format!(
        "v1.{:016x}{:016x}",
        cursor.ledger_generation, cursor.before_sequence
    )
}

fn decode_audit_cursor(value: &str) -> Result<AuditCursor, AppError> {
    let encoded = value.strip_prefix("v1.").ok_or_else(audit_cursor_invalid)?;
    if encoded.len() != 32 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(audit_cursor_invalid());
    }
    Ok(AuditCursor {
        ledger_generation: u64::from_str_radix(&encoded[..16], 16)
            .map_err(|_| audit_cursor_invalid())?,
        before_sequence: u64::from_str_radix(&encoded[16..], 16)
            .map_err(|_| audit_cursor_invalid())?,
    })
}

fn audit_cursor_invalid() -> AppError {
    AppError::new(ErrorCode::AuditCursorInvalid, "audit cursor is invalid")
}

fn audit_admission_state_name(state: AuditAdmissionState) -> &'static str {
    match state {
        AuditAdmissionState::Starting => "starting",
        AuditAdmissionState::Verifying => "verifying",
        AuditAdmissionState::Reconciling => "reconciling",
        AuditAdmissionState::Healthy => "healthy",
        AuditAdmissionState::Degraded => "degraded",
        AuditAdmissionState::FailedClosed => "failed_closed",
    }
}

fn audit_page_json(page: &AuditPage) -> String {
    let records = page
        .records
        .iter()
        .map(|view| {
            let record = &view.record;
            serde_json::json!({
                "sequence": view.sequence,
                "record_kind": record.record_kind.as_str(),
                "operation_id": record.context.operation_id.as_str(),
                "request_id": record.context.request_id.as_str(),
                "actor_kind": record.context.actor_kind.as_str(),
                "received_at_epoch_seconds": record.context.received_at_epoch_seconds,
                "action": record.action.as_str(),
                "target_kind": record.target_kind.as_str(),
                "target_id": record.target_id.as_str(),
                "before_revision": record.before_revision.as_ref().map(|value| value.as_str()),
                "after_revision": record.after_revision.as_ref().map(|value| value.as_str()),
                "outcome": record.outcome.map(|value| value.as_str()),
                "error_code": record.error_code.as_ref().map(|value| value.as_str()),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "schema_version": 1,
        "ledger": {
            "generation": page.head.generation,
            "sequence": page.head.sequence,
            "admission_state": audit_admission_state_name(page.admission_state),
        },
        "records": records,
        "next_cursor": page.next_cursor.map(encode_audit_cursor),
    })
    .to_string()
}

fn metrics_summary_json(snapshot: &MetricSnapshot) -> String {
    let mut counters = Vec::new();
    let mut gauges = Vec::new();
    let mut histograms = Vec::new();
    for series in &snapshot.series {
        let item = metric_series_json(series);
        match &series.value {
            MetricSeriesValue::Counter(_) if counters.len() < 500 => counters.push(item),
            MetricSeriesValue::Gauge(_) if gauges.len() < 500 => gauges.push(item),
            MetricSeriesValue::Histogram(_) if histograms.len() < 500 => histograms.push(item),
            _ => {}
        }
    }
    let dropped = snapshot
        .dropped
        .iter()
        .map(|(reason, count)| {
            let reason = match reason {
                edge_application::MetricDropReason::SeriesLimit => "series_limit",
                edge_application::MetricDropReason::ResponseBudget => "response_budget",
            };
            format!("\"{reason}\":{count}")
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"ready\":{},\"desired_generation\":{},\"applied_generation\":{},\"estimated_encoded_bytes\":{},\"dropped\":{{{dropped}}},\"counters\":[{}],\"gauges\":[{}],\"histograms\":[{}]}}", snapshot.ready, snapshot.desired_generation, snapshot.applied_generation, snapshot.estimated_encoded_bytes, counters.join(","), gauges.join(","), histograms.join(","))
}

fn metric_series_json(series: &edge_application::MetricSeries) -> String {
    let labels = series
        .key
        .labels
        .iter()
        .map(|(key, value)| format!("\"{}\":\"{}\"", json_escape(key), json_escape(value)))
        .collect::<Vec<_>>()
        .join(",");
    let value = match &series.value {
        MetricSeriesValue::Counter(value) => value.to_string(),
        MetricSeriesValue::Gauge(value) => value.to_string(),
        MetricSeriesValue::Histogram(value) => format!(
            "{{\"count\":{},\"sum_ms\":{},\"cumulative_buckets\":[{}]}}",
            value.count,
            value.sum_ms,
            value
                .cumulative_buckets
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ),
    };
    format!(
        "{{\"name\":\"{}\",\"labels\":{{{labels}}},\"value\":{value}}}",
        series.key.descriptor.definition().name
    )
}

pub fn handle_certificate_list_http<S>(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    certificates: &S,
    now_epoch_seconds: u64,
    renewal_window_seconds: u64,
) -> AdminHttpResponse
where
    S: CertificateStore + ?Sized,
{
    if request.method != AdminHttpMethod::Get || request.path != "/api/v1/certificates" {
        return error_response(
            404,
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found"),
            &request.request_id,
        );
    }
    if let Err(error) = require_session(sessions, request.session_id.as_deref()) {
        return error_response(401, error, &request.request_id);
    }

    match certificates.list_certificates() {
        Ok(certificates) => {
            let statuses =
                certificate_statuses(&certificates, now_epoch_seconds, renewal_window_seconds);
            AdminHttpResponse::json(200, certificate_list_response_json(&statuses))
        }
        Err(error) => error_response(500, error, &request.request_id),
    }
}

pub fn handle_certificate_get_http<S>(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    certificates: &S,
    now_epoch_seconds: u64,
    renewal_window_seconds: u64,
) -> AdminHttpResponse
where
    S: CertificateStore + ?Sized,
{
    if request.method != AdminHttpMethod::Get {
        return error_response(
            404,
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found"),
            &request.request_id,
        );
    }
    if let Err(error) = require_session(sessions, request.session_id.as_deref()) {
        return error_response(401, error, &request.request_id);
    }

    let certificate_ref = match certificate_ref_from_get_path(&request.path) {
        Ok(certificate_ref) => certificate_ref,
        Err(error) => {
            return error_response(http_status_for_error(&error), error, &request.request_id)
        }
    };
    match certificates.load_certificate(&certificate_ref) {
        Ok(Some(certificate)) => AdminHttpResponse::json(
            200,
            certificate_status_json(&certificate_status(
                &certificate,
                now_epoch_seconds,
                renewal_window_seconds,
            )),
        ),
        Ok(None) => error_response(
            404,
            AppError::new(
                ErrorCode::CertificateNotFound,
                format!("certificate not found: {}", certificate_ref.as_str()),
            ),
            &request.request_id,
        ),
        Err(error) => error_response(500, error, &request.request_id),
    }
}

pub fn handle_certificate_import_http<V, S, A, K>(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    revision_id: &ConfigRevisionId,
    validator: &mut V,
    certificates: &mut S,
    audit: &mut A,
    client: &mut K,
) -> AdminHttpResponse
where
    V: CertificateMaterialValidator + ?Sized,
    S: CertificateStore + ?Sized,
    A: AuditSink + ?Sized,
    K: CoreCommandClient + ?Sized,
{
    if request.method != AdminHttpMethod::Post {
        return error_response(
            404,
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found"),
            &request.request_id,
        );
    }
    if let Err(error) = require_session(sessions, request.session_id.as_deref()) {
        return error_response(401, error, &request.request_id);
    }
    if let Err(error) = require_csrf(
        sessions,
        request.session_id.as_deref().unwrap_or_default(),
        request.csrf_token.as_deref(),
    ) {
        return error_response(403, error, &request.request_id);
    }

    let certificate_ref = match certificate_ref_from_import_path(&request.path) {
        Ok(certificate_ref) => certificate_ref,
        Err(error) => {
            return error_response(http_status_for_error(&error), error, &request.request_id)
        }
    };
    let import_request = match manual_certificate_import_request_from_json(
        &request.body,
        certificate_ref,
        &request.request_id,
        revision_id,
    ) {
        Ok(import_request) => import_request,
        Err(error) => return error_response(400, error, &request.request_id),
    };

    match import_manual_certificate_and_install(
        import_request,
        validator,
        certificates,
        audit,
        client,
    ) {
        Ok(outcome) => AdminHttpResponse::json(
            200,
            certificate_import_outcome_json(&outcome, &request.request_id),
        ),
        Err(failure) => error_response(
            http_status_for_error(&failure.error),
            failure.error,
            &request.request_id,
        ),
    }
}

pub fn handle_certificate_issue_http<C, S, A, K>(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    issuer: &mut CertificateIssuer<C, S, A>,
    client: &mut K,
) -> AdminHttpResponse
where
    C: AcmeClient,
    S: CertificateStore,
    A: AuditSink,
    K: CoreCommandClient + ?Sized,
{
    if request.method != AdminHttpMethod::Post {
        return error_response(
            404,
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found"),
            &request.request_id,
        );
    }
    if let Err(error) = require_session(sessions, request.session_id.as_deref()) {
        return error_response(401, error, &request.request_id);
    }
    if let Err(error) = require_csrf(
        sessions,
        request.session_id.as_deref().unwrap_or_default(),
        request.csrf_token.as_deref(),
    ) {
        return error_response(403, error, &request.request_id);
    }

    let certificate_ref = match certificate_ref_from_issue_path(&request.path) {
        Ok(certificate_ref) => certificate_ref,
        Err(error) => {
            return error_response(http_status_for_error(&error), error, &request.request_id)
        }
    };
    let issue_request = match certificate_issue_request_from_json(&request.body) {
        Ok(issue_request) => issue_request,
        Err(error) => return error_response(400, error, &request.request_id),
    };
    match issue_certificate_for_ref_and_install(issuer, certificate_ref, issue_request, client) {
        Ok(outcome) => AdminHttpResponse::json(
            200,
            certificate_issue_outcome_json(&outcome, &request.request_id),
        ),
        Err(error) => error_response(http_status_for_error(&error), error, &request.request_id),
    }
}

pub fn handle_certificate_issue_http_with_http01<C, S, A, K, T, P>(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    issuer: &mut CertificateIssuer<C, S, A>,
    challenges: &mut T,
    probe: &mut P,
    client: &mut K,
) -> AdminHttpResponse
where
    C: AcmeClient,
    S: CertificateStore,
    A: AuditSink,
    K: CoreCommandClient + ?Sized,
    T: Http01ChallengeStore + ?Sized,
    P: Http01ChallengeProbe + ?Sized,
{
    if request.method != AdminHttpMethod::Post {
        return error_response(
            404,
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found"),
            &request.request_id,
        );
    }
    if let Err(error) = require_session(sessions, request.session_id.as_deref()) {
        return error_response(401, error, &request.request_id);
    }
    if let Err(error) = require_csrf(
        sessions,
        request.session_id.as_deref().unwrap_or_default(),
        request.csrf_token.as_deref(),
    ) {
        return error_response(403, error, &request.request_id);
    }

    let certificate_ref = match certificate_ref_from_issue_path(&request.path) {
        Ok(certificate_ref) => certificate_ref,
        Err(error) => {
            return error_response(http_status_for_error(&error), error, &request.request_id)
        }
    };
    let issue_request = match certificate_issue_request_from_json(&request.body) {
        Ok(issue_request) => issue_request,
        Err(error) => return error_response(400, error, &request.request_id),
    };
    match issue_certificate_for_ref_with_http01_and_install(
        issuer,
        challenges,
        probe,
        certificate_ref,
        issue_request,
        client,
    ) {
        Ok(outcome) => AdminHttpResponse::json(
            200,
            certificate_issue_outcome_json(&outcome, &request.request_id),
        ),
        Err(error) => error_response(http_status_for_error(&error), error, &request.request_id),
    }
}

pub fn handle_certificate_renew_http<C, S, A, K>(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    issuer: &mut CertificateIssuer<C, S, A>,
    client: &mut K,
) -> AdminHttpResponse
where
    C: AcmeClient,
    S: CertificateStore,
    A: AuditSink,
    K: CoreCommandClient + ?Sized,
{
    if request.method != AdminHttpMethod::Post {
        return error_response(
            404,
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found"),
            &request.request_id,
        );
    }
    if let Err(error) = require_session(sessions, request.session_id.as_deref()) {
        return error_response(401, error, &request.request_id);
    }
    if let Err(error) = require_csrf(
        sessions,
        request.session_id.as_deref().unwrap_or_default(),
        request.csrf_token.as_deref(),
    ) {
        return error_response(403, error, &request.request_id);
    }

    let certificate_ref = match certificate_ref_from_renew_path(&request.path) {
        Ok(certificate_ref) => certificate_ref,
        Err(error) => {
            return error_response(http_status_for_error(&error), error, &request.request_id)
        }
    };
    let renew_request = match certificate_renew_request_from_json(&request.body) {
        Ok(renew_request) => renew_request,
        Err(error) => return error_response(400, error, &request.request_id),
    };
    match renew_certificate_for_ref_and_install(issuer, certificate_ref, renew_request, client) {
        Ok(outcome) => AdminHttpResponse::json(
            200,
            certificate_issue_outcome_json(&outcome, &request.request_id),
        ),
        Err(error) => error_response(http_status_for_error(&error), error, &request.request_id),
    }
}

pub fn handle_access_logs_http(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    events: &[AccessLogEvent],
) -> AdminHttpResponse {
    if request.method != AdminHttpMethod::Get || request.path != "/api/v1/logs/access" {
        return error_response(
            404,
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found"),
            &request.request_id,
        );
    }
    if let Err(error) = require_session(sessions, request.session_id.as_deref()) {
        return error_response(401, error, &request.request_id);
    }

    AdminHttpResponse::json(200, access_logs_response_json(events))
}

pub fn handle_error_logs_http(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    events: &[RecentErrorEvent],
) -> AdminHttpResponse {
    if request.method != AdminHttpMethod::Get || request.path != "/api/v1/logs/errors" {
        return error_response(
            404,
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found"),
            &request.request_id,
        );
    }
    if let Err(error) = require_session(sessions, request.session_id.as_deref()) {
        return error_response(401, error, &request.request_id);
    }

    AdminHttpResponse::json(200, error_logs_response_json(events))
}

fn certificate_statuses(
    certificates: &[edge_ports::StoredCertificate],
    now_epoch_seconds: u64,
    renewal_window_seconds: u64,
) -> Vec<CertificateStatus> {
    let mut statuses = certificates
        .iter()
        .map(|certificate| {
            certificate_status(certificate, now_epoch_seconds, renewal_window_seconds)
        })
        .collect::<Vec<_>>();
    statuses.sort_by(|left, right| left.certificate_ref.cmp(&right.certificate_ref));
    statuses
}

fn certificate_ref_from_get_path(path: &str) -> Result<CertificateRef, AppError> {
    let Some(id) = path.strip_prefix("/api/v1/certificates/") else {
        return Err(AppError::new(
            ErrorCode::AdminRouteNotFound,
            "admin http route not found",
        ));
    };
    if id.is_empty() || id.contains('/') {
        return Err(AppError::new(
            ErrorCode::AdminRouteNotFound,
            "certificate route requires a single id segment",
        ));
    }
    Ok(CertificateRef::new(id.to_string()))
}

pub fn handle_config_get_http(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    snapshot: &ConfigSnapshot,
) -> AdminHttpResponse {
    if request.method != AdminHttpMethod::Get || request.path != "/api/v1/config" {
        return error_response(
            404,
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found"),
            &request.request_id,
        );
    }
    if let Err(error) = require_session(sessions, request.session_id.as_deref()) {
        return error_response(401, error, &request.request_id);
    }

    AdminHttpResponse::json(200, config_response_json(snapshot))
}

pub fn handle_config_validate_http(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
) -> AdminHttpResponse {
    if request.method != AdminHttpMethod::Post || request.path != "/api/v1/config/validate" {
        return error_response(
            404,
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found"),
            &request.request_id,
        );
    }
    if let Err(error) = require_session(sessions, request.session_id.as_deref()) {
        return error_response(401, error, &request.request_id);
    }

    AdminHttpResponse::json(
        200,
        config_validation_response_json(&validate_config_source(&request.body)),
    )
}

pub fn handle_config_diff_http(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    current: &ConfigSnapshot,
) -> AdminHttpResponse {
    if request.method != AdminHttpMethod::Post || request.path != "/api/v1/config/diff" {
        return error_response(
            404,
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found"),
            &request.request_id,
        );
    }
    if let Err(error) = require_session(sessions, request.session_id.as_deref()) {
        return error_response(401, error, &request.request_id);
    }

    let candidate_revision_id =
        ConfigRevisionId::new(format!("{}-config-diff", current.revision_id.as_str()));
    match parse_valid_config_source(&request.body, candidate_revision_id) {
        Ok(next) => {
            let diff = diff_config(Some(current), &next);
            AdminHttpResponse::json(200, config_diff_response_json(Some(&diff), &[]))
        }
        Err(errors) => AdminHttpResponse::json(200, config_diff_response_json(None, &errors)),
    }
}

pub fn handle_config_apply_http<R, A, C>(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    lifecycle: &mut ConfigLifecycle<R, A>,
    client: &mut C,
) -> AdminHttpResponse
where
    R: ConfigRevisionRepository,
    A: AuditSink,
    C: CoreCommandClient + ?Sized,
{
    if request.method != AdminHttpMethod::Post || request.path != "/api/v1/config/apply" {
        return error_response(
            404,
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found"),
            &request.request_id,
        );
    }
    if let Err(error) = require_session(sessions, request.session_id.as_deref()) {
        return error_response(401, error, &request.request_id);
    }
    if let Err(error) = require_csrf(
        sessions,
        request.session_id.as_deref().unwrap_or_default(),
        request.csrf_token.as_deref(),
    ) {
        return error_response(403, error, &request.request_id);
    }

    match apply_config_source(lifecycle, &request.body, client) {
        Ok(response) => AdminHttpResponse::json(200, apply_response_json(&response)),
        Err(error) => error_response(http_status_for_error(&error), error, &request.request_id),
    }
}

pub fn handle_proxy_host_list_http(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    snapshot: &ConfigSnapshot,
) -> AdminHttpResponse {
    if request.method != AdminHttpMethod::Get || request.path != "/api/v1/proxy-hosts" {
        return error_response(
            404,
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found"),
            &request.request_id,
        );
    }
    if let Err(error) = require_session(sessions, request.session_id.as_deref()) {
        return error_response(401, error, &request.request_id);
    }

    AdminHttpResponse::json(
        200,
        proxy_host_list_response_json(&proxy_hosts_from_snapshot(snapshot)),
    )
}

pub fn handle_proxy_host_get_http(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    snapshot: &ConfigSnapshot,
) -> AdminHttpResponse {
    if request.method != AdminHttpMethod::Get {
        return error_response(
            404,
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found"),
            &request.request_id,
        );
    }
    if let Err(error) = require_session(sessions, request.session_id.as_deref()) {
        return error_response(401, error, &request.request_id);
    }

    let proxy_host_id = match proxy_host_id_from_get_path(&request.path) {
        Ok(proxy_host_id) => proxy_host_id,
        Err(error) => {
            return error_response(http_status_for_error(&error), error, &request.request_id)
        }
    };
    match proxy_host_from_snapshot(snapshot, &proxy_host_id) {
        Ok(proxy_host) => AdminHttpResponse::json(200, proxy_host_response_json(&proxy_host)),
        Err(error) => error_response(http_status_for_error(&error), error, &request.request_id),
    }
}

pub fn handle_proxy_host_create_http<R, A, C>(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    lifecycle: &mut ConfigLifecycle<R, A>,
    client: &mut C,
) -> AdminHttpResponse
where
    R: ConfigRevisionRepository,
    A: AuditSink,
    C: CoreCommandClient + ?Sized,
{
    if request.method != AdminHttpMethod::Post || request.path != "/api/v1/proxy-hosts" {
        return error_response(
            404,
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found"),
            &request.request_id,
        );
    }
    if let Err(error) = require_session(sessions, request.session_id.as_deref()) {
        return error_response(401, error, &request.request_id);
    }
    if let Err(error) = require_csrf(
        sessions,
        request.session_id.as_deref().unwrap_or_default(),
        request.csrf_token.as_deref(),
    ) {
        return error_response(403, error, &request.request_id);
    }

    let proxy_host = match proxy_host_request_from_json(&request.body) {
        Ok(proxy_host) => proxy_host,
        Err(error) => return error_response(400, error, &request.request_id),
    };
    match create_proxy_host_and_apply(lifecycle, proxy_host, client) {
        Ok(response) => AdminHttpResponse::json(200, apply_response_json(&response)),
        Err(error) => error_response(http_status_for_error(&error), error, &request.request_id),
    }
}

pub fn handle_proxy_host_update_http<R, A, C>(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    lifecycle: &mut ConfigLifecycle<R, A>,
    client: &mut C,
) -> AdminHttpResponse
where
    R: ConfigRevisionRepository,
    A: AuditSink,
    C: CoreCommandClient + ?Sized,
{
    if request.method != AdminHttpMethod::Patch {
        return error_response(
            404,
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found"),
            &request.request_id,
        );
    }
    if let Err(error) = require_session(sessions, request.session_id.as_deref()) {
        return error_response(401, error, &request.request_id);
    }
    if let Err(error) = require_csrf(
        sessions,
        request.session_id.as_deref().unwrap_or_default(),
        request.csrf_token.as_deref(),
    ) {
        return error_response(403, error, &request.request_id);
    }

    let proxy_host_id = match proxy_host_id_from_update_path(&request.path) {
        Ok(proxy_host_id) => proxy_host_id,
        Err(error) => {
            return error_response(http_status_for_error(&error), error, &request.request_id)
        }
    };
    let proxy_host = match proxy_host_request_from_json(&request.body) {
        Ok(proxy_host) => proxy_host,
        Err(error) => return error_response(400, error, &request.request_id),
    };
    match update_proxy_host_and_apply(lifecycle, proxy_host_id, proxy_host, client) {
        Ok(response) => AdminHttpResponse::json(200, apply_response_json(&response)),
        Err(error) => error_response(http_status_for_error(&error), error, &request.request_id),
    }
}

pub fn handle_proxy_host_delete_http<R, A, C>(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    lifecycle: &mut ConfigLifecycle<R, A>,
    client: &mut C,
) -> AdminHttpResponse
where
    R: ConfigRevisionRepository,
    A: AuditSink,
    C: CoreCommandClient + ?Sized,
{
    if request.method != AdminHttpMethod::Delete {
        return error_response(
            404,
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found"),
            &request.request_id,
        );
    }
    if let Err(error) = require_session(sessions, request.session_id.as_deref()) {
        return error_response(401, error, &request.request_id);
    }
    if let Err(error) = require_csrf(
        sessions,
        request.session_id.as_deref().unwrap_or_default(),
        request.csrf_token.as_deref(),
    ) {
        return error_response(403, error, &request.request_id);
    }

    let proxy_host_id = match proxy_host_id_from_delete_path(&request.path) {
        Ok(proxy_host_id) => proxy_host_id,
        Err(error) => {
            return error_response(http_status_for_error(&error), error, &request.request_id)
        }
    };
    match delete_proxy_host_and_apply(lifecycle, proxy_host_id, client) {
        Ok(response) => AdminHttpResponse::json(200, apply_response_json(&response)),
        Err(error) => error_response(http_status_for_error(&error), error, &request.request_id),
    }
}

pub fn handle_config_rollback_http<R, A, C>(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    lifecycle: &mut ConfigLifecycle<R, A>,
    client: &mut C,
) -> AdminHttpResponse
where
    R: ConfigRevisionRepository,
    A: AuditSink,
    C: CoreCommandClient + ?Sized,
{
    if request.method != AdminHttpMethod::Post || request.path != "/api/v1/config/rollback" {
        return error_response(
            404,
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found"),
            &request.request_id,
        );
    }
    if let Err(error) = require_session(sessions, request.session_id.as_deref()) {
        return error_response(401, error, &request.request_id);
    }
    if let Err(error) = require_csrf(
        sessions,
        request.session_id.as_deref().unwrap_or_default(),
        request.csrf_token.as_deref(),
    ) {
        return error_response(403, error, &request.request_id);
    }

    let revision_id = match rollback_request_revision_id_from_json(&request.body) {
        Ok(revision_id) => revision_id,
        Err(error) => return error_response(400, error, &request.request_id),
    };
    match rollback(revision_id, lifecycle, client) {
        Ok(response) => AdminHttpResponse::json(200, apply_response_json(&response)),
        Err(error) => error_response(http_status_for_error(&error), error, &request.request_id),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::Arc;

    use super::*;
    use edge_application::checksum_snapshot;
    use edge_domain::{
        AdminConfig, CertificateRef, CommandAck, ConfigRevision, ConfigRevisionId, CoreCommand,
        Listener, ListenerId, ListenerProtocol, LogMode, RuntimeOptions, Service, ServiceId,
        Upstream, UpstreamId,
    };
    use edge_ports::{
        AcmeClient, AcmeHttp01ChallengeRuntime, AcmeOrderRequest, AcmeOrderResult, AuditEvent,
        AuditLedgerReader, RevisionRecord, StoredCertificate,
    };

    struct FakeAuditReader {
        called: Cell<u32>,
    }

    impl AuditLedgerReader for FakeAuditReader {
        fn query(
            &self,
            query: &edge_domain::AuditQuery,
        ) -> Result<edge_domain::AuditPage, AppError> {
            self.called.set(self.called.get() + 1);
            Ok(edge_domain::AuditPage {
                records: Vec::new(),
                next_cursor: None,
                head: edge_domain::AuditLedgerHead {
                    generation: 3,
                    sequence: query.limit as u64,
                },
                admission_state: edge_domain::AuditAdmissionState::Degraded,
            })
        }

        fn incomplete_operations(&self) -> Result<Vec<edge_domain::AuditRecord>, AppError> {
            Ok(Vec::new())
        }

        fn unresolved_reconciliations(&self) -> Result<Vec<edge_domain::AuditRecord>, AppError> {
            Ok(Vec::new())
        }

        fn head(&self) -> Result<edge_domain::AuditLedgerHead, AppError> {
            Ok(edge_domain::AuditLedgerHead::default())
        }
    }

    fn snapshot() -> ConfigSnapshot {
        ConfigSnapshot {
            schema_version: 1,
            revision_id: ConfigRevisionId::new("rev-1"),
            admin: AdminConfig {
                bind: "127.0.0.1:9443".to_string(),
                auth_required: true,
            },
            listeners: vec![Listener {
                id: ListenerId::new("http"),
                bind: "0.0.0.0:8080".to_string(),
                protocol: ListenerProtocol::Http,
                client_auth: edge_domain::ClientAuthPolicy::Disabled,
            }],
            routes: vec![],
            services: vec![Service {
                policy: edge_domain::ServicePolicy::default(),
                id: ServiceId::new("existing"),
                upstreams: vec![Upstream {
                    id: UpstreamId::new("existing-1"),
                    url: "http://127.0.0.1:3000".to_string(),
                    administrative_state: edge_domain::UpstreamAdministrativeState::Active,
                    tls: edge_domain::UpstreamTlsPolicy::Disabled,
                }],
            }],
            certificate_resolvers: vec![],
            log_mode: LogMode::Product,
            runtime: RuntimeOptions {
                max_connections: 1024,
                max_inflight_payload_bytes: 128 * 1024 * 1024,
                max_request_header_bytes: 16 * 1024,
                max_request_body_bytes: 1024 * 1024,
                upstream_read_timeout_ms: edge_domain::DEFAULT_UPSTREAM_READ_TIMEOUT_MS,
                metrics: edge_domain::MetricsConfig::default(),
            },
        }
    }

    fn snapshot_with_proxy_host() -> ConfigSnapshot {
        let base = snapshot();
        add_proxy_host(
            &base,
            &proxy_host_from_request(ProxyHostRequest {
                id: "app".to_string(),
                name: "App".to_string(),
                domains: vec!["app.example.com".to_string()],
                path_prefix: "/app".to_string(),
                upstream_url: "http://127.0.0.1:4000".to_string(),
                upstreams: vec![],
                health_check: None,
                retry: RetryPolicy::default(),
                passive_health: PassiveHealthMode::Disabled,
                https_enabled: true,
                letsencrypt_enabled: true,
                redirect_http_to_https: true,
                enabled: true,
            }),
        )
    }

    #[derive(Default)]
    struct FakeCommandClient {
        commands: Vec<CoreCommand>,
        reject: bool,
    }

    impl CoreCommandClient for FakeCommandClient {
        fn send(&mut self, command: CoreCommand) -> CommandAck {
            if self.reject {
                CommandAck::rejected(AppError::new(
                    ErrorCode::RuntimeCommandRejected,
                    "queue full",
                ))
            } else {
                self.commands.push(command);
                CommandAck::accepted()
            }
        }
    }

    #[derive(Default)]
    struct MemoryRevisionRepo {
        records: Vec<RevisionRecord>,
        current: Option<ConfigRevisionId>,
    }

    impl ConfigRevisionRepository for MemoryRevisionRepo {
        fn save_revision(&mut self, record: RevisionRecord) -> Result<(), AppError> {
            self.records.push(record);
            Ok(())
        }

        fn set_current(&mut self, revision_id: &ConfigRevisionId) -> Result<(), AppError> {
            self.current = Some(revision_id.clone());
            Ok(())
        }

        fn current(&self) -> Result<Option<RevisionRecord>, AppError> {
            Ok(self.current.as_ref().and_then(|current| {
                self.records
                    .iter()
                    .find(|record| &record.revision.id == current)
                    .cloned()
            }))
        }

        fn find_revision(
            &self,
            revision_id: &ConfigRevisionId,
        ) -> Result<Option<RevisionRecord>, AppError> {
            Ok(self
                .records
                .iter()
                .find(|record| &record.revision.id == revision_id)
                .cloned())
        }

        fn history(&self) -> Result<Vec<RevisionRecord>, AppError> {
            Ok(self.records.clone())
        }
    }

    #[derive(Default)]
    struct MemoryAudit {
        events: Vec<AuditEvent>,
    }

    impl AuditSink for MemoryAudit {
        fn record(&mut self, event: AuditEvent) -> Result<(), AppError> {
            self.events.push(event);
            Ok(())
        }
    }

    #[derive(Default)]
    struct MemorySecretStore {
        records: Vec<SecretRecord>,
    }

    impl SecretStore for MemorySecretStore {
        fn save_secret(&mut self, secret: SecretRecord) -> Result<(), AppError> {
            self.records.retain(|record| record.name != secret.name);
            self.records.push(secret);
            Ok(())
        }

        fn load_secret(&self, name: &str) -> Result<Option<SecretRecord>, AppError> {
            Ok(self
                .records
                .iter()
                .find(|record| record.name == name)
                .cloned())
        }
    }

    #[derive(Default)]
    struct MemoryCertStore {
        records: Vec<StoredCertificate>,
    }

    impl CertificateStore for MemoryCertStore {
        fn save_certificate(&mut self, certificate: StoredCertificate) -> Result<(), AppError> {
            self.records
                .retain(|record| record.certificate_ref != certificate.certificate_ref);
            self.records.push(certificate);
            Ok(())
        }

        fn load_certificate(
            &self,
            certificate_ref: &CertificateRef,
        ) -> Result<Option<StoredCertificate>, AppError> {
            Ok(self
                .records
                .iter()
                .find(|record| &record.certificate_ref == certificate_ref)
                .cloned())
        }

        fn list_certificates(&self) -> Result<Vec<StoredCertificate>, AppError> {
            Ok(self.records.clone())
        }

        fn delete_certificate(&mut self, certificate_ref: &CertificateRef) -> Result<(), AppError> {
            self.records
                .retain(|record| &record.certificate_ref != certificate_ref);
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeMaterialValidator {
        calls: usize,
    }

    impl edge_ports::CertificateMaterialValidator for FakeMaterialValidator {
        fn validate(
            &mut self,
            material: &edge_ports::CertificateMaterial,
        ) -> Result<edge_ports::ValidatedCertificateMaterial, AppError> {
            self.calls += 1;
            assert!(material.certificate_pem.contains('\n'));
            assert!(material.private_key_pem.contains('\n'));
            Ok(edge_ports::ValidatedCertificateMaterial {
                not_after_epoch_seconds: 4_000_000_000,
                dns_names: vec!["app.example.com".to_string()],
            })
        }
    }

    #[derive(Default)]
    struct FakeAcme {
        issued: Vec<AcmeOrderRequest>,
        fail: bool,
    }

    impl AcmeClient for FakeAcme {
        fn issue_certificate(
            &mut self,
            request: AcmeOrderRequest,
        ) -> Result<AcmeOrderResult, AppError> {
            self.issued.push(request.clone());
            if self.fail {
                return Err(AppError::new(
                    ErrorCode::AcmeChallengeFailed,
                    "challenge failed",
                ));
            }
            Ok(AcmeOrderResult {
                certificate: StoredCertificate {
                    certificate_ref: CertificateRef::new("acme-returned"),
                    domains: request.domains,
                    not_after_epoch_seconds: 4_102_444_800,
                    source: if request.production {
                        "fake-acme-production".to_string()
                    } else {
                        "fake-acme-staging".to_string()
                    },
                    certificate_pem: "cert".to_string(),
                    private_key_pem: "secret-key".to_string(),
                },
            })
        }

        fn issue_certificate_http01(
            &mut self,
            request: AcmeOrderRequest,
            challenge_runtime: &mut dyn AcmeHttp01ChallengeRuntime,
        ) -> Result<AcmeOrderResult, AppError> {
            for domain in &request.domains {
                let token = format!("fake-acme-http01-{}", domain.replace('.', "-"));
                let key_authorization = format!("{token}.fake-acme-account-thumbprint");
                challenge_runtime.present_http01(token.clone(), key_authorization.clone())?;
                challenge_runtime.verify_http01(&token, &key_authorization)?;
            }
            self.issue_certificate(request)
        }
    }

    fn lifecycle_with_current() -> ConfigLifecycle<MemoryRevisionRepo, MemoryAudit> {
        let snapshot = snapshot();
        let revision = ConfigRevision {
            id: snapshot.revision_id.clone(),
            schema_version: snapshot.schema_version,
            summary: "initial".to_string(),
        };
        let checksum = checksum_snapshot(&snapshot);
        let revision_id = revision.id.clone();
        let mut revisions = MemoryRevisionRepo::default();
        revisions
            .save_revision(RevisionRecord {
                revision,
                snapshot,
                checksum,
            })
            .unwrap();
        revisions.set_current(&revision_id).unwrap();
        ConfigLifecycle {
            revisions,
            audit: MemoryAudit::default(),
            validator: ConfigValidator::default(),
        }
    }

    #[test]
    fn exposes_crate_name() {
        assert_eq!(crate_name(), "edge-admin-api");
    }

    #[test]
    fn error_response_has_stable_contract_fields() {
        let response = ApiErrorResponse::from_error(
            AppError::new(ErrorCode::AdminAuthRequired, "login required"),
            "req-1",
        );

        assert_eq!(response.code, "ADMIN_AUTH_REQUIRED");
        assert_eq!(response.request_id, "req-1");
        assert!(!response.hint.is_empty());
    }

    #[test]
    fn login_success_creates_session_and_csrf() {
        let mut auth = AdminAuthenticator::new("hash");
        let mut sessions = SessionStore::default();

        let session = auth.login("hash", &mut sessions).unwrap();

        assert!(sessions.verify(&session.session_id));
        assert!(sessions.verify_csrf(&session.session_id, &session.csrf_token));
    }

    #[test]
    fn login_failure_is_rejected() {
        let mut auth = AdminAuthenticator::new("hash");
        let mut sessions = SessionStore::default();

        let error = auth.login("wrong", &mut sessions).unwrap_err();

        assert_eq!(error.code, ErrorCode::AdminInvalidCredentials);
    }

    #[test]
    fn unauthenticated_request_is_rejected() {
        let sessions = SessionStore::default();

        let error = require_session(&sessions, None).unwrap_err();

        assert_eq!(error.code, ErrorCode::AdminAuthRequired);
    }

    #[test]
    fn mutation_without_csrf_is_rejected() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });

        let error = require_csrf(&sessions, "session-1", None).unwrap_err();

        assert_eq!(error.code, ErrorCode::AdminCsrfRequired);
    }

    #[test]
    fn status_schema_is_stable() {
        let response = status_response(&snapshot());

        assert_eq!(response.version_prefix, "/api/v1");
        assert_eq!(response.current_revision_id, "rev-1");
    }

    #[test]
    fn status_schema_distinguishes_desired_and_active_resource_policy() {
        let active = snapshot();
        let mut desired = active.clone();
        desired.revision_id = ConfigRevisionId::new("rev-desired");
        desired.runtime.max_connections = 100;
        desired.runtime.max_inflight_payload_bytes = 32 * 1024 * 1024;

        let response = status_response_with_active(&desired, &active);
        let json = status_response_json(&response);

        assert_eq!(response.current_revision_id, "rev-desired");
        assert_eq!(response.desired_revision_id, "rev-desired");
        assert_eq!(response.active_revision_id, "rev-1");
        assert!(response.restart_required);
        assert_eq!(response.desired_resource_policy.max_connections, 100);
        assert_eq!(response.active_resource_policy.max_connections, 1024);
        assert!(json.contains("\"desired_revision_id\":\"rev-desired\""));
        assert!(json.contains("\"active_revision_id\":\"rev-1\""));
        assert!(json.contains("\"restart_required\":true"));
        assert!(json.contains("\"max_inflight_payload_bytes\":33554432"));
    }

    #[test]
    fn status_schema_exposes_nullable_revision_scoped_live_resource_status() {
        let active = snapshot();
        let mut desired = active.clone();
        desired.revision_id = ConfigRevisionId::new("rev-desired");
        desired.runtime.max_inflight_payload_bytes = 32 * 1024 * 1024;
        let live = edge_ports::RuntimeResourceStatusSnapshot {
            revision_id: active.revision_id.clone(),
            generation: 9,
            used_payload_bytes: 4_096,
            payload_limit_bytes: active.runtime.max_inflight_payload_bytes,
            active_connections: 3,
            pressure: edge_ports::RuntimeResourcePressure::Pressured,
        };

        let available = status_response_with_active_and_resource(&desired, &active, Some(live));
        let available_json = status_response_json(&available);
        let unavailable = status_response_with_active_and_resource(&desired, &active, None);
        let unavailable_json = status_response_json(&unavailable);

        assert_eq!(
            available.live_resource_status.as_ref().unwrap().revision_id,
            "rev-1"
        );
        assert!(available_json.contains("\"used_payload_bytes\":4096"));
        assert!(available_json.contains("\"pressure\":\"pressured\""));
        assert!(unavailable.live_resource_status.is_none());
        assert!(unavailable_json.contains("\"live_resource_status\":null"));
    }

    #[test]
    fn http_status_route_returns_current_revision_json() {
        let sessions = SessionStore::default();
        let snapshot = snapshot();
        let request = AdminHttpRequest::new(AdminHttpMethod::Get, "/api/v1/status", "req-1");

        let response = handle_http_request(
            &request,
            AdminHttpContext {
                snapshot: &snapshot,
                sessions: &sessions,
            },
        );

        assert_eq!(response.status_code, 200);
        assert!(response
            .headers
            .contains(&("content-type".to_string(), "application/json".to_string())));
        assert!(response.body.contains("\"current_revision_id\":\"rev-1\""));
        assert!(response.body.contains("\"routes\":0"));
    }

    #[test]
    fn http_health_route_returns_minimal_operational_json() {
        let sessions = SessionStore::default();
        let snapshot = snapshot();
        let request = AdminHttpRequest::new(AdminHttpMethod::Get, "/api/v1/health", "req-health");

        let response = handle_http_request(
            &request,
            AdminHttpContext {
                snapshot: &snapshot,
                sessions: &sessions,
            },
        );

        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("\"status\":\"ok\""));
        assert!(response.body.contains("\"current_revision_id\":\"rev-1\""));
        assert!(response.body.contains("\"routes\":0"));
        assert!(!response.body.contains("upstream_url"));
    }

    #[test]
    fn operational_probes_are_unauthenticated_and_never_return_config_details() {
        let live = AdminHttpRequest::new(AdminHttpMethod::Get, "/api/v1/health/live", "req-live");
        let ready =
            AdminHttpRequest::new(AdminHttpMethod::Get, "/api/v1/health/ready", "req-ready");
        let live_response =
            handle_operational_probe_http(&live, OperationalLifecycle::Draining, true, true, true);
        let ready_response =
            handle_operational_probe_http(&ready, OperationalLifecycle::Draining, true, true, true);
        assert_eq!(live_response.status_code, 200);
        assert_eq!(live_response.body, r#"{"status":"live"}"#);
        assert_eq!(ready_response.status_code, 503);
        assert_eq!(ready_response.body, r#"{"status":"not_ready"}"#);
        assert!(!ready_response.body.contains("revision"));
    }

    #[test]
    fn upstream_health_route_requires_session_and_returns_ordered_safe_status_items() {
        struct FakeHealthStatusReader;

        impl edge_ports::HealthStatusReader for FakeHealthStatusReader {
            fn read_health_status(&self) -> Result<HealthAvailabilitySnapshot, AppError> {
                Ok(HealthAvailabilitySnapshot {
                    revision_id: ConfigRevisionId::new("health-rev"),
                    generation: edge_domain::HealthGeneration(7),
                    entries: [
                        (
                            edge_domain::UpstreamHealthKey {
                                service_id: ServiceId::new("service-b"),
                                upstream_id: UpstreamId::new("upstream-b"),
                            },
                            edge_domain::UpstreamAvailability::Unhealthy,
                        ),
                        (
                            edge_domain::UpstreamHealthKey {
                                service_id: ServiceId::new("service-a"),
                                upstream_id: UpstreamId::new("upstream-a"),
                            },
                            edge_domain::UpstreamAvailability::Healthy,
                        ),
                        (
                            edge_domain::UpstreamHealthKey {
                                service_id: ServiceId::new("service-c"),
                                upstream_id: UpstreamId::new("upstream-c"),
                            },
                            edge_domain::UpstreamAvailability::Unknown,
                        ),
                        (
                            edge_domain::UpstreamHealthKey {
                                service_id: ServiceId::new("service-d"),
                                upstream_id: UpstreamId::new("upstream-d"),
                            },
                            edge_domain::UpstreamAvailability::Disabled,
                        ),
                    ]
                    .into_iter()
                    .collect(),
                })
            }
        }

        struct FakeRuntimeStatusReader;

        impl edge_ports::RuntimeUpstreamStatusReader for FakeRuntimeStatusReader {
            fn read_runtime_status(
                &self,
            ) -> Result<edge_ports::RuntimeUpstreamStatusSnapshot, AppError> {
                Ok(edge_ports::RuntimeUpstreamStatusSnapshot {
                    revision_id: ConfigRevisionId::new("health-rev"),
                    generation: 7,
                    upstreams: vec![edge_ports::RuntimeUpstreamStatus {
                        key: edge_domain::UpstreamHealthKey {
                            service_id: ServiceId::new("service-a"),
                            upstream_id: UpstreamId::new("upstream-a"),
                        },
                        state: edge_ports::RuntimeDrainState::Draining,
                        connection_count: 2,
                    }],
                })
            }
        }

        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let unauthorized = AdminHttpRequest::new(
            AdminHttpMethod::Get,
            "/api/v1/upstream-health",
            "req-health-unauthorized",
        );
        assert_eq!(
            handle_upstream_health_http(&unauthorized, &sessions, &FakeHealthStatusReader, None)
                .status_code,
            401
        );

        let request = AdminHttpRequest::new(
            AdminHttpMethod::Get,
            "/api/v1/upstream-health",
            "req-health-status",
        )
        .with_session_id("session-1");
        let response = handle_upstream_health_http(
            &request,
            &sessions,
            &FakeHealthStatusReader,
            Some(&FakeRuntimeStatusReader),
        );

        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("\"revision_id\":\"health-rev\""));
        assert!(response.body.contains("\"generation\":7"));
        let service_a = response.body.find("service-a").unwrap();
        let service_b = response.body.find("service-b").unwrap();
        assert!(service_a < service_b);
        assert!(response.body.contains("\"status\":\"healthy\""));
        assert!(response.body.contains("\"status\":\"unhealthy\""));
        assert!(response.body.contains("\"status\":\"unknown\""));
        assert!(response.body.contains("\"status\":\"disabled\""));
        assert!(response.body.contains("\"drain_state\":\"draining\""));
        assert!(response.body.contains("\"connection_count\":2"));
        assert!(!response.body.contains("127.0.0.1"));
        assert!(!response.body.contains("upstream_url"));
    }

    #[test]
    fn upstream_health_route_maps_reader_failure_to_stable_typed_error() {
        struct FailingHealthStatusReader;

        impl edge_ports::HealthStatusReader for FailingHealthStatusReader {
            fn read_health_status(&self) -> Result<HealthAvailabilitySnapshot, AppError> {
                Err(AppError::new(
                    ErrorCode::RuntimeHealthUnavailable,
                    "health runtime is stopped",
                ))
            }
        }

        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let request = AdminHttpRequest::new(
            AdminHttpMethod::Get,
            "/api/v1/upstream-health",
            "req-health-failure",
        )
        .with_session_id("session-1");
        let response =
            handle_upstream_health_http(&request, &sessions, &FailingHealthStatusReader, None);

        assert_eq!(response.status_code, 500);
        assert!(response
            .body
            .contains("\"code\":\"RUNTIME_HEALTH_UNAVAILABLE\""));
        assert!(response
            .body
            .contains("\"request_id\":\"req-health-failure\""));
    }

    #[test]
    fn http_certificate_list_requires_session() {
        let sessions = SessionStore::default();
        let store = MemoryCertStore::default();
        let request = AdminHttpRequest::new(
            AdminHttpMethod::Get,
            "/api/v1/certificates",
            "req-cert-auth",
        );

        let response = handle_certificate_list_http(&request, &sessions, &store, 1_000, 200);

        assert_eq!(response.status_code, 401);
        assert!(response.body.contains("\"code\":\"ADMIN_AUTH_REQUIRED\""));
    }

    #[derive(Default)]
    struct FakeTrustAdminService {
        items: Vec<TrustBundleMetadata>,
    }

    impl TrustBundleAdminService for FakeTrustAdminService {
        fn import(
            &mut self,
            _request_id: &str,
            trust_bundle_ref: TrustBundleRef,
            _encoded_material: Vec<u8>,
        ) -> Result<TrustBundleMetadata, AppError> {
            let metadata = TrustBundleMetadata {
                trust_bundle_ref,
                certificate_count: 1,
                imported_at_epoch_seconds: 10,
                content_sha256: [0; 32],
            };
            self.items.push(metadata.clone());
            Ok(metadata)
        }

        fn list(&mut self) -> Result<Vec<TrustBundleMetadata>, AppError> {
            Ok(self.items.clone())
        }

        fn delete(&mut self, trust_bundle_ref: TrustBundleRef) -> Result<(), AppError> {
            self.items
                .retain(|item| item.trust_bundle_ref != trust_bundle_ref);
            Ok(())
        }
    }

    #[test]
    fn phase009_trust_api_requires_auth_csrf_and_returns_metadata_only() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let mut service = FakeTrustAdminService::default();

        let unauthorized = AdminHttpRequest::new(
            AdminHttpMethod::Get,
            "/api/v1/trust-bundles",
            "req-trust-auth",
        );
        assert_eq!(
            handle_trust_bundle_http(&unauthorized, &sessions, &mut service).status_code,
            401
        );

        let import = AdminHttpRequest::new(
            AdminHttpMethod::Post,
            "/api/v1/trust-bundles",
            "req-trust-import",
        )
        .with_session_id("session-1")
        .with_csrf_token("csrf-1")
        .with_body("{\"trust_bundle_ref\":\"private-root\",\"encoded_material\":\"CA-PEM\"}");
        let imported = handle_trust_bundle_http(&import, &sessions, &mut service);
        assert_eq!(imported.status_code, 200);
        assert!(imported
            .body
            .contains("\"trust_bundle_ref\":\"private-root\""));
        assert!(!imported.body.contains("CA-PEM"));

        let list = AdminHttpRequest::new(
            AdminHttpMethod::Get,
            "/api/v1/trust-bundles",
            "req-trust-list",
        )
        .with_session_id("session-1");
        let listed = handle_trust_bundle_http(&list, &sessions, &mut service);
        assert_eq!(listed.status_code, 200);
        assert!(!listed.body.contains("encoded_material"));

        let delete = AdminHttpRequest::new(
            AdminHttpMethod::Delete,
            "/api/v1/trust-bundles/private-root",
            "req-trust-delete",
        )
        .with_session_id("session-1");
        assert_eq!(
            handle_trust_bundle_http(&delete, &sessions, &mut service).status_code,
            403
        );
    }

    #[test]
    fn http_certificate_list_masks_private_keys_and_marks_expiry() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let mut store = MemoryCertStore::default();
        store
            .save_certificate(StoredCertificate {
                certificate_ref: CertificateRef::new("cert-app"),
                domains: vec!["app.example.com".to_string()],
                not_after_epoch_seconds: 1_100,
                source: "manual".to_string(),
                certificate_pem: "cert".to_string(),
                private_key_pem: "secret-key".to_string(),
            })
            .unwrap();
        let request =
            AdminHttpRequest::new(AdminHttpMethod::Get, "/api/v1/certificates", "req-cert")
                .with_session_id("session-1");

        let response = handle_certificate_list_http(&request, &sessions, &store, 1_000, 200);

        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("\"certificates\":["));
        assert!(response.body.contains("\"certificate_ref\":\"cert-app\""));
        assert!(response.body.contains("\"domains\":[\"app.example.com\"]"));
        assert!(response.body.contains("\"expiring_soon\":true"));
        assert!(response.body.contains("\"private_key\":\"***\""));
        assert!(!response.body.contains("secret-key"));
    }

    #[test]
    fn http_certificate_get_returns_not_found_for_missing_certificate() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let store = MemoryCertStore::default();
        let request = AdminHttpRequest::new(
            AdminHttpMethod::Get,
            "/api/v1/certificates/missing",
            "req-cert",
        )
        .with_session_id("session-1");

        let response = handle_certificate_get_http(&request, &sessions, &store, 1_000, 200);

        assert_eq!(response.status_code, 404);
        assert!(response.body.contains("\"code\":\"CERTIFICATE_NOT_FOUND\""));
    }

    #[test]
    fn http_certificate_import_requires_session_before_parsing_material() {
        let sessions = SessionStore::default();
        let mut validator = FakeMaterialValidator::default();
        let mut store = MemoryCertStore::default();
        let mut audit = MemoryAudit::default();
        let mut client = FakeCommandClient::default();
        let request = AdminHttpRequest::new(
            AdminHttpMethod::Post,
            "/api/v1/certificates/proxy-host-app/import",
            "req-cert-import",
        )
        .with_body("{}");

        let response = handle_certificate_import_http(
            &request,
            &sessions,
            &ConfigRevisionId::new("rev-1"),
            &mut validator,
            &mut store,
            &mut audit,
            &mut client,
        );

        assert_eq!(response.status_code, 401);
        assert_eq!(validator.calls, 0);
        assert!(store.records.is_empty());
    }

    #[test]
    fn http_certificate_import_requires_csrf_before_parsing_material() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let mut validator = FakeMaterialValidator::default();
        let mut store = MemoryCertStore::default();
        let mut audit = MemoryAudit::default();
        let mut client = FakeCommandClient::default();
        let request = AdminHttpRequest::new(
            AdminHttpMethod::Post,
            "/api/v1/certificates/proxy-host-app/import",
            "req-cert-import",
        )
        .with_session_id("session-1")
        .with_body("{}");

        let response = handle_certificate_import_http(
            &request,
            &sessions,
            &ConfigRevisionId::new("rev-1"),
            &mut validator,
            &mut store,
            &mut audit,
            &mut client,
        );

        assert_eq!(response.status_code, 403);
        assert_eq!(validator.calls, 0);
        assert!(store.records.is_empty());
    }

    #[test]
    fn http_certificate_import_decodes_pem_and_returns_masked_status() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let mut validator = FakeMaterialValidator::default();
        let mut store = MemoryCertStore::default();
        let mut audit = MemoryAudit::default();
        let mut client = FakeCommandClient::default();
        let request = AdminHttpRequest::new(
            AdminHttpMethod::Post,
            "/api/v1/certificates/proxy-host-app/import",
            "req-cert-import",
        )
        .with_session_id("session-1")
        .with_csrf_token("csrf-1")
        .with_body(
            r#"{"domains":["app.example.com"],"fullchain_pem":"-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----","private_key_pem":"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"}"#,
        );

        let response = handle_certificate_import_http(
            &request,
            &sessions,
            &ConfigRevisionId::new("rev-1"),
            &mut validator,
            &mut store,
            &mut audit,
            &mut client,
        );

        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("\"request_id\":\"req-cert-import\""));
        assert!(response
            .body
            .contains("\"certificate_ref\":\"proxy-host-app\""));
        assert!(response.body.contains("\"source\":\"manual\""));
        assert!(response.body.contains("\"private_key\":\"***\""));
        assert!(response.body.contains("\"state\":\"installed\""));
        assert!(!response.body.contains("secret"));
        assert_eq!(validator.calls, 1);
        assert_eq!(store.records.len(), 1);
    }

    #[test]
    fn http_certificate_issue_requires_csrf_without_acme_or_command() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let mut issuer = CertificateIssuer {
            acme: FakeAcme::default(),
            store: MemoryCertStore::default(),
            audit: MemoryAudit::default(),
        };
        let mut client = FakeCommandClient::default();
        let request = AdminHttpRequest::new(
            AdminHttpMethod::Post,
            "/api/v1/certificates/proxy-host-app/issue",
            "req-cert-issue",
        )
        .with_session_id("session-1")
        .with_body(
            r#"{"domains":["app.example.com"],"account_email":"admin@example.com","production":false,"terms_accepted":false}"#,
        );

        let response = handle_certificate_issue_http(&request, &sessions, &mut issuer, &mut client);

        assert_eq!(response.status_code, 403);
        assert!(response.body.contains("\"code\":\"ADMIN_CSRF_REQUIRED\""));
        assert!(issuer.acme.issued.is_empty());
        assert!(issuer.store.records.is_empty());
        assert!(client.commands.is_empty());
    }

    #[test]
    fn http_certificate_issue_stores_target_ref_and_sends_install_command() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let mut issuer = CertificateIssuer {
            acme: FakeAcme::default(),
            store: MemoryCertStore::default(),
            audit: MemoryAudit::default(),
        };
        let mut client = FakeCommandClient::default();
        let request = AdminHttpRequest::new(
            AdminHttpMethod::Post,
            "/api/v1/certificates/proxy-host-app/issue",
            "req-cert-issue",
        )
        .with_session_id("session-1")
        .with_csrf_token("csrf-1")
        .with_body(
            r#"{"domains":["app.example.com"],"account_email":"admin@example.com","production":false,"terms_accepted":false}"#,
        );

        let response = handle_certificate_issue_http(&request, &sessions, &mut issuer, &mut client);

        assert_eq!(response.status_code, 200);
        assert!(response
            .body
            .contains("\"certificate_ref\":\"proxy-host-app\""));
        assert!(response.body.contains("\"request_id\":\"req-cert-issue\""));
        assert!(response.body.contains("\"source\":\"fake-acme-staging\""));
        assert!(response.body.contains("\"commands_sent\":1"));
        assert!(!response.body.contains("secret-key"));
        assert_eq!(
            issuer.store.records[0].certificate_ref.as_str(),
            "proxy-host-app"
        );
        assert_eq!(issuer.audit.events[0].event, "certificate.issue");
        assert!(matches!(
            client.commands.first(),
            Some(CoreCommand::InstallCertificate { certificate_ref })
                if certificate_ref.as_str() == "proxy-host-app"
        ));
    }

    #[test]
    fn http_certificate_renew_uses_existing_domains_and_sends_install_command() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let mut issuer = CertificateIssuer {
            acme: FakeAcme::default(),
            store: MemoryCertStore::default(),
            audit: MemoryAudit::default(),
        };
        issuer
            .store
            .save_certificate(StoredCertificate {
                certificate_ref: CertificateRef::new("proxy-host-app"),
                domains: vec!["app.example.com".to_string()],
                not_after_epoch_seconds: 1_000,
                source: "fake-acme-staging".to_string(),
                certificate_pem: "old-cert".to_string(),
                private_key_pem: "old-key".to_string(),
            })
            .unwrap();
        let mut client = FakeCommandClient::default();
        let request = AdminHttpRequest::new(
            AdminHttpMethod::Post,
            "/api/v1/certificates/proxy-host-app/renew",
            "req-cert-renew",
        )
        .with_session_id("session-1")
        .with_csrf_token("csrf-1")
        .with_body(
            r#"{"account_email":"admin@example.com","production":false,"terms_accepted":false}"#,
        );

        let response = handle_certificate_renew_http(&request, &sessions, &mut issuer, &mut client);

        assert_eq!(response.status_code, 200);
        assert!(response
            .body
            .contains("\"certificate_ref\":\"proxy-host-app\""));
        assert!(response.body.contains("\"request_id\":\"req-cert-renew\""));
        assert_eq!(
            issuer.acme.issued[0].domains,
            vec!["app.example.com".to_string()]
        );
        assert_eq!(issuer.store.records.len(), 1);
        assert_eq!(issuer.store.records[0].source, "fake-acme-staging");
        assert!(matches!(
            client.commands.first(),
            Some(CoreCommand::InstallCertificate { certificate_ref })
                if certificate_ref.as_str() == "proxy-host-app"
        ));
    }

    #[test]
    fn http_access_logs_require_session_and_omit_raw_path() {
        let sessions = SessionStore::default();
        let request =
            AdminHttpRequest::new(AdminHttpMethod::Get, "/api/v1/logs/access", "req-log-auth");
        let events = vec![AccessLogEvent {
            request_id: "req-1".to_string(),
            revision_id: "rev-1".to_string(),
            route_id: Some("route-1".to_string()),
            upstream_id: Some("upstream-1".to_string()),
            status_code: 200,
            duration_ms: 12,
            scheme: "https".to_string(),
            method: "GET".to_string(),
            path: "/secret?token=raw".to_string(),
        }];

        let rejected = handle_access_logs_http(&request, &sessions, &events);

        assert_eq!(rejected.status_code, 401);

        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let accepted =
            handle_access_logs_http(&request.with_session_id("session-1"), &sessions, &events);

        assert_eq!(accepted.status_code, 200);
        assert!(accepted.body.contains("\"access_logs\":["));
        assert!(accepted.body.contains("\"revision_id\":\"rev-1\""));
        assert!(accepted.body.contains("\"route_id\":\"route-1\""));
        assert!(accepted.body.contains("\"upstream_id\":\"upstream-1\""));
        assert!(!accepted.body.contains("/secret"));
        assert!(!accepted.body.contains("token=raw"));
    }

    #[test]
    fn http_error_logs_return_recent_errors() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let request =
            AdminHttpRequest::new(AdminHttpMethod::Get, "/api/v1/logs/errors", "req-errors")
                .with_session_id("session-1");
        let events = vec![RecentErrorEvent {
            request_id: Some("req-1".to_string()),
            error_code: "RUNTIME_COMMAND_REJECTED".to_string(),
            message: "queue full".to_string(),
        }];

        let response = handle_error_logs_http(&request, &sessions, &events);

        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("\"error_logs\":["));
        assert!(response
            .body
            .contains("\"error_code\":\"RUNTIME_COMMAND_REJECTED\""));
        assert!(response.body.contains("\"message\":\"queue full\""));
    }

    #[test]
    fn http_config_get_requires_session() {
        let sessions = SessionStore::default();
        let snapshot = snapshot();
        let request =
            AdminHttpRequest::new(AdminHttpMethod::Get, "/api/v1/config", "req-config-auth");

        let response = handle_http_request(
            &request,
            AdminHttpContext {
                snapshot: &snapshot,
                sessions: &sessions,
            },
        );

        assert_eq!(response.status_code, 401);
        assert!(response.body.contains("\"code\":\"ADMIN_AUTH_REQUIRED\""));
        assert!(response.body.contains("\"request_id\":\"req-config-auth\""));
    }

    #[test]
    fn http_config_get_returns_rendered_current_config() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let snapshot = snapshot();
        let request = AdminHttpRequest::new(AdminHttpMethod::Get, "/api/v1/config", "req-config")
            .with_session_id("session-1");

        let response = handle_http_request(
            &request,
            AdminHttpContext {
                snapshot: &snapshot,
                sessions: &sessions,
            },
        );

        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("\"revision_id\":\"rev-1\""));
        assert!(response.body.contains("\"config\":\"schema_version = 1\\n"));
        assert!(response.body.contains("[admin]\\n"));
    }

    #[test]
    fn http_config_validate_accepts_valid_raw_config_without_csrf() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let snapshot = snapshot();
        let request = AdminHttpRequest::new(
            AdminHttpMethod::Post,
            "/api/v1/config/validate",
            "req-validate",
        )
        .with_session_id("session-1")
        .with_body(render_mvp_config_snapshot(&snapshot));

        let response = handle_http_request(
            &request,
            AdminHttpContext {
                snapshot: &snapshot,
                sessions: &sessions,
            },
        );

        assert_eq!(response.status_code, 200);
        assert_eq!(response.body, "{\"valid\":true,\"errors\":[]}");
    }

    #[test]
    fn http_config_validate_reports_invalid_raw_config() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let snapshot = snapshot();
        let invalid = render_mvp_config_snapshot(&snapshot)
            .replace("http://127.0.0.1:3000", "https://127.0.0.1:3000");
        let request = AdminHttpRequest::new(
            AdminHttpMethod::Post,
            "/api/v1/config/validate",
            "req-invalid",
        )
        .with_session_id("session-1")
        .with_body(invalid);

        let response = handle_http_request(
            &request,
            AdminHttpContext {
                snapshot: &snapshot,
                sessions: &sessions,
            },
        );

        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("\"valid\":false"));
        assert!(response
            .body
            .contains("\"code\":\"CONFIG_INVALID_UPSTREAM_URL\""));
    }

    #[test]
    fn http_config_diff_returns_route_and_upstream_changes() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let snapshot = snapshot();
        let changed = render_mvp_config_snapshot(&snapshot)
            .replace("http://127.0.0.1:3000", "http://127.0.0.1:5000");
        let request =
            AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/config/diff", "req-diff")
                .with_session_id("session-1")
                .with_body(changed);

        let response = handle_http_request(
            &request,
            AdminHttpContext {
                snapshot: &snapshot,
                sessions: &sessions,
            },
        );

        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("\"valid\":true"));
        assert!(response
            .body
            .contains("\"changed_upstreams\":[\"existing\"]"));
    }

    #[test]
    fn http_config_diff_reports_invalid_candidate_without_state_change() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let snapshot = snapshot();
        let invalid = render_mvp_config_snapshot(&snapshot)
            .replace("http://127.0.0.1:3000", "https://127.0.0.1:3000");
        let request =
            AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/config/diff", "req-diff")
                .with_session_id("session-1")
                .with_body(invalid);

        let response = handle_http_request(
            &request,
            AdminHttpContext {
                snapshot: &snapshot,
                sessions: &sessions,
            },
        );

        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("\"valid\":false"));
        assert!(response
            .body
            .contains("\"code\":\"CONFIG_INVALID_UPSTREAM_URL\""));
        assert!(response.body.contains("\"changed_upstreams\":[]"));
    }

    #[test]
    fn http_proxy_host_list_requires_session() {
        let sessions = SessionStore::default();
        let snapshot = snapshot_with_proxy_host();
        let request =
            AdminHttpRequest::new(AdminHttpMethod::Get, "/api/v1/proxy-hosts", "req-list-auth");

        let response = handle_http_request(
            &request,
            AdminHttpContext {
                snapshot: &snapshot,
                sessions: &sessions,
            },
        );

        assert_eq!(response.status_code, 401);
        assert!(response.body.contains("\"code\":\"ADMIN_AUTH_REQUIRED\""));
        assert!(response.body.contains("\"request_id\":\"req-list-auth\""));
    }

    #[test]
    fn http_proxy_host_list_returns_generated_proxy_hosts() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let snapshot = snapshot_with_proxy_host();
        let request =
            AdminHttpRequest::new(AdminHttpMethod::Get, "/api/v1/proxy-hosts", "req-list")
                .with_session_id("session-1");

        let response = handle_http_request(
            &request,
            AdminHttpContext {
                snapshot: &snapshot,
                sessions: &sessions,
            },
        );

        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("\"proxy_hosts\":["));
        assert!(response.body.contains("\"id\":\"app\""));
        assert!(response.body.contains("\"name\":\"app\""));
        assert!(response.body.contains("\"domains\":[\"app.example.com\"]"));
        assert!(response.body.contains("\"path_prefix\":\"/app\""));
        assert!(response
            .body
            .contains("\"upstream_url\":\"http://127.0.0.1:4000\""));
        assert!(response.body.contains("\"https_enabled\":true"));
        assert!(response.body.contains("\"letsencrypt_enabled\":true"));
        assert!(response.body.contains("\"enabled\":true"));
    }

    #[test]
    fn http_proxy_host_get_returns_generated_proxy_host() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let snapshot = snapshot_with_proxy_host();
        let request =
            AdminHttpRequest::new(AdminHttpMethod::Get, "/api/v1/proxy-hosts/app", "req-get")
                .with_session_id("session-1");

        let response = handle_http_request(
            &request,
            AdminHttpContext {
                snapshot: &snapshot,
                sessions: &sessions,
            },
        );

        assert_eq!(response.status_code, 200);
        assert!(response.body.starts_with("{\"id\":\"app\""));
        assert!(response.body.contains("\"domains\":[\"app.example.com\"]"));
        assert!(response
            .body
            .contains("\"upstream_url\":\"http://127.0.0.1:4000\""));
    }

    #[test]
    fn http_proxy_host_get_missing_returns_not_found() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let snapshot = snapshot_with_proxy_host();
        let request = AdminHttpRequest::new(
            AdminHttpMethod::Get,
            "/api/v1/proxy-hosts/missing",
            "req-get",
        )
        .with_session_id("session-1");

        let response = handle_http_request(
            &request,
            AdminHttpContext {
                snapshot: &snapshot,
                sessions: &sessions,
            },
        );

        assert_eq!(response.status_code, 404);
        assert!(response.body.contains("\"code\":\"ADMIN_ROUTE_NOT_FOUND\""));
        assert!(response.body.contains("\"request_id\":\"req-get\""));
    }

    #[test]
    fn parses_raw_http_request_with_request_id() {
        let request = parse_admin_http_request(
            "GET /api/v1/status HTTP/1.1\r\nhost: 127.0.0.1\r\nx-request-id: req-http\r\n\r\n",
            "fallback",
        )
        .unwrap();

        assert_eq!(request.method, AdminHttpMethod::Get);
        assert_eq!(request.path, "/api/v1/status");
        assert_eq!(request.request_id, "req-http");
    }

    #[test]
    fn parses_raw_http_cookie_csrf_and_body() {
        let request = parse_admin_http_request(
            "POST /api/v1/proxy-hosts HTTP/1.1\r\ncookie: theme=dark; sponzey_session=session-1\r\nx-csrf-token: csrf-1\r\n\r\n{\"id\":\"app\"}",
            "fallback",
        )
        .unwrap();

        assert_eq!(request.method, AdminHttpMethod::Post);
        assert_eq!(request.session_id.as_deref(), Some("session-1"));
        assert_eq!(request.csrf_token.as_deref(), Some("csrf-1"));
        assert_eq!(request.body, "{\"id\":\"app\"}");
    }

    #[test]
    fn renders_admin_http_response_with_status_and_content_length() {
        let response = AdminHttpResponse::json(200, "{\"ok\":true}".to_string());

        let rendered = render_admin_http_response(&response);

        assert!(rendered.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(rendered.contains("content-length: 11\r\n"));
        assert!(rendered.ends_with("\r\n\r\n{\"ok\":true}"));
    }

    #[test]
    fn http_mutation_without_session_returns_auth_required_error() {
        let sessions = SessionStore::default();
        let snapshot = snapshot();
        let request = AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/proxy-hosts", "req-1");

        let response = handle_http_request(
            &request,
            AdminHttpContext {
                snapshot: &snapshot,
                sessions: &sessions,
            },
        );

        assert_eq!(response.status_code, 401);
        assert!(response.body.contains("\"code\":\"ADMIN_AUTH_REQUIRED\""));
        assert!(response.body.contains("\"request_id\":\"req-1\""));
    }

    #[test]
    fn http_mutation_without_csrf_returns_csrf_required_error() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let snapshot = snapshot();
        let request = AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/proxy-hosts", "req-2")
            .with_session_id("session-1");

        let response = handle_http_request(
            &request,
            AdminHttpContext {
                snapshot: &snapshot,
                sessions: &sessions,
            },
        );

        assert_eq!(response.status_code, 403);
        assert!(response.body.contains("\"code\":\"ADMIN_CSRF_REQUIRED\""));
        assert!(response.body.contains("\"request_id\":\"req-2\""));
    }

    #[test]
    fn http_authenticated_mutation_reports_endpoint_not_implemented_until_bound() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let snapshot = snapshot();
        let request = AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/proxy-hosts", "req-3")
            .with_session_id("session-1")
            .with_csrf_token("csrf-1");

        let response = handle_http_request(
            &request,
            AdminHttpContext {
                snapshot: &snapshot,
                sessions: &sessions,
            },
        );

        assert_eq!(response.status_code, 501);
        assert!(response
            .body
            .contains("\"code\":\"ADMIN_ENDPOINT_NOT_IMPLEMENTED\""));
        assert!(response.body.contains("\"request_id\":\"req-3\""));
    }

    #[test]
    fn http_proxy_host_create_goes_through_lifecycle_and_core_command() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let mut lifecycle = lifecycle_with_current();
        let mut client = FakeCommandClient::default();
        let request = AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/proxy-hosts", "req-4")
            .with_session_id("session-1")
            .with_csrf_token("csrf-1")
            .with_body(
                r#"{"id":"app","name":"App","domains":["app.example.com"],"path_prefix":"/","upstream_url":"http://127.0.0.1:4000","https_enabled":false,"letsencrypt_enabled":false,"redirect_http_to_https":false,"enabled":true}"#,
            );

        let response =
            handle_proxy_host_create_http(&request, &sessions, &mut lifecycle, &mut client);

        assert_eq!(response.status_code, 200);
        assert!(response
            .body
            .contains("\"revision_id\":\"rev-1-proxy-host-app\""));
        assert!(response.body.contains("\"commands_sent\":2"));
        assert!(response.body.contains("\"restart_required\":false"));
        assert_eq!(
            lifecycle
                .revisions
                .current()
                .unwrap()
                .unwrap()
                .revision
                .id
                .as_str(),
            "rev-1-proxy-host-app"
        );
        assert!(matches!(
            client.commands.first(),
            Some(CoreCommand::ApplyConfigSnapshot { .. })
        ));
    }

    #[test]
    fn http_proxy_host_create_without_csrf_does_not_send_command() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let mut lifecycle = lifecycle_with_current();
        let mut client = FakeCommandClient::default();
        let request = AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/proxy-hosts", "req-5")
            .with_session_id("session-1")
            .with_body(
                r#"{"id":"app","name":"App","domains":["app.example.com"],"path_prefix":"/","upstream_url":"http://127.0.0.1:4000","https_enabled":false,"letsencrypt_enabled":false,"redirect_http_to_https":false,"enabled":true}"#,
            );

        let response =
            handle_proxy_host_create_http(&request, &sessions, &mut lifecycle, &mut client);

        assert_eq!(response.status_code, 403);
        assert!(response.body.contains("\"code\":\"ADMIN_CSRF_REQUIRED\""));
        assert!(client.commands.is_empty());
        assert_eq!(
            lifecycle
                .revisions
                .current()
                .unwrap()
                .unwrap()
                .revision
                .id
                .as_str(),
            "rev-1"
        );
    }

    #[test]
    fn http_proxy_host_create_invalid_body_returns_malformed_request() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let mut lifecycle = lifecycle_with_current();
        let mut client = FakeCommandClient::default();
        let request = AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/proxy-hosts", "req-6")
            .with_session_id("session-1")
            .with_csrf_token("csrf-1")
            .with_body(r#"{"id":"app"}"#);

        let response =
            handle_proxy_host_create_http(&request, &sessions, &mut lifecycle, &mut client);

        assert_eq!(response.status_code, 400);
        assert!(response
            .body
            .contains("\"code\":\"HTTP_MALFORMED_REQUEST\""));
        assert!(response.body.contains("\"request_id\":\"req-6\""));
        assert!(client.commands.is_empty());
    }

    #[test]
    fn http_proxy_host_create_invalid_upstream_returns_validation_error() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let mut lifecycle = lifecycle_with_current();
        let mut client = FakeCommandClient::default();
        let request = AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/proxy-hosts", "req-7")
            .with_session_id("session-1")
            .with_csrf_token("csrf-1")
            .with_body(
                r#"{"id":"app","name":"App","domains":["app.example.com"],"path_prefix":"/","upstream_url":"https://127.0.0.1:4000","https_enabled":false,"letsencrypt_enabled":false,"redirect_http_to_https":false,"enabled":true}"#,
            );

        let response =
            handle_proxy_host_create_http(&request, &sessions, &mut lifecycle, &mut client);

        assert_eq!(response.status_code, 400);
        assert!(response
            .body
            .contains("\"code\":\"CONFIG_INVALID_UPSTREAM_URL\""));
        assert!(client.commands.is_empty());
        assert_eq!(
            lifecycle
                .revisions
                .current()
                .unwrap()
                .unwrap()
                .revision
                .id
                .as_str(),
            "rev-1"
        );
    }

    #[test]
    fn http_config_rollback_goes_through_lifecycle_and_core_command() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let mut lifecycle = lifecycle_with_current();
        let mut client = FakeCommandClient::default();
        create_proxy_host_and_apply(
            &mut lifecycle,
            ProxyHostRequest {
                id: "app".to_string(),
                name: "App".to_string(),
                domains: vec!["app.example.com".to_string()],
                path_prefix: "/".to_string(),
                upstream_url: "http://127.0.0.1:4000".to_string(),
                upstreams: vec![],
                health_check: None,
                retry: RetryPolicy::default(),
                passive_health: PassiveHealthMode::Disabled,
                https_enabled: false,
                letsencrypt_enabled: false,
                redirect_http_to_https: false,
                enabled: true,
            },
            &mut client,
        )
        .unwrap();
        let request =
            AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/config/rollback", "req-8")
                .with_session_id("session-1")
                .with_csrf_token("csrf-1")
                .with_body(r#"{"revision_id":"rev-1"}"#);

        let response =
            handle_config_rollback_http(&request, &sessions, &mut lifecycle, &mut client);

        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("\"revision_id\":\"rev-1\""));
        assert!(response.body.contains("\"commands_sent\":2"));
        assert_eq!(
            lifecycle
                .revisions
                .current()
                .unwrap()
                .unwrap()
                .revision
                .id
                .as_str(),
            "rev-1"
        );
        assert_eq!(
            lifecycle.audit.events.last().unwrap().event,
            "config.rollback"
        );
    }

    #[test]
    fn http_config_rollback_without_csrf_does_not_send_command() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let mut lifecycle = lifecycle_with_current();
        let mut client = FakeCommandClient::default();
        let request =
            AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/config/rollback", "req-9")
                .with_session_id("session-1")
                .with_body(r#"{"revision_id":"rev-1"}"#);

        let response =
            handle_config_rollback_http(&request, &sessions, &mut lifecycle, &mut client);

        assert_eq!(response.status_code, 403);
        assert!(response.body.contains("\"code\":\"ADMIN_CSRF_REQUIRED\""));
        assert!(client.commands.is_empty());
    }

    #[test]
    fn http_config_rollback_missing_revision_returns_stable_error() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let mut lifecycle = lifecycle_with_current();
        let mut client = FakeCommandClient::default();
        let request =
            AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/config/rollback", "req-10")
                .with_session_id("session-1")
                .with_csrf_token("csrf-1")
                .with_body(r#"{"revision_id":"missing"}"#);

        let response =
            handle_config_rollback_http(&request, &sessions, &mut lifecycle, &mut client);

        assert_eq!(response.status_code, 409);
        assert!(response
            .body
            .contains("\"code\":\"CONFIG_REVISION_NOT_FOUND\""));
        assert!(client.commands.is_empty());
        assert_eq!(
            lifecycle
                .revisions
                .current()
                .unwrap()
                .unwrap()
                .revision
                .id
                .as_str(),
            "rev-1"
        );
    }

    #[test]
    fn http_config_apply_goes_through_lifecycle_and_core_command() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let mut lifecycle = lifecycle_with_current();
        let mut client = FakeCommandClient::default();
        let changed = render_mvp_config_snapshot(&snapshot())
            .replace("http://127.0.0.1:3000", "http://127.0.0.1:5000");
        let request =
            AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/config/apply", "req-apply")
                .with_session_id("session-1")
                .with_csrf_token("csrf-1")
                .with_body(changed);

        let response = handle_config_apply_http(&request, &sessions, &mut lifecycle, &mut client);

        assert_eq!(response.status_code, 200);
        assert!(response
            .body
            .contains("\"revision_id\":\"rev-1-config-apply\""));
        assert!(response.body.contains("\"commands_sent\":2"));
        let current = lifecycle.revisions.current().unwrap().unwrap();
        assert_eq!(current.revision.id.as_str(), "rev-1-config-apply");
        let service = current
            .snapshot
            .services
            .iter()
            .find(|service| service.id.as_str() == "existing")
            .unwrap();
        assert_eq!(service.upstreams[0].url, "http://127.0.0.1:5000");
        assert!(matches!(
            client.commands.first(),
            Some(CoreCommand::ApplyConfigSnapshot { .. })
        ));
    }

    #[test]
    fn http_config_apply_without_csrf_does_not_send_command() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let mut lifecycle = lifecycle_with_current();
        let mut client = FakeCommandClient::default();
        let request =
            AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/config/apply", "req-apply")
                .with_session_id("session-1")
                .with_body(render_mvp_config_snapshot(&snapshot()));

        let response = handle_config_apply_http(&request, &sessions, &mut lifecycle, &mut client);

        assert_eq!(response.status_code, 403);
        assert!(response.body.contains("\"code\":\"ADMIN_CSRF_REQUIRED\""));
        assert!(client.commands.is_empty());
        assert_eq!(
            lifecycle
                .revisions
                .current()
                .unwrap()
                .unwrap()
                .revision
                .id
                .as_str(),
            "rev-1"
        );
    }

    #[test]
    fn http_config_apply_invalid_candidate_does_not_send_command() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let mut lifecycle = lifecycle_with_current();
        let mut client = FakeCommandClient::default();
        let invalid = render_mvp_config_snapshot(&snapshot())
            .replace("http://127.0.0.1:3000", "https://127.0.0.1:3000");
        let request =
            AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/config/apply", "req-apply")
                .with_session_id("session-1")
                .with_csrf_token("csrf-1")
                .with_body(invalid);

        let response = handle_config_apply_http(&request, &sessions, &mut lifecycle, &mut client);

        assert_eq!(response.status_code, 400);
        assert!(response
            .body
            .contains("\"code\":\"CONFIG_INVALID_UPSTREAM_URL\""));
        assert!(client.commands.is_empty());
        assert_eq!(
            lifecycle
                .revisions
                .current()
                .unwrap()
                .unwrap()
                .revision
                .id
                .as_str(),
            "rev-1"
        );
    }

    #[test]
    fn http_proxy_host_delete_goes_through_lifecycle_and_core_command() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let mut lifecycle = lifecycle_with_current();
        let mut client = FakeCommandClient::default();
        create_proxy_host_and_apply(
            &mut lifecycle,
            ProxyHostRequest {
                id: "app".to_string(),
                name: "App".to_string(),
                domains: vec!["app.example.com".to_string()],
                path_prefix: "/".to_string(),
                upstream_url: "http://127.0.0.1:4000".to_string(),
                upstreams: vec![],
                health_check: None,
                retry: RetryPolicy::default(),
                passive_health: PassiveHealthMode::Disabled,
                https_enabled: false,
                letsencrypt_enabled: false,
                redirect_http_to_https: false,
                enabled: true,
            },
            &mut client,
        )
        .unwrap();
        let request =
            AdminHttpRequest::new(AdminHttpMethod::Delete, "/api/v1/proxy-hosts/app", "req-11")
                .with_session_id("session-1")
                .with_csrf_token("csrf-1");

        let response =
            handle_proxy_host_delete_http(&request, &sessions, &mut lifecycle, &mut client);

        assert_eq!(response.status_code, 200);
        assert!(response
            .body
            .contains("\"revision_id\":\"rev-1-proxy-host-app-delete-proxy-host-app\""));
        assert!(response.body.contains("\"commands_sent\":2"));
        let current = lifecycle.revisions.current().unwrap().unwrap();
        assert!(!current
            .snapshot
            .routes
            .iter()
            .any(|route| route.id.as_str() == "proxy-host-app"));
        assert!(!current
            .snapshot
            .services
            .iter()
            .any(|service| service.id.as_str() == "proxy-host-app"));
    }

    #[test]
    fn http_proxy_host_delete_without_csrf_does_not_send_command() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let mut lifecycle = lifecycle_with_current();
        let mut client = FakeCommandClient::default();
        let request =
            AdminHttpRequest::new(AdminHttpMethod::Delete, "/api/v1/proxy-hosts/app", "req-12")
                .with_session_id("session-1");

        let response =
            handle_proxy_host_delete_http(&request, &sessions, &mut lifecycle, &mut client);

        assert_eq!(response.status_code, 403);
        assert!(response.body.contains("\"code\":\"ADMIN_CSRF_REQUIRED\""));
        assert!(client.commands.is_empty());
    }

    #[test]
    fn http_proxy_host_delete_missing_id_returns_not_found_without_command() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let mut lifecycle = lifecycle_with_current();
        let mut client = FakeCommandClient::default();
        let request =
            AdminHttpRequest::new(AdminHttpMethod::Delete, "/api/v1/proxy-hosts/app", "req-13")
                .with_session_id("session-1")
                .with_csrf_token("csrf-1");

        let response =
            handle_proxy_host_delete_http(&request, &sessions, &mut lifecycle, &mut client);

        assert_eq!(response.status_code, 404);
        assert!(response.body.contains("\"code\":\"ADMIN_ROUTE_NOT_FOUND\""));
        assert!(client.commands.is_empty());
        assert_eq!(
            lifecycle
                .revisions
                .current()
                .unwrap()
                .unwrap()
                .revision
                .id
                .as_str(),
            "rev-1"
        );
    }

    #[test]
    fn http_proxy_host_update_goes_through_lifecycle_and_core_command() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let mut lifecycle = lifecycle_with_current();
        let mut client = FakeCommandClient::default();
        create_proxy_host_and_apply(
            &mut lifecycle,
            ProxyHostRequest {
                id: "app".to_string(),
                name: "App".to_string(),
                domains: vec!["app.example.com".to_string()],
                path_prefix: "/".to_string(),
                upstream_url: "http://127.0.0.1:4000".to_string(),
                upstreams: vec![],
                health_check: None,
                retry: RetryPolicy::default(),
                passive_health: PassiveHealthMode::Disabled,
                https_enabled: false,
                letsencrypt_enabled: false,
                redirect_http_to_https: false,
                enabled: true,
            },
            &mut client,
        )
        .unwrap();
        client.commands.clear();
        let request =
            AdminHttpRequest::new(AdminHttpMethod::Patch, "/api/v1/proxy-hosts/app", "req-14")
                .with_session_id("session-1")
                .with_csrf_token("csrf-1")
                .with_body(
                    r#"{"id":"app","name":"App Updated","domains":["app.example.com"],"path_prefix":"/","upstream_url":"http://127.0.0.1:5000","https_enabled":false,"letsencrypt_enabled":false,"redirect_http_to_https":false,"enabled":false}"#,
                );

        let response =
            handle_proxy_host_update_http(&request, &sessions, &mut lifecycle, &mut client);

        assert_eq!(response.status_code, 200);
        assert!(response
            .body
            .contains("\"revision_id\":\"rev-1-proxy-host-app-update-proxy-host-app\""));
        assert!(response.body.contains("\"commands_sent\":2"));
        let current = lifecycle.revisions.current().unwrap().unwrap();
        let route = current
            .snapshot
            .routes
            .iter()
            .find(|route| route.id.as_str() == "proxy-host-app")
            .unwrap();
        assert!(!route.enabled);
        let service = current
            .snapshot
            .services
            .iter()
            .find(|service| service.id.as_str() == "proxy-host-app")
            .unwrap();
        assert_eq!(service.upstreams[0].url, "http://127.0.0.1:5000");
        assert!(matches!(
            client.commands.first(),
            Some(CoreCommand::ApplyConfigSnapshot { .. })
        ));
    }

    #[test]
    fn http_proxy_host_update_without_csrf_does_not_send_command() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let mut lifecycle = lifecycle_with_current();
        let mut client = FakeCommandClient::default();
        create_proxy_host_and_apply(
            &mut lifecycle,
            ProxyHostRequest {
                id: "app".to_string(),
                name: "App".to_string(),
                domains: vec!["app.example.com".to_string()],
                path_prefix: "/".to_string(),
                upstream_url: "http://127.0.0.1:4000".to_string(),
                upstreams: vec![],
                health_check: None,
                retry: RetryPolicy::default(),
                passive_health: PassiveHealthMode::Disabled,
                https_enabled: false,
                letsencrypt_enabled: false,
                redirect_http_to_https: false,
                enabled: true,
            },
            &mut client,
        )
        .unwrap();
        client.commands.clear();
        let request =
            AdminHttpRequest::new(AdminHttpMethod::Patch, "/api/v1/proxy-hosts/app", "req-15")
                .with_session_id("session-1")
                .with_body(
                    r#"{"id":"app","name":"App Updated","domains":["app.example.com"],"path_prefix":"/","upstream_url":"http://127.0.0.1:5000","https_enabled":false,"letsencrypt_enabled":false,"redirect_http_to_https":false,"enabled":false}"#,
                );

        let response =
            handle_proxy_host_update_http(&request, &sessions, &mut lifecycle, &mut client);

        assert_eq!(response.status_code, 403);
        assert!(response.body.contains("\"code\":\"ADMIN_CSRF_REQUIRED\""));
        assert!(client.commands.is_empty());
        assert_eq!(
            lifecycle
                .revisions
                .current()
                .unwrap()
                .unwrap()
                .revision
                .id
                .as_str(),
            "rev-1-proxy-host-app"
        );
    }

    #[test]
    fn http_proxy_host_update_id_mismatch_returns_malformed_request_without_command() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let mut lifecycle = lifecycle_with_current();
        let mut client = FakeCommandClient::default();
        create_proxy_host_and_apply(
            &mut lifecycle,
            ProxyHostRequest {
                id: "app".to_string(),
                name: "App".to_string(),
                domains: vec!["app.example.com".to_string()],
                path_prefix: "/".to_string(),
                upstream_url: "http://127.0.0.1:4000".to_string(),
                upstreams: vec![],
                health_check: None,
                retry: RetryPolicy::default(),
                passive_health: PassiveHealthMode::Disabled,
                https_enabled: false,
                letsencrypt_enabled: false,
                redirect_http_to_https: false,
                enabled: true,
            },
            &mut client,
        )
        .unwrap();
        client.commands.clear();
        let request =
            AdminHttpRequest::new(AdminHttpMethod::Patch, "/api/v1/proxy-hosts/app", "req-16")
                .with_session_id("session-1")
                .with_csrf_token("csrf-1")
                .with_body(
                    r#"{"id":"other","name":"Other","domains":["app.example.com"],"path_prefix":"/","upstream_url":"http://127.0.0.1:5000","https_enabled":false,"letsencrypt_enabled":false,"redirect_http_to_https":false,"enabled":true}"#,
                );

        let response =
            handle_proxy_host_update_http(&request, &sessions, &mut lifecycle, &mut client);

        assert_eq!(response.status_code, 400);
        assert!(response
            .body
            .contains("\"code\":\"HTTP_MALFORMED_REQUEST\""));
        assert!(client.commands.is_empty());
        assert_eq!(
            lifecycle
                .revisions
                .current()
                .unwrap()
                .unwrap()
                .revision
                .id
                .as_str(),
            "rev-1-proxy-host-app"
        );
    }

    #[test]
    fn canonical_proxy_host_json_preserves_upstream_pool_and_health_policy() {
        let request = proxy_host_request_from_json(
            r#"{"id":"app","name":"App","domains":["app.example.com"],"path_prefix":"/","upstreams":[{"id":"app-a","url":"http://127.0.0.1:4000","administrative_state":"active"},{"id":"app-b","url":"http://127.0.0.1:4001","administrative_state":"draining"}],"health_check":{"enabled":true,"path":"/ready","interval_ms":2000,"timeout_ms":300,"healthy_threshold":2,"unhealthy_threshold":3,"status_min":200,"status_max":399},"retry":{"enabled":true,"max_retries":1,"max_replay_bytes":8192},"passive_health":{"enabled":true,"failure_threshold":2,"ejection_ms":5000},"https_enabled":false,"letsencrypt_enabled":false,"redirect_http_to_https":false,"enabled":true}"#,
        )
        .unwrap();

        assert_eq!(request.upstream_url, "http://127.0.0.1:4000");
        assert_eq!(
            request.upstreams,
            vec![
                ProxyHostUpstreamRequest {
                    id: "app-a".to_string(),
                    url: "http://127.0.0.1:4000".to_string(),
                    administrative_state: edge_domain::UpstreamAdministrativeState::Active,
                },
                ProxyHostUpstreamRequest {
                    id: "app-b".to_string(),
                    url: "http://127.0.0.1:4001".to_string(),
                    administrative_state: edge_domain::UpstreamAdministrativeState::Draining,
                },
            ]
        );
        assert_eq!(request.health_check.as_ref().unwrap().path, "/ready");
        assert!(request.retry.enabled);
        assert_eq!(request.retry.max_replay_bytes, 8192);
        assert!(matches!(
            request.passive_health,
            edge_domain::PassiveHealthMode::Enabled(_)
        ));
        let proxy_host = proxy_host_from_request(request);
        let parts = edge_application::proxy_host_to_parts(&proxy_host);
        assert!(parts.service.policy.retry.enabled);
        assert!(matches!(
            parts.service.policy.passive_health,
            edge_domain::PassiveHealthMode::Enabled(_)
        ));
        assert_eq!(
            parts.service.upstreams[1].administrative_state,
            edge_domain::UpstreamAdministrativeState::Draining
        );
    }

    #[test]
    fn legacy_proxy_host_json_normalizes_to_primary_upstream_without_breaking_field() {
        let request = proxy_host_request_from_json(
            r#"{"id":"app","name":"App","domains":["app.example.com"],"path_prefix":"/","upstream_url":"http://127.0.0.1:4000","https_enabled":false,"letsencrypt_enabled":false,"redirect_http_to_https":false,"enabled":true}"#,
        )
        .unwrap();

        assert_eq!(request.upstream_url, "http://127.0.0.1:4000");
        assert!(request.upstreams.is_empty());
        assert!(request.health_check.is_none());
        assert_eq!(request.retry, edge_domain::RetryPolicy::default());
        assert_eq!(
            request.passive_health,
            edge_domain::PassiveHealthMode::Disabled
        );
    }

    #[test]
    fn canonical_proxy_host_create_roundtrips_pool_and_health_through_config_lifecycle() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let mut lifecycle = lifecycle_with_current();
        let mut client = FakeCommandClient::default();
        let request = AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/proxy-hosts", "req-pool")
            .with_session_id("session-1")
            .with_csrf_token("csrf-1")
            .with_body(
                r#"{"id":"app","name":"App","domains":["app.example.com"],"path_prefix":"/","upstreams":[{"id":"app-a","url":"http://127.0.0.1:4000"},{"id":"app-b","url":"http://127.0.0.1:4001"}],"health_check":{"enabled":true,"path":"/ready","interval_ms":2000,"timeout_ms":300,"healthy_threshold":2,"unhealthy_threshold":3,"status_min":200,"status_max":399},"https_enabled":false,"letsencrypt_enabled":false,"redirect_http_to_https":false,"enabled":true}"#,
            );

        let response =
            handle_proxy_host_create_http(&request, &sessions, &mut lifecycle, &mut client);

        assert_eq!(response.status_code, 200, "body={}", response.body);
        let current = lifecycle.revisions.current().unwrap().unwrap();
        let service = current
            .snapshot
            .services
            .iter()
            .find(|service| service.id.as_str() == "proxy-host-app")
            .unwrap();
        assert_eq!(
            service
                .upstreams
                .iter()
                .map(|upstream| upstream.id.as_str())
                .collect::<Vec<_>>(),
            vec!["app-a", "app-b"]
        );
        assert!(matches!(
            service.policy.health_check,
            HealthCheckPolicy::Http(ref policy) if policy.path == "/ready"
        ));
        let rendered = proxy_host_list_response_json(&proxy_hosts_from_snapshot(&current.snapshot));
        assert!(rendered.contains("\"upstreams\":[{\"id\":\"app-a\""));
        assert!(rendered.contains("\"health_check\":{\"enabled\":true"));
        assert!(rendered.contains("\"upstream_url\":\"http://127.0.0.1:4000\""));
    }

    #[test]
    fn http_setup_writes_password_hash_and_enables_login() {
        let mut sessions = SessionStore::default();
        let mut authenticator = None;
        let mut secrets = MemorySecretStore::default();
        let snapshot = snapshot();
        let setup = AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/setup", "req-setup")
            .with_body("{\"password_hash\":\"hash\"}");

        let setup_response = handle_stateful_http_request(
            &setup,
            AdminHttpRuntimeContext {
                snapshot: &snapshot,
                sessions: &mut sessions,
                authenticator: &mut authenticator,
                secrets: &mut secrets,
            },
        );

        assert_eq!(setup_response.status_code, 200);
        assert!(setup_response.body.contains("\"setup_complete\":true"));
        assert_eq!(
            secrets
                .load_secret("admin-password-hash")
                .unwrap()
                .unwrap()
                .value,
            "hash"
        );

        let login = AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/login", "req-login")
            .with_body("{\"password_hash\":\"hash\"}");
        let login_response = handle_stateful_http_request(
            &login,
            AdminHttpRuntimeContext {
                snapshot: &snapshot,
                sessions: &mut sessions,
                authenticator: &mut authenticator,
                secrets: &mut secrets,
            },
        );

        assert_eq!(login_response.status_code, 200);
        assert!(login_response.body.contains("\"csrf_token\":\"csrf-1\""));
    }

    #[test]
    fn http_setup_rejects_after_password_hash_exists() {
        let mut sessions = SessionStore::default();
        let mut authenticator = None;
        let mut secrets = MemorySecretStore::default();
        secrets
            .save_secret(SecretRecord {
                name: "admin-password-hash".to_string(),
                value: "hash".to_string(),
            })
            .unwrap();
        let snapshot = snapshot();
        let setup = AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/setup", "req-setup")
            .with_body("{\"password_hash\":\"new\"}");

        let response = handle_stateful_http_request(
            &setup,
            AdminHttpRuntimeContext {
                snapshot: &snapshot,
                sessions: &mut sessions,
                authenticator: &mut authenticator,
                secrets: &mut secrets,
            },
        );

        assert_eq!(response.status_code, 409);
        assert!(response
            .body
            .contains("\"code\":\"ADMIN_SETUP_ALREADY_COMPLETE\""));
    }

    #[test]
    fn http_login_before_setup_returns_setup_required() {
        let mut sessions = SessionStore::default();
        let mut authenticator = None;
        let mut secrets = MemorySecretStore::default();
        let snapshot = snapshot();
        let login = AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/login", "req-login")
            .with_body("{\"password_hash\":\"hash\"}");

        let response = handle_stateful_http_request(
            &login,
            AdminHttpRuntimeContext {
                snapshot: &snapshot,
                sessions: &mut sessions,
                authenticator: &mut authenticator,
                secrets: &mut secrets,
            },
        );

        assert_eq!(response.status_code, 403);
        assert!(response.body.contains("\"code\":\"ADMIN_SETUP_REQUIRED\""));
    }

    #[test]
    fn http_login_success_emits_secure_cookie_and_csrf_json() {
        let mut sessions = SessionStore::default();
        let mut authenticator = Some(AdminAuthenticator::new("hash"));
        let mut secrets = MemorySecretStore::default();
        let snapshot = snapshot();
        let request = AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/login", "req-login")
            .with_body("{\"password_hash\":\"hash\"}");

        let response = handle_stateful_http_request(
            &request,
            AdminHttpRuntimeContext {
                snapshot: &snapshot,
                sessions: &mut sessions,
                authenticator: &mut authenticator,
                secrets: &mut secrets,
            },
        );

        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("\"csrf_token\":\"csrf-1\""));
        assert!(response.headers.contains(&(
            "set-cookie".to_string(),
            "sponzey_session=session-1; Path=/; HttpOnly; Secure; SameSite=Strict".to_string()
        )));
        assert!(sessions.verify("session-1"));
    }

    #[test]
    fn http_login_failure_returns_stable_auth_error() {
        let mut sessions = SessionStore::default();
        let mut authenticator = Some(AdminAuthenticator::new("hash"));
        let mut secrets = MemorySecretStore::default();
        let snapshot = snapshot();
        let request = AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/login", "req-login")
            .with_body("{\"password_hash\":\"wrong\"}");

        let response = handle_stateful_http_request(
            &request,
            AdminHttpRuntimeContext {
                snapshot: &snapshot,
                sessions: &mut sessions,
                authenticator: &mut authenticator,
                secrets: &mut secrets,
            },
        );

        assert_eq!(response.status_code, 401);
        assert!(response
            .body
            .contains("\"code\":\"ADMIN_INVALID_CREDENTIALS\""));
        assert!(!sessions.verify("session-1"));
    }

    #[test]
    fn http_login_lockout_rejects_after_repeated_failures() {
        let mut sessions = SessionStore::default();
        let mut authenticator = Some(AdminAuthenticator::new("hash"));
        let mut secrets = MemorySecretStore::default();
        let snapshot = snapshot();
        let request = AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/login", "req-login")
            .with_body("{\"password_hash\":\"wrong\"}");

        for _ in 0..5 {
            let response = handle_stateful_http_request(
                &request,
                AdminHttpRuntimeContext {
                    snapshot: &snapshot,
                    sessions: &mut sessions,
                    authenticator: &mut authenticator,
                    secrets: &mut secrets,
                },
            );
            assert_eq!(response.status_code, 401);
        }

        let response = handle_stateful_http_request(
            &request,
            AdminHttpRuntimeContext {
                snapshot: &snapshot,
                sessions: &mut sessions,
                authenticator: &mut authenticator,
                secrets: &mut secrets,
            },
        );

        assert_eq!(response.status_code, 401);
        assert!(response.body.contains("too many failed attempts"));
        assert!(!sessions.verify("session-1"));
    }

    #[test]
    fn http_logout_requires_csrf_and_invalidates_session() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        let mut authenticator = Some(AdminAuthenticator::new("hash"));
        let mut secrets = MemorySecretStore::default();
        let snapshot = snapshot();
        let missing_csrf =
            AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/logout", "req-logout")
                .with_session_id("session-1");

        let rejected = handle_stateful_http_request(
            &missing_csrf,
            AdminHttpRuntimeContext {
                snapshot: &snapshot,
                sessions: &mut sessions,
                authenticator: &mut authenticator,
                secrets: &mut secrets,
            },
        );

        assert_eq!(rejected.status_code, 403);
        assert!(sessions.verify("session-1"));

        let request = AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/logout", "req-logout")
            .with_session_id("session-1")
            .with_csrf_token("csrf-1");

        let response = handle_stateful_http_request(
            &request,
            AdminHttpRuntimeContext {
                snapshot: &snapshot,
                sessions: &mut sessions,
                authenticator: &mut authenticator,
                secrets: &mut secrets,
            },
        );

        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("\"logged_out\":true"));
        assert!(response.headers.contains(&(
            "set-cookie".to_string(),
            "sponzey_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict".to_string()
        )));
        assert!(!sessions.verify("session-1"));
    }

    #[test]
    fn create_proxy_host_goes_through_config_lifecycle_and_core_command() {
        let mut client = FakeCommandClient::default();
        let mut lifecycle = lifecycle_with_current();

        let response = create_proxy_host_and_apply(
            &mut lifecycle,
            ProxyHostRequest {
                id: "app".to_string(),
                name: "App".to_string(),
                domains: vec!["app.example.com".to_string()],
                path_prefix: "/".to_string(),
                upstream_url: "http://127.0.0.1:4000".to_string(),
                upstreams: vec![],
                health_check: None,
                retry: RetryPolicy::default(),
                passive_health: PassiveHealthMode::Disabled,
                https_enabled: false,
                letsencrypt_enabled: false,
                redirect_http_to_https: false,
                enabled: true,
            },
            &mut client,
        )
        .unwrap();

        assert_eq!(response.commands_sent, 2);
        assert!(!response.restart_required);
        assert_eq!(
            lifecycle
                .revisions
                .current()
                .unwrap()
                .unwrap()
                .revision
                .id
                .as_str(),
            response.revision_id
        );
        assert_eq!(lifecycle.audit.events[0].event, "config.apply");
        assert!(matches!(
            client.commands.first(),
            Some(CoreCommand::ApplyConfigSnapshot { .. })
        ));
    }

    #[test]
    fn invalid_proxy_host_returns_validation_error() {
        let mut client = FakeCommandClient::default();
        let mut lifecycle = lifecycle_with_current();

        let error = create_proxy_host_and_apply(
            &mut lifecycle,
            ProxyHostRequest {
                id: "app".to_string(),
                name: "App".to_string(),
                domains: vec!["app.example.com".to_string()],
                path_prefix: "/".to_string(),
                upstream_url: "https://127.0.0.1:4000".to_string(),
                upstreams: vec![],
                health_check: None,
                retry: RetryPolicy::default(),
                passive_health: PassiveHealthMode::Disabled,
                https_enabled: false,
                letsencrypt_enabled: false,
                redirect_http_to_https: false,
                enabled: true,
            },
            &mut client,
        )
        .unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigInvalidUpstreamUrl);
        assert!(client.commands.is_empty());
        assert_eq!(
            lifecycle
                .revisions
                .current()
                .unwrap()
                .unwrap()
                .revision
                .id
                .as_str(),
            "rev-1"
        );
    }

    #[test]
    fn rollback_goes_through_config_lifecycle_and_core_command() {
        let mut client = FakeCommandClient::default();
        let mut lifecycle = lifecycle_with_current();
        create_proxy_host_and_apply(
            &mut lifecycle,
            ProxyHostRequest {
                id: "app".to_string(),
                name: "App".to_string(),
                domains: vec!["app.example.com".to_string()],
                path_prefix: "/".to_string(),
                upstream_url: "http://127.0.0.1:4000".to_string(),
                upstreams: vec![],
                health_check: None,
                retry: RetryPolicy::default(),
                passive_health: PassiveHealthMode::Disabled,
                https_enabled: false,
                letsencrypt_enabled: false,
                redirect_http_to_https: false,
                enabled: true,
            },
            &mut client,
        )
        .unwrap();

        let response =
            rollback(ConfigRevisionId::new("rev-1"), &mut lifecycle, &mut client).unwrap();

        assert_eq!(response.revision_id, "rev-1");
        assert_eq!(response.commands_sent, 2);
        assert_eq!(
            lifecycle
                .revisions
                .current()
                .unwrap()
                .unwrap()
                .revision
                .id
                .as_str(),
            "rev-1"
        );
        assert_eq!(
            lifecycle.audit.events.last().unwrap().event,
            "config.rollback"
        );
    }

    #[test]
    fn core_command_rejection_maps_to_api_error() {
        let mut client = FakeCommandClient {
            reject: true,
            ..FakeCommandClient::default()
        };
        let mut lifecycle = lifecycle_with_current();

        let error =
            rollback(ConfigRevisionId::new("rev-1"), &mut lifecycle, &mut client).unwrap_err();

        assert_eq!(error.code, ErrorCode::RuntimeCommandRejected);
    }

    #[derive(Clone)]
    struct FakeMetricSnapshotReader(Arc<MetricSnapshot>);

    impl MetricSnapshotReaderPort for FakeMetricSnapshotReader {
        fn read_metric_snapshot(&self) -> Result<Arc<MetricSnapshot>, AppError> {
            Ok(Arc::clone(&self.0))
        }
    }

    fn authenticated_sessions() -> SessionStore {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session-1".to_string(),
            csrf_token: "csrf-1".to_string(),
        });
        sessions
    }

    #[test]
    fn audit_query_requires_session_and_accepts_bounded_read_only_query() {
        let reader = FakeAuditReader {
            called: Cell::new(0),
        };
        let sessions = authenticated_sessions();
        let unauthenticated = handle_audit_query_http(
            &AdminHttpRequest::new(AdminHttpMethod::Get, "/api/v1/audit", "audit-unauth"),
            &sessions,
            &reader,
        );
        assert_eq!(unauthenticated.status_code, 401);
        assert_eq!(reader.called.get(), 0);

        let response = handle_audit_query_http(
            &AdminHttpRequest::new(
                AdminHttpMethod::Get,
                "/api/v1/audit?limit=25&action=config.apply&outcome=succeeded",
                "audit-query",
            )
            .with_session_id("session-1"),
            &sessions,
            &reader,
        );
        assert_eq!(response.status_code, 200);
        assert_eq!(reader.called.get(), 1);
        assert!(response.body.contains("\"generation\":3"));
        assert!(response.body.contains("\"admission_state\":\"degraded\""));
        assert!(response.body.contains("\"records\":[]"));
    }

    #[test]
    fn audit_query_rejects_unknown_duplicate_oversized_and_tampered_inputs() {
        let reader = FakeAuditReader {
            called: Cell::new(0),
        };
        let sessions = authenticated_sessions();
        for path in [
            "/api/v1/audit?unknown=value",
            "/api/v1/audit?limit=1&limit=2",
            "/api/v1/audit?limit=101",
            "/api/v1/audit?from=20&to=10",
            "/api/v1/audit?cursor=v1.tampered",
            "/api/v1/audit?action=config%2Eapply",
        ] {
            let response = handle_audit_query_http(
                &AdminHttpRequest::new(AdminHttpMethod::Get, path, "audit-invalid")
                    .with_session_id("session-1"),
                &sessions,
                &reader,
            );
            assert_eq!(response.status_code, 400, "path={path}");
        }
        assert_eq!(reader.called.get(), 0);
    }

    #[test]
    fn audit_cursor_codec_is_fixed_width_and_roundtrips_generation_and_sequence() {
        let cursor = edge_domain::AuditCursor {
            ledger_generation: 9,
            before_sequence: 42,
        };
        let encoded = encode_audit_cursor(cursor);
        assert_eq!(encoded.len(), 35);
        assert_eq!(decode_audit_cursor(&encoded).unwrap(), cursor);
        assert_eq!(
            decode_audit_cursor("v1.0000000000000009000000000000002x")
                .unwrap_err()
                .code,
            ErrorCode::AuditCursorInvalid
        );
    }

    #[test]
    fn metrics_summary_requires_session_and_rejects_query_parameters() {
        let reader = FakeMetricSnapshotReader(Arc::new(MetricSnapshot::default()));
        let sessions = authenticated_sessions();

        let unauthenticated = handle_metrics_http(
            &AdminHttpRequest::new(AdminHttpMethod::Get, "/api/v1/metrics", "req-metrics-1"),
            &sessions,
            &reader,
        );
        let query = handle_metrics_http(
            &AdminHttpRequest::new(
                AdminHttpMethod::Get,
                "/api/v1/metrics?name=requests",
                "req-metrics-2",
            )
            .with_session_id("session-1"),
            &sessions,
            &reader,
        );

        assert_eq!(unauthenticated.status_code, 401);
        assert_eq!(query.status_code, 400);
        assert!(query.body.contains("HTTP_MALFORMED_REQUEST"));
    }

    #[test]
    fn metrics_summary_maps_snapshot_and_bounds_each_array_to_500_series() {
        let series = (0..501)
            .map(|index| edge_application::MetricSeries {
                key: edge_application::MetricSeriesKey {
                    descriptor: edge_ports::MetricDescriptor::RequestsTotal,
                    labels: vec![
                        ("route_id".to_string(), format!("route-{index}")),
                        ("status_class".to_string(), "2xx".to_string()),
                    ],
                },
                value: MetricSeriesValue::Counter(index),
            })
            .collect();
        let reader = FakeMetricSnapshotReader(Arc::new(MetricSnapshot {
            series,
            estimated_encoded_bytes: 42,
            desired_generation: 7,
            applied_generation: 7,
            ready: true,
            ..MetricSnapshot::default()
        }));

        let response = handle_metrics_http(
            &AdminHttpRequest::new(AdminHttpMethod::Get, "/api/v1/metrics", "req-metrics-3")
                .with_session_id("session-1"),
            &authenticated_sessions(),
            &reader,
        );

        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("\"ready\":true"));
        assert!(response.body.contains("\"desired_generation\":7"));
        assert!(response.body.contains("\"estimated_encoded_bytes\":42"));
        assert_eq!(
            response.body.matches("sponzey_edge_requests_total").count(),
            500
        );
        assert!(!response.body.contains("route-500"));
    }

    struct FakeSupportCollector;
    impl SupportBundleCollector for FakeSupportCollector {
        fn collect_support_bundle(
            &mut self,
            request: SupportBundleRequest,
        ) -> Result<edge_ports::SupportBundleReport, AppError> {
            assert_eq!(request.artifacts.len(), 6);
            assert_eq!(request.bounds, default_support_bundle_bounds());
            Ok(edge_ports::SupportBundleReport {
                archive: edge_domain::SupportBundleArchiveReceipt {
                    archive_id: "archive-safe".into(),
                    digest_sha256: [0xab; 32],
                    redaction_applied: true,
                },
                collected_artifacts: vec![SupportBundleArtifact::VersionManifest],
                total_bytes: 42,
                oldest_collected_log_age_seconds: None,
                omissions: vec![],
            })
        }
    }

    #[test]
    fn support_bundle_api_requires_session_and_csrf_and_exposes_only_safe_receipt_fields() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session".into(),
            csrf_token: "csrf".into(),
        });
        assert_eq!(
            create_support_bundle(&sessions, None, None, FakeSupportCollector)
                .unwrap_err()
                .code,
            ErrorCode::AdminAuthRequired
        );
        assert_eq!(
            create_support_bundle(&sessions, Some("session"), None, FakeSupportCollector)
                .unwrap_err()
                .code,
            ErrorCode::AdminCsrfRequired
        );
        let response = create_support_bundle(
            &sessions,
            Some("session"),
            Some("csrf"),
            FakeSupportCollector,
        )
        .unwrap();
        assert_eq!(response.archive_id, "archive-safe");
        assert_eq!(response.digest_sha256, "ab".repeat(32));
        assert_eq!(response.collected_artifacts, ["version_manifest"]);
        assert_eq!(response.total_bytes, 42);
    }
}
