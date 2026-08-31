//! Admin API adapter boundary.
//!
//! This crate defines the API contract, authentication/session rules, and the
//! CoreCommand boundary. A concrete HTTP server can wrap these handlers later.

#[cfg(test)]
use edge_application::default_support_bundle_bounds;
#[cfg(test)]
use edge_application::render_mvp_config_snapshot;
#[cfg(test)]
use edge_application::ConfigValidator;
#[cfg(test)]
use edge_application::MetricSnapshotReaderPort;
use edge_application::{
    add_proxy_host, certificate_status, issue_certificate_for_ref_and_install,
    issue_certificate_for_ref_with_http01_and_install, remove_proxy_host,
    renew_certificate_for_ref_and_install, update_proxy_host, CertificateIssuer,
    CertificateRenewRequest, CertificateStatus, ConfigLifecycle, ManualCertificateImportRequest,
};
#[cfg(test)]
use edge_application::{AccessLogEvent, RecentErrorEvent};
#[cfg(test)]
use edge_application::{MetricSeriesValue, MetricSnapshot};
#[cfg(test)]
use edge_domain::HealthCheckPolicy;
#[cfg(test)]
use edge_domain::OperationalLifecycle;
#[cfg(test)]
use edge_domain::SupportBundleArtifact;
use edge_domain::{
    AppError, CertificateRef, ConfigRevisionId, ConfigSnapshot, ErrorCode, ProxyHostId,
    TrustBundleRef, ValidationError,
};
#[cfg(test)]
use edge_domain::{PassiveHealthMode, RetryPolicy};
use edge_ports::{
    AcmeClient, AcmeOrderRequest, AuditSink, CertificateStore, ConfigRevisionRepository,
    CoreCommandClient, Http01ChallengeProbe, Http01ChallengeStore, TrustBundleMetadata,
};
#[cfg(test)]
use edge_ports::{SecretRecord, SecretStore, SupportBundleCollector, SupportBundleRequest};

mod http_envelope;
pub use http_envelope::*;
mod status_read_model;
pub use status_read_model::*;
mod session_auth;
mod status_http;
pub use session_auth::*;
mod error_response;
pub use error_response::*;
mod admin_json_contract;
mod audit_and_log_read_http;
mod audit_read_model;
use admin_json_contract::*;
mod certificate_read_http;
mod config_mutation_http;
mod config_read_http;
mod config_source_schema;
mod health_response_http;
mod http_dispatch;
mod manual_certificate_import_http;
mod proxy_host_member_path;
mod proxy_host_mutation_http;
mod proxy_host_read_http;
mod proxy_host_request_decoder;
mod proxy_host_request_model;
mod proxy_host_snapshot_projection;
mod runtime_metrics_http;
mod runtime_metrics_read_model;
mod stateful_session_http;
mod support_bundle_api;
mod trust_bundle_http;
pub use audit_and_log_read_http::{
    handle_access_logs_http, handle_audit_query_http, handle_error_logs_http,
};
#[cfg(test)]
use audit_read_model::{decode_audit_cursor, encode_audit_cursor};
pub use certificate_read_http::{handle_certificate_get_http, handle_certificate_list_http};
pub use config_mutation_http::{handle_config_apply_http, handle_config_rollback_http};
pub use config_read_http::{
    handle_config_diff_http, handle_config_get_http, handle_config_validate_http,
};
pub use config_source_schema::{
    parse_valid_config_source, validate_config, validate_config_source,
};
pub use health_response_http::{
    handle_health_http, handle_operational_probe_http, handle_upstream_health_http,
};
pub(crate) use http_dispatch::is_mutation_route;
pub use http_dispatch::{handle_http_request, AdminHttpContext};
pub use manual_certificate_import_http::handle_certificate_import_http;
pub use proxy_host_member_path::{
    proxy_host_id_from_delete_path, proxy_host_id_from_get_path, proxy_host_id_from_update_path,
};
pub use proxy_host_mutation_http::{
    handle_proxy_host_create_http, handle_proxy_host_delete_http, handle_proxy_host_update_http,
};
pub use proxy_host_read_http::{handle_proxy_host_get_http, handle_proxy_host_list_http};
pub use proxy_host_request_decoder::proxy_host_request_from_json;
pub use proxy_host_request_model::{
    proxy_host_from_request, ProxyHostRequest, ProxyHostUpstreamRequest,
};
pub use proxy_host_snapshot_projection::{
    proxy_host_from_snapshot, proxy_hosts_from_snapshot, ProxyHostResponse,
};
pub use runtime_metrics_http::handle_metrics_http;
use runtime_metrics_read_model::metrics_summary_json;
pub use stateful_session_http::{handle_stateful_http_request, AdminHttpRuntimeContext};
pub use status_http::{handle_status_http, handle_status_http_with_resource};
pub use support_bundle_api::*;
pub use trust_bundle_http::handle_trust_bundle_http;

/// Foundation smoke helper.
pub fn crate_name() -> &'static str {
    "edge-admin-api"
}

pub const API_VERSION_PREFIX: &str = "/api/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiResponse<T> {
    pub request_id: String,
    pub data: T,
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

fn session_cookie_header(session_id: &str) -> String {
    format!(
        "sponzey_session={}; Path=/; HttpOnly; Secure; SameSite=Strict",
        json_escape(session_id)
    )
}

fn expired_session_cookie_header() -> &'static str {
    "sponzey_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict"
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

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::Arc;

    use super::*;
    use edge_application::checksum_snapshot;
    use edge_domain::{
        AdminConfig, CertificateRef, CommandAck, ConfigRevision, ConfigRevisionId, CoreCommand,
        HealthAvailabilitySnapshot, Listener, ListenerId, ListenerProtocol, LogMode,
        RuntimeOptions, Service, ServiceId, Upstream, UpstreamId,
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
    fn status_http_renders_desired_active_and_optional_live_resource_status() {
        let active = snapshot();
        let mut desired = active.clone();
        desired.revision_id = ConfigRevisionId::new("rev-desired");
        let live = edge_ports::RuntimeResourceStatusSnapshot {
            revision_id: active.revision_id.clone(),
            generation: 9,
            used_payload_bytes: 64,
            payload_limit_bytes: 128,
            active_connections: 2,
            pressure: edge_ports::RuntimeResourcePressure::Pressured,
        };

        let response = handle_status_http_with_resource(&desired, &active, Some(live));

        assert_eq!(response.status_code, 200);
        assert!(response
            .body
            .contains("\"desired_revision_id\":\"rev-desired\""));
        assert!(response.body.contains("\"active_revision_id\":\"rev-1\""));
        assert!(response.body.contains("\"live_resource_status\":{"));
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
    fn config_source_schema_preserves_valid_snapshot_and_validation_error_contract() {
        let snapshot = snapshot();
        let source = render_mvp_config_snapshot(&snapshot);

        let parsed = parse_valid_config_source(&source, ConfigRevisionId::new("candidate"))
            .expect("rendered snapshot is valid");
        assert_eq!(parsed.revision_id.as_str(), "candidate");
        assert!(validate_config_source(&source).is_empty());

        let invalid = source.replace("http://127.0.0.1:3000", "https://127.0.0.1:3000");
        let errors = validate_config_source(&invalid);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].code, ErrorCode::ConfigInvalidUpstreamUrl);
        assert!(parse_valid_config_source(&invalid, ConfigRevisionId::new("candidate")).is_err());
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
    fn proxy_host_member_path_parsers_preserve_v1_id_and_not_found_contract() {
        for parser in [
            proxy_host_id_from_get_path,
            proxy_host_id_from_update_path,
            proxy_host_id_from_delete_path,
        ] {
            assert_eq!(parser("/api/v1/proxy-hosts/app").unwrap().as_str(), "app");

            let wrong_prefix = parser("/api/v1/routes/app").unwrap_err();
            assert_eq!(wrong_prefix.code, ErrorCode::AdminRouteNotFound);
            assert_eq!(wrong_prefix.message, "admin http route not found");

            let empty_id = parser("/api/v1/proxy-hosts/").unwrap_err();
            assert_eq!(empty_id.code, ErrorCode::AdminRouteNotFound);
            assert_eq!(
                empty_id.message,
                "proxy host route requires a single id segment"
            );

            let nested_id = parser("/api/v1/proxy-hosts/app/health").unwrap_err();
            assert_eq!(nested_id.code, ErrorCode::AdminRouteNotFound);
            assert_eq!(
                nested_id.message,
                "proxy host route requires a single id segment"
            );
        }
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
        assert!(response.body.contains("\"commands_sent\":1"));
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
        assert!(response.body.contains("\"commands_sent\":1"));
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
        assert!(response.body.contains("\"commands_sent\":1"));
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
        assert!(response.body.contains("\"commands_sent\":1"));
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
        assert!(response.body.contains("\"commands_sent\":1"));
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

        assert_eq!(response.commands_sent, 1);
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
        assert_eq!(response.commands_sent, 1);
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

    #[test]
    fn support_bundle_http_preserves_safe_success_json_and_auth_statuses() {
        let mut sessions = SessionStore::default();
        sessions.insert(Session {
            session_id: "session".into(),
            csrf_token: "csrf".into(),
        });

        let unauthorized = handle_support_bundle_http(
            &AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/support-bundle", "req-1"),
            &sessions,
            FakeSupportCollector,
        );
        assert_eq!(unauthorized.status_code, 401);
        assert_eq!(
            unauthorized.error_code.as_deref(),
            Some("ADMIN_AUTH_REQUIRED")
        );

        let csrf_required = handle_support_bundle_http(
            &AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/support-bundle", "req-2")
                .with_session_id("session"),
            &sessions,
            FakeSupportCollector,
        );
        assert_eq!(csrf_required.status_code, 403);
        assert_eq!(
            csrf_required.error_code.as_deref(),
            Some("ADMIN_CSRF_REQUIRED")
        );

        let response = handle_support_bundle_http(
            &AdminHttpRequest::new(AdminHttpMethod::Post, "/api/v1/support-bundle", "req-3")
                .with_session_id("session")
                .with_csrf_token("csrf"),
            &sessions,
            FakeSupportCollector,
        );
        assert_eq!(response.status_code, 200);
        assert_eq!(
            response.body,
            format!(
                "{{\"archive_id\":\"archive-safe\",\"digest_sha256\":\"{}\",\"collected_artifacts\":[\"version_manifest\"],\"omitted_artifacts\":[],\"total_bytes\":42}}",
                "ab".repeat(32)
            )
        );
        assert!(!response.body.contains("redaction_applied"));
    }
}
