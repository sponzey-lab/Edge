//! Admin health, operational-probe, and upstream-health HTTP adaptation.

use edge_domain::{AppError, ConfigSnapshot, ErrorCode, OperationalLifecycle, ProbeStatus};
use edge_ports::{HealthStatusReader, RuntimeUpstreamStatusReader};

use crate::{
    error_response, health_response, health_response_json, http_status_for_error, require_session,
    upstream_health_status_response, upstream_health_status_response_json, AdminHttpMethod,
    AdminHttpRequest, AdminHttpResponse, SessionStore,
};

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

/// Renders the unauthenticated operational probe payload without config details.
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
            )
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
