//! Read-only Admin audit and recent-log HTTP adaptation.

use edge_application::{query_audit, AccessLogEvent, RecentErrorEvent};
use edge_domain::{AppError, ErrorCode};
use edge_ports::AuditLedgerReader;

use crate::{
    access_logs_response_json,
    audit_read_model::{audit_page_json, parse_audit_query},
    error_logs_response_json, error_response, http_status_for_error, require_session,
    AdminHttpMethod, AdminHttpRequest, AdminHttpResponse, SessionStore,
};

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
