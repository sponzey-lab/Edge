//! Admin config apply and rollback HTTP adaptation.

use edge_application::ConfigLifecycle;
use edge_domain::{AppError, ErrorCode};
use edge_ports::{AuditSink, ConfigRevisionRepository, CoreCommandClient};

use crate::{
    apply_config_source, apply_response_json, error_response, http_status_for_error, require_csrf,
    require_session, rollback, rollback_request_revision_id_from_json, AdminHttpMethod,
    AdminHttpRequest, AdminHttpResponse, SessionStore,
};

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
