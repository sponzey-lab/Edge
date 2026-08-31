//! Admin proxy-host mutation HTTP adaptation.

use edge_application::ConfigLifecycle;
use edge_domain::{AppError, ErrorCode};
use edge_ports::{AuditSink, ConfigRevisionRepository, CoreCommandClient};

use crate::{
    apply_response_json, create_proxy_host_and_apply, delete_proxy_host_and_apply, error_response,
    http_status_for_error, proxy_host_id_from_delete_path, proxy_host_id_from_update_path,
    proxy_host_request_from_json, require_csrf, require_session, update_proxy_host_and_apply,
    AdminHttpMethod, AdminHttpRequest, AdminHttpResponse, SessionStore,
};

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
