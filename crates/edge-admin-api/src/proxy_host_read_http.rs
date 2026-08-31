//! Read-only Admin proxy-host HTTP adaptation.

use edge_domain::{AppError, ConfigSnapshot, ErrorCode};

use crate::{
    error_response, http_status_for_error, proxy_host_from_snapshot, proxy_host_id_from_get_path,
    proxy_host_list_response_json, proxy_host_response_json, proxy_hosts_from_snapshot,
    require_session, AdminHttpMethod, AdminHttpRequest, AdminHttpResponse, SessionStore,
};

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
