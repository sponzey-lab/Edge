//! Root Admin HTTP route dispatch and unbound-mutation gating.

use edge_domain::{AppError, ConfigSnapshot, ErrorCode};

use crate::{
    error_response, handle_config_diff_http, handle_config_get_http, handle_config_validate_http,
    handle_health_http, handle_proxy_host_get_http, handle_proxy_host_list_http,
    handle_status_http, require_csrf, require_session, AdminHttpMethod, AdminHttpRequest,
    AdminHttpResponse, SessionStore,
};

pub struct AdminHttpContext<'a> {
    pub snapshot: &'a ConfigSnapshot,
    pub sessions: &'a SessionStore,
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

pub(crate) fn is_mutation_route(method: AdminHttpMethod, path: &str) -> bool {
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
