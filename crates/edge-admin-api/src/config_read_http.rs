//! Read-only Admin configuration HTTP adaptation.

use edge_application::diff_config;
use edge_domain::{AppError, ConfigRevisionId, ConfigSnapshot, ErrorCode};

use crate::{
    config_diff_response_json, config_response_json, config_validation_response_json,
    error_response, parse_valid_config_source, require_session, validate_config_source,
    AdminHttpMethod, AdminHttpRequest, AdminHttpResponse, SessionStore,
};

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
        Ok(next) => AdminHttpResponse::json(
            200,
            config_diff_response_json(Some(&diff_config(Some(current), &next)), &[]),
        ),
        Err(errors) => AdminHttpResponse::json(200, config_diff_response_json(None, &errors)),
    }
}
