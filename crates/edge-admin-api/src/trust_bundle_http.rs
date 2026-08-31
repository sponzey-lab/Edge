//! Admin trust-bundle HTTP adaptation.

use edge_domain::{AppError, ErrorCode, TrustBundleRef};

use crate::{
    error_response, http_status_for_error, json_string_field, require_csrf, require_session,
    trust_bundle_list_json, trust_bundle_metadata_json, AdminHttpMethod, AdminHttpRequest,
    AdminHttpResponse, SessionStore, TrustBundleAdminService,
};

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
