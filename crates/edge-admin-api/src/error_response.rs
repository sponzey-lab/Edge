//! Stable versioned Admin API error response projection.

use edge_domain::{AppError, ErrorCode};

use crate::{json_escape, AdminHttpResponse};

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

pub fn error_response(status_code: u16, error: AppError, request_id: &str) -> AdminHttpResponse {
    let error_code = error.code.as_str().to_string();
    AdminHttpResponse::json(
        status_code,
        error_response_json(&ApiErrorResponse::from_error(error, request_id)),
    )
    .with_error_code(error_code)
}

pub fn http_status_for_error(error: &AppError) -> u16 {
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

pub fn error_response_json(response: &ApiErrorResponse) -> String {
    format!(
        "{{\"code\":\"{}\",\"message\":\"{}\",\"hint\":\"{}\",\"request_id\":\"{}\"}}",
        json_escape(&response.code),
        json_escape(&response.message),
        json_escape(&response.hint),
        json_escape(&response.request_id)
    )
}
