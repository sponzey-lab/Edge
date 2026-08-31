//! Read-only Admin stored-certificate HTTP adaptation.

use edge_domain::{AppError, ErrorCode};
use edge_ports::CertificateStore;

use crate::{
    certificate_list_response_json, certificate_ref_from_get_path, certificate_status,
    certificate_status_json, certificate_statuses, error_response, http_status_for_error,
    require_session, AdminHttpMethod, AdminHttpRequest, AdminHttpResponse, SessionStore,
};

pub fn handle_certificate_list_http<S>(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    certificates: &S,
    now_epoch_seconds: u64,
    renewal_window_seconds: u64,
) -> AdminHttpResponse
where
    S: CertificateStore + ?Sized,
{
    if request.method != AdminHttpMethod::Get || request.path != "/api/v1/certificates" {
        return error_response(
            404,
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found"),
            &request.request_id,
        );
    }
    if let Err(error) = require_session(sessions, request.session_id.as_deref()) {
        return error_response(401, error, &request.request_id);
    }

    match certificates.list_certificates() {
        Ok(certificates) => {
            let statuses =
                certificate_statuses(&certificates, now_epoch_seconds, renewal_window_seconds);
            AdminHttpResponse::json(200, certificate_list_response_json(&statuses))
        }
        Err(error) => error_response(500, error, &request.request_id),
    }
}

pub fn handle_certificate_get_http<S>(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    certificates: &S,
    now_epoch_seconds: u64,
    renewal_window_seconds: u64,
) -> AdminHttpResponse
where
    S: CertificateStore + ?Sized,
{
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

    let certificate_ref = match certificate_ref_from_get_path(&request.path) {
        Ok(certificate_ref) => certificate_ref,
        Err(error) => {
            return error_response(http_status_for_error(&error), error, &request.request_id)
        }
    };
    match certificates.load_certificate(&certificate_ref) {
        Ok(Some(certificate)) => AdminHttpResponse::json(
            200,
            certificate_status_json(&certificate_status(
                &certificate,
                now_epoch_seconds,
                renewal_window_seconds,
            )),
        ),
        Ok(None) => error_response(
            404,
            AppError::new(
                ErrorCode::CertificateNotFound,
                format!("certificate not found: {}", certificate_ref.as_str()),
            ),
            &request.request_id,
        ),
        Err(error) => error_response(500, error, &request.request_id),
    }
}
