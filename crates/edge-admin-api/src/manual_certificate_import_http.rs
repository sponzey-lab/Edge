//! Admin manual-certificate-import HTTP adaptation.

use edge_application::import_manual_certificate_and_install;
use edge_domain::{AppError, ConfigRevisionId, ErrorCode};
use edge_ports::{AuditSink, CertificateMaterialValidator, CertificateStore, CoreCommandClient};

use crate::{
    certificate_import_outcome_json, certificate_ref_from_import_path, error_response,
    http_status_for_error, manual_certificate_import_request_from_json, require_csrf,
    require_session, AdminHttpMethod, AdminHttpRequest, AdminHttpResponse, SessionStore,
};

pub fn handle_certificate_import_http<V, S, A, K>(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    revision_id: &ConfigRevisionId,
    validator: &mut V,
    certificates: &mut S,
    audit: &mut A,
    client: &mut K,
) -> AdminHttpResponse
where
    V: CertificateMaterialValidator + ?Sized,
    S: CertificateStore + ?Sized,
    A: AuditSink + ?Sized,
    K: CoreCommandClient + ?Sized,
{
    if request.method != AdminHttpMethod::Post {
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

    let certificate_ref = match certificate_ref_from_import_path(&request.path) {
        Ok(certificate_ref) => certificate_ref,
        Err(error) => {
            return error_response(http_status_for_error(&error), error, &request.request_id)
        }
    };
    let import_request = match manual_certificate_import_request_from_json(
        &request.body,
        certificate_ref,
        &request.request_id,
        revision_id,
    ) {
        Ok(import_request) => import_request,
        Err(error) => return error_response(400, error, &request.request_id),
    };

    match import_manual_certificate_and_install(
        import_request,
        validator,
        certificates,
        audit,
        client,
    ) {
        Ok(outcome) => AdminHttpResponse::json(
            200,
            certificate_import_outcome_json(&outcome, &request.request_id),
        ),
        Err(failure) => error_response(
            http_status_for_error(&failure.error),
            failure.error,
            &request.request_id,
        ),
    }
}
