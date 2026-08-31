//! Read-only Admin runtime-metrics HTTP adaptation.

use edge_application::MetricSnapshotReaderPort;
use edge_domain::{AppError, ErrorCode};

use crate::{
    error_response, http_status_for_error, metrics_summary_json, require_session, AdminHttpMethod,
    AdminHttpRequest, AdminHttpResponse, SessionStore,
};

pub fn handle_metrics_http(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    reader: &dyn MetricSnapshotReaderPort,
) -> AdminHttpResponse {
    if request.method != AdminHttpMethod::Get {
        return error_response(
            404,
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found"),
            &request.request_id,
        );
    }
    if request.path != "/api/v1/metrics" {
        let error = if request.path.starts_with("/api/v1/metrics?") {
            AppError::new(
                ErrorCode::HttpMalformedRequest,
                "metrics query parameters are not supported",
            )
        } else {
            AppError::new(ErrorCode::AdminRouteNotFound, "admin http route not found")
        };
        return error_response(
            if error.code == ErrorCode::HttpMalformedRequest {
                400
            } else {
                404
            },
            error,
            &request.request_id,
        );
    }
    if let Err(error) = require_session(sessions, request.session_id.as_deref()) {
        return error_response(401, error, &request.request_id);
    }
    match reader.read_metric_snapshot() {
        Ok(snapshot) => AdminHttpResponse::json(200, metrics_summary_json(&snapshot)),
        Err(error) => error_response(http_status_for_error(&error), error, &request.request_id),
    }
}
