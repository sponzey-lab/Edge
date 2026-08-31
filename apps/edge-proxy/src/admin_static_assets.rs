//! Embedded Admin Web UI static-asset response projection.
//!
//! This module maps only GET requests for the bundled UI assets. It does not
//! parse HTTP, authenticate requests, choose cache policy, or access the network.

use edge_admin_api::{AdminHttpMethod, AdminHttpRequest, AdminHttpResponse};

pub(crate) fn handle_static_admin_asset(request: &AdminHttpRequest) -> Option<AdminHttpResponse> {
    if request.method != AdminHttpMethod::Get {
        return None;
    }
    let path = request
        .path
        .split('?')
        .next()
        .unwrap_or(request.path.as_str());
    let (content_type, body) = match path {
        "/" | "/index.html" => (
            "text/html; charset=utf-8",
            include_str!("../../admin-web/index.html"),
        ),
        "/styles.css" => (
            "text/css; charset=utf-8",
            include_str!("../../admin-web/styles.css"),
        ),
        "/app.js" => (
            "application/javascript; charset=utf-8",
            include_str!("../../admin-web/app.js"),
        ),
        _ => return None,
    };
    Some(AdminHttpResponse {
        status_code: 200,
        headers: vec![("content-type".to_string(), content_type.to_string())],
        body: body.to_string(),
        error_code: None,
    })
}
