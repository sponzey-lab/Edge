//! Read-only Admin status HTTP adaptation.

use edge_domain::ConfigSnapshot;
use edge_ports::RuntimeResourceStatusSnapshot;

use crate::{status_response_json, status_response_with_active_and_resource, AdminHttpResponse};

pub fn handle_status_http(desired: &ConfigSnapshot, active: &ConfigSnapshot) -> AdminHttpResponse {
    handle_status_http_with_resource(desired, active, None)
}

pub fn handle_status_http_with_resource(
    desired: &ConfigSnapshot,
    active: &ConfigSnapshot,
    live_resource_status: Option<RuntimeResourceStatusSnapshot>,
) -> AdminHttpResponse {
    AdminHttpResponse::json(
        200,
        status_response_json(&status_response_with_active_and_resource(
            desired,
            active,
            live_resource_status,
        )),
    )
}
