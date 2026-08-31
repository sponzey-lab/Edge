//! Proxy-host member-path parsing for the Admin API v1 contract.

use edge_domain::{AppError, ErrorCode, ProxyHostId};

pub fn proxy_host_id_from_delete_path(path: &str) -> Result<ProxyHostId, AppError> {
    proxy_host_id_from_member_path(path)
}

pub fn proxy_host_id_from_update_path(path: &str) -> Result<ProxyHostId, AppError> {
    proxy_host_id_from_member_path(path)
}

pub fn proxy_host_id_from_get_path(path: &str) -> Result<ProxyHostId, AppError> {
    proxy_host_id_from_member_path(path)
}

fn proxy_host_id_from_member_path(path: &str) -> Result<ProxyHostId, AppError> {
    let Some(id) = path.strip_prefix("/api/v1/proxy-hosts/") else {
        return Err(AppError::new(
            ErrorCode::AdminRouteNotFound,
            "admin http route not found",
        ));
    };
    if id.is_empty() || id.contains('/') {
        return Err(AppError::new(
            ErrorCode::AdminRouteNotFound,
            "proxy host route requires a single id segment",
        ));
    }
    Ok(ProxyHostId::new(id.to_string()))
}
