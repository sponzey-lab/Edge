//! Immutable config snapshot projection for Admin proxy-host responses.

use edge_domain::{
    AppError, ConfigSnapshot, ErrorCode, HealthCheckPolicy, HttpHealthCheckPolicy,
    PassiveHealthMode, ProxyHostId, RetryPolicy, Route,
};

use crate::ProxyHostUpstreamRequest;

/// Immutable Admin API response schema projected from a proxy-host snapshot.
///
/// Its values are derived from supplied configuration only; rendering and
/// request parsing remain separate contracts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyHostResponse {
    pub id: String,
    pub name: String,
    pub domains: Vec<String>,
    pub path_prefix: String,
    pub upstream_url: String,
    pub upstreams: Vec<ProxyHostUpstreamRequest>,
    pub health_check: Option<HttpHealthCheckPolicy>,
    pub retry: RetryPolicy,
    pub passive_health: PassiveHealthMode,
    pub https_enabled: bool,
    pub letsencrypt_enabled: bool,
    pub redirect_http_to_https: bool,
    pub enabled: bool,
}

pub fn proxy_hosts_from_snapshot(snapshot: &ConfigSnapshot) -> Vec<ProxyHostResponse> {
    let mut proxy_hosts: Vec<_> = snapshot
        .routes
        .iter()
        .filter_map(|route| proxy_host_response_from_generated_route(snapshot, route))
        .collect();
    proxy_hosts.sort_by(|left, right| left.id.cmp(&right.id));
    proxy_hosts
}

pub fn proxy_host_from_snapshot(
    snapshot: &ConfigSnapshot,
    id: &ProxyHostId,
) -> Result<ProxyHostResponse, AppError> {
    proxy_hosts_from_snapshot(snapshot)
        .into_iter()
        .find(|proxy_host| proxy_host.id == id.as_str())
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::AdminRouteNotFound,
                format!("proxy host not found: {}", id.as_str()),
            )
        })
}

fn proxy_host_response_from_generated_route(
    snapshot: &ConfigSnapshot,
    route: &Route,
) -> Option<ProxyHostResponse> {
    let id = route.id.as_str().strip_prefix("proxy-host-")?;
    if id.is_empty() {
        return None;
    }
    let service = snapshot
        .services
        .iter()
        .find(|service| service.id == route.service_id)?;
    let upstream = service.upstreams.first()?;
    let path_prefix = route.route_match.paths.first()?;
    Some(ProxyHostResponse {
        id: id.to_string(),
        name: id.to_string(),
        domains: route
            .route_match
            .hosts
            .iter()
            .map(|host| host.as_str().to_string())
            .collect(),
        path_prefix: path_prefix.as_str().to_string(),
        upstream_url: upstream.url.clone(),
        upstreams: service
            .upstreams
            .iter()
            .map(|upstream| ProxyHostUpstreamRequest {
                id: upstream.id.as_str().to_string(),
                url: upstream.url.clone(),
                administrative_state: upstream.administrative_state,
            })
            .collect(),
        health_check: match &service.policy.health_check {
            HealthCheckPolicy::Disabled => None,
            HealthCheckPolicy::Http(policy) => Some(policy.clone()),
        },
        retry: service.policy.retry,
        passive_health: service.policy.passive_health,
        https_enabled: route.certificate_ref.is_some(),
        letsencrypt_enabled: route.certificate_resolver_id.is_some(),
        redirect_http_to_https: route.redirect_http_to_https,
        enabled: route.enabled,
    })
}
