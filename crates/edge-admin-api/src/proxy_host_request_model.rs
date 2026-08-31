//! Proxy-host request values and pure conversion into the domain model.

use edge_domain::{
    HealthCheckPolicy, HostMatch, HttpHealthCheckPolicy, PassiveHealthMode, PathMatch, ProxyHost,
    ProxyHostId, RetryPolicy, Upstream, UpstreamAdministrativeState, UpstreamId,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyHostRequest {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyHostUpstreamRequest {
    pub id: String,
    pub url: String,
    pub administrative_state: UpstreamAdministrativeState,
}

pub fn proxy_host_from_request(request: ProxyHostRequest) -> ProxyHost {
    ProxyHost {
        id: ProxyHostId::new(request.id),
        name: request.name,
        domains: request.domains.iter().map(HostMatch::exact).collect(),
        path_prefix: PathMatch::prefix(request.path_prefix),
        upstream_url: request.upstream_url,
        upstreams: request
            .upstreams
            .into_iter()
            .map(|upstream| Upstream {
                id: UpstreamId::new(upstream.id),
                url: upstream.url,
                administrative_state: upstream.administrative_state,
                tls: edge_domain::UpstreamTlsPolicy::Disabled,
            })
            .collect(),
        health_check: request
            .health_check
            .map(HealthCheckPolicy::Http)
            .unwrap_or(HealthCheckPolicy::Disabled),
        retry: request.retry,
        passive_health: request.passive_health,
        https_enabled: request.https_enabled,
        letsencrypt_enabled: request.letsencrypt_enabled,
        redirect_http_to_https: request.redirect_http_to_https,
        enabled: request.enabled,
    }
}
