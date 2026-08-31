//! Pure conversion and immutable snapshot updates for Admin proxy-host values.

use edge_domain::{
    CertificateRef, ConfigSnapshot, LoadBalancingPolicy, ProxyHost, ProxyHostId, Route, RouteId,
    RouteMatch, Service, ServiceId, Upstream, UpstreamId, UpstreamTlsPolicy,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyHostParts {
    pub route: Route,
    pub service: Service,
}

/// Converts the Admin-facing proxy-host value into the canonical route and service pair.
pub fn proxy_host_to_parts(proxy_host: &ProxyHost) -> ProxyHostParts {
    let route_id = RouteId::new(format!("proxy-host-{}", proxy_host.id.as_str()));
    let service_id = ServiceId::new(format!("proxy-host-{}", proxy_host.id.as_str()));
    let upstream_id = UpstreamId::new(format!("proxy-host-{}-primary", proxy_host.id.as_str()));
    let upstreams = if proxy_host.upstreams.is_empty() {
        vec![Upstream {
            id: upstream_id,
            url: proxy_host.upstream_url.clone(),
            administrative_state: edge_domain::UpstreamAdministrativeState::Active,
            tls: UpstreamTlsPolicy::Disabled,
        }]
    } else {
        proxy_host.upstreams.clone()
    };
    let certificate_ref = proxy_host
        .https_enabled
        .then(|| CertificateRef::new(format!("proxy-host-{}", proxy_host.id.as_str())));

    ProxyHostParts {
        route: Route {
            id: route_id,
            route_match: RouteMatch::new(
                proxy_host.domains.clone(),
                vec![proxy_host.path_prefix.clone()],
            ),
            service_id: service_id.clone(),
            priority: 100,
            enabled: proxy_host.enabled,
            redirect_http_to_https: proxy_host.redirect_http_to_https,
            certificate_resolver_id: proxy_host
                .letsencrypt_enabled
                .then(|| edge_domain::CertificateResolverId::new("letsencrypt-http01")),
            certificate_ref,
        },
        service: Service {
            policy: edge_domain::ServicePolicy {
                load_balancing: LoadBalancingPolicy::RoundRobin,
                health_check: proxy_host.health_check.clone(),
                retry: proxy_host.retry,
                passive_health: proxy_host.passive_health,
            },
            id: service_id,
            upstreams,
        },
    }
}

/// Replaces the generated route and service in a new immutable snapshot.
pub fn add_proxy_host(snapshot: &ConfigSnapshot, proxy_host: &ProxyHost) -> ConfigSnapshot {
    let mut next = snapshot.clone();
    let parts = proxy_host_to_parts(proxy_host);
    next.routes.retain(|route| route.id != parts.route.id);
    next.services
        .retain(|service| service.id != parts.service.id);
    next.routes.push(parts.route);
    next.services.push(parts.service);
    next
}

pub fn update_proxy_host(snapshot: &ConfigSnapshot, proxy_host: &ProxyHost) -> ConfigSnapshot {
    add_proxy_host(snapshot, proxy_host)
}

pub fn remove_proxy_host(snapshot: &ConfigSnapshot, id: &ProxyHostId) -> ConfigSnapshot {
    let mut next = snapshot.clone();
    let generated = format!("proxy-host-{}", id.as_str());
    next.routes.retain(|route| route.id.as_str() != generated);
    next.services
        .retain(|service| service.id.as_str() != generated);
    next
}

pub fn set_proxy_host_enabled(
    snapshot: &ConfigSnapshot,
    id: &ProxyHostId,
    enabled: bool,
) -> ConfigSnapshot {
    let mut next = snapshot.clone();
    let generated = format!("proxy-host-{}", id.as_str());
    for route in &mut next.routes {
        if route.id.as_str() == generated {
            route.enabled = enabled;
        }
    }
    next
}
