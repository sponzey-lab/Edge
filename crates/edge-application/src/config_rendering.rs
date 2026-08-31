//! Canonical text rendering of an immutable MVP configuration snapshot.

use edge_domain::{
    ClientAuthPolicy, ConfigSnapshot, HealthCheckPolicy, HostMatch, ListenerProtocol,
    PassiveHealthMode, PathMatch, UpstreamAdministrativeState, UpstreamTlsPolicy,
};

/// Renders the canonical bootstrap/file representation without reading or writing a file.
pub fn render_mvp_config_snapshot(snapshot: &ConfigSnapshot) -> String {
    let mut output = String::new();
    output.push_str(&format!("schema_version = {}\n\n", snapshot.schema_version));
    output.push_str("[admin]\n");
    output.push_str(&format!("bind = \"{}\"\n", snapshot.admin.bind));
    output.push_str("enabled = true\n\n");
    output.push_str("[logging]\n");
    output.push_str(&format!("mode = \"{}\"\n\n", snapshot.log_mode.as_str()));
    output.push_str("[runtime]\n");
    output.push_str(&format!(
        "max_connections = {}\nmax_inflight_payload_bytes = {}\nupstream_read_timeout_ms = {}\n\n",
        snapshot.runtime.max_connections,
        snapshot.runtime.max_inflight_payload_bytes,
        snapshot.runtime.upstream_read_timeout_ms,
    ));
    if snapshot.runtime.metrics.enabled {
        output.push_str("[metrics]\n");
        output.push_str("enabled = true\n");
        output.push_str(&format!("bind = \"{}\"\n\n", snapshot.runtime.metrics.bind));
    }

    for listener in &snapshot.listeners {
        output.push_str("[[listeners]]\n");
        output.push_str(&format!("name = \"{}\"\n", listener.id));
        output.push_str(&format!("bind = \"{}\"\n", listener.bind));
        let protocol = match listener.protocol {
            ListenerProtocol::Http => "http",
            ListenerProtocol::Https => "https",
        };
        output.push_str(&format!("protocol = \"{protocol}\"\n"));
        match &listener.client_auth {
            ClientAuthPolicy::Disabled => {}
            ClientAuthPolicy::Required { trust_bundle_ref } => {
                output.push_str("client_auth = \"required\"\n");
                output.push_str(&format!(
                    "client_trust_bundle_ref = \"{}\"\n",
                    trust_bundle_ref.as_str()
                ));
            }
        }
        output.push('\n');
    }

    for service in &snapshot.services {
        output.push_str("[[services]]\n");
        output.push_str(&format!("name = \"{}\"\n", service.id));
        output.push_str(&format!(
            "load_balancer = \"{}\"\n\n",
            service.policy.load_balancing.as_str()
        ));
        if let HealthCheckPolicy::Http(policy) = &service.policy.health_check {
            output.push_str("[services.health_check]\n");
            output.push_str("enabled = true\n");
            output.push_str(&format!("path = \"{}\"\n", policy.path));
            output.push_str(&format!("interval_ms = {}\n", policy.interval_ms));
            output.push_str(&format!("timeout_ms = {}\n", policy.timeout_ms));
            output.push_str(&format!(
                "healthy_threshold = {}\n",
                policy.healthy_threshold
            ));
            output.push_str(&format!(
                "unhealthy_threshold = {}\n",
                policy.unhealthy_threshold
            ));
            output.push_str(&format!("status_min = {}\n", policy.status_min));
            output.push_str(&format!("status_max = {}\n\n", policy.status_max));
        }
        output.push_str("[services.retry]\n");
        output.push_str(&format!("enabled = {}\n", service.policy.retry.enabled));
        output.push_str(&format!(
            "max_retries = {}\n",
            service.policy.retry.max_retries
        ));
        output.push_str(&format!(
            "max_replay_bytes = {}\n\n",
            service.policy.retry.max_replay_bytes
        ));
        output.push_str("[services.passive_health]\n");
        let (passive_enabled, failure_threshold, ejection_ms) = match service.policy.passive_health
        {
            PassiveHealthMode::Disabled => (false, 3, 30_000),
            PassiveHealthMode::Enabled(policy) => {
                (true, policy.failure_threshold, policy.ejection_ms)
            }
        };
        output.push_str(&format!("enabled = {passive_enabled}\n"));
        output.push_str(&format!("failure_threshold = {failure_threshold}\n"));
        output.push_str(&format!("ejection_ms = {ejection_ms}\n\n"));
        for upstream in &service.upstreams {
            output.push_str("[[services.upstreams]]\n");
            output.push_str(&format!("name = \"{}\"\n", upstream.id));
            output.push_str(&format!("url = \"{}\"\n", upstream.url));
            match &upstream.tls {
                UpstreamTlsPolicy::Disabled => {}
                UpstreamTlsPolicy::ServerAuthenticated {
                    server_name,
                    http_host,
                    trust_bundle_ref,
                } => {
                    output.push_str(&format!("tls_server_name = \"{}\"\n", server_name.as_str()));
                    output.push_str(&format!(
                        "upstream_http_host = \"{}\"\n",
                        http_host.as_str()
                    ));
                    output.push_str(&format!(
                        "tls_trust_bundle_ref = \"{}\"\n",
                        trust_bundle_ref.as_str()
                    ));
                }
            }
            output.push_str(&format!(
                "administrative_state = \"{}\"\n\n",
                match upstream.administrative_state {
                    UpstreamAdministrativeState::Active => "active",
                    UpstreamAdministrativeState::Draining => "draining",
                }
            ));
        }
    }

    for route in &snapshot.routes {
        output.push_str("[[routes]]\n");
        output.push_str(&format!("name = \"{}\"\n", route.id));
        output.push_str(&format!(
            "hosts = [{}]\n",
            quoted_array(
                &route
                    .route_match
                    .hosts
                    .iter()
                    .map(HostMatch::as_str)
                    .collect::<Vec<_>>()
            )
        ));
        output.push_str(&format!(
            "paths = [{}]\n",
            quoted_array(
                &route
                    .route_match
                    .paths
                    .iter()
                    .filter(|path| !path.is_exact())
                    .map(PathMatch::as_str)
                    .collect::<Vec<_>>()
            )
        ));
        let exact_paths = route
            .route_match
            .paths
            .iter()
            .filter(|path| path.is_exact())
            .map(PathMatch::as_str)
            .collect::<Vec<_>>();
        if !exact_paths.is_empty() {
            output.push_str(&format!("exact_paths = [{}]\n", quoted_array(&exact_paths)));
        }
        output.push_str(&format!("service = \"{}\"\n", route.service_id));
        output.push_str(&format!("priority = {}\n", route.priority));
        output.push_str(&format!("enabled = {}\n", route.enabled));
        if let Some(certificate_ref) = &route.certificate_ref {
            output.push_str(&format!("certificate_ref = \"{}\"\n", certificate_ref));
        }
        output.push_str(&format!(
            "redirect_http_to_https = {}\n\n",
            route.redirect_http_to_https
        ));
    }
    output
}

fn quoted_array(values: &[&str]) -> String {
    values
        .iter()
        .map(|value| format!("\"{value}\""))
        .collect::<Vec<_>>()
        .join(", ")
}
