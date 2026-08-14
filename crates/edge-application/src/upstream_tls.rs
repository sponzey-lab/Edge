use edge_domain::{
    AppError, ConfigSnapshot, ErrorCode, ServiceId, TlsServerName, TrustBundleRef,
    UpstreamEndpoint, UpstreamId, UpstreamScheme, UpstreamTlsPolicy,
};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UpstreamTlsPreparationRequirement {
    pub service_id: ServiceId,
    pub upstream_id: UpstreamId,
    pub trust_bundle_ref: TrustBundleRef,
    pub server_name: TlsServerName,
}

pub fn plan_upstream_tls_preparation(
    snapshot: &ConfigSnapshot,
) -> Result<Vec<UpstreamTlsPreparationRequirement>, AppError> {
    let mut keys = BTreeSet::new();
    let mut requirements = Vec::new();
    for service in &snapshot.services {
        for upstream in &service.upstreams {
            let endpoint =
                UpstreamEndpoint::parse(&upstream.url).map_err(|_| upstream_tls_plan_invalid())?;
            let key = (service.id.clone(), upstream.id.clone());
            if !keys.insert(key.clone()) {
                return Err(upstream_tls_plan_invalid());
            }
            match (endpoint.scheme(), &upstream.tls) {
                (UpstreamScheme::Http, UpstreamTlsPolicy::Disabled) => {}
                (
                    UpstreamScheme::Https,
                    UpstreamTlsPolicy::ServerAuthenticated {
                        server_name,
                        trust_bundle_ref,
                        ..
                    },
                ) => requirements.push(UpstreamTlsPreparationRequirement {
                    service_id: key.0,
                    upstream_id: key.1,
                    trust_bundle_ref: trust_bundle_ref.clone(),
                    server_name: server_name.clone(),
                }),
                _ => return Err(upstream_tls_plan_invalid()),
            }
        }
    }
    requirements.sort();
    Ok(requirements)
}

fn upstream_tls_plan_invalid() -> AppError {
    AppError::new(
        ErrorCode::UpstreamTlsProfileInvalid,
        "upstream TLS preparation plan is invalid",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_domain::{
        AdminConfig, ConfigRevisionId, LogMode, RuntimeOptions, Service, Upstream,
        UpstreamAdministrativeState, UpstreamHttpHost, UpstreamTlsPolicy,
    };

    fn snapshot(upstreams: Vec<Upstream>) -> ConfigSnapshot {
        ConfigSnapshot {
            schema_version: 2,
            revision_id: ConfigRevisionId::new("rev-tls-plan"),
            admin: AdminConfig {
                bind: "127.0.0.1:9443".to_string(),
                auth_required: true,
            },
            listeners: vec![],
            routes: vec![],
            services: vec![Service {
                id: ServiceId::new("service-b"),
                upstreams,
                policy: edge_domain::ServicePolicy::default(),
            }],
            certificate_resolvers: vec![],
            log_mode: LogMode::Product,
            runtime: RuntimeOptions {
                max_connections: 10,
                max_inflight_payload_bytes: 128 * 1024 * 1024,
                max_request_header_bytes: 1024,
                max_request_body_bytes: 1024,
                upstream_read_timeout_ms: edge_domain::DEFAULT_UPSTREAM_READ_TIMEOUT_MS,
                metrics: edge_domain::MetricsConfig::default(),
            },
        }
    }

    fn https_upstream(id: &str, trust: &str, server_name: &str) -> Upstream {
        Upstream {
            id: UpstreamId::new(id),
            url: "https://127.0.0.1:8443".to_string(),
            administrative_state: UpstreamAdministrativeState::Active,
            tls: UpstreamTlsPolicy::ServerAuthenticated {
                server_name: TlsServerName::parse(server_name).unwrap(),
                http_host: UpstreamHttpHost::parse(server_name).unwrap(),
                trust_bundle_ref: TrustBundleRef::parse(trust).unwrap(),
            },
        }
    }

    #[test]
    fn phase009_upstream_tls_preparation_plan_is_typed_sorted_and_excludes_http() {
        let mut input = snapshot(vec![
            https_upstream("upstream-z", "root-z", "z.private.test"),
            Upstream {
                id: UpstreamId::new("upstream-http"),
                url: "http://127.0.0.1:8080".to_string(),
                administrative_state: UpstreamAdministrativeState::Active,
                tls: UpstreamTlsPolicy::Disabled,
            },
            https_upstream("upstream-a", "root-a", "a.private.test"),
        ]);
        input.services.push(Service {
            id: ServiceId::new("service-a"),
            upstreams: vec![https_upstream("upstream-b", "root-b", "b.private.test")],
            policy: edge_domain::ServicePolicy::default(),
        });

        let plan = plan_upstream_tls_preparation(&input).unwrap();

        assert_eq!(plan.len(), 3);
        assert_eq!(plan[0].service_id.as_str(), "service-a");
        assert_eq!(plan[1].upstream_id.as_str(), "upstream-a");
        assert_eq!(plan[2].upstream_id.as_str(), "upstream-z");
        assert_eq!(plan[1].trust_bundle_ref.as_str(), "root-a");
        assert_eq!(plan[1].server_name.as_str(), "a.private.test");
    }

    #[test]
    fn phase009_upstream_tls_preparation_plan_rejects_scheme_policy_contradiction() {
        let mut input = snapshot(vec![https_upstream(
            "upstream-a",
            "root-a",
            "a.private.test",
        )]);
        input.services[0].upstreams[0].url = "http://127.0.0.1:8080".to_string();

        let error = plan_upstream_tls_preparation(&input).unwrap_err();

        assert_eq!(
            error.code,
            edge_domain::ErrorCode::UpstreamTlsProfileInvalid
        );
    }
}
