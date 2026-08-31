//! Immutable configuration validation and stable error projection.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use edge_domain::{
    AcmeChallenge, ConfigSnapshot, ErrorCode, ListenerProtocol, RuntimeResourcePolicy,
    RuntimeTimeoutPolicy, UpstreamAdministrativeState, UpstreamEndpoint, UpstreamScheme,
    UpstreamTlsPolicy, ValidationError,
};

use crate::ConfigSource;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    pub errors: Vec<ValidationError>,
}

impl ValidationReport {
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn into_result(self) -> Result<(), Vec<ValidationError>> {
        if self.is_valid() {
            Ok(())
        } else {
            Err(self.errors)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigValidator {
    reject_unknown_fields: bool,
    allow_production_acme: bool,
}

impl Default for ConfigValidator {
    fn default() -> Self {
        Self {
            reject_unknown_fields: true,
            allow_production_acme: false,
        }
    }
}

impl ConfigValidator {
    pub fn allow_production_acme(mut self, allow: bool) -> Self {
        self.allow_production_acme = allow;
        self
    }

    pub fn validate_source(&self, source: &ConfigSource) -> ValidationReport {
        let mut errors = self.validate_snapshot(&source.snapshot).errors;

        if !source.schema_version_present {
            errors.push(ValidationError::new(
                ErrorCode::ConfigSchemaVersionMissing,
                "schema_version is required",
            ));
        }

        if self.reject_unknown_fields && !source.unknown_fields.is_empty() {
            errors.push(ValidationError::new(
                ErrorCode::ConfigSchemaVersionMissing,
                format!("unknown fields: {}", source.unknown_fields.join(", ")),
            ));
        }

        ValidationReport { errors }
    }

    pub fn validate_snapshot(&self, snapshot: &ConfigSnapshot) -> ValidationReport {
        let mut errors = Vec::new();
        if let Err(error) = RuntimeResourcePolicy::try_new(
            snapshot.runtime.max_connections,
            snapshot.runtime.max_inflight_payload_bytes,
        ) {
            errors.push(ValidationError::new(error.code, error.message));
        }
        if let Err(error) = RuntimeTimeoutPolicy::try_new(snapshot.runtime.upstream_read_timeout_ms)
        {
            errors.push(ValidationError::new(error.code, error.message));
        }
        let mut listener_ids = BTreeSet::new();
        let mut listener_binds = BTreeSet::new();
        let has_http_listener = snapshot
            .listeners
            .iter()
            .any(|listener| listener.protocol == ListenerProtocol::Http);

        for listener in &snapshot.listeners {
            if !listener_ids.insert(listener.id.as_str().to_string()) {
                errors.push(ValidationError::new(
                    ErrorCode::ConfigListenerDuplicate,
                    format!("duplicate listener: {}", listener.id),
                ));
            }
            if listener.bind.parse::<SocketAddr>().is_err() {
                errors.push(ValidationError::new(
                    ErrorCode::ConfigInvalidBindAddress,
                    format!("invalid listener bind address: {}", listener.bind),
                ));
            }
            listener_binds.insert(listener.bind.clone());
        }

        if snapshot.admin.bind.parse::<SocketAddr>().is_err() {
            errors.push(ValidationError::new(
                ErrorCode::ConfigInvalidBindAddress,
                format!("invalid admin bind address: {}", snapshot.admin.bind),
            ));
        }

        if snapshot.runtime.metrics.enabled {
            match snapshot.runtime.metrics.bind.parse::<SocketAddr>() {
                Ok(address) if address.ip().is_loopback() => {}
                _ => errors.push(ValidationError::new(
                    ErrorCode::ConfigInvalidBindAddress,
                    "enabled metrics bind must be a valid loopback socket address",
                )),
            }
        }

        if listener_binds.contains(snapshot.admin.bind.as_str()) {
            errors.push(ValidationError::new(
                ErrorCode::ConfigAdminBindConflict,
                "admin bind conflicts with listener bind",
            ));
        }

        if is_external_bind(&snapshot.admin.bind) && !snapshot.admin.auth_required {
            errors.push(ValidationError::new(
                ErrorCode::ConfigAdminExternalBindWithoutAuth,
                "external admin bind requires auth",
            ));
        }

        for resolver in &snapshot.certificate_resolvers {
            if !is_valid_email(&resolver.email) {
                errors.push(ValidationError::new(
                    ErrorCode::ConfigInvalidAcmeEmail,
                    format!("invalid ACME email: {}", resolver.email),
                ));
            }

            if resolver.challenge == AcmeChallenge::Http01 && !has_http_listener {
                errors.push(ValidationError::new(
                    ErrorCode::ConfigHttp01WithoutHttpListener,
                    "HTTP-01 requires an HTTP listener",
                ));
            }

            if resolver.production_enabled && !self.allow_production_acme {
                errors.push(ValidationError::new(
                    ErrorCode::ConfigProductionAcmeRequiresOptIn,
                    "production ACME requires explicit opt-in",
                ));
            }
        }

        let service_ids: BTreeSet<_> = snapshot
            .services
            .iter()
            .map(|service| service.id.as_str().to_string())
            .collect();

        for service in &snapshot.services {
            if service.upstreams.is_empty() {
                errors.push(ValidationError::new(
                    ErrorCode::ConfigServiceWithoutUpstream,
                    format!("service has no upstream: {}", service.id),
                ));
            }
            if !service.upstreams.is_empty()
                && service.upstreams.iter().all(|upstream| {
                    upstream.administrative_state == UpstreamAdministrativeState::Draining
                })
            {
                errors.push(ValidationError::new(
                    ErrorCode::ConfigServiceWithoutUpstream,
                    format!("service has no active upstream: {}", service.id),
                ));
            }

            let mut upstream_ids = BTreeSet::new();
            let mut upstream_endpoints = BTreeSet::new();
            for upstream in &service.upstreams {
                if upstream.id.as_str().is_empty() {
                    errors.push(ValidationError::new(
                        ErrorCode::ConfigUpstreamIdRequired,
                        format!("service {} has an upstream without a name", service.id),
                    ));
                } else if !upstream_ids.insert(upstream.id.as_str()) {
                    errors.push(ValidationError::new(
                        ErrorCode::ConfigUpstreamIdDuplicate,
                        format!(
                            "service {} has duplicate upstream name: {}",
                            service.id, upstream.id
                        ),
                    ));
                }

                match UpstreamEndpoint::parse(&upstream.url) {
                    Ok(endpoint) => {
                        if snapshot.schema_version == 1
                            && endpoint.scheme() == UpstreamScheme::Https
                        {
                            errors.push(ValidationError::new(
                                ErrorCode::ConfigInvalidUpstreamUrl,
                                "schema v1 upstream URL must use HTTP",
                            ));
                            continue;
                        }
                        let policy_matches = matches!(
                            (endpoint.scheme(), &upstream.tls),
                            (UpstreamScheme::Http, UpstreamTlsPolicy::Disabled)
                                | (
                                    UpstreamScheme::Https,
                                    UpstreamTlsPolicy::ServerAuthenticated { .. }
                                )
                        );
                        if !policy_matches {
                            errors.push(ValidationError::new(
                                ErrorCode::ConfigTlsPolicyInvalid,
                                "upstream scheme and TLS policy do not match",
                            ));
                        } else if is_metadata_host(endpoint.host()) {
                            errors.push(ValidationError::new(
                                ErrorCode::ConfigUnsafeUpstreamUrl,
                                format!("blocked metadata upstream url: {}", upstream.url),
                            ));
                        } else if !upstream_endpoints.insert(endpoint) {
                            errors.push(ValidationError::new(
                                ErrorCode::ConfigInvalidUpstreamUrl,
                                format!("duplicate normalized upstream url: {}", upstream.url),
                            ));
                        }
                    }
                    Err(error) => errors.push(error),
                }
            }
        }

        let mut route_ids = BTreeSet::new();
        let mut route_keys = BTreeSet::new();

        for route in &snapshot.routes {
            if !route_ids.insert(route.id.as_str().to_string()) {
                errors.push(ValidationError::new(
                    ErrorCode::ConfigRouteDuplicate,
                    format!("duplicate route: {}", route.id),
                ));
            }

            if route.route_match.hosts.is_empty() || route.route_match.paths.is_empty() {
                errors.push(ValidationError::new(
                    ErrorCode::ConfigRouteMatchEmpty,
                    format!("route has empty host/path match: {}", route.id),
                ));
            }

            if !service_ids.contains(route.service_id.as_str()) {
                errors.push(ValidationError::new(
                    ErrorCode::ConfigRouteMissingService,
                    format!("route references missing service: {}", route.service_id),
                ));
            }

            for host in &route.route_match.hosts {
                for path in &route.route_match.paths {
                    let key = format!("{}{}", host.as_str(), path.as_str());
                    if !route_keys.insert(key) {
                        errors.push(ValidationError::new(
                            ErrorCode::ConfigRouteDuplicate,
                            "duplicate normalized host/path route",
                        ));
                    }
                }
            }

            if route.redirect_http_to_https {
                if route.certificate_ref.is_none() && route.certificate_resolver_id.is_none() {
                    errors.push(ValidationError::new(
                        ErrorCode::ConfigHttpsRouteCertificateMissing,
                        format!("route has HTTPS redirect without certificate: {}", route.id),
                    ));
                }

                let resolver = route.certificate_resolver_id.as_ref().and_then(|id| {
                    snapshot
                        .certificate_resolvers
                        .iter()
                        .find(|resolver| resolver.id.as_str() == id.as_str())
                });
                if resolver.is_some_and(|resolver| resolver.challenge == AcmeChallenge::Http01) {
                    errors.push(ValidationError::new(
                        ErrorCode::ConfigAcmeChallengeBlockedByRedirect,
                        "HTTP-01 challenge must bypass HTTPS redirect",
                    ));
                }
            }
        }

        ValidationReport { errors }
    }
}

fn is_external_bind(bind: &str) -> bool {
    bind.starts_with("0.0.0.0") || bind.starts_with("[::]")
}

fn is_valid_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains('@')
}

fn is_metadata_host(host: &str) -> bool {
    matches!(
        host,
        "169.254.169.254"
            | "169.254.169.253"
            | "metadata.google.internal"
            | "metadata"
            | "instance-data"
    )
}
