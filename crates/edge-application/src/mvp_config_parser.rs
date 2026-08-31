//! Pure MVP configuration source parsing and normalization.

use std::collections::BTreeMap;

use crate::config_scalar_parser::{
    parse_bool, parse_i32, parse_string, parse_string_array, parse_u16, parse_u32, parse_u64,
    parse_u8, parse_usize,
};
use crate::failure_policy_normalization::{
    normalize_failure_policies, PassiveHealthPolicyDraft, RetryPolicyDraft,
};
use edge_domain::{
    normalize_client_auth_policy, normalize_upstream_tls_policy, AdminConfig, AppError,
    CertificateRef, ClientAuthPolicy, ConfigRevisionId, ConfigSnapshot, ErrorCode,
    HealthCheckPolicy, HostMatch, HttpHealthCheckPolicy, Listener, ListenerId, ListenerProtocol,
    LoadBalancingPolicy, LogMode, MetricsConfig, PathMatch, Route, RouteId, RouteMatch,
    RuntimeOptions, Service, ServiceId, Upstream, UpstreamAdministrativeState, UpstreamId,
    UpstreamTlsPolicy, DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_INFLIGHT_PAYLOAD_BYTES,
    DEFAULT_MAX_REQUEST_BODY_BYTES, DEFAULT_UPSTREAM_READ_TIMEOUT_MS,
    FIXED_REQUEST_HEADER_RESERVE_BYTES,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigSource {
    pub snapshot: ConfigSnapshot,
    pub schema_version_present: bool,
    pub unknown_fields: Vec<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct MvpConfigDraft {
    schema_version: Option<u32>,
    admin_bind: Option<String>,
    log_mode: Option<LogMode>,
    max_connections: Option<usize>,
    max_inflight_payload_bytes: Option<usize>,
    upstream_read_timeout_ms: Option<u64>,
    metrics_enabled: Option<bool>,
    metrics_bind: Option<String>,
    listeners: Vec<Listener>,
    services: Vec<Service>,
    routes: Vec<Route>,
    current_service: Option<usize>,
    current_upstream: Option<(usize, usize)>,
    health_checks: BTreeMap<usize, HttpHealthCheckDraft>,
    retry_policies: BTreeMap<usize, RetryPolicyDraft>,
    passive_health_policies: BTreeMap<usize, PassiveHealthPolicyDraft>,
    listener_tls: BTreeMap<usize, ListenerTlsDraft>,
    upstream_tls: BTreeMap<(usize, usize), UpstreamTlsDraft>,
    unknown_fields: Vec<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ListenerTlsDraft {
    client_auth: Option<String>,
    trust_bundle_ref: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct UpstreamTlsDraft {
    server_name: Option<String>,
    http_host: Option<String>,
    trust_bundle_ref: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct HttpHealthCheckDraft {
    enabled: Option<bool>,
    path: Option<String>,
    interval_ms: Option<u64>,
    timeout_ms: Option<u64>,
    healthy_threshold: Option<u32>,
    unhealthy_threshold: Option<u32>,
    status_min: Option<u16>,
    status_max: Option<u16>,
}

pub fn parse_mvp_config(
    source: &str,
    revision_id: ConfigRevisionId,
) -> Result<ConfigSource, AppError> {
    let mut draft = MvpConfigDraft::default();
    let mut section = String::new();

    for raw_line in source.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with("[[") && line.ends_with("]]") {
            section = line
                .trim_start_matches("[[")
                .trim_end_matches("]]")
                .trim()
                .to_string();
            match section.as_str() {
                "listeners" => {
                    draft.listeners.push(Listener {
                        id: ListenerId::new(""),
                        bind: String::new(),
                        protocol: ListenerProtocol::Http,
                        client_auth: ClientAuthPolicy::Disabled,
                    });
                    draft.current_service = None;
                    draft.current_upstream = None;
                }
                "services" => {
                    draft.services.push(Service {
                        policy: edge_domain::ServicePolicy::default(),
                        id: ServiceId::new(""),
                        upstreams: Vec::new(),
                    });
                    draft.current_service = Some(draft.services.len() - 1);
                    draft.current_upstream = None;
                }
                "services.upstreams" => {
                    let Some(service_index) = draft.current_service else {
                        return Err(AppError::new(
                            ErrorCode::ConfigServiceWithoutUpstream,
                            "upstream declared before service",
                        ));
                    };
                    draft.services[service_index].upstreams.push(Upstream {
                        id: UpstreamId::new(""),
                        url: String::new(),
                        administrative_state: UpstreamAdministrativeState::Active,
                        tls: UpstreamTlsPolicy::Disabled,
                    });
                    let upstream_index = draft.services[service_index].upstreams.len() - 1;
                    draft.current_upstream = Some((service_index, upstream_index));
                }
                "routes" => {
                    draft.routes.push(Route {
                        id: RouteId::new(""),
                        route_match: RouteMatch::new(Vec::new(), Vec::new()),
                        service_id: ServiceId::new(""),
                        priority: 0,
                        enabled: true,
                        redirect_http_to_https: false,
                        certificate_resolver_id: None,
                        certificate_ref: None,
                    });
                    draft.current_service = None;
                    draft.current_upstream = None;
                }
                _ => {
                    draft.current_upstream = None;
                    draft.unknown_fields.push(section.clone());
                }
            }
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            section = line
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim()
                .to_string();
            draft.current_upstream = None;
            if matches!(
                section.as_str(),
                "services.health_check" | "services.retry" | "services.passive_health"
            ) {
                let Some(service_index) = draft.current_service else {
                    return Err(AppError::new(
                        ErrorCode::ConfigServiceWithoutUpstream,
                        "health check declared before service",
                    ));
                };
                match section.as_str() {
                    "services.health_check" => {
                        draft.health_checks.entry(service_index).or_default();
                    }
                    "services.retry" => {
                        draft.retry_policies.entry(service_index).or_default();
                    }
                    "services.passive_health" => {
                        draft
                            .passive_health_policies
                            .entry(service_index)
                            .or_default();
                    }
                    _ => unreachable!(),
                }
            } else {
                draft.current_service = None;
            }
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return Err(AppError::new(
                ErrorCode::ConfigSchemaVersionMissing,
                format!("malformed config line: {line}"),
            ));
        };
        apply_mvp_config_value(&mut draft, &section, key.trim(), value.trim())?;
    }

    let schema_version = draft.schema_version.unwrap_or(0);
    for (index, listener) in draft.listeners.iter_mut().enumerate() {
        let policy = draft.listener_tls.get(&index).cloned().unwrap_or_default();
        listener.client_auth = normalize_client_auth_policy(
            schema_version,
            listener.protocol.clone(),
            policy.client_auth.as_deref(),
            policy.trust_bundle_ref.as_deref(),
        )
        .map_err(|error| AppError::new(error.code, error.message))?;
    }
    for (service_index, service) in draft.services.iter_mut().enumerate() {
        for (upstream_index, upstream) in service.upstreams.iter_mut().enumerate() {
            let policy = draft
                .upstream_tls
                .get(&(service_index, upstream_index))
                .cloned()
                .unwrap_or_default();
            upstream.tls = normalize_upstream_tls_policy(
                schema_version,
                &upstream.url,
                policy.server_name.as_deref(),
                policy.http_host.as_deref(),
                policy.trust_bundle_ref.as_deref(),
            )
            .map_err(|error| AppError::new(error.code, error.message))?
            .tls;
        }
    }

    normalize_upstream_ids(&mut draft.services)?;
    normalize_service_policies(&mut draft.services, &draft.health_checks)?;
    normalize_failure_policies(
        &mut draft.services,
        &draft.retry_policies,
        &draft.passive_health_policies,
    )?;

    let snapshot = ConfigSnapshot {
        schema_version: draft.schema_version.unwrap_or(0),
        revision_id,
        admin: AdminConfig {
            bind: draft
                .admin_bind
                .unwrap_or_else(|| "127.0.0.1:9443".to_string()),
            auth_required: true,
        },
        listeners: draft.listeners,
        routes: draft.routes,
        services: draft.services,
        certificate_resolvers: Vec::new(),
        log_mode: draft.log_mode.unwrap_or(LogMode::Product),
        runtime: RuntimeOptions {
            max_connections: draft.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
            max_inflight_payload_bytes: draft
                .max_inflight_payload_bytes
                .unwrap_or(DEFAULT_MAX_INFLIGHT_PAYLOAD_BYTES),
            max_request_header_bytes: FIXED_REQUEST_HEADER_RESERVE_BYTES,
            max_request_body_bytes: DEFAULT_MAX_REQUEST_BODY_BYTES,
            upstream_read_timeout_ms: draft
                .upstream_read_timeout_ms
                .unwrap_or(DEFAULT_UPSTREAM_READ_TIMEOUT_MS),

            metrics: MetricsConfig {
                enabled: draft.metrics_enabled.unwrap_or(false),
                bind: draft
                    .metrics_bind
                    .unwrap_or_else(|| "127.0.0.1:9464".to_string()),
            },
        },
    };

    Ok(ConfigSource {
        snapshot,
        schema_version_present: draft.schema_version.is_some(),
        unknown_fields: draft.unknown_fields,
    })
}

fn normalize_service_policies(
    services: &mut [Service],
    health_checks: &BTreeMap<usize, HttpHealthCheckDraft>,
) -> Result<(), AppError> {
    for (&service_index, draft) in health_checks {
        let Some(service) = services.get_mut(service_index) else {
            return Err(AppError::new(
                ErrorCode::InternalBug,
                "health-check draft references a missing service",
            ));
        };
        if !draft.enabled.unwrap_or(false) {
            service.policy.health_check = HealthCheckPolicy::Disabled;
            continue;
        }

        let defaults = HttpHealthCheckPolicy::default();
        service.policy.health_check = HealthCheckPolicy::Http(
            HttpHealthCheckPolicy::new(
                draft.path.clone().unwrap_or(defaults.path),
                draft.interval_ms.unwrap_or(defaults.interval_ms),
                draft.timeout_ms.unwrap_or(defaults.timeout_ms),
                draft
                    .healthy_threshold
                    .unwrap_or(defaults.healthy_threshold),
                draft
                    .unhealthy_threshold
                    .unwrap_or(defaults.unhealthy_threshold),
                draft.status_min.unwrap_or(defaults.status_min),
                draft.status_max.unwrap_or(defaults.status_max),
            )
            .map_err(|error| AppError::new(error.code, error.message))?,
        );
    }
    Ok(())
}

fn normalize_upstream_ids(services: &mut [Service]) -> Result<(), AppError> {
    for service in services {
        if service.upstreams.len() == 1 && service.upstreams[0].id.as_str().is_empty() {
            service.upstreams[0].id = UpstreamId::new(format!("{}-primary", service.id.as_str()));
        }

        if service.upstreams.len() > 1
            && service
                .upstreams
                .iter()
                .any(|upstream| upstream.id.as_str().is_empty())
        {
            return Err(AppError::new(
                ErrorCode::ConfigUpstreamIdRequired,
                format!(
                    "service {} has multiple upstreams without explicit names",
                    service.id
                ),
            ));
        }
    }

    Ok(())
}

fn apply_mvp_config_value(
    draft: &mut MvpConfigDraft,
    section: &str,
    key: &str,
    value: &str,
) -> Result<(), AppError> {
    match (section, key) {
        ("", "schema_version") => {
            draft.schema_version = Some(parse_u32(value)?);
        }
        ("admin", "bind") => draft.admin_bind = Some(parse_string(value)?),
        ("admin", "enabled") => {}
        ("logging", "mode") => {
            draft.log_mode = Some(
                parse_string(value)?
                    .parse::<LogMode>()
                    .map_err(|error| AppError::new(error.code, error.message))?,
            );
        }
        ("storage", "data_dir") => {}
        ("runtime", "max_connections") => {
            draft.max_connections = Some(parse_usize(value)?);
        }
        ("runtime", "max_inflight_payload_bytes") => {
            draft.max_inflight_payload_bytes = Some(parse_usize(value)?);
        }
        ("runtime", "upstream_read_timeout_ms") => {
            draft.upstream_read_timeout_ms = Some(parse_u64(value)?);
        }
        ("metrics", "enabled") => draft.metrics_enabled = Some(parse_bool(value)?),
        ("metrics", "bind") => draft.metrics_bind = Some(parse_string(value)?),
        ("listeners", "name") => {
            if let Some(listener) = draft.listeners.last_mut() {
                listener.id = ListenerId::new(parse_string(value)?);
            }
        }
        ("listeners", "bind") => {
            if let Some(listener) = draft.listeners.last_mut() {
                listener.bind = parse_string(value)?;
            }
        }
        ("listeners", "protocol") => {
            if let Some(listener) = draft.listeners.last_mut() {
                listener.protocol = match parse_string(value)?.as_str() {
                    "http" => ListenerProtocol::Http,
                    "https" => ListenerProtocol::Https,
                    other => {
                        return Err(AppError::new(
                            ErrorCode::ConfigSchemaVersionMissing,
                            format!("unsupported listener protocol: {other}"),
                        ));
                    }
                };
            }
        }
        ("listeners", "client_auth") => {
            let index = draft.listeners.len().checked_sub(1).ok_or_else(|| {
                AppError::new(
                    ErrorCode::ConfigClientAuthPolicyInvalid,
                    "listener is missing",
                )
            })?;
            draft.listener_tls.entry(index).or_default().client_auth = Some(parse_string(value)?);
        }
        ("listeners", "client_trust_bundle_ref") => {
            let index = draft.listeners.len().checked_sub(1).ok_or_else(|| {
                AppError::new(
                    ErrorCode::ConfigClientAuthPolicyInvalid,
                    "listener is missing",
                )
            })?;
            draft
                .listener_tls
                .entry(index)
                .or_default()
                .trust_bundle_ref = Some(parse_string(value)?);
        }
        ("services", "name") => {
            if let Some(service_index) = draft.current_service {
                draft.services[service_index].id = ServiceId::new(parse_string(value)?);
            }
        }
        ("services", "load_balancer") => {
            if let Some(service_index) = draft.current_service {
                draft.services[service_index].policy.load_balancing = parse_string(value)?
                    .parse::<LoadBalancingPolicy>()
                    .map_err(|error| AppError::new(error.code, error.message))?;
            }
        }
        ("services.health_check", key) => {
            let Some(service_index) = draft.current_service else {
                return Err(AppError::new(
                    ErrorCode::ConfigServiceWithoutUpstream,
                    "health check declared before service",
                ));
            };
            let health = draft.health_checks.entry(service_index).or_default();
            match key {
                "enabled" => health.enabled = Some(parse_bool(value)?),
                "path" => health.path = Some(parse_string(value)?),
                "interval_ms" => health.interval_ms = Some(parse_u64(value)?),
                "timeout_ms" => health.timeout_ms = Some(parse_u64(value)?),
                "healthy_threshold" => health.healthy_threshold = Some(parse_u32(value)?),
                "unhealthy_threshold" => health.unhealthy_threshold = Some(parse_u32(value)?),
                "status_min" => health.status_min = Some(parse_u16(value)?),
                "status_max" => health.status_max = Some(parse_u16(value)?),
                _ => draft.unknown_fields.push(format!("{section}.{key}")),
            }
        }
        ("services.retry", key) => {
            let index = draft.current_service.ok_or_else(|| {
                AppError::new(
                    ErrorCode::ConfigServiceWithoutUpstream,
                    "retry declared before service",
                )
            })?;
            let policy = draft.retry_policies.entry(index).or_default();
            match key {
                "enabled" => policy.enabled = Some(parse_bool(value)?),
                "max_retries" => policy.max_retries = Some(parse_u8(value)?),
                "max_replay_bytes" => policy.max_replay_bytes = Some(parse_u64(value)?),
                _ => draft.unknown_fields.push(format!("{section}.{key}")),
            }
        }
        ("services.passive_health", key) => {
            let index = draft.current_service.ok_or_else(|| {
                AppError::new(
                    ErrorCode::ConfigServiceWithoutUpstream,
                    "passive health declared before service",
                )
            })?;
            let policy = draft.passive_health_policies.entry(index).or_default();
            match key {
                "enabled" => policy.enabled = Some(parse_bool(value)?),
                "failure_threshold" => policy.failure_threshold = Some(parse_u8(value)?),
                "ejection_ms" => policy.ejection_ms = Some(parse_u64(value)?),
                _ => draft.unknown_fields.push(format!("{section}.{key}")),
            }
        }
        ("services.upstreams", "name") => {
            let Some((service_index, upstream_index)) = draft.current_upstream else {
                return Err(AppError::new(
                    ErrorCode::ConfigServiceWithoutUpstream,
                    "upstream declared before service",
                ));
            };
            draft.services[service_index].upstreams[upstream_index].id =
                UpstreamId::new(parse_string(value)?);
        }
        ("services.upstreams", "url") => {
            let Some((service_index, upstream_index)) = draft.current_upstream else {
                return Err(AppError::new(
                    ErrorCode::ConfigServiceWithoutUpstream,
                    "upstream declared before service",
                ));
            };
            draft.services[service_index].upstreams[upstream_index].url = parse_string(value)?;
        }
        ("services.upstreams", "administrative_state") => {
            let (service_index, upstream_index) = draft.current_upstream.ok_or_else(|| {
                AppError::new(
                    ErrorCode::ConfigServiceWithoutUpstream,
                    "upstream declared before service",
                )
            })?;
            draft.services[service_index].upstreams[upstream_index].administrative_state =
                match parse_string(value)?.as_str() {
                    "active" => UpstreamAdministrativeState::Active,
                    "draining" => UpstreamAdministrativeState::Draining,
                    _ => {
                        return Err(AppError::new(
                            ErrorCode::ConfigPassiveHealthPolicyInvalid,
                            "unsupported upstream administrative state",
                        ))
                    }
                };
        }
        ("services.upstreams", "tls_server_name") => {
            let index = draft.current_upstream.ok_or_else(|| {
                AppError::new(ErrorCode::ConfigTlsPolicyInvalid, "upstream is missing")
            })?;
            draft.upstream_tls.entry(index).or_default().server_name = Some(parse_string(value)?);
        }
        ("services.upstreams", "upstream_http_host") => {
            let index = draft.current_upstream.ok_or_else(|| {
                AppError::new(ErrorCode::ConfigTlsPolicyInvalid, "upstream is missing")
            })?;
            draft.upstream_tls.entry(index).or_default().http_host = Some(parse_string(value)?);
        }
        ("services.upstreams", "tls_trust_bundle_ref") => {
            let index = draft.current_upstream.ok_or_else(|| {
                AppError::new(ErrorCode::ConfigTlsPolicyInvalid, "upstream is missing")
            })?;
            draft
                .upstream_tls
                .entry(index)
                .or_default()
                .trust_bundle_ref = Some(parse_string(value)?);
        }
        ("routes", "name") => {
            if let Some(route) = draft.routes.last_mut() {
                route.id = RouteId::new(parse_string(value)?);
            }
        }
        ("routes", "hosts") => {
            if let Some(route) = draft.routes.last_mut() {
                route.route_match.hosts = parse_string_array(value)?
                    .iter()
                    .map(HostMatch::exact)
                    .collect();
            }
        }
        ("routes", "paths") => {
            if let Some(route) = draft.routes.last_mut() {
                route
                    .route_match
                    .paths
                    .extend(parse_string_array(value)?.iter().map(PathMatch::prefix));
            }
        }
        ("routes", "exact_paths") => {
            if let Some(route) = draft.routes.last_mut() {
                route
                    .route_match
                    .paths
                    .extend(parse_string_array(value)?.iter().map(PathMatch::exact));
            }
        }
        ("routes", "service") => {
            if let Some(route) = draft.routes.last_mut() {
                route.service_id = ServiceId::new(parse_string(value)?);
            }
        }
        ("routes", "priority") => {
            if let Some(route) = draft.routes.last_mut() {
                route.priority = parse_i32(value)?;
            }
        }
        ("routes", "enabled") => {
            if let Some(route) = draft.routes.last_mut() {
                route.enabled = parse_bool(value)?;
            }
        }
        ("routes", "redirect_http_to_https") => {
            if let Some(route) = draft.routes.last_mut() {
                route.redirect_http_to_https = parse_bool(value)?;
            }
        }
        ("routes", "certificate_ref") => {
            if let Some(route) = draft.routes.last_mut() {
                route.certificate_ref = Some(CertificateRef::new(parse_string(value)?));
            }
        }
        _ => draft.unknown_fields.push(format!("{section}.{key}")),
    }

    Ok(())
}
