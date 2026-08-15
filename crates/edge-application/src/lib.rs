//! Application use cases.
//!
//! This crate orchestrates domain rules through ports. It must not read process
//! environment variables or talk to concrete adapters directly.

mod backup;
pub use backup::*;
mod operational_upgrade;
pub use operational_upgrade::*;
mod support_bundle;
pub use support_bundle::*;

mod audit;
pub use audit::*;

mod drain;
mod failure_observability;
mod health;
mod metrics;
mod passive_health;
mod resource_observability;
mod trust;
mod upstream_tls;

pub use drain::*;
pub use failure_observability::*;
pub use health::*;
pub use metrics::*;
pub use passive_health::*;
pub use resource_observability::*;
pub use trust::*;
pub use upstream_tls::*;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::SocketAddr;

use edge_domain::{
    normalize_client_auth_policy, normalize_host, normalize_upstream_tls_policy, AcmeChallenge,
    AdminConfig, AppError, CertificateRef, ClientAuthPolicy, CommandAck, ConfigRevision,
    ConfigRevisionId, ConfigSnapshot, CoreCommand, ErrorCode, HealthCheckPolicy, HostMatch,
    HttpHealthCheckPolicy, Listener, ListenerId, ListenerProtocol, LoadBalancingPolicy, LogMode,
    MetricsConfig, PassiveHealthMode, PassiveHealthPolicy, PathMatch, ProxyHost, ProxyHostId,
    RetryPolicy, Route, RouteId, RouteMatch, RuntimeOptions, RuntimeResourcePolicy,
    RuntimeTimeoutPolicy, Service, ServiceId, Upstream, UpstreamAdministrativeState,
    UpstreamEndpoint, UpstreamId, UpstreamScheme, UpstreamTlsPolicy, ValidationError,
    DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_INFLIGHT_PAYLOAD_BYTES, DEFAULT_MAX_REQUEST_BODY_BYTES,
    DEFAULT_UPSTREAM_READ_TIMEOUT_MS, FIXED_REQUEST_HEADER_RESERVE_BYTES,
};
use edge_ports::{
    AcmeClient, AcmeHttp01ChallengeRuntime, AcmeOrderRequest, AcmeOrderResult, AuditEvent,
    AuditSink, BootstrapConfigSeed, CertificateMaterial, CertificateMaterialValidator,
    CertificateStore, ConfigRevisionRepository, CoreCommandClient, Http01ChallengeProbe,
    Http01ChallengeStore, LogSink, MetricDescriptor, MetricEvent, MetricsSink, ResourceMetricKind,
    ResourceRejectionReason, RevisionRecord, StartupConfigPreflight, StoredCertificate,
    StructuredLogEvent,
};

/// Foundation smoke helper.
pub fn crate_name() -> &'static str {
    "edge-application"
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigSource {
    pub snapshot: ConfigSnapshot,
    pub schema_version_present: bool,
    pub unknown_fields: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupConfigOrigin {
    RevisionCurrent,
    BootstrapSeedImported,
}

impl StartupConfigOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RevisionCurrent => "revision_current",
            Self::BootstrapSeedImported => "bootstrap_seed_imported",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedStartupConfig {
    pub snapshot: ConfigSnapshot,
    pub origin: StartupConfigOrigin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupConfigResolutionState {
    OpeningRepository,
    RepositoryEmpty,
    ReadingSeed,
    ValidatingSeed,
    ImportingSeed,
    ReadingCurrent,
    ValidatingCurrent,
    Resolved,
    Unconfigured,
    Failed { error_code: ErrorCode },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupConfigResolutionEvent {
    RepositoryInspected { empty: bool },
    SeedRead,
    SeedAbsent,
    SeedValidated,
    SeedImported,
    CurrentRead,
    CurrentValidated,
    Failed(ErrorCode),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupConfigResolutionMachine {
    state: StartupConfigResolutionState,
}

impl Default for StartupConfigResolutionMachine {
    fn default() -> Self {
        Self {
            state: StartupConfigResolutionState::OpeningRepository,
        }
    }
}

impl StartupConfigResolutionMachine {
    pub fn state(&self) -> &StartupConfigResolutionState {
        &self.state
    }

    pub fn transition(&mut self, event: StartupConfigResolutionEvent) -> Result<(), AppError> {
        use StartupConfigResolutionEvent as Event;
        use StartupConfigResolutionState as State;

        let next = match (&self.state, event) {
            (State::OpeningRepository, Event::RepositoryInspected { empty: true }) => {
                State::RepositoryEmpty
            }
            (State::OpeningRepository, Event::RepositoryInspected { empty: false }) => {
                State::ReadingCurrent
            }
            (State::RepositoryEmpty, Event::SeedRead) => State::ValidatingSeed,
            (State::RepositoryEmpty, Event::SeedAbsent) => State::Unconfigured,
            (State::ValidatingSeed, Event::SeedValidated) => State::ImportingSeed,
            (State::ImportingSeed, Event::SeedImported) => State::Resolved,
            (State::ReadingCurrent, Event::CurrentRead) => State::ValidatingCurrent,
            (State::ValidatingCurrent, Event::CurrentValidated) => State::Resolved,
            (
                State::OpeningRepository
                | State::RepositoryEmpty
                | State::ReadingSeed
                | State::ValidatingSeed
                | State::ImportingSeed
                | State::ReadingCurrent
                | State::ValidatingCurrent,
                Event::Failed(error_code),
            ) => State::Failed { error_code },
            (state, event) => {
                return Err(AppError::new(
                    ErrorCode::InternalBug,
                    format!("invalid startup config transition: {state:?} + {event:?}"),
                ));
            }
        };
        self.state = next;
        Ok(())
    }
}

pub struct ResolveStartupConfigUseCase<'a, R, S, P> {
    revisions: &'a mut R,
    seed: &'a mut S,
    preflight: &'a mut P,
    validator: ConfigValidator,
}

impl<'a, R, S, P> ResolveStartupConfigUseCase<'a, R, S, P>
where
    R: ConfigRevisionRepository,
    S: BootstrapConfigSeed,
    P: StartupConfigPreflight,
{
    pub fn new(revisions: &'a mut R, seed: &'a mut S, preflight: &'a mut P) -> Self {
        Self {
            revisions,
            seed,
            preflight,
            validator: ConfigValidator::default(),
        }
    }

    pub fn execute(&mut self) -> Result<Option<ResolvedStartupConfig>, AppError> {
        let mut machine = StartupConfigResolutionMachine::default();
        let current_revision_id = self.revisions.current_revision_id().map_err(|error| {
            fail_startup_resolution(
                &mut machine,
                ErrorCode::ConfigCurrentRevisionInvalid,
                error.message,
            )
        })?;
        let current = self.revisions.current().map_err(|error| {
            fail_startup_resolution(
                &mut machine,
                ErrorCode::ConfigCurrentRevisionInvalid,
                error.message,
            )
        })?;

        if current_revision_id.is_some() && current.is_none() {
            machine
                .transition(StartupConfigResolutionEvent::RepositoryInspected { empty: false })?;
            return Err(fail_startup_resolution(
                &mut machine,
                ErrorCode::ConfigCurrentRevisionMissing,
                "current revision pointer does not reference a stored revision",
            ));
        }

        if let Some(record) = current {
            machine
                .transition(StartupConfigResolutionEvent::RepositoryInspected { empty: false })?;
            machine.transition(StartupConfigResolutionEvent::CurrentRead)?;
            self.validator
                .validate_snapshot(&record.snapshot)
                .into_result()
                .map_err(|errors| {
                    fail_startup_resolution(
                        &mut machine,
                        ErrorCode::ConfigCurrentRevisionInvalid,
                        validation_errors_to_app_error(&errors).message,
                    )
                })?;
            self.preflight
                .preflight(&record.snapshot)
                .map_err(|error| {
                    fail_startup_resolution(&mut machine, error.code, error.message)
                })?;
            machine.transition(StartupConfigResolutionEvent::CurrentValidated)?;
            return Ok(Some(ResolvedStartupConfig {
                snapshot: record.snapshot,
                origin: StartupConfigOrigin::RevisionCurrent,
            }));
        }

        let history = self.revisions.history()?;
        if !history.is_empty() {
            machine
                .transition(StartupConfigResolutionEvent::RepositoryInspected { empty: false })?;
            return Err(fail_startup_resolution(
                &mut machine,
                ErrorCode::ConfigCurrentRevisionMissing,
                "revision repository is non-empty but current revision is unavailable",
            ));
        }

        machine.transition(StartupConfigResolutionEvent::RepositoryInspected { empty: true })?;
        let Some(seed) = self.seed.read_seed()? else {
            machine.transition(StartupConfigResolutionEvent::SeedAbsent)?;
            return Ok(None);
        };
        machine.transition(StartupConfigResolutionEvent::SeedRead)?;
        let source =
            parse_mvp_config(&seed, ConfigRevisionId::new("bootstrap-seed")).map_err(|error| {
                fail_startup_resolution(
                    &mut machine,
                    ErrorCode::ConfigBootstrapSeedInvalid,
                    error.message,
                )
            })?;
        self.validator
            .validate_source(&source)
            .into_result()
            .map_err(|errors| {
                fail_startup_resolution(
                    &mut machine,
                    ErrorCode::ConfigBootstrapSeedInvalid,
                    validation_errors_to_app_error(&errors).message,
                )
            })?;
        self.preflight
            .preflight(&source.snapshot)
            .map_err(|error| fail_startup_resolution(&mut machine, error.code, error.message))?;
        machine.transition(StartupConfigResolutionEvent::SeedValidated)?;

        let record = revision_record_for_snapshot(source.snapshot.clone(), "bootstrap seed");
        let revision_id = record.revision.id.clone();
        self.revisions.save_revision(record)?;
        self.revisions.set_current(&revision_id)?;
        machine.transition(StartupConfigResolutionEvent::SeedImported)?;

        Ok(Some(ResolvedStartupConfig {
            snapshot: source.snapshot,
            origin: StartupConfigOrigin::BootstrapSeedImported,
        }))
    }
}

fn fail_startup_resolution(
    machine: &mut StartupConfigResolutionMachine,
    code: ErrorCode,
    message: impl Into<String>,
) -> AppError {
    let _ = machine.transition(StartupConfigResolutionEvent::Failed(code));
    AppError::new(code, message)
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

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct RetryPolicyDraft {
    enabled: Option<bool>,
    max_retries: Option<u8>,
    max_replay_bytes: Option<u64>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct PassiveHealthPolicyDraft {
    enabled: Option<bool>,
    failure_threshold: Option<u8>,
    ejection_ms: Option<u64>,
}

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

fn normalize_failure_policies(
    services: &mut [Service],
    retries: &BTreeMap<usize, RetryPolicyDraft>,
    passive: &BTreeMap<usize, PassiveHealthPolicyDraft>,
) -> Result<(), AppError> {
    for (&index, draft) in retries {
        let service = services.get_mut(index).ok_or_else(|| {
            AppError::new(
                ErrorCode::InternalBug,
                "retry draft references missing service",
            )
        })?;
        let defaults = RetryPolicy::default();
        service.policy.retry = RetryPolicy::new(
            draft.enabled.unwrap_or(false),
            draft.max_retries.unwrap_or(defaults.max_retries),
            draft.max_replay_bytes.unwrap_or(defaults.max_replay_bytes),
        )
        .map_err(|error| AppError::new(error.code, error.message))?;
    }
    for (&index, draft) in passive {
        let service = services.get_mut(index).ok_or_else(|| {
            AppError::new(
                ErrorCode::InternalBug,
                "passive health draft references missing service",
            )
        })?;
        if draft.enabled.unwrap_or(false) {
            service.policy.passive_health = PassiveHealthMode::Enabled(
                PassiveHealthPolicy::new(
                    draft.failure_threshold.unwrap_or(3),
                    draft.ejection_ms.unwrap_or(30_000),
                )
                .map_err(|error| AppError::new(error.code, error.message))?,
            );
        }
    }
    Ok(())
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
                route
                    .route_match
                    .hosts
                    .iter()
                    .map(HostMatch::as_str)
                    .collect::<Vec<_>>()
                    .as_slice()
            )
        ));
        output.push_str(&format!(
            "paths = [{}]\n",
            quoted_array(
                route
                    .route_match
                    .paths
                    .iter()
                    .filter(|path| !path.is_exact())
                    .map(PathMatch::as_str)
                    .collect::<Vec<_>>()
                    .as_slice()
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

fn parse_string(value: &str) -> Result<String, AppError> {
    let trimmed = value.trim();
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        Ok(trimmed[1..trimmed.len() - 1].to_string())
    } else {
        Err(AppError::new(
            ErrorCode::ConfigSchemaVersionMissing,
            format!("expected quoted string: {value}"),
        ))
    }
}

fn parse_string_array(value: &str) -> Result<Vec<String>, AppError> {
    let trimmed = value.trim();
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return Err(AppError::new(
            ErrorCode::ConfigSchemaVersionMissing,
            format!("expected string array: {value}"),
        ));
    }
    let inner = trimmed[1..trimmed.len() - 1].trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    inner
        .split(',')
        .map(|item| parse_string(item.trim()))
        .collect()
}

fn parse_u32(value: &str) -> Result<u32, AppError> {
    value.trim().parse::<u32>().map_err(|_| {
        AppError::new(
            ErrorCode::ConfigSchemaVersionMissing,
            format!("expected unsigned integer: {value}"),
        )
    })
}

fn parse_u64(value: &str) -> Result<u64, AppError> {
    value.trim().parse::<u64>().map_err(|_| {
        AppError::new(
            ErrorCode::ConfigSchemaVersionMissing,
            format!("expected unsigned integer: {value}"),
        )
    })
}

fn parse_u16(value: &str) -> Result<u16, AppError> {
    value.trim().parse::<u16>().map_err(|_| {
        AppError::new(
            ErrorCode::ConfigSchemaVersionMissing,
            format!("expected 16-bit unsigned integer: {value}"),
        )
    })
}

fn parse_u8(value: &str) -> Result<u8, AppError> {
    value.trim().parse::<u8>().map_err(|_| {
        AppError::new(
            ErrorCode::ConfigSchemaVersionMissing,
            format!("expected 8-bit unsigned integer: {value}"),
        )
    })
}

fn parse_usize(value: &str) -> Result<usize, AppError> {
    value.trim().parse::<usize>().map_err(|_| {
        AppError::new(
            ErrorCode::ConfigSchemaVersionMissing,
            format!("expected unsigned integer: {value}"),
        )
    })
}

fn parse_i32(value: &str) -> Result<i32, AppError> {
    value.trim().parse::<i32>().map_err(|_| {
        AppError::new(
            ErrorCode::ConfigSchemaVersionMissing,
            format!("expected signed integer: {value}"),
        )
    })
}

fn parse_bool(value: &str) -> Result<bool, AppError> {
    match value.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(AppError::new(
            ErrorCode::ConfigSchemaVersionMissing,
            format!("expected boolean: {value}"),
        )),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpRouteAction {
    Proxy {
        route_id: RouteId,
        service_id: ServiceId,
    },
    Redirect {
        status_code: u16,
        location: String,
    },
    AcmeChallengeBypass {
        token: String,
    },
    NotFound,
}

pub fn select_http_route_action(
    snapshot: &ConfigSnapshot,
    host: &str,
    path: &str,
) -> HttpRouteAction {
    if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
        return HttpRouteAction::AcmeChallengeBypass {
            token: token.to_string(),
        };
    }

    let Some(route) = snapshot.select_route(host, path) else {
        return HttpRouteAction::NotFound;
    };

    if route.redirect_http_to_https {
        return HttpRouteAction::Redirect {
            status_code: 308,
            location: format!("https://{host}{path}"),
        };
    }

    HttpRouteAction::Proxy {
        route_id: route.id.clone(),
        service_id: route.service_id.clone(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigDiff {
    pub added_routes: Vec<String>,
    pub removed_routes: Vec<String>,
    pub changed_upstreams: Vec<String>,
}

pub fn diff_config(current: Option<&ConfigSnapshot>, next: &ConfigSnapshot) -> ConfigDiff {
    let Some(current) = current else {
        return ConfigDiff {
            added_routes: next.routes.iter().map(route_name).collect(),
            removed_routes: Vec::new(),
            changed_upstreams: next
                .services
                .iter()
                .map(|service| service.id.as_str().to_string())
                .collect(),
        };
    };

    let current_routes = route_map(&current.routes);
    let next_routes = route_map(&next.routes);

    let added_routes = next_routes
        .keys()
        .filter(|id| !current_routes.contains_key(*id))
        .cloned()
        .collect();
    let removed_routes = current_routes
        .keys()
        .filter(|id| !next_routes.contains_key(*id))
        .cloned()
        .collect();

    let current_upstreams = upstream_map(current);
    let next_upstreams = upstream_map(next);
    let changed_upstreams = next_upstreams
        .iter()
        .filter_map(|(id, value)| {
            if current_upstreams.get(id) != Some(value) {
                Some(id.clone())
            } else {
                None
            }
        })
        .collect();

    ConfigDiff {
        added_routes,
        removed_routes,
        changed_upstreams,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyPlan {
    pub commands: Vec<CoreCommand>,
    pub warnings: Vec<String>,
    pub restart_required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigActivationState {
    Aligned,
    PendingRestart,
}

impl ConfigActivationState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aligned => "aligned",
            Self::PendingRestart => "pending_restart",
        }
    }
}

pub fn config_activation_state(
    active: &ConfigSnapshot,
    desired: &ConfigSnapshot,
) -> ConfigActivationState {
    if restart_warnings(active, desired).is_empty() {
        ConfigActivationState::Aligned
    } else {
        ConfigActivationState::PendingRestart
    }
}

pub fn plan_apply(snapshot: ConfigSnapshot) -> ApplyPlan {
    plan_apply_with_current(None, snapshot)
}

pub fn plan_apply_with_current(
    current: Option<&ConfigSnapshot>,
    snapshot: ConfigSnapshot,
) -> ApplyPlan {
    let warnings = current.map_or_else(Vec::new, |current| restart_warnings(current, &snapshot));
    if !warnings.is_empty() {
        return ApplyPlan {
            commands: Vec::new(),
            warnings,
            restart_required: true,
        };
    }

    ApplyPlan {
        commands: vec![
            CoreCommand::ApplyConfigSnapshot { snapshot },
            CoreCommand::RefreshRouteTable,
        ],
        warnings: Vec::new(),
        restart_required: false,
    }
}

fn restart_warnings(current: &ConfigSnapshot, next: &ConfigSnapshot) -> Vec<String> {
    let mut warnings = Vec::new();
    if current.listeners != next.listeners {
        warnings.push("listener changes require process restart in MVP".to_string());
    }
    if current.runtime.metrics != next.runtime.metrics {
        warnings.push("metrics changes require process restart in MVP".to_string());
    }
    if current.runtime.max_connections != next.runtime.max_connections
        || current.runtime.max_inflight_payload_bytes != next.runtime.max_inflight_payload_bytes
        || current.runtime.upstream_read_timeout_ms != next.runtime.upstream_read_timeout_ms
    {
        warnings.push("resource policy changes require process restart".to_string());
    }
    warnings
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyHostParts {
    pub route: Route,
    pub service: Service,
}

pub fn proxy_host_to_parts(proxy_host: &ProxyHost) -> ProxyHostParts {
    let route_id = RouteId::new(format!("proxy-host-{}", proxy_host.id.as_str()));
    let service_id = ServiceId::new(format!("proxy-host-{}", proxy_host.id.as_str()));
    let upstream_id = UpstreamId::new(format!("proxy-host-{}-primary", proxy_host.id.as_str()));
    let upstreams = if proxy_host.upstreams.is_empty() {
        vec![Upstream {
            id: upstream_id,
            url: proxy_host.upstream_url.clone(),
            administrative_state: UpstreamAdministrativeState::Active,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateStatus {
    pub certificate_ref: CertificateRef,
    pub domains: Vec<String>,
    pub source: String,
    pub expired: bool,
    pub expiring_soon: bool,
    pub not_after_epoch_seconds: u64,
    pub private_key_masked: &'static str,
}

pub fn certificate_status(
    certificate: &StoredCertificate,
    now_epoch_seconds: u64,
    renewal_window_seconds: u64,
) -> CertificateStatus {
    let seconds_left = certificate
        .not_after_epoch_seconds
        .saturating_sub(now_epoch_seconds);
    CertificateStatus {
        certificate_ref: certificate.certificate_ref.clone(),
        domains: certificate.domains.clone(),
        source: certificate.source.clone(),
        expired: certificate.not_after_epoch_seconds <= now_epoch_seconds,
        expiring_soon: seconds_left <= renewal_window_seconds,
        not_after_epoch_seconds: certificate.not_after_epoch_seconds,
        private_key_masked: certificate.masked_private_key(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalDueReason {
    Expired,
    InsideWindow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalSkipReason {
    OutsideWindow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateRenewalDecision {
    RenewalDue {
        certificate_ref: CertificateRef,
        domains: Vec<String>,
        reason: RenewalDueReason,
    },
    RenewalSkipped {
        certificate_ref: CertificateRef,
        reason: RenewalSkipReason,
    },
    RenewalFailed {
        certificate_ref: CertificateRef,
        error_code: ErrorCode,
        retryable: bool,
        failed_attempts: u32,
        next_retry_epoch_seconds: Option<u64>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenewalRetryPolicy {
    pub max_attempts: u32,
    pub backoff_seconds: u64,
}

pub fn plan_certificate_renewal(
    certificate: &StoredCertificate,
    now_epoch_seconds: u64,
    renewal_window_seconds: u64,
) -> CertificateRenewalDecision {
    if certificate.not_after_epoch_seconds <= now_epoch_seconds {
        return CertificateRenewalDecision::RenewalDue {
            certificate_ref: certificate.certificate_ref.clone(),
            domains: certificate.domains.clone(),
            reason: RenewalDueReason::Expired,
        };
    }

    let seconds_left = certificate.not_after_epoch_seconds - now_epoch_seconds;
    if seconds_left <= renewal_window_seconds {
        CertificateRenewalDecision::RenewalDue {
            certificate_ref: certificate.certificate_ref.clone(),
            domains: certificate.domains.clone(),
            reason: RenewalDueReason::InsideWindow,
        }
    } else {
        CertificateRenewalDecision::RenewalSkipped {
            certificate_ref: certificate.certificate_ref.clone(),
            reason: RenewalSkipReason::OutsideWindow,
        }
    }
}

pub fn renewal_failure_decision(
    certificate_ref: CertificateRef,
    error: &AppError,
    now_epoch_seconds: u64,
    failed_attempts: u32,
    policy: RenewalRetryPolicy,
) -> CertificateRenewalDecision {
    let fatal_error = matches!(
        error.code,
        ErrorCode::AcmeTermsNotAccepted
            | ErrorCode::ConfigProductionAcmeRequiresOptIn
            | ErrorCode::CertificateNotFound
    );
    let retryable = !fatal_error && failed_attempts < policy.max_attempts;
    let next_retry_epoch_seconds = retryable.then(|| {
        let attempt_multiplier = u64::from(failed_attempts.max(1));
        now_epoch_seconds.saturating_add(policy.backoff_seconds.saturating_mul(attempt_multiplier))
    });

    CertificateRenewalDecision::RenewalFailed {
        certificate_ref,
        error_code: error.code,
        retryable,
        failed_attempts,
        next_retry_epoch_seconds,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http01Token {
    pub token: String,
    pub key_authorization: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Http01TokenStore {
    tokens: BTreeMap<String, String>,
}

impl Http01TokenStore {
    pub fn insert(&mut self, token: Http01Token) {
        self.tokens.insert(token.token, token.key_authorization);
    }

    pub fn respond(&self, token: &str) -> Option<&str> {
        self.tokens.get(token).map(String::as_str)
    }

    pub fn clear(&mut self, token: &str) {
        self.tokens.remove(token);
    }
}

impl edge_ports::Http01ChallengeResponder for Http01TokenStore {
    fn respond(&self, token: &str) -> Option<String> {
        self.tokens.get(token).cloned()
    }
}

impl edge_ports::Http01ChallengeStore for Http01TokenStore {
    fn insert_http01(&mut self, token: String, key_authorization: String) -> Result<(), AppError> {
        self.insert(Http01Token {
            token,
            key_authorization,
        });
        Ok(())
    }

    fn clear_http01(&mut self, token: &str) -> Result<(), AppError> {
        self.clear(token);
        Ok(())
    }
}

pub struct Http01ChallengeRuntime<'a, T, P>
where
    T: Http01ChallengeStore + ?Sized,
    P: Http01ChallengeProbe + ?Sized,
{
    challenges: &'a mut T,
    probe: &'a mut P,
    presented_tokens: Vec<String>,
}

impl<'a, T, P> Http01ChallengeRuntime<'a, T, P>
where
    T: Http01ChallengeStore + ?Sized,
    P: Http01ChallengeProbe + ?Sized,
{
    pub fn new(challenges: &'a mut T, probe: &'a mut P) -> Self {
        Self {
            challenges,
            probe,
            presented_tokens: Vec::new(),
        }
    }

    pub fn clear_presented_http01(&mut self) -> Result<(), AppError> {
        let mut first_error = None;
        for token in std::mem::take(&mut self.presented_tokens) {
            if let Err(error) = self.challenges.clear_http01(&token) {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }

        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl<T, P> AcmeHttp01ChallengeRuntime for Http01ChallengeRuntime<'_, T, P>
where
    T: Http01ChallengeStore + ?Sized,
    P: Http01ChallengeProbe + ?Sized,
{
    fn present_http01(&mut self, token: String, key_authorization: String) -> Result<(), AppError> {
        self.challenges
            .insert_http01(token.clone(), key_authorization)?;
        self.presented_tokens.push(token);
        Ok(())
    }

    fn verify_http01(
        &mut self,
        token: &str,
        expected_key_authorization: &str,
    ) -> Result<(), AppError> {
        self.probe.verify_http01(token, expected_key_authorization)
    }
}

pub struct CertificateIssuer<C, S, A> {
    pub acme: C,
    pub store: S,
    pub audit: A,
}

impl<C, S, A> CertificateIssuer<C, S, A>
where
    C: AcmeClient,
    S: CertificateStore,
    A: AuditSink,
{
    pub fn issue(&mut self, request: AcmeOrderRequest) -> Result<AcmeOrderResult, AppError> {
        self.issue_with_target_ref(None, request, "certificate.issue")
    }

    pub fn issue_for_ref(
        &mut self,
        certificate_ref: CertificateRef,
        request: AcmeOrderRequest,
    ) -> Result<AcmeOrderResult, AppError> {
        self.issue_with_target_ref(Some(certificate_ref), request, "certificate.issue")
    }

    pub fn issue_for_ref_with_http01(
        &mut self,
        certificate_ref: CertificateRef,
        request: AcmeOrderRequest,
        challenge_runtime: &mut dyn AcmeHttp01ChallengeRuntime,
    ) -> Result<AcmeOrderResult, AppError> {
        self.issue_with_target_ref_and_http01(
            Some(certificate_ref),
            request,
            challenge_runtime,
            "certificate.issue",
        )
    }

    pub fn renew_for_ref(
        &mut self,
        certificate_ref: CertificateRef,
        request: CertificateRenewRequest,
    ) -> Result<AcmeOrderResult, AppError> {
        let existing = self
            .store
            .load_certificate(&certificate_ref)?
            .ok_or_else(|| {
                AppError::new(
                    ErrorCode::CertificateNotFound,
                    format!("certificate not found: {}", certificate_ref.as_str()),
                )
            })?;

        self.issue_with_target_ref(
            Some(certificate_ref),
            AcmeOrderRequest {
                domains: existing.domains,
                account_email: request.account_email,
                production: request.production,
                terms_accepted: request.terms_accepted,
            },
            "certificate.renew",
        )
    }

    fn issue_with_target_ref(
        &mut self,
        certificate_ref: Option<CertificateRef>,
        request: AcmeOrderRequest,
        audit_event: &str,
    ) -> Result<AcmeOrderResult, AppError> {
        if request.production && !request.terms_accepted {
            return Err(AppError::new(
                ErrorCode::AcmeTermsNotAccepted,
                "production ACME requires terms acceptance",
            ));
        }

        let mut result = self.acme.issue_certificate(request)?;
        if let Some(certificate_ref) = certificate_ref {
            result.certificate.certificate_ref = certificate_ref;
        }
        self.store.save_certificate(result.certificate.clone())?;
        self.audit.record(AuditEvent {
            event: audit_event.to_string(),
            revision_id: None,
        })?;
        Ok(result)
    }

    fn issue_with_target_ref_and_http01(
        &mut self,
        certificate_ref: Option<CertificateRef>,
        request: AcmeOrderRequest,
        challenge_runtime: &mut dyn AcmeHttp01ChallengeRuntime,
        audit_event: &str,
    ) -> Result<AcmeOrderResult, AppError> {
        if request.production && !request.terms_accepted {
            return Err(AppError::new(
                ErrorCode::AcmeTermsNotAccepted,
                "production ACME requires terms acceptance",
            ));
        }

        let mut result = self
            .acme
            .issue_certificate_http01(request, challenge_runtime)?;
        if let Some(certificate_ref) = certificate_ref {
            result.certificate.certificate_ref = certificate_ref;
        }
        self.store.save_certificate(result.certificate.clone())?;
        self.audit.record(AuditEvent {
            event: audit_event.to_string(),
            revision_id: None,
        })?;
        Ok(result)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRenewRequest {
    pub account_email: String,
    pub production: bool,
    pub terms_accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateIssueOutcome {
    pub certificate_ref: CertificateRef,
    pub domains: Vec<String>,
    pub source: String,
    pub not_after_epoch_seconds: u64,
    pub commands_sent: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualCertificateImportRequest {
    pub certificate_ref: CertificateRef,
    pub domains: Vec<String>,
    pub fullchain_pem: String,
    pub private_key_pem: String,
    pub expected_not_after_epoch_seconds: Option<u64>,
    pub request_id: String,
    pub revision_id: ConfigRevisionId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualCertificateStatus {
    pub certificate_ref: CertificateRef,
    pub domains: Vec<String>,
    pub source: String,
    pub not_after_epoch_seconds: u64,
    pub private_key_masked: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualCertificateImportOutcome {
    pub status: ManualCertificateStatus,
    pub state: CertificateImportState,
    pub commands_sent: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualCertificateImportFailure {
    pub state: CertificateImportState,
    pub error: AppError,
    pub compensation_error: Option<AppError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateImportState {
    Received,
    Validated,
    Stored,
    InstallCommandSent,
    Installed,
    Failed {
        error_code: ErrorCode,
        compensation_failed: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateImportEvent {
    Validated,
    Stored,
    InstallCommandSent,
    Installed,
    Failed {
        error_code: ErrorCode,
        compensation_failed: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateImportMachine {
    state: CertificateImportState,
}

impl Default for CertificateImportMachine {
    fn default() -> Self {
        Self {
            state: CertificateImportState::Received,
        }
    }
}

impl CertificateImportMachine {
    pub fn state(&self) -> &CertificateImportState {
        &self.state
    }

    pub fn transition(&mut self, event: CertificateImportEvent) -> Result<(), AppError> {
        let next = match (&self.state, event) {
            (CertificateImportState::Received, CertificateImportEvent::Validated) => {
                CertificateImportState::Validated
            }
            (CertificateImportState::Validated, CertificateImportEvent::Stored) => {
                CertificateImportState::Stored
            }
            (CertificateImportState::Stored, CertificateImportEvent::InstallCommandSent) => {
                CertificateImportState::InstallCommandSent
            }
            (CertificateImportState::InstallCommandSent, CertificateImportEvent::Installed) => {
                CertificateImportState::Installed
            }
            (
                CertificateImportState::Received
                | CertificateImportState::Validated
                | CertificateImportState::Stored
                | CertificateImportState::InstallCommandSent,
                CertificateImportEvent::Failed {
                    error_code,
                    compensation_failed,
                },
            ) => CertificateImportState::Failed {
                error_code,
                compensation_failed,
            },
            (state, event) => {
                return Err(AppError::new(
                    ErrorCode::InternalBug,
                    format!("invalid certificate import transition: {state:?} + {event:?}"),
                ));
            }
        };
        self.state = next;
        Ok(())
    }
}

pub fn import_manual_certificate_and_install<V, S, A, K>(
    request: ManualCertificateImportRequest,
    validator: &mut V,
    store: &mut S,
    audit: &mut A,
    core: &mut K,
) -> Result<ManualCertificateImportOutcome, ManualCertificateImportFailure>
where
    V: CertificateMaterialValidator + ?Sized,
    S: CertificateStore + ?Sized,
    A: AuditSink + ?Sized,
    K: CoreCommandClient + ?Sized,
{
    let mut machine = CertificateImportMachine::default();
    let normalized = match normalize_manual_certificate_import_request(request) {
        Ok(normalized) => normalized,
        Err(error) => return Err(import_failure(&mut machine, error, None)),
    };

    let validated = match validator.validate(&normalized.material) {
        Ok(validated) => validated,
        Err(error) => return Err(import_failure(&mut machine, error, None)),
    };
    if validated.not_after_epoch_seconds == 0
        || normalized
            .expected_not_after_epoch_seconds
            .is_some_and(|expected| expected != validated.not_after_epoch_seconds)
    {
        return Err(import_failure(
            &mut machine,
            AppError::new(
                ErrorCode::CertificateInvalid,
                "certificate expiry does not match the validated leaf certificate",
            ),
            None,
        ));
    }
    if let Err(error) = validate_declared_domains_against_certificate_identities(
        &normalized.domains,
        &validated.dns_names,
    ) {
        return Err(import_failure(&mut machine, error, None));
    }
    transition_or_failure(&mut machine, CertificateImportEvent::Validated)?;

    let certificate = StoredCertificate {
        certificate_ref: normalized.certificate_ref.clone(),
        domains: normalized.domains.clone(),
        not_after_epoch_seconds: validated.not_after_epoch_seconds,
        source: "manual".to_string(),
        certificate_pem: normalized.material.certificate_pem,
        private_key_pem: normalized.material.private_key_pem,
    };
    let previous = match store.load_certificate(&certificate.certificate_ref) {
        Ok(previous) => previous,
        Err(error) => return Err(import_failure(&mut machine, error, None)),
    };
    if let Err(error) = store.save_certificate(certificate.clone()) {
        return Err(import_failure(&mut machine, error, None));
    }
    transition_or_failure(&mut machine, CertificateImportEvent::Stored)?;

    if let Err(error) = audit.record(AuditEvent {
        event: "certificate.import".to_string(),
        revision_id: Some(normalized.revision_id),
    }) {
        let compensation_error = restore_certificate(store, previous, &certificate.certificate_ref);
        return Err(import_failure(&mut machine, error, compensation_error));
    }

    transition_or_failure(&mut machine, CertificateImportEvent::InstallCommandSent)?;
    match core.send(CoreCommand::InstallCertificate {
        certificate_ref: certificate.certificate_ref.clone(),
    }) {
        CommandAck::Accepted => {
            transition_or_failure(&mut machine, CertificateImportEvent::Installed)?;
            let private_key_masked = certificate.masked_private_key();
            Ok(ManualCertificateImportOutcome {
                status: ManualCertificateStatus {
                    certificate_ref: certificate.certificate_ref,
                    domains: certificate.domains,
                    source: certificate.source,
                    not_after_epoch_seconds: certificate.not_after_epoch_seconds,
                    private_key_masked,
                },
                state: machine.state,
                commands_sent: 1,
            })
        }
        CommandAck::Rejected(error) => {
            let compensation_error =
                restore_certificate(store, previous, &certificate.certificate_ref);
            Err(import_failure(&mut machine, error, compensation_error))
        }
    }
}

struct NormalizedManualCertificateImport {
    certificate_ref: CertificateRef,
    domains: Vec<String>,
    material: CertificateMaterial,
    expected_not_after_epoch_seconds: Option<u64>,
    revision_id: ConfigRevisionId,
}

fn normalize_manual_certificate_import_request(
    request: ManualCertificateImportRequest,
) -> Result<NormalizedManualCertificateImport, AppError> {
    let certificate_ref = request.certificate_ref.as_str().trim();
    if certificate_ref.is_empty() {
        return Err(AppError::new(
            ErrorCode::CertificateInvalid,
            "certificate_ref must not be empty",
        ));
    }
    if request.fullchain_pem.trim().is_empty() || request.private_key_pem.trim().is_empty() {
        return Err(AppError::new(
            ErrorCode::CertificateInvalid,
            "certificate and private key PEM must not be empty",
        ));
    }

    let mut domains = BTreeSet::new();
    for domain in request.domains {
        let domain = normalize_host(&domain);
        if domain.is_empty()
            || domain.contains(char::is_whitespace)
            || domain.contains('/')
            || domain.contains('*')
        {
            return Err(AppError::new(
                ErrorCode::CertificateInvalid,
                "certificate domain is invalid or unsupported",
            ));
        }
        domains.insert(domain);
    }
    if domains.is_empty() {
        return Err(AppError::new(
            ErrorCode::CertificateInvalid,
            "at least one certificate domain is required",
        ));
    }

    Ok(NormalizedManualCertificateImport {
        certificate_ref: CertificateRef::new(certificate_ref),
        domains: domains.into_iter().collect(),
        material: CertificateMaterial {
            certificate_pem: request.fullchain_pem,
            private_key_pem: request.private_key_pem,
        },
        expected_not_after_epoch_seconds: request.expected_not_after_epoch_seconds,
        revision_id: request.revision_id,
    })
}

fn validate_declared_domains_against_certificate_identities(
    declared_domains: &[String],
    certificate_dns_names: &[String],
) -> Result<(), AppError> {
    if certificate_dns_names.is_empty() {
        return Err(certificate_identity_mismatch());
    }
    let identities = certificate_dns_names
        .iter()
        .filter_map(|identity| normalize_certificate_dns_identity(identity))
        .collect::<Vec<_>>();
    if identities.is_empty() {
        return Err(certificate_identity_mismatch());
    }
    for domain in declared_domains {
        if !identities
            .iter()
            .any(|identity| certificate_identity_covers_domain(identity, domain))
        {
            return Err(certificate_identity_mismatch());
        }
    }
    Ok(())
}

fn normalize_certificate_dns_identity(identity: &str) -> Option<String> {
    let normalized = normalize_host(identity);
    if normalized.is_empty()
        || normalized.contains(char::is_whitespace)
        || normalized.contains('/')
        || normalized == "*"
    {
        return None;
    }
    if let Some(suffix) = normalized.strip_prefix("*.") {
        if suffix.is_empty() || suffix.contains('*') {
            return None;
        }
        return Some(format!("*.{suffix}"));
    }
    (!normalized.contains('*')).then_some(normalized)
}

fn certificate_identity_covers_domain(identity: &str, domain: &str) -> bool {
    if let Some(suffix) = identity.strip_prefix("*.") {
        let Some(prefix) = domain.strip_suffix(&format!(".{suffix}")) else {
            return false;
        };
        return !prefix.is_empty() && !prefix.contains('.');
    }
    identity == domain
}

fn certificate_identity_mismatch() -> AppError {
    AppError::new(
        ErrorCode::CertificateInvalid,
        "certificate identity does not cover declared domain",
    )
}

fn restore_certificate<S: CertificateStore + ?Sized>(
    store: &mut S,
    previous: Option<StoredCertificate>,
    certificate_ref: &CertificateRef,
) -> Option<AppError> {
    let result = match previous {
        Some(previous) => store.save_certificate(previous),
        None => store.delete_certificate(certificate_ref),
    };
    result.err()
}

fn transition_or_failure(
    machine: &mut CertificateImportMachine,
    event: CertificateImportEvent,
) -> Result<(), ManualCertificateImportFailure> {
    machine
        .transition(event)
        .map_err(|error| import_failure(machine, error, None))
}

fn import_failure(
    machine: &mut CertificateImportMachine,
    error: AppError,
    compensation_error: Option<AppError>,
) -> ManualCertificateImportFailure {
    let compensation_failed = compensation_error.is_some();
    let _ = machine.transition(CertificateImportEvent::Failed {
        error_code: error.code,
        compensation_failed,
    });
    ManualCertificateImportFailure {
        state: machine.state.clone(),
        error,
        compensation_error,
    }
}

pub fn issue_certificate_for_ref_and_install<C, S, A, K>(
    issuer: &mut CertificateIssuer<C, S, A>,
    certificate_ref: CertificateRef,
    request: AcmeOrderRequest,
    core: &mut K,
) -> Result<CertificateIssueOutcome, AppError>
where
    C: AcmeClient,
    S: CertificateStore,
    A: AuditSink,
    K: CoreCommandClient + ?Sized,
{
    let result = issuer.issue_for_ref(certificate_ref, request)?;
    install_certificate_result(result, core)
}

pub fn issue_certificate_for_ref_with_http01_and_install<C, S, A, K, T, P>(
    issuer: &mut CertificateIssuer<C, S, A>,
    challenges: &mut T,
    probe: &mut P,
    certificate_ref: CertificateRef,
    request: AcmeOrderRequest,
    core: &mut K,
) -> Result<CertificateIssueOutcome, AppError>
where
    C: AcmeClient,
    S: CertificateStore,
    A: AuditSink,
    K: CoreCommandClient + ?Sized,
    T: Http01ChallengeStore + ?Sized,
    P: Http01ChallengeProbe + ?Sized,
{
    let mut challenge_runtime = Http01ChallengeRuntime::new(challenges, probe);
    let outcome = issuer
        .issue_for_ref_with_http01(certificate_ref, request, &mut challenge_runtime)
        .and_then(|result| install_certificate_result(result, core));
    let cleanup = challenge_runtime.clear_presented_http01();

    match (outcome, cleanup) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), _) => Err(error),
    }
}

pub fn renew_certificate_for_ref_and_install<C, S, A, K>(
    issuer: &mut CertificateIssuer<C, S, A>,
    certificate_ref: CertificateRef,
    request: CertificateRenewRequest,
    core: &mut K,
) -> Result<CertificateIssueOutcome, AppError>
where
    C: AcmeClient,
    S: CertificateStore,
    A: AuditSink,
    K: CoreCommandClient + ?Sized,
{
    let result = issuer.renew_for_ref(certificate_ref, request)?;
    install_certificate_result(result, core)
}

fn install_certificate_result<K>(
    result: AcmeOrderResult,
    core: &mut K,
) -> Result<CertificateIssueOutcome, AppError>
where
    K: CoreCommandClient + ?Sized,
{
    let certificate = result.certificate;
    match core.send(CoreCommand::InstallCertificate {
        certificate_ref: certificate.certificate_ref.clone(),
    }) {
        CommandAck::Accepted => Ok(CertificateIssueOutcome {
            certificate_ref: certificate.certificate_ref,
            domains: certificate.domains,
            source: certificate.source,
            not_after_epoch_seconds: certificate.not_after_epoch_seconds,
            commands_sent: 1,
        }),
        CommandAck::Rejected(error) => Err(error),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessLogEvent {
    pub request_id: String,
    pub revision_id: String,
    pub route_id: Option<String>,
    pub upstream_id: Option<String>,
    pub status_code: u16,
    pub duration_ms: u64,
    pub scheme: String,
    pub method: String,
    pub path: String,
}

pub fn structured_access_log(mode: &LogMode, event: &AccessLogEvent) -> StructuredLogEvent {
    let mut fields = vec![
        ("request_id".to_string(), event.request_id.clone()),
        ("revision_id".to_string(), event.revision_id.clone()),
        ("status_code".to_string(), event.status_code.to_string()),
        ("duration_ms".to_string(), event.duration_ms.to_string()),
        ("scheme".to_string(), event.scheme.clone()),
    ];

    if let Some(route_id) = &event.route_id {
        fields.push(("route_id".to_string(), route_id.clone()));
    }
    if let Some(upstream_id) = &event.upstream_id {
        fields.push(("upstream_id".to_string(), upstream_id.clone()));
    }
    if matches!(mode, LogMode::FieldDebug | LogMode::Dev) {
        fields.push(("method".to_string(), event.method.clone()));
        fields.push(("path".to_string(), event.path.clone()));
    }
    if matches!(mode, LogMode::Dev) {
        fields.push(("state".to_string(), "http.request.completed".to_string()));
    }

    StructuredLogEvent {
        component: "edge-core".to_string(),
        event: "access".to_string(),
        fields,
    }
}

pub fn record_access_log<L: LogSink>(
    sink: &mut L,
    mode: &LogMode,
    event: &AccessLogEvent,
) -> Result<(), AppError> {
    sink.record_log(structured_access_log(mode, event))
}

pub fn request_metrics(event: &AccessLogEvent) -> Vec<MetricEvent> {
    let route_id = event.route_id.as_deref().unwrap_or("unmatched").to_string();
    let status_class = match event.status_code / 100 {
        1..=5 => format!("{}xx", event.status_code / 100),
        _ => "other".to_string(),
    };
    vec![
        MetricEvent::counter_add(
            MetricDescriptor::RequestsTotal,
            1,
            vec![
                ("route_id".into(), route_id.clone()),
                ("status_class".into(), status_class),
            ],
        )
        .expect("request metric contract"),
        MetricEvent::histogram_observe(
            MetricDescriptor::RequestDuration,
            event.duration_ms,
            vec![("route_id".into(), route_id)],
        )
        .expect("duration metric contract"),
    ]
}

pub fn record_request_metrics<M: MetricsSink>(
    sink: &mut M,
    event: &AccessLogEvent,
) -> Result<(), AppError> {
    for metric in request_metrics(event) {
        sink.record_metric(metric)?;
    }
    Ok(())
}

pub fn upstream_failure_metric(
    route_id: Option<&str>,
    upstream_id: Option<&str>,
    error_code: ErrorCode,
) -> MetricEvent {
    MetricEvent::counter_add(
        MetricDescriptor::UpstreamFailuresTotal,
        1,
        vec![
            ("route_id".into(), route_id.unwrap_or("unmatched").into()),
            (
                "upstream_id".into(),
                upstream_id.unwrap_or("unmatched").into(),
            ),
            ("error_code".into(), error_code.as_str().into()),
        ],
    )
    .expect("upstream failure metric contract")
}

pub fn tls_handshake_failure_metric(error_code: ErrorCode) -> MetricEvent {
    MetricEvent::counter_add(
        MetricDescriptor::TlsHandshakeFailuresTotal,
        1,
        vec![("error_code".into(), error_code.as_str().into())],
    )
    .expect("TLS metric contract")
}

pub fn active_connection_metric(active_connections: i64) -> MetricEvent {
    MetricEvent::gauge_set(
        MetricDescriptor::ActiveConnections,
        active_connections,
        Vec::new(),
    )
    .expect("connection metric contract")
}

pub fn resource_payload_bytes_metric(used_bytes: usize) -> MetricEvent {
    MetricEvent::gauge_set(
        MetricDescriptor::ResourcePayloadBytes,
        i64::try_from(used_bytes).unwrap_or(i64::MAX),
        Vec::new(),
    )
    .expect("resource payload metric contract")
}

pub fn resource_payload_limit_bytes_metric(limit_bytes: usize) -> MetricEvent {
    MetricEvent::gauge_set(
        MetricDescriptor::ResourcePayloadLimitBytes,
        i64::try_from(limit_bytes).unwrap_or(i64::MAX),
        Vec::new(),
    )
    .expect("resource payload limit metric contract")
}

pub fn resource_admission_rejection_metric(
    resource_kind: ResourceMetricKind,
    reason: ResourceRejectionReason,
) -> MetricEvent {
    MetricEvent::counter_add(
        MetricDescriptor::ResourceAdmissionRejectionsTotal,
        1,
        vec![
            ("resource_kind".into(), resource_kind.as_str().into()),
            ("reason".into(), reason.as_str().into()),
        ],
    )
    .expect("resource admission metric contract")
}

pub fn build_info_metric(version: &str) -> MetricEvent {
    MetricEvent::gauge_set(
        MetricDescriptor::BuildInfo,
        1,
        vec![("version".into(), version.into())],
    )
    .expect("build info metric contract")
}

pub fn process_start_time_metric(epoch_seconds: u64) -> MetricEvent {
    MetricEvent::gauge_set(
        MetricDescriptor::ProcessStartTime,
        i64::try_from(epoch_seconds).unwrap_or(i64::MAX),
        Vec::new(),
    )
    .expect("process start time metric contract")
}

pub fn certificate_expiry_metric(certificate: &StoredCertificate) -> MetricEvent {
    MetricEvent::gauge_set(
        MetricDescriptor::CertificateNotAfter,
        i64::try_from(certificate.not_after_epoch_seconds).unwrap_or(i64::MAX),
        vec![
            (
                "certificate_ref".to_string(),
                certificate.certificate_ref.as_str().to_string(),
            ),
            ("source".to_string(), certificate.source.clone()),
        ],
    )
    .expect("certificate metric contract")
}

pub fn structured_config_apply_log(revision_id: &ConfigRevisionId) -> StructuredLogEvent {
    StructuredLogEvent {
        component: "edge-application".to_string(),
        event: "config.apply".to_string(),
        fields: vec![("revision_id".to_string(), revision_id.as_str().to_string())],
    }
}

pub fn structured_certificate_mutation_log(
    operation: &str,
    success: bool,
    request_id: &str,
    revision_id: &ConfigRevisionId,
    certificate_ref: &CertificateRef,
    status_code: u16,
    error_code: Option<&str>,
) -> StructuredLogEvent {
    let mut fields = vec![
        ("request_id".to_string(), request_id.to_string()),
        ("revision_id".to_string(), revision_id.as_str().to_string()),
        (
            "certificate_ref".to_string(),
            certificate_ref.as_str().to_string(),
        ),
        ("status_code".to_string(), status_code.to_string()),
    ];
    if let Some(error_code) = error_code {
        fields.push(("error_code".to_string(), error_code.to_string()));
    }

    StructuredLogEvent {
        component: "admin-api".to_string(),
        event: format!(
            "{operation}.{}",
            if success { "success" } else { "failure" }
        ),
        fields,
    }
}

pub fn structured_manual_certificate_import_log(
    success: bool,
    request_id: &str,
    revision_id: &ConfigRevisionId,
    certificate_ref: &CertificateRef,
    error_code: Option<&str>,
) -> StructuredLogEvent {
    let mut fields = vec![
        ("request_id".to_string(), request_id.to_string()),
        ("revision_id".to_string(), revision_id.as_str().to_string()),
        (
            "certificate_ref".to_string(),
            certificate_ref.as_str().to_string(),
        ),
        ("source".to_string(), "manual".to_string()),
    ];
    if let Some(error_code) = error_code {
        fields.push(("error_code".to_string(), error_code.to_string()));
    }
    StructuredLogEvent {
        component: "edge-application".to_string(),
        event: format!(
            "certificate.import.{}",
            if success { "success" } else { "failure" }
        ),
        fields,
    }
}

pub fn admin_auth_audit_event(success: bool) -> AuditEvent {
    AuditEvent {
        event: if success {
            "admin.login.success".to_string()
        } else {
            "admin.login.failure".to_string()
        },
        revision_id: None,
    }
}

pub fn record_admin_auth_audit<A: AuditSink>(sink: &mut A, success: bool) -> Result<(), AppError> {
    sink.record(admin_auth_audit_event(success))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestIdGenerator {
    prefix: String,
    next: u64,
}

impl RequestIdGenerator {
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
            next: 1,
        }
    }

    pub fn next_id(&mut self) -> String {
        let id = format!("{}-{:016x}", self.prefix, self.next);
        self.next += 1;
        id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedLogQueue {
    capacity: usize,
    events: VecDeque<StructuredLogEvent>,
    dropped_oldest: u64,
}

impl BoundedLogQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            events: VecDeque::new(),
            dropped_oldest: 0,
        }
    }

    pub fn push(&mut self, event: StructuredLogEvent) {
        if self.capacity == 0 {
            self.dropped_oldest += 1;
            return;
        }
        if self.events.len() >= self.capacity {
            self.events.pop_front();
            self.dropped_oldest += 1;
        }
        self.events.push_back(event);
    }

    pub fn events(&self) -> Vec<StructuredLogEvent> {
        self.events.iter().cloned().collect()
    }

    pub fn dropped_oldest(&self) -> u64 {
        self.dropped_oldest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecentAccessLogBuffer {
    capacity: usize,
    events: VecDeque<AccessLogEvent>,
}

impl RecentAccessLogBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            events: VecDeque::new(),
        }
    }

    pub fn push(&mut self, event: AccessLogEvent) {
        if self.capacity == 0 {
            return;
        }
        if self.events.len() >= self.capacity {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    pub fn recent(&self) -> Vec<AccessLogEvent> {
        self.events.iter().cloned().collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecentErrorEvent {
    pub request_id: Option<String>,
    pub error_code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecentErrorBuffer {
    capacity: usize,
    events: VecDeque<RecentErrorEvent>,
}

impl RecentErrorBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            events: VecDeque::new(),
        }
    }

    pub fn push(&mut self, event: RecentErrorEvent) {
        if self.capacity == 0 {
            return;
        }
        if self.events.len() >= self.capacity {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    pub fn recent(&self) -> Vec<RecentErrorEvent> {
        self.events.iter().cloned().collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyResult {
    pub revision_id: ConfigRevisionId,
    pub plan: ApplyPlan,
}

pub struct ConfigLifecycle<R, A> {
    pub revisions: R,
    pub audit: A,
    pub validator: ConfigValidator,
}

impl<R, A> ConfigLifecycle<R, A>
where
    R: ConfigRevisionRepository,
    A: AuditSink,
{
    pub fn apply(&mut self, snapshot: ConfigSnapshot) -> Result<ApplyResult, AppError> {
        self.validator
            .validate_snapshot(&snapshot)
            .into_result()
            .map_err(|errors| validation_errors_to_app_error(&errors))?;

        let revision = ConfigRevision {
            id: snapshot.revision_id.clone(),
            schema_version: snapshot.schema_version,
            summary: format!("apply {}", snapshot.revision_id),
        };
        let checksum = checksum_snapshot(&snapshot);
        let record = RevisionRecord {
            revision,
            snapshot: snapshot.clone(),
            checksum,
        };
        let current = self.revisions.current()?;
        let plan =
            plan_apply_with_current(current.as_ref().map(|record| &record.snapshot), snapshot);
        let revision_id = record.revision.id.clone();

        self.revisions.save_revision(record)?;
        self.revisions.set_current(&revision_id)?;
        self.audit.record(AuditEvent {
            event: "config.apply".to_string(),
            revision_id: Some(revision_id.clone()),
        })?;

        Ok(ApplyResult { revision_id, plan })
    }

    pub fn apply_with_core<C>(
        &mut self,
        snapshot: ConfigSnapshot,
        core: &mut C,
    ) -> Result<ApplyResult, AppError>
    where
        C: CoreCommandClient + ?Sized,
    {
        self.validator
            .validate_snapshot(&snapshot)
            .into_result()
            .map_err(|errors| validation_errors_to_app_error(&errors))?;

        let revision_id = snapshot.revision_id.clone();
        let record = revision_record_for_snapshot(snapshot.clone(), "apply");
        let current = self.revisions.current()?;
        let plan =
            plan_apply_with_current(current.as_ref().map(|record| &record.snapshot), snapshot);

        self.revisions.save_revision(record)?;
        if let Err(error) = send_apply_plan(core, &plan) {
            self.audit.record(AuditEvent {
                event: "config.apply.failure".to_string(),
                revision_id: Some(revision_id.clone()),
            })?;
            return Err(error);
        }

        self.revisions.set_current(&revision_id)?;
        self.audit.record(AuditEvent {
            event: "config.apply".to_string(),
            revision_id: Some(revision_id.clone()),
        })?;

        Ok(ApplyResult { revision_id, plan })
    }

    pub fn rollback(&mut self, revision_id: &ConfigRevisionId) -> Result<ApplyResult, AppError> {
        let record = self.revisions.find_revision(revision_id)?.ok_or_else(|| {
            AppError::new(
                ErrorCode::ConfigRevisionNotFound,
                format!("revision not found: {revision_id}"),
            )
        })?;
        let current = self.revisions.current()?;
        let plan = plan_apply_with_current(
            current.as_ref().map(|record| &record.snapshot),
            record.snapshot,
        );

        self.revisions.set_current(revision_id)?;
        self.audit.record(AuditEvent {
            event: "config.rollback".to_string(),
            revision_id: Some(revision_id.clone()),
        })?;

        Ok(ApplyResult {
            revision_id: revision_id.clone(),
            plan,
        })
    }

    pub fn rollback_with_core<C>(
        &mut self,
        revision_id: &ConfigRevisionId,
        core: &mut C,
    ) -> Result<ApplyResult, AppError>
    where
        C: CoreCommandClient + ?Sized,
    {
        let record = self.revisions.find_revision(revision_id)?.ok_or_else(|| {
            AppError::new(
                ErrorCode::ConfigRevisionNotFound,
                format!("revision not found: {revision_id}"),
            )
        })?;
        self.validator
            .validate_snapshot(&record.snapshot)
            .into_result()
            .map_err(|errors| validation_errors_to_app_error(&errors))?;
        let current = self.revisions.current()?;
        let plan = plan_apply_with_current(
            current.as_ref().map(|record| &record.snapshot),
            record.snapshot,
        );

        if let Err(error) = send_apply_plan(core, &plan) {
            self.audit.record(AuditEvent {
                event: "config.rollback.failure".to_string(),
                revision_id: Some(revision_id.clone()),
            })?;
            return Err(error);
        }

        self.revisions.set_current(revision_id)?;
        self.audit.record(AuditEvent {
            event: "config.rollback".to_string(),
            revision_id: Some(revision_id.clone()),
        })?;

        Ok(ApplyResult {
            revision_id: revision_id.clone(),
            plan,
        })
    }
}

pub fn checksum_snapshot(snapshot: &ConfigSnapshot) -> String {
    format!(
        "schema:{};revision:{};listeners:{};routes:{};services:{}",
        snapshot.schema_version,
        snapshot.revision_id,
        snapshot.listeners.len(),
        snapshot.routes.len(),
        snapshot.services.len()
    )
}

fn revision_record_for_snapshot(snapshot: ConfigSnapshot, action: &str) -> RevisionRecord {
    let revision = ConfigRevision {
        id: snapshot.revision_id.clone(),
        schema_version: snapshot.schema_version,
        summary: format!("{action} {}", snapshot.revision_id),
    };
    let checksum = checksum_snapshot(&snapshot);
    RevisionRecord {
        revision,
        snapshot,
        checksum,
    }
}

fn send_apply_plan<C>(core: &mut C, plan: &ApplyPlan) -> Result<(), AppError>
where
    C: CoreCommandClient + ?Sized,
{
    for command in plan.commands.iter().cloned() {
        match core.send(command) {
            CommandAck::Accepted => {}
            CommandAck::Rejected(error) => return Err(error),
        }
    }
    Ok(())
}

fn validation_errors_to_app_error(errors: &[ValidationError]) -> AppError {
    let first = errors.first().cloned().unwrap_or_else(|| {
        ValidationError::new(ErrorCode::InternalBug, "unknown validation error")
    });
    AppError::new(first.code, first.message)
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

fn route_name(route: &Route) -> String {
    route.id.as_str().to_string()
}

fn route_map(routes: &[Route]) -> BTreeMap<String, &Route> {
    routes
        .iter()
        .map(|route| (route_name(route), route))
        .collect()
}

fn upstream_map(snapshot: &ConfigSnapshot) -> BTreeMap<String, Vec<String>> {
    snapshot
        .services
        .iter()
        .map(|service| {
            (
                service.id.as_str().to_string(),
                std::iter::once(format!("policy:{:?}", service.policy))
                    .chain(service.upstreams.iter().map(|upstream| {
                        format!(
                            "{}|{}|{:?}",
                            upstream.id, upstream.url, upstream.administrative_state
                        )
                    }))
                    .collect(),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_domain::{
        AdminConfig, CertificateResolver, CertificateResolverId, HostMatch, Listener, ListenerId,
        PathMatch, Route, RouteId, RouteMatch, RuntimeOptions, Service, ServiceId, Upstream,
        UpstreamId,
    };
    use edge_ports::ValidatedCertificateMaterial;

    #[derive(Default)]
    struct MemoryRevisionRepo {
        records: Vec<RevisionRecord>,
        current: Option<ConfigRevisionId>,
        fail_save: bool,
    }

    impl ConfigRevisionRepository for MemoryRevisionRepo {
        fn save_revision(&mut self, record: RevisionRecord) -> Result<(), AppError> {
            if self.fail_save {
                return Err(AppError::new(ErrorCode::InternalBug, "save failed"));
            }
            self.records.push(record);
            Ok(())
        }

        fn set_current(&mut self, revision_id: &ConfigRevisionId) -> Result<(), AppError> {
            self.current = Some(revision_id.clone());
            Ok(())
        }

        fn current_revision_id(&self) -> Result<Option<ConfigRevisionId>, AppError> {
            Ok(self.current.clone())
        }

        fn current(&self) -> Result<Option<RevisionRecord>, AppError> {
            Ok(self
                .current
                .as_ref()
                .and_then(|current| {
                    self.records
                        .iter()
                        .find(|record| &record.revision.id == current)
                })
                .cloned())
        }

        fn find_revision(
            &self,
            revision_id: &ConfigRevisionId,
        ) -> Result<Option<RevisionRecord>, AppError> {
            Ok(self
                .records
                .iter()
                .find(|record| &record.revision.id == revision_id)
                .cloned())
        }

        fn history(&self) -> Result<Vec<RevisionRecord>, AppError> {
            Ok(self.records.clone())
        }
    }

    #[derive(Default)]
    struct MemoryBootstrapSeed {
        source: Option<String>,
        reads: usize,
    }

    impl BootstrapConfigSeed for MemoryBootstrapSeed {
        fn read_seed(&mut self) -> Result<Option<String>, AppError> {
            self.reads += 1;
            Ok(self.source.clone())
        }
    }

    #[derive(Default)]
    struct AcceptingStartupPreflight {
        revisions: Vec<String>,
    }

    impl StartupConfigPreflight for AcceptingStartupPreflight {
        fn preflight(&mut self, snapshot: &ConfigSnapshot) -> Result<(), AppError> {
            self.revisions
                .push(snapshot.revision_id.as_str().to_string());
            Ok(())
        }
    }

    #[test]
    fn startup_config_imports_seed_only_when_revision_repository_is_empty() {
        let mut revisions = MemoryRevisionRepo::default();
        let mut seed = MemoryBootstrapSeed {
            source: Some(render_mvp_config_snapshot(&valid_snapshot("seed-revision"))),
            reads: 0,
        };
        let mut preflight = AcceptingStartupPreflight::default();

        let resolved = ResolveStartupConfigUseCase::new(&mut revisions, &mut seed, &mut preflight)
            .execute()
            .unwrap()
            .unwrap();

        assert_eq!(resolved.origin, StartupConfigOrigin::BootstrapSeedImported);
        assert_eq!(resolved.snapshot.revision_id.as_str(), "bootstrap-seed");
        assert_eq!(seed.reads, 1);
        assert_eq!(
            revisions.current.as_ref().unwrap().as_str(),
            "bootstrap-seed"
        );
        assert_eq!(revisions.records.len(), 1);
    }

    #[test]
    fn startup_config_uses_repository_current_without_reading_seed() {
        let snapshot = valid_snapshot("admin-applied");
        let record = revision_record_for_snapshot(snapshot.clone(), "test");
        let mut revisions = MemoryRevisionRepo {
            records: vec![record],
            current: Some(snapshot.revision_id.clone()),
            fail_save: false,
        };
        let mut seed = MemoryBootstrapSeed {
            source: Some(render_mvp_config_snapshot(&valid_snapshot("stale-seed"))),
            reads: 0,
        };
        let mut preflight = AcceptingStartupPreflight::default();

        let resolved = ResolveStartupConfigUseCase::new(&mut revisions, &mut seed, &mut preflight)
            .execute()
            .unwrap()
            .unwrap();

        assert_eq!(resolved.origin, StartupConfigOrigin::RevisionCurrent);
        assert_eq!(resolved.snapshot.revision_id.as_str(), "admin-applied");
        assert_eq!(seed.reads, 0);
    }

    #[test]
    fn startup_config_rejects_non_empty_repository_without_valid_current_pointer() {
        let snapshot = valid_snapshot("orphaned");
        let mut revisions = MemoryRevisionRepo {
            records: vec![revision_record_for_snapshot(snapshot, "test")],
            current: None,
            fail_save: false,
        };
        let mut seed = MemoryBootstrapSeed::default();
        let mut preflight = AcceptingStartupPreflight::default();

        let error = ResolveStartupConfigUseCase::new(&mut revisions, &mut seed, &mut preflight)
            .execute()
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigCurrentRevisionMissing);
        assert_eq!(seed.reads, 0);
    }

    #[test]
    fn startup_config_keeps_empty_repository_unconfigured_when_seed_is_absent() {
        let mut revisions = MemoryRevisionRepo::default();
        let mut seed = MemoryBootstrapSeed::default();
        let mut preflight = AcceptingStartupPreflight::default();

        let resolved = ResolveStartupConfigUseCase::new(&mut revisions, &mut seed, &mut preflight)
            .execute()
            .unwrap();

        assert!(resolved.is_none());
        assert_eq!(seed.reads, 1);
        assert!(revisions.records.is_empty());
    }

    #[test]
    fn startup_config_resolution_machine_rejects_seed_read_for_present_repository() {
        let mut machine = StartupConfigResolutionMachine::default();

        machine
            .transition(StartupConfigResolutionEvent::RepositoryInspected { empty: false })
            .unwrap();
        let error = machine
            .transition(StartupConfigResolutionEvent::SeedRead)
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::InternalBug);
        assert_eq!(
            machine.state(),
            &StartupConfigResolutionState::ReadingCurrent
        );
    }

    #[derive(Default)]
    struct MemoryAudit {
        events: Vec<AuditEvent>,
    }

    impl AuditSink for MemoryAudit {
        fn record(&mut self, event: AuditEvent) -> Result<(), AppError> {
            self.events.push(event);
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeCoreCommandClient {
        commands: Vec<CoreCommand>,
        reject_after: Option<usize>,
    }

    impl CoreCommandClient for FakeCoreCommandClient {
        fn send(&mut self, command: CoreCommand) -> CommandAck {
            self.commands.push(command);
            if self
                .reject_after
                .is_some_and(|count| self.commands.len() >= count)
            {
                CommandAck::rejected(AppError::new(
                    ErrorCode::RuntimeCommandRejected,
                    "command rejected",
                ))
            } else {
                CommandAck::accepted()
            }
        }
    }

    pub(crate) fn valid_snapshot(revision: &str) -> ConfigSnapshot {
        ConfigSnapshot {
            schema_version: 1,
            revision_id: ConfigRevisionId::new(revision),
            admin: AdminConfig {
                bind: "127.0.0.1:9443".to_string(),
                auth_required: true,
            },
            listeners: vec![Listener {
                id: ListenerId::new("http"),
                bind: "0.0.0.0:8080".to_string(),
                protocol: ListenerProtocol::Http,
                client_auth: edge_domain::ClientAuthPolicy::Disabled,
            }],
            routes: vec![Route {
                id: RouteId::new("app"),
                route_match: RouteMatch::new(
                    vec![HostMatch::exact("example.com")],
                    vec![PathMatch::prefix("/")],
                ),
                service_id: ServiceId::new("app"),
                priority: 0,
                enabled: true,
                redirect_http_to_https: false,
                certificate_resolver_id: None,
                certificate_ref: None,
            }],
            services: vec![Service {
                policy: edge_domain::ServicePolicy::default(),
                id: ServiceId::new("app"),
                upstreams: vec![Upstream {
                    id: UpstreamId::new("app-1"),
                    url: "http://127.0.0.1:3000".to_string(),
                    administrative_state: UpstreamAdministrativeState::Active,
                    tls: edge_domain::UpstreamTlsPolicy::Disabled,
                }],
            }],
            certificate_resolvers: vec![],
            log_mode: edge_domain::LogMode::Product,
            runtime: RuntimeOptions {
                max_connections: 1024,
                max_inflight_payload_bytes: DEFAULT_MAX_INFLIGHT_PAYLOAD_BYTES,
                max_request_header_bytes: 16 * 1024,
                max_request_body_bytes: 1024 * 1024,
                upstream_read_timeout_ms: DEFAULT_UPSTREAM_READ_TIMEOUT_MS,
                metrics: edge_domain::MetricsConfig::default(),
            },
        }
    }

    #[test]
    fn exposes_crate_name() {
        assert_eq!(crate_name(), "edge-application");
    }

    #[test]
    fn valid_config_passes() {
        assert!(ConfigValidator::default()
            .validate_snapshot(&valid_snapshot("rev-1"))
            .is_valid());
    }

    #[test]
    fn parses_minimal_toml_config() {
        let source = include_str!("../../../examples/minimal.toml");
        let parsed = parse_mvp_config(source, ConfigRevisionId::new("file-current")).unwrap();

        assert!(parsed.schema_version_present);
        assert!(parsed.unknown_fields.is_empty());
        assert_eq!(parsed.snapshot.schema_version, 1);
        assert_eq!(parsed.snapshot.admin.bind, "127.0.0.1:9443");
        assert_eq!(parsed.snapshot.listeners[0].bind, "0.0.0.0:8080");
        assert_eq!(
            parsed.snapshot.listeners[0].client_auth,
            ClientAuthPolicy::Disabled
        );
        assert_eq!(
            parsed.snapshot.routes[0].route_match.hosts[0].as_str(),
            "localhost"
        );
        assert_eq!(
            parsed.snapshot.services[0].upstreams[0].url,
            "http://127.0.0.1:3000"
        );
        assert_eq!(
            parsed.snapshot.services[0].upstreams[0].tls,
            UpstreamTlsPolicy::Disabled
        );
        assert!(ConfigValidator::default()
            .validate_source(&parsed)
            .is_valid());
    }

    #[test]
    fn parses_and_renders_route_priority() {
        let source = include_str!("../../../examples/minimal.toml").replace(
            "service = \"example\"",
            "service = \"example\"\npriority = 42",
        );
        let parsed = parse_mvp_config(&source, ConfigRevisionId::new("priority")).unwrap();

        assert!(parsed.unknown_fields.is_empty());
        assert_eq!(parsed.snapshot.routes[0].priority, 42);
        assert!(render_mvp_config_snapshot(&parsed.snapshot).contains("priority = 42"));
    }

    #[test]
    fn parses_and_renders_exact_route_paths_without_changing_prefix_paths() {
        let source = include_str!("../../../examples/minimal.toml").replace(
            "paths = [\"/\"]",
            "paths = [\"/api\"]\nexact_paths = [\"/health\"]",
        );
        let parsed = parse_mvp_config(&source, ConfigRevisionId::new("exact-path")).unwrap();

        assert!(parsed.unknown_fields.is_empty());
        assert!(parsed.snapshot.routes[0].route_match.paths[0].matches("/api/child"));
        assert!(parsed.snapshot.routes[0].route_match.paths[1].matches("/health"));
        assert!(!parsed.snapshot.routes[0].route_match.paths[1].matches("/health/child"));
        let rendered = render_mvp_config_snapshot(&parsed.snapshot);
        assert!(rendered.contains("paths = [\"/api\"]"));
        assert!(rendered.contains("exact_paths = [\"/health\"]"));
    }

    #[test]
    fn runtime_resource_policy_defaults_parses_and_roundtrips_canonically() {
        let source = include_str!("../../../examples/minimal.toml");
        let legacy_source = source.replace("max_inflight_payload_bytes = 134217728\n", "");
        let defaulted =
            parse_mvp_config(&legacy_source, ConfigRevisionId::new("defaulted")).unwrap();
        assert_eq!(
            defaulted.snapshot.runtime.max_inflight_payload_bytes,
            edge_domain::DEFAULT_MAX_INFLIGHT_PAYLOAD_BYTES
        );
        assert_eq!(
            defaulted.snapshot.runtime.upstream_read_timeout_ms,
            edge_domain::DEFAULT_UPSTREAM_READ_TIMEOUT_MS
        );

        let explicit_source = source
            .replace("max_connections = 1024", "max_connections = 100")
            .replace(
                "max_inflight_payload_bytes = 134217728",
                "max_inflight_payload_bytes = 33554432",
            )
            .replace(
                "upstream_read_timeout_ms = 30000",
                "upstream_read_timeout_ms = 50",
            );
        let explicit =
            parse_mvp_config(&explicit_source, ConfigRevisionId::new("explicit")).unwrap();
        assert_eq!(explicit.snapshot.runtime.max_connections, 100);
        assert_eq!(
            explicit.snapshot.runtime.max_inflight_payload_bytes,
            32 * 1024 * 1024
        );
        assert_eq!(explicit.snapshot.runtime.upstream_read_timeout_ms, 50);
        assert!(ConfigValidator::default()
            .validate_source(&explicit)
            .is_valid());

        let rendered = render_mvp_config_snapshot(&explicit.snapshot);
        assert!(rendered.contains("max_inflight_payload_bytes = 33554432"));
        assert!(rendered.contains("upstream_read_timeout_ms = 50"));
        let reparsed = parse_mvp_config(&rendered, ConfigRevisionId::new("reparsed")).unwrap();
        assert_eq!(
            reparsed.snapshot.runtime.max_inflight_payload_bytes,
            explicit.snapshot.runtime.max_inflight_payload_bytes
        );
        assert_eq!(
            reparsed.snapshot.runtime.upstream_read_timeout_ms,
            explicit.snapshot.runtime.upstream_read_timeout_ms
        );
    }

    #[test]
    fn runtime_resource_policy_validation_rejects_invalid_bounds_and_relationship() {
        let validator = ConfigValidator::default();
        let invalid_cases = [
            (0, edge_domain::DEFAULT_MAX_INFLIGHT_PAYLOAD_BYTES),
            (
                edge_domain::HARD_MAX_CONNECTIONS + 1,
                edge_domain::DEFAULT_MAX_INFLIGHT_PAYLOAD_BYTES,
            ),
            (100, edge_domain::MIN_MAX_INFLIGHT_PAYLOAD_BYTES - 1),
            (100, edge_domain::HARD_MAX_INFLIGHT_PAYLOAD_BYTES + 1),
            (
                edge_domain::HARD_MAX_CONNECTIONS,
                edge_domain::DEFAULT_MAX_INFLIGHT_PAYLOAD_BYTES,
            ),
        ];

        for (max_connections, max_inflight_payload_bytes) in invalid_cases {
            let mut snapshot = valid_snapshot("invalid-resource-policy");
            snapshot.runtime.max_connections = max_connections;
            snapshot.runtime.max_inflight_payload_bytes = max_inflight_payload_bytes;

            let report = validator.validate_snapshot(&snapshot);
            assert!(report
                .errors
                .iter()
                .any(|error| { error.code == ErrorCode::ConfigResourceLimitInvalid }));
        }
    }

    #[test]
    fn runtime_timeout_policy_validation_rejects_invalid_bounds() {
        let validator = ConfigValidator::default();
        for invalid in [
            edge_domain::MIN_UPSTREAM_READ_TIMEOUT_MS - 1,
            edge_domain::HARD_MAX_UPSTREAM_READ_TIMEOUT_MS + 1,
        ] {
            let mut snapshot = valid_snapshot("invalid-timeout-policy");
            snapshot.runtime.upstream_read_timeout_ms = invalid;
            assert!(validator
                .validate_snapshot(&snapshot)
                .errors
                .iter()
                .any(|error| error.code == ErrorCode::ConfigResourceLimitInvalid));
        }
    }

    #[test]
    fn phase009_schema_v2_tls_policy_parses_and_roundtrips_canonically() {
        let source = include_str!("../../../examples/minimal.toml")
            .replace("schema_version = 1", "schema_version = 2")
            .replace(
                "protocol = \"http\"",
                "protocol = \"https\"\nclient_auth = \"required\"\nclient_trust_bundle_ref = \"private-client-root\"",
            )
            .replace(
                "url = \"http://127.0.0.1:3000\"",
                "url = \"https://127.0.0.1:3000\"\ntls_trust_bundle_ref = \"private-server-root\"\nupstream_http_host = \"backend.private.test\"\ntls_server_name = \"backend.private.test\"",
            );
        let parsed = parse_mvp_config(&source, ConfigRevisionId::new("v2")).unwrap();
        assert!(ConfigValidator::default()
            .validate_source(&parsed)
            .is_valid());
        assert!(matches!(
            parsed.snapshot.listeners[0].client_auth,
            ClientAuthPolicy::Required { .. }
        ));
        assert!(matches!(
            parsed.snapshot.services[0].upstreams[0].tls,
            UpstreamTlsPolicy::ServerAuthenticated { .. }
        ));
        let rendered = render_mvp_config_snapshot(&parsed.snapshot);
        let reparsed = parse_mvp_config(&rendered, ConfigRevisionId::new("v2-next")).unwrap();
        assert_eq!(
            reparsed.snapshot.listeners[0].client_auth,
            parsed.snapshot.listeners[0].client_auth
        );
        assert_eq!(
            reparsed.snapshot.services[0].upstreams[0].tls,
            parsed.snapshot.services[0].upstreams[0].tls
        );
    }

    #[test]
    fn phase009_schema_rejects_tls_fields_in_v1_and_incomplete_v2_policy() {
        let v1 = include_str!("../../../examples/minimal.toml").replace(
            "url = \"http://127.0.0.1:3000\"",
            "url = \"http://127.0.0.1:3000\"\ntls_server_name = \"backend.private.test\"",
        );
        assert_eq!(
            parse_mvp_config(&v1, ConfigRevisionId::new("bad-v1"))
                .unwrap_err()
                .code,
            ErrorCode::ConfigTlsPolicyInvalid
        );

        let incomplete = include_str!("../../../examples/minimal.toml")
            .replace("schema_version = 1", "schema_version = 2")
            .replace(
                "url = \"http://127.0.0.1:3000\"",
                "url = \"https://127.0.0.1:3000\"\ntls_server_name = \"backend.private.test\"",
            );
        assert_eq!(
            parse_mvp_config(&incomplete, ConfigRevisionId::new("bad-v2"))
                .unwrap_err()
                .code,
            ErrorCode::ConfigTlsPolicyInvalid
        );
    }

    #[test]
    fn metrics_config_defaults_disabled_and_roundtrips_enabled_loopback() {
        let legacy = parse_mvp_config(
            include_str!("../../../examples/minimal.toml"),
            ConfigRevisionId::new("legacy"),
        )
        .unwrap();
        assert!(!legacy.snapshot.runtime.metrics.enabled);
        assert_eq!(legacy.snapshot.runtime.metrics.bind, "127.0.0.1:9464");
        assert!(!render_mvp_config_snapshot(&legacy.snapshot).contains("[metrics]"));

        let source = format!(
            "{}\n[metrics]\nenabled = true\nbind = \"127.0.0.1:9465\"\n",
            include_str!("../../../examples/minimal.toml")
        );
        let parsed = parse_mvp_config(&source, ConfigRevisionId::new("metrics")).unwrap();
        assert!(ConfigValidator::default()
            .validate_source(&parsed)
            .is_valid());
        let rendered = render_mvp_config_snapshot(&parsed.snapshot);
        let reparsed = parse_mvp_config(&rendered, ConfigRevisionId::new("metrics-2")).unwrap();
        assert_eq!(
            reparsed.snapshot.runtime.metrics,
            parsed.snapshot.runtime.metrics
        );
    }

    #[test]
    fn enabled_metrics_rejects_non_loopback_and_change_requires_restart() {
        let mut source = parse_mvp_config(
            include_str!("../../../examples/minimal.toml"),
            ConfigRevisionId::new("current"),
        )
        .unwrap();
        let current = source.snapshot.clone();
        source.snapshot.runtime.metrics = MetricsConfig {
            enabled: true,
            bind: "0.0.0.0:9464".to_string(),
        };
        assert!(!ConfigValidator::default()
            .validate_source(&source)
            .is_valid());
        source.snapshot.runtime.metrics.bind = "127.0.0.1:9464".to_string();
        assert!(plan_apply_with_current(Some(&current), source.snapshot).restart_required);
    }

    #[test]
    fn legacy_single_upstream_normalizes_to_stable_primary_id() {
        let source = include_str!("../../../examples/minimal.toml");

        let parsed = parse_mvp_config(source, ConfigRevisionId::new("file-current")).unwrap();

        assert_eq!(
            parsed.snapshot.services[0].upstreams[0].id.as_str(),
            "example-primary"
        );
    }

    #[test]
    fn explicit_multi_upstream_names_parse_independent_of_key_order() {
        let source = r#"
schema_version = 1

[[services]]
name = "app"

[[services.upstreams]]
name = "app-a"
url = "http://127.0.0.1:3001"

[[services.upstreams]]
url = "http://127.0.0.1:3002"
name = "app-b"
"#;

        let parsed = parse_mvp_config(source, ConfigRevisionId::new("file-current")).unwrap();

        assert!(parsed.unknown_fields.is_empty());
        assert_eq!(parsed.snapshot.services[0].upstreams.len(), 2);
        assert_eq!(
            parsed.snapshot.services[0].upstreams[0].id.as_str(),
            "app-a"
        );
        assert_eq!(
            parsed.snapshot.services[0].upstreams[1].id.as_str(),
            "app-b"
        );
    }

    #[test]
    fn service_policy_config_parses_and_renders_losslessly() {
        let source = r#"
schema_version = 1
[[services]]
name = "app"
load_balancer = "round_robin"
[services.health_check]
enabled = true
path = "/ready"
interval_ms = 5000
timeout_ms = 1000
healthy_threshold = 1
unhealthy_threshold = 2
status_min = 200
status_max = 299
[[services.upstreams]]
name = "app-a"
url = "http://127.0.0.1:3001"
"#;

        let parsed = parse_mvp_config(source, ConfigRevisionId::new("rev-policy")).unwrap();
        assert!(parsed.unknown_fields.is_empty());
        assert_eq!(
            parsed.snapshot.services[0].policy.load_balancing,
            edge_domain::LoadBalancingPolicy::RoundRobin
        );
        assert!(matches!(
            parsed.snapshot.services[0].policy.health_check,
            edge_domain::HealthCheckPolicy::Http(_)
        ));

        let rendered = render_mvp_config_snapshot(&parsed.snapshot);
        let reparsed = parse_mvp_config(&rendered, ConfigRevisionId::new("rev-policy")).unwrap();
        assert_eq!(
            reparsed.snapshot.services[0].policy,
            parsed.snapshot.services[0].policy
        );
    }

    #[test]
    fn failure_aware_policy_config_parses_defaults_and_roundtrips() {
        let source = r#"
schema_version = 1
[[services]]
name = "app"
[services.retry]
enabled = true
max_retries = 1
max_replay_bytes = 32768
[services.passive_health]
enabled = true
failure_threshold = 3
ejection_ms = 30000
[[services.upstreams]]
name = "app-a"
url = "http://127.0.0.1:3001"
administrative_state = "active"
[[services.upstreams]]
name = "app-b"
url = "http://127.0.0.1:3002"
administrative_state = "draining"
"#;
        let parsed = parse_mvp_config(source, ConfigRevisionId::new("rev-failure")).unwrap();
        let service = &parsed.snapshot.services[0];
        assert_eq!(
            service.policy.retry,
            RetryPolicy::new(true, 1, 32_768).unwrap()
        );
        assert_eq!(
            service.policy.passive_health,
            PassiveHealthMode::Enabled(PassiveHealthPolicy::new(3, 30_000).unwrap())
        );
        assert_eq!(
            service.upstreams[1].administrative_state,
            UpstreamAdministrativeState::Draining
        );
        let rendered = render_mvp_config_snapshot(&parsed.snapshot);
        let reparsed = parse_mvp_config(&rendered, ConfigRevisionId::new("rev-failure")).unwrap();
        assert_eq!(reparsed.snapshot.services, parsed.snapshot.services);
    }

    #[test]
    fn failure_aware_policy_rejects_invalid_bounds_and_all_draining() {
        let invalid = "schema_version = 1\n[[services]]\nname = \"app\"\n[services.retry]\nenabled = true\nmax_retries = 0\nmax_replay_bytes = 32768\n";
        assert_eq!(
            parse_mvp_config(invalid, ConfigRevisionId::new("bad"))
                .unwrap_err()
                .code,
            ErrorCode::ConfigRetryPolicyInvalid
        );
        let mut snapshot = valid_snapshot("rev-drain");
        for upstream in &mut snapshot.services[0].upstreams {
            upstream.administrative_state = UpstreamAdministrativeState::Draining;
        }
        assert!(ConfigValidator::default()
            .validate_snapshot(&snapshot)
            .errors
            .iter()
            .any(|error| error.code == ErrorCode::ConfigServiceWithoutUpstream));
    }

    #[test]
    fn diff_reports_retry_passive_and_administrative_changes() {
        let current = valid_snapshot("rev-a");
        let mut next = current.clone();
        next.services[0].policy.retry = RetryPolicy::new(true, 1, 32_768).unwrap();
        assert_eq!(
            diff_config(Some(&current), &next).changed_upstreams,
            vec!["app"]
        );
        let mut drain = current.clone();
        drain.services[0].upstreams[0].administrative_state = UpstreamAdministrativeState::Draining;
        assert_eq!(
            diff_config(Some(&current), &drain).changed_upstreams,
            vec!["app"]
        );
    }

    #[test]
    fn unknown_load_balancing_policy_is_rejected_with_stable_error() {
        let error = parse_mvp_config(
            "schema_version = 1\n[[services]]\nname = \"app\"\nload_balancer = \"random\"\n",
            ConfigRevisionId::new("rev-policy"),
        )
        .unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigInvalidLoadBalancingPolicy);
    }

    #[test]
    fn invalid_health_policy_is_rejected_by_domain_constructor() {
        let source = r#"
schema_version = 1
[[services]]
name = "app"
[services.health_check]
enabled = true
interval_ms = 1000
timeout_ms = 1000
"#;

        let error = parse_mvp_config(source, ConfigRevisionId::new("rev-policy")).unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigHealthCheckInvalidInterval);
    }

    #[test]
    fn disabled_health_policy_canonicalizes_to_omitted_block() {
        let source = r#"
schema_version = 1
[[services]]
name = "app"
[services.health_check]
enabled = false
[[services.upstreams]]
url = "http://127.0.0.1:3001"
"#;

        let parsed = parse_mvp_config(source, ConfigRevisionId::new("rev-policy")).unwrap();
        let rendered = render_mvp_config_snapshot(&parsed.snapshot);

        assert_eq!(
            parsed.snapshot.services[0].policy.health_check,
            HealthCheckPolicy::Disabled
        );
        assert!(!rendered.contains("[services.health_check]"));
        assert!(rendered.contains("load_balancer = \"round_robin\""));
    }

    #[test]
    fn multiple_upstreams_without_explicit_names_are_rejected() {
        let source = r#"
schema_version = 1

[[services]]
name = "app"

[[services.upstreams]]
url = "http://127.0.0.1:3001"

[[services.upstreams]]
url = "http://127.0.0.1:3002"
"#;

        let error = parse_mvp_config(source, ConfigRevisionId::new("file-current")).unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigUpstreamIdRequired);
    }

    #[test]
    fn parser_records_unknown_fields() {
        let parsed = parse_mvp_config(
            "schema_version = 1\n[unknown]\nvalue = \"x\"\n",
            ConfigRevisionId::new("file-current"),
        )
        .unwrap();

        assert_eq!(parsed.unknown_fields, vec!["unknown.value"]);
        assert!(!ConfigValidator::default()
            .validate_source(&parsed)
            .is_valid());
    }

    #[test]
    fn renders_mvp_config_snapshot_for_file_repository_roundtrip() {
        let snapshot = valid_snapshot("rev-1");

        let rendered = render_mvp_config_snapshot(&snapshot);
        let parsed = parse_mvp_config(&rendered, ConfigRevisionId::new("rev-1")).unwrap();

        assert!(ConfigValidator::default()
            .validate_source(&parsed)
            .is_valid());
        assert_eq!(parsed.snapshot.listeners[0].bind, "0.0.0.0:8080");
        assert_eq!(
            parsed.snapshot.services[0].upstreams[0].url,
            "http://127.0.0.1:3000"
        );
        assert_eq!(
            parsed.snapshot.services[0].upstreams[0].id.as_str(),
            "app-1"
        );
        assert!(rendered.contains("name = \"app-1\"\nurl = \"http://127.0.0.1:3000\""));
        assert_eq!(
            parsed.snapshot.routes[0].route_match.hosts[0].as_str(),
            "example.com"
        );
    }

    #[test]
    fn config_schema_roundtrips_route_certificate_ref() {
        let mut snapshot = valid_snapshot("rev-1");
        snapshot.routes[0].certificate_ref = Some(CertificateRef::new("cert-example"));

        let rendered = render_mvp_config_snapshot(&snapshot);
        let parsed = parse_mvp_config(&rendered, ConfigRevisionId::new("rev-1")).unwrap();

        assert!(rendered.contains("certificate_ref = \"cert-example\""));
        assert_eq!(
            parsed.snapshot.routes[0]
                .certificate_ref
                .as_ref()
                .unwrap()
                .as_str(),
            "cert-example"
        );
    }

    #[test]
    fn schema_version_missing_fails() {
        let source = ConfigSource {
            snapshot: valid_snapshot("rev-1"),
            schema_version_present: false,
            unknown_fields: vec![],
        };
        let report = ConfigValidator::default().validate_source(&source);

        assert!(report
            .errors
            .iter()
            .any(|error| error.code == ErrorCode::ConfigSchemaVersionMissing));
    }

    #[test]
    fn duplicate_listener_fails() {
        let mut snapshot = valid_snapshot("rev-1");
        snapshot.listeners.push(snapshot.listeners[0].clone());

        let report = ConfigValidator::default().validate_snapshot(&snapshot);

        assert!(report
            .errors
            .iter()
            .any(|error| error.code == ErrorCode::ConfigListenerDuplicate));
    }

    #[test]
    fn invalid_listener_bind_fails() {
        let mut snapshot = valid_snapshot("rev-1");
        snapshot.listeners[0].bind = "not-a-socket-address".to_string();

        let report = ConfigValidator::default().validate_snapshot(&snapshot);

        assert!(report
            .errors
            .iter()
            .any(|error| error.code == ErrorCode::ConfigInvalidBindAddress));
    }

    #[test]
    fn admin_bind_conflict_fails() {
        let mut snapshot = valid_snapshot("rev-1");
        snapshot.admin.bind = "0.0.0.0:8080".to_string();

        let report = ConfigValidator::default().validate_snapshot(&snapshot);

        assert!(report
            .errors
            .iter()
            .any(|error| error.code == ErrorCode::ConfigAdminBindConflict));
    }

    #[test]
    fn empty_route_host_or_path_fails() {
        let mut snapshot = valid_snapshot("rev-1");
        snapshot.routes[0].route_match.hosts.clear();

        let report = ConfigValidator::default().validate_snapshot(&snapshot);

        assert!(report
            .errors
            .iter()
            .any(|error| error.code == ErrorCode::ConfigRouteMatchEmpty));
    }

    #[test]
    fn missing_service_fails() {
        let mut snapshot = valid_snapshot("rev-1");
        snapshot.routes[0].service_id = ServiceId::new("missing");

        let report = ConfigValidator::default().validate_snapshot(&snapshot);

        assert!(report
            .errors
            .iter()
            .any(|error| error.code == ErrorCode::ConfigRouteMissingService));
    }

    #[test]
    fn service_without_upstream_fails() {
        let mut snapshot = valid_snapshot("rev-1");
        snapshot.services[0].upstreams.clear();

        let report = ConfigValidator::default().validate_snapshot(&snapshot);

        assert!(report
            .errors
            .iter()
            .any(|error| error.code == ErrorCode::ConfigServiceWithoutUpstream));
    }

    #[test]
    fn duplicate_upstream_ids_fail_validation() {
        let mut snapshot = valid_snapshot("rev-1");
        let duplicate_id = snapshot.services[0].upstreams[0].id.clone();
        snapshot.services[0].upstreams.push(Upstream {
            id: duplicate_id,
            url: "http://127.0.0.1:3001".to_string(),
            administrative_state: UpstreamAdministrativeState::Active,
            tls: edge_domain::UpstreamTlsPolicy::Disabled,
        });

        let report = ConfigValidator::default().validate_snapshot(&snapshot);

        assert!(report
            .errors
            .iter()
            .any(|error| error.code == ErrorCode::ConfigUpstreamIdDuplicate));
    }

    #[test]
    fn duplicate_normalized_upstream_endpoints_fail_validation() {
        let mut snapshot = valid_snapshot("rev-1");
        snapshot.services[0].upstreams[0].url = "http://127.0.0.1".to_string();
        snapshot.services[0].upstreams.push(Upstream {
            id: UpstreamId::new("secondary"),
            url: "http://127.0.0.1:80".to_string(),
            administrative_state: UpstreamAdministrativeState::Active,
            tls: edge_domain::UpstreamTlsPolicy::Disabled,
        });

        let report = ConfigValidator::default().validate_snapshot(&snapshot);

        assert!(report.errors.iter().any(|error| {
            error.code == ErrorCode::ConfigInvalidUpstreamUrl
                && error.message.contains("duplicate normalized upstream")
        }));
    }

    #[test]
    fn invalid_upstream_url_fails() {
        let mut snapshot = valid_snapshot("rev-1");
        snapshot.services[0].upstreams[0].url = "https://127.0.0.1:3000".to_string();

        let report = ConfigValidator::default().validate_snapshot(&snapshot);

        assert!(report
            .errors
            .iter()
            .any(|error| error.code == ErrorCode::ConfigInvalidUpstreamUrl));
    }

    #[test]
    fn metadata_upstream_url_fails() {
        let mut snapshot = valid_snapshot("rev-1");
        snapshot.services[0].upstreams[0].url = "http://169.254.169.254/latest".to_string();

        let report = ConfigValidator::default().validate_snapshot(&snapshot);

        assert!(report
            .errors
            .iter()
            .any(|error| error.code == ErrorCode::ConfigUnsafeUpstreamUrl));
    }

    #[test]
    fn http01_without_http_listener_fails() {
        let mut snapshot = valid_snapshot("rev-1");
        snapshot.listeners.clear();
        snapshot.certificate_resolvers.push(CertificateResolver {
            id: CertificateResolverId::new("le"),
            email: "admin@example.com".to_string(),
            challenge: AcmeChallenge::Http01,
            production_enabled: false,
        });

        let report = ConfigValidator::default().validate_snapshot(&snapshot);

        assert!(report
            .errors
            .iter()
            .any(|error| error.code == ErrorCode::ConfigHttp01WithoutHttpListener));
    }

    #[test]
    fn invalid_acme_email_fails() {
        let mut snapshot = valid_snapshot("rev-1");
        snapshot.certificate_resolvers.push(CertificateResolver {
            id: CertificateResolverId::new("le"),
            email: "not-an-email".to_string(),
            challenge: AcmeChallenge::Http01,
            production_enabled: false,
        });

        let report = ConfigValidator::default().validate_snapshot(&snapshot);

        assert!(report
            .errors
            .iter()
            .any(|error| error.code == ErrorCode::ConfigInvalidAcmeEmail));
    }

    #[test]
    fn https_redirect_route_without_certificate_fails() {
        let mut snapshot = valid_snapshot("rev-1");
        snapshot.routes[0].redirect_http_to_https = true;

        let report = ConfigValidator::default().validate_snapshot(&snapshot);

        assert!(report
            .errors
            .iter()
            .any(|error| error.code == ErrorCode::ConfigHttpsRouteCertificateMissing));
    }

    #[test]
    fn normalized_host_path_duplicate_fails() {
        let mut snapshot = valid_snapshot("rev-1");
        let mut duplicate = snapshot.routes[0].clone();
        duplicate.id = RouteId::new("app-2");
        duplicate.route_match = RouteMatch::new(
            vec![HostMatch::exact("EXAMPLE.com.")],
            vec![PathMatch::prefix("/")],
        );
        snapshot.routes.push(duplicate);

        let report = ConfigValidator::default().validate_snapshot(&snapshot);

        assert!(report
            .errors
            .iter()
            .any(|error| error.code == ErrorCode::ConfigRouteDuplicate));
    }

    #[test]
    fn production_acme_requires_opt_in() {
        let mut snapshot = valid_snapshot("rev-1");
        snapshot.certificate_resolvers.push(CertificateResolver {
            id: CertificateResolverId::new("le"),
            email: "admin@example.com".to_string(),
            challenge: AcmeChallenge::Http01,
            production_enabled: true,
        });

        let report = ConfigValidator::default().validate_snapshot(&snapshot);

        assert!(report
            .errors
            .iter()
            .any(|error| error.code == ErrorCode::ConfigProductionAcmeRequiresOptIn));
    }

    #[test]
    fn diff_reports_added_and_removed_routes() {
        let current = valid_snapshot("rev-1");
        let mut next = valid_snapshot("rev-2");
        next.routes[0].id = RouteId::new("new");

        let diff = diff_config(Some(&current), &next);

        assert_eq!(diff.added_routes, vec!["new"]);
        assert_eq!(diff.removed_routes, vec!["app"]);
    }

    #[test]
    fn diff_reports_changed_upstreams() {
        let current = valid_snapshot("rev-1");
        let mut next = valid_snapshot("rev-2");
        next.services[0].upstreams[0].url = "http://127.0.0.1:4000".to_string();

        let diff = diff_config(Some(&current), &next);

        assert_eq!(diff.changed_upstreams, vec!["app"]);
    }

    #[test]
    fn plan_apply_marks_listener_bind_change_restart_required() {
        let current = valid_snapshot("rev-1");
        let mut next = valid_snapshot("rev-2");
        next.listeners[0].bind = "127.0.0.1:18080".to_string();

        let plan = plan_apply_with_current(Some(&current), next);

        assert!(plan.restart_required);
        assert!(plan.commands.is_empty());
        assert_eq!(
            plan.warnings,
            vec!["listener changes require process restart in MVP".to_string()]
        );
    }

    #[test]
    fn plan_apply_marks_resource_policy_change_restart_required() {
        let current = valid_snapshot("rev-1");
        let mut next = valid_snapshot("rev-2");
        next.runtime.max_connections = 100;
        next.runtime.max_inflight_payload_bytes = 32 * 1024 * 1024;

        let plan = plan_apply_with_current(Some(&current), next);

        assert!(plan.restart_required);
        assert!(plan.commands.is_empty());
        assert_eq!(
            plan.warnings,
            vec!["resource policy changes require process restart".to_string()]
        );
    }

    #[test]
    fn config_activation_state_distinguishes_aligned_and_pending_restart() {
        let active = valid_snapshot("rev-active");
        let aligned = active.clone();
        assert_eq!(
            config_activation_state(&active, &aligned),
            ConfigActivationState::Aligned
        );

        let mut pending = valid_snapshot("rev-desired");
        pending.runtime.max_connections = 100;
        pending.runtime.max_inflight_payload_bytes = 32 * 1024 * 1024;
        assert_eq!(
            config_activation_state(&active, &pending),
            ConfigActivationState::PendingRestart
        );
    }

    #[test]
    fn plan_apply_keeps_route_and_upstream_changes_hot_apply() {
        let current = valid_snapshot("rev-1");
        let mut next = valid_snapshot("rev-2");
        next.routes[0].priority += 1;
        next.services[0].upstreams[0].url = "http://127.0.0.1:4000".to_string();

        let plan = plan_apply_with_current(Some(&current), next);

        assert!(!plan.restart_required);
        assert!(matches!(
            plan.commands.first(),
            Some(CoreCommand::ApplyConfigSnapshot { .. })
        ));
        assert!(matches!(
            plan.commands.get(1),
            Some(CoreCommand::RefreshRouteTable)
        ));
    }

    #[test]
    fn apply_saves_revision_and_audit() {
        let mut lifecycle = ConfigLifecycle {
            revisions: MemoryRevisionRepo::default(),
            audit: MemoryAudit::default(),
            validator: ConfigValidator::default(),
        };

        let result = lifecycle.apply(valid_snapshot("rev-1")).unwrap();

        assert_eq!(result.revision_id.as_str(), "rev-1");
        assert_eq!(lifecycle.revisions.history().unwrap().len(), 1);
        assert_eq!(lifecycle.audit.events.len(), 1);
        assert!(matches!(
            result.plan.commands.first(),
            Some(CoreCommand::ApplyConfigSnapshot { .. })
        ));
    }

    #[test]
    fn apply_failure_keeps_current_config() {
        let repo = MemoryRevisionRepo {
            fail_save: true,
            ..MemoryRevisionRepo::default()
        };
        let mut lifecycle = ConfigLifecycle {
            revisions: repo,
            audit: MemoryAudit::default(),
            validator: ConfigValidator::default(),
        };

        let result = lifecycle.apply(valid_snapshot("rev-1"));

        assert!(result.is_err());
        assert!(lifecycle.revisions.current().unwrap().is_none());
    }

    #[test]
    fn config_lifecycle_apply_with_core_commits_current_after_command_ack() {
        let mut lifecycle = ConfigLifecycle {
            revisions: MemoryRevisionRepo::default(),
            audit: MemoryAudit::default(),
            validator: ConfigValidator::default(),
        };
        let mut client = FakeCoreCommandClient::default();

        let result = lifecycle
            .apply_with_core(valid_snapshot("rev-1"), &mut client)
            .unwrap();

        assert_eq!(result.revision_id.as_str(), "rev-1");
        assert_eq!(client.commands.len(), 2);
        assert!(matches!(
            client.commands.first(),
            Some(CoreCommand::ApplyConfigSnapshot { .. })
        ));
        assert_eq!(
            lifecycle
                .revisions
                .current()
                .unwrap()
                .unwrap()
                .revision
                .id
                .as_str(),
            "rev-1"
        );
        assert_eq!(lifecycle.audit.events[0].event, "config.apply");
    }

    #[test]
    fn config_lifecycle_apply_with_core_ack_failure_keeps_current_revision() {
        let mut lifecycle = ConfigLifecycle {
            revisions: MemoryRevisionRepo::default(),
            audit: MemoryAudit::default(),
            validator: ConfigValidator::default(),
        };
        let mut accept = FakeCoreCommandClient::default();
        lifecycle
            .apply_with_core(valid_snapshot("rev-1"), &mut accept)
            .unwrap();

        let mut reject = FakeCoreCommandClient {
            reject_after: Some(1),
            ..FakeCoreCommandClient::default()
        };
        let result = lifecycle.apply_with_core(valid_snapshot("rev-2"), &mut reject);

        assert!(result.is_err());
        assert_eq!(
            lifecycle
                .revisions
                .current()
                .unwrap()
                .unwrap()
                .revision
                .id
                .as_str(),
            "rev-1"
        );
        assert!(lifecycle
            .revisions
            .find_revision(&ConfigRevisionId::new("rev-2"))
            .unwrap()
            .is_some());
        assert_eq!(
            lifecycle.audit.events.last().unwrap().event,
            "config.apply.failure"
        );
    }

    #[test]
    fn config_lifecycle_listener_change_commits_restart_required_revision_without_hot_command() {
        let mut lifecycle = ConfigLifecycle {
            revisions: MemoryRevisionRepo::default(),
            audit: MemoryAudit::default(),
            validator: ConfigValidator::default(),
        };
        let mut client = FakeCoreCommandClient::default();
        lifecycle
            .apply_with_core(valid_snapshot("rev-1"), &mut client)
            .unwrap();

        let mut next = valid_snapshot("rev-2");
        next.listeners[0].bind = "127.0.0.1:18080".to_string();
        let result = lifecycle.apply_with_core(next, &mut client).unwrap();

        assert!(result.plan.restart_required);
        assert_eq!(client.commands.len(), 2);
        assert_eq!(
            lifecycle
                .revisions
                .current()
                .unwrap()
                .unwrap()
                .revision
                .id
                .as_str(),
            "rev-2"
        );
    }

    #[test]
    fn resource_policy_apply_and_pending_rollback_do_not_send_hot_commands() {
        let mut lifecycle = ConfigLifecycle {
            revisions: MemoryRevisionRepo::default(),
            audit: MemoryAudit::default(),
            validator: ConfigValidator::default(),
        };
        let mut client = FakeCoreCommandClient::default();
        lifecycle
            .apply_with_core(valid_snapshot("rev-1"), &mut client)
            .unwrap();
        assert_eq!(client.commands.len(), 2);

        let mut pending = valid_snapshot("rev-2");
        pending.runtime.max_connections = 100;
        pending.runtime.max_inflight_payload_bytes = 32 * 1024 * 1024;
        let apply = lifecycle.apply_with_core(pending, &mut client).unwrap();

        assert!(apply.plan.restart_required);
        assert_eq!(client.commands.len(), 2);
        assert_eq!(
            lifecycle
                .revisions
                .current()
                .unwrap()
                .unwrap()
                .revision
                .id
                .as_str(),
            "rev-2"
        );

        let rollback = lifecycle
            .rollback_with_core(&ConfigRevisionId::new("rev-1"), &mut client)
            .unwrap();
        assert!(rollback.plan.restart_required);
        assert_eq!(client.commands.len(), 2);
        assert_eq!(
            lifecycle
                .revisions
                .current()
                .unwrap()
                .unwrap()
                .revision
                .id
                .as_str(),
            "rev-1"
        );
    }

    #[test]
    fn invalid_resource_policy_apply_has_no_revision_core_or_audit_effect() {
        let mut lifecycle = ConfigLifecycle {
            revisions: MemoryRevisionRepo::default(),
            audit: MemoryAudit::default(),
            validator: ConfigValidator::default(),
        };
        let mut client = FakeCoreCommandClient::default();
        let mut invalid = valid_snapshot("invalid-resource");
        invalid.runtime.max_connections = 0;

        let error = lifecycle.apply_with_core(invalid, &mut client).unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigResourceLimitInvalid);
        assert!(lifecycle.revisions.history().unwrap().is_empty());
        assert!(lifecycle.revisions.current().unwrap().is_none());
        assert!(client.commands.is_empty());
        assert!(lifecycle.audit.events.is_empty());
    }

    #[test]
    fn rollback_activates_previous_revision() {
        let mut lifecycle = ConfigLifecycle {
            revisions: MemoryRevisionRepo::default(),
            audit: MemoryAudit::default(),
            validator: ConfigValidator::default(),
        };
        lifecycle.apply(valid_snapshot("rev-1")).unwrap();
        lifecycle.apply(valid_snapshot("rev-2")).unwrap();

        let result = lifecycle.rollback(&ConfigRevisionId::new("rev-1")).unwrap();

        assert_eq!(result.revision_id.as_str(), "rev-1");
        assert_eq!(
            lifecycle
                .revisions
                .current()
                .unwrap()
                .unwrap()
                .revision
                .id
                .as_str(),
            "rev-1"
        );
    }

    #[test]
    fn rollback_missing_revision_returns_clear_error() {
        let mut lifecycle = ConfigLifecycle {
            revisions: MemoryRevisionRepo::default(),
            audit: MemoryAudit::default(),
            validator: ConfigValidator::default(),
        };

        let error = lifecycle
            .rollback(&ConfigRevisionId::new("missing"))
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigRevisionNotFound);
    }

    #[test]
    fn config_lifecycle_rollback_with_core_applies_previous_revision_after_ack() {
        let mut lifecycle = ConfigLifecycle {
            revisions: MemoryRevisionRepo::default(),
            audit: MemoryAudit::default(),
            validator: ConfigValidator::default(),
        };
        let mut client = FakeCoreCommandClient::default();
        lifecycle
            .apply_with_core(valid_snapshot("rev-1"), &mut client)
            .unwrap();
        lifecycle
            .apply_with_core(valid_snapshot("rev-2"), &mut client)
            .unwrap();

        let result = lifecycle
            .rollback_with_core(&ConfigRevisionId::new("rev-1"), &mut client)
            .unwrap();

        assert_eq!(result.revision_id.as_str(), "rev-1");
        assert_eq!(
            lifecycle
                .revisions
                .current()
                .unwrap()
                .unwrap()
                .revision
                .id
                .as_str(),
            "rev-1"
        );
        assert!(matches!(
            client.commands.last(),
            Some(CoreCommand::RefreshRouteTable)
        ));
        assert_eq!(
            lifecycle.audit.events.last().unwrap().event,
            "config.rollback"
        );
    }

    #[test]
    fn config_lifecycle_rollback_with_core_ack_failure_keeps_current_revision() {
        let mut lifecycle = ConfigLifecycle {
            revisions: MemoryRevisionRepo::default(),
            audit: MemoryAudit::default(),
            validator: ConfigValidator::default(),
        };
        let mut accept = FakeCoreCommandClient::default();
        lifecycle
            .apply_with_core(valid_snapshot("rev-1"), &mut accept)
            .unwrap();
        lifecycle
            .apply_with_core(valid_snapshot("rev-2"), &mut accept)
            .unwrap();

        let mut reject = FakeCoreCommandClient {
            reject_after: Some(1),
            ..FakeCoreCommandClient::default()
        };
        let result = lifecycle.rollback_with_core(&ConfigRevisionId::new("rev-1"), &mut reject);

        assert!(result.is_err());
        assert_eq!(
            lifecycle
                .revisions
                .current()
                .unwrap()
                .unwrap()
                .revision
                .id
                .as_str(),
            "rev-2"
        );
        assert_eq!(
            lifecycle.audit.events.last().unwrap().event,
            "config.rollback.failure"
        );
    }

    #[test]
    fn proxy_host_generates_route_service_and_upstream() {
        let proxy_host = ProxyHost {
            id: ProxyHostId::new("app"),
            name: "App".to_string(),
            domains: vec![HostMatch::exact("app.example.com")],
            path_prefix: PathMatch::prefix("/"),
            upstream_url: "http://127.0.0.1:3000".to_string(),
            upstreams: vec![],
            health_check: HealthCheckPolicy::Disabled,
            retry: RetryPolicy::default(),
            passive_health: PassiveHealthMode::Disabled,
            https_enabled: true,
            letsencrypt_enabled: true,
            redirect_http_to_https: true,
            enabled: true,
        };

        let parts = proxy_host_to_parts(&proxy_host);

        assert_eq!(parts.route.id.as_str(), "proxy-host-app");
        assert_eq!(parts.route.service_id.as_str(), "proxy-host-app");
        assert!(parts.route.certificate_ref.is_some());
        assert_eq!(
            parts.service.upstreams[0].url,
            "http://127.0.0.1:3000".to_string()
        );
    }

    #[test]
    fn proxy_host_add_remove_and_disable_updates_snapshot() {
        let mut snapshot = valid_snapshot("rev-1");
        snapshot.runtime.max_connections = 100;
        snapshot.runtime.max_inflight_payload_bytes = 32 * 1024 * 1024;
        let proxy_host = ProxyHost {
            id: ProxyHostId::new("admin"),
            name: "Admin".to_string(),
            domains: vec![HostMatch::exact("admin.example.com")],
            path_prefix: PathMatch::prefix("/"),
            upstream_url: "http://127.0.0.1:4000".to_string(),
            upstreams: vec![],
            health_check: HealthCheckPolicy::Disabled,
            retry: RetryPolicy::default(),
            passive_health: PassiveHealthMode::Disabled,
            https_enabled: false,
            letsencrypt_enabled: false,
            redirect_http_to_https: false,
            enabled: true,
        };

        let added = add_proxy_host(&snapshot, &proxy_host);
        assert!(added.select_route("admin.example.com", "/").is_some());

        let disabled = set_proxy_host_enabled(&added, &ProxyHostId::new("admin"), false);
        assert!(disabled.select_route("admin.example.com", "/").is_none());
        assert_eq!(
            disabled.runtime.max_inflight_payload_bytes,
            snapshot.runtime.max_inflight_payload_bytes
        );

        let removed = remove_proxy_host(&added, &ProxyHostId::new("admin"));
        assert!(removed.select_route("admin.example.com", "/").is_none());
        assert!(!removed
            .services
            .iter()
            .any(|service| service.id.as_str() == "proxy-host-admin"));

        let rendered = render_mvp_config_snapshot(&removed);
        let reparsed = parse_mvp_config(&rendered, ConfigRevisionId::new("rev-2")).unwrap();
        assert_eq!(reparsed.snapshot.runtime, snapshot.runtime);
    }

    #[test]
    fn proxy_host_update_replaces_route_service_and_upstream() {
        let original = ProxyHost {
            id: ProxyHostId::new("app"),
            name: "App".to_string(),
            domains: vec![HostMatch::exact("app.example.com")],
            path_prefix: PathMatch::prefix("/"),
            upstream_url: "http://127.0.0.1:3000".to_string(),
            upstreams: vec![],
            health_check: HealthCheckPolicy::Disabled,
            retry: RetryPolicy::default(),
            passive_health: PassiveHealthMode::Disabled,
            https_enabled: false,
            letsencrypt_enabled: false,
            redirect_http_to_https: false,
            enabled: true,
        };
        let updated = ProxyHost {
            upstream_url: "http://127.0.0.1:4000".to_string(),
            path_prefix: PathMatch::prefix("/api"),
            ..original.clone()
        };

        let snapshot = add_proxy_host(&valid_snapshot("rev-1"), &original);
        let snapshot = update_proxy_host(&snapshot, &updated);

        let route = snapshot
            .select_route("app.example.com", "/api/users")
            .unwrap();
        let service = snapshot
            .services
            .iter()
            .find(|service| service.id == route.service_id)
            .unwrap();

        assert!(snapshot.select_route("app.example.com", "/").is_none());
        assert_eq!(service.upstreams[0].url, "http://127.0.0.1:4000");
        assert_eq!(
            snapshot
                .routes
                .iter()
                .filter(|route| route.id.as_str() == "proxy-host-app")
                .count(),
            1
        );
    }

    #[test]
    fn proxy_host_matches_any_declared_domain() {
        let proxy_host = ProxyHost {
            id: ProxyHostId::new("app"),
            name: "App".to_string(),
            domains: vec![
                HostMatch::exact("app.example.com"),
                HostMatch::exact("alt.example.com"),
            ],
            path_prefix: PathMatch::prefix("/"),
            upstream_url: "http://127.0.0.1:3000".to_string(),
            upstreams: vec![],
            health_check: HealthCheckPolicy::Disabled,
            retry: RetryPolicy::default(),
            passive_health: PassiveHealthMode::Disabled,
            https_enabled: false,
            letsencrypt_enabled: false,
            redirect_http_to_https: false,
            enabled: true,
        };

        let snapshot = add_proxy_host(&valid_snapshot("rev-1"), &proxy_host);

        assert!(snapshot.select_route("app.example.com", "/").is_some());
        assert!(snapshot.select_route("alt.example.com", "/").is_some());
    }

    #[test]
    fn unknown_host_route_action_is_not_found() {
        let action = select_http_route_action(&valid_snapshot("rev-1"), "missing.example.com", "/");

        assert_eq!(action, HttpRouteAction::NotFound);
    }

    #[test]
    fn redirect_route_action_returns_permanent_redirect() {
        let mut snapshot = valid_snapshot("rev-1");
        snapshot.routes[0].redirect_http_to_https = true;
        snapshot.routes[0].certificate_ref = Some(CertificateRef::new("cert-app"));

        let action = select_http_route_action(&snapshot, "example.com", "/login");

        assert_eq!(
            action,
            HttpRouteAction::Redirect {
                status_code: 308,
                location: "https://example.com/login".to_string()
            }
        );
    }

    #[test]
    fn acme_challenge_path_bypasses_redirect_route_action() {
        let mut snapshot = valid_snapshot("rev-1");
        snapshot.routes[0].redirect_http_to_https = true;
        snapshot.routes[0].certificate_ref = Some(CertificateRef::new("cert-app"));

        let action =
            select_http_route_action(&snapshot, "example.com", "/.well-known/acme-challenge/t1");

        assert_eq!(
            action,
            HttpRouteAction::AcmeChallengeBypass {
                token: "t1".to_string()
            }
        );
    }

    fn stored_certificate(
        certificate_ref: &str,
        not_after_epoch_seconds: u64,
    ) -> StoredCertificate {
        StoredCertificate {
            certificate_ref: CertificateRef::new(certificate_ref),
            domains: vec!["app.example.com".to_string()],
            not_after_epoch_seconds,
            source: "manual".to_string(),
            certificate_pem: "cert".to_string(),
            private_key_pem: "secret-key".to_string(),
        }
    }

    #[test]
    fn certificate_status_masks_key_and_marks_expiry() {
        let cert = stored_certificate("cert-app", 1_000);

        let status = certificate_status(&cert, 900, 200);

        assert!(!status.expired);
        assert!(status.expiring_soon);
        assert_eq!(status.private_key_masked, "***");
    }

    #[test]
    fn certificate_renewal_is_due_inside_window() {
        let cert = stored_certificate("cert-app", 1_000);

        let decision = plan_certificate_renewal(&cert, 900, 200);

        assert_eq!(
            decision,
            CertificateRenewalDecision::RenewalDue {
                certificate_ref: CertificateRef::new("cert-app"),
                domains: vec!["app.example.com".to_string()],
                reason: RenewalDueReason::InsideWindow,
            }
        );
    }

    #[test]
    fn certificate_renewal_is_skipped_outside_window() {
        let cert = stored_certificate("cert-app", 1_000);

        let decision = plan_certificate_renewal(&cert, 700, 200);

        assert_eq!(
            decision,
            CertificateRenewalDecision::RenewalSkipped {
                certificate_ref: CertificateRef::new("cert-app"),
                reason: RenewalSkipReason::OutsideWindow,
            }
        );
    }

    #[test]
    fn certificate_renewal_retryable_failure_sets_next_retry() {
        let error = AppError::new(ErrorCode::AcmeChallengeFailed, "challenge failed");

        let decision = renewal_failure_decision(
            CertificateRef::new("cert-app"),
            &error,
            1_000,
            2,
            RenewalRetryPolicy {
                max_attempts: 3,
                backoff_seconds: 30,
            },
        );

        assert_eq!(
            decision,
            CertificateRenewalDecision::RenewalFailed {
                certificate_ref: CertificateRef::new("cert-app"),
                error_code: ErrorCode::AcmeChallengeFailed,
                retryable: true,
                failed_attempts: 2,
                next_retry_epoch_seconds: Some(1_060),
            }
        );
    }

    #[test]
    fn certificate_renewal_fatal_failure_has_no_retry() {
        let error = AppError::new(ErrorCode::AcmeTermsNotAccepted, "terms required");

        let decision = renewal_failure_decision(
            CertificateRef::new("cert-app"),
            &error,
            1_000,
            1,
            RenewalRetryPolicy {
                max_attempts: 3,
                backoff_seconds: 30,
            },
        );

        assert_eq!(
            decision,
            CertificateRenewalDecision::RenewalFailed {
                certificate_ref: CertificateRef::new("cert-app"),
                error_code: ErrorCode::AcmeTermsNotAccepted,
                retryable: false,
                failed_attempts: 1,
                next_retry_epoch_seconds: None,
            }
        );
    }

    #[test]
    fn certificate_renewal_retryable_failure_stops_at_max_attempts() {
        let error = AppError::new(ErrorCode::AcmeChallengeFailed, "challenge failed");

        let decision = renewal_failure_decision(
            CertificateRef::new("cert-app"),
            &error,
            1_000,
            3,
            RenewalRetryPolicy {
                max_attempts: 3,
                backoff_seconds: 30,
            },
        );

        assert_eq!(
            decision,
            CertificateRenewalDecision::RenewalFailed {
                certificate_ref: CertificateRef::new("cert-app"),
                error_code: ErrorCode::AcmeChallengeFailed,
                retryable: false,
                failed_attempts: 3,
                next_retry_epoch_seconds: None,
            }
        );
    }

    #[test]
    fn http01_token_store_matches_exact_token() {
        let mut store = Http01TokenStore::default();
        store.insert(Http01Token {
            token: "abc".to_string(),
            key_authorization: "abc.key".to_string(),
        });

        assert_eq!(store.respond("abc"), Some("abc.key"));
        assert_eq!(store.respond("abcd"), None);
        store.clear("abc");
        assert_eq!(store.respond("abc"), None);
    }

    #[derive(Default)]
    struct FakeAcme {
        fail: bool,
        issued: Vec<AcmeOrderRequest>,
    }

    impl AcmeClient for FakeAcme {
        fn issue_certificate(
            &mut self,
            request: AcmeOrderRequest,
        ) -> Result<AcmeOrderResult, AppError> {
            self.issued.push(request.clone());
            if self.fail {
                return Err(AppError::new(
                    ErrorCode::AcmeChallengeFailed,
                    "challenge failed",
                ));
            }
            Ok(AcmeOrderResult {
                certificate: StoredCertificate {
                    certificate_ref: CertificateRef::new("acme-app"),
                    domains: request.domains,
                    not_after_epoch_seconds: 10_000,
                    source: "acme".to_string(),
                    certificate_pem: "cert".to_string(),
                    private_key_pem: "key".to_string(),
                },
            })
        }

        fn issue_certificate_http01(
            &mut self,
            request: AcmeOrderRequest,
            challenge_runtime: &mut dyn AcmeHttp01ChallengeRuntime,
        ) -> Result<AcmeOrderResult, AppError> {
            let token = fake_http01_token(&request);
            let key_authorization = fake_http01_key_authorization(&token);
            challenge_runtime.present_http01(token.clone(), key_authorization.clone())?;
            challenge_runtime.verify_http01(&token, &key_authorization)?;
            self.issue_certificate(request)
        }
    }

    fn fake_http01_token(request: &AcmeOrderRequest) -> String {
        let first_domain = request
            .domains
            .first()
            .cloned()
            .unwrap_or_else(|| "empty-domain".to_string())
            .replace('.', "-");
        format!("fake-acme-http01-{first_domain}")
    }

    fn fake_http01_key_authorization(token: &str) -> String {
        format!("{token}.fake-acme-account-thumbprint")
    }

    #[derive(Default)]
    struct FakeHttp01Probe {
        fail: bool,
        verified: Vec<(String, String)>,
    }

    impl Http01ChallengeProbe for FakeHttp01Probe {
        fn verify_http01(
            &mut self,
            token: &str,
            expected_key_authorization: &str,
        ) -> Result<(), AppError> {
            self.verified
                .push((token.to_string(), expected_key_authorization.to_string()));
            if self.fail {
                Err(AppError::new(
                    ErrorCode::AcmeChallengeFailed,
                    "HTTP-01 probe failed",
                ))
            } else {
                Ok(())
            }
        }
    }

    #[derive(Default)]
    struct MemoryCertStore {
        saved: Vec<StoredCertificate>,
    }

    impl CertificateStore for MemoryCertStore {
        fn save_certificate(&mut self, certificate: StoredCertificate) -> Result<(), AppError> {
            self.saved.push(certificate);
            Ok(())
        }

        fn load_certificate(
            &self,
            certificate_ref: &CertificateRef,
        ) -> Result<Option<StoredCertificate>, AppError> {
            Ok(self
                .saved
                .iter()
                .find(|cert| &cert.certificate_ref == certificate_ref)
                .cloned())
        }

        fn list_certificates(&self) -> Result<Vec<StoredCertificate>, AppError> {
            Ok(self.saved.clone())
        }

        fn delete_certificate(&mut self, certificate_ref: &CertificateRef) -> Result<(), AppError> {
            self.saved
                .retain(|certificate| &certificate.certificate_ref != certificate_ref);
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeCertificateMaterialValidator {
        calls: usize,
        reject: bool,
        not_after_epoch_seconds: u64,
        dns_names: Vec<String>,
    }

    impl CertificateMaterialValidator for FakeCertificateMaterialValidator {
        fn validate(
            &mut self,
            _material: &CertificateMaterial,
        ) -> Result<ValidatedCertificateMaterial, AppError> {
            self.calls += 1;
            if self.reject {
                return Err(AppError::new(
                    ErrorCode::CertificateInvalid,
                    "certificate and private key do not match",
                ));
            }
            Ok(ValidatedCertificateMaterial {
                not_after_epoch_seconds: self.not_after_epoch_seconds,
                dns_names: if self.dns_names.is_empty() {
                    vec!["app.example.com".to_string()]
                } else {
                    self.dns_names.clone()
                },
            })
        }
    }

    #[derive(Default)]
    struct ImportCertificateStore {
        certificate: Option<StoredCertificate>,
        saves: usize,
        deletes: usize,
        fail_on_save: Option<usize>,
        fail_delete: bool,
    }

    struct RejectingAudit;

    impl AuditSink for RejectingAudit {
        fn record(&mut self, _event: AuditEvent) -> Result<(), AppError> {
            Err(AppError::new(ErrorCode::InternalBug, "audit unavailable"))
        }
    }

    impl CertificateStore for ImportCertificateStore {
        fn save_certificate(&mut self, certificate: StoredCertificate) -> Result<(), AppError> {
            self.saves += 1;
            if self.fail_on_save == Some(self.saves) {
                return Err(AppError::new(
                    ErrorCode::CertificateStoreFailed,
                    "certificate save rejected",
                ));
            }
            self.certificate = Some(certificate);
            Ok(())
        }

        fn load_certificate(
            &self,
            certificate_ref: &CertificateRef,
        ) -> Result<Option<StoredCertificate>, AppError> {
            Ok(self
                .certificate
                .as_ref()
                .filter(|certificate| &certificate.certificate_ref == certificate_ref)
                .cloned())
        }

        fn list_certificates(&self) -> Result<Vec<StoredCertificate>, AppError> {
            Ok(self.certificate.iter().cloned().collect())
        }

        fn delete_certificate(&mut self, certificate_ref: &CertificateRef) -> Result<(), AppError> {
            self.deletes += 1;
            if self.fail_delete {
                return Err(AppError::new(
                    ErrorCode::CertificateStoreFailed,
                    "certificate delete rejected",
                ));
            }
            if self
                .certificate
                .as_ref()
                .is_some_and(|certificate| &certificate.certificate_ref == certificate_ref)
            {
                self.certificate = None;
            }
            Ok(())
        }
    }

    fn manual_certificate_import_request() -> ManualCertificateImportRequest {
        ManualCertificateImportRequest {
            certificate_ref: CertificateRef::new("proxy-host-app"),
            domains: vec![
                " App.Example.com. ".to_string(),
                "app.example.com".to_string(),
            ],
            fullchain_pem: "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----"
                .to_string(),
            private_key_pem: "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"
                .to_string(),
            expected_not_after_epoch_seconds: None,
            request_id: "req-import-1".to_string(),
            revision_id: ConfigRevisionId::new("rev-42"),
        }
    }

    #[test]
    fn certificate_import_validates_stores_audits_and_installs_manual_material() {
        let mut validator = FakeCertificateMaterialValidator {
            not_after_epoch_seconds: 4_000_000_000,
            dns_names: vec!["app.example.com".to_string()],
            ..FakeCertificateMaterialValidator::default()
        };
        let mut store = ImportCertificateStore::default();
        let mut audit = MemoryAudit::default();
        let mut core = FakeCoreCommandClient::default();

        let outcome = import_manual_certificate_and_install(
            manual_certificate_import_request(),
            &mut validator,
            &mut store,
            &mut audit,
            &mut core,
        )
        .unwrap();

        assert_eq!(outcome.state, CertificateImportState::Installed);
        assert_eq!(outcome.status.private_key_masked, "***");
        assert_eq!(outcome.status.source, "manual");
        assert_eq!(outcome.status.domains, vec!["app.example.com"]);
        assert_eq!(validator.calls, 1);
        assert_eq!(store.saves, 1);
        assert_eq!(audit.events[0].event, "certificate.import");
        assert!(matches!(
            core.commands.as_slice(),
            [CoreCommand::InstallCertificate { certificate_ref }]
                if certificate_ref.as_str() == "proxy-host-app"
        ));
    }

    #[test]
    fn certificate_import_rejects_empty_input_before_external_ports() {
        let mut request = manual_certificate_import_request();
        request.certificate_ref = CertificateRef::new("  ");
        let mut validator = FakeCertificateMaterialValidator::default();
        let mut store = ImportCertificateStore::default();
        let mut audit = MemoryAudit::default();
        let mut core = FakeCoreCommandClient::default();

        let failure = import_manual_certificate_and_install(
            request,
            &mut validator,
            &mut store,
            &mut audit,
            &mut core,
        )
        .unwrap_err();

        assert_eq!(failure.error.code, ErrorCode::CertificateInvalid);
        assert!(matches!(
            failure.state,
            CertificateImportState::Failed { .. }
        ));
        assert_eq!(validator.calls, 0);
        assert_eq!(store.saves, 0);
        assert!(core.commands.is_empty());
    }

    #[test]
    fn certificate_import_rejects_invalid_tls_material_before_store_or_core() {
        let mut validator = FakeCertificateMaterialValidator {
            reject: true,
            ..FakeCertificateMaterialValidator::default()
        };
        let mut store = ImportCertificateStore::default();
        let mut audit = MemoryAudit::default();
        let mut core = FakeCoreCommandClient::default();

        let failure = import_manual_certificate_and_install(
            manual_certificate_import_request(),
            &mut validator,
            &mut store,
            &mut audit,
            &mut core,
        )
        .unwrap_err();

        assert_eq!(failure.error.code, ErrorCode::CertificateInvalid);
        assert_eq!(store.saves, 0);
        assert!(audit.events.is_empty());
        assert!(core.commands.is_empty());
    }

    #[test]
    fn certificate_import_rejects_declared_domain_missing_from_certificate_identity_before_store_or_core(
    ) {
        let mut validator = FakeCertificateMaterialValidator {
            not_after_epoch_seconds: 4_000_000_000,
            dns_names: vec!["other.example.com".to_string()],
            ..FakeCertificateMaterialValidator::default()
        };
        let mut store = ImportCertificateStore::default();
        let mut audit = MemoryAudit::default();
        let mut core = FakeCoreCommandClient::default();

        let failure = import_manual_certificate_and_install(
            manual_certificate_import_request(),
            &mut validator,
            &mut store,
            &mut audit,
            &mut core,
        )
        .unwrap_err();

        assert_eq!(failure.error.code, ErrorCode::CertificateInvalid);
        assert!(failure
            .error
            .message
            .contains("certificate identity does not cover declared domain"));
        assert_eq!(validator.calls, 1);
        assert_eq!(store.saves, 0);
        assert!(audit.events.is_empty());
        assert!(core.commands.is_empty());
    }

    #[test]
    fn certificate_identity_accepts_one_label_wildcard_only() {
        let mut request = manual_certificate_import_request();
        request.domains = vec!["api.example.com".to_string()];
        let mut validator = FakeCertificateMaterialValidator {
            not_after_epoch_seconds: 4_000_000_000,
            dns_names: vec!["*.example.com".to_string()],
            ..FakeCertificateMaterialValidator::default()
        };
        let mut store = ImportCertificateStore::default();
        let mut audit = MemoryAudit::default();
        let mut core = FakeCoreCommandClient::default();

        let outcome = import_manual_certificate_and_install(
            request,
            &mut validator,
            &mut store,
            &mut audit,
            &mut core,
        )
        .unwrap();

        assert_eq!(outcome.status.domains, vec!["api.example.com"]);
        assert_eq!(store.saves, 1);
    }

    #[test]
    fn certificate_identity_rejects_wildcard_for_multiple_labels() {
        let mut request = manual_certificate_import_request();
        request.domains = vec!["deep.api.example.com".to_string()];
        let mut validator = FakeCertificateMaterialValidator {
            not_after_epoch_seconds: 4_000_000_000,
            dns_names: vec!["*.example.com".to_string()],
            ..FakeCertificateMaterialValidator::default()
        };
        let mut store = ImportCertificateStore::default();
        let mut audit = MemoryAudit::default();
        let mut core = FakeCoreCommandClient::default();

        let failure = import_manual_certificate_and_install(
            request,
            &mut validator,
            &mut store,
            &mut audit,
            &mut core,
        )
        .unwrap_err();

        assert_eq!(failure.error.code, ErrorCode::CertificateInvalid);
        assert_eq!(store.saves, 0);
        assert!(audit.events.is_empty());
        assert!(core.commands.is_empty());
    }

    #[test]
    fn certificate_import_store_failure_does_not_send_core_command() {
        let mut validator = FakeCertificateMaterialValidator {
            not_after_epoch_seconds: 4_000_000_000,
            dns_names: vec!["app.example.com".to_string()],
            ..FakeCertificateMaterialValidator::default()
        };
        let mut store = ImportCertificateStore {
            fail_on_save: Some(1),
            ..ImportCertificateStore::default()
        };
        let mut audit = MemoryAudit::default();
        let mut core = FakeCoreCommandClient::default();

        let failure = import_manual_certificate_and_install(
            manual_certificate_import_request(),
            &mut validator,
            &mut store,
            &mut audit,
            &mut core,
        )
        .unwrap_err();

        assert_eq!(failure.error.code, ErrorCode::CertificateStoreFailed);
        assert!(store.certificate.is_none());
        assert!(audit.events.is_empty());
        assert!(core.commands.is_empty());
    }

    #[test]
    fn certificate_import_command_rejection_restores_previous_certificate() {
        let previous = StoredCertificate {
            certificate_ref: CertificateRef::new("proxy-host-app"),
            domains: vec!["old.example.com".to_string()],
            not_after_epoch_seconds: 3_000_000_000,
            source: "manual".to_string(),
            certificate_pem: "old-certificate".to_string(),
            private_key_pem: "old-private-key".to_string(),
        };
        let mut validator = FakeCertificateMaterialValidator {
            not_after_epoch_seconds: 4_000_000_000,
            ..FakeCertificateMaterialValidator::default()
        };
        let mut store = ImportCertificateStore {
            certificate: Some(previous.clone()),
            ..ImportCertificateStore::default()
        };
        let mut audit = MemoryAudit::default();
        let mut core = FakeCoreCommandClient {
            reject_after: Some(1),
            ..FakeCoreCommandClient::default()
        };

        let failure = import_manual_certificate_and_install(
            manual_certificate_import_request(),
            &mut validator,
            &mut store,
            &mut audit,
            &mut core,
        )
        .unwrap_err();

        assert_eq!(failure.error.code, ErrorCode::RuntimeCommandRejected);
        assert!(failure.compensation_error.is_none());
        assert_eq!(store.certificate, Some(previous));
        assert_eq!(store.saves, 2);
    }

    #[test]
    fn certificate_import_command_rejection_removes_new_certificate() {
        let mut validator = FakeCertificateMaterialValidator {
            not_after_epoch_seconds: 4_000_000_000,
            ..FakeCertificateMaterialValidator::default()
        };
        let mut store = ImportCertificateStore::default();
        let mut audit = MemoryAudit::default();
        let mut core = FakeCoreCommandClient {
            reject_after: Some(1),
            ..FakeCoreCommandClient::default()
        };

        let failure = import_manual_certificate_and_install(
            manual_certificate_import_request(),
            &mut validator,
            &mut store,
            &mut audit,
            &mut core,
        )
        .unwrap_err();

        assert_eq!(failure.error.code, ErrorCode::RuntimeCommandRejected);
        assert!(store.certificate.is_none());
        assert_eq!(store.deletes, 1);
    }

    #[test]
    fn certificate_import_reports_compensation_failure_without_hiding_command_error() {
        let mut validator = FakeCertificateMaterialValidator {
            not_after_epoch_seconds: 4_000_000_000,
            ..FakeCertificateMaterialValidator::default()
        };
        let mut store = ImportCertificateStore {
            fail_delete: true,
            ..ImportCertificateStore::default()
        };
        let mut audit = MemoryAudit::default();
        let mut core = FakeCoreCommandClient {
            reject_after: Some(1),
            ..FakeCoreCommandClient::default()
        };

        let failure = import_manual_certificate_and_install(
            manual_certificate_import_request(),
            &mut validator,
            &mut store,
            &mut audit,
            &mut core,
        )
        .unwrap_err();

        assert_eq!(failure.error.code, ErrorCode::RuntimeCommandRejected);
        assert_eq!(
            failure.compensation_error.as_ref().map(|error| error.code),
            Some(ErrorCode::CertificateStoreFailed)
        );
        assert_eq!(
            failure.state,
            CertificateImportState::Failed {
                error_code: ErrorCode::RuntimeCommandRejected,
                compensation_failed: true,
            }
        );
    }

    #[test]
    fn certificate_import_audit_failure_restores_previous_certificate_without_core_command() {
        let previous = StoredCertificate {
            certificate_ref: CertificateRef::new("proxy-host-app"),
            domains: vec!["old.example.com".to_string()],
            not_after_epoch_seconds: 3_000_000_000,
            source: "manual".to_string(),
            certificate_pem: "old-certificate".to_string(),
            private_key_pem: "old-private-key".to_string(),
        };
        let mut validator = FakeCertificateMaterialValidator {
            not_after_epoch_seconds: 4_000_000_000,
            ..FakeCertificateMaterialValidator::default()
        };
        let mut store = ImportCertificateStore {
            certificate: Some(previous.clone()),
            ..ImportCertificateStore::default()
        };
        let mut audit = RejectingAudit;
        let mut core = FakeCoreCommandClient::default();

        let failure = import_manual_certificate_and_install(
            manual_certificate_import_request(),
            &mut validator,
            &mut store,
            &mut audit,
            &mut core,
        )
        .unwrap_err();

        assert_eq!(failure.error.code, ErrorCode::InternalBug);
        assert_eq!(store.certificate, Some(previous));
        assert!(core.commands.is_empty());
    }

    #[test]
    fn certificate_import_rejects_expiry_that_differs_from_validated_leaf() {
        let mut request = manual_certificate_import_request();
        request.expected_not_after_epoch_seconds = Some(3_000_000_000);
        let mut validator = FakeCertificateMaterialValidator {
            not_after_epoch_seconds: 4_000_000_000,
            ..FakeCertificateMaterialValidator::default()
        };
        let mut store = ImportCertificateStore::default();
        let mut audit = MemoryAudit::default();
        let mut core = FakeCoreCommandClient::default();

        let failure = import_manual_certificate_and_install(
            request,
            &mut validator,
            &mut store,
            &mut audit,
            &mut core,
        )
        .unwrap_err();

        assert_eq!(failure.error.code, ErrorCode::CertificateInvalid);
        assert_eq!(store.saves, 0);
        assert!(core.commands.is_empty());
    }

    #[test]
    fn certificate_import_state_machine_rejects_out_of_order_transition() {
        let mut machine = CertificateImportMachine::default();

        let error = machine
            .transition(CertificateImportEvent::InstallCommandSent)
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::InternalBug);
        assert_eq!(machine.state(), &CertificateImportState::Received);
    }

    #[test]
    fn certificate_import_product_log_contains_only_safe_fields() {
        let request = manual_certificate_import_request();
        let log = structured_manual_certificate_import_log(
            true,
            &request.request_id,
            &request.revision_id,
            &request.certificate_ref,
            None,
        );

        assert_eq!(log.event, "certificate.import.success");
        assert!(log
            .fields
            .iter()
            .any(|(key, value)| key == "source" && value == "manual"));
        assert!(!log.fields.iter().any(|(key, value)| {
            key.contains("pem")
                || key.contains("private")
                || value.contains("PRIVATE KEY")
                || value.contains("secret")
        }));
    }

    #[test]
    fn certificate_issuer_rejects_production_without_terms() {
        let mut issuer = CertificateIssuer {
            acme: FakeAcme::default(),
            store: MemoryCertStore::default(),
            audit: MemoryAudit::default(),
        };

        let error = issuer
            .issue(AcmeOrderRequest {
                domains: vec!["app.example.com".to_string()],
                account_email: "admin@example.com".to_string(),
                production: true,
                terms_accepted: false,
            })
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::AcmeTermsNotAccepted);
    }

    #[test]
    fn certificate_issuer_saves_certificate_and_audit_event() {
        let mut issuer = CertificateIssuer {
            acme: FakeAcme::default(),
            store: MemoryCertStore::default(),
            audit: MemoryAudit::default(),
        };

        let result = issuer
            .issue(AcmeOrderRequest {
                domains: vec!["app.example.com".to_string()],
                account_email: "admin@example.com".to_string(),
                production: false,
                terms_accepted: false,
            })
            .unwrap();

        assert_eq!(result.certificate.source, "acme");
        assert_eq!(issuer.store.saved.len(), 1);
        assert_eq!(issuer.audit.events[0].event, "certificate.issue");
    }

    #[test]
    fn certificate_issue_for_ref_installs_target_certificate() {
        let mut issuer = CertificateIssuer {
            acme: FakeAcme::default(),
            store: MemoryCertStore::default(),
            audit: MemoryAudit::default(),
        };
        let mut client = FakeCoreCommandClient::default();

        let outcome = issue_certificate_for_ref_and_install(
            &mut issuer,
            CertificateRef::new("proxy-host-app"),
            AcmeOrderRequest {
                domains: vec!["app.example.com".to_string()],
                account_email: "admin@example.com".to_string(),
                production: false,
                terms_accepted: false,
            },
            &mut client,
        )
        .unwrap();

        assert_eq!(outcome.certificate_ref.as_str(), "proxy-host-app");
        assert_eq!(
            issuer.store.saved.last().unwrap().certificate_ref.as_str(),
            "proxy-host-app"
        );
        assert!(matches!(
            client.commands.first(),
            Some(CoreCommand::InstallCertificate { certificate_ref })
                if certificate_ref.as_str() == "proxy-host-app"
        ));
    }

    #[test]
    fn certificate_issue_with_http01_registers_probes_and_clears_token() {
        let mut issuer = CertificateIssuer {
            acme: FakeAcme::default(),
            store: MemoryCertStore::default(),
            audit: MemoryAudit::default(),
        };
        let mut client = FakeCoreCommandClient::default();
        let mut tokens = Http01TokenStore::default();
        let mut probe = FakeHttp01Probe::default();

        let outcome = issue_certificate_for_ref_with_http01_and_install(
            &mut issuer,
            &mut tokens,
            &mut probe,
            CertificateRef::new("proxy-host-app"),
            AcmeOrderRequest {
                domains: vec!["app.example.com".to_string()],
                account_email: "admin@example.com".to_string(),
                production: false,
                terms_accepted: false,
            },
            &mut client,
        )
        .unwrap();

        assert_eq!(outcome.certificate_ref.as_str(), "proxy-host-app");
        assert_eq!(probe.verified.len(), 1);
        assert_eq!(probe.verified[0].0, "fake-acme-http01-app-example-com");
        assert!(tokens.respond("fake-acme-http01-app-example-com").is_none());
        assert_eq!(issuer.acme.issued.len(), 1);
        assert_eq!(issuer.store.saved.len(), 1);
    }

    #[test]
    fn certificate_issue_with_http01_clears_token_when_probe_fails() {
        let mut issuer = CertificateIssuer {
            acme: FakeAcme::default(),
            store: MemoryCertStore::default(),
            audit: MemoryAudit::default(),
        };
        let mut client = FakeCoreCommandClient::default();
        let mut tokens = Http01TokenStore::default();
        let mut probe = FakeHttp01Probe {
            fail: true,
            ..FakeHttp01Probe::default()
        };

        let error = issue_certificate_for_ref_with_http01_and_install(
            &mut issuer,
            &mut tokens,
            &mut probe,
            CertificateRef::new("proxy-host-app"),
            AcmeOrderRequest {
                domains: vec!["app.example.com".to_string()],
                account_email: "admin@example.com".to_string(),
                production: false,
                terms_accepted: false,
            },
            &mut client,
        )
        .unwrap_err();

        assert_eq!(error.code, ErrorCode::AcmeChallengeFailed);
        assert!(tokens.respond("fake-acme-http01-app-example-com").is_none());
        assert!(issuer.acme.issued.is_empty());
        assert!(issuer.store.saved.is_empty());
        assert!(client.commands.is_empty());
    }

    #[test]
    fn certificate_issue_with_http01_clears_token_when_acme_fails() {
        let mut issuer = CertificateIssuer {
            acme: FakeAcme {
                fail: true,
                ..FakeAcme::default()
            },
            store: MemoryCertStore::default(),
            audit: MemoryAudit::default(),
        };
        let mut client = FakeCoreCommandClient::default();
        let mut tokens = Http01TokenStore::default();
        let mut probe = FakeHttp01Probe::default();

        let error = issue_certificate_for_ref_with_http01_and_install(
            &mut issuer,
            &mut tokens,
            &mut probe,
            CertificateRef::new("proxy-host-app"),
            AcmeOrderRequest {
                domains: vec!["app.example.com".to_string()],
                account_email: "admin@example.com".to_string(),
                production: false,
                terms_accepted: false,
            },
            &mut client,
        )
        .unwrap_err();

        assert_eq!(error.code, ErrorCode::AcmeChallengeFailed);
        assert!(tokens.respond("fake-acme-http01-app-example-com").is_none());
        assert_eq!(issuer.acme.issued.len(), 1);
        assert!(issuer.store.saved.is_empty());
        assert!(client.commands.is_empty());
    }

    #[test]
    fn certificate_renew_missing_certificate_does_not_call_acme_or_core() {
        let mut issuer = CertificateIssuer {
            acme: FakeAcme::default(),
            store: MemoryCertStore::default(),
            audit: MemoryAudit::default(),
        };
        let mut client = FakeCoreCommandClient::default();

        let error = renew_certificate_for_ref_and_install(
            &mut issuer,
            CertificateRef::new("missing"),
            CertificateRenewRequest {
                account_email: "admin@example.com".to_string(),
                production: false,
                terms_accepted: false,
            },
            &mut client,
        )
        .unwrap_err();

        assert_eq!(error.code, ErrorCode::CertificateNotFound);
        assert!(issuer.acme.issued.is_empty());
        assert!(client.commands.is_empty());
    }

    #[test]
    fn product_access_log_excludes_sensitive_request_material_and_includes_revision() {
        let event = AccessLogEvent {
            request_id: "req-1".to_string(),
            revision_id: "rev-1".to_string(),
            route_id: Some("route-1".to_string()),
            upstream_id: Some("upstream-1".to_string()),
            status_code: 200,
            duration_ms: 12,
            scheme: "https".to_string(),
            method: "GET".to_string(),
            path: "/secret?token=value&authorization=bearer&cookie=session&body=raw".to_string(),
        };

        let log = structured_access_log(&LogMode::Product, &event);
        let rendered_values = log
            .fields
            .iter()
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>()
            .join(" ");

        assert!(!log.fields.iter().any(|(key, _)| key == "path"));
        assert!(!rendered_values.contains("/secret"));
        assert!(!rendered_values.contains("token=value"));
        assert!(!rendered_values.contains("authorization"));
        assert!(!rendered_values.contains("cookie"));
        assert!(!rendered_values.contains("body=raw"));
        assert!(log
            .fields
            .iter()
            .any(|(key, value)| key == "request_id" && value == "req-1"));
        assert!(log
            .fields
            .iter()
            .any(|(key, value)| key == "revision_id" && value == "rev-1"));
        assert!(log
            .fields
            .iter()
            .any(|(key, value)| key == "scheme" && value == "https"));
    }

    #[test]
    fn field_debug_access_log_includes_route_detail() {
        let event = AccessLogEvent {
            request_id: "req-1".to_string(),
            revision_id: "rev-1".to_string(),
            route_id: Some("route-1".to_string()),
            upstream_id: Some("upstream-1".to_string()),
            status_code: 502,
            duration_ms: 30,
            scheme: "https".to_string(),
            method: "GET".to_string(),
            path: "/api".to_string(),
        };

        let log = structured_access_log(&LogMode::FieldDebug, &event);

        assert!(log.fields.iter().any(|(key, _)| key == "path"));
        assert!(log.fields.iter().any(|(key, _)| key == "route_id"));
    }

    #[test]
    fn dev_access_log_includes_state_transition_marker() {
        let event = AccessLogEvent {
            request_id: "req-1".to_string(),
            revision_id: "rev-1".to_string(),
            route_id: Some("route-1".to_string()),
            upstream_id: Some("upstream-1".to_string()),
            status_code: 200,
            duration_ms: 10,
            scheme: "https".to_string(),
            method: "GET".to_string(),
            path: "/dev".to_string(),
        };

        let log = structured_access_log(&LogMode::Dev, &event);

        assert!(log
            .fields
            .iter()
            .any(|(key, value)| key == "state" && value == "http.request.completed"));
        assert!(log.fields.iter().any(|(key, _)| key == "route_id"));
    }

    #[derive(Default)]
    struct MemoryMetrics {
        metrics: Vec<MetricEvent>,
    }

    impl MetricsSink for MemoryMetrics {
        fn record_metric(&mut self, metric: MetricEvent) -> Result<(), AppError> {
            self.metrics.push(metric);
            Ok(())
        }
    }

    #[test]
    fn request_metrics_do_not_use_raw_path_labels() {
        let event = AccessLogEvent {
            request_id: "req-1".to_string(),
            revision_id: "rev-1".to_string(),
            route_id: Some("route-1".to_string()),
            upstream_id: Some("upstream-1".to_string()),
            status_code: 404,
            duration_ms: 8,
            scheme: "http".to_string(),
            method: "GET".to_string(),
            path: "/tenant/123/private".to_string(),
        };
        let mut sink = MemoryMetrics::default();

        record_request_metrics(&mut sink, &event).unwrap();

        assert_eq!(sink.metrics.len(), 2);
        assert!(!sink
            .metrics
            .iter()
            .flat_map(|metric| metric.labels.iter())
            .any(|(_, value)| value.contains("/tenant")));
    }

    #[test]
    fn tls_handshake_failure_metric_uses_only_stable_error_code_label() {
        let metric = tls_handshake_failure_metric(ErrorCode::TlsHandshakeTimeout);

        assert_eq!(
            metric.descriptor,
            MetricDescriptor::TlsHandshakeFailuresTotal
        );
        assert_eq!(
            metric.labels,
            vec![(
                "error_code".to_string(),
                "TLS_HANDSHAKE_TIMEOUT".to_string(),
            )]
        );
    }

    #[test]
    fn process_identity_metrics_use_explicit_startup_values() {
        let build = build_info_metric("1.2.3");
        let started = process_start_time_metric(1_700_000_000);

        assert_eq!(build.descriptor, MetricDescriptor::BuildInfo);
        assert_eq!(build.operation, edge_ports::MetricOperation::GaugeSet(1));
        assert_eq!(build.labels, vec![("version".into(), "1.2.3".into())]);
        assert_eq!(started.descriptor, MetricDescriptor::ProcessStartTime);
        assert_eq!(
            started.operation,
            edge_ports::MetricOperation::GaugeSet(1_700_000_000)
        );
        assert!(started.labels.is_empty());
    }

    #[test]
    fn config_apply_log_includes_revision_id() {
        let log = structured_config_apply_log(&ConfigRevisionId::new("rev-42"));

        assert!(log
            .fields
            .iter()
            .any(|(key, value)| key == "revision_id" && value == "rev-42"));
    }

    #[test]
    fn certificate_mutation_product_log_includes_safe_release_fields() {
        let log = structured_certificate_mutation_log(
            "certificate.issue",
            true,
            "req-cert-1",
            &ConfigRevisionId::new("rev-42"),
            &CertificateRef::new("proxy-host-app"),
            200,
            None,
        );

        assert_eq!(log.component, "admin-api");
        assert_eq!(log.event, "certificate.issue.success");
        assert!(log
            .fields
            .iter()
            .any(|(key, value)| key == "request_id" && value == "req-cert-1"));
        assert!(log
            .fields
            .iter()
            .any(|(key, value)| key == "revision_id" && value == "rev-42"));
        assert!(log
            .fields
            .iter()
            .any(|(key, value)| key == "certificate_ref" && value == "proxy-host-app"));
        assert!(log
            .fields
            .iter()
            .any(|(key, value)| key == "status_code" && value == "200"));
        assert!(!log.fields.iter().any(|(key, value)| {
            key.contains("pem")
                || key.contains("private")
                || value.contains("PRIVATE KEY")
                || value.contains("secret")
        }));
    }

    #[test]
    fn certificate_mutation_failure_product_log_includes_error_code() {
        let log = structured_certificate_mutation_log(
            "certificate.renew",
            false,
            "req-cert-2",
            &ConfigRevisionId::new("rev-42"),
            &CertificateRef::new("proxy-host-app"),
            500,
            Some(ErrorCode::RuntimeCommandRejected.as_str()),
        );

        assert_eq!(log.event, "certificate.renew.failure");
        assert!(log
            .fields
            .iter()
            .any(|(key, value)| key == "error_code" && value == "RUNTIME_COMMAND_REJECTED"));
    }

    #[test]
    fn upstream_failure_metric_uses_bounded_labels() {
        let metric = upstream_failure_metric(
            Some("route-1"),
            Some("upstream-1"),
            ErrorCode::RuntimeCommandRejected,
        );

        assert_eq!(metric.descriptor, MetricDescriptor::UpstreamFailuresTotal);
        assert!(metric
            .labels
            .iter()
            .any(|(key, value)| key == "error_code" && value == "RUNTIME_COMMAND_REJECTED"));
        assert!(!metric
            .labels
            .iter()
            .any(|(key, value)| key == "path" || value.contains('/')));
    }

    #[test]
    fn active_connection_gauge_records_current_count() {
        let metric = active_connection_metric(7);

        assert_eq!(metric.descriptor, MetricDescriptor::ActiveConnections);
        assert_eq!(metric.operation, edge_ports::MetricOperation::GaugeSet(7));
        assert!(metric.labels.is_empty());
    }

    #[test]
    fn resource_metrics_use_active_values_and_closed_rejection_labels() {
        let used = resource_payload_bytes_metric(4_096);
        let limit = resource_payload_limit_bytes_metric(128 * 1_024 * 1_024);
        let connection_rejection = resource_admission_rejection_metric(
            ResourceMetricKind::Connection,
            ResourceRejectionReason::ConnectionLimit,
        );
        let payload_rejection = resource_admission_rejection_metric(
            ResourceMetricKind::Payload,
            ResourceRejectionReason::PayloadPressure,
        );

        assert_eq!(used.descriptor, MetricDescriptor::ResourcePayloadBytes);
        assert_eq!(used.operation, edge_ports::MetricOperation::GaugeSet(4_096));
        assert_eq!(
            limit.descriptor,
            MetricDescriptor::ResourcePayloadLimitBytes
        );
        assert_eq!(
            limit.operation,
            edge_ports::MetricOperation::GaugeSet(128 * 1_024 * 1_024)
        );
        assert_eq!(
            connection_rejection.labels,
            vec![
                ("reason".to_string(), "connection_limit".to_string()),
                ("resource_kind".to_string(), "connection".to_string()),
            ]
        );
        assert_eq!(
            payload_rejection.labels,
            vec![
                ("reason".to_string(), "payload_pressure".to_string()),
                ("resource_kind".to_string(), "payload".to_string()),
            ]
        );
    }

    #[test]
    fn certificate_expiry_metric_omits_domain_and_private_key() {
        let certificate = StoredCertificate {
            certificate_ref: CertificateRef::new("cert-app"),
            domains: vec!["app.example.com".to_string()],
            not_after_epoch_seconds: 1_700_000_000,
            source: "manual".to_string(),
            certificate_pem: "cert".to_string(),
            private_key_pem: "secret-key".to_string(),
        };

        let metric = certificate_expiry_metric(&certificate);

        assert_eq!(metric.descriptor, MetricDescriptor::CertificateNotAfter);
        assert!(metric
            .labels
            .iter()
            .any(|(key, value)| key == "certificate_ref" && value == "cert-app"));
        assert!(!metric
            .labels
            .iter()
            .any(|(_, value)| value.contains("example.com") || value.contains("secret")));
    }

    #[test]
    fn login_failure_audit_event_is_recorded() {
        let mut audit = MemoryAudit::default();

        record_admin_auth_audit(&mut audit, false).unwrap();

        assert_eq!(audit.events[0].event, "admin.login.failure");
        assert!(audit.events[0].revision_id.is_none());
    }

    #[test]
    fn request_id_generator_creates_stable_unique_ids() {
        let mut generator = RequestIdGenerator::new("req");

        assert_eq!(generator.next_id(), "req-0000000000000001");
        assert_eq!(generator.next_id(), "req-0000000000000002");
    }

    #[test]
    fn bounded_log_queue_drops_oldest_when_full() {
        let mut queue = BoundedLogQueue::new(1);
        queue.push(StructuredLogEvent {
            component: "edge-core".to_string(),
            event: "first".to_string(),
            fields: vec![],
        });
        queue.push(StructuredLogEvent {
            component: "edge-core".to_string(),
            event: "second".to_string(),
            fields: vec![],
        });

        assert_eq!(queue.dropped_oldest(), 1);
        assert_eq!(queue.events()[0].event, "second");
    }

    #[test]
    fn recent_access_log_buffer_keeps_latest_events() {
        let mut buffer = RecentAccessLogBuffer::new(2);
        for index in 1..=3 {
            buffer.push(AccessLogEvent {
                request_id: format!("req-{index}"),
                revision_id: "rev-1".to_string(),
                route_id: None,
                upstream_id: None,
                status_code: 200,
                duration_ms: 1,
                scheme: "http".to_string(),
                method: "GET".to_string(),
                path: "/".to_string(),
            });
        }

        let recent = buffer.recent();

        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].request_id, "req-2");
        assert_eq!(recent[1].request_id, "req-3");
    }

    #[test]
    fn recent_error_buffer_keeps_latest_errors() {
        let mut buffer = RecentErrorBuffer::new(1);
        buffer.push(RecentErrorEvent {
            request_id: Some("req-1".to_string()),
            error_code: "HTTP_MALFORMED_REQUEST".to_string(),
            message: "bad request".to_string(),
        });
        buffer.push(RecentErrorEvent {
            request_id: Some("req-2".to_string()),
            error_code: "RUNTIME_COMMAND_REJECTED".to_string(),
            message: "rejected".to_string(),
        });

        let recent = buffer.recent();

        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].request_id.as_deref(), Some("req-2"));
        assert_eq!(recent[0].error_code, "RUNTIME_COMMAND_REJECTED");
    }
}
