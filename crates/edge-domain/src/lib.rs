//! Pure domain model crate.
//!
//! This crate must not depend on networking, filesystem, TLS, API, or UI
//! frameworks. Keep business rules here small and directly testable.

mod backup;
pub use backup::*;
mod audit;
pub use audit::*;
mod operational_lifecycle;
pub use operational_lifecycle::*;
mod operational_upgrade;
pub use operational_upgrade::*;
mod support_bundle;
pub use support_bundle::*;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

/// Returns the crate name for foundation smoke tests.
pub fn crate_name() -> &'static str {
    "edge-domain"
}

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

id_type!(ListenerId);
id_type!(RouteId);
id_type!(ServiceId);
id_type!(UpstreamId);
id_type!(CertificateResolverId);
id_type!(CertificateRef);
id_type!(ConfigRevisionId);
id_type!(ProxyHostId);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenerProtocol {
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener {
    pub id: ListenerId,
    pub bind: String,
    pub protocol: ListenerProtocol,
    pub client_auth: ClientAuthPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostMatch {
    normalized: String,
}

impl HostMatch {
    pub fn exact(host: impl AsRef<str>) -> Self {
        Self {
            normalized: normalize_host(host.as_ref()),
        }
    }

    pub fn matches(&self, host: &str) -> bool {
        self.normalized == normalize_host(host)
    }

    pub fn as_str(&self) -> &str {
        &self.normalized
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathMatch {
    prefix: String,
    exact: bool,
}

impl PathMatch {
    pub fn prefix(path: impl AsRef<str>) -> Self {
        Self {
            prefix: normalize_path(path.as_ref()),
            exact: false,
        }
    }

    pub fn exact(path: impl AsRef<str>) -> Self {
        Self {
            prefix: normalize_path(path.as_ref()),
            exact: true,
        }
    }

    pub fn matches(&self, path: &str) -> bool {
        let path = normalize_path(path);

        if self.exact {
            return path == self.prefix;
        }

        if self.prefix == "/" {
            return true;
        }

        path == self.prefix
            || path
                .strip_prefix(self.prefix.as_str())
                .is_some_and(|remaining| remaining.starts_with('/'))
    }

    pub fn as_str(&self) -> &str {
        &self.prefix
    }

    pub fn is_exact(&self) -> bool {
        self.exact
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteMatch {
    pub hosts: Vec<HostMatch>,
    pub paths: Vec<PathMatch>,
}

impl RouteMatch {
    pub fn new(hosts: Vec<HostMatch>, paths: Vec<PathMatch>) -> Self {
        Self { hosts, paths }
    }

    pub fn matches(&self, host: &str, path: &str) -> bool {
        self.hosts.iter().any(|candidate| candidate.matches(host))
            && self.paths.iter().any(|candidate| candidate.matches(path))
    }

    pub fn best_path_specificity(&self, path: &str) -> (usize, bool) {
        self.paths
            .iter()
            .filter(|candidate| candidate.matches(path))
            .map(|candidate| (candidate.as_str().len(), candidate.is_exact()))
            .max()
            .unwrap_or((0, false))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub id: RouteId,
    pub route_match: RouteMatch,
    pub service_id: ServiceId,
    pub priority: i32,
    pub enabled: bool,
    pub redirect_http_to_https: bool,
    pub certificate_resolver_id: Option<CertificateResolverId>,
    pub certificate_ref: Option<CertificateRef>,
}

impl Route {
    pub fn matches(&self, host: &str, path: &str) -> bool {
        self.enabled && self.route_match.matches(host, path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub id: ServiceId,
    pub upstreams: Vec<Upstream>,
    pub policy: ServicePolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    pub id: UpstreamId,
    pub url: String,
    pub administrative_state: UpstreamAdministrativeState,
    pub tls: UpstreamTlsPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct HttpUpstreamEndpoint {
    pub host: String,
    pub port: u16,
    base_path: String,
    ipv6: bool,
}

impl HttpUpstreamEndpoint {
    pub fn parse_http(value: &str) -> Result<Self, ValidationError> {
        Self::parse(value)
    }

    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        if value.chars().any(char::is_control) || value.contains(['?', '#', '@']) {
            return Err(invalid_upstream_url());
        }
        let remainder = value
            .strip_prefix("http://")
            .ok_or_else(invalid_upstream_url)?;
        let (authority, base_path) = remainder
            .split_once('/')
            .map(|(authority, path)| (authority, format!("/{path}")))
            .unwrap_or((remainder, String::new()));
        if authority.is_empty() {
            return Err(invalid_upstream_url());
        }

        let (host, port, ipv6) = if let Some(bracketed) = authority.strip_prefix('[') {
            let Some(close) = bracketed.find(']') else {
                return Err(invalid_upstream_url());
            };
            let host = &bracketed[..close];
            let suffix = &bracketed[close + 1..];
            if !is_ipv6_literal(host) {
                return Err(invalid_upstream_url());
            }
            let port = parse_optional_port(suffix)?;
            (host.to_ascii_lowercase(), port, true)
        } else {
            let (host, port) = match authority.rsplit_once(':') {
                Some((host, port)) if !host.contains(':') => (host, parse_port(port)?),
                Some(_) => return Err(invalid_upstream_url()),
                None => (authority, 80),
            };
            if !is_ipv4_literal(host) {
                return Err(invalid_upstream_url());
            }
            (host.to_string(), port, false)
        };

        Ok(Self {
            host,
            port,
            base_path,
            ipv6,
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn base_path(&self) -> &str {
        &self.base_path
    }

    pub fn authority(&self) -> String {
        let host = if self.ipv6 {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == 80 {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    pub fn connect_address(&self) -> String {
        if self.ipv6 {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    pub fn address(&self) -> String {
        self.connect_address()
    }

    pub fn as_url(&self) -> String {
        format!("http://{}{}", self.authority(), self.base_path)
    }

    pub fn join_path(&self, request_path: &str) -> String {
        if self.base_path.is_empty() || self.base_path == "/" {
            return request_path.to_string();
        }
        format!(
            "{}{}",
            self.base_path.trim_end_matches('/'),
            if request_path.starts_with('/') {
                request_path.to_string()
            } else {
                format!("/{request_path}")
            }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustBundleRef(String);

impl TrustBundleRef {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        if value.is_empty()
            || value.len() > 64
            || value == "."
            || value == ".."
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ValidationError::new(
                ErrorCode::ConfigTrustBundleRefInvalid,
                "trust bundle reference is invalid",
            ));
        }
        Ok(Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TlsServerName(String);

impl TlsServerName {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        let normalized = value.trim_end_matches('.').to_ascii_lowercase();
        if is_ipv4_literal(&normalized)
            || is_ipv6_literal(&normalized)
            || !valid_dns_name(&normalized)
        {
            return Err(ValidationError::new(
                ErrorCode::ConfigTlsServerNameInvalid,
                "TLS server name must be a valid DNS name",
            ));
        }
        Ok(Self(normalized))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UpstreamHttpHost(String);

impl UpstreamHttpHost {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        if value.is_empty()
            || value.len() > 255
            || value
                .chars()
                .any(|ch| ch.is_control() || ch.is_whitespace())
            || value.contains(['@', '/', '?', '#'])
        {
            return Err(invalid_upstream_http_host());
        }
        let (host, port) = match value.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (host, Some(port)),
            Some(_) => return Err(invalid_upstream_http_host()),
            None => (value, None),
        };
        if !valid_dns_name(&host.to_ascii_lowercase())
            || port.is_some_and(|port| parse_port(port).is_err())
        {
            return Err(invalid_upstream_http_host());
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UpstreamScheme {
    Http,
    Https,
}

impl UpstreamScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UpstreamEndpoint {
    scheme: UpstreamScheme,
    host: String,
    port: u16,
    base_path: String,
    ipv6: bool,
}

impl UpstreamEndpoint {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        if value.chars().any(char::is_control) || value.contains(['?', '#', '@']) {
            return Err(invalid_upstream_url());
        }
        let (scheme, remainder) = if let Some(value) = value.strip_prefix("http://") {
            (UpstreamScheme::Http, value)
        } else if let Some(value) = value.strip_prefix("https://") {
            (UpstreamScheme::Https, value)
        } else {
            return Err(invalid_upstream_url());
        };
        let (authority, base_path) = remainder
            .split_once('/')
            .map(|(authority, path)| (authority, format!("/{path}")))
            .unwrap_or((remainder, String::new()));
        if authority.is_empty() {
            return Err(invalid_upstream_url());
        }
        let default_port = scheme.default_port();
        let (host, port, ipv6) = if let Some(bracketed) = authority.strip_prefix('[') {
            let Some(close) = bracketed.find(']') else {
                return Err(invalid_upstream_url());
            };
            let host = &bracketed[..close];
            let suffix = &bracketed[close + 1..];
            if !is_ipv6_literal(host) {
                return Err(invalid_upstream_url());
            }
            (
                host.to_ascii_lowercase(),
                parse_optional_port_with_default(suffix, default_port)?,
                true,
            )
        } else {
            let (host, port) = match authority.rsplit_once(':') {
                Some((host, port)) if !host.contains(':') => (host, parse_port(port)?),
                Some(_) => return Err(invalid_upstream_url()),
                None => (authority, default_port),
            };
            if !is_ipv4_literal(host) {
                return Err(invalid_upstream_url());
            }
            (host.to_string(), port, false)
        };
        Ok(Self {
            scheme,
            host,
            port,
            base_path,
            ipv6,
        })
    }

    pub fn scheme(&self) -> UpstreamScheme {
        self.scheme
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn connect_address(&self) -> String {
        if self.ipv6 {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    pub fn authority(&self) -> String {
        let host = if self.ipv6 {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == self.scheme.default_port() {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    pub fn as_url(&self) -> String {
        format!(
            "{}://{}{}",
            self.scheme.as_str(),
            self.authority(),
            self.base_path
        )
    }

    pub fn join_path(&self, request_path: &str) -> String {
        if self.base_path.is_empty() || self.base_path == "/" {
            return request_path.to_string();
        }
        format!(
            "{}{}",
            self.base_path.trim_end_matches('/'),
            if request_path.starts_with('/') {
                request_path.to_string()
            } else {
                format!("/{request_path}")
            }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamTlsPolicy {
    Disabled,
    ServerAuthenticated {
        server_name: TlsServerName,
        http_host: UpstreamHttpHost,
        trust_bundle_ref: TrustBundleRef,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedUpstreamPolicy {
    pub endpoint: UpstreamEndpoint,
    pub tls: UpstreamTlsPolicy,
}

pub fn normalize_upstream_tls_policy(
    schema_version: u32,
    url: &str,
    tls_server_name: Option<&str>,
    upstream_http_host: Option<&str>,
    tls_trust_bundle_ref: Option<&str>,
) -> Result<NormalizedUpstreamPolicy, ValidationError> {
    let endpoint = UpstreamEndpoint::parse(url)?;
    if schema_version == 1 && endpoint.scheme() == UpstreamScheme::Https {
        return Err(invalid_upstream_url());
    }
    let fields_are_empty =
        tls_server_name.is_none() && upstream_http_host.is_none() && tls_trust_bundle_ref.is_none();
    let tls = match (schema_version, endpoint.scheme(), fields_are_empty) {
        (1, UpstreamScheme::Http, true) | (2, UpstreamScheme::Http, true) => {
            UpstreamTlsPolicy::Disabled
        }
        (2, UpstreamScheme::Https, false) => UpstreamTlsPolicy::ServerAuthenticated {
            server_name: TlsServerName::parse(tls_server_name.ok_or_else(invalid_tls_policy)?)?,
            http_host: UpstreamHttpHost::parse(upstream_http_host.ok_or_else(invalid_tls_policy)?)?,
            trust_bundle_ref: TrustBundleRef::parse(
                tls_trust_bundle_ref.ok_or_else(invalid_tls_policy)?,
            )?,
        },
        _ => return Err(invalid_tls_policy()),
    };
    Ok(NormalizedUpstreamPolicy { endpoint, tls })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAuthPolicy {
    Disabled,
    Required { trust_bundle_ref: TrustBundleRef },
}

pub fn normalize_client_auth_policy(
    schema_version: u32,
    protocol: ListenerProtocol,
    client_auth: Option<&str>,
    trust_bundle_ref: Option<&str>,
) -> Result<ClientAuthPolicy, ValidationError> {
    match (schema_version, protocol, client_auth, trust_bundle_ref) {
        (1, _, None, None) | (2, ListenerProtocol::Http, None, None) => {
            Ok(ClientAuthPolicy::Disabled)
        }
        (2, ListenerProtocol::Https, None | Some("disabled"), None) => {
            Ok(ClientAuthPolicy::Disabled)
        }
        (2, ListenerProtocol::Https, Some("required"), Some(reference)) => {
            Ok(ClientAuthPolicy::Required {
                trust_bundle_ref: TrustBundleRef::parse(reference)?,
            })
        }
        _ => Err(invalid_client_auth_policy()),
    }
}

pub fn validate_client_auth_trust(
    policy: &ClientAuthPolicy,
    known_trust_bundles: &BTreeSet<TrustBundleRef>,
) -> Result<(), ValidationError> {
    if let ClientAuthPolicy::Required { trust_bundle_ref } = policy {
        if !known_trust_bundles.contains(trust_bundle_ref) {
            return Err(ValidationError::new(
                ErrorCode::ConfigTrustBundleNotFound,
                "referenced trust bundle does not exist",
            ));
        }
    }
    Ok(())
}

fn valid_dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.contains('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn invalid_upstream_http_host() -> ValidationError {
    ValidationError::new(
        ErrorCode::ConfigUpstreamHttpHostInvalid,
        "upstream HTTP Host authority is invalid",
    )
}

fn invalid_tls_policy() -> ValidationError {
    ValidationError::new(
        ErrorCode::ConfigTlsPolicyInvalid,
        "upstream TLS policy is incomplete or contradicts its scheme",
    )
}

fn invalid_client_auth_policy() -> ValidationError {
    ValidationError::new(
        ErrorCode::ConfigClientAuthPolicyInvalid,
        "listener client-auth policy is invalid",
    )
}

fn invalid_upstream_url() -> ValidationError {
    ValidationError::new(
        ErrorCode::ConfigInvalidUpstreamUrl,
        "upstream URL must use HTTP with a literal IP address and valid port",
    )
}

fn parse_optional_port(suffix: &str) -> Result<u16, ValidationError> {
    if suffix.is_empty() {
        Ok(80)
    } else {
        parse_port(suffix.strip_prefix(':').ok_or_else(invalid_upstream_url)?)
    }
}

fn parse_optional_port_with_default(
    suffix: &str,
    default_port: u16,
) -> Result<u16, ValidationError> {
    if suffix.is_empty() {
        Ok(default_port)
    } else {
        parse_port(suffix.strip_prefix(':').ok_or_else(invalid_upstream_url)?)
    }
}

fn parse_port(value: &str) -> Result<u16, ValidationError> {
    let port = value.parse::<u16>().map_err(|_| invalid_upstream_url())?;
    if port == 0 {
        Err(invalid_upstream_url())
    } else {
        Ok(port)
    }
}

fn is_ipv4_literal(value: &str) -> bool {
    let octets: Vec<_> = value.split('.').collect();
    octets.len() == 4
        && octets
            .iter()
            .all(|octet| !octet.is_empty() && octet.parse::<u8>().is_ok())
}

fn is_ipv6_literal(value: &str) -> bool {
    if value.is_empty() || value.contains('.') {
        return false;
    }
    let parts: Vec<_> = value.split("::").collect();
    if parts.len() > 2 {
        return false;
    }
    let valid_groups = |part: &str| {
        if part.is_empty() {
            return Some(0_usize);
        }
        let groups: Vec<_> = part.split(':').collect();
        groups
            .iter()
            .all(|group| {
                !group.is_empty()
                    && group.len() <= 4
                    && group.chars().all(|character| character.is_ascii_hexdigit())
            })
            .then_some(groups.len())
    };
    let Some(left) = valid_groups(parts[0]) else {
        return false;
    };
    if parts.len() == 1 {
        return left == 8;
    }
    let Some(right) = valid_groups(parts[1]) else {
        return false;
    };
    left + right < 8
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamAvailability {
    Disabled,
    Unknown,
    Healthy,
    Unhealthy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthGeneration(pub u64);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UpstreamHealthKey {
    pub service_id: ServiceId,
    pub upstream_id: UpstreamId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthAvailabilitySnapshot {
    pub revision_id: ConfigRevisionId,
    pub generation: HealthGeneration,
    pub entries: BTreeMap<UpstreamHealthKey, UpstreamAvailability>,
}

impl UpstreamAvailability {
    pub fn is_eligible(self) -> bool {
        !matches!(self, Self::Unhealthy)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamSelection {
    Selected {
        upstream_id: UpstreamId,
        next_sequence: u64,
    },
    NoEligibleUpstream,
}

pub fn select_upstream(
    service: &Service,
    availability: &BTreeMap<UpstreamId, UpstreamAvailability>,
    sequence: u64,
) -> UpstreamSelection {
    let health_enabled = matches!(service.policy.health_check, HealthCheckPolicy::Http(_));
    let eligible: Vec<_> = service
        .upstreams
        .iter()
        .filter(|upstream| {
            upstream.administrative_state == UpstreamAdministrativeState::Active
                && (!health_enabled
                    || availability
                        .get(&upstream.id)
                        .copied()
                        .unwrap_or(UpstreamAvailability::Unknown)
                        .is_eligible())
        })
        .collect();

    if eligible.is_empty() {
        return UpstreamSelection::NoEligibleUpstream;
    }

    let selected = eligible[(sequence % eligible.len() as u64) as usize];
    UpstreamSelection::Selected {
        upstream_id: selected.id.clone(),
        next_sequence: sequence.wrapping_add(1),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadBalancingPolicy {
    RoundRobin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePolicy {
    pub load_balancing: LoadBalancingPolicy,
    pub health_check: HealthCheckPolicy,
    pub retry: RetryPolicy,
    pub passive_health: PassiveHealthMode,
}

impl Default for ServicePolicy {
    fn default() -> Self {
        Self {
            load_balancing: LoadBalancingPolicy::RoundRobin,
            health_check: HealthCheckPolicy::Disabled,
            retry: RetryPolicy::default(),
            passive_health: PassiveHealthMode::Disabled,
        }
    }
}

impl LoadBalancingPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RoundRobin => "round_robin",
        }
    }
}

impl FromStr for LoadBalancingPolicy {
    type Err = ValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "round_robin" => Ok(Self::RoundRobin),
            _ => Err(ValidationError::new(
                ErrorCode::ConfigInvalidLoadBalancingPolicy,
                "unknown load-balancing policy",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum HealthCheckPolicy {
    #[default]
    Disabled,
    Http(HttpHealthCheckPolicy),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpHealthCheckPolicy {
    pub path: String,
    pub interval_ms: u64,
    pub timeout_ms: u64,
    pub healthy_threshold: u32,
    pub unhealthy_threshold: u32,
    pub status_min: u16,
    pub status_max: u16,
}

impl HttpHealthCheckPolicy {
    pub fn new(
        path: impl Into<String>,
        interval_ms: u64,
        timeout_ms: u64,
        healthy_threshold: u32,
        unhealthy_threshold: u32,
        status_min: u16,
        status_max: u16,
    ) -> Result<Self, ValidationError> {
        let path = path.into();
        if path.is_empty()
            || path.len() > 2_048
            || !path.starts_with('/')
            || path.contains(['?', '#'])
            || path.chars().any(char::is_control)
        {
            return Err(ValidationError::new(
                ErrorCode::ConfigHealthCheckInvalidPath,
                "health-check path must be a bounded absolute path without query or fragment",
            ));
        }
        if !(1_000..=86_400_000).contains(&interval_ms)
            || !(100..=30_000).contains(&timeout_ms)
            || timeout_ms >= interval_ms
        {
            return Err(ValidationError::new(
                ErrorCode::ConfigHealthCheckInvalidInterval,
                "health-check timeout and interval are outside the supported bounds",
            ));
        }
        if !(1..=10).contains(&healthy_threshold) || !(1..=10).contains(&unhealthy_threshold) {
            return Err(ValidationError::new(
                ErrorCode::ConfigHealthCheckInvalidThreshold,
                "health-check thresholds must be between 1 and 10",
            ));
        }
        if !(100..=599).contains(&status_min)
            || !(100..=599).contains(&status_max)
            || status_min > status_max
        {
            return Err(ValidationError::new(
                ErrorCode::ConfigHealthCheckInvalidStatusRange,
                "health-check status range must be ordered within 100 through 599",
            ));
        }

        Ok(Self {
            path,
            interval_ms,
            timeout_ms,
            healthy_threshold,
            unhealthy_threshold,
            status_min,
            status_max,
        })
    }
}

impl Default for HttpHealthCheckPolicy {
    fn default() -> Self {
        Self::new("/health", 10_000, 2_000, 2, 3, 200, 399)
            .expect("default health-check policy must be valid")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamHealthState {
    Disabled,
    Unknown {
        consecutive_successes: u32,
        consecutive_failures: u32,
    },
    Healthy {
        consecutive_failures: u32,
    },
    Unhealthy {
        consecutive_successes: u32,
    },
}

impl UpstreamHealthState {
    pub fn for_policy(policy: &HealthCheckPolicy) -> Self {
        match policy {
            HealthCheckPolicy::Disabled => Self::Disabled,
            HealthCheckPolicy::Http(_) => Self::Unknown {
                consecutive_successes: 0,
                consecutive_failures: 0,
            },
        }
    }

    pub fn availability(&self) -> UpstreamAvailability {
        match self {
            Self::Disabled => UpstreamAvailability::Disabled,
            Self::Unknown { .. } => UpstreamAvailability::Unknown,
            Self::Healthy { .. } => UpstreamAvailability::Healthy,
            Self::Unhealthy { .. } => UpstreamAvailability::Unhealthy,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthObservation {
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthStateChange {
    pub from: UpstreamAvailability,
    pub to: UpstreamAvailability,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthTransitionResult {
    pub state: UpstreamHealthState,
    pub change: Option<HealthStateChange>,
}

pub fn transition_upstream_health(
    state: UpstreamHealthState,
    observation: HealthObservation,
    policy: &HttpHealthCheckPolicy,
) -> HealthTransitionResult {
    let from = state.availability();
    let next = match (state, observation) {
        (UpstreamHealthState::Disabled, _) => UpstreamHealthState::Disabled,
        (
            UpstreamHealthState::Unknown {
                consecutive_successes,
                ..
            },
            HealthObservation::Succeeded,
        ) => {
            let successes = consecutive_successes.saturating_add(1);
            if successes >= policy.healthy_threshold {
                UpstreamHealthState::Healthy {
                    consecutive_failures: 0,
                }
            } else {
                UpstreamHealthState::Unknown {
                    consecutive_successes: successes,
                    consecutive_failures: 0,
                }
            }
        }
        (
            UpstreamHealthState::Unknown {
                consecutive_failures,
                ..
            },
            HealthObservation::Failed,
        ) => {
            let failures = consecutive_failures.saturating_add(1);
            if failures >= policy.unhealthy_threshold {
                UpstreamHealthState::Unhealthy {
                    consecutive_successes: 0,
                }
            } else {
                UpstreamHealthState::Unknown {
                    consecutive_successes: 0,
                    consecutive_failures: failures,
                }
            }
        }
        (UpstreamHealthState::Healthy { .. }, HealthObservation::Succeeded) => {
            UpstreamHealthState::Healthy {
                consecutive_failures: 0,
            }
        }
        (
            UpstreamHealthState::Healthy {
                consecutive_failures,
            },
            HealthObservation::Failed,
        ) => {
            let failures = consecutive_failures.saturating_add(1);
            if failures >= policy.unhealthy_threshold {
                UpstreamHealthState::Unhealthy {
                    consecutive_successes: 0,
                }
            } else {
                UpstreamHealthState::Healthy {
                    consecutive_failures: failures,
                }
            }
        }
        (UpstreamHealthState::Unhealthy { .. }, HealthObservation::Failed) => {
            UpstreamHealthState::Unhealthy {
                consecutive_successes: 0,
            }
        }
        (
            UpstreamHealthState::Unhealthy {
                consecutive_successes,
            },
            HealthObservation::Succeeded,
        ) => {
            let successes = consecutive_successes.saturating_add(1);
            if successes >= policy.healthy_threshold {
                UpstreamHealthState::Healthy {
                    consecutive_failures: 0,
                }
            } else {
                UpstreamHealthState::Unhealthy {
                    consecutive_successes: successes,
                }
            }
        }
    };
    let to = next.availability();

    HealthTransitionResult {
        state: next,
        change: (from != to).then_some(HealthStateChange { from, to }),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub enabled: bool,
    pub max_retries: u8,
    pub max_replay_bytes: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            max_retries: 1,
            max_replay_bytes: 32_768,
        }
    }
}

impl RetryPolicy {
    pub fn new(
        enabled: bool,
        max_retries: u8,
        max_replay_bytes: u64,
    ) -> Result<Self, ValidationError> {
        if max_retries > 1
            || (enabled && max_retries != 1)
            || !(1_024..=65_536).contains(&max_replay_bytes)
        {
            return Err(ValidationError::new(
                ErrorCode::ConfigRetryPolicyInvalid,
                "retry policy is outside supported bounds",
            ));
        }
        Ok(Self {
            enabled,
            max_retries,
            max_replay_bytes,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayMethod {
    Get,
    Head,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryFailureKind {
    Connect,
    ConnectTimeout,
    Write,
    Read,
    ReadTimeout,
    ResetBeforeResponse,
}

#[derive(Debug, Clone, Copy)]
pub struct RetryInput<'a> {
    pub policy: &'a RetryPolicy,
    pub method: ReplayMethod,
    pub body_bytes: u64,
    pub request_bytes_written: u64,
    pub response_started: bool,
    pub attempts_used: u8,
    pub replay_reserved: bool,
    pub failure: RetryFailureKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDenialReason {
    Disabled,
    MethodNotReplayable,
    BodyPresent,
    RequestWriteStarted,
    ResponseStarted,
    RetryBudgetExhausted,
    ReplayBudgetExhausted,
    FailureNotRetryable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    Retry,
    DoNotRetry(RetryDenialReason),
}

pub fn evaluate_retry(input: RetryInput<'_>) -> RetryDecision {
    let denial = if !input.policy.enabled {
        Some(RetryDenialReason::Disabled)
    } else if !matches!(input.method, ReplayMethod::Get | ReplayMethod::Head) {
        Some(RetryDenialReason::MethodNotReplayable)
    } else if input.body_bytes != 0 {
        Some(RetryDenialReason::BodyPresent)
    } else if input.request_bytes_written != 0 {
        Some(RetryDenialReason::RequestWriteStarted)
    } else if input.response_started {
        Some(RetryDenialReason::ResponseStarted)
    } else if input.attempts_used >= input.policy.max_retries {
        Some(RetryDenialReason::RetryBudgetExhausted)
    } else if !input.replay_reserved {
        Some(RetryDenialReason::ReplayBudgetExhausted)
    } else if !matches!(
        input.failure,
        RetryFailureKind::Connect
            | RetryFailureKind::ConnectTimeout
            | RetryFailureKind::Write
            | RetryFailureKind::Read
            | RetryFailureKind::ReadTimeout
            | RetryFailureKind::ResetBeforeResponse
    ) {
        Some(RetryDenialReason::FailureNotRetryable)
    } else {
        None
    };
    denial.map_or(RetryDecision::Retry, RetryDecision::DoNotRetry)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PassiveHealthPolicy {
    pub failure_threshold: u8,
    pub ejection_ms: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PassiveHealthMode {
    #[default]
    Disabled,
    Enabled(PassiveHealthPolicy),
}

impl PassiveHealthPolicy {
    pub fn new(failure_threshold: u8, ejection_ms: u64) -> Result<Self, ValidationError> {
        if !(1..=10).contains(&failure_threshold) || !(1_000..=86_400_000).contains(&ejection_ms) {
            return Err(ValidationError::new(
                ErrorCode::ConfigPassiveHealthPolicyInvalid,
                "passive health policy is outside supported bounds",
            ));
        }
        Ok(Self {
            failure_threshold,
            ejection_ms,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassiveHealthState {
    Disabled,
    Observing { consecutive_failures: u8 },
    Ejected { until_ms: u64 },
}

impl PassiveHealthState {
    pub fn observing() -> Self {
        Self::Observing {
            consecutive_failures: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassiveHealthEvent {
    Succeeded,
    Failed { now_ms: u64 },
    CooldownElapsed { now_ms: u64 },
}

pub fn transition_passive_health(
    state: PassiveHealthState,
    event: PassiveHealthEvent,
    policy: &PassiveHealthPolicy,
) -> PassiveHealthState {
    match (state, event) {
        (PassiveHealthState::Disabled, _) => PassiveHealthState::Disabled,
        (PassiveHealthState::Observing { .. }, PassiveHealthEvent::Succeeded) => {
            PassiveHealthState::observing()
        }
        (
            PassiveHealthState::Observing {
                consecutive_failures,
            },
            PassiveHealthEvent::Failed { now_ms },
        ) => {
            let failures = consecutive_failures.saturating_add(1);
            if failures >= policy.failure_threshold {
                PassiveHealthState::Ejected {
                    until_ms: now_ms.saturating_add(policy.ejection_ms),
                }
            } else {
                PassiveHealthState::Observing {
                    consecutive_failures: failures,
                }
            }
        }
        (
            current @ PassiveHealthState::Observing { .. },
            PassiveHealthEvent::CooldownElapsed { .. },
        ) => current,
        (
            current @ PassiveHealthState::Ejected { .. },
            PassiveHealthEvent::Succeeded | PassiveHealthEvent::Failed { .. },
        ) => current,
        (
            PassiveHealthState::Ejected { until_ms },
            PassiveHealthEvent::CooldownElapsed { now_ms },
        ) => {
            if now_ms >= until_ms {
                PassiveHealthState::observing()
            } else {
                PassiveHealthState::Ejected { until_ms }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamMembership {
    Present,
    Removed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamAdministrativeState {
    Active,
    Draining,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveUpstreamState {
    pub membership: UpstreamMembership,
    pub administrative: UpstreamAdministrativeState,
    pub active_health: UpstreamAvailability,
    pub passive_health: PassiveHealthState,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamExclusionReason {
    Removed,
    Draining,
    ActiveUnhealthy,
    PassiveEjected,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveEligibility {
    Eligible,
    Excluded(UpstreamExclusionReason),
}

pub fn effective_eligibility(state: &EffectiveUpstreamState) -> EffectiveEligibility {
    if state.membership == UpstreamMembership::Removed {
        EffectiveEligibility::Excluded(UpstreamExclusionReason::Removed)
    } else if state.administrative == UpstreamAdministrativeState::Draining {
        EffectiveEligibility::Excluded(UpstreamExclusionReason::Draining)
    } else if state.active_health == UpstreamAvailability::Unhealthy {
        EffectiveEligibility::Excluded(UpstreamExclusionReason::ActiveUnhealthy)
    } else if matches!(state.passive_health, PassiveHealthState::Ejected { .. }) {
        EffectiveEligibility::Excluded(UpstreamExclusionReason::PassiveEjected)
    } else {
        EffectiveEligibility::Eligible
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcmeChallenge {
    Http01,
    Dns01,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateResolver {
    pub id: CertificateResolverId,
    pub email: String,
    pub challenge: AcmeChallenge,
    pub production_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyHost {
    pub id: ProxyHostId,
    pub name: String,
    pub domains: Vec<HostMatch>,
    pub path_prefix: PathMatch,
    pub upstream_url: String,
    pub upstreams: Vec<Upstream>,
    pub health_check: HealthCheckPolicy,
    pub retry: RetryPolicy,
    pub passive_health: PassiveHealthMode,
    pub https_enabled: bool,
    pub letsencrypt_enabled: bool,
    pub redirect_http_to_https: bool,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogMode {
    Product,
    FieldDebug,
    Dev,
}

impl LogMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Product => "product",
            Self::FieldDebug => "field-debug",
            Self::Dev => "dev",
        }
    }
}

impl FromStr for LogMode {
    type Err = ValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "product" => Ok(Self::Product),
            "field-debug" => Ok(Self::FieldDebug),
            "dev" => Ok(Self::Dev),
            _ => Err(ValidationError::new(
                ErrorCode::ConfigInvalidLogMode,
                "unknown log mode",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapConfig {
    pub data_dir: String,
    pub config_file: String,
    pub admin_bind: String,
    pub log_mode: LogMode,
}

impl BootstrapConfig {
    pub fn new(
        data_dir: impl Into<String>,
        config_file: impl Into<String>,
        admin_bind: impl Into<String>,
        log_mode: LogMode,
    ) -> Self {
        Self {
            data_dir: data_dir.into(),
            config_file: config_file.into(),
            admin_bind: admin_bind.into(),
            log_mode,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeOptions {
    pub max_connections: usize,
    pub max_inflight_payload_bytes: usize,
    pub max_request_header_bytes: usize,
    pub max_request_body_bytes: usize,
    pub upstream_read_timeout_ms: u64,
    pub metrics: MetricsConfig,
}

pub const DEFAULT_MAX_CONNECTIONS: usize = 1_024;
pub const MIN_MAX_CONNECTIONS: usize = 1;
pub const HARD_MAX_CONNECTIONS: usize = 4_096;
pub const DEFAULT_MAX_INFLIGHT_PAYLOAD_BYTES: usize = 128 * 1024 * 1024;
pub const MIN_MAX_INFLIGHT_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
pub const HARD_MAX_INFLIGHT_PAYLOAD_BYTES: usize = 512 * 1024 * 1024;
pub const FIXED_REQUEST_HEADER_RESERVE_BYTES: usize = 16 * 1024;
pub const FIXED_RESPONSE_BUFFER_RESERVE_BYTES: usize = 64 * 1024;
pub const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
pub const DEFAULT_UPSTREAM_READ_TIMEOUT_MS: u64 = 30_000;
pub const MIN_UPSTREAM_READ_TIMEOUT_MS: u64 = 10;
pub const HARD_MAX_UPSTREAM_READ_TIMEOUT_MS: u64 = 120_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeResourcePolicy {
    max_connections: usize,
    max_inflight_payload_bytes: usize,
}

impl RuntimeResourcePolicy {
    pub fn try_new(
        max_connections: usize,
        max_inflight_payload_bytes: usize,
    ) -> Result<Self, AppError> {
        if !(MIN_MAX_CONNECTIONS..=HARD_MAX_CONNECTIONS).contains(&max_connections) {
            return Err(invalid_resource_policy(
                "max connections is outside the supported range",
            ));
        }
        if !(MIN_MAX_INFLIGHT_PAYLOAD_BYTES..=HARD_MAX_INFLIGHT_PAYLOAD_BYTES)
            .contains(&max_inflight_payload_bytes)
        {
            return Err(invalid_resource_policy(
                "in-flight payload limit is outside the supported range",
            ));
        }

        let per_connection_reserve = FIXED_REQUEST_HEADER_RESERVE_BYTES
            .checked_add(FIXED_RESPONSE_BUFFER_RESERVE_BYTES)
            .ok_or_else(|| invalid_resource_policy("fixed payload reserve overflowed"))?;
        let required_fixed_payload_reserve_bytes = max_connections
            .checked_mul(per_connection_reserve)
            .ok_or_else(|| invalid_resource_policy("fixed payload reserve overflowed"))?;
        if max_inflight_payload_bytes < required_fixed_payload_reserve_bytes {
            return Err(invalid_resource_policy(
                "in-flight payload limit is below the fixed connection reserve",
            ));
        }

        Ok(Self {
            max_connections,
            max_inflight_payload_bytes,
        })
    }

    pub fn max_connections(self) -> usize {
        self.max_connections
    }

    pub fn max_inflight_payload_bytes(self) -> usize {
        self.max_inflight_payload_bytes
    }

    pub fn required_fixed_payload_reserve_bytes(self) -> usize {
        self.max_connections
            * (FIXED_REQUEST_HEADER_RESERVE_BYTES + FIXED_RESPONSE_BUFFER_RESERVE_BYTES)
    }
}

impl Default for RuntimeResourcePolicy {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_inflight_payload_bytes: DEFAULT_MAX_INFLIGHT_PAYLOAD_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeTimeoutPolicy {
    upstream_read_timeout_ms: u64,
}

impl RuntimeTimeoutPolicy {
    pub fn try_new(upstream_read_timeout_ms: u64) -> Result<Self, AppError> {
        if !(MIN_UPSTREAM_READ_TIMEOUT_MS..=HARD_MAX_UPSTREAM_READ_TIMEOUT_MS)
            .contains(&upstream_read_timeout_ms)
        {
            return Err(invalid_resource_policy(
                "upstream read timeout is outside the supported range",
            ));
        }

        Ok(Self {
            upstream_read_timeout_ms,
        })
    }

    pub fn upstream_read_timeout_ms(&self) -> u64 {
        self.upstream_read_timeout_ms
    }
}

impl Default for RuntimeTimeoutPolicy {
    fn default() -> Self {
        Self {
            upstream_read_timeout_ms: DEFAULT_UPSTREAM_READ_TIMEOUT_MS,
        }
    }
}

fn invalid_resource_policy(message: &'static str) -> AppError {
    AppError::new(ErrorCode::ConfigResourceLimitInvalid, message)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceChargeState {
    Requested,
    Granted,
    InUse,
    Transferred,
    Released,
    RejectedCapacity,
    AllocationFailed,
}

impl ResourceChargeState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Released | Self::RejectedCapacity | Self::AllocationFailed
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub bind: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "127.0.0.1:9464".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminConfig {
    pub bind: String,
    pub auth_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigSnapshot {
    pub schema_version: u32,
    pub revision_id: ConfigRevisionId,
    pub admin: AdminConfig,
    pub listeners: Vec<Listener>,
    pub routes: Vec<Route>,
    pub services: Vec<Service>,
    pub certificate_resolvers: Vec<CertificateResolver>,
    pub log_mode: LogMode,
    pub runtime: RuntimeOptions,
}

impl ConfigSnapshot {
    pub fn select_route(&self, host: &str, path: &str) -> Option<&Route> {
        self.routes
            .iter()
            .filter(|route| route.matches(host, path))
            .max_by_key(|route| {
                (
                    route.priority,
                    route.route_match.best_path_specificity(path),
                )
            })
    }

    pub fn find_service(&self, service_id: &ServiceId) -> Option<&Service> {
        self.services
            .iter()
            .find(|service| &service.id == service_id)
    }

    pub fn primary_upstream_for_service(&self, service_id: &ServiceId) -> Option<&Upstream> {
        self.find_service(service_id)?.primary_upstream()
    }
}

impl Service {
    pub fn primary_upstream(&self) -> Option<&Upstream> {
        self.upstreams.first()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigRevision {
    pub id: ConfigRevisionId,
    pub schema_version: u32,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreCommand {
    ApplyConfigSnapshot {
        snapshot: ConfigSnapshot,
    },
    ActivateConfigSnapshot {
        snapshot: ConfigSnapshot,
        availability: HealthAvailabilitySnapshot,
    },
    PublishUpstreamAvailability {
        snapshot: HealthAvailabilitySnapshot,
    },
    RollbackConfigSnapshot {
        revision_id: ConfigRevisionId,
    },
    InstallCertificate {
        certificate_ref: CertificateRef,
    },
    RefreshRouteTable,
    BeginDrain {
        deadline_ms: u64,
    },
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandAck {
    Accepted,
    Rejected(AppError),
}

impl CommandAck {
    pub fn accepted() -> Self {
        Self::Accepted
    }

    pub fn rejected(error: AppError) -> Self {
        Self::Rejected(error)
    }

    pub fn is_success(&self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DataDirectoryLockState {
    #[default]
    Unlocked,
    AcquiringExclusive,
    HeldExclusive,
    Releasing,
    Released,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataDirectoryLockEvent {
    AcquireRequested,
    AcquireSucceeded,
    AcquireFailed,
    ReleaseRequested,
    ReleaseSucceeded,
    ReleaseFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DataDirectoryLockMachine {
    state: DataDirectoryLockState,
}

impl DataDirectoryLockMachine {
    pub fn state(&self) -> DataDirectoryLockState {
        self.state
    }

    pub fn transition(&mut self, event: DataDirectoryLockEvent) -> Result<(), AppError> {
        let next = match (self.state, event) {
            (DataDirectoryLockState::Unlocked, DataDirectoryLockEvent::AcquireRequested) => {
                DataDirectoryLockState::AcquiringExclusive
            }
            (
                DataDirectoryLockState::AcquiringExclusive,
                DataDirectoryLockEvent::AcquireSucceeded,
            ) => DataDirectoryLockState::HeldExclusive,
            (DataDirectoryLockState::AcquiringExclusive, DataDirectoryLockEvent::AcquireFailed) => {
                DataDirectoryLockState::Failed
            }
            (DataDirectoryLockState::HeldExclusive, DataDirectoryLockEvent::ReleaseRequested) => {
                DataDirectoryLockState::Releasing
            }
            (DataDirectoryLockState::Releasing, DataDirectoryLockEvent::ReleaseSucceeded) => {
                DataDirectoryLockState::Released
            }
            (DataDirectoryLockState::Releasing, DataDirectoryLockEvent::ReleaseFailed) => {
                DataDirectoryLockState::Failed
            }
            _ => {
                return Err(AppError::new(
                    ErrorCode::DataDirectoryLockStateInvalid,
                    "data directory lock event is invalid for the current state",
                ));
            }
        };
        self.state = next;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    ConfigAdminBindConflict,
    ConfigAdminExternalBindWithoutAuth,
    ConfigAcmeChallengeBlockedByRedirect,
    ConfigHttp01WithoutHttpListener,
    ConfigHttpsRouteCertificateMissing,
    ConfigInvalidAcmeEmail,
    ConfigInvalidBindAddress,
    ConfigHealthCheckInvalidInterval,
    ConfigHealthCheckInvalidPath,
    ConfigHealthCheckInvalidStatusRange,
    ConfigHealthCheckInvalidThreshold,
    ConfigInvalidLoadBalancingPolicy,
    ConfigInvalidLogMode,
    ConfigResourceLimitInvalid,
    ConfigRetryPolicyInvalid,
    ConfigPassiveHealthPolicyInvalid,
    ConfigInvalidUpstreamUrl,
    ConfigTrustBundleRefInvalid,
    ConfigTrustBundleNotFound,
    TrustBundleInvalid,
    TrustBundleAlreadyExists,
    TrustBundleLimitExceeded,
    TrustBundleReferenced,
    TrustBundleStoreFailed,
    UpstreamTlsUntrusted,
    UpstreamTlsIdentityMismatch,
    UpstreamTlsProfileInvalid,
    ConfigTlsServerNameInvalid,
    ConfigUpstreamHttpHostInvalid,
    ConfigTlsPolicyInvalid,
    ConfigClientAuthPolicyInvalid,
    ConfigUpstreamIdDuplicate,
    ConfigUpstreamIdRequired,
    ConfigListenerDuplicate,
    ConfigProductionAcmeRequiresOptIn,
    ConfigCurrentRevisionInvalid,
    ConfigCurrentRevisionMissing,
    ConfigBootstrapSeedInvalid,
    ConfigRevisionNotFound,
    ConfigRouteDuplicate,
    ConfigRouteMatchEmpty,
    ConfigRouteMissingService,
    ConfigSchemaVersionMissing,
    ConfigServiceWithoutUpstream,
    ConfigStoreFailed,
    ConfigUnsafeUpstreamUrl,
    AcmeChallengeFailed,
    AcmeTermsNotAccepted,
    AdminAuthRequired,
    AdminCsrfRequired,
    AdminEndpointNotImplemented,
    AdminInvalidCredentials,
    AdminRouteNotFound,
    AdminSetupAlreadyComplete,
    AdminSetupRequired,
    CertificateExpired,
    CertificateInvalid,
    CertificateNotFound,
    CertificateStoreFailed,
    HttpConnectMethodRejected,
    HttpHeaderTooLarge,
    HttpMalformedRequest,
    HttpRequestBodyTooLarge,
    HttpRequestLineTooLarge,
    HttpTransferEncodingContentLengthConflict,
    SupportBundleBoundsExceeded,
    SupportBundleReportInvalid,
    RuntimeCommandRejected,
    RuntimeHealthUnavailable,
    RuntimeUpstreamBadGateway,
    RuntimeUpstreamTimeout,
    ResourcePayloadCapacityReached,
    ResourceAllocationFailed,
    ResourceAccountingInvariantFailed,
    TlsHandshakeFailed,
    TlsHandshakeTimeout,
    ProcessCommandInvalid,
    ProcessCommandNotImplemented,
    DataDirectoryBusy,
    DataDirectoryLockFailed,
    DataDirectoryLockStateInvalid,
    BackupManifestInvalid,
    BackupSchemaUnsupported,
    BackupLimitExceeded,
    BackupSecretInputInvalid,
    BackupSourceInvalid,
    BackupSourceChanged,
    BackupDestinationUnsafe,
    BackupDestinationExists,
    BackupEncryptionFailed,
    BackupWriteFailed,
    BackupPublishFailed,
    BackupStateTransitionInvalid,
    BackupAuthenticationFailed,
    BackupFormatInvalid,
    BackupDigestMismatch,
    BackupPathUnsafe,
    RestoreTargetBusy,
    RestoreTargetNotEmpty,
    RestoreTargetUnsafe,
    RestoreStageFailed,
    RestoreConfigInvalid,
    RestoreCertificateInvalid,
    RestoreSecretInvalid,
    RestorePreflightFailed,
    RestoreCommitFailed,
    RestoreRollbackFailed,
    RestoreTransactionUnresolved,
    RestoreTransactionAmbiguous,
    RestorePlatformUnsupported,
    RestoreStateTransitionInvalid,
    AuditUnavailable,
    AuditMutationBlocked,
    AuditRecordInvalid,
    AuditRecordTooLarge,
    AuditCapacityReached,
    AuditSequenceInvalid,
    AuditChainMismatch,
    AuditInteriorCorruption,
    AuditTrailingFrameIncomplete,
    AuditUnsupportedVersion,
    AuditAppendFailed,
    AuditSyncFailed,
    AuditCursorInvalid,
    AuditReconciliationUnknown,
    InternalBug,
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ConfigAdminBindConflict => "CONFIG_ADMIN_BIND_CONFLICT",
            Self::ConfigAdminExternalBindWithoutAuth => "CONFIG_ADMIN_EXTERNAL_BIND_WITHOUT_AUTH",
            Self::ConfigAcmeChallengeBlockedByRedirect => {
                "CONFIG_ACME_CHALLENGE_BLOCKED_BY_REDIRECT"
            }
            Self::ConfigHttp01WithoutHttpListener => "CONFIG_HTTP01_WITHOUT_HTTP_LISTENER",
            Self::ConfigHttpsRouteCertificateMissing => "CONFIG_HTTPS_ROUTE_CERTIFICATE_MISSING",
            Self::ConfigInvalidAcmeEmail => "CONFIG_INVALID_ACME_EMAIL",
            Self::ConfigInvalidBindAddress => "CONFIG_INVALID_BIND_ADDRESS",
            Self::ConfigHealthCheckInvalidInterval => "CONFIG_HEALTH_CHECK_INVALID_INTERVAL",
            Self::ConfigHealthCheckInvalidPath => "CONFIG_HEALTH_CHECK_INVALID_PATH",
            Self::ConfigHealthCheckInvalidStatusRange => "CONFIG_HEALTH_CHECK_INVALID_STATUS_RANGE",
            Self::ConfigHealthCheckInvalidThreshold => "CONFIG_HEALTH_CHECK_INVALID_THRESHOLD",
            Self::ConfigInvalidLoadBalancingPolicy => "CONFIG_INVALID_LOAD_BALANCING_POLICY",
            Self::ConfigInvalidLogMode => "CONFIG_INVALID_LOG_MODE",
            Self::ConfigResourceLimitInvalid => "CONFIG_RESOURCE_LIMIT_INVALID",
            Self::ConfigRetryPolicyInvalid => "CONFIG_RETRY_POLICY_INVALID",
            Self::ConfigPassiveHealthPolicyInvalid => "CONFIG_PASSIVE_HEALTH_POLICY_INVALID",
            Self::ConfigInvalidUpstreamUrl => "CONFIG_INVALID_UPSTREAM_URL",
            Self::ConfigTrustBundleRefInvalid => "CONFIG_TRUST_BUNDLE_REF_INVALID",
            Self::ConfigTrustBundleNotFound => "CONFIG_TRUST_BUNDLE_NOT_FOUND",
            Self::TrustBundleInvalid => "TRUST_BUNDLE_INVALID",
            Self::TrustBundleAlreadyExists => "TRUST_BUNDLE_ALREADY_EXISTS",
            Self::TrustBundleLimitExceeded => "TRUST_BUNDLE_LIMIT_EXCEEDED",
            Self::TrustBundleReferenced => "TRUST_BUNDLE_REFERENCED",
            Self::TrustBundleStoreFailed => "TRUST_BUNDLE_STORE_FAILED",
            Self::UpstreamTlsUntrusted => "UPSTREAM_TLS_UNTRUSTED",
            Self::UpstreamTlsIdentityMismatch => "UPSTREAM_TLS_IDENTITY_MISMATCH",
            Self::UpstreamTlsProfileInvalid => "UPSTREAM_TLS_PROFILE_INVALID",
            Self::ConfigTlsServerNameInvalid => "CONFIG_TLS_SERVER_NAME_INVALID",
            Self::ConfigUpstreamHttpHostInvalid => "CONFIG_UPSTREAM_HTTP_HOST_INVALID",
            Self::ConfigTlsPolicyInvalid => "CONFIG_TLS_POLICY_INVALID",
            Self::ConfigClientAuthPolicyInvalid => "CONFIG_CLIENT_AUTH_POLICY_INVALID",
            Self::ConfigUpstreamIdDuplicate => "CONFIG_UPSTREAM_ID_DUPLICATE",
            Self::ConfigUpstreamIdRequired => "CONFIG_UPSTREAM_ID_REQUIRED",
            Self::ConfigListenerDuplicate => "CONFIG_LISTENER_DUPLICATE",
            Self::ConfigProductionAcmeRequiresOptIn => "CONFIG_PRODUCTION_ACME_REQUIRES_OPT_IN",
            Self::ConfigCurrentRevisionInvalid => "CONFIG_CURRENT_REVISION_INVALID",
            Self::ConfigCurrentRevisionMissing => "CONFIG_CURRENT_REVISION_MISSING",
            Self::ConfigBootstrapSeedInvalid => "CONFIG_BOOTSTRAP_SEED_INVALID",
            Self::ConfigRevisionNotFound => "CONFIG_REVISION_NOT_FOUND",
            Self::ConfigRouteDuplicate => "CONFIG_ROUTE_DUPLICATE",
            Self::ConfigRouteMatchEmpty => "CONFIG_ROUTE_MATCH_EMPTY",
            Self::ConfigRouteMissingService => "CONFIG_ROUTE_MISSING_SERVICE",
            Self::ConfigSchemaVersionMissing => "CONFIG_SCHEMA_VERSION_MISSING",
            Self::ConfigServiceWithoutUpstream => "CONFIG_SERVICE_WITHOUT_UPSTREAM",
            Self::ConfigStoreFailed => "CONFIG_STORE_FAILED",
            Self::ConfigUnsafeUpstreamUrl => "CONFIG_UNSAFE_UPSTREAM_URL",
            Self::AcmeChallengeFailed => "ACME_CHALLENGE_FAILED",
            Self::AcmeTermsNotAccepted => "ACME_TERMS_NOT_ACCEPTED",
            Self::AdminAuthRequired => "ADMIN_AUTH_REQUIRED",
            Self::AdminCsrfRequired => "ADMIN_CSRF_REQUIRED",
            Self::AdminEndpointNotImplemented => "ADMIN_ENDPOINT_NOT_IMPLEMENTED",
            Self::AdminInvalidCredentials => "ADMIN_INVALID_CREDENTIALS",
            Self::AdminRouteNotFound => "ADMIN_ROUTE_NOT_FOUND",
            Self::AdminSetupAlreadyComplete => "ADMIN_SETUP_ALREADY_COMPLETE",
            Self::AdminSetupRequired => "ADMIN_SETUP_REQUIRED",
            Self::CertificateExpired => "CERTIFICATE_EXPIRED",
            Self::CertificateInvalid => "CERTIFICATE_INVALID",
            Self::CertificateNotFound => "CERTIFICATE_NOT_FOUND",
            Self::CertificateStoreFailed => "CERTIFICATE_STORE_FAILED",
            Self::HttpConnectMethodRejected => "HTTP_CONNECT_METHOD_REJECTED",
            Self::HttpHeaderTooLarge => "HTTP_HEADER_TOO_LARGE",
            Self::HttpMalformedRequest => "HTTP_MALFORMED_REQUEST",
            Self::HttpRequestBodyTooLarge => "HTTP_REQUEST_BODY_TOO_LARGE",
            Self::HttpRequestLineTooLarge => "HTTP_REQUEST_LINE_TOO_LARGE",
            Self::HttpTransferEncodingContentLengthConflict => {
                "HTTP_TRANSFER_ENCODING_CONTENT_LENGTH_CONFLICT"
            }
            Self::SupportBundleBoundsExceeded => "SUPPORT_BUNDLE_BOUNDS_EXCEEDED",
            Self::SupportBundleReportInvalid => "SUPPORT_BUNDLE_REPORT_INVALID",
            Self::RuntimeCommandRejected => "RUNTIME_COMMAND_REJECTED",
            Self::RuntimeHealthUnavailable => "RUNTIME_HEALTH_UNAVAILABLE",
            Self::RuntimeUpstreamBadGateway => "RUNTIME_UPSTREAM_BAD_GATEWAY",
            Self::RuntimeUpstreamTimeout => "RUNTIME_UPSTREAM_TIMEOUT",
            Self::ResourcePayloadCapacityReached => "RESOURCE_PAYLOAD_CAPACITY_REACHED",
            Self::ResourceAllocationFailed => "RESOURCE_ALLOCATION_FAILED",
            Self::ResourceAccountingInvariantFailed => "RESOURCE_ACCOUNTING_INVARIANT_FAILED",
            Self::TlsHandshakeFailed => "TLS_HANDSHAKE_FAILED",
            Self::TlsHandshakeTimeout => "TLS_HANDSHAKE_TIMEOUT",
            Self::ProcessCommandInvalid => "PROCESS_COMMAND_INVALID",
            Self::ProcessCommandNotImplemented => "PROCESS_COMMAND_NOT_IMPLEMENTED",
            Self::DataDirectoryBusy => "DATA_DIRECTORY_BUSY",
            Self::DataDirectoryLockFailed => "DATA_DIRECTORY_LOCK_FAILED",
            Self::DataDirectoryLockStateInvalid => "DATA_DIRECTORY_LOCK_STATE_INVALID",
            Self::BackupManifestInvalid => "BACKUP_MANIFEST_INVALID",
            Self::BackupSchemaUnsupported => "BACKUP_SCHEMA_UNSUPPORTED",
            Self::BackupLimitExceeded => "BACKUP_LIMIT_EXCEEDED",
            Self::BackupSecretInputInvalid => "BACKUP_SECRET_INPUT_INVALID",
            Self::BackupSourceInvalid => "BACKUP_SOURCE_INVALID",
            Self::BackupSourceChanged => "BACKUP_SOURCE_CHANGED",
            Self::BackupDestinationUnsafe => "BACKUP_DESTINATION_UNSAFE",
            Self::BackupDestinationExists => "BACKUP_DESTINATION_EXISTS",
            Self::BackupEncryptionFailed => "BACKUP_ENCRYPTION_FAILED",
            Self::BackupWriteFailed => "BACKUP_WRITE_FAILED",
            Self::BackupPublishFailed => "BACKUP_PUBLISH_FAILED",
            Self::BackupStateTransitionInvalid => "BACKUP_STATE_TRANSITION_INVALID",
            Self::BackupAuthenticationFailed => "BACKUP_AUTHENTICATION_FAILED",
            Self::BackupFormatInvalid => "BACKUP_FORMAT_INVALID",
            Self::BackupDigestMismatch => "BACKUP_DIGEST_MISMATCH",
            Self::BackupPathUnsafe => "BACKUP_PATH_UNSAFE",
            Self::RestoreTargetBusy => "RESTORE_TARGET_BUSY",
            Self::RestoreTargetNotEmpty => "RESTORE_TARGET_NOT_EMPTY",
            Self::RestoreTargetUnsafe => "RESTORE_TARGET_UNSAFE",
            Self::RestoreStageFailed => "RESTORE_STAGE_FAILED",
            Self::RestoreConfigInvalid => "RESTORE_CONFIG_INVALID",
            Self::RestoreCertificateInvalid => "RESTORE_CERTIFICATE_INVALID",
            Self::RestoreSecretInvalid => "RESTORE_SECRET_INVALID",
            Self::RestorePreflightFailed => "RESTORE_PREFLIGHT_FAILED",
            Self::RestoreCommitFailed => "RESTORE_COMMIT_FAILED",
            Self::RestoreRollbackFailed => "RESTORE_ROLLBACK_FAILED",
            Self::RestoreTransactionUnresolved => "RESTORE_TRANSACTION_UNRESOLVED",
            Self::RestoreTransactionAmbiguous => "RESTORE_TRANSACTION_AMBIGUOUS",
            Self::RestorePlatformUnsupported => "RESTORE_PLATFORM_UNSUPPORTED",
            Self::RestoreStateTransitionInvalid => "RESTORE_STATE_TRANSITION_INVALID",
            Self::AuditUnavailable => "AUDIT_UNAVAILABLE",
            Self::AuditCursorInvalid => "AUDIT_CURSOR_INVALID",
            Self::AuditMutationBlocked => "AUDIT_MUTATION_BLOCKED",
            Self::AuditRecordInvalid => "AUDIT_RECORD_INVALID",
            Self::AuditRecordTooLarge => "AUDIT_RECORD_TOO_LARGE",
            Self::AuditCapacityReached => "AUDIT_CAPACITY_REACHED",
            Self::AuditSequenceInvalid => "AUDIT_SEQUENCE_INVALID",
            Self::AuditChainMismatch => "AUDIT_CHAIN_MISMATCH",
            Self::AuditInteriorCorruption => "AUDIT_INTERIOR_CORRUPTION",
            Self::AuditTrailingFrameIncomplete => "AUDIT_TRAILING_FRAME_INCOMPLETE",
            Self::AuditUnsupportedVersion => "AUDIT_UNSUPPORTED_VERSION",
            Self::AuditAppendFailed => "AUDIT_APPEND_FAILED",
            Self::AuditSyncFailed => "AUDIT_SYNC_FAILED",
            Self::AuditReconciliationUnknown => "AUDIT_RECONCILIATION_UNKNOWN",
            Self::InternalBug => "INTERNAL_BUG",
        }
    }

    pub fn default_user_message(&self) -> &'static str {
        match self {
            Self::ConfigAdminBindConflict => "The admin bind address conflicts with a listener.",
            Self::ConfigAdminExternalBindWithoutAuth => {
                "Admin access exposed outside localhost requires authentication."
            }
            Self::ConfigAcmeChallengeBlockedByRedirect => {
                "ACME HTTP-01 challenge traffic must not be blocked by redirects."
            }
            Self::ConfigHttp01WithoutHttpListener => "ACME HTTP-01 requires an HTTP listener.",
            Self::ConfigHttpsRouteCertificateMissing => {
                "HTTPS routes require a certificate reference or resolver."
            }
            Self::ConfigInvalidAcmeEmail => "The ACME account email is invalid.",
            Self::ConfigInvalidBindAddress => "The bind address is invalid.",
            Self::ConfigHealthCheckInvalidInterval => "The health-check timing values are invalid.",
            Self::ConfigHealthCheckInvalidPath => "The health-check path is invalid.",
            Self::ConfigHealthCheckInvalidStatusRange => {
                "The health-check status range is invalid."
            }
            Self::ConfigHealthCheckInvalidThreshold => "The health-check threshold is invalid.",
            Self::ConfigInvalidLoadBalancingPolicy => "The load-balancing policy is not supported.",
            Self::ConfigInvalidLogMode => "The log mode is not supported.",
            Self::ConfigResourceLimitInvalid => "The runtime resource limit is invalid.",
            Self::ConfigRetryPolicyInvalid => "The retry policy is invalid.",
            Self::ConfigPassiveHealthPolicyInvalid => "The passive health policy is invalid.",
            Self::ConfigInvalidUpstreamUrl => "The upstream URL is not supported.",
            Self::ConfigTrustBundleRefInvalid => "The trust bundle reference is invalid.",
            Self::ConfigTrustBundleNotFound => "The referenced trust bundle was not found.",
            Self::TrustBundleInvalid => "The trust bundle material is invalid.",
            Self::TrustBundleAlreadyExists => "The trust bundle reference already exists.",
            Self::TrustBundleLimitExceeded => "The trust bundle resource limit was exceeded.",
            Self::TrustBundleReferenced => "The trust bundle is referenced by a config revision.",
            Self::TrustBundleStoreFailed => "The trust bundle store operation failed.",
            Self::UpstreamTlsUntrusted => "The upstream TLS certificate is not trusted.",
            Self::UpstreamTlsIdentityMismatch => "The upstream TLS identity does not match.",
            Self::UpstreamTlsProfileInvalid => "The upstream TLS profile is invalid.",
            Self::ConfigTlsServerNameInvalid => "The TLS server name is invalid.",
            Self::ConfigUpstreamHttpHostInvalid => "The upstream HTTP Host is invalid.",
            Self::ConfigTlsPolicyInvalid => "The upstream TLS policy is invalid.",
            Self::ConfigClientAuthPolicyInvalid => "The listener client-auth policy is invalid.",
            Self::ConfigUpstreamIdDuplicate => "Upstream names must be unique within a service.",
            Self::ConfigUpstreamIdRequired => "Multiple upstreams require explicit stable names.",
            Self::ConfigListenerDuplicate => "A listener with the same id already exists.",
            Self::ConfigProductionAcmeRequiresOptIn => "Production ACME requires explicit opt-in.",
            Self::ConfigCurrentRevisionInvalid => "The current config revision is invalid.",
            Self::ConfigCurrentRevisionMissing => "The current config revision is missing.",
            Self::ConfigBootstrapSeedInvalid => "The bootstrap config seed is invalid.",
            Self::ConfigRevisionNotFound => "The requested config revision was not found.",
            Self::ConfigRouteDuplicate => "A route with the same match already exists.",
            Self::ConfigRouteMatchEmpty => "A route must include at least one host and one path.",
            Self::ConfigRouteMissingService => "The route references a missing service.",
            Self::ConfigSchemaVersionMissing => "The config schema version is required.",
            Self::ConfigServiceWithoutUpstream => "A service must have at least one upstream.",
            Self::ConfigStoreFailed => "The config store operation failed.",
            Self::ConfigUnsafeUpstreamUrl => {
                "The upstream URL targets a blocked metadata endpoint."
            }
            Self::AcmeChallengeFailed => "The ACME challenge failed.",
            Self::AcmeTermsNotAccepted => "ACME terms of service must be accepted first.",
            Self::AdminAuthRequired => "Admin authentication is required.",
            Self::AdminCsrfRequired => "A valid CSRF token is required.",
            Self::AdminEndpointNotImplemented => "The admin endpoint is not implemented yet.",
            Self::AdminInvalidCredentials => "The admin credentials are invalid.",
            Self::AdminRouteNotFound => "The admin route was not found.",
            Self::AdminSetupAlreadyComplete => "Admin setup is already complete.",
            Self::AdminSetupRequired => "Admin setup is required before login.",
            Self::CertificateExpired => "The certificate is expired.",
            Self::CertificateInvalid => "The certificate material is invalid.",
            Self::CertificateNotFound => "The certificate was not found.",
            Self::CertificateStoreFailed => "The certificate store operation failed.",
            Self::HttpConnectMethodRejected => "CONNECT is not supported by this reverse proxy.",
            Self::HttpHeaderTooLarge => "The request headers are too large.",
            Self::HttpMalformedRequest => "The HTTP request is malformed.",
            Self::HttpRequestBodyTooLarge => "The request body is too large.",
            Self::HttpRequestLineTooLarge => "The request line is too large.",
            Self::HttpTransferEncodingContentLengthConflict => {
                "Transfer-Encoding and Content-Length cannot be combined."
            }
            Self::SupportBundleBoundsExceeded => {
                "The support bundle exceeded its collection bounds."
            }
            Self::SupportBundleReportInvalid => {
                "The support bundle collector returned an invalid report."
            }
            Self::RuntimeCommandRejected => "The runtime rejected the command.",
            Self::RuntimeHealthUnavailable => "Runtime health status is unavailable.",
            Self::RuntimeUpstreamBadGateway => "The upstream returned bad gateway.",
            Self::RuntimeUpstreamTimeout => "The upstream timed out.",
            Self::ResourcePayloadCapacityReached => "The runtime payload capacity was reached.",
            Self::ResourceAllocationFailed => "The runtime payload allocation failed.",
            Self::ResourceAccountingInvariantFailed => {
                "The runtime resource accounting invariant failed."
            }
            Self::TlsHandshakeFailed => "The TLS handshake failed.",
            Self::TlsHandshakeTimeout => "The TLS handshake timed out.",
            Self::ProcessCommandInvalid => "The process command is invalid.",
            Self::ProcessCommandNotImplemented => "The process command is not implemented yet.",
            Self::DataDirectoryBusy => "The data directory is in use by another process.",
            Self::DataDirectoryLockFailed => "The data directory lock operation failed.",
            Self::DataDirectoryLockStateInvalid => "The data directory lock state is invalid.",
            Self::BackupManifestInvalid => "The backup manifest is invalid.",
            Self::BackupSchemaUnsupported => "The backup schema is not supported.",
            Self::BackupLimitExceeded => "The backup resource limit was exceeded.",
            Self::BackupSecretInputInvalid => "The backup secret input is invalid.",
            Self::BackupSourceInvalid => "The backup source is invalid.",
            Self::BackupSourceChanged => "The backup source changed during creation.",
            Self::BackupDestinationUnsafe => "The backup destination is unsafe.",
            Self::BackupDestinationExists => "The backup destination already exists.",
            Self::BackupEncryptionFailed => "The backup encryption operation failed.",
            Self::BackupWriteFailed => "The backup write operation failed.",
            Self::BackupPublishFailed => "The backup publish operation failed.",
            Self::BackupStateTransitionInvalid => "The backup state transition is invalid.",
            Self::BackupAuthenticationFailed => "The backup could not be authenticated.",
            Self::BackupFormatInvalid => "The backup format is invalid.",
            Self::BackupDigestMismatch => "The backup digest does not match.",
            Self::BackupPathUnsafe => "The backup contains an unsafe path.",
            Self::RestoreTargetBusy => "The restore target is in use.",
            Self::RestoreTargetNotEmpty => "The restore target is not empty.",
            Self::RestoreTargetUnsafe => "The restore target is unsafe.",
            Self::RestoreStageFailed => "The restore staging operation failed.",
            Self::RestoreConfigInvalid => "The restored configuration is invalid.",
            Self::RestoreCertificateInvalid => "A restored certificate is invalid.",
            Self::RestoreSecretInvalid => "A restored secret is invalid.",
            Self::RestorePreflightFailed => "The restored runtime preflight failed.",
            Self::RestoreCommitFailed => "The restore commit failed.",
            Self::RestoreRollbackFailed => "The restore rollback failed.",
            Self::RestoreTransactionUnresolved => "The restore transaction is unresolved.",
            Self::RestoreTransactionAmbiguous => "The restore transaction state is ambiguous.",
            Self::RestorePlatformUnsupported => {
                "The restore operation is unsupported on this platform."
            }
            Self::RestoreStateTransitionInvalid => "The restore state transition is invalid.",
            Self::AuditUnavailable => "The audit ledger is unavailable.",
            Self::AuditCursorInvalid => "The audit query cursor is stale or invalid.",
            Self::AuditMutationBlocked => "Persistent mutation is blocked by audit state.",
            Self::AuditRecordInvalid => "The audit record is invalid.",
            Self::AuditRecordTooLarge => "The audit record exceeds the size limit.",
            Self::AuditCapacityReached => "The audit ledger capacity was reached.",
            Self::AuditSequenceInvalid => "The audit ledger sequence is invalid.",
            Self::AuditChainMismatch => "The audit ledger hash chain does not match.",
            Self::AuditInteriorCorruption => "The audit ledger contains interior corruption.",
            Self::AuditTrailingFrameIncomplete => {
                "The audit ledger has an incomplete trailing frame."
            }
            Self::AuditUnsupportedVersion => "The audit ledger version is unsupported.",
            Self::AuditAppendFailed => "The audit record could not be persisted.",
            Self::AuditSyncFailed => "The audit ledger could not be synchronized.",
            Self::AuditReconciliationUnknown => {
                "The authoritative operation state could not be reconciled."
            }
            Self::InternalBug => "An internal error occurred.",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppError {
    pub code: ErrorCode,
    pub message: String,
}

impl AppError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub code: ErrorCode,
    pub message: String,
}

impl ValidationError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

pub fn normalize_path(path: &str) -> String {
    let trimmed = path.trim();
    let with_slash = if trimmed.is_empty() {
        "/".to_string()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    };

    if with_slash.len() > 1 {
        with_slash.trim_end_matches('/').to_string()
    } else {
        with_slash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn route(id: &str, host: &str, path: &str, priority: i32, enabled: bool) -> Route {
        Route {
            id: RouteId::new(id),
            route_match: RouteMatch::new(
                vec![HostMatch::exact(host)],
                vec![PathMatch::prefix(path)],
            ),
            service_id: ServiceId::new("service"),
            priority,
            enabled,
            redirect_http_to_https: false,
            certificate_resolver_id: None,
            certificate_ref: None,
        }
    }

    fn snapshot(routes: Vec<Route>) -> ConfigSnapshot {
        ConfigSnapshot {
            schema_version: 1,
            revision_id: ConfigRevisionId::new("rev-1"),
            admin: AdminConfig {
                bind: "127.0.0.1:9443".to_string(),
                auth_required: true,
            },
            listeners: vec![],
            routes,
            services: vec![Service {
                policy: ServicePolicy::default(),
                id: ServiceId::new("service"),
                upstreams: vec![Upstream {
                    id: UpstreamId::new("service-1"),
                    url: "http://127.0.0.1:3000".to_string(),
                    administrative_state: UpstreamAdministrativeState::Active,
                    tls: crate::UpstreamTlsPolicy::Disabled,
                }],
            }],
            certificate_resolvers: vec![],
            log_mode: LogMode::Product,
            runtime: RuntimeOptions {
                max_connections: 1024,
                max_inflight_payload_bytes: DEFAULT_MAX_INFLIGHT_PAYLOAD_BYTES,
                max_request_header_bytes: 16 * 1024,
                max_request_body_bytes: 1024 * 1024,
                upstream_read_timeout_ms: DEFAULT_UPSTREAM_READ_TIMEOUT_MS,
                metrics: MetricsConfig::default(),
            },
        }
    }

    #[test]
    fn exposes_crate_name() {
        assert_eq!(crate_name(), "edge-domain");
    }

    #[test]
    fn runtime_resource_policy_defaults_are_validated_and_immutable() {
        let policy = RuntimeResourcePolicy::default();

        assert_eq!(policy.max_connections(), 1_024);
        assert_eq!(policy.max_inflight_payload_bytes(), 128 * 1024 * 1024);
        assert_eq!(
            policy.required_fixed_payload_reserve_bytes(),
            1_024 * (16 * 1024 + 64 * 1024)
        );
    }

    #[test]
    fn runtime_resource_policy_accepts_supported_boundaries() {
        let minimum = RuntimeResourcePolicy::try_new(1, 16 * 1024 * 1024).unwrap();
        let maximum = RuntimeResourcePolicy::try_new(4_096, 512 * 1024 * 1024).unwrap();

        assert_eq!(minimum.max_connections(), 1);
        assert_eq!(maximum.max_connections(), 4_096);
        assert_eq!(maximum.max_inflight_payload_bytes(), 512 * 1024 * 1024);
    }

    #[test]
    fn runtime_timeout_policy_accepts_only_bounded_read_timeouts() {
        assert_eq!(
            RuntimeTimeoutPolicy::try_new(MIN_UPSTREAM_READ_TIMEOUT_MS)
                .unwrap()
                .upstream_read_timeout_ms(),
            MIN_UPSTREAM_READ_TIMEOUT_MS
        );
        assert_eq!(
            RuntimeTimeoutPolicy::try_new(HARD_MAX_UPSTREAM_READ_TIMEOUT_MS)
                .unwrap()
                .upstream_read_timeout_ms(),
            HARD_MAX_UPSTREAM_READ_TIMEOUT_MS
        );
        for invalid in [
            MIN_UPSTREAM_READ_TIMEOUT_MS - 1,
            HARD_MAX_UPSTREAM_READ_TIMEOUT_MS + 1,
        ] {
            assert_eq!(
                RuntimeTimeoutPolicy::try_new(invalid).unwrap_err().code,
                ErrorCode::ConfigResourceLimitInvalid
            );
        }
    }

    #[test]
    fn runtime_resource_policy_rejects_invalid_bounds_and_relationships() {
        for result in [
            RuntimeResourcePolicy::try_new(0, 128 * 1024 * 1024),
            RuntimeResourcePolicy::try_new(4_097, 512 * 1024 * 1024),
            RuntimeResourcePolicy::try_new(1, 16 * 1024 * 1024 - 1),
            RuntimeResourcePolicy::try_new(1, 512 * 1024 * 1024 + 1),
            RuntimeResourcePolicy::try_new(4_096, 128 * 1024 * 1024),
        ] {
            let error = result.unwrap_err();
            assert_eq!(error.code, ErrorCode::ConfigResourceLimitInvalid);
            assert_eq!(error.code.as_str(), "CONFIG_RESOURCE_LIMIT_INVALID");
        }
    }

    #[test]
    fn resource_charge_lifecycle_has_explicit_terminal_states() {
        for state in [
            ResourceChargeState::Requested,
            ResourceChargeState::Granted,
            ResourceChargeState::InUse,
            ResourceChargeState::Transferred,
        ] {
            assert!(!state.is_terminal());
        }
        for state in [
            ResourceChargeState::Released,
            ResourceChargeState::RejectedCapacity,
            ResourceChargeState::AllocationFailed,
        ] {
            assert!(state.is_terminal());
        }
    }

    #[test]
    fn host_exact_match_succeeds() {
        let host = HostMatch::exact("example.com");

        assert!(host.matches("example.com"));
    }

    #[test]
    fn host_mismatch_fails() {
        let host = HostMatch::exact("example.com");

        assert!(!host.matches("api.example.com"));
    }

    #[test]
    fn host_normalization_allows_case_and_trailing_dot() {
        let host = HostMatch::exact("Example.COM.");

        assert_eq!(host.as_str(), "example.com");
        assert!(host.matches("example.com"));
    }

    #[test]
    fn path_prefix_match_succeeds() {
        let path = PathMatch::prefix("/api");

        assert!(path.matches("/api/v1"));
    }

    #[test]
    fn path_prefix_mismatch_fails() {
        let path = PathMatch::prefix("/api");

        assert!(!path.matches("/admin"));
    }

    #[test]
    fn api_prefix_matches_api_subpath() {
        let path = PathMatch::prefix("/api");

        assert!(path.matches("/api/v1"));
    }

    #[test]
    fn api_prefix_does_not_match_apix() {
        let path = PathMatch::prefix("/api");

        assert!(!path.matches("/apix"));
    }

    #[test]
    fn exact_path_matches_only_the_declared_path_and_wins_a_same_length_prefix_tie() {
        let exact = PathMatch::exact("/health");
        assert!(exact.matches("/health"));
        assert!(!exact.matches("/health/check"));

        let snapshot = snapshot(vec![
            route("prefix", "example.com", "/health", 10, true),
            Route {
                id: RouteId::new("exact"),
                route_match: RouteMatch::new(
                    vec![HostMatch::exact("example.com")],
                    vec![PathMatch::exact("/health")],
                ),
                service_id: ServiceId::new("service"),
                priority: 10,
                enabled: true,
                redirect_http_to_https: false,
                certificate_resolver_id: None,
                certificate_ref: None,
            },
        ]);

        assert_eq!(
            snapshot
                .select_route("example.com", "/health")
                .unwrap()
                .id
                .as_str(),
            "exact"
        );
        assert_eq!(
            snapshot
                .select_route("example.com", "/health/check")
                .unwrap()
                .id
                .as_str(),
            "prefix"
        );
    }

    #[test]
    fn route_priority_selects_highest_priority() {
        let snapshot = snapshot(vec![
            route("low", "example.com", "/", 1, true),
            route("high", "example.com", "/", 10, true),
        ]);
        let selected = snapshot
            .select_route("example.com", "/")
            .expect("expected selected route");

        assert_eq!(selected.id.as_str(), "high");
    }

    #[test]
    fn snapshot_finds_service_by_id() {
        let snapshot = snapshot(vec![route("app", "example.com", "/", 1, true)]);

        let service = snapshot
            .find_service(&ServiceId::new("service"))
            .expect("service");

        assert_eq!(service.id.as_str(), "service");
    }

    #[test]
    fn snapshot_selects_primary_upstream_for_service() {
        let snapshot = snapshot(vec![route("app", "example.com", "/", 1, true)]);

        let upstream = snapshot
            .primary_upstream_for_service(&ServiceId::new("service"))
            .expect("upstream");

        assert_eq!(upstream.id.as_str(), "service-1");
        assert_eq!(upstream.url, "http://127.0.0.1:3000");
    }

    #[test]
    fn more_specific_path_prefix_wins_with_same_priority() {
        let snapshot = snapshot(vec![
            route("root", "example.com", "/", 10, true),
            route("api", "example.com", "/api", 10, true),
        ]);
        let selected = snapshot
            .select_route("example.com", "/api/users")
            .expect("expected selected route");

        assert_eq!(selected.id.as_str(), "api");
    }

    #[test]
    fn disabled_route_is_not_selected() {
        let snapshot = snapshot(vec![route("disabled", "example.com", "/", 10, false)]);
        let selected = snapshot.select_route("example.com", "/");

        assert!(selected.is_none());
    }

    #[test]
    fn config_snapshot_has_revision_id() {
        let snapshot = snapshot(vec![]);

        assert_eq!(snapshot.revision_id.as_str(), "rev-1");
    }

    #[test]
    fn log_mode_parse_succeeds() {
        assert_eq!("product".parse::<LogMode>().unwrap(), LogMode::Product);
        assert_eq!(
            "field-debug".parse::<LogMode>().unwrap(),
            LogMode::FieldDebug
        );
        assert_eq!("dev".parse::<LogMode>().unwrap(), LogMode::Dev);
    }

    #[test]
    fn unknown_log_mode_parse_fails() {
        let error = "verbose".parse::<LogMode>().unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigInvalidLogMode);
    }

    #[test]
    fn round_robin_policy_parses_from_stable_config_name() {
        assert_eq!(
            "round_robin".parse::<LoadBalancingPolicy>().unwrap(),
            LoadBalancingPolicy::RoundRobin
        );
        assert_eq!(LoadBalancingPolicy::RoundRobin.as_str(), "round_robin");
        assert_eq!(
            "random".parse::<LoadBalancingPolicy>().unwrap_err().code,
            ErrorCode::ConfigInvalidLoadBalancingPolicy
        );
    }

    #[test]
    fn default_http_health_policy_matches_phase_005_safety_limits() {
        let policy = HttpHealthCheckPolicy::default();

        assert_eq!(policy.path, "/health");
        assert_eq!(policy.interval_ms, 10_000);
        assert_eq!(policy.timeout_ms, 2_000);
        assert_eq!(policy.healthy_threshold, 2);
        assert_eq!(policy.unhealthy_threshold, 3);
        assert_eq!((policy.status_min, policy.status_max), (200, 399));
        assert_eq!(HealthCheckPolicy::default(), HealthCheckPolicy::Disabled);
    }

    #[test]
    fn service_policy_default_is_explicit_round_robin_without_health_checks() {
        let policy = ServicePolicy::default();

        assert_eq!(
            policy,
            ServicePolicy {
                load_balancing: LoadBalancingPolicy::RoundRobin,
                health_check: HealthCheckPolicy::Disabled,
                retry: RetryPolicy::default(),
                passive_health: PassiveHealthMode::Disabled,
            }
        );
    }

    fn service_with_upstreams(ids: &[&str]) -> Service {
        Service {
            id: ServiceId::new("app"),
            upstreams: ids
                .iter()
                .map(|id| Upstream {
                    id: UpstreamId::new(*id),
                    url: format!("http://127.0.0.1:{}", 3000 + id.len()),
                    administrative_state: UpstreamAdministrativeState::Active,
                    tls: crate::UpstreamTlsPolicy::Disabled,
                })
                .collect(),
            policy: ServicePolicy::default(),
        }
    }

    #[test]
    fn round_robin_selection_is_deterministic_and_wraps() {
        let service = service_with_upstreams(&["a", "b", "c"]);
        let availability = BTreeMap::new();

        for (sequence, expected) in [(0_u64, "a"), (1, "b"), (2, "c"), (3, "a")] {
            assert_eq!(
                select_upstream(&service, &availability, sequence),
                UpstreamSelection::Selected {
                    upstream_id: UpstreamId::new(expected),
                    next_sequence: sequence.wrapping_add(1),
                }
            );
        }

        assert_eq!(
            select_upstream(&service, &availability, u64::MAX),
            UpstreamSelection::Selected {
                upstream_id: UpstreamId::new("a"),
                next_sequence: 0,
            }
        );
    }

    #[test]
    fn round_robin_selection_skips_unhealthy_and_accepts_unknown() {
        let mut service = service_with_upstreams(&["a", "b", "c"]);
        service.policy.health_check = HealthCheckPolicy::Http(HttpHealthCheckPolicy::default());
        let availability = BTreeMap::from([
            (UpstreamId::new("a"), UpstreamAvailability::Unhealthy),
            (UpstreamId::new("b"), UpstreamAvailability::Healthy),
        ]);

        assert_eq!(
            select_upstream(&service, &availability, 0),
            UpstreamSelection::Selected {
                upstream_id: UpstreamId::new("b"),
                next_sequence: 1,
            }
        );
        assert_eq!(
            select_upstream(&service, &availability, 1),
            UpstreamSelection::Selected {
                upstream_id: UpstreamId::new("c"),
                next_sequence: 2,
            }
        );
    }

    #[test]
    fn round_robin_selection_skips_administratively_draining_upstream() {
        let mut service = service_with_upstreams(&["a", "b"]);
        service.upstreams[0].administrative_state = UpstreamAdministrativeState::Draining;

        assert_eq!(
            select_upstream(&service, &BTreeMap::new(), 0),
            UpstreamSelection::Selected {
                upstream_id: UpstreamId::new("b"),
                next_sequence: 1,
            }
        );
    }

    #[test]
    fn round_robin_selection_reports_no_eligible_upstream() {
        let empty = service_with_upstreams(&[]);
        assert_eq!(
            select_upstream(&empty, &BTreeMap::new(), 7),
            UpstreamSelection::NoEligibleUpstream
        );

        let mut service = service_with_upstreams(&["a", "b"]);
        service.policy.health_check = HealthCheckPolicy::Http(HttpHealthCheckPolicy::default());
        let availability = BTreeMap::from([
            (UpstreamId::new("a"), UpstreamAvailability::Unhealthy),
            (UpstreamId::new("b"), UpstreamAvailability::Unhealthy),
        ]);
        assert_eq!(
            select_upstream(&service, &availability, 7),
            UpstreamSelection::NoEligibleUpstream
        );
    }

    fn health_policy(healthy_threshold: u32, unhealthy_threshold: u32) -> HttpHealthCheckPolicy {
        HttpHealthCheckPolicy::new(
            "/health",
            10_000,
            2_000,
            healthy_threshold,
            unhealthy_threshold,
            200,
            399,
        )
        .unwrap()
    }

    #[test]
    fn health_state_initializes_from_policy_and_disabled_ignores_observations() {
        assert_eq!(
            UpstreamHealthState::for_policy(&HealthCheckPolicy::Disabled),
            UpstreamHealthState::Disabled
        );
        assert_eq!(
            UpstreamHealthState::for_policy(&HealthCheckPolicy::Http(health_policy(2, 3))),
            UpstreamHealthState::Unknown {
                consecutive_successes: 0,
                consecutive_failures: 0,
            }
        );

        let result = transition_upstream_health(
            UpstreamHealthState::Disabled,
            HealthObservation::Succeeded,
            &health_policy(1, 1),
        );
        assert_eq!(result.state, UpstreamHealthState::Disabled);
        assert_eq!(result.change, None);

        let failed = transition_upstream_health(
            UpstreamHealthState::Disabled,
            HealthObservation::Failed,
            &health_policy(1, 1),
        );
        assert_eq!(failed.state, UpstreamHealthState::Disabled);
        assert_eq!(failed.change, None);
    }

    #[test]
    fn consecutive_successes_make_unknown_healthy_and_recover_unhealthy() {
        let policy = health_policy(2, 3);
        let first = transition_upstream_health(
            UpstreamHealthState::Unknown {
                consecutive_successes: 0,
                consecutive_failures: 0,
            },
            HealthObservation::Succeeded,
            &policy,
        );
        assert_eq!(
            first,
            HealthTransitionResult {
                state: UpstreamHealthState::Unknown {
                    consecutive_successes: 1,
                    consecutive_failures: 0,
                },
                change: None,
            }
        );
        let healthy =
            transition_upstream_health(first.state, HealthObservation::Succeeded, &policy);
        assert_eq!(
            healthy.state,
            UpstreamHealthState::Healthy {
                consecutive_failures: 0
            }
        );
        assert_eq!(
            healthy.change,
            Some(HealthStateChange {
                from: UpstreamAvailability::Unknown,
                to: UpstreamAvailability::Healthy,
            })
        );

        let recovered = transition_upstream_health(
            UpstreamHealthState::Unhealthy {
                consecutive_successes: 1,
            },
            HealthObservation::Succeeded,
            &policy,
        );
        assert_eq!(
            recovered.state,
            UpstreamHealthState::Healthy {
                consecutive_failures: 0
            }
        );
        assert_eq!(
            recovered.change,
            Some(HealthStateChange {
                from: UpstreamAvailability::Unhealthy,
                to: UpstreamAvailability::Healthy,
            })
        );

        let remains_unhealthy = transition_upstream_health(
            UpstreamHealthState::Unhealthy {
                consecutive_successes: 1,
            },
            HealthObservation::Failed,
            &policy,
        );
        assert_eq!(
            remains_unhealthy.state,
            UpstreamHealthState::Unhealthy {
                consecutive_successes: 0,
            }
        );
        assert_eq!(remains_unhealthy.change, None);
    }

    #[test]
    fn consecutive_failures_make_unknown_and_healthy_unhealthy() {
        let policy = health_policy(2, 2);
        let first = transition_upstream_health(
            UpstreamHealthState::Healthy {
                consecutive_failures: 0,
            },
            HealthObservation::Failed,
            &policy,
        );
        assert_eq!(
            first.state,
            UpstreamHealthState::Healthy {
                consecutive_failures: 1,
            }
        );
        assert_eq!(first.change, None);

        let unhealthy = transition_upstream_health(first.state, HealthObservation::Failed, &policy);
        assert_eq!(
            unhealthy.state,
            UpstreamHealthState::Unhealthy {
                consecutive_successes: 0,
            }
        );
        assert_eq!(
            unhealthy.change,
            Some(HealthStateChange {
                from: UpstreamAvailability::Healthy,
                to: UpstreamAvailability::Unhealthy,
            })
        );

        let unknown_unhealthy = transition_upstream_health(
            UpstreamHealthState::Unknown {
                consecutive_successes: 0,
                consecutive_failures: 1,
            },
            HealthObservation::Failed,
            &policy,
        );
        assert_eq!(
            unknown_unhealthy.change,
            Some(HealthStateChange {
                from: UpstreamAvailability::Unknown,
                to: UpstreamAvailability::Unhealthy,
            })
        );
    }

    #[test]
    fn opposite_observation_resets_counter_and_threshold_one_transitions_immediately() {
        let policy = health_policy(2, 3);
        let reset_unknown = transition_upstream_health(
            UpstreamHealthState::Unknown {
                consecutive_successes: 1,
                consecutive_failures: 0,
            },
            HealthObservation::Failed,
            &policy,
        );
        assert_eq!(
            reset_unknown.state,
            UpstreamHealthState::Unknown {
                consecutive_successes: 0,
                consecutive_failures: 1,
            }
        );
        let reset_healthy = transition_upstream_health(
            UpstreamHealthState::Healthy {
                consecutive_failures: 2,
            },
            HealthObservation::Succeeded,
            &policy,
        );
        assert_eq!(
            reset_healthy.state,
            UpstreamHealthState::Healthy {
                consecutive_failures: 0,
            }
        );

        let immediate = health_policy(1, 1);
        assert_eq!(
            transition_upstream_health(
                UpstreamHealthState::Unknown {
                    consecutive_successes: 0,
                    consecutive_failures: 0,
                },
                HealthObservation::Succeeded,
                &immediate,
            )
            .state,
            UpstreamHealthState::Healthy {
                consecutive_failures: 0,
            }
        );
    }

    #[test]
    fn health_counter_saturates_without_overflow() {
        let policy = health_policy(10, 10);
        let result = transition_upstream_health(
            UpstreamHealthState::Unknown {
                consecutive_successes: u32::MAX,
                consecutive_failures: 0,
            },
            HealthObservation::Succeeded,
            &policy,
        );

        assert_eq!(
            result.state,
            UpstreamHealthState::Healthy {
                consecutive_failures: 0,
            }
        );
    }

    #[test]
    fn http_health_policy_accepts_documented_boundary_values() {
        let minimum = HttpHealthCheckPolicy::new("/", 1_000, 100, 1, 1, 100, 100).unwrap();
        assert_eq!(minimum.path, "/");

        let maximum = HttpHealthCheckPolicy::new(
            format!("/{}", "a".repeat(2_047)),
            86_400_000,
            30_000,
            10,
            10,
            599,
            599,
        )
        .unwrap();
        assert_eq!(maximum.path.len(), 2_048);
    }

    #[test]
    fn http_upstream_endpoint_normalizes_literal_addresses_ports_and_paths() {
        let default = HttpUpstreamEndpoint::parse("http://127.0.0.1").unwrap();
        assert_eq!(default.host(), "127.0.0.1");
        assert_eq!(default.port(), 80);
        assert_eq!(default.authority(), "127.0.0.1");
        assert_eq!(default.base_path(), "");
        assert_eq!(default.connect_address(), "127.0.0.1:80");
        assert_eq!(default.as_url(), "http://127.0.0.1");

        let explicit = HttpUpstreamEndpoint::parse("http://127.0.0.1:8080/api").unwrap();
        assert_eq!(explicit.authority(), "127.0.0.1:8080");
        assert_eq!(explicit.base_path(), "/api");
        assert_eq!(explicit.as_url(), "http://127.0.0.1:8080/api");
        assert_eq!(explicit.join_path("/users?active=1"), "/api/users?active=1");
    }

    #[test]
    fn http_upstream_endpoint_supports_bracketed_ipv6_literals() {
        let endpoint = HttpUpstreamEndpoint::parse("http://[::1]:8080/health").unwrap();

        assert_eq!(endpoint.host(), "::1");
        assert_eq!(endpoint.port(), 8080);
        assert_eq!(endpoint.authority(), "[::1]:8080");
        assert_eq!(endpoint.connect_address(), "[::1]:8080");
    }

    #[test]
    fn http_upstream_endpoint_rejects_ambiguous_or_unsupported_inputs() {
        for value in [
            "https://127.0.0.1",
            "http://",
            "http://localhost:80",
            "http://user@127.0.0.1",
            "http://127.0.0.1:0",
            "http://127.0.0.1:65536",
            "http://127.0.0.1/path?query=1",
            "http://127.0.0.1/path#fragment",
            "http://::1:80",
            "http://[:::1]:80",
        ] {
            assert_eq!(
                HttpUpstreamEndpoint::parse(value).unwrap_err().code,
                ErrorCode::ConfigInvalidUpstreamUrl,
                "value={value}"
            );
        }
    }

    #[test]
    fn http_upstream_endpoint_canonical_value_detects_equivalent_default_port() {
        assert_eq!(
            HttpUpstreamEndpoint::parse("http://127.0.0.1").unwrap(),
            HttpUpstreamEndpoint::parse("http://127.0.0.1:80").unwrap()
        );
    }

    #[test]
    fn phase009_trust_and_tls_identity_values_are_bounded_and_typed() {
        assert_eq!(
            TrustBundleRef::parse("private-root-v1").unwrap().as_str(),
            "private-root-v1"
        );
        assert_eq!(
            TlsServerName::parse("Backend.Private.Test.")
                .unwrap()
                .as_str(),
            "backend.private.test"
        );
        assert_eq!(
            UpstreamHttpHost::parse("backend.private.test:8443")
                .unwrap()
                .as_str(),
            "backend.private.test:8443"
        );

        for invalid in ["", ".", "..", "bad/ref", "bad ref", &"a".repeat(65)] {
            assert_eq!(
                TrustBundleRef::parse(invalid).unwrap_err().code,
                ErrorCode::ConfigTrustBundleRefInvalid
            );
        }
        for invalid in ["127.0.0.1", "bad name", "-bad.test", "bad_.test"] {
            assert_eq!(
                TlsServerName::parse(invalid).unwrap_err().code,
                ErrorCode::ConfigTlsServerNameInvalid
            );
        }
        for invalid in [
            "",
            "user@backend.test",
            "backend.test/path",
            "backend.test?x=1",
            "backend.test #fragment",
        ] {
            assert_eq!(
                UpstreamHttpHost::parse(invalid).unwrap_err().code,
                ErrorCode::ConfigUpstreamHttpHostInvalid
            );
        }
    }

    #[test]
    fn phase009_endpoint_supports_literal_ip_http_and_https_without_losing_identity() {
        let http = UpstreamEndpoint::parse("http://127.0.0.1/api").unwrap();
        assert_eq!(http.scheme(), UpstreamScheme::Http);
        assert_eq!(http.port(), 80);
        assert_eq!(http.as_url(), "http://127.0.0.1/api");

        let https = UpstreamEndpoint::parse("https://[::1]:9443/base").unwrap();
        assert_eq!(https.scheme(), UpstreamScheme::Https);
        assert_eq!(https.port(), 9443);
        assert_eq!(https.connect_address(), "[::1]:9443");
        assert_eq!(https.as_url(), "https://[::1]:9443/base");

        assert_eq!(
            HttpUpstreamEndpoint::parse("https://127.0.0.1")
                .unwrap_err()
                .code,
            ErrorCode::ConfigInvalidUpstreamUrl
        );
    }

    #[test]
    fn phase009_schema_normalizes_v1_and_requires_complete_v2_upstream_tls_policy() {
        let v1 =
            normalize_upstream_tls_policy(1, "http://127.0.0.1:8080", None, None, None).unwrap();
        assert!(matches!(v1.tls, UpstreamTlsPolicy::Disabled));
        assert_eq!(v1.endpoint.scheme(), UpstreamScheme::Http);

        let v2 = normalize_upstream_tls_policy(
            2,
            "https://127.0.0.1:9443",
            Some("backend.private.test"),
            Some("backend.private.test"),
            Some("private-server-root"),
        )
        .unwrap();
        assert_eq!(v2.endpoint.scheme(), UpstreamScheme::Https);
        assert!(matches!(
            v2.tls,
            UpstreamTlsPolicy::ServerAuthenticated { .. }
        ));

        for input in [
            (
                2,
                "https://127.0.0.1",
                None,
                Some("backend.test"),
                Some("root"),
            ),
            (
                2,
                "http://127.0.0.1",
                Some("backend.test"),
                Some("backend.test"),
                Some("root"),
            ),
        ] {
            assert_eq!(
                normalize_upstream_tls_policy(input.0, input.1, input.2, input.3, input.4)
                    .unwrap_err()
                    .code,
                ErrorCode::ConfigTlsPolicyInvalid
            );
        }
        assert_eq!(
            normalize_upstream_tls_policy(
                1,
                "https://127.0.0.1",
                Some("backend.test"),
                Some("backend.test"),
                Some("root"),
            )
            .unwrap_err()
            .code,
            ErrorCode::ConfigInvalidUpstreamUrl
        );
    }

    #[test]
    fn phase009_schema_normalizes_v1_client_auth_and_validates_v2_trust_reference() {
        assert_eq!(
            normalize_client_auth_policy(1, ListenerProtocol::Https, None, None).unwrap(),
            ClientAuthPolicy::Disabled
        );
        let required = normalize_client_auth_policy(
            2,
            ListenerProtocol::Https,
            Some("required"),
            Some("private-client-root"),
        )
        .unwrap();
        assert!(matches!(required, ClientAuthPolicy::Required { .. }));

        for input in [
            (2, ListenerProtocol::Http, Some("required"), Some("root")),
            (2, ListenerProtocol::Https, Some("required"), None),
            (2, ListenerProtocol::Https, Some("disabled"), Some("root")),
            (1, ListenerProtocol::Https, Some("required"), Some("root")),
        ] {
            assert_eq!(
                normalize_client_auth_policy(input.0, input.1, input.2, input.3)
                    .unwrap_err()
                    .code,
                ErrorCode::ConfigClientAuthPolicyInvalid
            );
        }

        let known = [TrustBundleRef::parse("private-client-root").unwrap()]
            .into_iter()
            .collect();
        assert!(validate_client_auth_trust(&required, &known).is_ok());
        assert_eq!(
            validate_client_auth_trust(&required, &BTreeSet::new())
                .unwrap_err()
                .code,
            ErrorCode::ConfigTrustBundleNotFound
        );
    }

    #[test]
    fn http_health_policy_rejects_invalid_paths() {
        for path in [
            "",
            "health",
            "/health?full=1",
            "/health#fragment",
            "/bad\npath",
        ] {
            let error =
                HttpHealthCheckPolicy::new(path, 10_000, 2_000, 2, 3, 200, 399).unwrap_err();
            assert_eq!(error.code, ErrorCode::ConfigHealthCheckInvalidPath);
        }
        let too_long = format!("/{}", "a".repeat(2_048));
        assert_eq!(
            HttpHealthCheckPolicy::new(too_long, 10_000, 2_000, 2, 3, 200, 399)
                .unwrap_err()
                .code,
            ErrorCode::ConfigHealthCheckInvalidPath
        );
    }

    #[test]
    fn http_health_policy_rejects_invalid_numeric_bounds() {
        let cases = [
            (
                999,
                100,
                2,
                3,
                200,
                399,
                ErrorCode::ConfigHealthCheckInvalidInterval,
            ),
            (
                86_400_001,
                100,
                2,
                3,
                200,
                399,
                ErrorCode::ConfigHealthCheckInvalidInterval,
            ),
            (
                10_000,
                99,
                2,
                3,
                200,
                399,
                ErrorCode::ConfigHealthCheckInvalidInterval,
            ),
            (
                10_000,
                10_000,
                2,
                3,
                200,
                399,
                ErrorCode::ConfigHealthCheckInvalidInterval,
            ),
            (
                40_000,
                30_001,
                2,
                3,
                200,
                399,
                ErrorCode::ConfigHealthCheckInvalidInterval,
            ),
            (
                10_000,
                2_000,
                0,
                3,
                200,
                399,
                ErrorCode::ConfigHealthCheckInvalidThreshold,
            ),
            (
                10_000,
                2_000,
                2,
                11,
                200,
                399,
                ErrorCode::ConfigHealthCheckInvalidThreshold,
            ),
            (
                10_000,
                2_000,
                2,
                3,
                99,
                399,
                ErrorCode::ConfigHealthCheckInvalidStatusRange,
            ),
            (
                10_000,
                2_000,
                2,
                3,
                400,
                399,
                ErrorCode::ConfigHealthCheckInvalidStatusRange,
            ),
            (
                10_000,
                2_000,
                2,
                3,
                200,
                600,
                ErrorCode::ConfigHealthCheckInvalidStatusRange,
            ),
        ];

        for (interval, timeout, healthy, unhealthy, status_min, status_max, expected) in cases {
            let error = HttpHealthCheckPolicy::new(
                "/health", interval, timeout, healthy, unhealthy, status_min, status_max,
            )
            .unwrap_err();
            assert_eq!(error.code, expected);
        }
    }

    #[test]
    fn bootstrap_config_accepts_typed_values() {
        let config = BootstrapConfig::new(
            ".sponzey",
            ".sponzey/config/current.toml",
            "127.0.0.1:9443",
            LogMode::Product,
        );

        assert_eq!(config.data_dir, ".sponzey");
        assert_eq!(config.log_mode, LogMode::Product);
    }

    #[test]
    fn retry_decision_allows_one_safe_get_or_head_attempt() {
        let policy = RetryPolicy::new(true, 1, 32_768).unwrap();
        for method in [ReplayMethod::Get, ReplayMethod::Head] {
            assert_eq!(
                evaluate_retry(RetryInput {
                    policy: &policy,
                    method,
                    body_bytes: 0,
                    request_bytes_written: 0,
                    response_started: false,
                    attempts_used: 0,
                    replay_reserved: true,
                    failure: RetryFailureKind::Connect,
                }),
                RetryDecision::Retry
            );
        }
    }

    #[test]
    fn retry_decision_returns_stable_denial_reasons() {
        let policy = RetryPolicy::new(true, 1, 32_768).unwrap();
        let base = RetryInput {
            policy: &policy,
            method: ReplayMethod::Get,
            body_bytes: 0,
            request_bytes_written: 0,
            response_started: false,
            attempts_used: 0,
            replay_reserved: true,
            failure: RetryFailureKind::Connect,
        };
        assert_eq!(
            evaluate_retry(RetryInput {
                method: ReplayMethod::Other,
                ..base
            }),
            RetryDecision::DoNotRetry(RetryDenialReason::MethodNotReplayable)
        );
        assert_eq!(
            evaluate_retry(RetryInput {
                body_bytes: 1,
                ..base
            }),
            RetryDecision::DoNotRetry(RetryDenialReason::BodyPresent)
        );
        assert_eq!(
            evaluate_retry(RetryInput {
                request_bytes_written: 1,
                ..base
            }),
            RetryDecision::DoNotRetry(RetryDenialReason::RequestWriteStarted)
        );
        assert_eq!(
            evaluate_retry(RetryInput {
                response_started: true,
                ..base
            }),
            RetryDecision::DoNotRetry(RetryDenialReason::ResponseStarted)
        );
        assert_eq!(
            evaluate_retry(RetryInput {
                attempts_used: 1,
                ..base
            }),
            RetryDecision::DoNotRetry(RetryDenialReason::RetryBudgetExhausted)
        );
        assert_eq!(
            evaluate_retry(RetryInput {
                replay_reserved: false,
                ..base
            }),
            RetryDecision::DoNotRetry(RetryDenialReason::ReplayBudgetExhausted)
        );
    }

    #[test]
    fn retry_and_passive_policy_validate_plan_bounds() {
        assert!(RetryPolicy::new(true, 1, 1_024).is_ok());
        assert!(RetryPolicy::new(true, 0, 1_024).is_err());
        assert!(RetryPolicy::new(false, 2, 1_024).is_err());
        assert!(RetryPolicy::new(false, 0, 1_023).is_err());
        assert!(PassiveHealthPolicy::new(1, 1_000).is_ok());
        assert!(PassiveHealthPolicy::new(0, 1_000).is_err());
        assert!(PassiveHealthPolicy::new(10, 86_400_000).is_ok());
        assert!(PassiveHealthPolicy::new(11, 86_400_001).is_err());
    }

    #[test]
    fn passive_health_ejects_resets_and_recovers_at_cooldown() {
        let policy = PassiveHealthPolicy::new(2, 1_000).unwrap();
        let once = transition_passive_health(
            PassiveHealthState::observing(),
            PassiveHealthEvent::Failed { now_ms: 10 },
            &policy,
        );
        assert_eq!(
            once,
            PassiveHealthState::Observing {
                consecutive_failures: 1
            }
        );
        let reset = transition_passive_health(once, PassiveHealthEvent::Succeeded, &policy);
        assert_eq!(reset, PassiveHealthState::observing());
        let once = transition_passive_health(
            reset,
            PassiveHealthEvent::Failed {
                now_ms: u64::MAX - 10,
            },
            &policy,
        );
        let ejected = transition_passive_health(
            once,
            PassiveHealthEvent::Failed {
                now_ms: u64::MAX - 10,
            },
            &policy,
        );
        assert_eq!(ejected, PassiveHealthState::Ejected { until_ms: u64::MAX });
        assert_eq!(
            transition_passive_health(
                ejected,
                PassiveHealthEvent::CooldownElapsed {
                    now_ms: u64::MAX - 1
                },
                &policy
            ),
            ejected
        );
        assert_eq!(
            transition_passive_health(
                ejected,
                PassiveHealthEvent::CooldownElapsed { now_ms: u64::MAX },
                &policy
            ),
            PassiveHealthState::observing()
        );
    }

    #[test]
    fn disabled_passive_health_ignores_observations() {
        let policy = PassiveHealthPolicy::new(3, 30_000).unwrap();
        assert_eq!(
            transition_passive_health(
                PassiveHealthState::Disabled,
                PassiveHealthEvent::Failed { now_ms: 10 },
                &policy
            ),
            PassiveHealthState::Disabled
        );
    }

    #[test]
    fn effective_eligibility_composes_membership_admin_active_and_passive_state() {
        let eligible = EffectiveUpstreamState {
            membership: UpstreamMembership::Present,
            administrative: UpstreamAdministrativeState::Active,
            active_health: UpstreamAvailability::Unknown,
            passive_health: PassiveHealthState::observing(),
        };
        assert_eq!(
            effective_eligibility(&eligible),
            EffectiveEligibility::Eligible
        );
        assert_eq!(
            effective_eligibility(&EffectiveUpstreamState {
                administrative: UpstreamAdministrativeState::Draining,
                ..eligible
            }),
            EffectiveEligibility::Excluded(UpstreamExclusionReason::Draining)
        );
        assert_eq!(
            effective_eligibility(&EffectiveUpstreamState {
                membership: UpstreamMembership::Removed,
                ..eligible
            }),
            EffectiveEligibility::Excluded(UpstreamExclusionReason::Removed)
        );
        assert_eq!(
            effective_eligibility(&EffectiveUpstreamState {
                active_health: UpstreamAvailability::Unhealthy,
                ..eligible
            }),
            EffectiveEligibility::Excluded(UpstreamExclusionReason::ActiveUnhealthy)
        );
        assert_eq!(
            effective_eligibility(&EffectiveUpstreamState {
                passive_health: PassiveHealthState::Ejected { until_ms: 100 },
                ..eligible
            }),
            EffectiveEligibility::Excluded(UpstreamExclusionReason::PassiveEjected)
        );
    }

    #[test]
    fn core_command_does_not_expose_adapter_details() {
        let command = CoreCommand::RefreshRouteTable;

        assert_eq!(command, CoreCommand::RefreshRouteTable);
    }

    #[test]
    fn command_ack_expresses_success_and_failure() {
        assert!(CommandAck::accepted().is_success());

        let rejected = CommandAck::rejected(AppError::new(
            ErrorCode::RuntimeCommandRejected,
            "queue is full",
        ));

        assert!(!rejected.is_success());
    }

    #[test]
    fn error_code_has_stable_string() {
        assert_eq!(
            ErrorCode::ConfigInvalidLogMode.as_str(),
            "CONFIG_INVALID_LOG_MODE"
        );
        assert_eq!(
            ErrorCode::AdminEndpointNotImplemented.as_str(),
            "ADMIN_ENDPOINT_NOT_IMPLEMENTED"
        );
        assert_eq!(
            ErrorCode::AdminRouteNotFound.as_str(),
            "ADMIN_ROUTE_NOT_FOUND"
        );
        assert_eq!(
            ErrorCode::AdminSetupRequired.as_str(),
            "ADMIN_SETUP_REQUIRED"
        );
        assert_eq!(
            ErrorCode::AdminSetupAlreadyComplete.as_str(),
            "ADMIN_SETUP_ALREADY_COMPLETE"
        );
        assert_eq!(
            ErrorCode::RuntimeUpstreamBadGateway.as_str(),
            "RUNTIME_UPSTREAM_BAD_GATEWAY"
        );
        assert_eq!(
            ErrorCode::RuntimeUpstreamTimeout.as_str(),
            "RUNTIME_UPSTREAM_TIMEOUT"
        );
    }

    #[test]
    fn error_code_is_separate_from_user_message() {
        let code = ErrorCode::ConfigInvalidLogMode;

        assert_ne!(code.as_str(), code.default_user_message());
    }

    #[test]
    fn data_directory_lock_state_tracks_acquire_and_release() {
        let mut machine = DataDirectoryLockMachine::default();

        machine
            .transition(DataDirectoryLockEvent::AcquireRequested)
            .unwrap();
        machine
            .transition(DataDirectoryLockEvent::AcquireSucceeded)
            .unwrap();
        machine
            .transition(DataDirectoryLockEvent::ReleaseRequested)
            .unwrap();
        machine
            .transition(DataDirectoryLockEvent::ReleaseSucceeded)
            .unwrap();

        assert_eq!(machine.state(), DataDirectoryLockState::Released);
    }

    #[test]
    fn data_directory_lock_state_rejects_invalid_and_post_terminal_events() {
        let mut machine = DataDirectoryLockMachine::default();
        let invalid = machine
            .transition(DataDirectoryLockEvent::AcquireSucceeded)
            .unwrap_err();
        assert_eq!(invalid.code, ErrorCode::DataDirectoryLockStateInvalid);
        assert_eq!(machine.state(), DataDirectoryLockState::Unlocked);

        machine
            .transition(DataDirectoryLockEvent::AcquireRequested)
            .unwrap();
        machine
            .transition(DataDirectoryLockEvent::AcquireFailed)
            .unwrap();
        let terminal = machine
            .transition(DataDirectoryLockEvent::AcquireRequested)
            .unwrap_err();
        assert_eq!(terminal.code, ErrorCode::DataDirectoryLockStateInvalid);
        assert_eq!(machine.state(), DataDirectoryLockState::Failed);
    }
}
