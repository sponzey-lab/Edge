//! Pure policy for classifying configuration changes and generating apply commands.

use std::collections::BTreeMap;

use edge_domain::{ConfigSnapshot, CoreCommand, Route};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigDiff {
    pub added_routes: Vec<String>,
    pub removed_routes: Vec<String>,
    pub changed_upstreams: Vec<String>,
}

/// Compares two immutable snapshots without runtime or persistence I/O.
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

/// Identifies whether the desired snapshot can be atomically activated without restart.
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

/// Creates only Core commands when no restart-only change is present.
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
        commands: vec![CoreCommand::ApplyConfigSnapshot { snapshot }],
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
