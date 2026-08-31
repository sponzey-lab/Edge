//! Admin status and health responses projected from supplied snapshots.

use std::collections::BTreeMap;

use edge_application::{config_activation_state, ConfigActivationState};
use edge_domain::{ConfigSnapshot, HealthAvailabilitySnapshot, UpstreamAvailability};
use edge_ports::{RuntimeDrainState, RuntimeResourceStatusSnapshot, RuntimeUpstreamStatusSnapshot};

use crate::API_VERSION_PREFIX;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusResponse {
    pub version_prefix: String,
    pub current_revision_id: String,
    pub desired_revision_id: String,
    pub active_revision_id: String,
    pub restart_required: bool,
    pub activation_state: String,
    pub desired_resource_policy: ResourcePolicyResponse,
    pub active_resource_policy: ResourcePolicyResponse,
    pub live_resource_status: Option<LiveResourceStatusResponse>,
    pub routes: usize,
    pub services: usize,
    pub certificates: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveResourceStatusResponse {
    pub revision_id: String,
    pub generation: u64,
    pub used_payload_bytes: usize,
    pub payload_limit_bytes: usize,
    pub active_connections: usize,
    pub pressure: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourcePolicyResponse {
    pub max_connections: usize,
    pub max_inflight_payload_bytes: usize,
}

pub fn status_response(snapshot: &ConfigSnapshot) -> StatusResponse {
    status_response_with_active(snapshot, snapshot)
}

pub fn status_response_with_active(
    desired: &ConfigSnapshot,
    active: &ConfigSnapshot,
) -> StatusResponse {
    status_response_with_active_and_resource(desired, active, None)
}

/// Represents desired and active snapshots separately so restart-required state stays observable.
pub fn status_response_with_active_and_resource(
    desired: &ConfigSnapshot,
    active: &ConfigSnapshot,
    live_resource_status: Option<RuntimeResourceStatusSnapshot>,
) -> StatusResponse {
    let activation_state = config_activation_state(active, desired);
    StatusResponse {
        version_prefix: API_VERSION_PREFIX.to_string(),
        current_revision_id: desired.revision_id.as_str().to_string(),
        desired_revision_id: desired.revision_id.as_str().to_string(),
        active_revision_id: active.revision_id.as_str().to_string(),
        restart_required: activation_state == ConfigActivationState::PendingRestart,
        activation_state: activation_state.as_str().to_string(),
        desired_resource_policy: ResourcePolicyResponse {
            max_connections: desired.runtime.max_connections,
            max_inflight_payload_bytes: desired.runtime.max_inflight_payload_bytes,
        },
        active_resource_policy: ResourcePolicyResponse {
            max_connections: active.runtime.max_connections,
            max_inflight_payload_bytes: active.runtime.max_inflight_payload_bytes,
        },
        live_resource_status: live_resource_status.map(|status| LiveResourceStatusResponse {
            revision_id: status.revision_id.as_str().to_string(),
            generation: status.generation,
            used_payload_bytes: status.used_payload_bytes,
            payload_limit_bytes: status.payload_limit_bytes,
            active_connections: status.active_connections,
            pressure: status.pressure.as_str().to_string(),
        }),
        routes: desired.routes.len(),
        services: desired.services.len(),
        certificates: desired
            .routes
            .iter()
            .filter(|route| route.certificate_ref.is_some())
            .count(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthResponse {
    pub status: String,
    pub current_revision_id: String,
    pub routes: usize,
    pub services: usize,
}

pub fn health_response(snapshot: &ConfigSnapshot) -> HealthResponse {
    HealthResponse {
        status: "ok".to_string(),
        current_revision_id: snapshot.revision_id.as_str().to_string(),
        routes: snapshot.routes.len(),
        services: snapshot.services.len(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamHealthStatusItem {
    pub service_id: String,
    pub upstream_id: String,
    pub status: UpstreamAvailability,
    pub drain_state: Option<RuntimeDrainState>,
    pub connection_count: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamHealthStatusResponse {
    pub revision_id: String,
    pub generation: u64,
    pub upstreams: Vec<UpstreamHealthStatusItem>,
}

pub fn upstream_health_status_response(
    snapshot: HealthAvailabilitySnapshot,
    runtime: Option<RuntimeUpstreamStatusSnapshot>,
) -> UpstreamHealthStatusResponse {
    let runtime = runtime.map(|snapshot| {
        snapshot
            .upstreams
            .into_iter()
            .map(|item| (item.key, (item.state, item.connection_count)))
            .collect::<BTreeMap<_, _>>()
    });
    UpstreamHealthStatusResponse {
        revision_id: snapshot.revision_id.as_str().to_string(),
        generation: snapshot.generation.0,
        upstreams: snapshot
            .entries
            .into_iter()
            .map(|(key, status)| {
                let drain = runtime.as_ref().and_then(|items| items.get(&key)).copied();
                UpstreamHealthStatusItem {
                    service_id: key.service_id.as_str().to_string(),
                    upstream_id: key.upstream_id.as_str().to_string(),
                    status,
                    drain_state: drain.map(|value| value.0),
                    connection_count: drain.map(|value| value.1),
                }
            })
            .collect(),
    }
}
