//! Field-debug health-probe observation projection and bounded sampling.
//!
//! This module translates supplied probe outcomes into secret-free structured logs. It has no
//! scheduling, reconciliation, network, filesystem, or certificate-automation responsibilities.

use std::collections::BTreeMap;

use edge_domain::ConfigRevisionId;
use edge_ports::{HealthGeneration, HealthProbeFailure, StructuredLogEvent, UpstreamHealthKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HealthProbeDebugReason {
    Succeeded,
    ConnectTimeout,
    ConnectError,
    WriteError,
    MalformedResponse,
    StatusMismatch,
    ReadTimeout,
    ResponseTooLarge,
    TlsProfile,
    TlsHandshake,
    TlsHandshakeTimeout,
    Cancelled,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthProbeDebugEvent {
    revision_id: ConfigRevisionId,
    generation: HealthGeneration,
    key: UpstreamHealthKey,
    reason: HealthProbeDebugReason,
    status_code: Option<u16>,
    duration_ms: u64,
}

impl HealthProbeDebugEvent {
    pub fn succeeded(
        revision_id: ConfigRevisionId,
        generation: HealthGeneration,
        key: UpstreamHealthKey,
        status_code: u16,
        duration_ms: u64,
    ) -> Self {
        Self {
            revision_id,
            generation,
            key,
            reason: HealthProbeDebugReason::Succeeded,
            status_code: Some(status_code),
            duration_ms,
        }
    }

    pub fn failed(
        revision_id: ConfigRevisionId,
        generation: HealthGeneration,
        key: UpstreamHealthKey,
        failure: HealthProbeFailure,
        duration_ms: u64,
    ) -> Self {
        let (reason, status_code) = match failure {
            HealthProbeFailure::ConnectTimeout => (HealthProbeDebugReason::ConnectTimeout, None),
            HealthProbeFailure::ConnectError => (HealthProbeDebugReason::ConnectError, None),
            HealthProbeFailure::WriteError => (HealthProbeDebugReason::WriteError, None),
            HealthProbeFailure::MalformedResponse => {
                (HealthProbeDebugReason::MalformedResponse, None)
            }
            HealthProbeFailure::StatusMismatch { status_code } => {
                (HealthProbeDebugReason::StatusMismatch, Some(status_code))
            }
            HealthProbeFailure::ReadTimeout => (HealthProbeDebugReason::ReadTimeout, None),
            HealthProbeFailure::ResponseTooLarge => {
                (HealthProbeDebugReason::ResponseTooLarge, None)
            }
            HealthProbeFailure::TlsProfile => (HealthProbeDebugReason::TlsProfile, None),
            HealthProbeFailure::TlsHandshake => (HealthProbeDebugReason::TlsHandshake, None),
            HealthProbeFailure::TlsHandshakeTimeout => {
                (HealthProbeDebugReason::TlsHandshakeTimeout, None)
            }
            HealthProbeFailure::Cancelled => (HealthProbeDebugReason::Cancelled, None),
            HealthProbeFailure::Internal => (HealthProbeDebugReason::Internal, None),
        };
        Self {
            revision_id,
            generation,
            key,
            reason,
            status_code,
            duration_ms,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FieldDebugHealthSampler {
    capacity: usize,
    last_emitted_ms: BTreeMap<(UpstreamHealthKey, HealthProbeDebugReason), u64>,
}

impl FieldDebugHealthSampler {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            last_emitted_ms: BTreeMap::new(),
        }
    }

    pub fn should_emit(&mut self, event: &HealthProbeDebugEvent, now_ms: u64) -> bool {
        if self.capacity == 0 {
            return false;
        }
        let key = (event.key.clone(), event.reason);
        if self
            .last_emitted_ms
            .get(&key)
            .is_some_and(|previous| now_ms.saturating_sub(*previous) < 60_000)
        {
            return false;
        }
        if !self.last_emitted_ms.contains_key(&key) && self.last_emitted_ms.len() >= self.capacity {
            let oldest = self
                .last_emitted_ms
                .iter()
                .min_by_key(|(entry, timestamp)| (*timestamp, *entry))
                .map(|(entry, _)| entry.clone());
            if let Some(oldest) = oldest {
                self.last_emitted_ms.remove(&oldest);
            }
        }
        self.last_emitted_ms.insert(key, now_ms);
        true
    }

    pub fn len(&self) -> usize {
        self.last_emitted_ms.len()
    }

    pub fn is_empty(&self) -> bool {
        self.last_emitted_ms.is_empty()
    }
}

pub fn structured_health_probe_debug_log(event: &HealthProbeDebugEvent) -> StructuredLogEvent {
    let mut fields = vec![
        (
            "revision_id".to_string(),
            event.revision_id.as_str().to_string(),
        ),
        ("generation".to_string(), event.generation.0.to_string()),
        (
            "service_id".to_string(),
            event.key.service_id.as_str().to_string(),
        ),
        (
            "upstream_id".to_string(),
            event.key.upstream_id.as_str().to_string(),
        ),
        (
            "outcome".to_string(),
            health_probe_debug_reason_name(event.reason).to_string(),
        ),
    ];
    if let Some(status_code) = event.status_code {
        fields.push(("status_code".to_string(), status_code.to_string()));
    }
    fields.push(("duration_ms".to_string(), event.duration_ms.to_string()));
    StructuredLogEvent {
        component: "edge-application".to_string(),
        event: "upstream_health_probe_debug".to_string(),
        fields,
    }
}

fn health_probe_debug_reason_name(reason: HealthProbeDebugReason) -> &'static str {
    match reason {
        HealthProbeDebugReason::Succeeded => "succeeded",
        HealthProbeDebugReason::ConnectTimeout => "connect_timeout",
        HealthProbeDebugReason::ConnectError => "connect_error",
        HealthProbeDebugReason::WriteError => "write_error",
        HealthProbeDebugReason::MalformedResponse => "malformed_response",
        HealthProbeDebugReason::StatusMismatch => "status_mismatch",
        HealthProbeDebugReason::ReadTimeout => "read_timeout",
        HealthProbeDebugReason::ResponseTooLarge => "response_too_large",
        HealthProbeDebugReason::TlsProfile => "tls_profile",
        HealthProbeDebugReason::TlsHandshake => "tls_handshake",
        HealthProbeDebugReason::TlsHandshakeTimeout => "tls_handshake_timeout",
        HealthProbeDebugReason::Cancelled => "cancelled",
        HealthProbeDebugReason::Internal => "internal",
    }
}
