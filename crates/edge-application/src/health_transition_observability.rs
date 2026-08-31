//! Health state-transition observation projection.
//!
//! This module maps supplied state changes to bounded metrics and secret-free structured logs.
//! It has no probe scheduling, reconciliation, runtime I/O, or certificate-automation role.

use edge_domain::{AppError, ConfigRevisionId, HealthStateChange, UpstreamAvailability};
use edge_ports::{
    HealthGeneration, LogSink, MetricDescriptor, MetricEvent, MetricsSink, StructuredLogEvent,
    UpstreamHealthKey,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthTransitionEvent {
    revision_id: ConfigRevisionId,
    generation: HealthGeneration,
    key: UpstreamHealthKey,
    change: HealthStateChange,
}

impl HealthTransitionEvent {
    pub fn new(
        revision_id: ConfigRevisionId,
        generation: HealthGeneration,
        key: UpstreamHealthKey,
        change: HealthStateChange,
    ) -> Option<Self> {
        (change.from != change.to).then_some(Self {
            revision_id,
            generation,
            key,
            change,
        })
    }
}

pub fn structured_health_transition_log(event: &HealthTransitionEvent) -> StructuredLogEvent {
    StructuredLogEvent {
        component: "edge-application".to_string(),
        event: "upstream_health_changed".to_string(),
        fields: vec![
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
                "previous_state".to_string(),
                availability_name(event.change.from).to_string(),
            ),
            (
                "next_state".to_string(),
                availability_name(event.change.to).to_string(),
            ),
        ],
    }
}

pub fn health_transition_metric(event: &HealthTransitionEvent) -> MetricEvent {
    MetricEvent::counter_add(
        MetricDescriptor::UpstreamHealthTransitionsTotal,
        1,
        vec![
            (
                "service_id".to_string(),
                event.key.service_id.as_str().to_string(),
            ),
            (
                "upstream_id".to_string(),
                event.key.upstream_id.as_str().to_string(),
            ),
            (
                "from".to_string(),
                availability_name(event.change.from).to_string(),
            ),
            (
                "to".to_string(),
                availability_name(event.change.to).to_string(),
            ),
        ],
    )
    .expect("health transition metric contract")
}

pub fn record_health_transition_log<L>(
    sink: &mut L,
    event: &HealthTransitionEvent,
) -> Result<(), AppError>
where
    L: LogSink + ?Sized,
{
    sink.record_log(structured_health_transition_log(event))
}

pub fn record_health_transition_metric<M>(
    sink: &mut M,
    event: &HealthTransitionEvent,
) -> Result<(), AppError>
where
    M: MetricsSink + ?Sized,
{
    sink.record_metric(health_transition_metric(event))
}

pub(crate) fn availability_name(availability: UpstreamAvailability) -> &'static str {
    match availability {
        UpstreamAvailability::Disabled => "disabled",
        UpstreamAvailability::Unknown => "unknown",
        UpstreamAvailability::Healthy => "healthy",
        UpstreamAvailability::Unhealthy => "unhealthy",
    }
}
