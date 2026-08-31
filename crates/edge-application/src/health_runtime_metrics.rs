//! Bounded runtime health metric projection.
//!
//! It maps supplied health state/results to fixed metric descriptors and labels without
//! scheduling probes, mutating health state, performing I/O, or enabling certificate automation.

use crate::health::{HealthDispatchDropReason, ProbeResultIgnored};
use edge_domain::{ServiceId, UpstreamAvailability};
use edge_ports::{MetricDescriptor, MetricEvent, UpstreamHealthKey};

pub fn upstream_availability_metric(
    key: &UpstreamHealthKey,
    availability: UpstreamAvailability,
) -> MetricEvent {
    let available = match availability {
        UpstreamAvailability::Healthy | UpstreamAvailability::Unknown => 1,
        UpstreamAvailability::Disabled | UpstreamAvailability::Unhealthy => 0,
    };
    MetricEvent::gauge_set(
        MetricDescriptor::UpstreamAvailable,
        available,
        health_key_labels(key),
    )
    .expect("upstream availability metric contract")
}

pub fn upstream_selection_metric(key: &UpstreamHealthKey) -> MetricEvent {
    MetricEvent::counter_add(
        MetricDescriptor::UpstreamSelectionsTotal,
        1,
        health_key_labels(key),
    )
    .expect("selection metric contract")
}

pub fn no_eligible_upstream_metric(service_id: &ServiceId) -> MetricEvent {
    MetricEvent::counter_add(
        MetricDescriptor::UpstreamNoEligibleTotal,
        1,
        vec![("service_id".into(), service_id.as_str().into())],
    )
    .expect("no eligible metric contract")
}

pub fn ignored_health_result_metric(
    key: &UpstreamHealthKey,
    reason: ProbeResultIgnored,
) -> MetricEvent {
    let _ = key;
    MetricEvent::counter_add(
        MetricDescriptor::MetricEventsDroppedTotal,
        1,
        vec![("reason".into(), ignored_result_name(reason).into())],
    )
    .expect("ignored metric contract")
}

pub fn health_dispatch_drop_metric(reason: HealthDispatchDropReason) -> MetricEvent {
    MetricEvent::counter_add(
        MetricDescriptor::MetricEventsDroppedTotal,
        1,
        vec![("reason".into(), dispatch_drop_name(reason).into())],
    )
    .expect("dispatch metric contract")
}

pub(crate) fn health_key_labels(key: &UpstreamHealthKey) -> Vec<(String, String)> {
    vec![
        (
            "service_id".to_string(),
            key.service_id.as_str().to_string(),
        ),
        (
            "upstream_id".to_string(),
            key.upstream_id.as_str().to_string(),
        ),
    ]
}

fn ignored_result_name(reason: ProbeResultIgnored) -> &'static str {
    match reason {
        ProbeResultIgnored::StaleGeneration => "stale_generation",
        ProbeResultIgnored::UnknownUpstream => "unknown_upstream",
        ProbeResultIgnored::NotInFlight => "not_in_flight",
        ProbeResultIgnored::RequestMismatch => "request_mismatch",
        ProbeResultIgnored::Stopped => "stopped",
    }
}

fn dispatch_drop_name(reason: HealthDispatchDropReason) -> &'static str {
    match reason {
        HealthDispatchDropReason::QueueFull => "queue_full",
        HealthDispatchDropReason::WorkerStopped => "worker_stopped",
    }
}
