//! Runtime-state and failure projections to bounded-label metric events.

use edge_domain::ErrorCode;
use edge_ports::{
    MetricDescriptor, MetricEvent, ResourceMetricKind, ResourceRejectionReason, StoredCertificate,
};

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

/// Emits only certificate reference and source, never a domain or private-key label.
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
