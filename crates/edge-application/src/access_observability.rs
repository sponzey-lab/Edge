//! Safe access-event projection to structured logs and bounded-cardinality metrics.

use edge_domain::{AppError, LogMode};
use edge_ports::{LogSink, MetricDescriptor, MetricEvent, MetricsSink, StructuredLogEvent};

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

/// Produces a log-mode-specific event without request body, headers, or Product-mode path data.
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

/// Maps a request to bounded route/status-class metric labels, never a raw path label.
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
