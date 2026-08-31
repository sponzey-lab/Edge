//! Supplied runtime metric snapshot JSON projection.

use edge_application::{MetricSeries, MetricSeriesValue, MetricSnapshot};

pub(crate) fn metrics_summary_json(snapshot: &MetricSnapshot) -> String {
    let mut counters = Vec::new();
    let mut gauges = Vec::new();
    let mut histograms = Vec::new();
    for series in &snapshot.series {
        let item = metric_series_json(series);
        match &series.value {
            MetricSeriesValue::Counter(_) if counters.len() < 500 => counters.push(item),
            MetricSeriesValue::Gauge(_) if gauges.len() < 500 => gauges.push(item),
            MetricSeriesValue::Histogram(_) if histograms.len() < 500 => histograms.push(item),
            _ => {}
        }
    }
    let dropped = snapshot
        .dropped
        .iter()
        .map(|(reason, count)| {
            let reason = match reason {
                edge_application::MetricDropReason::SeriesLimit => "series_limit",
                edge_application::MetricDropReason::ResponseBudget => "response_budget",
            };
            format!("\"{reason}\":{count}")
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"ready\":{},\"desired_generation\":{},\"applied_generation\":{},\"estimated_encoded_bytes\":{},\"dropped\":{{{dropped}}},\"counters\":[{}],\"gauges\":[{}],\"histograms\":[{}]}}",
        snapshot.ready,
        snapshot.desired_generation,
        snapshot.applied_generation,
        snapshot.estimated_encoded_bytes,
        counters.join(","),
        gauges.join(","),
        histograms.join(","),
    )
}

fn metric_series_json(series: &MetricSeries) -> String {
    let labels = series
        .key
        .labels
        .iter()
        .map(|(key, value)| {
            format!(
                "\"{}\":\"{}\"",
                crate::json_escape(key),
                crate::json_escape(value)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let value = match &series.value {
        MetricSeriesValue::Counter(value) => value.to_string(),
        MetricSeriesValue::Gauge(value) => value.to_string(),
        MetricSeriesValue::Histogram(value) => format!(
            "{{\"count\":{},\"sum_ms\":{},\"cumulative_buckets\":[{}]}}",
            value.count,
            value.sum_ms,
            value
                .cumulative_buckets
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ),
    };
    format!(
        "{{\"name\":\"{}\",\"labels\":{{{labels}}},\"value\":{value}}}",
        series.key.descriptor.definition().name
    )
}
