//! Proxy-host request JSON decoding and nested policy normalization.

use edge_domain::{
    AppError, HttpHealthCheckPolicy, PassiveHealthMode, RetryPolicy, UpstreamAdministrativeState,
};

use crate::admin_json_contract::json_string_field;
use crate::{
    malformed_json_field, required_json_bool, required_json_string, required_json_string_array,
    ProxyHostRequest, ProxyHostUpstreamRequest,
};

pub fn proxy_host_request_from_json(body: &str) -> Result<ProxyHostRequest, AppError> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|_| malformed_json_field("body"))?;
    let upstreams = proxy_host_upstreams_from_json(&value)?;
    let upstream_url = json_string_field(body, "upstream_url")
        .or_else(|| upstreams.first().map(|upstream| upstream.url.clone()))
        .ok_or_else(|| malformed_json_field("upstream_url or upstreams"))?;
    Ok(ProxyHostRequest {
        id: required_json_string(body, "id")?,
        name: required_json_string(body, "name")?,
        domains: required_json_string_array(body, "domains")?,
        path_prefix: required_json_string(body, "path_prefix")?,
        upstream_url,
        upstreams,
        health_check: proxy_host_health_check_from_json(&value)?,
        retry: proxy_host_retry_from_json(&value)?,
        passive_health: proxy_host_passive_health_from_json(&value)?,
        https_enabled: required_json_bool(body, "https_enabled")?,
        letsencrypt_enabled: required_json_bool(body, "letsencrypt_enabled")?,
        redirect_http_to_https: required_json_bool(body, "redirect_http_to_https")?,
        enabled: required_json_bool(body, "enabled")?,
    })
}

fn proxy_host_upstreams_from_json(
    value: &serde_json::Value,
) -> Result<Vec<ProxyHostUpstreamRequest>, AppError> {
    let Some(items) = value.get("upstreams") else {
        return Ok(Vec::new());
    };
    let items = items
        .as_array()
        .ok_or_else(|| malformed_json_field("upstreams"))?;
    items
        .iter()
        .map(|item| {
            let id = item
                .get("id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| malformed_json_field("upstreams.id"))?;
            let url = item
                .get("url")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| malformed_json_field("upstreams.url"))?;
            Ok(ProxyHostUpstreamRequest {
                id: id.to_string(),
                url: url.to_string(),
                administrative_state: match item
                    .get("administrative_state")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("active")
                {
                    "active" => UpstreamAdministrativeState::Active,
                    "draining" => UpstreamAdministrativeState::Draining,
                    _ => return Err(malformed_json_field("upstreams.administrative_state")),
                },
            })
        })
        .collect()
}

fn proxy_host_retry_from_json(value: &serde_json::Value) -> Result<RetryPolicy, AppError> {
    let Some(policy) = value.get("retry") else {
        return Ok(RetryPolicy::default());
    };
    Ok(RetryPolicy {
        enabled: policy
            .get("enabled")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| malformed_json_field("retry.enabled"))?,
        max_retries: policy
            .get("max_retries")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| malformed_json_field("retry.max_retries"))?
            .try_into()
            .map_err(|_| malformed_json_field("retry.max_retries"))?,
        max_replay_bytes: policy
            .get("max_replay_bytes")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| malformed_json_field("retry.max_replay_bytes"))?,
    })
}

fn proxy_host_passive_health_from_json(
    value: &serde_json::Value,
) -> Result<PassiveHealthMode, AppError> {
    let Some(policy) = value.get("passive_health") else {
        return Ok(PassiveHealthMode::Disabled);
    };
    let enabled = policy
        .get("enabled")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| malformed_json_field("passive_health.enabled"))?;
    if !enabled {
        return Ok(PassiveHealthMode::Disabled);
    }
    let failure_threshold = policy
        .get("failure_threshold")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| malformed_json_field("passive_health.failure_threshold"))?
        .try_into()
        .map_err(|_| malformed_json_field("passive_health.failure_threshold"))?;
    let ejection_ms = policy
        .get("ejection_ms")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| malformed_json_field("passive_health.ejection_ms"))?;
    edge_domain::PassiveHealthPolicy::new(failure_threshold, ejection_ms)
        .map(PassiveHealthMode::Enabled)
        .map_err(|error| AppError::new(error.code, error.message))
}

fn proxy_host_health_check_from_json(
    value: &serde_json::Value,
) -> Result<Option<HttpHealthCheckPolicy>, AppError> {
    let Some(health) = value.get("health_check") else {
        return Ok(None);
    };
    let enabled = health
        .get("enabled")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| malformed_json_field("health_check.enabled"))?;
    if !enabled {
        return Ok(None);
    }
    let string = |field: &str| {
        health
            .get(field)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| malformed_json_field(field))
    };
    let integer = |field: &str| {
        health
            .get(field)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| malformed_json_field(field))
    };
    HttpHealthCheckPolicy::new(
        string("path")?,
        integer("interval_ms")?,
        integer("timeout_ms")?,
        u32::try_from(integer("healthy_threshold")?)
            .map_err(|_| malformed_json_field("healthy_threshold"))?,
        u32::try_from(integer("unhealthy_threshold")?)
            .map_err(|_| malformed_json_field("unhealthy_threshold"))?,
        u16::try_from(integer("status_min")?).map_err(|_| malformed_json_field("status_min"))?,
        u16::try_from(integer("status_max")?).map_err(|_| malformed_json_field("status_max"))?,
    )
    .map(Some)
    .map_err(|error| AppError::new(error.code, error.message))
}
