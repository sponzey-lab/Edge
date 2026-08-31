//! Pure Admin API v1 JSON response rendering and supplied-body field parsing.

use edge_application::{
    render_mvp_config_snapshot, AccessLogEvent, CertificateIssueOutcome, CertificateStatus,
    ConfigDiff, ManualCertificateImportOutcome, RecentErrorEvent,
};
use edge_domain::{
    ConfigSnapshot, HttpHealthCheckPolicy, PassiveHealthMode, RetryPolicy,
    UpstreamAdministrativeState, UpstreamAvailability, ValidationError,
};
use edge_ports::{RuntimeDrainState, TrustBundleMetadata};

use crate::{
    ApplyResponse, HealthResponse, ProxyHostResponse, ProxyHostUpstreamRequest, Session,
    StatusResponse, UpstreamHealthStatusResponse,
};

pub(crate) fn trust_bundle_metadata_json(metadata: &TrustBundleMetadata) -> String {
    format!(
        "{{\"trust_bundle_ref\":\"{}\",\"certificate_count\":{},\"imported_at_epoch_seconds\":{}}}",
        json_escape(metadata.trust_bundle_ref.as_str()),
        metadata.certificate_count,
        metadata.imported_at_epoch_seconds
    )
}

pub(crate) fn trust_bundle_list_json(items: &[TrustBundleMetadata]) -> String {
    format!(
        "{{\"trust_bundles\":[{}]}}",
        items
            .iter()
            .map(trust_bundle_metadata_json)
            .collect::<Vec<_>>()
            .join(",")
    )
}

pub(crate) fn status_response_json(response: &StatusResponse) -> String {
    let live_resource_status = response.live_resource_status.as_ref().map_or_else(
        || "null".to_string(),
        |status| {
            format!(
                "{{\"revision_id\":\"{}\",\"generation\":{},\"used_payload_bytes\":{},\"payload_limit_bytes\":{},\"active_connections\":{},\"pressure\":\"{}\"}}",
                json_escape(&status.revision_id),
                status.generation,
                status.used_payload_bytes,
                status.payload_limit_bytes,
                status.active_connections,
                json_escape(&status.pressure),
            )
        },
    );
    format!(
        "{{\"version_prefix\":\"{}\",\"current_revision_id\":\"{}\",\"desired_revision_id\":\"{}\",\"active_revision_id\":\"{}\",\"restart_required\":{},\"activation_state\":\"{}\",\"desired_resource_policy\":{{\"max_connections\":{},\"max_inflight_payload_bytes\":{}}},\"active_resource_policy\":{{\"max_connections\":{},\"max_inflight_payload_bytes\":{}}},\"live_resource_status\":{},\"routes\":{},\"services\":{},\"certificates\":{}}}",
        json_escape(&response.version_prefix),
        json_escape(&response.current_revision_id),
        json_escape(&response.desired_revision_id),
        json_escape(&response.active_revision_id),
        response.restart_required,
        json_escape(&response.activation_state),
        response.desired_resource_policy.max_connections,
        response.desired_resource_policy.max_inflight_payload_bytes,
        response.active_resource_policy.max_connections,
        response.active_resource_policy.max_inflight_payload_bytes,
        live_resource_status,
        response.routes,
        response.services,
        response.certificates
    )
}

pub(crate) fn health_response_json(response: &HealthResponse) -> String {
    format!(
        "{{\"status\":\"{}\",\"current_revision_id\":\"{}\",\"routes\":{},\"services\":{}}}",
        json_escape(&response.status),
        json_escape(&response.current_revision_id),
        response.routes,
        response.services
    )
}

pub(crate) fn upstream_health_status_response_json(
    response: &UpstreamHealthStatusResponse,
) -> String {
    let upstreams = response
        .upstreams
        .iter()
        .map(|item| {
            format!(
                "{{\"service_id\":\"{}\",\"upstream_id\":\"{}\",\"status\":\"{}\",\"drain_state\":{},\"connection_count\":{}}}",
                json_escape(&item.service_id),
                json_escape(&item.upstream_id),
                upstream_availability_name(item.status),
                item.drain_state.map(runtime_drain_state_name).map(|value| format!("\"{value}\"")).unwrap_or_else(|| "null".to_string()),
                item.connection_count.map(|value| value.to_string()).unwrap_or_else(|| "null".to_string())
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"revision_id\":\"{}\",\"generation\":{},\"upstreams\":[{}]}}",
        json_escape(&response.revision_id),
        response.generation,
        upstreams
    )
}

pub(crate) fn runtime_drain_state_name(state: RuntimeDrainState) -> &'static str {
    match state {
        RuntimeDrainState::Active => "active",
        RuntimeDrainState::Draining => "draining",
        RuntimeDrainState::Drained => "drained",
        RuntimeDrainState::Removed => "removed",
    }
}

pub(crate) fn upstream_availability_name(status: UpstreamAvailability) -> &'static str {
    match status {
        UpstreamAvailability::Disabled => "disabled",

        UpstreamAvailability::Unknown => "unknown",
        UpstreamAvailability::Healthy => "healthy",
        UpstreamAvailability::Unhealthy => "unhealthy",
    }
}

pub(crate) fn login_response_json(session: &Session) -> String {
    format!(
        "{{\"csrf_token\":\"{}\"}}",
        json_escape(&session.csrf_token)
    )
}

pub(crate) fn apply_response_json(response: &ApplyResponse) -> String {
    format!(
        "{{\"revision_id\":\"{}\",\"commands_sent\":{},\"restart_required\":{}}}",
        json_escape(&response.revision_id),
        response.commands_sent,
        response.restart_required
    )
}

pub(crate) fn proxy_host_list_response_json(proxy_hosts: &[ProxyHostResponse]) -> String {
    let items = proxy_hosts
        .iter()
        .map(proxy_host_response_json)
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"proxy_hosts\":[{items}]}}")
}

pub(crate) fn proxy_host_response_json(proxy_host: &ProxyHostResponse) -> String {
    format!(
        "{{\"id\":\"{}\",\"name\":\"{}\",\"domains\":{},\"path_prefix\":\"{}\",\"upstream_url\":\"{}\",\"upstreams\":{},\"health_check\":{},\"retry\":{},\"passive_health\":{},\"https_enabled\":{},\"letsencrypt_enabled\":{},\"redirect_http_to_https\":{},\"enabled\":{}}}",
        json_escape(&proxy_host.id),
        json_escape(&proxy_host.name),
        json_string_array_json(&proxy_host.domains),
        json_escape(&proxy_host.path_prefix),
        json_escape(&proxy_host.upstream_url),
        proxy_host_upstreams_json(&proxy_host.upstreams),
        proxy_host_health_check_json(proxy_host.health_check.as_ref()),
        proxy_host_retry_json(proxy_host.retry),
        proxy_host_passive_health_json(proxy_host.passive_health),
        proxy_host.https_enabled,
        proxy_host.letsencrypt_enabled,
        proxy_host.redirect_http_to_https,
        proxy_host.enabled
    )
}

pub(crate) fn proxy_host_upstreams_json(upstreams: &[ProxyHostUpstreamRequest]) -> String {
    let items = upstreams
        .iter()
        .map(|upstream| {
            format!(
                "{{\"id\":\"{}\",\"url\":\"{}\",\"administrative_state\":\"{}\"}}",
                json_escape(&upstream.id),
                json_escape(&upstream.url),
                match upstream.administrative_state {
                    UpstreamAdministrativeState::Active => "active",
                    UpstreamAdministrativeState::Draining => "draining",
                }
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("[{items}]")
}

pub(crate) fn proxy_host_retry_json(policy: RetryPolicy) -> String {
    format!(
        "{{\"enabled\":{},\"max_retries\":{},\"max_replay_bytes\":{}}}",
        policy.enabled, policy.max_retries, policy.max_replay_bytes
    )
}

pub(crate) fn proxy_host_passive_health_json(mode: PassiveHealthMode) -> String {
    match mode {
        PassiveHealthMode::Disabled => "{\"enabled\":false}".to_string(),
        PassiveHealthMode::Enabled(policy) => format!(
            "{{\"enabled\":true,\"failure_threshold\":{},\"ejection_ms\":{}}}",
            policy.failure_threshold, policy.ejection_ms
        ),
    }
}

pub(crate) fn proxy_host_health_check_json(health: Option<&HttpHealthCheckPolicy>) -> String {
    match health {
        Some(health) => format!(
            "{{\"enabled\":true,\"path\":\"{}\",\"interval_ms\":{},\"timeout_ms\":{},\"healthy_threshold\":{},\"unhealthy_threshold\":{},\"status_min\":{},\"status_max\":{}}}",
            json_escape(&health.path),
            health.interval_ms,
            health.timeout_ms,
            health.healthy_threshold,
            health.unhealthy_threshold,
            health.status_min,
            health.status_max
        ),
        None => "{\"enabled\":false}".to_string(),
    }
}

pub(crate) fn json_string_array_json(values: &[String]) -> String {
    let items = values
        .iter()
        .map(|value| format!("\"{}\"", json_escape(value)))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{items}]")
}

pub(crate) fn certificate_list_response_json(certificates: &[CertificateStatus]) -> String {
    let items = certificates
        .iter()
        .map(certificate_status_json)
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"certificates\":[{items}]}}")
}

pub(crate) fn certificate_status_json(certificate: &CertificateStatus) -> String {
    format!(
        "{{\"certificate_ref\":\"{}\",\"domains\":{},\"source\":\"{}\",\"expired\":{},\"expiring_soon\":{},\"not_after_epoch_seconds\":{},\"private_key\":\"{}\"}}",
        json_escape(certificate.certificate_ref.as_str()),
        json_string_array_json(&certificate.domains),
        json_escape(&certificate.source),
        certificate.expired,
        certificate.expiring_soon,
        certificate.not_after_epoch_seconds,
        json_escape(certificate.private_key_masked)
    )
}

pub(crate) fn certificate_issue_outcome_json(
    outcome: &CertificateIssueOutcome,
    request_id: &str,
) -> String {
    format!(
        "{{\"request_id\":\"{}\",\"certificate_ref\":\"{}\",\"domains\":{},\"source\":\"{}\",\"not_after_epoch_seconds\":{},\"commands_sent\":{}}}",
        json_escape(request_id),
        json_escape(outcome.certificate_ref.as_str()),
        json_string_array_json(&outcome.domains),
        json_escape(&outcome.source),
        outcome.not_after_epoch_seconds,
        outcome.commands_sent
    )
}

pub(crate) fn certificate_import_outcome_json(
    outcome: &ManualCertificateImportOutcome,
    request_id: &str,
) -> String {
    format!(
        "{{\"request_id\":\"{}\",\"certificate_ref\":\"{}\",\"domains\":{},\"source\":\"{}\",\"not_after_epoch_seconds\":{},\"private_key\":\"{}\",\"state\":\"installed\",\"commands_sent\":{}}}",
        json_escape(request_id),
        json_escape(outcome.status.certificate_ref.as_str()),
        json_string_array_json(&outcome.status.domains),
        json_escape(&outcome.status.source),
        outcome.status.not_after_epoch_seconds,
        outcome.status.private_key_masked,
        outcome.commands_sent
    )
}

pub(crate) fn access_logs_response_json(events: &[AccessLogEvent]) -> String {
    let items = events
        .iter()
        .map(access_log_event_json)
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"access_logs\":[{items}]}}")
}

pub(crate) fn access_log_event_json(event: &AccessLogEvent) -> String {
    format!(
        "{{\"request_id\":\"{}\",\"revision_id\":\"{}\",\"route_id\":{},\"upstream_id\":{},\"status_code\":{},\"duration_ms\":{}}}",
        json_escape(&event.request_id),
        json_escape(&event.revision_id),
        json_optional_string_json(event.route_id.as_deref()),
        json_optional_string_json(event.upstream_id.as_deref()),
        event.status_code,
        event.duration_ms
    )
}

pub(crate) fn error_logs_response_json(events: &[RecentErrorEvent]) -> String {
    let items = events
        .iter()
        .map(error_log_event_json)
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"error_logs\":[{items}]}}")
}

pub(crate) fn error_log_event_json(event: &RecentErrorEvent) -> String {
    format!(
        "{{\"request_id\":{},\"error_code\":\"{}\",\"message\":\"{}\"}}",
        json_optional_string_json(event.request_id.as_deref()),
        json_escape(&event.error_code),
        json_escape(&event.message)
    )
}

pub(crate) fn json_optional_string_json(value: Option<&str>) -> String {
    match value {
        Some(value) => format!("\"{}\"", json_escape(value)),
        None => "null".to_string(),
    }
}

pub(crate) fn config_response_json(snapshot: &ConfigSnapshot) -> String {
    format!(
        "{{\"revision_id\":\"{}\",\"config\":\"{}\"}}",
        json_escape(snapshot.revision_id.as_str()),
        json_escape(&render_mvp_config_snapshot(snapshot))
    )
}

pub(crate) fn config_validation_response_json(errors: &[ValidationError]) -> String {
    let items = errors
        .iter()
        .map(validation_error_json)
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"valid\":{},\"errors\":[{}]}}", errors.is_empty(), items)
}

pub(crate) fn config_diff_response_json(
    diff: Option<&ConfigDiff>,
    errors: &[ValidationError],
) -> String {
    let empty = ConfigDiff {
        added_routes: Vec::new(),
        removed_routes: Vec::new(),
        changed_upstreams: Vec::new(),
    };
    let diff = diff.unwrap_or(&empty);
    let errors_json = errors
        .iter()
        .map(validation_error_json)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"valid\":{},\"errors\":[{}],\"diff\":{{\"added_routes\":{},\"removed_routes\":{},\"changed_upstreams\":{}}}}}",
        errors.is_empty(),
        errors_json,
        json_string_array_json(&diff.added_routes),
        json_string_array_json(&diff.removed_routes),
        json_string_array_json(&diff.changed_upstreams)
    )
}

pub(crate) fn validation_error_json(error: &ValidationError) -> String {
    format!(
        "{{\"code\":\"{}\",\"message\":\"{}\",\"hint\":\"{}\"}}",
        json_escape(error.code.as_str()),
        json_escape(&error.message),
        json_escape(error.code.default_user_message())
    )
}

pub(crate) fn json_escape(value: &str) -> String {
    let mut escaped = String::new();
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(character),
        }
    }
    escaped
}

pub(crate) fn json_string_field(body: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\"");
    let after_name = body.split_once(&needle)?.1;
    let after_colon = after_name.split_once(':')?.1.trim_start();
    let after_open = after_colon.strip_prefix('"')?;
    let mut output = String::new();
    let mut escaped = false;
    for character in after_open.chars() {
        if escaped {
            push_json_escaped_character(&mut output, character)?;
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            return Some(output);
        } else {
            output.push(character);
        }
    }
    None
}

pub(crate) fn json_bool_field(body: &str, field: &str) -> Option<bool> {
    let needle = format!("\"{field}\"");
    let after_name = body.split_once(&needle)?.1;
    let after_colon = after_name.split_once(':')?.1.trim_start();
    if after_colon.starts_with("true") {
        Some(true)
    } else if after_colon.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

pub(crate) fn json_string_array_field(body: &str, field: &str) -> Option<Vec<String>> {
    let needle = format!("\"{field}\"");
    let after_name = body.split_once(&needle)?.1;
    let mut input = after_name.split_once(':')?.1.trim_start();
    input = input.strip_prefix('[')?.trim_start();

    let mut values = Vec::new();
    loop {
        input = input.trim_start();
        if input.starts_with(']') {
            return Some(values);
        }
        let parsed = parse_json_string_prefix(input)?;
        values.push(parsed.0);
        input = parsed.1.trim_start();
        if let Some(remaining) = input.strip_prefix(',') {
            input = remaining;
        } else if input.starts_with(']') {
            return Some(values);
        } else {
            return None;
        }
    }
}

pub(crate) fn parse_json_string_prefix(input: &str) -> Option<(String, &str)> {
    let after_open = input.strip_prefix('"')?;
    let mut output = String::new();
    let mut escaped = false;
    for (index, character) in after_open.char_indices() {
        if escaped {
            push_json_escaped_character(&mut output, character)?;
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            return Some((output, &after_open[index + character.len_utf8()..]));
        } else {
            output.push(character);
        }
    }
    None
}

pub(crate) fn push_json_escaped_character(output: &mut String, character: char) -> Option<()> {
    output.push(match character {
        '"' => '"',
        '\\' => '\\',
        '/' => '/',
        'n' => '\n',
        'r' => '\r',
        't' => '\t',
        _ => return None,
    });
    Some(())
}
