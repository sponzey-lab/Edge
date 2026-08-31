//! Bounded audit query and read-model conversion for the Admin API.

use std::collections::BTreeMap;

use edge_domain::{
    AppError, AuditAction, AuditAdmissionState, AuditCursor, AuditOutcome, AuditPage, AuditQuery,
    AuditTargetKind, ErrorCode,
};

pub(crate) fn parse_audit_query(path: &str) -> Result<AuditQuery, AppError> {
    let (_, raw_query) = path.split_once('?').unwrap_or((path, ""));
    let mut values = BTreeMap::new();
    if !raw_query.is_empty() {
        for pair in raw_query.split('&') {
            let (key, value) = pair.split_once('=').ok_or_else(audit_query_invalid)?;
            if key.is_empty()
                || value.is_empty()
                || value.contains('%')
                || !matches!(
                    key,
                    "action" | "outcome" | "target_kind" | "from" | "to" | "limit" | "cursor"
                )
                || values.insert(key, value).is_some()
            {
                return Err(audit_query_invalid());
            }
        }
    }
    let action = values
        .get("action")
        .map(|value| parse_audit_action(value))
        .transpose()?;
    let outcome = values
        .get("outcome")
        .map(|value| parse_audit_outcome(value))
        .transpose()?;
    let target_kind = values
        .get("target_kind")
        .map(|value| parse_audit_target_kind(value))
        .transpose()?;
    let from = parse_optional_u64(&values, "from")?;
    let to = parse_optional_u64(&values, "to")?;
    let limit = values
        .get("limit")
        .map(|value| value.parse::<u16>().map_err(|_| audit_query_invalid()))
        .transpose()?
        .unwrap_or(edge_domain::AUDIT_QUERY_DEFAULT_LIMIT);
    let mut query = AuditQuery::new(action, outcome, target_kind, from, to, limit)
        .map_err(|_| audit_query_invalid())?;
    if let Some(cursor) = values.get("cursor") {
        query = query.with_cursor(decode_audit_cursor(cursor)?);
    }
    Ok(query)
}

fn parse_optional_u64(values: &BTreeMap<&str, &str>, key: &str) -> Result<Option<u64>, AppError> {
    values
        .get(key)
        .map(|value| value.parse::<u64>().map_err(|_| audit_query_invalid()))
        .transpose()
}

fn parse_audit_action(value: &str) -> Result<AuditAction, AppError> {
    match value {
        "config.apply" => Ok(AuditAction::ConfigApply),
        "config.rollback" => Ok(AuditAction::ConfigRollback),
        "proxy_host.create" => Ok(AuditAction::ProxyHostCreate),
        "proxy_host.update" => Ok(AuditAction::ProxyHostUpdate),
        "proxy_host.delete" => Ok(AuditAction::ProxyHostDelete),
        "certificate.issue" => Ok(AuditAction::CertificateIssue),
        "certificate.renew" => Ok(AuditAction::CertificateRenew),
        "certificate.import" => Ok(AuditAction::CertificateImport),
        "certificate.install" => Ok(AuditAction::CertificateInstall),
        "trust_bundle.import" => Ok(AuditAction::TrustBundleImport),
        "trust_bundle.delete" => Ok(AuditAction::TrustBundleDelete),
        "admin.setup" => Ok(AuditAction::AdminSetup),
        "admin.login.success" => Ok(AuditAction::AdminLoginSuccess),
        "admin.logout" => Ok(AuditAction::AdminLogout),
        "admin.lockout" => Ok(AuditAction::AdminLockout),
        "admin.auth.failure_sampled" => Ok(AuditAction::AdminAuthFailureSampled),
        "maintenance.restore_imported" => Ok(AuditAction::MaintenanceRestoreImported),
        "system.trailing_recovery" => Ok(AuditAction::SystemTrailingRecovery),
        "audit.retention.checkpoint" => Ok(AuditAction::RetentionCheckpoint),
        _ => Err(audit_query_invalid()),
    }
}

fn parse_audit_outcome(value: &str) -> Result<AuditOutcome, AppError> {
    match value {
        "succeeded" => Ok(AuditOutcome::Succeeded),
        "failed" => Ok(AuditOutcome::Failed),
        "observed" => Ok(AuditOutcome::Observed),
        "reconciled_committed" => Ok(AuditOutcome::ReconciledCommitted),
        "reconciled_not_committed" => Ok(AuditOutcome::ReconciledNotCommitted),
        "reconciliation_unknown" => Ok(AuditOutcome::ReconciliationUnknown),
        _ => Err(audit_query_invalid()),
    }
}

fn parse_audit_target_kind(value: &str) -> Result<AuditTargetKind, AppError> {
    match value {
        "config_revision" => Ok(AuditTargetKind::ConfigRevision),
        "proxy_host" => Ok(AuditTargetKind::ProxyHost),
        "certificate" => Ok(AuditTargetKind::Certificate),
        "trust_bundle" => Ok(AuditTargetKind::TrustBundle),
        "admin_account" => Ok(AuditTargetKind::AdminAccount),
        "restore" => Ok(AuditTargetKind::Restore),
        "audit_ledger" => Ok(AuditTargetKind::AuditLedger),
        _ => Err(audit_query_invalid()),
    }
}

fn audit_query_invalid() -> AppError {
    AppError::new(
        ErrorCode::HttpMalformedRequest,
        "audit query does not match the supported contract",
    )
}

pub(crate) fn encode_audit_cursor(cursor: AuditCursor) -> String {
    format!(
        "v1.{:016x}{:016x}",
        cursor.ledger_generation, cursor.before_sequence
    )
}

pub(crate) fn decode_audit_cursor(value: &str) -> Result<AuditCursor, AppError> {
    let encoded = value.strip_prefix("v1.").ok_or_else(audit_cursor_invalid)?;
    if encoded.len() != 32 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(audit_cursor_invalid());
    }
    Ok(AuditCursor {
        ledger_generation: u64::from_str_radix(&encoded[..16], 16)
            .map_err(|_| audit_cursor_invalid())?,
        before_sequence: u64::from_str_radix(&encoded[16..], 16)
            .map_err(|_| audit_cursor_invalid())?,
    })
}

fn audit_cursor_invalid() -> AppError {
    AppError::new(ErrorCode::AuditCursorInvalid, "audit cursor is invalid")
}

fn audit_admission_state_name(state: AuditAdmissionState) -> &'static str {
    match state {
        AuditAdmissionState::Starting => "starting",
        AuditAdmissionState::Verifying => "verifying",
        AuditAdmissionState::Reconciling => "reconciling",
        AuditAdmissionState::Healthy => "healthy",
        AuditAdmissionState::Degraded => "degraded",
        AuditAdmissionState::FailedClosed => "failed_closed",
    }
}

pub(crate) fn audit_page_json(page: &AuditPage) -> String {
    let records = page
        .records
        .iter()
        .map(|view| {
            let record = &view.record;
            serde_json::json!({
                "sequence": view.sequence,
                "record_kind": record.record_kind.as_str(),
                "operation_id": record.context.operation_id.as_str(),
                "request_id": record.context.request_id.as_str(),
                "actor_kind": record.context.actor_kind.as_str(),
                "received_at_epoch_seconds": record.context.received_at_epoch_seconds,
                "action": record.action.as_str(),
                "target_kind": record.target_kind.as_str(),
                "target_id": record.target_id.as_str(),
                "before_revision": record.before_revision.as_ref().map(|value| value.as_str()),
                "after_revision": record.after_revision.as_ref().map(|value| value.as_str()),
                "outcome": record.outcome.map(|value| value.as_str()),
                "error_code": record.error_code.as_ref().map(|value| value.as_str()),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "schema_version": 1,
        "ledger": {
            "generation": page.head.generation,
            "sequence": page.head.sequence,
            "admission_state": audit_admission_state_name(page.admission_state),
        },
        "records": records,
        "next_cursor": page.next_cursor.map(encode_audit_cursor),
    })
    .to_string()
}
