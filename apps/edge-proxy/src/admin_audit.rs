//! Shared Admin durable-audit response adapter.
//!
//! This boundary builds typed audit context, parses only the small JSON fields
//! needed for audit identities, and finalizes an already-begun operation. It
//! does not authenticate, route requests, or apply configuration.

use edge_adapters::{SharedAuditAdmission, SharedFileAuditLedger};
use edge_admin_api::{AdminHttpRequest, AdminHttpResponse};
use edge_application::{complete_audit_operation, CompleteAuditOperationInput};
use edge_domain::{
    AppError, AuditActorKind, AuditContext, AuditEffectState, AuditOperationId, AuditRequestId,
    AuditStableErrorCode, AuditTargetId, ErrorCode,
};

use crate::admin_trust_bundles::current_epoch_seconds;

pub(crate) fn admin_audit_context(request: &AdminHttpRequest) -> Result<AuditContext, AppError> {
    let request_id = AuditRequestId::parse(&request.request_id).map_err(|_| {
        AppError::new(
            ErrorCode::AuditRecordInvalid,
            "admin request id is not audit-safe",
        )
    })?;
    let operation_id = AuditOperationId::parse(format!("operation-{}", request.request_id))
        .map_err(|_| {
            AppError::new(
                ErrorCode::AuditRecordInvalid,
                "admin operation id is not audit-safe",
            )
        })?;
    Ok(AuditContext {
        operation_id,
        request_id,
        actor_kind: AuditActorKind::BootstrapAdmin,
        received_at_epoch_seconds: current_epoch_seconds()
            .map_err(|_| AppError::new(ErrorCode::InternalBug, "system clock is unavailable"))?,
    })
}

pub(crate) fn json_string_field(body: &str, field: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()?
        .get(field)?
        .as_str()
        .map(str::to_string)
}

pub(crate) fn response_revision_id(response: &AdminHttpResponse) -> Option<String> {
    json_string_field(&response.body, "revision_id")
}

pub(crate) fn audit_failure_response(
    request: &AdminHttpRequest,
    status_code: u16,
    error: &AppError,
    effect_committed: bool,
) -> AdminHttpResponse {
    AdminHttpResponse {
        status_code,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: serde_json::json!({
            "request_id": request.request_id,
            "error_code": error.code.as_str(),
            "message": error.code.default_user_message(),
            "effect_committed": effect_committed,
        })
        .to_string(),
        error_code: Some(error.code.as_str().to_string()),
    }
}

pub(crate) fn complete_audited_admin_response(
    request: &AdminHttpRequest,
    response: AdminHttpResponse,
    ledger: &mut SharedFileAuditLedger,
    admission: &mut SharedAuditAdmission,
    operation: edge_application::AuditPersistentOperationInput,
    expected_head: edge_domain::AuditLedgerHead,
) -> AdminHttpResponse {
    let committed = (200..300).contains(&response.status_code);
    let error_code = if committed {
        None
    } else {
        AuditStableErrorCode::parse(
            response
                .error_code
                .as_deref()
                .unwrap_or(ErrorCode::InternalBug.as_str()),
        )
        .ok()
        .or_else(|| AuditStableErrorCode::parse(ErrorCode::InternalBug.as_str()).ok())
    };
    match complete_audit_operation(
        ledger,
        admission,
        CompleteAuditOperationInput {
            operation,
            expected_head,
            effect_state: if committed {
                AuditEffectState::Committed
            } else {
                AuditEffectState::Rejected
            },
            after_revision: committed
                .then(|| response_revision_id(&response))
                .flatten()
                .and_then(|revision| AuditTargetId::parse(revision).ok()),
            error_code,
        },
    ) {
        Ok(_) => response,
        Err(failure) => audit_failure_response(request, 503, &failure.error, committed),
    }
}
