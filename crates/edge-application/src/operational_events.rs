//! Secret-free operational log and audit event projection.

use edge_domain::{AppError, CertificateRef, ConfigRevisionId};
use edge_ports::{AuditEvent, AuditSink, StructuredLogEvent};

pub fn structured_config_apply_log(revision_id: &ConfigRevisionId) -> StructuredLogEvent {
    StructuredLogEvent {
        component: "edge-application".to_string(),
        event: "config.apply".to_string(),
        fields: vec![("revision_id".to_string(), revision_id.as_str().to_string())],
    }
}

/// Creates an operation outcome event without certificate material or other secret values.
pub fn structured_certificate_mutation_log(
    operation: &str,
    success: bool,
    request_id: &str,
    revision_id: &ConfigRevisionId,
    certificate_ref: &CertificateRef,
    status_code: u16,
    error_code: Option<&str>,
) -> StructuredLogEvent {
    let mut fields = vec![
        ("request_id".to_string(), request_id.to_string()),
        ("revision_id".to_string(), revision_id.as_str().to_string()),
        (
            "certificate_ref".to_string(),
            certificate_ref.as_str().to_string(),
        ),
        ("status_code".to_string(), status_code.to_string()),
    ];
    if let Some(error_code) = error_code {
        fields.push(("error_code".to_string(), error_code.to_string()));
    }

    StructuredLogEvent {
        component: "admin-api".to_string(),
        event: format!(
            "{operation}.{}",
            if success { "success" } else { "failure" }
        ),
        fields,
    }
}

/// Creates the manual-import result event without PEM or private-key fields.
pub fn structured_manual_certificate_import_log(
    success: bool,
    request_id: &str,
    revision_id: &ConfigRevisionId,
    certificate_ref: &CertificateRef,
    error_code: Option<&str>,
) -> StructuredLogEvent {
    let mut fields = vec![
        ("request_id".to_string(), request_id.to_string()),
        ("revision_id".to_string(), revision_id.as_str().to_string()),
        (
            "certificate_ref".to_string(),
            certificate_ref.as_str().to_string(),
        ),
        ("source".to_string(), "manual".to_string()),
    ];
    if let Some(error_code) = error_code {
        fields.push(("error_code".to_string(), error_code.to_string()));
    }
    StructuredLogEvent {
        component: "edge-application".to_string(),
        event: format!(
            "certificate.import.{}",
            if success { "success" } else { "failure" }
        ),
        fields,
    }
}

pub fn admin_auth_audit_event(success: bool) -> AuditEvent {
    AuditEvent {
        event: if success {
            "admin.login.success".to_string()
        } else {
            "admin.login.failure".to_string()
        },
        revision_id: None,
    }
}

pub fn record_admin_auth_audit<A: AuditSink>(sink: &mut A, success: bool) -> Result<(), AppError> {
    sink.record(admin_auth_audit_event(success))
}
