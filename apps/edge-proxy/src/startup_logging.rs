//! Secret-free bootstrap startup-log projection.
//!
//! This module renders supplied startup facts only. It does not change startup order, access
//! environment state, perform TLS work, or enable certificate automation.

use crate::bootstrap::AcmeClientMode;
use edge_application::{InitializeAuditLedgerOutput, StartupConfigOrigin};
use edge_domain::{AppError, BootstrapConfig, ConfigRevisionId};
use edge_ports::{LogSink, StructuredLogEvent};

pub(crate) fn record_audit_startup_log<L>(
    sink: &mut L,
    output: &InitializeAuditLedgerOutput,
) -> Result<(), AppError>
where
    L: LogSink + ?Sized,
{
    sink.record_log(StructuredLogEvent {
        component: "audit".to_string(),
        event: "audit.startup.ready".to_string(),
        fields: vec![
            (
                "record_count".to_string(),
                output.verified_record_count.to_string(),
            ),
            (
                "incomplete_count".to_string(),
                output.incomplete_count.to_string(),
            ),
            (
                "reconciled_count".to_string(),
                output.reconciled_count.to_string(),
            ),
            (
                "admission_state".to_string(),
                format!("{:?}", output.admission_state).to_ascii_lowercase(),
            ),
        ],
    })
}

pub(crate) fn record_process_start_log<L>(
    sink: &mut L,
    config: &BootstrapConfig,
    acme_client_mode: AcmeClientMode,
) -> Result<(), AppError>
where
    L: LogSink,
{
    sink.record_log(StructuredLogEvent {
        component: "edge-proxy".to_string(),
        event: "process.start".to_string(),
        fields: vec![
            ("data_dir".to_string(), config.data_dir.clone()),
            ("config_file".to_string(), config.config_file.clone()),
            ("admin_bind".to_string(), config.admin_bind.clone()),
            ("log_mode".to_string(), config.log_mode.as_str().to_string()),
            (
                "acme_client".to_string(),
                acme_client_mode.as_str().to_string(),
            ),
        ],
    })
}

pub(crate) fn record_startup_config_resolution_log<L>(
    sink: &mut L,
    origin: StartupConfigOrigin,
    revision_id: &ConfigRevisionId,
) -> Result<(), AppError>
where
    L: LogSink,
{
    sink.record_log(StructuredLogEvent {
        component: "edge-proxy".to_string(),
        event: "config.startup.resolved".to_string(),
        fields: vec![
            ("origin".to_string(), origin.as_str().to_string()),
            ("revision_id".to_string(), revision_id.as_str().to_string()),
        ],
    })
}

pub(crate) fn record_upstream_tls_prepared_log<L>(
    sink: &mut L,
    revision_id: &ConfigRevisionId,
    prepared_upstream_count: usize,
) -> Result<(), AppError>
where
    L: LogSink,
{
    sink.record_log(StructuredLogEvent {
        component: "edge-proxy".to_string(),
        event: "upstream_tls.startup.prepared".to_string(),
        fields: vec![
            ("revision_id".to_string(), revision_id.as_str().to_string()),
            (
                "prepared_upstream_count".to_string(),
                prepared_upstream_count.to_string(),
            ),
        ],
    })
}
