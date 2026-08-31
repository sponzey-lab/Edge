//! File-backed Admin trust-bundle adapter and durable-audit completion boundary.
//!
//! This module receives already-authenticated Admin API calls from `admin_http`.
//! It never renders trust material into responses or logs, and does not handle
//! HTTP parsing, routing, or certificate automation.

use std::io;
use std::sync::{Arc, Mutex};

use edge_adapters::{
    FileRevisionRepository, FileTrustBundleStore, RustlsTrustBundleMaterialValidator,
    SharedAuditAdmission, SharedFileAuditLedger,
};
use edge_admin_api::TrustBundleAdminService;
use edge_application::{
    begin_audit_operation, complete_audit_operation, delete_trust_bundle, import_trust_bundle,
    list_trust_bundles, AuditPersistentOperationInput, BeginAuditOperationOutput,
    CompleteAuditOperationInput, ImportTrustBundleInput,
};
use edge_domain::{
    AppError, AuditAction, AuditActorKind, AuditContext, AuditEffectState, AuditOperationId,
    AuditRequestId, AuditStableErrorCode, AuditTargetId, ErrorCode, TrustBundleRef,
};
use edge_ports::{
    AuditEvent, AuditSink, ConfigRevisionRepository, LogSink, RetainedConfigSnapshots,
    StructuredLogEvent, TrustBundleEventSink, TrustBundleMetadata, TrustBundleOperationEvent,
};

struct RetainedRevisionSnapshots(FileRevisionRepository);

impl RetainedConfigSnapshots for RetainedRevisionSnapshots {
    fn retained_config_snapshots(&self) -> Result<Vec<edge_domain::ConfigSnapshot>, AppError> {
        Ok(self
            .0
            .history()?
            .into_iter()
            .map(|record| record.snapshot)
            .collect())
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct NoopTrustBundleAuditSink;

impl AuditSink for NoopTrustBundleAuditSink {
    fn record(&mut self, _event: AuditEvent) -> Result<(), AppError> {
        Ok(())
    }
}

struct TrustBundleRuntimeEvents {
    product_log: Arc<Mutex<Box<dyn LogSink + Send>>>,
    audit: NoopTrustBundleAuditSink,
}

impl TrustBundleEventSink for TrustBundleRuntimeEvents {
    fn record_trust_product_event(&mut self, event: TrustBundleOperationEvent) {
        let mut fields = vec![
            (
                "trust_bundle_ref".to_string(),
                event.trust_bundle_ref.as_str().to_string(),
            ),
            ("outcome".to_string(), event.outcome.to_string()),
        ];
        if let Some(count) = event.certificate_count {
            fields.push(("certificate_count".to_string(), count.to_string()));
        }
        if let Some(code) = event.error_code {
            fields.push(("error_code".to_string(), code.as_str().to_string()));
        }
        if let Ok(mut sink) = self.product_log.lock() {
            let _ = sink.record_log(StructuredLogEvent {
                component: "admin-api".to_string(),
                event: event.event.to_string(),
                fields,
            });
        }
    }

    fn record_trust_audit_event(&mut self, event: TrustBundleOperationEvent) {
        let _ = self.audit.record(AuditEvent {
            event: format!("{}.{}", event.event, event.outcome),
            revision_id: None,
        });
    }
}

pub(crate) struct TrustBundleRuntimeService {
    validator: RustlsTrustBundleMaterialValidator,
    store: FileTrustBundleStore,
    revisions: RetainedRevisionSnapshots,
    events: TrustBundleRuntimeEvents,
    durable_audit: Option<(SharedFileAuditLedger, SharedAuditAdmission)>,
}

impl TrustBundleRuntimeService {
    pub(crate) fn new(
        store: FileTrustBundleStore,
        revisions: FileRevisionRepository,
        product_log: Arc<Mutex<Box<dyn LogSink + Send>>>,
        durable_audit: Option<(SharedFileAuditLedger, SharedAuditAdmission)>,
    ) -> Self {
        Self {
            validator: RustlsTrustBundleMaterialValidator,
            store,
            revisions: RetainedRevisionSnapshots(revisions),
            events: TrustBundleRuntimeEvents {
                product_log,
                audit: NoopTrustBundleAuditSink,
            },
            durable_audit,
        }
    }
}

impl TrustBundleAdminService for TrustBundleRuntimeService {
    fn import(
        &mut self,
        request_id: &str,
        trust_bundle_ref: TrustBundleRef,
        encoded_material: Vec<u8>,
    ) -> Result<TrustBundleMetadata, AppError> {
        let imported_at_epoch_seconds = current_epoch_seconds()
            .map_err(|_| AppError::new(ErrorCode::InternalBug, "system clock is unavailable"))?;
        let audit = self.durable_audit.clone();
        let operation = prepare_trust_audit(
            audit.as_ref(),
            request_id,
            imported_at_epoch_seconds,
            AuditAction::TrustBundleImport,
            &trust_bundle_ref,
        )?;
        let begin = begin_optional_audit(audit.as_ref(), operation.as_ref())?;
        let result = import_trust_bundle(
            &mut self.validator,
            &mut self.store,
            &mut self.events,
            ImportTrustBundleInput {
                request_id: request_id.to_string(),
                trust_bundle_ref,
                encoded_material,
                imported_at_epoch_seconds,
            },
        );
        complete_optional_audit(audit, operation, begin, result)
    }

    fn list(&mut self) -> Result<Vec<TrustBundleMetadata>, AppError> {
        list_trust_bundles(&mut self.store)
    }

    fn delete(&mut self, trust_bundle_ref: TrustBundleRef) -> Result<(), AppError> {
        let timestamp = current_epoch_seconds()
            .map_err(|_| AppError::new(ErrorCode::InternalBug, "system clock is unavailable"))?;
        let request_id = format!("trust-delete-{}", trust_bundle_ref.as_str());
        let audit = self.durable_audit.clone();
        let operation = prepare_trust_audit(
            audit.as_ref(),
            &request_id,
            timestamp,
            AuditAction::TrustBundleDelete,
            &trust_bundle_ref,
        )?;
        let begin = begin_optional_audit(audit.as_ref(), operation.as_ref())?;
        let result = delete_trust_bundle(
            &mut self.store,
            &self.revisions,
            &mut self.events,
            trust_bundle_ref,
        );
        complete_optional_audit(audit, operation, begin, result)
    }
}

fn prepare_trust_audit(
    audit: Option<&(SharedFileAuditLedger, SharedAuditAdmission)>,
    request_id: &str,
    timestamp: u64,
    action: AuditAction,
    trust_bundle_ref: &TrustBundleRef,
) -> Result<Option<AuditPersistentOperationInput>, AppError> {
    if audit.is_none() {
        return Ok(None);
    }
    let context = AuditContext {
        operation_id: AuditOperationId::parse(format!("operation-{request_id}")).map_err(|_| {
            AppError::new(
                ErrorCode::AuditRecordInvalid,
                "invalid trust audit operation id",
            )
        })?,
        request_id: AuditRequestId::parse(request_id).map_err(|_| {
            AppError::new(
                ErrorCode::AuditRecordInvalid,
                "invalid trust audit request id",
            )
        })?,
        actor_kind: AuditActorKind::BootstrapAdmin,
        received_at_epoch_seconds: timestamp,
    };
    edge_application::trust_audit_operation(
        context,
        action,
        AuditTargetId::parse(trust_bundle_ref.as_str()).map_err(|_| {
            AppError::new(
                ErrorCode::AuditRecordInvalid,
                "invalid trust bundle audit target",
            )
        })?,
    )
    .map(Some)
}

fn begin_optional_audit(
    audit: Option<&(SharedFileAuditLedger, SharedAuditAdmission)>,
    operation: Option<&AuditPersistentOperationInput>,
) -> Result<Option<BeginAuditOperationOutput>, AppError> {
    match (audit, operation) {
        (Some((ledger, admission)), Some(operation)) => {
            let mut ledger = ledger.clone();
            begin_audit_operation(&mut ledger, admission, operation.clone())
                .map(Some)
                .map_err(|failure| failure.error)
        }
        _ => Ok(None),
    }
}

fn complete_optional_audit<T>(
    audit: Option<(SharedFileAuditLedger, SharedAuditAdmission)>,
    operation: Option<AuditPersistentOperationInput>,
    begin: Option<BeginAuditOperationOutput>,
    effect: Result<T, AppError>,
) -> Result<T, AppError> {
    let (Some((mut ledger, mut admission)), Some(operation), Some(begin)) =
        (audit, operation, begin)
    else {
        return effect;
    };
    let (effect_state, stable_error) = match &effect {
        Ok(_) => (AuditEffectState::Committed, None),
        Err(error) => (
            AuditEffectState::Rejected,
            AuditStableErrorCode::parse(error.code.as_str()).ok(),
        ),
    };
    match complete_audit_operation(
        &mut ledger,
        &mut admission,
        CompleteAuditOperationInput {
            operation,
            expected_head: begin.head,
            effect_state,
            after_revision: None,
            error_code: stable_error,
        },
    ) {
        Ok(_) => effect,
        Err(failure) => Err(AppError::new(
            failure.error.code,
            if effect_state == AuditEffectState::Committed {
                "trust mutation committed but audit terminal persistence failed"
            } else {
                "trust mutation failed and audit terminal persistence also failed"
            },
        )),
    }
}

pub(crate) fn current_epoch_seconds() -> io::Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| io::Error::other("system time is before unix epoch"))
}
