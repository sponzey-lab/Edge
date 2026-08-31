//! Config revision application and rollback orchestration.
//!
//! This boundary persists only through typed ports and sends validated Core
//! commands before publishing a runtime revision.

use edge_domain::{AppError, ConfigRevisionId, ConfigSnapshot, ErrorCode};
use edge_ports::{AuditEvent, AuditSink, ConfigRevisionRepository, CoreCommandClient};

use crate::{
    plan_apply_with_current, revision_record_for_snapshot, send_apply_plan,
    validation_errors_to_app_error, ApplyPlan, ConfigValidator,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyResult {
    pub revision_id: ConfigRevisionId,
    pub plan: ApplyPlan,
}

pub struct ConfigLifecycle<R, A> {
    pub revisions: R,
    pub audit: A,
    pub validator: ConfigValidator,
}

impl<R, A> ConfigLifecycle<R, A>
where
    R: ConfigRevisionRepository,
    A: AuditSink,
{
    pub fn apply(&mut self, snapshot: ConfigSnapshot) -> Result<ApplyResult, AppError> {
        self.validator
            .validate_snapshot(&snapshot)
            .into_result()
            .map_err(|errors| validation_errors_to_app_error(&errors))?;
        let record = revision_record_for_snapshot(snapshot.clone(), "apply");
        let current = self.revisions.current()?;
        let plan =
            plan_apply_with_current(current.as_ref().map(|record| &record.snapshot), snapshot);
        let revision_id = record.revision.id.clone();
        self.revisions.save_revision(record)?;
        self.revisions.set_current(&revision_id)?;
        self.audit.record(AuditEvent {
            event: "config.apply".to_string(),
            revision_id: Some(revision_id.clone()),
        })?;
        Ok(ApplyResult { revision_id, plan })
    }

    pub fn apply_with_core<C>(
        &mut self,
        snapshot: ConfigSnapshot,
        core: &mut C,
    ) -> Result<ApplyResult, AppError>
    where
        C: CoreCommandClient + ?Sized,
    {
        self.validator
            .validate_snapshot(&snapshot)
            .into_result()
            .map_err(|errors| validation_errors_to_app_error(&errors))?;
        let revision_id = snapshot.revision_id.clone();
        let record = revision_record_for_snapshot(snapshot.clone(), "apply");
        let current = self.revisions.current()?;
        let plan =
            plan_apply_with_current(current.as_ref().map(|record| &record.snapshot), snapshot);
        self.revisions.save_revision(record)?;
        if let Err(error) = send_apply_plan(core, &plan) {
            self.audit.record(AuditEvent {
                event: "config.apply.failure".to_string(),
                revision_id: Some(revision_id.clone()),
            })?;
            return Err(error);
        }
        self.revisions.set_current(&revision_id)?;
        self.audit.record(AuditEvent {
            event: "config.apply".to_string(),
            revision_id: Some(revision_id.clone()),
        })?;
        Ok(ApplyResult { revision_id, plan })
    }

    pub fn rollback(&mut self, revision_id: &ConfigRevisionId) -> Result<ApplyResult, AppError> {
        let record = self.revisions.find_revision(revision_id)?.ok_or_else(|| {
            AppError::new(
                ErrorCode::ConfigRevisionNotFound,
                format!("revision not found: {revision_id}"),
            )
        })?;
        let current = self.revisions.current()?;
        let plan = plan_apply_with_current(
            current.as_ref().map(|record| &record.snapshot),
            record.snapshot,
        );
        self.revisions.set_current(revision_id)?;
        self.audit.record(AuditEvent {
            event: "config.rollback".to_string(),
            revision_id: Some(revision_id.clone()),
        })?;
        Ok(ApplyResult {
            revision_id: revision_id.clone(),
            plan,
        })
    }

    pub fn rollback_with_core<C>(
        &mut self,
        revision_id: &ConfigRevisionId,
        core: &mut C,
    ) -> Result<ApplyResult, AppError>
    where
        C: CoreCommandClient + ?Sized,
    {
        let record = self.revisions.find_revision(revision_id)?.ok_or_else(|| {
            AppError::new(
                ErrorCode::ConfigRevisionNotFound,
                format!("revision not found: {revision_id}"),
            )
        })?;
        self.validator
            .validate_snapshot(&record.snapshot)
            .into_result()
            .map_err(|errors| validation_errors_to_app_error(&errors))?;
        let current = self.revisions.current()?;
        let plan = plan_apply_with_current(
            current.as_ref().map(|record| &record.snapshot),
            record.snapshot,
        );
        if let Err(error) = send_apply_plan(core, &plan) {
            self.audit.record(AuditEvent {
                event: "config.rollback.failure".to_string(),
                revision_id: Some(revision_id.clone()),
            })?;
            return Err(error);
        }
        self.revisions.set_current(revision_id)?;
        self.audit.record(AuditEvent {
            event: "config.rollback".to_string(),
            revision_id: Some(revision_id.clone()),
        })?;
        Ok(ApplyResult {
            revision_id: revision_id.clone(),
            plan,
        })
    }
}
