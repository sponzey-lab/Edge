//! Bootstrap-only audit admission adapters.
//!
//! These supplied port implementations retain startup state and fail closed
//! when no authoritative operation fact is available; they neither access the
//! audit ledger nor decide audit policy.

use edge_domain::{
    AppError, AuditAction, AuditAdmissionState, AuditAuthoritativeFact, AuditOperationId,
    AuditTargetId,
};
use edge_ports::{AuditAdmissionController, AuditAuthoritativeStateInspector};

pub(crate) struct StartupAuditAdmission(pub(crate) AuditAdmissionState);

impl AuditAdmissionController for StartupAuditAdmission {
    fn state(&self) -> AuditAdmissionState {
        self.0
    }

    fn replace_state(&mut self, state: AuditAdmissionState) {
        self.0 = state;
    }
}

pub(crate) struct FailClosedAuditInspector;

impl AuditAuthoritativeStateInspector for FailClosedAuditInspector {
    fn inspect(
        &mut self,
        _operation_id: &AuditOperationId,
        _action: AuditAction,
        _target_id: &AuditTargetId,
    ) -> Result<AuditAuthoritativeFact, AppError> {
        Ok(AuditAuthoritativeFact::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_tracks_state_and_inspector_returns_unknown() {
        let mut admission = StartupAuditAdmission(AuditAdmissionState::Starting);
        assert_eq!(admission.state(), AuditAdmissionState::Starting);
        admission.replace_state(AuditAdmissionState::Healthy);
        assert_eq!(admission.state(), AuditAdmissionState::Healthy);

        let mut inspector = FailClosedAuditInspector;
        let fact = inspector
            .inspect(
                &AuditOperationId::parse("startup-audit-test").unwrap(),
                AuditAction::SystemTrailingRecovery,
                &AuditTargetId::parse("audit-ledger").unwrap(),
            )
            .unwrap();
        assert_eq!(fact, AuditAuthoritativeFact::Unknown);
    }
}
