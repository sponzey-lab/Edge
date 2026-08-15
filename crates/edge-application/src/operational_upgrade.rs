use edge_domain::{
    AppError, ErrorCode, OfflineUpgradeJournal, OfflineUpgradeRequest, OfflineUpgradeState,
};
use edge_ports::{
    OfflineUpgradeBackupReceipt, OfflineUpgradeDeployment, OfflineUpgradeJournalStore,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineUpgradePrepared {
    pub target_version: String,
    pub target_image_digest: String,
    pub backup: OfflineUpgradeBackupReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineUpgradeExecutionReceipt {
    pub operation_id: String,
    pub state: OfflineUpgradeState,
}

pub struct PrepareOfflineUpgradeUseCase<'a, D> {
    deployment: &'a mut D,
}

impl<'a, D: OfflineUpgradeDeployment> PrepareOfflineUpgradeUseCase<'a, D> {
    pub fn new(deployment: &'a mut D) -> Self {
        Self { deployment }
    }

    pub fn execute(
        &mut self,
        request: OfflineUpgradeRequest,
    ) -> Result<OfflineUpgradePrepared, AppError> {
        request.validate()?;
        self.deployment.admit_upgrade_artifact(&request)?;
        self.deployment.preflight_upgrade(&request)?;
        let backup = self.deployment.create_and_verify_upgrade_backup(&request)?;
        Ok(OfflineUpgradePrepared {
            target_version: request.target_version,
            target_image_digest: request.image_digest,
            backup,
        })
    }
}

pub struct ExecuteOfflineUpgradeUseCase<'a, D> {
    deployment: &'a mut D,
}

pub fn persist_upgrade_journal<J: OfflineUpgradeJournalStore>(
    store: &mut J,
    state: OfflineUpgradeState,
    backup: &OfflineUpgradeBackupReceipt,
    target_artifact_digest: &str,
) -> Result<(), AppError> {
    let journal = OfflineUpgradeJournal {
        operation_id: format!("upgrade-{}", backup.backup_id),
        state,
        backup_id: backup.backup_id.clone(),
        previous_artifact_digest: backup.previous_artifact_digest.clone(),
        target_artifact_digest: target_artifact_digest.to_string(),
    };
    journal.validate()?;
    store.persist_upgrade_journal(&journal)
}

pub fn recover_offline_upgrade<D: OfflineUpgradeDeployment, J: OfflineUpgradeJournalStore>(
    deployment: &mut D,
    journals: &mut J,
    operation_id: &str,
) -> Result<OfflineUpgradeState, AppError> {
    let journal = journals
        .load_upgrade_journal(operation_id)?
        .ok_or_else(|| {
            AppError::new(
                ErrorCode::BackupManifestInvalid,
                "upgrade journal is unavailable",
            )
        })?;
    journal.validate()?;
    match journal.state {
        OfflineUpgradeState::Committed => Ok(OfflineUpgradeState::Committed),
        OfflineUpgradeState::Switched | OfflineUpgradeState::Ready => {
            let backup = OfflineUpgradeBackupReceipt {
                backup_id: journal.backup_id.clone(),
                previous_artifact_digest: journal.previous_artifact_digest.clone(),
            };
            let rolling_back = OfflineUpgradeJournal {
                state: OfflineUpgradeState::RollingBack,
                ..journal.clone()
            };
            journals.persist_upgrade_journal(&rolling_back)?;
            deployment.rollback_upgrade(&backup)?;
            let rolled_back = OfflineUpgradeJournal {
                state: OfflineUpgradeState::RolledBack,
                ..rolling_back
            };
            journals.persist_upgrade_journal(&rolled_back)?;
            Ok(OfflineUpgradeState::RolledBack)
        }
        _ => Err(AppError::new(
            ErrorCode::BackupStateTransitionInvalid,
            "upgrade journal requires manual recovery",
        )),
    }
}

impl<'a, D: OfflineUpgradeDeployment> ExecuteOfflineUpgradeUseCase<'a, D> {
    pub fn new(deployment: &'a mut D) -> Self {
        Self { deployment }
    }
    pub fn execute(
        &mut self,
        request: OfflineUpgradeRequest,
    ) -> Result<OfflineUpgradeState, AppError> {
        let prepared =
            PrepareOfflineUpgradeUseCase::new(self.deployment).execute(request.clone())?;
        self.deployment.stage_upgrade_artifact(&request)?;
        let mut state = OfflineUpgradeState::Prepared.transition(OfflineUpgradeState::Draining)?;
        if let Err(error) = self.deployment.drain_and_stop_service() {
            self.deployment.rollback_upgrade(&prepared.backup)?;
            return Err(error);
        }
        state = state.transition(OfflineUpgradeState::Stopped)?;
        if let Err(error) = self.deployment.switch_to_staged_artifact() {
            self.deployment.rollback_upgrade(&prepared.backup)?;
            return Err(error);
        }
        state = state.transition(OfflineUpgradeState::Switched)?;
        if let Err(error) = self.deployment.start_and_wait_ready() {
            self.deployment.rollback_upgrade(&prepared.backup)?;
            return Err(error);
        }
        state
            .transition(OfflineUpgradeState::Ready)?
            .transition(OfflineUpgradeState::Committed)
    }
}

pub fn execute_journaled_offline_upgrade<
    D: OfflineUpgradeDeployment,
    J: OfflineUpgradeJournalStore,
>(
    deployment: &mut D,
    journals: &mut J,
    request: OfflineUpgradeRequest,
) -> Result<OfflineUpgradeState, AppError> {
    execute_journaled_offline_upgrade_with_receipt(deployment, journals, request)
        .map(|receipt| receipt.state)
}

pub fn execute_journaled_offline_upgrade_with_receipt<
    D: OfflineUpgradeDeployment,
    J: OfflineUpgradeJournalStore,
>(
    deployment: &mut D,
    journals: &mut J,
    request: OfflineUpgradeRequest,
) -> Result<OfflineUpgradeExecutionReceipt, AppError> {
    let prepared = PrepareOfflineUpgradeUseCase::new(deployment).execute(request.clone())?;
    persist_upgrade_journal(
        journals,
        OfflineUpgradeState::Prepared,
        &prepared.backup,
        &request.image_digest,
    )?;
    deployment.stage_upgrade_artifact(&request)?;
    persist_upgrade_journal(
        journals,
        OfflineUpgradeState::Draining,
        &prepared.backup,
        &request.image_digest,
    )?;
    if let Err(error) = deployment.drain_and_stop_service() {
        return Err(rollback_journaled_upgrade(
            deployment,
            journals,
            &prepared.backup,
            &request.image_digest,
            error,
        ));
    }
    persist_upgrade_journal(
        journals,
        OfflineUpgradeState::Stopped,
        &prepared.backup,
        &request.image_digest,
    )?;
    if let Err(error) = deployment.switch_to_staged_artifact() {
        return Err(rollback_journaled_upgrade(
            deployment,
            journals,
            &prepared.backup,
            &request.image_digest,
            error,
        ));
    }
    persist_upgrade_journal(
        journals,
        OfflineUpgradeState::Switched,
        &prepared.backup,
        &request.image_digest,
    )?;
    if let Err(error) = deployment.start_and_wait_ready() {
        return Err(rollback_journaled_upgrade(
            deployment,
            journals,
            &prepared.backup,
            &request.image_digest,
            error,
        ));
    }
    persist_upgrade_journal(
        journals,
        OfflineUpgradeState::Ready,
        &prepared.backup,
        &request.image_digest,
    )?;
    persist_upgrade_journal(
        journals,
        OfflineUpgradeState::Committed,
        &prepared.backup,
        &request.image_digest,
    )?;
    Ok(OfflineUpgradeExecutionReceipt {
        operation_id: format!("upgrade-{}", prepared.backup.backup_id),
        state: OfflineUpgradeState::Committed,
    })
}

fn rollback_journaled_upgrade<D: OfflineUpgradeDeployment, J: OfflineUpgradeJournalStore>(
    deployment: &mut D,
    journals: &mut J,
    backup: &OfflineUpgradeBackupReceipt,
    target_artifact_digest: &str,
    original_error: AppError,
) -> AppError {
    if let Err(error) = persist_upgrade_journal(
        journals,
        OfflineUpgradeState::RollingBack,
        backup,
        target_artifact_digest,
    ) {
        return error;
    }
    if let Err(error) = deployment.rollback_upgrade(backup) {
        return error;
    }
    if let Err(error) = persist_upgrade_journal(
        journals,
        OfflineUpgradeState::RolledBack,
        backup,
        target_artifact_digest,
    ) {
        return error;
    }
    original_error
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_domain::{AppError, ErrorCode};
    use edge_ports::{
        OfflineUpgradeBackupReceipt, OfflineUpgradeDeployment, OfflineUpgradeJournalStore,
    };

    #[derive(Default)]
    struct Fake {
        calls: Vec<&'static str>,
        fail_drain: bool,
        fail_switch: bool,
        fail_start: bool,
        fail_rollback: bool,
    }
    #[derive(Default)]
    struct Journal {
        value: Option<edge_domain::OfflineUpgradeJournal>,
        fail: bool,
        fail_state: Option<OfflineUpgradeState>,
        states: Vec<OfflineUpgradeState>,
    }
    impl OfflineUpgradeJournalStore for Journal {
        fn persist_upgrade_journal(
            &mut self,
            journal: &edge_domain::OfflineUpgradeJournal,
        ) -> Result<(), AppError> {
            if self.fail || self.fail_state == Some(journal.state) {
                return Err(AppError::new(
                    ErrorCode::BackupStateTransitionInvalid,
                    "journal failed",
                ));
            }
            self.states.push(journal.state);
            self.value = Some(journal.clone());
            Ok(())
        }
        fn load_upgrade_journal(
            &mut self,
            _: &str,
        ) -> Result<Option<edge_domain::OfflineUpgradeJournal>, AppError> {
            Ok(self.value.clone())
        }
    }
    impl OfflineUpgradeDeployment for Fake {
        fn admit_upgrade_artifact(&mut self, _: &OfflineUpgradeRequest) -> Result<(), AppError> {
            self.calls.push("admit");
            Ok(())
        }
        fn preflight_upgrade(&mut self, _: &OfflineUpgradeRequest) -> Result<(), AppError> {
            self.calls.push("preflight");
            Ok(())
        }
        fn stage_upgrade_artifact(&mut self, _: &OfflineUpgradeRequest) -> Result<(), AppError> {
            self.calls.push("stage");
            Ok(())
        }
        fn drain_and_stop_service(&mut self) -> Result<(), AppError> {
            self.calls.push("drain-stop");
            if self.fail_drain {
                return Err(AppError::new(
                    ErrorCode::RuntimeCommandRejected,
                    "drain failed",
                ));
            }
            Ok(())
        }
        fn switch_to_staged_artifact(&mut self) -> Result<(), AppError> {
            self.calls.push("switch");
            if self.fail_switch {
                return Err(AppError::new(
                    ErrorCode::RuntimeCommandRejected,
                    "switch failed",
                ));
            }
            Ok(())
        }
        fn start_and_wait_ready(&mut self) -> Result<(), AppError> {
            self.calls.push("start-ready");
            if self.fail_start {
                return Err(AppError::new(
                    ErrorCode::RuntimeCommandRejected,
                    "readiness failed",
                ));
            }
            Ok(())
        }
        fn rollback_upgrade(&mut self, _: &OfflineUpgradeBackupReceipt) -> Result<(), AppError> {
            self.calls.push("rollback");
            if self.fail_rollback {
                return Err(AppError::new(
                    ErrorCode::RestoreRollbackFailed,
                    "rollback failed",
                ));
            }
            Ok(())
        }
        fn create_and_verify_upgrade_backup(
            &mut self,
            _: &OfflineUpgradeRequest,
        ) -> Result<OfflineUpgradeBackupReceipt, AppError> {
            self.calls.push("backup");
            Ok(OfflineUpgradeBackupReceipt {
                backup_id: "backup-1".into(),
                previous_artifact_digest: "b".repeat(64),
            })
        }
    }
    fn request() -> OfflineUpgradeRequest {
        OfflineUpgradeRequest {
            target_version: "v1.2.3".into(),
            image_digest: "a".repeat(64),
            artifact_file: "/root/edge-proxy-1.2.3".into(),
            passphrase_file: "/secure/p".into(),
        }
    }
    #[test]
    fn preflight_and_verified_backup_run_before_any_switch() {
        let mut deployment = Fake::default();
        let output = PrepareOfflineUpgradeUseCase::new(&mut deployment)
            .execute(request())
            .unwrap();
        assert_eq!(deployment.calls, ["admit", "preflight", "backup"]);
        assert_eq!(output.backup.backup_id, "backup-1");
    }
    #[test]
    fn invalid_request_never_reaches_deployment() {
        let mut deployment = Fake::default();
        let mut bad = request();
        bad.passphrase_file = "relative".into();
        assert_eq!(
            PrepareOfflineUpgradeUseCase::new(&mut deployment)
                .execute(bad)
                .unwrap_err()
                .code,
            ErrorCode::BackupSecretInputInvalid
        );
        assert!(deployment.calls.is_empty());
    }

    #[test]
    fn invalid_artifact_reference_never_reaches_admission_or_backup() {
        let mut deployment = Fake::default();
        let mut bad = request();
        bad.artifact_file = "relative-artifact".into();
        assert_eq!(
            PrepareOfflineUpgradeUseCase::new(&mut deployment)
                .execute(bad)
                .unwrap_err()
                .code,
            ErrorCode::BackupDestinationUnsafe
        );
        assert!(deployment.calls.is_empty());
    }

    #[test]
    fn full_upgrade_orders_all_adapter_effects_before_commit() {
        let mut deployment = Fake::default();
        assert_eq!(
            ExecuteOfflineUpgradeUseCase::new(&mut deployment)
                .execute(request())
                .unwrap(),
            edge_domain::OfflineUpgradeState::Committed
        );
        assert_eq!(
            deployment.calls,
            [
                "admit",
                "preflight",
                "backup",
                "stage",
                "drain-stop",
                "switch",
                "start-ready"
            ]
        );
    }

    #[test]
    fn switch_failure_rolls_back_without_starting_new_artifact() {
        let mut deployment = Fake {
            fail_switch: true,
            ..Default::default()
        };
        let error = ExecuteOfflineUpgradeUseCase::new(&mut deployment)
            .execute(request())
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::RuntimeCommandRejected);
        assert_eq!(
            deployment.calls,
            [
                "admit",
                "preflight",
                "backup",
                "stage",
                "drain-stop",
                "switch",
                "rollback"
            ]
        );
    }

    #[test]
    fn journal_persistence_contains_only_recovery_identity() {
        let mut journal = Journal::default();
        let backup = OfflineUpgradeBackupReceipt {
            backup_id: "backup-1".into(),
            previous_artifact_digest: "b".repeat(64),
        };
        persist_upgrade_journal(
            &mut journal,
            OfflineUpgradeState::Stopped,
            &backup,
            &"a".repeat(64),
        )
        .unwrap();
        assert_eq!(journal.value.unwrap().operation_id, "upgrade-backup-1");
    }

    #[test]
    fn recovery_rolls_back_switched_journal_and_persists_terminal_state() {
        let mut deployment = Fake::default();
        let mut journal = Journal {
            value: Some(edge_domain::OfflineUpgradeJournal {
                operation_id: "upgrade-backup-1".into(),
                state: OfflineUpgradeState::Switched,
                backup_id: "backup-1".into(),
                previous_artifact_digest: "b".repeat(64),
                target_artifact_digest: "a".repeat(64),
            }),
            fail: false,
            fail_state: None,
            states: Vec::new(),
        };
        assert_eq!(
            recover_offline_upgrade(&mut deployment, &mut journal, "upgrade-backup-1").unwrap(),
            OfflineUpgradeState::RolledBack
        );
        assert_eq!(deployment.calls, ["rollback"]);
        assert_eq!(
            journal.value.unwrap().state,
            OfflineUpgradeState::RolledBack
        );
        assert_eq!(
            journal.states,
            [
                OfflineUpgradeState::RollingBack,
                OfflineUpgradeState::RolledBack
            ]
        );
    }

    #[test]
    fn journaled_upgrade_persists_every_crash_relevant_state_in_order() {
        let mut deployment = Fake::default();
        let mut journal = Journal::default();
        assert_eq!(
            execute_journaled_offline_upgrade(&mut deployment, &mut journal, request()).unwrap(),
            OfflineUpgradeState::Committed
        );
        assert_eq!(
            journal.states,
            [
                OfflineUpgradeState::Prepared,
                OfflineUpgradeState::Draining,
                OfflineUpgradeState::Stopped,
                OfflineUpgradeState::Switched,
                OfflineUpgradeState::Ready,
                OfflineUpgradeState::Committed
            ]
        );
        assert_eq!(
            deployment.calls,
            [
                "admit",
                "preflight",
                "backup",
                "stage",
                "drain-stop",
                "switch",
                "start-ready"
            ]
        );
    }

    #[test]
    fn journal_persistence_failure_stops_before_artifact_stage() {
        let mut deployment = Fake::default();
        let mut journal = Journal {
            fail: true,
            ..Default::default()
        };
        assert!(
            execute_journaled_offline_upgrade(&mut deployment, &mut journal, request()).is_err()
        );
        assert_eq!(deployment.calls, ["admit", "preflight", "backup"]);
    }

    #[test]
    fn journaled_switch_failure_rolls_back_and_persists_terminal_receipt() {
        let mut deployment = Fake {
            fail_switch: true,
            ..Default::default()
        };
        let mut journal = Journal::default();
        assert_eq!(
            execute_journaled_offline_upgrade(&mut deployment, &mut journal, request())
                .unwrap_err()
                .code,
            ErrorCode::RuntimeCommandRejected
        );
        assert_eq!(
            deployment.calls,
            [
                "admit",
                "preflight",
                "backup",
                "stage",
                "drain-stop",
                "switch",
                "rollback"
            ]
        );
        assert_eq!(
            journal.states,
            [
                OfflineUpgradeState::Prepared,
                OfflineUpgradeState::Draining,
                OfflineUpgradeState::Stopped,
                OfflineUpgradeState::RollingBack,
                OfflineUpgradeState::RolledBack
            ]
        );
    }

    #[test]
    fn journaled_drain_failure_rolls_back_and_persists_terminal_receipt() {
        let mut deployment = Fake {
            fail_drain: true,
            ..Default::default()
        };
        let mut journal = Journal::default();
        assert!(
            execute_journaled_offline_upgrade(&mut deployment, &mut journal, request()).is_err()
        );
        assert_eq!(deployment.calls.last(), Some(&"rollback"));
        assert_eq!(
            journal.states,
            [
                OfflineUpgradeState::Prepared,
                OfflineUpgradeState::Draining,
                OfflineUpgradeState::RollingBack,
                OfflineUpgradeState::RolledBack
            ]
        );
    }

    #[test]
    fn journaled_readiness_failure_rolls_back_and_persists_terminal_receipt() {
        let mut deployment = Fake {
            fail_start: true,
            ..Default::default()
        };
        let mut journal = Journal::default();
        assert!(
            execute_journaled_offline_upgrade(&mut deployment, &mut journal, request()).is_err()
        );
        assert_eq!(deployment.calls.last(), Some(&"rollback"));
        assert_eq!(
            journal.states,
            [
                OfflineUpgradeState::Prepared,
                OfflineUpgradeState::Draining,
                OfflineUpgradeState::Stopped,
                OfflineUpgradeState::Switched,
                OfflineUpgradeState::RollingBack,
                OfflineUpgradeState::RolledBack
            ]
        );
    }

    #[test]
    fn rollback_failure_preserves_rolling_back_receipt_and_returns_failure() {
        let mut deployment = Fake {
            fail_switch: true,
            fail_rollback: true,
            ..Default::default()
        };
        let mut journal = Journal::default();
        assert_eq!(
            execute_journaled_offline_upgrade(&mut deployment, &mut journal, request())
                .unwrap_err()
                .code,
            ErrorCode::RestoreRollbackFailed
        );
        assert_eq!(
            journal.states,
            [
                OfflineUpgradeState::Prepared,
                OfflineUpgradeState::Draining,
                OfflineUpgradeState::Stopped,
                OfflineUpgradeState::RollingBack
            ]
        );
    }

    #[test]
    fn journal_failure_before_drain_stops_before_service_shutdown() {
        let mut deployment = Fake::default();
        let mut journal = Journal {
            fail_state: Some(OfflineUpgradeState::Draining),
            ..Default::default()
        };
        assert!(
            execute_journaled_offline_upgrade(&mut deployment, &mut journal, request()).is_err()
        );
        assert_eq!(deployment.calls, ["admit", "preflight", "backup", "stage"]);
    }

    #[test]
    fn journal_failure_after_switch_stops_before_starting_new_artifact() {
        let mut deployment = Fake::default();
        let mut journal = Journal {
            fail_state: Some(OfflineUpgradeState::Switched),
            ..Default::default()
        };
        assert!(
            execute_journaled_offline_upgrade(&mut deployment, &mut journal, request()).is_err()
        );
        assert_eq!(
            deployment.calls,
            [
                "admit",
                "preflight",
                "backup",
                "stage",
                "drain-stop",
                "switch"
            ]
        );
    }
}
