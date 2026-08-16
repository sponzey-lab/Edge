use std::path::{Path, PathBuf};

use edge_domain::{AppError, ErrorCode, OfflineUpgradeJournal, OfflineUpgradeState};
use edge_ports::{
    OfflineUpgradeBackupReceipt, OfflineUpgradeCommand, OfflineUpgradeCommandResult,
    OfflineUpgradeCommandRunner, OfflineUpgradeDeployment, OfflineUpgradeJournalStore,
};

#[derive(Debug, Clone)]
pub struct FileOfflineUpgradeJournalStore {
    journal: PathBuf,
    temporary: PathBuf,
}

pub struct CommandOfflineUpgradeDeployment<R> {
    runner: R,
}

const SYSTEMD_UPGRADE_HELPER: &str = "/usr/local/libexec/sponzey-edge/upgrade-helper";
const COMPOSE_UPGRADE_HELPER: &str = "/usr/local/libexec/sponzey-edge/compose-upgrade-helper";
const COMPOSE_PROJECT_DIRECTORY: &str = "/etc/sponzey-edge/compose";
const COMPOSE_FILE: &str = "/etc/sponzey-edge/compose/docker-compose.yml";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeHelperInvocation {
    pub executable: PathBuf,
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeHelperProcessOutput {
    pub exit_code: i32,
    pub stdout: String,
}

pub trait UpgradeHelperProcessExecutor {
    fn execute_upgrade_helper(
        &mut self,
        invocation: UpgradeHelperInvocation,
    ) -> Result<UpgradeHelperProcessOutput, AppError>;
}

pub struct SystemUpgradeHelperProcessExecutor;

impl UpgradeHelperProcessExecutor for SystemUpgradeHelperProcessExecutor {
    fn execute_upgrade_helper(
        &mut self,
        invocation: UpgradeHelperInvocation,
    ) -> Result<UpgradeHelperProcessOutput, AppError> {
        if (invocation.executable != Path::new(SYSTEMD_UPGRADE_HELPER)
            && invocation.executable != Path::new(COMPOSE_UPGRADE_HELPER))
            || invocation
                .arguments
                .iter()
                .any(|value| value.contains('\0'))
        {
            return Err(AppError::new(
                ErrorCode::RuntimeCommandRejected,
                "unsafe upgrade helper invocation",
            ));
        }
        let output = std::process::Command::new(&invocation.executable)
            .args(&invocation.arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .output()
            .map_err(|_| {
                AppError::new(
                    ErrorCode::RuntimeCommandRejected,
                    "upgrade helper could not start",
                )
            })?;
        if output.stdout.len() > 4096 {
            return Err(AppError::new(
                ErrorCode::RuntimeCommandRejected,
                "upgrade helper output exceeds the bound",
            ));
        }
        let stdout = String::from_utf8(output.stdout).map_err(|_| {
            AppError::new(
                ErrorCode::RuntimeCommandRejected,
                "upgrade helper output is not UTF-8",
            )
        })?;
        Ok(UpgradeHelperProcessOutput {
            exit_code: output.status.code().unwrap_or(-1),
            stdout,
        })
    }
}

pub struct SystemdUpgradeHelperRunner<E> {
    executor: E,
}

pub struct ComposeUpgradeHelperRunner<E> {
    executor: E,
}

impl<E> ComposeUpgradeHelperRunner<E> {
    pub fn new(executor: E) -> Self {
        Self { executor }
    }

    pub fn into_inner(self) -> E {
        self.executor
    }
}

impl<E: UpgradeHelperProcessExecutor> OfflineUpgradeCommandRunner
    for ComposeUpgradeHelperRunner<E>
{
    fn run_upgrade_command(
        &mut self,
        command: OfflineUpgradeCommand,
    ) -> Result<OfflineUpgradeCommandResult, AppError> {
        let expects_backup = matches!(command, OfflineUpgradeCommand::CreateAndVerifyBackup { .. });
        let mut invocation = render_helper_command(command);
        invocation.executable = PathBuf::from(COMPOSE_UPGRADE_HELPER);
        invocation.arguments.splice(
            0..0,
            [
                "--project-directory".to_string(),
                COMPOSE_PROJECT_DIRECTORY.to_string(),
                "--file".to_string(),
                COMPOSE_FILE.to_string(),
            ],
        );
        let output = self.executor.execute_upgrade_helper(invocation)?;
        if output.exit_code != 0 {
            return Err(AppError::new(
                ErrorCode::RuntimeCommandRejected,
                "compose upgrade helper command failed",
            ));
        }
        if expects_backup {
            Ok(OfflineUpgradeCommandResult::BackupCreated(
                parse_backup_receipt(&output.stdout)?,
            ))
        } else if output.stdout.is_empty() {
            Ok(OfflineUpgradeCommandResult::Completed)
        } else {
            Err(command_result_error())
        }
    }
}

impl<E> SystemdUpgradeHelperRunner<E> {
    pub fn new(executor: E) -> Self {
        Self { executor }
    }

    pub fn into_inner(self) -> E {
        self.executor
    }
}

impl<E: UpgradeHelperProcessExecutor> OfflineUpgradeCommandRunner
    for SystemdUpgradeHelperRunner<E>
{
    fn run_upgrade_command(
        &mut self,
        command: OfflineUpgradeCommand,
    ) -> Result<OfflineUpgradeCommandResult, AppError> {
        let expects_backup = matches!(command, OfflineUpgradeCommand::CreateAndVerifyBackup { .. });
        let output = self
            .executor
            .execute_upgrade_helper(render_helper_command(command))?;
        if output.exit_code != 0 {
            return Err(AppError::new(
                ErrorCode::RuntimeCommandRejected,
                "upgrade helper command failed",
            ));
        }
        if expects_backup {
            Ok(OfflineUpgradeCommandResult::BackupCreated(
                parse_backup_receipt(&output.stdout)?,
            ))
        } else if output.stdout.is_empty() {
            Ok(OfflineUpgradeCommandResult::Completed)
        } else {
            Err(command_result_error())
        }
    }
}

fn render_helper_command(command: OfflineUpgradeCommand) -> UpgradeHelperInvocation {
    let arguments = match command {
        OfflineUpgradeCommand::AdmitArtifact {
            artifact_file,
            image_digest,
        } => vec![
            "admit-artifact".to_string(),
            "--input".to_string(),
            artifact_file,
            "--image-digest".to_string(),
            image_digest,
        ],
        OfflineUpgradeCommand::Preflight {
            target_version,
            image_digest,
        } => vec![
            "preflight".to_string(),
            "--version".to_string(),
            target_version,
            "--image-digest".to_string(),
            image_digest,
        ],
        OfflineUpgradeCommand::CreateAndVerifyBackup { passphrase_file } => vec![
            "backup-create-verify".to_string(),
            "--passphrase-file".to_string(),
            passphrase_file,
        ],
        OfflineUpgradeCommand::StageArtifact { image_digest } => vec![
            "stage-artifact".to_string(),
            "--image-digest".to_string(),
            image_digest,
        ],
        OfflineUpgradeCommand::DrainAndStop => vec!["drain-stop".to_string()],
        OfflineUpgradeCommand::SwitchToStagedArtifact => vec!["switch-staged".to_string()],
        OfflineUpgradeCommand::StartAndWaitReady => vec!["start-ready".to_string()],
        OfflineUpgradeCommand::Rollback {
            backup_id,
            previous_artifact_digest,
        } => vec![
            "rollback".to_string(),
            "--backup-id".to_string(),
            backup_id,
            "--previous-artifact-digest".to_string(),
            previous_artifact_digest,
        ],
    };
    UpgradeHelperInvocation {
        executable: PathBuf::from(SYSTEMD_UPGRADE_HELPER),
        arguments,
    }
}

fn parse_backup_receipt(stdout: &str) -> Result<OfflineUpgradeBackupReceipt, AppError> {
    let mut values = std::collections::BTreeMap::new();
    for line in stdout.lines() {
        let (key, value) = line.split_once('=').ok_or_else(command_result_error)?;
        if values.insert(key, value).is_some() {
            return Err(command_result_error());
        }
    }
    if values.len() != 2 {
        return Err(command_result_error());
    }
    let backup_id = values
        .remove("backup_id")
        .filter(|value| !value.is_empty())
        .ok_or_else(command_result_error)?
        .to_string();
    let previous_artifact_digest = values
        .remove("previous_artifact_digest")
        .filter(|value| is_sha256_digest(value))
        .ok_or_else(command_result_error)?
        .to_string();
    Ok(OfflineUpgradeBackupReceipt {
        backup_id,
        previous_artifact_digest,
    })
}

fn is_sha256_digest(value: &str) -> bool {
    let digest = value.strip_prefix("sha256:").unwrap_or(value);
    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

impl<R> CommandOfflineUpgradeDeployment<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }

    pub fn into_inner(self) -> R {
        self.runner
    }
}

impl<R: OfflineUpgradeCommandRunner> OfflineUpgradeDeployment
    for CommandOfflineUpgradeDeployment<R>
{
    fn admit_upgrade_artifact(
        &mut self,
        request: &edge_domain::OfflineUpgradeRequest,
    ) -> Result<(), AppError> {
        completed(
            self.runner
                .run_upgrade_command(OfflineUpgradeCommand::AdmitArtifact {
                    artifact_file: request.artifact_file.clone(),
                    image_digest: request.image_digest.clone(),
                })?,
        )
    }

    fn preflight_upgrade(
        &mut self,
        request: &edge_domain::OfflineUpgradeRequest,
    ) -> Result<(), AppError> {
        completed(
            self.runner
                .run_upgrade_command(OfflineUpgradeCommand::Preflight {
                    target_version: request.target_version.clone(),
                    image_digest: request.image_digest.clone(),
                })?,
        )
    }

    fn create_and_verify_upgrade_backup(
        &mut self,
        request: &edge_domain::OfflineUpgradeRequest,
    ) -> Result<OfflineUpgradeBackupReceipt, AppError> {
        match self
            .runner
            .run_upgrade_command(OfflineUpgradeCommand::CreateAndVerifyBackup {
                passphrase_file: request.passphrase_file.clone(),
            })? {
            OfflineUpgradeCommandResult::BackupCreated(receipt) => Ok(receipt),
            OfflineUpgradeCommandResult::Completed => Err(command_result_error()),
        }
    }

    fn stage_upgrade_artifact(
        &mut self,
        request: &edge_domain::OfflineUpgradeRequest,
    ) -> Result<(), AppError> {
        completed(
            self.runner
                .run_upgrade_command(OfflineUpgradeCommand::StageArtifact {
                    image_digest: request.image_digest.clone(),
                })?,
        )
    }

    fn drain_and_stop_service(&mut self) -> Result<(), AppError> {
        completed(
            self.runner
                .run_upgrade_command(OfflineUpgradeCommand::DrainAndStop)?,
        )
    }

    fn switch_to_staged_artifact(&mut self) -> Result<(), AppError> {
        completed(
            self.runner
                .run_upgrade_command(OfflineUpgradeCommand::SwitchToStagedArtifact)?,
        )
    }

    fn start_and_wait_ready(&mut self) -> Result<(), AppError> {
        completed(
            self.runner
                .run_upgrade_command(OfflineUpgradeCommand::StartAndWaitReady)?,
        )
    }

    fn rollback_upgrade(&mut self, receipt: &OfflineUpgradeBackupReceipt) -> Result<(), AppError> {
        completed(
            self.runner
                .run_upgrade_command(OfflineUpgradeCommand::Rollback {
                    backup_id: receipt.backup_id.clone(),
                    previous_artifact_digest: receipt.previous_artifact_digest.clone(),
                })?,
        )
    }
}

fn completed(result: OfflineUpgradeCommandResult) -> Result<(), AppError> {
    match result {
        OfflineUpgradeCommandResult::Completed => Ok(()),
        OfflineUpgradeCommandResult::BackupCreated(_) => Err(command_result_error()),
    }
}

fn command_result_error() -> AppError {
    AppError::new(
        ErrorCode::BackupStateTransitionInvalid,
        "upgrade command returned an unexpected result",
    )
}

impl FileOfflineUpgradeJournalStore {
    pub fn new(data_dir: impl AsRef<Path>) -> Result<Self, AppError> {
        let root = data_dir.as_ref();
        if root.as_os_str().is_empty() {
            return Err(error());
        }
        let journal = root.join("upgrade-journal");
        Ok(Self {
            temporary: root.join("upgrade-journal.tmp"),
            journal,
        })
    }
}

impl OfflineUpgradeJournalStore for FileOfflineUpgradeJournalStore {
    fn persist_upgrade_journal(&mut self, journal: &OfflineUpgradeJournal) -> Result<(), AppError> {
        journal.validate().map_err(|_| error())?;
        std::fs::create_dir_all(self.journal.parent().ok_or_else(error)?).map_err(|_| error())?;
        let body = format!(
            "version=1\noperation={}\nstate={}\nbackup={}\nprevious={}\ntarget={}\n",
            hex(journal.operation_id.as_bytes()),
            state_name(journal.state),
            hex(journal.backup_id.as_bytes()),
            journal.previous_artifact_digest,
            journal.target_artifact_digest
        );
        if self.temporary.exists() {
            std::fs::remove_file(&self.temporary).map_err(|_| error())?;
        }
        super::write_synced_owner_file(&self.temporary, body.as_bytes()).map_err(|_| error())?;
        std::fs::rename(&self.temporary, &self.journal).map_err(|_| error())?;
        sync_parent(&self.journal).map_err(|_| error())?;
        Ok(())
    }
    fn load_upgrade_journal(
        &mut self,
        operation_id: &str,
    ) -> Result<Option<OfflineUpgradeJournal>, AppError> {
        if !self.journal.exists() {
            return Ok(None);
        }
        let bytes = super::read_owner_file_nofollow(&self.journal, 4096).map_err(|_| error())?;
        let text = std::str::from_utf8(&bytes).map_err(|_| error())?;
        let mut values = std::collections::BTreeMap::new();
        for line in text.lines() {
            let (key, value) = line.split_once('=').ok_or_else(error)?;
            if values.insert(key, value).is_some() {
                return Err(error());
            }
        }
        if values.remove("version") != Some("1") || values.len() != 5 {
            return Err(error());
        }
        let state = match values.get("state").copied() {
            Some("prepared") => OfflineUpgradeState::Prepared,
            Some("draining") => OfflineUpgradeState::Draining,
            Some("stopped") => OfflineUpgradeState::Stopped,
            Some("switched") => OfflineUpgradeState::Switched,
            Some("ready") => OfflineUpgradeState::Ready,
            Some("committed") => OfflineUpgradeState::Committed,
            Some("rolling_back") => OfflineUpgradeState::RollingBack,
            Some("rolled_back") => OfflineUpgradeState::RolledBack,
            _ => return Err(error()),
        };
        let journal = OfflineUpgradeJournal {
            operation_id: decode(values.get("operation").copied().ok_or_else(error)?)?,
            state,
            backup_id: decode(values.get("backup").copied().ok_or_else(error)?)?,
            previous_artifact_digest: values
                .get("previous")
                .copied()
                .ok_or_else(error)?
                .to_string(),
            target_artifact_digest: values.get("target").copied().ok_or_else(error)?.to_string(),
        };
        journal.validate().map_err(|_| error())?;
        if journal.operation_id != operation_id {
            return Err(error());
        }
        Ok(Some(journal))
    }
}

fn state_name(state: OfflineUpgradeState) -> &'static str {
    match state {
        OfflineUpgradeState::Prepared => "prepared",
        OfflineUpgradeState::Draining => "draining",
        OfflineUpgradeState::Stopped => "stopped",
        OfflineUpgradeState::Switched => "switched",
        OfflineUpgradeState::Ready => "ready",
        OfflineUpgradeState::Committed => "committed",
        OfflineUpgradeState::RollingBack => "rolling_back",
        OfflineUpgradeState::RolledBack => "rolled_back",
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn decode(value: &str) -> Result<String, AppError> {
    if !value.len().is_multiple_of(2) {
        return Err(error());
    }
    let bytes = (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).map_err(|_| error()))
        .collect::<Result<Vec<_>, _>>()?;
    String::from_utf8(bytes).map_err(|_| error())
}
fn error() -> AppError {
    AppError::new(
        ErrorCode::BackupManifestInvalid,
        "upgrade journal is invalid",
    )
}

fn sync_parent(path: &Path) -> std::io::Result<()> {
    std::fs::File::open(
        path.parent()
            .ok_or_else(|| std::io::Error::other("missing journal parent"))?,
    )?
    .sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeProcessExecutor {
        invocations: Vec<UpgradeHelperInvocation>,
        exit_code: i32,
    }

    impl UpgradeHelperProcessExecutor for FakeProcessExecutor {
        fn execute_upgrade_helper(
            &mut self,
            invocation: UpgradeHelperInvocation,
        ) -> Result<UpgradeHelperProcessOutput, AppError> {
            let stdout = if invocation.arguments.first().map(String::as_str)
                == Some("backup-create-verify")
            {
                "backup_id=backup-1\nprevious_artifact_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n".to_string()
            } else {
                String::new()
            };
            self.invocations.push(invocation);
            Ok(UpgradeHelperProcessOutput {
                exit_code: self.exit_code,
                stdout,
            })
        }
    }

    #[derive(Default)]
    struct FakeCommandRunner {
        commands: Vec<OfflineUpgradeCommand>,
    }

    impl OfflineUpgradeCommandRunner for FakeCommandRunner {
        fn run_upgrade_command(
            &mut self,
            command: OfflineUpgradeCommand,
        ) -> Result<OfflineUpgradeCommandResult, AppError> {
            let result = match command {
                OfflineUpgradeCommand::CreateAndVerifyBackup { .. } => {
                    OfflineUpgradeCommandResult::BackupCreated(OfflineUpgradeBackupReceipt {
                        backup_id: "backup-1".to_string(),
                        previous_artifact_digest: "a".repeat(64),
                    })
                }
                _ => OfflineUpgradeCommandResult::Completed,
            };
            self.commands.push(command);
            Ok(result)
        }
    }

    fn root(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sponzey-edge-upgrade-journal-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }
    fn journal() -> OfflineUpgradeJournal {
        OfflineUpgradeJournal {
            operation_id: "upgrade-backup-1".into(),
            state: OfflineUpgradeState::Switched,
            backup_id: "backup-1".into(),
            previous_artifact_digest: "a".repeat(64),
            target_artifact_digest: "b".repeat(64),
        }
    }

    #[test]
    fn command_deployment_maps_secret_free_typed_commands() {
        let runner = FakeCommandRunner::default();
        let mut deployment = CommandOfflineUpgradeDeployment::new(runner);
        let request = edge_domain::OfflineUpgradeRequest {
            target_version: "v1.2.3".to_string(),
            image_digest: "b".repeat(64),
            artifact_file: "/root/edge-proxy-1.2.3".to_string(),
            passphrase_file: "/run/secrets/upgrade".to_string(),
        };
        deployment.admit_upgrade_artifact(&request).unwrap();
        deployment.preflight_upgrade(&request).unwrap();
        let backup = deployment
            .create_and_verify_upgrade_backup(&request)
            .unwrap();
        deployment.stage_upgrade_artifact(&request).unwrap();
        deployment.drain_and_stop_service().unwrap();
        deployment.switch_to_staged_artifact().unwrap();
        deployment.start_and_wait_ready().unwrap();
        deployment.rollback_upgrade(&backup).unwrap();
        assert_eq!(
            deployment.into_inner().commands,
            vec![
                OfflineUpgradeCommand::AdmitArtifact {
                    artifact_file: "/root/edge-proxy-1.2.3".to_string(),
                    image_digest: "b".repeat(64),
                },
                OfflineUpgradeCommand::Preflight {
                    target_version: "v1.2.3".to_string(),
                    image_digest: "b".repeat(64),
                },
                OfflineUpgradeCommand::CreateAndVerifyBackup {
                    passphrase_file: "/run/secrets/upgrade".to_string(),
                },
                OfflineUpgradeCommand::StageArtifact {
                    image_digest: "b".repeat(64),
                },
                OfflineUpgradeCommand::DrainAndStop,
                OfflineUpgradeCommand::SwitchToStagedArtifact,
                OfflineUpgradeCommand::StartAndWaitReady,
                OfflineUpgradeCommand::Rollback {
                    backup_id: "backup-1".to_string(),
                    previous_artifact_digest: "a".repeat(64),
                },
            ]
        );
    }

    #[test]
    fn systemd_helper_runner_uses_only_fixed_absolute_helper_invocations() {
        let executor = FakeProcessExecutor::default();
        let mut runner = SystemdUpgradeHelperRunner::new(executor);
        runner
            .run_upgrade_command(OfflineUpgradeCommand::AdmitArtifact {
                artifact_file: "/root/edge-proxy-1.2.3".to_string(),
                image_digest: "b".repeat(64),
            })
            .unwrap();
        let backup = match runner
            .run_upgrade_command(OfflineUpgradeCommand::CreateAndVerifyBackup {
                passphrase_file: "/run/secrets/upgrade".to_string(),
            })
            .unwrap()
        {
            OfflineUpgradeCommandResult::BackupCreated(value) => value,
            _ => panic!("expected backup receipt"),
        };
        runner
            .run_upgrade_command(OfflineUpgradeCommand::Rollback {
                backup_id: backup.backup_id,
                previous_artifact_digest: backup.previous_artifact_digest,
            })
            .unwrap();
        assert_eq!(
            runner.into_inner().invocations,
            vec![
                UpgradeHelperInvocation {
                    executable: PathBuf::from("/usr/local/libexec/sponzey-edge/upgrade-helper"),
                    arguments: vec![
                        "admit-artifact".to_string(),
                        "--input".to_string(),
                        "/root/edge-proxy-1.2.3".to_string(),
                        "--image-digest".to_string(),
                        "b".repeat(64),
                    ],
                },
                UpgradeHelperInvocation {
                    executable: PathBuf::from("/usr/local/libexec/sponzey-edge/upgrade-helper"),
                    arguments: vec![
                        "backup-create-verify".to_string(),
                        "--passphrase-file".to_string(),
                        "/run/secrets/upgrade".to_string(),
                    ],
                },
                UpgradeHelperInvocation {
                    executable: PathBuf::from("/usr/local/libexec/sponzey-edge/upgrade-helper"),
                    arguments: vec![
                        "rollback".to_string(),
                        "--backup-id".to_string(),
                        "backup-1".to_string(),
                        "--previous-artifact-digest".to_string(),
                        "a".repeat(64),
                    ],
                },
            ]
        );
    }

    #[test]
    fn systemd_helper_runner_rejects_non_zero_exit_before_returning_receipt() {
        let executor = FakeProcessExecutor {
            exit_code: 1,
            ..Default::default()
        };
        let mut runner = SystemdUpgradeHelperRunner::new(executor);
        assert_eq!(
            runner
                .run_upgrade_command(OfflineUpgradeCommand::DrainAndStop)
                .unwrap_err()
                .code,
            ErrorCode::RuntimeCommandRejected
        );
    }

    #[test]
    fn compose_helper_runner_uses_fixed_project_and_compose_file() {
        let executor = FakeProcessExecutor::default();
        let mut runner = ComposeUpgradeHelperRunner::new(executor);
        let result = runner
            .run_upgrade_command(OfflineUpgradeCommand::DrainAndStop)
            .unwrap();
        assert_eq!(result, OfflineUpgradeCommandResult::Completed);
        assert_eq!(
            runner.into_inner().invocations,
            vec![UpgradeHelperInvocation {
                executable: PathBuf::from("/usr/local/libexec/sponzey-edge/compose-upgrade-helper"),
                arguments: vec![
                    "--project-directory".to_string(),
                    "/etc/sponzey-edge/compose".to_string(),
                    "--file".to_string(),
                    "/etc/sponzey-edge/compose/docker-compose.yml".to_string(),
                    "drain-stop".to_string(),
                ],
            }]
        );
    }

    #[test]
    fn compose_helper_runner_rejects_non_zero_exit() {
        let executor = FakeProcessExecutor {
            exit_code: 1,
            ..Default::default()
        };
        let mut runner = ComposeUpgradeHelperRunner::new(executor);
        assert_eq!(
            runner
                .run_upgrade_command(OfflineUpgradeCommand::DrainAndStop)
                .unwrap_err()
                .code,
            ErrorCode::RuntimeCommandRejected
        );
    }
    #[test]
    fn file_upgrade_journal_round_trips_fixed_identity() {
        let root = root("round-trip");
        let mut store = FileOfflineUpgradeJournalStore::new(&root).unwrap();
        store.persist_upgrade_journal(&journal()).unwrap();
        assert_eq!(
            store.load_upgrade_journal("upgrade-backup-1").unwrap(),
            Some(journal())
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn file_upgrade_journal_rejects_corrupt_content() {
        let root = root("corrupt");
        let mut store = FileOfflineUpgradeJournalStore::new(&root).unwrap();
        std::fs::write(root.join("upgrade-journal"), b"version=1\nunknown=x\n").unwrap();
        assert!(store.load_upgrade_journal("upgrade-backup-1").is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn file_upgrade_journal_is_owner_only_after_durable_publish() {
        use std::os::unix::fs::PermissionsExt;

        let root = root("owner-only");
        let mut store = FileOfflineUpgradeJournalStore::new(&root).unwrap();
        store.persist_upgrade_journal(&journal()).unwrap();
        let mode = std::fs::metadata(root.join("upgrade-journal"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn file_upgrade_journal_rejects_non_file_temporary_path() {
        let root = root("temporary-directory");
        std::fs::create_dir(root.join("upgrade-journal.tmp")).unwrap();
        let mut store = FileOfflineUpgradeJournalStore::new(&root).unwrap();
        assert!(store.persist_upgrade_journal(&journal()).is_err());
        assert!(!root.join("upgrade-journal").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn file_upgrade_journal_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;
        let root = root("symlink");
        let outside = root
            .parent()
            .unwrap()
            .join("sponzey-edge-upgrade-journal-outside");
        std::fs::write(&outside, b"outside").unwrap();
        symlink(&outside, root.join("upgrade-journal")).unwrap();
        let mut store = FileOfflineUpgradeJournalStore::new(&root).unwrap();
        assert!(store.load_upgrade_journal("upgrade-backup-1").is_err());
        std::fs::remove_file(outside).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}
