mod admin_http;
mod bootstrap;
mod health_runtime;
mod process_mode;

use admin_http::{
    spawn_admin_http_server_with_mutations_and_logs, AdminHttpChallengeRuntime,
    AdminHttpRuntimeWiring, AdminHttpStores, AdminHttpSupportBundlePaths, AdminLogReceivers,
    Http01RuntimeProbe, SharedHttp01TokenStore, SharedOperationalRuntimeStatus,
    SharedRuntimeResourceStatus, SharedRuntimeUpstreamStatus,
};
use bootstrap::{
    acme_client_mode_from_env, bootstrap_config_from_env, dev_serve_config_from_env,
    ensure_data_layout, AcmeClientMode,
};
use edge_adapters::{
    load_rustls_server_config, spawn_metric_registry_collector, spawn_metrics_listener,
    stderr_json_log_sink, stdout_json_log_sink, AgeBackupArchiveReader, AgeBackupArchiveWriter,
    AuditLedgerOptions, CommandOfflineUpgradeDeployment, FakeAcmeClient, FileAuditLedger,
    FileBackupArtifactSource, FileBootstrapConfigSeed, FileCertificateStore,
    FileDataDirectoryLockManager, FileNewTargetRestorePublisher, FileOfflineUpgradeJournalStore,
    FileReplaceRestorePublisher, FileRestoreArchiveExtractor, FileRestorePreflight,
    FileRestoreProvenanceWriter, FileRestoreTransactionStore, FileRevisionRepository,
    FileSecretStore, FileTrustBundleStore, LetsEncryptHttp01AcmeClient, MetricChannelPublisher,
    PreparedHealthTlsRegistry, RandomOperationIdGenerator, RustlsClientTlsSessionFactory,
    RustlsServerTlsSessionFactory, Sha256BackupManifestDigester, SharedFileAuditLedger,
    SystemClock, SystemUpgradeHelperProcessExecutor, SystemdUpgradeHelperRunner,
    TlsRuntimeSnapshot, UpgradeHelperProcessExecutor,
};
#[cfg(test)]
use edge_application::parse_mvp_config;
use edge_application::{
    build_info_metric, certificate_expiry_metric, execute_journaled_offline_upgrade_with_receipt,
    initialize_audit_ledger, plan_upstream_tls_preparation, process_start_time_metric,
    recover_offline_upgrade, upstream_availability_metric, CreateBackupInput, CreateBackupUseCase,
    RecoverRestoreUseCase, ReplaceRestoreBackupInput, ReplaceRestoreBackupUseCase,
    ResolveStartupConfigUseCase, RestoreBackupInput, RestoreBackupUseCase, StartupConfigOrigin,
    TlsFailureObservation, TlsFailureProductSampler, VerifyBackupInput, VerifyBackupUseCase,
};
use edge_core::legacy_single_upstream::{run_single_upstream_proxy, SingleUpstreamProxyConfig};
use edge_core::snapshot_http::{
    run_snapshot_http_proxy_mio, runtime_command_channel, SnapshotProxyConfig,
    SnapshotRuntimeCommandClient,
};
use edge_core::{
    HttpLimits, PreparedClientTlsRegistry, PreparedServerTlsRegistry, ResourceLimits,
    UpstreamTarget,
};
use edge_domain::{
    AppError, AuditAction, AuditActorKind, AuditAdmissionState, AuditAuthoritativeFact,
    AuditContext, AuditOperationId, AuditRequestId, AuditTargetId, BootstrapConfig, CertificateRef,
    ClientAuthPolicy, CommandAck, ConfigRevisionId, ConfigSnapshot, CoreCommand, ErrorCode,
    ListenerProtocol, OperationalLifecycle, RuntimeResourcePolicy, TrustBundleRef,
};
use edge_ports::{
    AcmeClient, AuditAdmissionController, AuditAuthoritativeStateInspector, AuditLedgerReader,
    AuditLedgerVerifier, CertificateStore, CoreCommandClient, DataDirectoryLockManager, LogSink,
    MetricPublishOutcome, MetricPublisher, SecretStore, StartupConfigPreflight, StructuredLogEvent,
    TrustBundleReader,
};
#[cfg(test)]
use edge_ports::{ConfigRevisionRepository, MetricEvent};
use health_runtime::{HealthRuntimeController, HealthRuntimeObservability};
use process_mode::{parse_process_mode, ProbeOptions, ProbeTarget, ProcessMode};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
#[cfg(unix)]
use std::io::Read;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, RwLock};

const SIGTERM_DRAIN_DEADLINE_MS: u64 = 30_000;

#[cfg(unix)]
static SIGTERM_REQUESTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn handle_sigterm(_signal: libc::c_int) {
    // SAFETY: AtomicBool::store is lock-free on supported Unix targets and the
    // handler performs no allocation, I/O, locking, or command delivery.
    SIGTERM_REQUESTED.store(true, std::sync::atomic::Ordering::Relaxed);
}

fn main() -> std::io::Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let mode = parse_process_mode(&args).map_err(app_error_to_io)?;
    match mode {
        ProcessMode::Serve => run_serve(),
        ProcessMode::Probe(options) => std::process::exit(run_probe(options)),
        maintenance => run_maintenance(maintenance),
    }
}

fn run_maintenance(mode: ProcessMode) -> std::io::Result<()> {
    match mode {
        ProcessMode::BackupCreate(options) => run_backup_create(options),
        ProcessMode::BackupVerify(options) => run_backup_verify(options),
        ProcessMode::Restore(options) => {
            if options.replace {
                run_restore_replace(options)
            } else {
                run_restore_new_target(options)
            }
        }
        ProcessMode::RestoreRecover(options) => run_restore_recover(options),
        ProcessMode::AuditVerify(options) => run_audit_verify(options),
        ProcessMode::Upgrade(options) => run_upgrade(options),
        ProcessMode::UpgradeRecover(options) => run_upgrade_recover(options),
        ProcessMode::Probe(options) => std::process::exit(run_probe(options)),
        ProcessMode::Serve => run_serve(),
    }
}

fn run_upgrade(options: process_mode::UpgradeOptions) -> std::io::Result<()> {
    let receipt = run_upgrade_with_executor(options, SystemUpgradeHelperProcessExecutor)
        .map_err(app_error_to_io)?;
    println!(
        "{}",
        render_upgrade_result(&receipt.operation_id, receipt.state)
    );
    Ok(())
}

fn run_upgrade_with_executor<E: UpgradeHelperProcessExecutor>(
    options: process_mode::UpgradeOptions,
    executor: E,
) -> Result<edge_application::OfflineUpgradeExecutionReceipt, AppError> {
    let runner = SystemdUpgradeHelperRunner::new(executor);
    let mut deployment = CommandOfflineUpgradeDeployment::new(runner);
    let mut journals = FileOfflineUpgradeJournalStore::new(&options.data_dir)?;
    execute_journaled_offline_upgrade_with_receipt(&mut deployment, &mut journals, options.request)
}

fn run_upgrade_recover(options: process_mode::UpgradeRecoverOptions) -> std::io::Result<()> {
    let state =
        run_upgrade_recover_with_executor(options.clone(), SystemUpgradeHelperProcessExecutor)
            .map_err(app_error_to_io)?;
    println!("{}", render_upgrade_result(&options.operation_id, state));
    Ok(())
}

fn run_upgrade_recover_with_executor<E: UpgradeHelperProcessExecutor>(
    options: process_mode::UpgradeRecoverOptions,
    executor: E,
) -> Result<edge_domain::OfflineUpgradeState, AppError> {
    let runner = SystemdUpgradeHelperRunner::new(executor);
    let mut deployment = CommandOfflineUpgradeDeployment::new(runner);
    let mut journals = FileOfflineUpgradeJournalStore::new(&options.data_dir)?;
    recover_offline_upgrade(&mut deployment, &mut journals, &options.operation_id)
}

fn render_upgrade_result(operation_id: &str, state: edge_domain::OfflineUpgradeState) -> String {
    let state = match state {
        edge_domain::OfflineUpgradeState::Committed => "committed",
        edge_domain::OfflineUpgradeState::RolledBack => "rolled_back",
        _ => "incomplete",
    };
    serde_json::json!({ "result_schema_version": 1, "operation_id": operation_id, "state": state })
        .to_string()
}

fn run_probe(options: ProbeOptions) -> i32 {
    let address = match options.admin_bind.parse::<SocketAddr>() {
        Ok(address) if address.ip().is_loopback() => address,
        _ => return 2,
    };
    let path = match options.target {
        ProbeTarget::Live => "/api/v1/health/live",
        ProbeTarget::Ready => "/api/v1/health/ready",
    };
    let expected = match options.target {
        ProbeTarget::Live => "live",
        ProbeTarget::Ready => "ready",
    };
    let result = (|| -> std::io::Result<String> {
        use std::io::{Read, Write};
        let mut stream =
            std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_secs(2))?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
        stream.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response)
    })();
    match result {
        Ok(response)
            if response.starts_with("HTTP/1.1 200 ")
                && response.contains(&format!("\"status\":\"{expected}\"")) =>
        {
            0
        }
        Ok(response) if response.starts_with("HTTP/1.1 503 ") => 1,
        _ => 2,
    }
}

fn run_audit_verify(options: process_mode::AuditVerifyOptions) -> std::io::Result<()> {
    let audit_directory = options.data_dir.join("logs/audit");
    let has_segment = std::fs::read_dir(&audit_directory)
        .map(|entries| {
            entries.filter_map(Result::ok).any(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with("segment-") && name.ends_with(".audit"))
            })
        })
        .unwrap_or(false);
    if !has_segment {
        return Err(std::io::Error::other("AUDIT_UNAVAILABLE"));
    }
    let lock = FileDataDirectoryLockManager::new(&options.data_dir).map_err(app_error_to_io)?;
    let _guard = lock.try_acquire_exclusive().map_err(app_error_to_io)?;
    let mut ledger = FileAuditLedger::open(&options.data_dir, AuditLedgerOptions::default())
        .map_err(app_error_to_io)?;
    let report = ledger.verify().map_err(app_error_to_io)?;
    let incomplete = ledger.incomplete_operations().map_err(app_error_to_io)?;
    let unresolved = ledger
        .unresolved_reconciliations()
        .map_err(app_error_to_io)?;
    println!(
        "{}",
        serde_json::json!({
            "report_schema_version": 1,
            "generation": report.head.generation,
            "sequence": report.head.sequence,
            "record_count": report.record_count,
            "segment_count": report.segment_count,
            "incomplete_operation_count": incomplete.len(),
            "unresolved_reconciliation_count": unresolved.len(),
            "status": if unresolved.is_empty() { "verified" } else { "failed_closed" },
        })
    );
    if unresolved.is_empty() {
        Ok(())
    } else {
        Err(std::io::Error::other("AUDIT_RECONCILIATION_UNKNOWN"))
    }
}

fn run_restore_replace(options: process_mode::RestoreOptions) -> std::io::Result<()> {
    let passphrase = read_owner_only_passphrase(&options.passphrase_file)?;
    let lock =
        FileDataDirectoryLockManager::new(&options.target_data_dir).map_err(app_error_to_io)?;
    let mut extractor = FileRestoreArchiveExtractor::new(&options.input, &options.target_data_dir)
        .map_err(app_error_to_io)?;
    let stage = extractor.stage_path().to_path_buf();
    let mut preflight = FileRestorePreflight::new(&stage);
    let mut transactions =
        FileRestoreTransactionStore::new(&options.target_data_dir).map_err(app_error_to_io)?;
    let mut publisher = FileReplaceRestorePublisher::new(&options.target_data_dir, &stage)
        .map_err(app_error_to_io)?;
    let mut provenance = FileRestoreProvenanceWriter::new(&options.target_data_dir);
    let mut ids = RandomOperationIdGenerator;
    let mut logs = stderr_json_log_sink();
    let receipt = ReplaceRestoreBackupUseCase::new(
        &lock,
        &mut extractor,
        &mut preflight,
        &mut transactions,
        &mut publisher,
        &mut provenance,
        &SystemClock,
        &mut ids,
        &mut logs,
        edge_domain::BackupLimits::schema_v3(),
    )
    .execute(ReplaceRestoreBackupInput { passphrase })
    .map_err(app_error_to_io)?;
    print_restore_receipt(&receipt);
    Ok(())
}

fn run_restore_recover(options: process_mode::RestoreRecoverOptions) -> std::io::Result<()> {
    let lock =
        FileDataDirectoryLockManager::new(&options.target_data_dir).map_err(app_error_to_io)?;
    let _guard = lock.try_acquire_exclusive().map_err(app_error_to_io)?;
    let stage = restore_stage_path(&options.target_data_dir)?;
    let mut transactions =
        FileRestoreTransactionStore::new(&options.target_data_dir).map_err(app_error_to_io)?;
    let mut publisher = FileReplaceRestorePublisher::new(&options.target_data_dir, stage)
        .map_err(app_error_to_io)?;
    let mut provenance = FileRestoreProvenanceWriter::new(&options.target_data_dir);
    let mut logs = stderr_json_log_sink();
    let receipt = RecoverRestoreUseCase::new(
        &mut transactions,
        &mut publisher,
        &mut provenance,
        &SystemClock,
        &mut logs,
    )
    .execute(&options.operation_id)
    .map_err(app_error_to_io)?;
    println!(
        "{}",
        serde_json::json!({ "receipt_schema_version": 1, "operation_id": receipt.operation_id, "outcome": receipt.outcome })
    );
    Ok(())
}

fn restore_stage_path(target: &Path) -> std::io::Result<std::path::PathBuf> {
    let parent = target
        .parent()
        .ok_or_else(|| std::io::Error::other("RESTORE_TARGET_UNSAFE"))?;
    let name = target
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| std::io::Error::other("RESTORE_TARGET_UNSAFE"))?;
    Ok(parent.join(format!(".{name}.restore-stage")))
}

fn print_restore_receipt(receipt: &edge_application::RestoreReceipt) {
    println!(
        "{}",
        serde_json::json!({ "receipt_schema_version": 1, "operation_id": receipt.operation_id, "archive_id": receipt.archive_id, "restored_layout_version": receipt.restored_layout_version, "restored_revision_id": receipt.restored_revision_id.as_str(), "certificate_count": receipt.certificate_count, "trust_bundle_count": receipt.trust_bundle_count, "rollback_copy_created": receipt.rollback_copy_created, "commit_mode": receipt.commit_mode })
    );
}

fn run_restore_new_target(options: process_mode::RestoreOptions) -> std::io::Result<()> {
    let passphrase = read_owner_only_passphrase(&options.passphrase_file)?;
    let lock =
        FileDataDirectoryLockManager::new(&options.target_data_dir).map_err(app_error_to_io)?;
    let mut extractor = FileRestoreArchiveExtractor::new(&options.input, &options.target_data_dir)
        .map_err(app_error_to_io)?;
    let stage = extractor.stage_path().to_path_buf();
    let mut preflight = FileRestorePreflight::new(&stage);
    let mut publisher = FileNewTargetRestorePublisher::new(&stage, &options.target_data_dir);
    let mut provenance = FileRestoreProvenanceWriter::new(&options.target_data_dir);
    let mut ids = RandomOperationIdGenerator;
    let mut logs = stderr_json_log_sink();
    let receipt = RestoreBackupUseCase::new(
        &lock,
        &mut extractor,
        &mut preflight,
        &mut publisher,
        &mut provenance,
        &SystemClock,
        &mut ids,
        &mut logs,
        edge_domain::BackupLimits::schema_v3(),
    )
    .execute(RestoreBackupInput { passphrase })
    .map_err(app_error_to_io)?;
    print_restore_receipt(&receipt);
    Ok(())
}

fn run_backup_verify(options: process_mode::BackupVerifyOptions) -> std::io::Result<()> {
    let passphrase = read_owner_only_passphrase(&options.passphrase_file)?;
    let mut reader = AgeBackupArchiveReader::new(&options.input);
    let mut ids = RandomOperationIdGenerator;
    let mut logs = stderr_json_log_sink();
    let report = VerifyBackupUseCase::new(
        &mut reader,
        &Sha256BackupManifestDigester,
        &SystemClock,
        &mut ids,
        &mut logs,
        edge_domain::BackupLimits::schema_v3(),
    )
    .execute(VerifyBackupInput { passphrase })
    .map_err(app_error_to_io)?;
    println!(
        "{}",
        serde_json::json!({
            "report_schema_version": 1,
            "operation_id": report.operation_id,
            "archive_id": report.archive_id,
            "backup_schema_version": report.schema_version,
            "artifact_count": report.artifact_count,
            "total_bytes": report.total_bytes,
            "config_present": report.config_present,
            "revision_pointer_valid": report.revision_pointer_valid,
            "certificates_count": report.certificates_count,
            "referenced_certificates_count": report.referenced_certificates_count,
            "trust_bundles_count": report.trust_bundles_count,
            "referenced_trust_bundles_count": report.referenced_trust_bundles_count,
            "audit_segments_count": report.audit_segments_count,
            "admin_initialized": report.admin_initialized,
            "secrets_present": report.secrets_present,
            "compatible": report.compatible,
        })
    );
    Ok(())
}

fn run_backup_create(options: process_mode::BackupCreateOptions) -> std::io::Result<()> {
    let destination_identity = options
        .output
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| std::io::Error::other("BACKUP_DESTINATION_UNSAFE"))?
        .to_string();
    let passphrase = read_owner_only_passphrase(&options.passphrase_file)?;
    let lock = FileDataDirectoryLockManager::new(&options.data_dir).map_err(app_error_to_io)?;
    let mut source = FileBackupArtifactSource::new(&options.data_dir);
    let mut writer = AgeBackupArchiveWriter::new(&options.output).map_err(app_error_to_io)?;
    let mut ids = RandomOperationIdGenerator;
    let mut logs = stderr_json_log_sink();
    let receipt = CreateBackupUseCase::new(
        &lock,
        &mut source,
        &Sha256BackupManifestDigester,
        &mut writer,
        &SystemClock,
        &mut ids,
        &mut logs,
        edge_domain::BackupLimits::schema_v3(),
    )
    .execute(CreateBackupInput {
        source_app_version: env!("CARGO_PKG_VERSION").to_string(),
        destination_identity,
        passphrase,
    })
    .map_err(app_error_to_io)?;
    println!(
        "{}",
        serde_json::json!({
            "receipt_schema_version": 1,
            "operation_id": receipt.operation_id,
            "archive_id": receipt.archive_id,
            "backup_schema_version": receipt.schema_version,
            "artifact_count": receipt.artifact_count,
            "plaintext_bytes": receipt.plaintext_bytes,
            "encrypted_bytes": receipt.encrypted_bytes,
            "created_at_epoch_seconds": receipt.created_at_epoch_seconds,
            "destination_identity": receipt.destination_identity,
            "current_revision_id": receipt.current_revision_id.as_str(),
            "source_fingerprint": receipt.source_fingerprint,
        })
    );
    Ok(())
}

fn read_owner_only_passphrase(path: &Path) -> std::io::Result<edge_domain::SensitiveString> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| std::io::Error::other("BACKUP_SECRET_INPUT_INVALID"))?;
        let metadata = file
            .metadata()
            .map_err(|_| std::io::Error::other("BACKUP_SECRET_INPUT_INVALID"))?;
        if !metadata.is_file() {
            return Err(std::io::Error::other("BACKUP_SECRET_INPUT_INVALID"));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(std::io::Error::other("BACKUP_SECRET_INPUT_INVALID"));
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let mut value = String::from_utf8(bytes)
            .map_err(|_| std::io::Error::other("BACKUP_SECRET_INPUT_INVALID"))?;
        if value.ends_with('\n') {
            value.pop();
            if value.ends_with('\r') {
                value.pop();
            }
        }
        edge_domain::SensitiveString::new(value).map_err(app_error_to_io)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(std::io::Error::other("BACKUP_SECRET_INPUT_INVALID"))
    }
}

struct StartupAuditAdmission(AuditAdmissionState);

impl AuditAdmissionController for StartupAuditAdmission {
    fn state(&self) -> AuditAdmissionState {
        self.0
    }

    fn replace_state(&mut self, state: AuditAdmissionState) {
        self.0 = state;
    }
}

struct FailClosedAuditInspector;

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

fn run_serve() -> std::io::Result<()> {
    let config = bootstrap_config_from_env();
    let acme_client_mode = acme_client_mode_from_env()?;
    ensure_data_layout(&config.data_dir)?;
    let lock_manager =
        FileDataDirectoryLockManager::new(&config.data_dir).map_err(app_error_to_io)?;
    let _data_directory_lock = lock_manager
        .try_acquire_exclusive()
        .map_err(app_error_to_io)?;
    let startup_epoch_seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| std::io::Error::other("system clock before epoch"))?
        .as_secs();
    let recovery_context = AuditContext {
        operation_id: AuditOperationId::parse(format!("startup-recovery-{startup_epoch_seconds}"))
            .map_err(|error| std::io::Error::other(error.as_str()))?,
        request_id: AuditRequestId::parse(format!("startup-{startup_epoch_seconds}"))
            .map_err(|error| std::io::Error::other(error.as_str()))?,
        actor_kind: AuditActorKind::SystemRecovery,
        received_at_epoch_seconds: startup_epoch_seconds,
    };
    let mut audit_ledger = FileAuditLedger::open(
        &config.data_dir,
        AuditLedgerOptions::default().with_recovery_context(recovery_context),
    )
    .map_err(app_error_to_io)?;
    let mut audit_admission = StartupAuditAdmission(AuditAdmissionState::Starting);
    let mut audit_inspector = FailClosedAuditInspector;
    let audit_startup = initialize_audit_ledger(
        &mut audit_ledger,
        &mut audit_inspector,
        &mut audit_admission,
    )
    .map_err(app_error_to_io)?;
    let shared_audit = SharedFileAuditLedger::new(audit_ledger, audit_startup.admission_state);
    let mut product_log = stdout_json_log_sink();
    record_audit_startup_log(&mut product_log, &audit_startup).map_err(app_error_to_io)?;
    record_process_start_log(&mut product_log, &config, acme_client_mode)
        .map_err(app_error_to_io)?;
    println!(
        "edge-proxy bootstrap ok: data_dir={}, config_file={}, admin_bind={}, log_mode={}, acme_client={}",
        config.data_dir,
        config.config_file,
        config.admin_bind,
        config.log_mode.as_str(),
        acme_client_mode.as_str()
    );

    if let Some(serve) = dev_serve_config_from_env() {
        let upstream = UpstreamTarget::parse_http(&serve.upstream_url).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{}: {}", error.code.as_str(), error.message),
            )
        })?;
        println!(
            "edge-proxy dev serving: listen={}, upstream={}",
            serve.listen, serve.upstream_url
        );
        run_single_upstream_proxy(SingleUpstreamProxyConfig {
            listen: serve.listen,
            upstream,
            limits: HttpLimits::default(),
        })?;
    } else if let Some(proxy_runtime) =
        startup_proxy_config_from_file(&config.config_file, &config.data_dir)?
    {
        record_startup_config_resolution_log(
            &mut product_log,
            proxy_runtime.origin,
            &proxy_runtime.revision_id,
        )
        .map_err(app_error_to_io)?;
        let StartupProxyRuntime {
            http,
            https,
            tls,
            origin: _,
            revision_id: _,
        } = proxy_runtime;
        let admin_snapshot = http.snapshot.clone();
        let health_snapshot = admin_snapshot.clone();
        let metrics_config = admin_snapshot.runtime.metrics.clone();
        let admin_bind = admin_snapshot.admin.bind.clone();
        let operational_lifecycle = Arc::new(std::sync::Mutex::new(OperationalLifecycle::Ready));
        let shared_https_snapshot = Arc::new(RwLock::new(admin_snapshot.clone()));
        let admin_password_hash = load_optional_admin_password_hash(&config.data_dir)?;
        let admin_secrets = FileSecretStore::new(Path::new(&config.data_dir).join("secrets"));
        let admin_revisions =
            FileRevisionRepository::new(Path::new(&config.data_dir).join("config"));
        let admin_certificates =
            FileCertificateStore::new(Path::new(&config.data_dir).join("certs"));
        let (admin_command_client, runtime_commands) = runtime_command_channel(128);
        let runtime_tls_installer = admin_command_client.clone();
        let health_command_client = admin_command_client.clone();
        let (access_log_sender, access_log_receiver) = std::sync::mpsc::sync_channel(1024);
        let (error_log_sender, error_log_receiver) = std::sync::mpsc::sync_channel(1024);
        let (metric_sender, metric_receiver) = std::sync::mpsc::sync_channel(1024);
        let (health_log_sender, health_log_receiver) = std::sync::mpsc::sync_channel(256);
        install_sigterm_drain_watcher(
            admin_command_client.clone(),
            Arc::clone(&operational_lifecycle),
            health_log_sender.clone(),
        )?;
        let (tls_failure_sender, tls_failure_receiver) = std::sync::mpsc::sync_channel(256);
        let metric_publisher: Arc<dyn MetricPublisher> =
            Arc::new(MetricChannelPublisher::new(metric_sender.clone()));
        let (metric_snapshot, _metric_collector) =
            spawn_metric_registry_collector(metric_receiver, Some(health_log_sender.clone()));
        record_process_identity_metrics(
            metric_publisher.as_ref(),
            env!("CARGO_PKG_VERSION"),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|error| {
                    std::io::Error::other(format!("system clock before epoch: {error}"))
                })?
                .as_secs(),
        )
        .map_err(app_error_to_io)?;
        let _metrics_listener = spawn_metrics_listener(
            &metrics_config,
            metric_snapshot.clone(),
            Some(health_log_sender.clone()),
        )?;
        let log_drop_counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let runtime_status = SharedRuntimeUpstreamStatus::with_observability(
            health_log_sender.clone(),
            Arc::clone(&metric_publisher),
            std::sync::Arc::clone(&log_drop_counter),
        );
        let resource_status = SharedRuntimeResourceStatus::default();
        let operational_runtime_status = SharedOperationalRuntimeStatus::default();
        let mut runtime_trust_store =
            FileTrustBundleStore::new(Path::new(&config.data_dir).join("trust-bundles"));
        let prepared_tls = prepare_tls_runtime_generation(
            &admin_snapshot,
            &https,
            tls.as_ref(),
            &mut runtime_trust_store,
        )
        .map_err(app_error_to_io)?;
        record_upstream_tls_prepared_log(
            &mut product_log,
            &admin_snapshot.revision_id,
            prepared_tls.request_registry.len(),
        )
        .map_err(app_error_to_io)?;
        let PreparedTlsRuntimeGeneration {
            request_registry,
            health_registry,
            https_listeners: prepared_https_listeners,
        } = prepared_tls;
        let health_runtime = HealthRuntimeController::new_with_observability_and_tls(
            health_command_client,
            HealthRuntimeObservability::new(
                health_log_sender.clone(),
                Arc::clone(&metric_publisher),
                std::sync::Arc::clone(&log_drop_counter),
            ),
            health_registry,
        );
        let initial_health = health_runtime
            .prepare(health_snapshot)
            .map_err(app_error_to_io)?;
        for (key, availability) in &initial_health.availability().entries {
            publish_required_metric(
                metric_publisher.as_ref(),
                upstream_availability_metric(key, *availability),
            )
            .map_err(app_error_to_io)?;
        }
        health_runtime
            .commit(initial_health)
            .map_err(app_error_to_io)?;
        let http01_tokens = SharedHttp01TokenStore::default();
        let http01_probe = Http01RuntimeProbe::new(http.listen);
        record_startup_certificate_expiry_metrics(&admin_certificates, metric_publisher.as_ref())
            .map_err(app_error_to_io)?;
        let mut proxy_config = http
            .with_client_tls_registry(request_registry)
            .with_challenge_responder(http01_tokens.clone())
            .with_runtime_commands(runtime_commands)
            .with_access_log_sender(access_log_sender)
            .with_error_log_sender(error_log_sender)
            .with_tls_failure_sender(tls_failure_sender)
            .with_metric_publisher(Arc::clone(&metric_publisher))
            .with_product_log_sender(health_log_sender.clone())
            .with_passive_observation_dispatcher(health_runtime.clone())
            .with_runtime_status_publisher(runtime_status.clone())
            .with_resource_status_publisher(resource_status.clone())
            .with_operational_runtime_status_publisher(operational_runtime_status.clone())
            .with_log_drop_counter(std::sync::Arc::clone(&log_drop_counter));
        let _health_log_collector = spawn_product_log_collector(health_log_receiver);
        let _tls_failure_log_collector = spawn_tls_failure_log_collector(tls_failure_receiver);
        let shared_tls_snapshot = tls.map(|tls| Arc::new(RwLock::new(tls)));
        for listener in prepared_https_listeners {
            proxy_config = proxy_config.with_https_listener(listener.bind, listener.factory);
        }
        let _admin_http = spawn_admin_http_server_with_mutations_and_logs(
            &admin_bind,
            admin_snapshot,
            admin_password_hash,
            AdminHttpStores {
                secrets: admin_secrets,
                revisions: admin_revisions,
                certificates: admin_certificates,
                trust_bundles: FileTrustBundleStore::new(
                    Path::new(&config.data_dir).join("trust-bundles"),
                ),
            },
            AdminHttpRuntimeWiring {
                acme_client: acme_client_for_mode(acme_client_mode),
                challenge_runtime: AdminHttpChallengeRuntime {
                    tokens: http01_tokens,
                    probe: http01_probe,
                },
                command_client: MirroredSnapshotCommandClient::new(
                    admin_command_client,
                    shared_https_snapshot,
                )
                .with_health_runtime(health_runtime.clone())
                .with_tls_install(
                    FileCertificateStore::new(Path::new(&config.data_dir).join("certs")),
                    shared_tls_snapshot,
                )
                .with_trust_bundles(FileTrustBundleStore::new(
                    Path::new(&config.data_dir).join("trust-bundles"),
                ))
                .with_runtime_tls_installer(runtime_tls_installer),
                health_status_reader: std::sync::Arc::new(health_runtime.clone()),
                runtime_status_reader: std::sync::Arc::new(runtime_status),
                resource_status_reader: std::sync::Arc::new(resource_status),
                metrics_reader: std::sync::Arc::new(metric_snapshot),
                operational_lifecycle: Arc::clone(&operational_lifecycle),
                operational_runtime_status_reader: std::sync::Arc::new(operational_runtime_status),
                product_log: Box::new(stdout_json_log_sink()),
                log_receivers: AdminLogReceivers {
                    access: access_log_receiver,
                    error: error_log_receiver,
                    dropped: log_drop_counter,
                },
                audit_ledger: shared_audit,
                support_bundle_paths: AdminHttpSupportBundlePaths {
                    source_root: Path::new(&config.data_dir).join("support"),
                    output: Path::new(&config.data_dir)
                        .join("support")
                        .join("latest.tar"),
                },
            },
        )?;
        println!("edge-proxy admin api listening: bind={admin_bind}");
        println!(
            "edge-proxy serving snapshot from config: listen={}",
            proxy_config.listen
        );
        let proxy_result = run_snapshot_http_proxy_mio(proxy_config);
        if let Ok(mut lifecycle) = operational_lifecycle.lock() {
            *lifecycle =
                lifecycle.transition(edge_domain::OperationalLifecycleEvent::DrainCompleted);
        }
        health_runtime.shutdown();
        proxy_result?;
    }

    Ok(())
}

#[cfg(unix)]
fn install_sigterm_drain_watcher(
    mut command_client: SnapshotRuntimeCommandClient,
    lifecycle: Arc<std::sync::Mutex<OperationalLifecycle>>,
    product_log: std::sync::mpsc::SyncSender<StructuredLogEvent>,
) -> std::io::Result<()> {
    SIGTERM_REQUESTED.store(false, std::sync::atomic::Ordering::Relaxed);
    // SAFETY: the handler is an extern C function with the required signature;
    // it only stores to SIGTERM_REQUESTED, which the watcher consumes outside
    // signal context.
    unsafe {
        libc::signal(
            libc::SIGTERM,
            handle_sigterm as *const () as libc::sighandler_t,
        );
    }
    std::thread::spawn(move || loop {
        if SIGTERM_REQUESTED.swap(false, std::sync::atomic::Ordering::Relaxed) {
            begin_sigterm_drain(&mut command_client, &lifecycle, &product_log);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    });
    Ok(())
}

fn begin_sigterm_drain<C>(
    command_client: &mut C,
    lifecycle: &Arc<std::sync::Mutex<OperationalLifecycle>>,
    product_log: &std::sync::mpsc::SyncSender<StructuredLogEvent>,
) where
    C: CoreCommandClient,
{
    if let Ok(mut current) = lifecycle.lock() {
        *current = current.transition(edge_domain::OperationalLifecycleEvent::TerminationRequested);
    }
    let acknowledgement = command_client.send(CoreCommand::BeginDrain {
        deadline_ms: SIGTERM_DRAIN_DEADLINE_MS,
    });
    if !acknowledgement.is_success() {
        if let Ok(mut current) = lifecycle.lock() {
            *current = current.transition(edge_domain::OperationalLifecycleEvent::Failed);
        }
        let _ = product_log.try_send(StructuredLogEvent {
            component: "edge-proxy".to_string(),
            event: "process.drain.command_rejected".to_string(),
            fields: vec![(
                "error_code".to_string(),
                "RUNTIME_COMMAND_REJECTED".to_string(),
            )],
        });
    }
}

#[cfg(not(unix))]
fn install_sigterm_drain_watcher(
    _command_client: SnapshotRuntimeCommandClient,
    _lifecycle: Arc<std::sync::Mutex<OperationalLifecycle>>,
    _product_log: std::sync::mpsc::SyncSender<StructuredLogEvent>,
) -> std::io::Result<()> {
    Ok(())
}

fn acme_client_for_mode(mode: AcmeClientMode) -> Box<dyn AcmeClient + Send> {
    match mode {
        AcmeClientMode::Fake => Box::new(FakeAcmeClient::default()),
        AcmeClientMode::LetsEncryptStaging => Box::new(LetsEncryptHttp01AcmeClient::new()),
    }
}

fn startup_proxy_config_from_file(
    path: &str,
    data_dir: &str,
) -> std::io::Result<Option<StartupProxyRuntime>> {
    let mut revisions = FileRevisionRepository::new(Path::new(data_dir).join("config"));
    let mut seed = FileBootstrapConfigSeed::new(path);
    let certificates = FileCertificateStore::new(Path::new(data_dir).join("certs"));
    let mut preflight = StartupTlsPreflight {
        certificates: &certificates,
    };
    let Some(resolved) =
        ResolveStartupConfigUseCase::new(&mut revisions, &mut seed, &mut preflight)
            .execute()
            .map_err(app_error_to_io)?
    else {
        return Ok(None);
    };
    let revision_id = resolved.snapshot.revision_id.clone();
    let origin = resolved.origin;
    let tls = prepare_tls_runtime_snapshot_for_snapshot(&resolved.snapshot, &certificates)
        .map_err(app_error_to_io)?;
    let https = https_listener_configs(&resolved.snapshot)?;
    let http = first_http_proxy_config(resolved.snapshot)?;
    Ok(Some(StartupProxyRuntime {
        http,
        https,
        tls,
        origin,
        revision_id,
    }))
}

struct StartupProxyRuntime {
    http: SnapshotProxyConfig,
    https: Vec<StartupHttpsListener>,
    tls: Option<TlsRuntimeSnapshot>,
    origin: StartupConfigOrigin,
    revision_id: ConfigRevisionId,
}

#[derive(Clone)]
struct StartupHttpsListener {
    bind: SocketAddr,
    client_auth: ClientAuthPolicy,
}

#[derive(Clone)]
struct PreparedHttpsListener {
    bind: SocketAddr,
    factory: RustlsServerTlsSessionFactory,
}

struct StartupTlsPreflight<'a, S> {
    certificates: &'a S,
}

impl<S> StartupConfigPreflight for StartupTlsPreflight<'_, S>
where
    S: CertificateStore,
{
    fn preflight(&mut self, snapshot: &ConfigSnapshot) -> Result<(), AppError> {
        prepare_tls_runtime_snapshot_for_snapshot(snapshot, self.certificates).map(|_| ())
    }
}

fn load_optional_admin_password_hash(data_dir: &str) -> std::io::Result<Option<String>> {
    let store = FileSecretStore::new(Path::new(data_dir).join("secrets"));
    let secret = store
        .load_secret("admin-password-hash")
        .map_err(app_error_to_io)?;
    Ok(secret.map(|secret| secret.value))
}

fn prepare_tls_runtime_snapshot_for_snapshot<S>(
    snapshot: &ConfigSnapshot,
    certificates: &S,
) -> Result<Option<TlsRuntimeSnapshot>, AppError>
where
    S: CertificateStore + ?Sized,
{
    if !snapshot
        .listeners
        .iter()
        .any(|listener| listener.protocol == ListenerProtocol::Https)
    {
        return Ok(None);
    }

    let certificate_refs = https_certificate_refs(snapshot);
    if certificate_refs.is_empty() {
        return Err(AppError::new(
            ErrorCode::CertificateNotFound,
            "HTTPS listener requires at least one route certificate_ref",
        ));
    }

    let mut loaded = Vec::new();
    for certificate_ref in certificate_refs {
        let certificate = certificates
            .load_certificate(&certificate_ref)?
            .ok_or_else(|| {
                AppError::new(
                    ErrorCode::CertificateNotFound,
                    format!("certificate not found: {}", certificate_ref.as_str()),
                )
            })?;
        loaded.push(load_rustls_server_config(&certificate)?);
    }
    TlsRuntimeSnapshot::from_configs(loaded).map(Some)
}

fn https_certificate_refs(snapshot: &ConfigSnapshot) -> Vec<CertificateRef> {
    let mut refs = BTreeSet::new();
    for route in snapshot.routes.iter().filter(|route| route.enabled) {
        if let Some(certificate_ref) = &route.certificate_ref {
            refs.insert(certificate_ref.clone());
        }
    }
    refs.into_iter().collect()
}

fn https_listener_configs(snapshot: &ConfigSnapshot) -> std::io::Result<Vec<StartupHttpsListener>> {
    let https_listeners: Vec<_> = snapshot
        .listeners
        .iter()
        .filter(|listener| listener.protocol == ListenerProtocol::Https)
        .collect();
    if https_listeners.is_empty() {
        return Ok(Vec::new());
    }

    https_listeners
        .into_iter()
        .map(|listener| {
            let bind = listener.bind.parse::<SocketAddr>().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "HTTPS listener bind is invalid",
                )
            })?;
            Ok(StartupHttpsListener {
                bind,
                client_auth: listener.client_auth.clone(),
            })
        })
        .collect()
}

#[cfg(test)]
fn prepare_https_listener_factories<R>(
    listeners: &[StartupHttpsListener],
    tls: &TlsRuntimeSnapshot,
    trust_reader: &mut R,
) -> Result<Vec<PreparedHttpsListener>, AppError>
where
    R: TrustBundleReader,
{
    let mut cache = TrustBundleCache::new(trust_reader);
    prepare_https_listener_factories_with_cache(listeners, tls, &mut cache)
}

fn prepare_https_listener_factories_with_cache<R>(
    listeners: &[StartupHttpsListener],
    tls: &TlsRuntimeSnapshot,
    trust_cache: &mut TrustBundleCache<'_, R>,
) -> Result<Vec<PreparedHttpsListener>, AppError>
where
    R: TrustBundleReader,
{
    let no_client_auth = RustlsServerTlsSessionFactory::new(tls.sni_server_config()?);
    let mut required_factories = BTreeMap::<TrustBundleRef, RustlsServerTlsSessionFactory>::new();
    let mut prepared = Vec::with_capacity(listeners.len());
    for listener in listeners {
        let factory = match &listener.client_auth {
            ClientAuthPolicy::Disabled => no_client_auth.clone(),
            ClientAuthPolicy::Required { trust_bundle_ref } => {
                if let Some(factory) = required_factories.get(trust_bundle_ref) {
                    factory.clone()
                } else {
                    let bundle = trust_cache.load(trust_bundle_ref)?;
                    let factory = RustlsServerTlsSessionFactory::new(
                        tls.sni_server_config_with_required_client_auth(&bundle)?,
                    );
                    required_factories.insert(trust_bundle_ref.clone(), factory.clone());
                    factory
                }
            }
        };
        prepared.push(PreparedHttpsListener {
            bind: listener.bind,
            factory,
        });
    }
    Ok(prepared)
}

struct TrustBundleCache<'a, R> {
    reader: &'a mut R,
    bundles: BTreeMap<TrustBundleRef, edge_ports::ValidatedTrustBundle>,
}

impl<'a, R> TrustBundleCache<'a, R>
where
    R: TrustBundleReader,
{
    fn new(reader: &'a mut R) -> Self {
        Self {
            reader,
            bundles: BTreeMap::new(),
        }
    }

    fn load(
        &mut self,
        reference: &TrustBundleRef,
    ) -> Result<edge_ports::ValidatedTrustBundle, AppError> {
        if let Some(bundle) = self.bundles.get(reference) {
            return Ok(bundle.clone());
        }
        let bundle = self.reader.load_trust_bundle(reference)?.ok_or_else(|| {
            AppError::new(
                ErrorCode::ConfigTrustBundleNotFound,
                "configured trust bundle was not found",
            )
        })?;
        self.bundles.insert(reference.clone(), bundle.clone());
        Ok(bundle)
    }
}

struct MirroredSnapshotCommandClient<C> {
    inner: C,
    snapshot: Arc<RwLock<ConfigSnapshot>>,
    tls_install: Option<TlsInstallState>,
    runtime_tls_installer: Option<SnapshotRuntimeCommandClient>,
    health_runtime: Option<HealthRuntimeController<C>>,
}

struct TlsInstallState {
    certificates: FileCertificateStore,
    tls: Option<Arc<RwLock<TlsRuntimeSnapshot>>>,
    trust_bundles: Option<FileTrustBundleStore>,
}

impl<C> MirroredSnapshotCommandClient<C> {
    fn new(inner: C, snapshot: Arc<RwLock<ConfigSnapshot>>) -> Self {
        Self {
            inner,
            snapshot,
            tls_install: None,
            runtime_tls_installer: None,
            health_runtime: None,
        }
    }

    fn with_tls_install(
        mut self,
        certificates: FileCertificateStore,
        tls: Option<Arc<RwLock<TlsRuntimeSnapshot>>>,
    ) -> Self {
        self.tls_install = Some(TlsInstallState {
            certificates,
            tls,
            trust_bundles: None,
        });
        self
    }

    fn with_trust_bundles(mut self, trust_bundles: FileTrustBundleStore) -> Self {
        if let Some(install) = self.tls_install.as_mut() {
            install.trust_bundles = Some(trust_bundles);
        }
        self
    }

    fn with_runtime_tls_installer(mut self, installer: SnapshotRuntimeCommandClient) -> Self {
        self.runtime_tls_installer = Some(installer);
        self
    }

    fn with_health_runtime(mut self, runtime: HealthRuntimeController<C>) -> Self {
        self.health_runtime = Some(runtime);
        self
    }

    fn load_tls_install_config(
        &self,
        certificate_ref: &CertificateRef,
    ) -> Result<Option<edge_adapters::LoadedRustlsServerConfig>, AppError> {
        let Some(install) = &self.tls_install else {
            return Ok(None);
        };
        if install.tls.is_none() {
            return Ok(None);
        }

        let certificate = install
            .certificates
            .load_certificate(certificate_ref)?
            .ok_or_else(|| {
                AppError::new(
                    ErrorCode::CertificateNotFound,
                    format!("certificate not found: {}", certificate_ref.as_str()),
                )
            })?;
        load_rustls_server_config(&certificate).map(Some)
    }
}

impl<C> CoreCommandClient for MirroredSnapshotCommandClient<C>
where
    C: CoreCommandClient + Clone + Send + 'static,
{
    fn send(&mut self, command: CoreCommand) -> CommandAck {
        let current_snapshot = match self.snapshot.read() {
            Ok(snapshot) => snapshot.clone(),
            Err(_) => {
                return CommandAck::rejected(AppError::new(
                    ErrorCode::RuntimeCommandRejected,
                    "config snapshot lock poisoned",
                ))
            }
        };
        let mirror_snapshot = match &command {
            CoreCommand::ApplyConfigSnapshot { snapshot } => Some(snapshot.clone()),
            _ => None,
        };
        let tls_install_config = match &command {
            CoreCommand::InstallCertificate { certificate_ref } => {
                match self.load_tls_install_config(certificate_ref) {
                    Ok(config) => config,
                    Err(error) => return CommandAck::rejected(error),
                }
            }
            _ => None,
        };
        let apply_tls_snapshot = match (&command, self.tls_install.as_ref()) {
            (CoreCommand::ApplyConfigSnapshot { snapshot }, Some(install))
                if install.tls.is_some() =>
            {
                match prepare_tls_runtime_snapshot_for_snapshot(snapshot, &install.certificates) {
                    Ok(snapshot) => snapshot,
                    Err(error) => return CommandAck::rejected(error),
                }
            }
            _ => None,
        };
        let mut next_tls_snapshot = apply_tls_snapshot;
        if let Some(config) = tls_install_config {
            let guard = match self
                .tls_install
                .as_ref()
                .and_then(|install| install.tls.as_ref())
                .expect("TLS install config exists only when TLS snapshot exists")
                .read()
            {
                Ok(guard) => guard,
                Err(_) => {
                    return CommandAck::rejected(AppError::new(
                        ErrorCode::RuntimeCommandRejected,
                        "tls snapshot lock poisoned",
                    ))
                }
            };
            let mut candidate = guard.clone();
            if let Err(error) = candidate.replace_config(config) {
                return CommandAck::rejected(error);
            }
            next_tls_snapshot = Some(candidate);
        }
        let install_snapshot = if matches!(&command, CoreCommand::InstallCertificate { .. }) {
            Some(current_snapshot.clone())
        } else {
            None
        };
        let prepared_generation = match (&command, self.tls_install.as_mut()) {
            (CoreCommand::ApplyConfigSnapshot { snapshot }, Some(install)) => {
                if let Some(trust_bundles) = install.trust_bundles.as_mut() {
                    let listeners = match https_listener_configs(snapshot) {
                        Ok(listeners) => listeners,
                        Err(_) => {
                            return CommandAck::rejected(AppError::new(
                                ErrorCode::ConfigInvalidBindAddress,
                                "HTTPS listener bind is invalid",
                            ))
                        }
                    };
                    match prepare_tls_runtime_generation(
                        snapshot,
                        &listeners,
                        next_tls_snapshot.as_ref(),
                        trust_bundles,
                    ) {
                        Ok(generation) => Some(generation),
                        Err(error) => return CommandAck::rejected(error),
                    }
                } else {
                    None
                }
            }
            (CoreCommand::InstallCertificate { .. }, Some(install)) => {
                if let Some(trust_bundles) = install.trust_bundles.as_mut() {
                    let snapshot = install_snapshot
                        .as_ref()
                        .expect("install command captured current snapshot");
                    let listeners = match https_listener_configs(snapshot) {
                        Ok(listeners) => listeners,
                        Err(_) => {
                            return CommandAck::rejected(AppError::new(
                                ErrorCode::ConfigInvalidBindAddress,
                                "HTTPS listener bind is invalid",
                            ))
                        }
                    };
                    match prepare_tls_runtime_generation(
                        snapshot,
                        &listeners,
                        next_tls_snapshot.as_ref(),
                        trust_bundles,
                    ) {
                        Ok(generation) => Some(generation),
                        Err(error) => return CommandAck::rejected(error),
                    }
                } else {
                    None
                }
            }
            _ => None,
        };
        let rollback_generation = match (&command, self.tls_install.as_mut()) {
            (CoreCommand::ApplyConfigSnapshot { .. }, Some(install))
                if prepared_generation.is_some() =>
            {
                let current_tls = match install.tls.as_ref() {
                    Some(tls) => match tls.read() {
                        Ok(tls) => Some(tls.clone()),
                        Err(_) => {
                            return CommandAck::rejected(AppError::new(
                                ErrorCode::RuntimeCommandRejected,
                                "tls snapshot lock poisoned",
                            ))
                        }
                    },
                    None => None,
                };
                let listeners = match https_listener_configs(&current_snapshot) {
                    Ok(listeners) => listeners,
                    Err(_) => {
                        return CommandAck::rejected(AppError::new(
                            ErrorCode::ConfigInvalidBindAddress,
                            "HTTPS listener bind is invalid",
                        ))
                    }
                };
                let trust_bundles = install
                    .trust_bundles
                    .as_mut()
                    .expect("candidate generation requires trust store");
                match prepare_tls_runtime_generation(
                    &current_snapshot,
                    &listeners,
                    current_tls.as_ref(),
                    trust_bundles,
                ) {
                    Ok(generation) => Some(generation),
                    Err(error) => return CommandAck::rejected(error),
                }
            }
            _ => None,
        };
        let prepared_health = match (&command, self.health_runtime.as_ref()) {
            (CoreCommand::ApplyConfigSnapshot { snapshot }, Some(runtime)) => {
                let prepared = if let Some(generation) = prepared_generation.as_ref() {
                    runtime.prepare_with_tls_registry(
                        snapshot.clone(),
                        generation.health_registry.clone(),
                    )
                } else {
                    runtime.prepare(snapshot.clone())
                };
                match prepared {
                    Ok(prepared) => Some(prepared),
                    Err(error) => return CommandAck::rejected(error),
                }
            }
            _ => None,
        };
        let rollback_health = match (self.health_runtime.as_ref(), rollback_generation.as_ref()) {
            (Some(runtime), Some(generation)) => match runtime.prepare_with_tls_registry(
                current_snapshot.clone(),
                generation.health_registry.clone(),
            ) {
                Ok(prepared) => Some(prepared),
                Err(error) => return CommandAck::rejected(error),
            },
            _ => None,
        };
        let activation_availability = prepared_health
            .as_ref()
            .map(|prepared| prepared.availability().clone());
        let mut combined_tls_apply = false;
        let ack = if let (CoreCommand::InstallCertificate { .. }, Some(generation)) =
            (&command, prepared_generation.as_ref())
        {
            let Some(installer) = self.runtime_tls_installer.as_mut() else {
                return CommandAck::rejected(AppError::new(
                    ErrorCode::RuntimeCommandRejected,
                    "prepared TLS generation requires the runtime command boundary",
                ));
            };
            let server_registry = match generation.server_registry() {
                Ok(registry) => registry,
                Err(error) => return CommandAck::rejected(error),
            };
            combined_tls_apply = true;
            installer.install_server_tls_registry(server_registry)
        } else if let (
            CoreCommand::ApplyConfigSnapshot { snapshot },
            Some(generation),
            Some(installer),
            Some(availability),
        ) = (
            &command,
            prepared_generation.as_ref(),
            self.runtime_tls_installer.as_mut(),
            activation_availability.as_ref(),
        ) {
            let server_registry = match generation.server_registry() {
                Ok(registry) => registry,
                Err(error) => return CommandAck::rejected(error),
            };
            combined_tls_apply = true;
            installer.activate_runtime_generation(
                snapshot.clone(),
                availability.clone(),
                server_registry,
                generation.request_registry.clone(),
            )
        } else if prepared_generation.is_some() {
            CommandAck::rejected(AppError::new(
                ErrorCode::RuntimeCommandRejected,
                "prepared TLS generation requires the runtime command boundary",
            ))
        } else if let (
            CoreCommand::ApplyConfigSnapshot { snapshot },
            Some(candidate),
            Some(installer),
            Some(availability),
        ) = (
            &command,
            next_tls_snapshot.as_ref(),
            self.runtime_tls_installer.as_mut(),
            activation_availability.as_ref(),
        ) {
            let server_config = match candidate.sni_server_config() {
                Ok(config) => config,
                Err(error) => return CommandAck::rejected(error),
            };
            combined_tls_apply = true;
            installer.activate_snapshot_with_tls_session_factory(
                snapshot.clone(),
                availability.clone(),
                RustlsServerTlsSessionFactory::new(server_config),
            )
        } else if let (CoreCommand::ApplyConfigSnapshot { snapshot }, Some(availability)) =
            (&command, activation_availability.as_ref())
        {
            self.inner.send(CoreCommand::ActivateConfigSnapshot {
                snapshot: snapshot.clone(),
                availability: availability.clone(),
            })
        } else {
            self.inner.send(command)
        };
        if ack.is_success() {
            if let (Some(runtime), Some(prepared)) = (self.health_runtime.as_ref(), prepared_health)
            {
                let commit = if let Some(generation) = prepared_generation.as_ref() {
                    runtime.commit_with_tls_registry(prepared, generation.health_registry.clone())
                } else {
                    runtime.commit(prepared)
                };
                if let Err(error) = commit {
                    let compensation = match (
                        self.runtime_tls_installer.as_mut(),
                        rollback_generation.as_ref(),
                        rollback_health.as_ref(),
                    ) {
                        (Some(installer), Some(generation), Some(rollback_health)) => {
                            match generation.server_registry() {
                                Ok(server_registry) => installer.activate_runtime_generation(
                                    current_snapshot.clone(),
                                    rollback_health.availability().clone(),
                                    server_registry,
                                    generation.request_registry.clone(),
                                ),
                                Err(compensation_error) => CommandAck::rejected(compensation_error),
                            }
                        }
                        _ => CommandAck::rejected(AppError::new(
                            ErrorCode::RuntimeCommandRejected,
                            "runtime generation compensation was not prepared",
                        )),
                    };
                    if !compensation.is_success() {
                        return CommandAck::rejected(AppError::new(
                            ErrorCode::RuntimeCommandRejected,
                            "runtime generation compensation failed",
                        ));
                    }
                    if let (Some(runtime), Some(prepared), Some(generation)) = (
                        self.health_runtime.as_ref(),
                        rollback_health,
                        rollback_generation.as_ref(),
                    ) {
                        if runtime
                            .commit_with_tls_registry(prepared, generation.health_registry.clone())
                            .is_err()
                        {
                            return CommandAck::rejected(AppError::new(
                                ErrorCode::RuntimeCommandRejected,
                                "health runtime compensation failed",
                            ));
                        }
                    }
                    return CommandAck::rejected(error);
                }
            }
            if !combined_tls_apply {
                if let (Some(installer), Some(snapshot)) = (
                    self.runtime_tls_installer.as_mut(),
                    next_tls_snapshot.as_ref(),
                ) {
                    let server_config = match snapshot.sni_server_config() {
                        Ok(config) => config,
                        Err(error) => return CommandAck::rejected(error),
                    };
                    let runtime_ack = installer.install_tls_session_factory(
                        RustlsServerTlsSessionFactory::new(server_config),
                    );
                    if !runtime_ack.is_success() {
                        return runtime_ack;
                    }
                }
            }
            if let Some(snapshot) = mirror_snapshot {
                if let Ok(mut current) = self.snapshot.write() {
                    *current = snapshot;
                }
            }
            if let (Some(snapshot), Some(tls)) = (
                next_tls_snapshot,
                self.tls_install
                    .as_ref()
                    .and_then(|install| install.tls.as_ref()),
            ) {
                match tls.write() {
                    Ok(mut current) => *current = snapshot,
                    Err(_) => {
                        return CommandAck::rejected(AppError::new(
                            ErrorCode::RuntimeCommandRejected,
                            "tls snapshot lock poisoned",
                        ))
                    }
                }
            }
        }
        ack
    }
}

fn spawn_product_log_collector(
    receiver: std::sync::mpsc::Receiver<StructuredLogEvent>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut sink = stdout_json_log_sink();
        while let Ok(event) = receiver.recv() {
            let _ = sink.record_log(event);
        }
    })
}

fn spawn_tls_failure_log_collector(
    receiver: std::sync::mpsc::Receiver<TlsFailureObservation>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut sampler = TlsFailureProductSampler::new(60, 256);
        let mut sink = stdout_json_log_sink();
        while let Ok(observation) = receiver.recv() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0);
            if let Some(event) = sampler.observe(observation, now) {
                let _ = sink.record_log(event);
            }
        }
    })
}

fn record_startup_certificate_expiry_metrics<C>(
    certificates: &C,
    publisher: &dyn MetricPublisher,
) -> Result<(), edge_domain::AppError>
where
    C: CertificateStore + ?Sized,
{
    for certificate in certificates.list_certificates()? {
        if publisher.try_publish(certificate_expiry_metric(&certificate))
            == MetricPublishOutcome::Stopped
        {
            return Err(AppError::new(
                ErrorCode::InternalBug,
                "metric collector stopped during startup",
            ));
        }
    }
    Ok(())
}

fn record_process_identity_metrics(
    publisher: &dyn MetricPublisher,
    version: &str,
    process_start_epoch_seconds: u64,
) -> Result<(), edge_domain::AppError> {
    publish_required_metric(publisher, build_info_metric(version))?;
    publish_required_metric(
        publisher,
        process_start_time_metric(process_start_epoch_seconds),
    )
}

fn publish_required_metric(
    publisher: &dyn MetricPublisher,
    metric: edge_ports::MetricEvent,
) -> Result<(), edge_domain::AppError> {
    match publisher.try_publish(metric) {
        MetricPublishOutcome::Accepted => Ok(()),
        MetricPublishOutcome::Full => Err(AppError::new(
            ErrorCode::InternalBug,
            "metric queue full during required startup publication",
        )),
        MetricPublishOutcome::Stopped => Err(AppError::new(
            ErrorCode::InternalBug,
            "metric collector stopped during required startup publication",
        )),
    }
}

fn record_audit_startup_log<L>(
    sink: &mut L,
    output: &edge_application::InitializeAuditLedgerOutput,
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

fn record_process_start_log<L>(
    sink: &mut L,
    config: &BootstrapConfig,
    acme_client_mode: AcmeClientMode,
) -> Result<(), edge_domain::AppError>
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

fn record_startup_config_resolution_log<L>(
    sink: &mut L,
    origin: StartupConfigOrigin,
    revision_id: &ConfigRevisionId,
) -> Result<(), edge_domain::AppError>
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

fn record_upstream_tls_prepared_log<L>(
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

pub(crate) fn app_error_to_io(error: edge_domain::AppError) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("{}: {}", error.code.as_str(), error.message),
    )
}

fn first_http_proxy_config(snapshot: ConfigSnapshot) -> std::io::Result<SnapshotProxyConfig> {
    let listener = snapshot
        .listeners
        .iter()
        .find(|listener| listener.protocol == ListenerProtocol::Http)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no HTTP listener"))?;
    let listen = listener.bind.parse().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "listener bind is invalid")
    })?;

    let http_limits = http_limits_for_snapshot(&snapshot);
    let resource_limits = resource_limits_for_snapshot(&snapshot);
    let resource_policy = RuntimeResourcePolicy::try_new(
        snapshot.runtime.max_connections,
        snapshot.runtime.max_inflight_payload_bytes,
    )
    .map_err(app_error_to_io)?;

    Ok(SnapshotProxyConfig::new(listen, snapshot, http_limits)
        .with_resource_limits(resource_limits)
        .with_resource_policy(resource_policy))
}

struct PreparedUpstreamTlsRuntime {
    request_registry: PreparedClientTlsRegistry,
    health_registry: PreparedHealthTlsRegistry,
}

#[cfg(test)]
fn prepare_upstream_tls_runtime<R>(
    snapshot: &ConfigSnapshot,
    reader: &mut R,
) -> Result<PreparedUpstreamTlsRuntime, AppError>
where
    R: TrustBundleReader,
{
    let mut cache = TrustBundleCache::new(reader);
    prepare_upstream_tls_runtime_with_cache(snapshot, &mut cache)
}

fn prepare_upstream_tls_runtime_with_cache<R>(
    snapshot: &ConfigSnapshot,
    trust_cache: &mut TrustBundleCache<'_, R>,
) -> Result<PreparedUpstreamTlsRuntime, AppError>
where
    R: TrustBundleReader,
{
    let requirements = plan_upstream_tls_preparation(snapshot)?;
    let mut factories =
        BTreeMap::<edge_domain::TrustBundleRef, RustlsClientTlsSessionFactory>::new();
    let mut registry = PreparedClientTlsRegistry::new();
    let mut health_registry = PreparedHealthTlsRegistry::new();
    for requirement in requirements {
        let factory = if let Some(factory) = factories.get(&requirement.trust_bundle_ref) {
            factory.clone()
        } else {
            let bundle = trust_cache.load(&requirement.trust_bundle_ref)?;
            let factory = RustlsClientTlsSessionFactory::from_trust_bundle(&bundle)?;
            factories.insert(requirement.trust_bundle_ref.clone(), factory.clone());
            factory
        };
        registry.insert(
            requirement.service_id.clone(),
            requirement.upstream_id.clone(),
            factory.clone(),
        )?;
        health_registry.insert(
            edge_domain::UpstreamHealthKey {
                service_id: requirement.service_id,
                upstream_id: requirement.upstream_id,
            },
            factory,
        )?;
    }
    Ok(PreparedUpstreamTlsRuntime {
        request_registry: registry,
        health_registry,
    })
}

struct PreparedTlsRuntimeGeneration {
    request_registry: PreparedClientTlsRegistry,
    health_registry: PreparedHealthTlsRegistry,
    https_listeners: Vec<PreparedHttpsListener>,
}

impl PreparedTlsRuntimeGeneration {
    fn server_registry(&self) -> Result<PreparedServerTlsRegistry, AppError> {
        let mut registry = PreparedServerTlsRegistry::new();
        for listener in &self.https_listeners {
            registry.insert(listener.bind, listener.factory.clone())?;
        }
        Ok(registry)
    }
}

fn prepare_tls_runtime_generation<R>(
    snapshot: &ConfigSnapshot,
    https_listeners: &[StartupHttpsListener],
    tls: Option<&TlsRuntimeSnapshot>,
    reader: &mut R,
) -> Result<PreparedTlsRuntimeGeneration, AppError>
where
    R: TrustBundleReader,
{
    let mut cache = TrustBundleCache::new(reader);
    let upstream = prepare_upstream_tls_runtime_with_cache(snapshot, &mut cache)?;
    let https_listeners = if https_listeners.is_empty() {
        Vec::new()
    } else {
        let tls = tls.ok_or_else(|| {
            AppError::new(
                ErrorCode::CertificateNotFound,
                "HTTPS listener requires a prepared TLS certificate snapshot",
            )
        })?;
        prepare_https_listener_factories_with_cache(https_listeners, tls, &mut cache)?
    };
    Ok(PreparedTlsRuntimeGeneration {
        request_registry: upstream.request_registry,
        health_registry: upstream.health_registry,
        https_listeners,
    })
}

pub(crate) fn http_limits_for_snapshot(snapshot: &ConfigSnapshot) -> HttpLimits {
    HttpLimits {
        max_header_bytes: snapshot.runtime.max_request_header_bytes,
        max_body_bytes: snapshot.runtime.max_request_body_bytes,
        ..HttpLimits::default()
    }
}

fn resource_limits_for_snapshot(snapshot: &ConfigSnapshot) -> ResourceLimits {
    ResourceLimits {
        max_connections: snapshot.runtime.max_connections,
        max_request_header_bytes: snapshot.runtime.max_request_header_bytes,
        max_request_body_bytes: snapshot.runtime.max_request_body_bytes,
        upstream_read_timeout: std::time::Duration::from_millis(
            snapshot.runtime.upstream_read_timeout_ms,
        ),
        ..ResourceLimits::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_domain::LogMode;
    use std::io::{Read, Write};

    #[derive(Default)]
    struct FakeUpgradeHelper {
        invocations: Vec<edge_adapters::UpgradeHelperInvocation>,
        fail: bool,
    }

    impl edge_adapters::UpgradeHelperProcessExecutor for FakeUpgradeHelper {
        fn execute_upgrade_helper(
            &mut self,
            invocation: edge_adapters::UpgradeHelperInvocation,
        ) -> Result<edge_adapters::UpgradeHelperProcessOutput, AppError> {
            let stdout = if invocation.arguments.first().map(String::as_str)
                == Some("backup-create-verify")
            {
                "backup_id=backup-1\nprevious_artifact_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n".to_string()
            } else {
                String::new()
            };
            self.invocations.push(invocation);
            Ok(edge_adapters::UpgradeHelperProcessOutput {
                exit_code: if self.fail { 1 } else { 0 },
                stdout,
            })
        }
    }

    fn upgrade_options(root: std::path::PathBuf) -> process_mode::UpgradeOptions {
        process_mode::UpgradeOptions {
            data_dir: root,
            request: edge_domain::OfflineUpgradeRequest {
                target_version: "v1.2.3".to_string(),
                image_digest: "b".repeat(64),
                artifact_file: "/root/edge-proxy-1.2.3".to_string(),
                passphrase_file: "/run/secrets/upgrade".to_string(),
            },
        }
    }

    #[test]
    fn upgrade_maintenance_wires_journaled_helper_commands_without_serve_mode() {
        let root = temp_root("upgrade-maintenance");
        let result =
            run_upgrade_with_executor(upgrade_options(root.clone()), FakeUpgradeHelper::default());
        assert_eq!(
            result.unwrap(),
            edge_application::OfflineUpgradeExecutionReceipt {
                operation_id: "upgrade-backup-1".to_string(),
                state: edge_domain::OfflineUpgradeState::Committed,
            }
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn upgrade_helper_failure_returns_stable_error_before_runtime_is_started() {
        let root = temp_root("upgrade-helper-failure");
        let error = run_upgrade_with_executor(
            upgrade_options(root.clone()),
            FakeUpgradeHelper {
                fail: true,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::RuntimeCommandRejected);
        assert!(!root.join("upgrade-journal").exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn upgrade_recover_uses_the_same_fixed_helper_and_journal_boundary() {
        let root = temp_root("upgrade-recover");
        let mut journals = FileOfflineUpgradeJournalStore::new(&root).unwrap();
        edge_ports::OfflineUpgradeJournalStore::persist_upgrade_journal(
            &mut journals,
            &edge_domain::OfflineUpgradeJournal {
                operation_id: "upgrade-backup-1".to_string(),
                state: edge_domain::OfflineUpgradeState::Switched,
                backup_id: "backup-1".to_string(),
                previous_artifact_digest: "a".repeat(64),
                target_artifact_digest: "b".repeat(64),
            },
        )
        .unwrap();
        let state = run_upgrade_recover_with_executor(
            process_mode::UpgradeRecoverOptions {
                data_dir: root.clone(),
                operation_id: "upgrade-backup-1".to_string(),
            },
            FakeUpgradeHelper::default(),
        )
        .unwrap();
        assert_eq!(state, edge_domain::OfflineUpgradeState::RolledBack);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn upgrade_result_is_bounded_and_does_not_expose_path_references() {
        let result = render_upgrade_result(
            "upgrade-backup-1",
            edge_domain::OfflineUpgradeState::Committed,
        );
        assert_eq!(
            result,
            "{\"operation_id\":\"upgrade-backup-1\",\"result_schema_version\":1,\"state\":\"committed\"}"
        );
        assert!(!result.contains("/root/"));
        assert!(!result.contains("passphrase"));
    }

    #[cfg(unix)]
    #[test]
    fn sigterm_handler_only_sets_the_watcher_flag() {
        SIGTERM_REQUESTED.store(false, std::sync::atomic::Ordering::Relaxed);
        handle_sigterm(libc::SIGTERM);
        assert!(SIGTERM_REQUESTED.swap(false, std::sync::atomic::Ordering::Relaxed));
    }

    fn temp_root(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "sponzey-edge-proxy-{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn audit_verify_requires_an_existing_ledger_and_accepts_a_verified_ledger() {
        let root = temp_root("audit-verify");
        let missing = run_audit_verify(process_mode::AuditVerifyOptions {
            data_dir: root.clone(),
        })
        .unwrap_err();
        assert_eq!(missing.to_string(), "AUDIT_UNAVAILABLE");
        assert!(!root.join("logs/audit").exists());

        let ledger = FileAuditLedger::open(&root, AuditLedgerOptions::default()).unwrap();
        drop(ledger);
        run_audit_verify(process_mode::AuditVerifyOptions {
            data_dir: root.clone(),
        })
        .unwrap();

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn backup_passphrase_reader_requires_owner_only_regular_file() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_root("backup-passphrase-permissions");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("passphrase");
        std::fs::write(&path, "private passphrase\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let secret = read_owner_only_passphrase(&path).unwrap();
        assert_eq!(
            secret.expose(|value| value.to_string()),
            "private passphrase"
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_owner_only_passphrase(&path).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn backup_passphrase_reader_rejects_symlink() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_root("backup-passphrase-symlink");
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("target");
        let alias = root.join("alias");
        std::fs::write(&target, "private passphrase").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&target, &alias).unwrap();

        assert!(read_owner_only_passphrase(&alias).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn derives_proxy_config_from_minimal_file_snapshot() {
        let source = include_str!("../../../examples/minimal.toml");
        let mut parsed = parse_mvp_config(source, ConfigRevisionId::new("file-current")).unwrap();
        parsed.snapshot.runtime.max_connections = 100;
        parsed.snapshot.runtime.max_inflight_payload_bytes = 32 * 1024 * 1024;

        let proxy = first_http_proxy_config(parsed.snapshot).unwrap();

        assert_eq!(proxy.listen.to_string(), "0.0.0.0:8080");
        assert_eq!(proxy.resource_policy.max_connections(), 100);
        assert_eq!(
            proxy.resource_policy.max_inflight_payload_bytes(),
            32 * 1024 * 1024
        );
        assert_eq!(
            proxy.resource_limits.upstream_read_timeout,
            std::time::Duration::from_millis(edge_domain::DEFAULT_UPSTREAM_READ_TIMEOUT_MS)
        );
    }

    #[test]
    fn rejects_invalid_runtime_resource_policy_before_proxy_start() {
        let source = include_str!("../../../examples/minimal.toml");
        let mut parsed = parse_mvp_config(source, ConfigRevisionId::new("invalid-resource"))
            .unwrap()
            .snapshot;
        parsed.runtime.max_connections = 0;

        let error = match first_http_proxy_config(parsed) {
            Ok(_) => panic!("invalid resource policy must be rejected"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("CONFIG_RESOURCE_LIMIT_INVALID"));
    }

    #[test]
    fn startup_imports_valid_primary_config_into_file_revision_store() {
        let root = temp_root("startup-import");
        ensure_data_layout(root.to_str().unwrap()).unwrap();
        let config_path = root.join("config/current.toml");
        std::fs::write(&config_path, include_str!("../../../examples/minimal.toml")).unwrap();

        let proxy =
            startup_proxy_config_from_file(config_path.to_str().unwrap(), root.to_str().unwrap())
                .unwrap()
                .unwrap();

        let current = std::fs::read_to_string(root.join("config/current")).unwrap();
        let revisions = std::fs::read_dir(root.join("config/revisions"))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(proxy.http.listen.to_string(), "0.0.0.0:8080");
        assert!(proxy.https.is_empty());
        assert!(proxy.tls.is_none());
        assert_eq!(current, "bootstrap-seed");
        assert_eq!(
            revisions
                .iter()
                .filter(
                    |entry| entry.path().extension().and_then(|value| value.to_str())
                        == Some("toml")
                )
                .count(),
            1
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_uses_repository_current_after_admin_apply_instead_of_stale_seed() {
        let root = temp_root("startup-repository-current");
        ensure_data_layout(root.to_str().unwrap()).unwrap();
        let config_path = root.join("config/current.toml");
        std::fs::write(&config_path, include_str!("../../../examples/minimal.toml")).unwrap();

        startup_proxy_config_from_file(config_path.to_str().unwrap(), root.to_str().unwrap())
            .unwrap()
            .unwrap();

        let mut snapshot = parse_mvp_config(
            include_str!("../../../examples/minimal.toml"),
            ConfigRevisionId::new("admin-applied"),
        )
        .unwrap()
        .snapshot;
        snapshot.runtime.max_connections = 100;
        snapshot.runtime.max_inflight_payload_bytes = 32 * 1024 * 1024;
        let revision = edge_domain::ConfigRevision {
            id: snapshot.revision_id.clone(),
            schema_version: snapshot.schema_version,
            summary: "admin apply".to_string(),
        };
        let mut revisions = FileRevisionRepository::new(root.join("config"));
        revisions
            .save_revision(edge_ports::RevisionRecord {
                revision,
                checksum: edge_application::checksum_snapshot(&snapshot),
                snapshot,
            })
            .unwrap();
        revisions
            .set_current(&ConfigRevisionId::new("admin-applied"))
            .unwrap();

        let runtime =
            startup_proxy_config_from_file(config_path.to_str().unwrap(), root.to_str().unwrap())
                .unwrap()
                .unwrap();

        assert_eq!(runtime.origin, StartupConfigOrigin::RevisionCurrent);
        assert_eq!(runtime.revision_id.as_str(), "admin-applied");
        assert_eq!(runtime.http.snapshot.revision_id.as_str(), "admin-applied");
        assert_eq!(runtime.http.resource_policy.max_connections(), 100);
        assert_eq!(
            runtime.http.resource_policy.max_inflight_payload_bytes(),
            32 * 1024 * 1024
        );
        assert_eq!(
            std::fs::read_to_string(root.join("config/current")).unwrap(),
            "admin-applied"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_rejects_dangling_current_pointer_instead_of_reimporting_seed() {
        let root = temp_root("startup-dangling-current");
        ensure_data_layout(root.to_str().unwrap()).unwrap();
        let config_path = root.join("config/current.toml");
        std::fs::write(&config_path, include_str!("../../../examples/minimal.toml")).unwrap();
        std::fs::write(root.join("config/current"), "missing-revision").unwrap();

        let error = match startup_proxy_config_from_file(
            config_path.to_str().unwrap(),
            root.to_str().unwrap(),
        ) {
            Ok(_) => panic!("startup unexpectedly reimported a dangling repository"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("CONFIG_CURRENT_REVISION_MISSING"));
        assert_eq!(
            std::fs::read_to_string(root.join("config/current")).unwrap(),
            "missing-revision"
        );
        assert!(std::fs::read_dir(root.join("config/revisions"))
            .unwrap()
            .next()
            .is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_preloads_https_tls_configs_before_runtime_start() {
        let root = temp_root("startup-https-preload");
        ensure_data_layout(root.to_str().unwrap()).unwrap();
        let config_path = root.join("config/current.toml");
        std::fs::write(&config_path, https_config_source("cert-example")).unwrap();
        let mut certificates = FileCertificateStore::new(root.join("certs"));
        certificates
            .save_certificate(test_certificate("cert-example"))
            .unwrap();

        let proxy =
            startup_proxy_config_from_file(config_path.to_str().unwrap(), root.to_str().unwrap())
                .unwrap()
                .unwrap();

        assert_eq!(proxy.http.listen.to_string(), "0.0.0.0:8080");
        assert_eq!(proxy.https.len(), 1);
        let tls = proxy.tls.expect("TLS runtime snapshot");
        assert_eq!(tls.len(), 1);
        assert!(tls.get(&CertificateRef::new("cert-example")).is_some());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn phase009_https_listener_preparation_loads_required_trust_once_and_preserves_disabled() {
        use edge_ports::{TrustBundleMaterialValidator, ValidatedTrustBundle};

        struct CountingTrustReader {
            bundle: Option<ValidatedTrustBundle>,
            loads: usize,
        }
        impl TrustBundleReader for CountingTrustReader {
            fn load_trust_bundle(
                &mut self,
                trust_bundle_ref: &TrustBundleRef,
            ) -> Result<Option<ValidatedTrustBundle>, AppError> {
                self.loads += 1;
                Ok(self
                    .bundle
                    .as_ref()
                    .filter(|bundle| &bundle.metadata.trust_bundle_ref == trust_bundle_ref)
                    .cloned())
            }
        }

        let certificate = test_certificate("cert-example");
        let tls =
            TlsRuntimeSnapshot::from_configs(
                vec![load_rustls_server_config(&certificate).unwrap()],
            )
            .unwrap();
        let fixture = PrivatePkiFixture::new("operator.private.test");
        let reference = TrustBundleRef::parse("private-client-root").unwrap();
        let bundle = edge_adapters::RustlsTrustBundleMaterialValidator
            .validate_trust_bundle(&reference, fixture.root_pem.as_bytes(), 10)
            .unwrap();
        let required = ClientAuthPolicy::Required {
            trust_bundle_ref: reference.clone(),
        };
        let listeners = vec![
            StartupHttpsListener {
                bind: "127.0.0.1:8443".parse().unwrap(),
                client_auth: ClientAuthPolicy::Disabled,
            },
            StartupHttpsListener {
                bind: "127.0.0.1:9443".parse().unwrap(),
                client_auth: required.clone(),
            },
            StartupHttpsListener {
                bind: "127.0.0.1:10443".parse().unwrap(),
                client_auth: required,
            },
        ];
        let mut reader = CountingTrustReader {
            bundle: Some(bundle),
            loads: 0,
        };

        let prepared = prepare_https_listener_factories(&listeners, &tls, &mut reader).unwrap();

        assert_eq!(prepared.len(), 3);
        assert_eq!(reader.loads, 1);
        assert_eq!(prepared[0].bind, listeners[0].bind);

        let mut missing = CountingTrustReader {
            bundle: None,
            loads: 0,
        };
        let error = prepare_https_listener_factories(&listeners[1..2], &tls, &mut missing)
            .err()
            .expect("missing required trust must reject preparation");
        assert_eq!(error.code, ErrorCode::ConfigTrustBundleNotFound);
    }

    #[test]
    fn phase009_tls_generation_reads_shared_inbound_outbound_root_once() {
        use edge_ports::{TrustBundleMaterialValidator, ValidatedTrustBundle};

        struct CountingTrustReader {
            bundle: ValidatedTrustBundle,
            loads: usize,
        }
        impl TrustBundleReader for CountingTrustReader {
            fn load_trust_bundle(
                &mut self,
                reference: &TrustBundleRef,
            ) -> Result<Option<ValidatedTrustBundle>, AppError> {
                self.loads += 1;
                Ok((&self.bundle.metadata.trust_bundle_ref == reference)
                    .then(|| self.bundle.clone()))
            }
        }

        let server = test_certificate("cert-example");
        let tls =
            TlsRuntimeSnapshot::from_configs(vec![load_rustls_server_config(&server).unwrap()])
                .unwrap();
        let fixture = PrivatePkiFixture::new("shared.private.test");
        let reference = TrustBundleRef::parse("shared-private-root").unwrap();
        let bundle = edge_adapters::RustlsTrustBundleMaterialValidator
            .validate_trust_bundle(&reference, fixture.root_pem.as_bytes(), 10)
            .unwrap();
        let https_addr = free_loopback_addr();
        let source = https_config_source_with_upstream(
            "cert-example",
            "127.0.0.1:9443",
            &https_addr.to_string(),
        )
        .replace("schema_version = 1", "schema_version = 2")
        .replace(
            "url = \"http://127.0.0.1:9443\"",
            "url = \"https://127.0.0.1:9443\"\ntls_server_name = \"shared.private.test\"\nupstream_http_host = \"shared.private.test\"\ntls_trust_bundle_ref = \"shared-private-root\"",
        )
        .replace(
            "protocol = \"https\"",
            "protocol = \"https\"\nclient_auth = \"required\"\nclient_trust_bundle_ref = \"shared-private-root\"",
        );
        let snapshot = parse_mvp_config(&source, ConfigRevisionId::new("shared-trust"))
            .unwrap()
            .snapshot;
        let listeners = https_listener_configs(&snapshot).unwrap();
        let mut reader = CountingTrustReader { bundle, loads: 0 };

        let generation =
            prepare_tls_runtime_generation(&snapshot, &listeners, Some(&tls), &mut reader).unwrap();

        assert_eq!(reader.loads, 1);
        assert_eq!(generation.request_registry.len(), 1);
        assert_eq!(generation.health_registry.len(), 1);
        assert_eq!(generation.https_listeners.len(), 1);
        assert_eq!(generation.server_registry().unwrap().len(), 1);
    }

    #[test]
    fn unified_mio_https_self_signed_proxy_forwards_without_connection_thread() {
        let (upstream_addr, upstream) = spawn_text_backend("mio-https-ok");
        let certificate = test_certificate("cert-example");
        let loaded = load_rustls_server_config(&certificate).unwrap();
        let https_addr = free_loopback_addr();
        let http_addr = free_loopback_addr();
        let source = https_config_source_with_upstream(
            "cert-example",
            &upstream_addr.to_string(),
            &https_addr.to_string(),
        );
        let snapshot = parse_mvp_config(&source, ConfigRevisionId::new("mio-https-smoke"))
            .unwrap()
            .snapshot;
        let (mut command_client, command_receiver) = runtime_command_channel(8);
        let (access_sender, access_receiver) = std::sync::mpsc::sync_channel(4);
        let runtime = std::thread::spawn(move || {
            run_snapshot_http_proxy_mio(
                SnapshotProxyConfig::new(http_addr, snapshot, HttpLimits::default())
                    .with_runtime_commands(command_receiver)
                    .with_access_log_sender(access_sender)
                    .with_https_listener(
                        https_addr,
                        RustlsServerTlsSessionFactory::new(loaded.server_config),
                    ),
            )
        });
        assert!(command_client
            .send(CoreCommand::RefreshRouteTable)
            .is_success());

        let response = https_get(https_addr, &certificate.certificate_pem);
        let upstream_request = upstream.join().unwrap();
        let access_event = access_receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert!(command_client.send(CoreCommand::Shutdown).is_success());
        runtime.join().unwrap().unwrap();

        assert!(
            response.contains("HTTP/1.1 200 OK"),
            "response was {response:?}"
        );
        assert!(response.ends_with("mio-https-ok"));
        assert!(upstream_request.contains("X-Forwarded-Proto: https"));
        assert_eq!(access_event.scheme, "https");
    }

    #[test]
    fn phase009_unified_mio_required_mtls_forwards_only_trusted_client() {
        use edge_ports::TrustBundleMaterialValidator;

        struct OneTrustBundle(Option<edge_ports::ValidatedTrustBundle>);
        impl TrustBundleReader for OneTrustBundle {
            fn load_trust_bundle(
                &mut self,
                reference: &TrustBundleRef,
            ) -> Result<Option<edge_ports::ValidatedTrustBundle>, AppError> {
                Ok(self
                    .0
                    .as_ref()
                    .filter(|bundle| &bundle.metadata.trust_bundle_ref == reference)
                    .cloned())
            }
        }

        let (upstream_addr, upstream) = spawn_text_backend("mio-mtls-ok");
        let server = PrivatePkiFixture::new("edge.private.test");
        let trusted_client = PrivateClientPkiFixture::new();
        let wrong_client = PrivateClientPkiFixture::new();
        let reference = TrustBundleRef::parse("private-client-root").unwrap();
        let bundle = edge_adapters::RustlsTrustBundleMaterialValidator
            .validate_trust_bundle(&reference, trusted_client.root_pem.as_bytes(), 10)
            .unwrap();
        let tls = TlsRuntimeSnapshot::from_configs(vec![load_rustls_server_config(
            &server.stored_certificate("edge-server"),
        )
        .unwrap()])
        .unwrap();
        let https_addr = free_loopback_addr();
        let http_addr = free_loopback_addr();
        let listeners = vec![StartupHttpsListener {
            bind: https_addr,
            client_auth: ClientAuthPolicy::Required {
                trust_bundle_ref: reference,
            },
        }];
        let mut reader = OneTrustBundle(Some(bundle));
        let prepared = prepare_https_listener_factories(&listeners, &tls, &mut reader).unwrap();
        let source = https_config_source_with_host_upstream(
            "edge.private.test",
            "edge-server",
            &upstream_addr.to_string(),
            &https_addr.to_string(),
        );
        let snapshot = parse_mvp_config(&source, ConfigRevisionId::new("mio-mtls"))
            .unwrap()
            .snapshot;
        let mut candidate = snapshot.clone();
        candidate.revision_id = ConfigRevisionId::new("mio-mtls-hot-generation");
        let (mut command_client, command_receiver) = runtime_command_channel(8);
        let listener = prepared.into_iter().next().unwrap();
        let mut server_registry = PreparedServerTlsRegistry::new();
        server_registry
            .insert(listener.bind, listener.factory.clone())
            .unwrap();
        let runtime = std::thread::spawn(move || {
            run_snapshot_http_proxy_mio(
                SnapshotProxyConfig::new(http_addr, snapshot, HttpLimits::default())
                    .with_runtime_commands(command_receiver)
                    .with_https_listener(listener.bind, listener.factory),
            )
        });
        assert!(command_client
            .send(CoreCommand::RefreshRouteTable)
            .is_success());
        let availability = edge_application::HealthRuntimeCoordinator::activate(
            &candidate,
            edge_ports::HealthGeneration(1),
            0,
        )
        .unwrap()
        .availability_snapshot();
        assert!(command_client
            .activate_runtime_generation(
                candidate,
                availability,
                server_registry,
                PreparedClientTlsRegistry::new(),
            )
            .is_success());

        assert!(https_get_result(https_addr, "edge.private.test", &server.root_pem).is_err());
        assert!(https_get_with_client_result(
            https_addr,
            "edge.private.test",
            &server.root_pem,
            &wrong_client.fullchain_pem,
            &wrong_client.leaf_key_pem,
        )
        .is_err());
        let response = https_get_with_client_result(
            https_addr,
            "edge.private.test",
            &server.root_pem,
            &trusted_client.fullchain_pem,
            &trusted_client.leaf_key_pem,
        )
        .unwrap();

        assert!(response.contains("200 OK"));
        assert!(response.ends_with("mio-mtls-ok"));
        assert!(command_client.send(CoreCommand::Shutdown).is_success());
        runtime.join().unwrap().unwrap();
        let request = upstream.join().unwrap();
        assert!(request.contains("Host: edge.private.test"));
    }

    #[test]
    fn unified_mio_private_pki_requires_root_trust_and_correct_sni() {
        let fixture = PrivatePkiFixture::new("app.private.test");
        let (upstream_addr, upstream) = spawn_text_backend("private-pki-ok");
        let certificate = fixture.stored_certificate("cert-private");
        let loaded = load_rustls_server_config(&certificate).unwrap();
        let https_addr = free_loopback_addr();
        let http_addr = free_loopback_addr();
        let source = https_config_source_with_host_upstream(
            &fixture.dns_name,
            "cert-private",
            &upstream_addr.to_string(),
            &https_addr.to_string(),
        );
        let snapshot = parse_mvp_config(&source, ConfigRevisionId::new("private-pki-smoke"))
            .unwrap()
            .snapshot;
        let (mut command_client, command_receiver) = runtime_command_channel(8);
        let runtime = std::thread::spawn(move || {
            run_snapshot_http_proxy_mio(
                SnapshotProxyConfig::new(http_addr, snapshot, HttpLimits::default())
                    .with_runtime_commands(command_receiver)
                    .with_https_listener(
                        https_addr,
                        RustlsServerTlsSessionFactory::new(loaded.server_config),
                    ),
            )
        });
        assert!(command_client
            .send(CoreCommand::RefreshRouteTable)
            .is_success());

        let unrelated_root = rcgen::generate_simple_self_signed(vec!["unrelated.test".into()])
            .unwrap()
            .cert
            .pem();
        assert!(https_get_result(https_addr, &fixture.dns_name, &unrelated_root).is_err());
        assert!(https_get_result(https_addr, "wrong.private.test", &fixture.root_pem).is_err());
        let response = https_get_result(https_addr, &fixture.dns_name, &fixture.root_pem).unwrap();

        let upstream_request = upstream.join().unwrap();
        assert!(command_client.send(CoreCommand::Shutdown).is_success());
        runtime.join().unwrap().unwrap();
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.ends_with("private-pki-ok"));
        assert!(upstream_request.contains("X-Forwarded-Proto: https"));
        assert_eq!(
            fixture.fullchain_pem.matches("BEGIN CERTIFICATE").count(),
            2
        );
        assert!(!fixture.fullchain_pem.contains(&fixture.root_pem));
        assert!(!fixture.fullchain_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn phase009_outbound_private_pki_mio_requires_managed_root_and_correct_sni() {
        let server_fixture = PrivatePkiFixture::new("backend.private.test");
        let unrelated_fixture = PrivatePkiFixture::new("unrelated.private.test");

        let (response, request) = run_outbound_private_tls_case(
            &server_fixture,
            &server_fixture.root_pem,
            "backend.private.test",
        );
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response:?}");
        let request = request.expect("trusted backend must receive request");
        assert!(
            request.contains("Host: backend.private.test"),
            "{request:?}"
        );
        assert!(
            request.contains("X-Forwarded-Host: public.example.test"),
            "{request:?}"
        );

        let (response, request) = run_outbound_private_tls_case(
            &server_fixture,
            &unrelated_fixture.root_pem,
            "backend.private.test",
        );
        assert!(
            response.starts_with("HTTP/1.1 502 Bad Gateway"),
            "{response:?}"
        );
        assert!(request.is_none());

        let (response, request) = run_outbound_private_tls_case(
            &server_fixture,
            &server_fixture.root_pem,
            "wrong.private.test",
        );
        assert!(
            response.starts_with("HTTP/1.1 502 Bad Gateway"),
            "{response:?}"
        );
        assert!(request.is_none());
    }

    #[test]
    fn phase009_outbound_private_pki_websocket_tunnels_inside_tls() {
        let fixture = PrivatePkiFixture::new("backend.private.test");
        let (backend, backend_thread) = spawn_private_tls_websocket_backend(&fixture);
        let snapshot =
            outbound_private_tls_snapshot(backend, "backend.private.test", "private-server-root");
        let mut reader = TestTrustBundleReader::new("private-server-root", &fixture.root_pem);
        let registry = prepare_upstream_tls_runtime(&snapshot, &mut reader)
            .unwrap()
            .request_registry;
        let proxy_addr = free_loopback_addr();
        let (mut command_client, command_receiver) = runtime_command_channel(8);
        let runtime = std::thread::spawn(move || {
            run_snapshot_http_proxy_mio(
                SnapshotProxyConfig::new(proxy_addr, snapshot, HttpLimits::default())
                    .with_client_tls_registry(registry)
                    .with_runtime_commands(command_receiver),
            )
        });
        assert!(command_client
            .send(CoreCommand::RefreshRouteTable)
            .is_success());
        let mut client = std::net::TcpStream::connect(proxy_addr).unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        client
            .write_all(
                b"GET /socket HTTP/1.1\r\nHost: public.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .unwrap();
        let mut response = Vec::new();
        let mut buffer = [0_u8; 512];
        while !response.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = client.read(&mut buffer).unwrap();
            assert!(read > 0);
            response.extend_from_slice(&buffer[..read]);
        }
        assert!(response.starts_with(b"HTTP/1.1 101 Switching Protocols"));

        client.write_all(b"ping").unwrap();
        let mut pong = [0_u8; 4];
        client.read_exact(&mut pong).unwrap();
        assert_eq!(&pong, b"pong");
        let _ = client.shutdown(std::net::Shutdown::Both);

        assert!(command_client.send(CoreCommand::Shutdown).is_success());
        runtime.join().unwrap().unwrap();
        let request = backend_thread.join().unwrap();
        assert!(request.contains("Upgrade: websocket"));
        assert!(request.contains("Host: backend.private.test"));
    }

    #[test]
    fn phase009_upstream_tls_registry_loads_each_managed_root_once() {
        let fixture = PrivatePkiFixture::new("backend.private.test");
        let backend = free_loopback_addr();
        let mut snapshot =
            outbound_private_tls_snapshot(backend, "backend.private.test", "private-root");
        let mut second = snapshot.services[0].upstreams[0].clone();
        second.id = edge_domain::UpstreamId::new("private-backend-b");
        snapshot.services[0].upstreams.push(second);
        let mut reader = TestTrustBundleReader::new("private-root", &fixture.root_pem);

        let prepared = prepare_upstream_tls_runtime(&snapshot, &mut reader).unwrap();
        assert_eq!(prepared.health_registry.len(), 2);
        assert!(prepared
            .health_registry
            .contains(&edge_domain::UpstreamHealthKey {
                service_id: edge_domain::ServiceId::new("private-backend"),
                upstream_id: edge_domain::UpstreamId::new("private-backend-a"),
            }));
        let registry = prepared.request_registry;

        assert_eq!(reader.load_count, 1);
        assert!(registry.contains(
            &edge_domain::ServiceId::new("private-backend"),
            &edge_domain::UpstreamId::new("private-backend-a"),
        ));
        assert!(registry.contains(
            &edge_domain::ServiceId::new("private-backend"),
            &edge_domain::UpstreamId::new("private-backend-b"),
        ));
    }

    #[test]
    fn phase009_upstream_tls_registry_fails_closed_when_managed_root_is_missing() {
        let fixture = PrivatePkiFixture::new("backend.private.test");
        let snapshot = outbound_private_tls_snapshot(
            free_loopback_addr(),
            "backend.private.test",
            "required-root",
        );
        let mut reader = TestTrustBundleReader::new("different-root", &fixture.root_pem);

        let error = match prepare_upstream_tls_runtime(&snapshot, &mut reader) {
            Ok(_) => panic!("missing managed root must fail startup preparation"),
            Err(error) => error,
        };

        assert_eq!(error.code, ErrorCode::ConfigTrustBundleNotFound);
        assert_eq!(reader.load_count, 1);
        assert!(!error.message.contains("required-root"));
        assert!(!error.message.contains("backend.private.test"));
    }

    #[test]
    fn phase009_upstream_tls_startup_log_exposes_only_revision_and_count() {
        let mut sink = edge_adapters::MemoryLogSink::default();

        record_upstream_tls_prepared_log(&mut sink, &ConfigRevisionId::new("private-runtime"), 2)
            .unwrap();

        let event = &sink.events()[0];
        assert_eq!(event.event, "upstream_tls.startup.prepared");
        assert_eq!(
            event.fields,
            vec![
                ("revision_id".to_string(), "private-runtime".to_string()),
                ("prepared_upstream_count".to_string(), "2".to_string()),
            ]
        );
    }

    #[test]
    fn private_pki_material_preserves_leaf_facts_and_rejects_incomplete_chain() {
        let fixture = PrivatePkiFixture::new("app.private.test");
        let material = edge_ports::CertificateMaterial {
            certificate_pem: fixture.fullchain_pem.clone(),
            private_key_pem: fixture.leaf_key_pem.clone(),
        };
        let mut validator = edge_adapters::RustlsCertificateMaterialValidator;
        let facts =
            edge_ports::CertificateMaterialValidator::validate(&mut validator, &material).unwrap();
        assert_eq!(facts.dns_names, vec![fixture.dns_name.clone()]);
        assert!(facts.not_after_epoch_seconds > 0);

        let leaf_only = edge_ports::StoredCertificate {
            certificate_pem: fixture.leaf_pem.clone(),
            ..fixture.stored_certificate("leaf-only")
        };
        let reversed = edge_ports::StoredCertificate {
            certificate_pem: format!("{}{}", fixture.intermediate_pem, fixture.leaf_pem),
            ..fixture.stored_certificate("reversed")
        };
        assert!(private_tls_handshake(
            load_rustls_server_config(&leaf_only).unwrap().server_config,
            &fixture.dns_name,
            &fixture.root_pem,
        )
        .is_err());
        assert!(load_rustls_server_config(&reversed).is_err());

        let expired = PrivatePkiFixture::new_with_leaf_validity(
            "expired.private.test",
            (2020, 1, 1),
            (2021, 1, 1),
        );
        assert!(private_tls_handshake(
            load_rustls_server_config(&expired.stored_certificate("expired"))
                .unwrap()
                .server_config,
            &expired.dns_name,
            &expired.root_pem,
        )
        .is_err());
        let not_yet_valid = PrivatePkiFixture::new_with_leaf_validity(
            "future.private.test",
            (2030, 1, 1),
            (2031, 1, 1),
        );
        assert!(private_tls_handshake(
            load_rustls_server_config(&not_yet_valid.stored_certificate("future"))
                .unwrap()
                .server_config,
            &not_yet_valid.dns_name,
            &not_yet_valid.root_pem,
        )
        .is_err());

        let mismatched_key = rcgen::KeyPair::generate().unwrap().serialize_pem();
        let mismatched = edge_ports::CertificateMaterial {
            certificate_pem: fixture.fullchain_pem.clone(),
            private_key_pem: mismatched_key,
        };
        assert!(
            edge_ports::CertificateMaterialValidator::validate(&mut validator, &mismatched)
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_pki_backup_restore_restarts_admin_and_trusted_https() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_root("private-pki-disaster-recovery");
        let source_dir = root.join("source");
        let restored_dir = root.join("restored");
        let wrong_target = root.join("wrong-target");
        let archive = root.join("recovery.age");
        std::fs::create_dir_all(&root).unwrap();
        ensure_data_layout(source_dir.to_str().unwrap()).unwrap();

        let fixture = PrivatePkiFixture::new("app.private.test");
        let (upstream_addr, upstream) = spawn_text_backend_for_requests("recovered-pki", 2);
        let configured_https = free_loopback_addr();
        let config_source = https_config_source_with_host_upstream(
            &fixture.dns_name,
            "cert-recovery",
            &upstream_addr.to_string(),
            &configured_https.to_string(),
        );
        let parsed =
            parse_mvp_config(&config_source, ConfigRevisionId::new("recovery-revision")).unwrap();
        let revision = edge_domain::ConfigRevision {
            id: parsed.snapshot.revision_id.clone(),
            schema_version: parsed.snapshot.schema_version,
            summary: "private PKI recovery".to_string(),
        };
        let mut revisions = FileRevisionRepository::new(source_dir.join("config"));
        revisions
            .save_revision(edge_ports::RevisionRecord {
                revision,
                checksum: edge_application::checksum_snapshot(&parsed.snapshot),
                snapshot: parsed.snapshot,
            })
            .unwrap();
        revisions
            .set_current(&ConfigRevisionId::new("recovery-revision"))
            .unwrap();
        FileCertificateStore::new(source_dir.join("certs"))
            .save_certificate(fixture.stored_certificate("cert-recovery"))
            .unwrap();
        FileSecretStore::new(source_dir.join("secrets"))
            .save_secret(edge_ports::SecretRecord {
                name: "admin-password-hash".to_string(),
                value: "recovery-password-hash".to_string(),
            })
            .unwrap();

        let source_startup = startup_proxy_config_from_file(
            source_dir.join("unused-seed.toml").to_str().unwrap(),
            source_dir.to_str().unwrap(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(source_startup.origin, StartupConfigOrigin::RevisionCurrent);
        assert_eq!(source_startup.revision_id.as_str(), "recovery-revision");
        let source_response = run_private_pki_snapshot_request(
            source_startup.http.snapshot,
            fixture.stored_certificate("cert-recovery"),
            &fixture.dns_name,
            &fixture.root_pem,
        );
        assert!(source_response.ends_with("recovered-pki"));

        let mut source_sessions = edge_admin_api::SessionStore::default();
        let old_session = edge_admin_api::AdminAuthenticator::new("recovery-password-hash")
            .login("recovery-password-hash", &mut source_sessions)
            .unwrap();
        assert!(source_sessions.verify_csrf(&old_session.session_id, &old_session.csrf_token));

        let mut backup_source = FileBackupArtifactSource::new(&source_dir);
        let source_lock = FileDataDirectoryLockManager::new(&source_dir).unwrap();
        let mut writer = AgeBackupArchiveWriter::new(&archive).unwrap();
        let mut create_ids = RandomOperationIdGenerator;
        let mut create_logs = edge_adapters::MemoryLogSink::default();
        let create = CreateBackupUseCase::new(
            &source_lock,
            &mut backup_source,
            &Sha256BackupManifestDigester,
            &mut writer,
            &SystemClock,
            &mut create_ids,
            &mut create_logs,
            edge_domain::BackupLimits::schema_v1(),
        )
        .execute(CreateBackupInput {
            source_app_version: env!("CARGO_PKG_VERSION").to_string(),
            destination_identity: "private-pki-recovery-archive".to_string(),
            passphrase: edge_domain::SensitiveString::new("recovery-passphrase").unwrap(),
        })
        .unwrap();

        let mut reader = AgeBackupArchiveReader::new(&archive);
        let mut verify_ids = RandomOperationIdGenerator;
        let mut verify_logs = edge_adapters::MemoryLogSink::default();
        let report = VerifyBackupUseCase::new(
            &mut reader,
            &Sha256BackupManifestDigester,
            &SystemClock,
            &mut verify_ids,
            &mut verify_logs,
            edge_domain::BackupLimits::schema_v1(),
        )
        .execute(VerifyBackupInput {
            passphrase: edge_domain::SensitiveString::new("recovery-passphrase").unwrap(),
        })
        .unwrap();
        assert_eq!(report.archive_id, create.archive_id);
        assert_eq!(report.certificates_count, 1);
        assert!(report.admin_initialized);

        let wrong_lock = FileDataDirectoryLockManager::new(&wrong_target).unwrap();
        let mut wrong_extractor =
            FileRestoreArchiveExtractor::new(&archive, &wrong_target).unwrap();
        let mut wrong_preflight = FileRestorePreflight::new(wrong_extractor.stage_path());
        let mut wrong_publisher =
            FileNewTargetRestorePublisher::new(wrong_extractor.stage_path(), &wrong_target);
        let mut wrong_provenance = FileRestoreProvenanceWriter::new(&wrong_target);
        let mut wrong_ids = RandomOperationIdGenerator;
        let mut wrong_logs = edge_adapters::MemoryLogSink::default();
        assert_eq!(
            RestoreBackupUseCase::new(
                &wrong_lock,
                &mut wrong_extractor,
                &mut wrong_preflight,
                &mut wrong_publisher,
                &mut wrong_provenance,
                &SystemClock,
                &mut wrong_ids,
                &mut wrong_logs,
                edge_domain::BackupLimits::schema_v1(),
            )
            .execute(RestoreBackupInput {
                passphrase: edge_domain::SensitiveString::new("wrong-passphrase").unwrap(),
            })
            .unwrap_err()
            .code,
            ErrorCode::BackupAuthenticationFailed
        );
        assert!(!wrong_target.exists());

        let restore_lock = FileDataDirectoryLockManager::new(&restored_dir).unwrap();
        let mut extractor = FileRestoreArchiveExtractor::new(&archive, &restored_dir).unwrap();
        let mut preflight = FileRestorePreflight::new(extractor.stage_path());
        let mut publisher =
            FileNewTargetRestorePublisher::new(extractor.stage_path(), &restored_dir);
        let mut provenance = FileRestoreProvenanceWriter::new(&restored_dir);
        let mut restore_ids = RandomOperationIdGenerator;
        let mut restore_logs = edge_adapters::MemoryLogSink::default();
        let restore = RestoreBackupUseCase::new(
            &restore_lock,
            &mut extractor,
            &mut preflight,
            &mut publisher,
            &mut provenance,
            &SystemClock,
            &mut restore_ids,
            &mut restore_logs,
            edge_domain::BackupLimits::schema_v1(),
        )
        .execute(RestoreBackupInput {
            passphrase: edge_domain::SensitiveString::new("recovery-passphrase").unwrap(),
        })
        .unwrap();
        assert_eq!(restore.archive_id, create.archive_id);
        assert_eq!(restore.restored_revision_id.as_str(), "recovery-revision");
        assert_eq!(restore.certificate_count, 1);

        let restored_startup = startup_proxy_config_from_file(
            restored_dir.join("unused-seed.toml").to_str().unwrap(),
            restored_dir.to_str().unwrap(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            restored_startup.origin,
            StartupConfigOrigin::RevisionCurrent
        );
        assert_eq!(restored_startup.revision_id.as_str(), "recovery-revision");
        let restored_certificate = FileCertificateStore::new(restored_dir.join("certs"))
            .load_certificate(&CertificateRef::new("cert-recovery"))
            .unwrap()
            .unwrap();
        assert_eq!(restored_certificate.domains, vec![fixture.dns_name.clone()]);
        assert_eq!(restored_certificate.certificate_pem, fixture.fullchain_pem);

        let restored_hash = load_optional_admin_password_hash(restored_dir.to_str().unwrap())
            .unwrap()
            .unwrap();
        let fresh_sessions = edge_admin_api::SessionStore::default();
        assert!(
            edge_admin_api::require_session(&fresh_sessions, Some(&old_session.session_id))
                .is_err()
        );
        let mut restored_sessions = fresh_sessions;
        let new_session = edge_admin_api::AdminAuthenticator::new(restored_hash)
            .login("recovery-password-hash", &mut restored_sessions)
            .unwrap();
        assert!(restored_sessions.verify_csrf(&new_session.session_id, &new_session.csrf_token));

        let restored_response = run_private_pki_snapshot_request(
            restored_startup.http.snapshot,
            restored_certificate,
            &fixture.dns_name,
            &fixture.root_pem,
        );
        assert!(restored_response.ends_with("recovered-pki"));
        let requests = upstream.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests
            .iter()
            .all(|request| request.contains("X-Forwarded-Proto: https")));

        let key_path = restored_dir
            .join("certs")
            .join("cert-recovery")
            .join("privkey.pem");
        assert_eq!(
            std::fs::metadata(key_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(restored_dir.join("secrets/admin-password-hash.secret"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let log_text = format!(
            "{:?}{:?}{:?}",
            create_logs.events(),
            verify_logs.events(),
            restore_logs.events()
        );
        for secret in [
            "recovery-passphrase",
            "recovery-password-hash",
            "BEGIN CERTIFICATE",
            "PRIVATE KEY",
        ] {
            assert!(!log_text.contains(secret));
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn phase009_backup_v2_restores_bidirectional_private_tls_trust() {
        use edge_ports::{TrustBundleMaterialValidator, TrustBundleStore};

        let root = temp_root("bidirectional-tls-recovery");
        let source_dir = root.join("source");
        let restored_dir = root.join("restored");
        let archive = root.join("recovery-v2.age");
        std::fs::create_dir_all(&root).unwrap();
        ensure_data_layout(source_dir.to_str().unwrap()).unwrap();
        let edge_server = PrivatePkiFixture::new("edge.recovery.test");
        let backend_server = PrivatePkiFixture::new("backend.recovery.test");
        let trusted_client = PrivateClientPkiFixture::new();
        let (backend_addr, backend_thread) = spawn_private_tls_backend(&backend_server);
        let https_addr = free_loopback_addr();
        let source = https_config_source_with_host_upstream(
            "edge.recovery.test",
            "edge-server",
            &backend_addr.to_string(),
            &https_addr.to_string(),
        )
        .replace("schema_version = 1", "schema_version = 2")
        .replace(
            &format!("url = \"http://{backend_addr}\""),
            &format!("url = \"https://{backend_addr}\"\ntls_server_name = \"backend.recovery.test\"\nupstream_http_host = \"backend.recovery.test\"\ntls_trust_bundle_ref = \"backend-root\""),
        )
        .replace(
            "protocol = \"https\"",
            "protocol = \"https\"\nclient_auth = \"required\"\nclient_trust_bundle_ref = \"client-root\"",
        );
        let parsed = parse_mvp_config(&source, ConfigRevisionId::new("tls-recovery-v2")).unwrap();
        let mut revisions = FileRevisionRepository::new(source_dir.join("config"));
        revisions
            .save_revision(edge_ports::RevisionRecord {
                revision: edge_domain::ConfigRevision {
                    id: parsed.snapshot.revision_id.clone(),
                    schema_version: 2,
                    summary: "bidirectional private TLS recovery".to_string(),
                },
                checksum: edge_application::checksum_snapshot(&parsed.snapshot),
                snapshot: parsed.snapshot,
            })
            .unwrap();
        revisions
            .set_current(&ConfigRevisionId::new("tls-recovery-v2"))
            .unwrap();
        FileCertificateStore::new(source_dir.join("certs"))
            .save_certificate(edge_server.stored_certificate("edge-server"))
            .unwrap();
        let mut trust_store = FileTrustBundleStore::new(source_dir.join("trust-bundles"));
        for (reference, pem) in [
            ("backend-root", backend_server.root_pem.as_str()),
            ("client-root", trusted_client.root_pem.as_str()),
        ] {
            let reference = TrustBundleRef::parse(reference).unwrap();
            let bundle = edge_adapters::RustlsTrustBundleMaterialValidator
                .validate_trust_bundle(&reference, pem.as_bytes(), 10)
                .unwrap();
            trust_store.create_trust_bundle(bundle).unwrap();
        }

        let lock = FileDataDirectoryLockManager::new(&source_dir).unwrap();
        let mut backup_source = FileBackupArtifactSource::new(&source_dir);
        let mut writer = AgeBackupArchiveWriter::new(&archive).unwrap();
        let create = CreateBackupUseCase::new(
            &lock,
            &mut backup_source,
            &Sha256BackupManifestDigester,
            &mut writer,
            &SystemClock,
            &mut RandomOperationIdGenerator,
            &mut edge_adapters::MemoryLogSink::default(),
            edge_domain::BackupLimits::schema_v2(),
        )
        .execute(CreateBackupInput {
            source_app_version: env!("CARGO_PKG_VERSION").to_string(),
            destination_identity: "bidirectional-recovery-v2".to_string(),
            passphrase: edge_domain::SensitiveString::new("recovery-v2-passphrase").unwrap(),
        })
        .unwrap();
        assert_eq!(create.schema_version, 2);
        let report = VerifyBackupUseCase::new(
            &mut AgeBackupArchiveReader::new(&archive),
            &Sha256BackupManifestDigester,
            &SystemClock,
            &mut RandomOperationIdGenerator,
            &mut edge_adapters::MemoryLogSink::default(),
            edge_domain::BackupLimits::schema_v2(),
        )
        .execute(VerifyBackupInput {
            passphrase: edge_domain::SensitiveString::new("recovery-v2-passphrase").unwrap(),
        })
        .unwrap();
        assert_eq!(
            (
                report.trust_bundles_count,
                report.referenced_trust_bundles_count
            ),
            (2, 2)
        );

        let restore_lock = FileDataDirectoryLockManager::new(&restored_dir).unwrap();
        let mut extractor = FileRestoreArchiveExtractor::new(&archive, &restored_dir).unwrap();
        let mut preflight = FileRestorePreflight::new(extractor.stage_path());
        let mut publisher =
            FileNewTargetRestorePublisher::new(extractor.stage_path(), &restored_dir);
        let mut provenance = FileRestoreProvenanceWriter::new(&restored_dir);
        let restore = RestoreBackupUseCase::new(
            &restore_lock,
            &mut extractor,
            &mut preflight,
            &mut publisher,
            &mut provenance,
            &SystemClock,
            &mut RandomOperationIdGenerator,
            &mut edge_adapters::MemoryLogSink::default(),
            edge_domain::BackupLimits::schema_v2(),
        )
        .execute(RestoreBackupInput {
            passphrase: edge_domain::SensitiveString::new("recovery-v2-passphrase").unwrap(),
        })
        .unwrap();
        assert_eq!(restore.trust_bundle_count, 2);

        let startup = startup_proxy_config_from_file(
            restored_dir.join("unused.toml").to_str().unwrap(),
            restored_dir.to_str().unwrap(),
        )
        .unwrap()
        .unwrap();
        let snapshot = startup.http.snapshot;
        let mut restored_trust = FileTrustBundleStore::new(restored_dir.join("trust-bundles"));
        let generation = prepare_tls_runtime_generation(
            &snapshot,
            &startup.https,
            startup.tls.as_ref(),
            &mut restored_trust,
        )
        .unwrap();
        let listener = generation.https_listeners.into_iter().next().unwrap();
        let http_addr = free_loopback_addr();
        let (mut commands, receiver) = runtime_command_channel(8);
        let runtime = std::thread::spawn(move || {
            run_snapshot_http_proxy_mio(
                SnapshotProxyConfig::new(http_addr, snapshot, HttpLimits::default())
                    .with_client_tls_registry(generation.request_registry)
                    .with_runtime_commands(receiver)
                    .with_https_listener(listener.bind, listener.factory),
            )
        });
        assert!(commands.send(CoreCommand::RefreshRouteTable).is_success());
        assert!(https_get_result(https_addr, "edge.recovery.test", &edge_server.root_pem).is_err());
        let response = https_get_with_client_result(
            https_addr,
            "edge.recovery.test",
            &edge_server.root_pem,
            &trusted_client.fullchain_pem,
            &trusted_client.leaf_key_pem,
        )
        .unwrap();
        assert!(response.ends_with("secure"));
        assert!(commands.send(CoreCommand::Shutdown).is_success());
        runtime.join().unwrap().unwrap();
        assert!(backend_thread
            .join()
            .unwrap()
            .unwrap()
            .contains("Host: backend.recovery.test"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unified_mio_https_websocket_tunnels_payload() {
        let (upstream_addr, upstream) = spawn_websocket_backend();
        let certificate = test_certificate("cert-example");
        let loaded = load_rustls_server_config(&certificate).unwrap();
        let https_addr = free_loopback_addr();
        let http_addr = free_loopback_addr();
        let source = https_config_source_with_upstream(
            "cert-example",
            &upstream_addr.to_string(),
            &https_addr.to_string(),
        );
        let snapshot = parse_mvp_config(&source, ConfigRevisionId::new("mio-wss-smoke"))
            .unwrap()
            .snapshot;
        let (mut command_client, command_receiver) = runtime_command_channel(8);
        let runtime = std::thread::spawn(move || {
            run_snapshot_http_proxy_mio(
                SnapshotProxyConfig::new(http_addr, snapshot, HttpLimits::default())
                    .with_runtime_commands(command_receiver)
                    .with_https_listener(
                        https_addr,
                        RustlsServerTlsSessionFactory::new(loaded.server_config),
                    ),
            )
        });
        assert!(command_client
            .send(CoreCommand::RefreshRouteTable)
            .is_success());

        let mut client = rustls_test_stream(https_addr, "localhost", &certificate.certificate_pem);
        client
            .write_all(
                b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .unwrap();
        let mut response_headers = Vec::new();
        let mut byte = [0_u8; 1];
        while !response_headers.ends_with(b"\r\n\r\n") {
            client.read_exact(&mut byte).unwrap();
            response_headers.push(byte[0]);
        }
        client.write_all(b"ping").unwrap();
        let mut pong = [0_u8; 4];
        client.read_exact(&mut pong).unwrap();
        drop(client);

        let upstream_request = upstream.join().unwrap();
        assert!(command_client.send(CoreCommand::Shutdown).is_success());
        runtime.join().unwrap().unwrap();
        assert!(String::from_utf8_lossy(&response_headers).contains("101 Switching Protocols"));
        assert_eq!(&pong, b"pong");
        assert!(upstream_request.contains("X-Forwarded-Proto: https"));
    }

    #[test]
    fn unified_mio_https_hot_install_uses_new_certificate_for_new_connection() {
        let root = temp_root("unified-mio-hot-install");
        let (upstream_addr, upstream) = spawn_text_backend_for_requests("hot-mio", 2);
        let old_certificate = test_certificate("cert-app");
        let new_certificate = test_certificate("cert-app");
        let old_loaded = load_rustls_server_config(&old_certificate).unwrap();
        let tls = Arc::new(RwLock::new(
            TlsRuntimeSnapshot::from_configs(vec![old_loaded.clone()]).unwrap(),
        ));
        let mut certificates = FileCertificateStore::new(root.join("certs"));
        certificates
            .save_certificate(new_certificate.clone())
            .unwrap();
        let https_addr = free_loopback_addr();
        let http_addr = free_loopback_addr();
        let source = https_config_source_with_upstream(
            "cert-app",
            &upstream_addr.to_string(),
            &https_addr.to_string(),
        );
        let snapshot = parse_mvp_config(&source, ConfigRevisionId::new("mio-hot-install"))
            .unwrap()
            .snapshot;
        let shared_snapshot = Arc::new(RwLock::new(snapshot.clone()));
        let (command_client, command_receiver) = runtime_command_channel(8);
        let mut readiness_client = command_client.clone();
        let runtime = std::thread::spawn(move || {
            run_snapshot_http_proxy_mio(
                SnapshotProxyConfig::new(http_addr, snapshot, HttpLimits::default())
                    .with_runtime_commands(command_receiver)
                    .with_https_listener(
                        https_addr,
                        RustlsServerTlsSessionFactory::new(old_loaded.server_config),
                    ),
            )
        });
        assert!(readiness_client
            .send(CoreCommand::RefreshRouteTable)
            .is_success());

        let mut old_connection =
            rustls_test_stream(https_addr, "localhost", &old_certificate.certificate_pem);
        old_connection
            .conn
            .complete_io(&mut old_connection.sock)
            .unwrap();
        assert!(!old_connection.conn.is_handshaking());
        let mut client =
            MirroredSnapshotCommandClient::new(command_client.clone(), shared_snapshot)
                .with_tls_install(
                    FileCertificateStore::new(root.join("certs")),
                    Some(Arc::clone(&tls)),
                )
                .with_trust_bundles(FileTrustBundleStore::new(root.join("trust-bundles")))
                .with_runtime_tls_installer(command_client.clone());
        let ack = client.send(CoreCommand::InstallCertificate {
            certificate_ref: CertificateRef::new("cert-app"),
        });
        assert!(ack.is_success(), "ack={ack:?}");
        old_connection
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let old_response = read_https_response(&mut old_connection);
        let new_response = https_get(https_addr, &new_certificate.certificate_pem);
        let requests = upstream.join().unwrap();
        let mut shutdown_client = command_client;
        assert!(shutdown_client.send(CoreCommand::Shutdown).is_success());
        runtime.join().unwrap().unwrap();

        assert!(old_response.ends_with("hot-mio"));
        assert!(new_response.ends_with("hot-mio"));
        assert_eq!(requests.len(), 2);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unified_mio_tls_apply_activates_config_health_and_tls_together() {
        let root = temp_root("unified-mio-atomic-activation");
        let certificate = test_certificate("cert-app");
        let loaded = load_rustls_server_config(&certificate).unwrap();
        let tls = Arc::new(RwLock::new(
            TlsRuntimeSnapshot::from_configs(vec![loaded.clone()]).unwrap(),
        ));
        let mut certificates = FileCertificateStore::new(root.join("certs"));
        certificates.save_certificate(certificate).unwrap();
        let https_addr = free_loopback_addr();
        let http_addr = free_loopback_addr();
        let source = https_config_source_with_upstream(
            "cert-app",
            "127.0.0.1:3000",
            &https_addr.to_string(),
        );
        let current = parse_mvp_config(&source, ConfigRevisionId::new("atomic-current"))
            .unwrap()
            .snapshot;
        let candidate = parse_mvp_config(&source, ConfigRevisionId::new("atomic-next"))
            .unwrap()
            .snapshot;
        let shared_snapshot = Arc::new(RwLock::new(current.clone()));
        let (command_client, command_receiver) = runtime_command_channel(8);
        let mut readiness_client = command_client.clone();
        let runtime = std::thread::spawn(move || {
            run_snapshot_http_proxy_mio(
                SnapshotProxyConfig::new(http_addr, current, HttpLimits::default())
                    .with_runtime_commands(command_receiver)
                    .with_https_listener(
                        https_addr,
                        RustlsServerTlsSessionFactory::new(loaded.server_config),
                    ),
            )
        });
        assert!(readiness_client
            .send(CoreCommand::RefreshRouteTable)
            .is_success());
        let health = HealthRuntimeController::new(command_client.clone());
        let mut client = MirroredSnapshotCommandClient::new(
            command_client.clone(),
            Arc::clone(&shared_snapshot),
        )
        .with_health_runtime(health.clone())
        .with_tls_install(
            FileCertificateStore::new(root.join("certs")),
            Some(Arc::clone(&tls)),
        )
        .with_trust_bundles(FileTrustBundleStore::new(root.join("trust-bundles")))
        .with_runtime_tls_installer(command_client.clone());

        let ack = client.send(CoreCommand::ApplyConfigSnapshot {
            snapshot: candidate,
        });

        assert!(ack.is_success(), "ack={ack:?}");
        assert_eq!(
            health.active_generation(),
            Some(edge_domain::HealthGeneration(1))
        );
        assert_eq!(
            shared_snapshot.read().unwrap().revision_id.as_str(),
            "atomic-next"
        );
        health.shutdown();
        let mut shutdown_client = command_client;
        assert!(shutdown_client.send(CoreCommand::Shutdown).is_success());
        runtime.join().unwrap().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn https_listener_selects_certificate_by_sni_among_loaded_configs() {
        let (upstream_addr, upstream) = spawn_text_backend("sni-admin-ok");
        let default_certificate = test_certificate_for_host("cert-a-default", "app.localhost");
        let admin_certificate = test_certificate_for_host("cert-z-admin", "admin.localhost");
        let default_config = load_rustls_server_config(&default_certificate).unwrap();
        let admin_config = load_rustls_server_config(&admin_certificate).unwrap();
        let tls = TlsRuntimeSnapshot::from_configs(vec![default_config, admin_config]).unwrap();
        let https_addr = free_loopback_addr();
        let source = https_config_source_with_host_upstream(
            "admin.localhost",
            "cert-z-admin",
            &upstream_addr.to_string(),
            &https_addr.to_string(),
        );
        let snapshot = parse_mvp_config(&source, ConfigRevisionId::new("https-sni"))
            .unwrap()
            .snapshot;
        let http_addr = free_loopback_addr();
        let (mut command_client, command_receiver) = runtime_command_channel(4);
        let server_config = tls.sni_server_config().unwrap();
        let runtime = std::thread::spawn(move || {
            run_snapshot_http_proxy_mio(
                SnapshotProxyConfig::new(http_addr, snapshot, HttpLimits::default())
                    .with_runtime_commands(command_receiver)
                    .with_https_listener(
                        https_addr,
                        RustlsServerTlsSessionFactory::new(server_config),
                    ),
            )
        });
        assert!(command_client
            .send(CoreCommand::RefreshRouteTable)
            .is_success());

        let response = https_get_for_host(
            https_addr,
            "admin.localhost",
            &admin_certificate.certificate_pem,
        );
        let upstream_request = upstream.join().unwrap();
        assert!(command_client.send(CoreCommand::Shutdown).is_success());
        runtime.join().unwrap().unwrap();

        assert!(
            response.contains("HTTP/1.1 200 OK"),
            "response was {response:?}"
        );
        assert!(response.ends_with("sni-admin-ok"));
        assert!(upstream_request.contains("Host: admin.localhost"));
        assert!(upstream_request.contains("X-Forwarded-Proto: https"));
    }

    #[test]
    fn https_proxy_connection_closes_idle_tls_handshake_on_timeout() {
        let certificate = test_certificate("cert-example");
        let tls_config = load_rustls_server_config(&certificate).unwrap();
        let snapshot = parse_mvp_config(
            &https_config_source("cert-example"),
            ConfigRevisionId::new("tls-timeout"),
        )
        .unwrap()
        .snapshot;
        let https_addr = free_loopback_addr();
        let http_addr = free_loopback_addr();
        let limits = ResourceLimits {
            idle_timeout: std::time::Duration::from_millis(50),
            ..ResourceLimits::default()
        };
        let (mut command_client, command_receiver) = runtime_command_channel(4);
        let (error_sender, _error_receiver) = std::sync::mpsc::sync_channel(0);
        let (metric_sender, metric_receiver) = std::sync::mpsc::sync_channel(8);
        let drop_counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let runtime_drop_counter = Arc::clone(&drop_counter);
        let runtime = std::thread::spawn(move || {
            run_snapshot_http_proxy_mio(
                SnapshotProxyConfig::new(http_addr, snapshot, HttpLimits::default())
                    .with_resource_limits(limits)
                    .with_runtime_commands(command_receiver)
                    .with_error_log_sender(error_sender)
                    .with_metric_publisher(Arc::new(MetricChannelPublisher::new(metric_sender)))
                    .with_log_drop_counter(runtime_drop_counter)
                    .with_https_listener(
                        https_addr,
                        RustlsServerTlsSessionFactory::new(tls_config.server_config),
                    ),
            )
        });
        assert!(command_client
            .send(CoreCommand::RefreshRouteTable)
            .is_success());
        let mut client = std::net::TcpStream::connect(https_addr).unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();

        let started = std::time::Instant::now();
        let mut closed_payload = Vec::new();
        let read = client.read_to_end(&mut closed_payload);
        assert!(command_client.send(CoreCommand::Shutdown).is_success());
        runtime.join().unwrap().unwrap();

        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "idle TLS handshake did not close promptly; read was {read:?}"
        );
        assert!(
            read.is_ok()
                || read.as_ref().is_err_and(|error| matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
                )),
            "client socket should be closed after timeout, got {read:?}"
        );
        assert!(drop_counter.load(std::sync::atomic::Ordering::Relaxed) > 0);
        assert!(metric_receiver.try_iter().any(|metric| {
            metric.descriptor == edge_ports::MetricDescriptor::TlsHandshakeFailuresTotal
                && metric.labels
                    == vec![(
                        "error_code".to_string(),
                        ErrorCode::TlsHandshakeTimeout.as_str().to_string(),
                    )]
        }));
    }

    #[test]
    fn malformed_tls_closes_only_offending_connection_and_http_stays_available() {
        let (upstream_addr, upstream) = spawn_text_backend("http-still-ok");
        let certificate = test_certificate("cert-example");
        let loaded = load_rustls_server_config(&certificate).unwrap();
        let https_addr = free_loopback_addr();
        let http_addr = free_loopback_addr();
        let source = https_config_source_with_upstream(
            "cert-example",
            &upstream_addr.to_string(),
            &https_addr.to_string(),
        );
        let snapshot = parse_mvp_config(&source, ConfigRevisionId::new("malformed-tls"))
            .unwrap()
            .snapshot;
        let limits = ResourceLimits {
            idle_timeout: std::time::Duration::from_millis(100),
            ..ResourceLimits::default()
        };
        let (mut command_client, command_receiver) = runtime_command_channel(4);
        let runtime = std::thread::spawn(move || {
            run_snapshot_http_proxy_mio(
                SnapshotProxyConfig::new(http_addr, snapshot, HttpLimits::default())
                    .with_resource_limits(limits)
                    .with_runtime_commands(command_receiver)
                    .with_https_listener(
                        https_addr,
                        RustlsServerTlsSessionFactory::new(loaded.server_config),
                    ),
            )
        });
        assert!(command_client
            .send(CoreCommand::RefreshRouteTable)
            .is_success());

        let mut malformed = std::net::TcpStream::connect(https_addr).unwrap();
        malformed
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        malformed
            .write_all(&[0xff, 0x03, 0x03, 0x00, 0x00])
            .unwrap();
        malformed.shutdown(std::net::Shutdown::Write).unwrap();
        let mut ignored = Vec::new();
        let malformed_read = malformed.read_to_end(&mut ignored);
        assert!(
            malformed_read.is_ok()
                || malformed_read.as_ref().is_err_and(|error| matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
                )),
            "malformed TLS connection was not closed: {malformed_read:?}"
        );

        let mut http = std::net::TcpStream::connect(http_addr).unwrap();
        http.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        http.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        http.read_to_string(&mut response).unwrap();
        let upstream_request = upstream.join().unwrap();
        assert!(command_client.send(CoreCommand::Shutdown).is_success());
        runtime.join().unwrap().unwrap();

        assert!(response.ends_with("http-still-ok"));
        assert!(upstream_request.contains("X-Forwarded-Proto: http"));
    }

    #[derive(Clone, Default)]
    struct RecordingCoreCommandClient {
        commands: Vec<CoreCommand>,
        reject: bool,
    }

    impl CoreCommandClient for RecordingCoreCommandClient {
        fn send(&mut self, command: CoreCommand) -> CommandAck {
            if self.reject {
                CommandAck::rejected(AppError::new(
                    ErrorCode::RuntimeCommandRejected,
                    "command rejected",
                ))
            } else {
                self.commands.push(command);
                CommandAck::accepted()
            }
        }
    }

    #[test]
    fn rejected_sigterm_drain_marks_lifecycle_failed_and_logs_only_error_code() {
        let mut command_client = RecordingCoreCommandClient {
            reject: true,
            ..Default::default()
        };
        let lifecycle = Arc::new(std::sync::Mutex::new(OperationalLifecycle::Ready));
        let (log_sender, log_receiver) = std::sync::mpsc::sync_channel(1);

        begin_sigterm_drain(&mut command_client, &lifecycle, &log_sender);

        assert_eq!(*lifecycle.lock().unwrap(), OperationalLifecycle::Failed);
        assert!(command_client.commands.is_empty());
        let event = log_receiver.try_recv().unwrap();
        assert_eq!(event.component, "edge-proxy");
        assert_eq!(event.event, "process.drain.command_rejected");
        assert_eq!(
            event.fields,
            vec![(
                "error_code".to_string(),
                "RUNTIME_COMMAND_REJECTED".to_string()
            )]
        );
    }

    #[test]
    fn mirrored_apply_uses_monotonic_atomic_health_activation() {
        let first = parse_mvp_config(
            include_str!("../../../examples/minimal.toml"),
            ConfigRevisionId::new("health-activate-1"),
        )
        .unwrap()
        .snapshot;
        let second = parse_mvp_config(
            include_str!("../../../examples/minimal.toml"),
            ConfigRevisionId::new("health-activate-1"),
        )
        .unwrap()
        .snapshot;
        let shared = Arc::new(RwLock::new(first.clone()));
        let inner = RecordingCoreCommandClient::default();
        let health = HealthRuntimeController::new(inner.clone());
        let mut client =
            MirroredSnapshotCommandClient::new(inner, shared).with_health_runtime(health.clone());

        assert!(client
            .send(CoreCommand::ApplyConfigSnapshot {
                snapshot: first.clone(),
            })
            .is_success());
        assert!(client
            .send(CoreCommand::ApplyConfigSnapshot { snapshot: second })
            .is_success());

        let generations = client
            .inner
            .commands
            .iter()
            .map(|command| match command {
                CoreCommand::ActivateConfigSnapshot { availability, .. } => availability.generation,
                unexpected => panic!("expected atomic health activation, got {unexpected:?}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            generations,
            vec![
                edge_domain::HealthGeneration(1),
                edge_domain::HealthGeneration(2)
            ]
        );
        assert_eq!(
            health.active_generation(),
            Some(edge_domain::HealthGeneration(2))
        );
        health.shutdown();
    }

    #[test]
    fn rejected_atomic_health_activation_preserves_current_runtime_and_mirror() {
        let current = parse_mvp_config(
            include_str!("../../../examples/minimal.toml"),
            ConfigRevisionId::new("health-current"),
        )
        .unwrap()
        .snapshot;
        let mut candidate = current.clone();
        candidate.revision_id = ConfigRevisionId::new("health-rejected");
        let shared = Arc::new(RwLock::new(current.clone()));
        let publisher = RecordingCoreCommandClient::default();
        let health = HealthRuntimeController::new(publisher);
        let initial = health.prepare(current.clone()).unwrap();
        health.commit(initial).unwrap();
        let inner = RecordingCoreCommandClient {
            reject: true,
            ..RecordingCoreCommandClient::default()
        };
        let mut client = MirroredSnapshotCommandClient::new(inner, Arc::clone(&shared))
            .with_health_runtime(health.clone());

        let ack = client.send(CoreCommand::ApplyConfigSnapshot {
            snapshot: candidate,
        });

        assert!(!ack.is_success());
        assert_eq!(
            health.active_generation(),
            Some(edge_domain::HealthGeneration(1))
        );
        assert_eq!(shared.read().unwrap().revision_id, current.revision_id);
        health.shutdown();
    }

    #[test]
    fn phase009_health_commit_failure_compensates_to_previous_runtime_generation() {
        let root = temp_root("runtime-generation-compensation");
        ensure_data_layout(root.to_str().unwrap()).unwrap();
        let (upstream_addr, upstream) = spawn_text_backend("previous-generation");
        let source = include_str!("../../../examples/minimal.toml")
            .replace("127.0.0.1:3000", &upstream_addr.to_string())
            .replace("0.0.0.0:8080", &free_loopback_addr().to_string());
        let current = parse_mvp_config(&source, ConfigRevisionId::new("compensation-current"))
            .unwrap()
            .snapshot;
        let mut candidate = current.clone();
        candidate.revision_id = ConfigRevisionId::new("compensation-candidate");
        candidate.routes.clear();
        candidate.services.clear();
        let http_addr: SocketAddr = current.listeners[0].bind.parse().unwrap();
        let shared = Arc::new(RwLock::new(current.clone()));
        let (command_client, command_receiver) = runtime_command_channel(8);
        let mut readiness = command_client.clone();
        let runtime = std::thread::spawn(move || {
            run_snapshot_http_proxy_mio(
                SnapshotProxyConfig::new(http_addr, current, HttpLimits::default())
                    .with_runtime_commands(command_receiver),
            )
        });
        assert!(readiness.send(CoreCommand::RefreshRouteTable).is_success());
        let health = HealthRuntimeController::new(command_client.clone());
        health.fail_next_commit();
        let mut client =
            MirroredSnapshotCommandClient::new(command_client.clone(), Arc::clone(&shared))
                .with_health_runtime(health.clone())
                .with_tls_install(FileCertificateStore::new(root.join("certs")), None)
                .with_trust_bundles(FileTrustBundleStore::new(root.join("trust-bundles")))
                .with_runtime_tls_installer(command_client.clone());

        let ack = client.send(CoreCommand::ApplyConfigSnapshot {
            snapshot: candidate,
        });

        assert!(matches!(
            ack,
            CommandAck::Rejected(error) if error.message == "injected health commit failure"
        ));
        assert_eq!(
            shared.read().unwrap().revision_id.as_str(),
            "compensation-current"
        );
        let mut request = std::net::TcpStream::connect(http_addr).unwrap();
        request
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        request.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        request.read_to_string(&mut response).unwrap();
        assert!(response.ends_with("previous-generation"));
        upstream.join().unwrap();
        health.shutdown();
        let mut shutdown = command_client;
        assert!(shutdown.send(CoreCommand::Shutdown).is_success());
        runtime.join().unwrap().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn install_certificate_command_replaces_tls_runtime_snapshot_after_ack() {
        let root = temp_root("tls-hot-install-success");
        let old_certificate = test_certificate("cert-app");
        let old_config = load_rustls_server_config(&old_certificate).unwrap();
        let old_config_arc = Arc::clone(&old_config.server_config);
        let tls = Arc::new(RwLock::new(
            TlsRuntimeSnapshot::from_configs(vec![old_config]).unwrap(),
        ));
        let mut certificates = FileCertificateStore::new(root.join("certs"));
        certificates
            .save_certificate(test_certificate("cert-app"))
            .unwrap();
        let snapshot = Arc::new(RwLock::new(
            parse_mvp_config(
                &https_config_source("cert-app"),
                ConfigRevisionId::new("tls-hot-install"),
            )
            .unwrap()
            .snapshot,
        ));
        let mut client =
            MirroredSnapshotCommandClient::new(RecordingCoreCommandClient::default(), snapshot)
                .with_tls_install(
                    FileCertificateStore::new(root.join("certs")),
                    Some(tls.clone()),
                );

        let ack = client.send(CoreCommand::InstallCertificate {
            certificate_ref: CertificateRef::new("cert-app"),
        });

        assert!(ack.is_success());
        assert_eq!(client.inner.commands.len(), 1);
        let current = tls.read().unwrap();
        assert!(!Arc::ptr_eq(
            &old_config_arc,
            &current.default_config().server_config
        ));
        assert_eq!(
            current.certificate_refs(),
            vec![CertificateRef::new("cert-app")]
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn install_certificate_missing_ref_rejects_without_core_command() {
        let root = temp_root("tls-hot-install-missing");
        let old_config = load_rustls_server_config(&test_certificate("cert-app")).unwrap();
        let tls = Arc::new(RwLock::new(
            TlsRuntimeSnapshot::from_configs(vec![old_config]).unwrap(),
        ));
        let snapshot = Arc::new(RwLock::new(
            parse_mvp_config(
                &https_config_source("cert-app"),
                ConfigRevisionId::new("tls-hot-install-missing"),
            )
            .unwrap()
            .snapshot,
        ));
        let mut client =
            MirroredSnapshotCommandClient::new(RecordingCoreCommandClient::default(), snapshot)
                .with_tls_install(FileCertificateStore::new(root.join("certs")), Some(tls));

        let ack = client.send(CoreCommand::InstallCertificate {
            certificate_ref: CertificateRef::new("missing-cert"),
        });

        assert!(!ack.is_success());
        assert!(client.inner.commands.is_empty());
    }

    #[test]
    fn install_certificate_core_rejection_preserves_tls_runtime_snapshot() {
        let root = temp_root("tls-hot-install-core-reject");
        let old_config = load_rustls_server_config(&test_certificate("cert-app")).unwrap();
        let old_config_arc = Arc::clone(&old_config.server_config);
        let tls = Arc::new(RwLock::new(
            TlsRuntimeSnapshot::from_configs(vec![old_config]).unwrap(),
        ));
        let mut certificates = FileCertificateStore::new(root.join("certs"));
        certificates
            .save_certificate(test_certificate("cert-app"))
            .unwrap();
        let snapshot = Arc::new(RwLock::new(
            parse_mvp_config(
                &https_config_source("cert-app"),
                ConfigRevisionId::new("tls-hot-install-reject"),
            )
            .unwrap()
            .snapshot,
        ));
        let mut client = MirroredSnapshotCommandClient::new(
            RecordingCoreCommandClient {
                reject: true,
                ..RecordingCoreCommandClient::default()
            },
            snapshot,
        )
        .with_tls_install(
            FileCertificateStore::new(root.join("certs")),
            Some(tls.clone()),
        );

        let ack = client.send(CoreCommand::InstallCertificate {
            certificate_ref: CertificateRef::new("cert-app"),
        });

        assert!(!ack.is_success());
        assert!(Arc::ptr_eq(
            &old_config_arc,
            &tls.read().unwrap().default_config().server_config
        ));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn install_certificate_rejects_sni_domain_conflict_without_core_command() {
        let root = temp_root("tls-hot-install-sni-conflict");
        let app_config =
            load_rustls_server_config(&test_certificate_for_host("cert-app", "app.localhost"))
                .unwrap();
        let admin_config =
            load_rustls_server_config(&test_certificate_for_host("cert-admin", "admin.localhost"))
                .unwrap();
        let tls = Arc::new(RwLock::new(
            TlsRuntimeSnapshot::from_configs(vec![app_config, admin_config]).unwrap(),
        ));
        let mut certificates = FileCertificateStore::new(root.join("certs"));
        certificates
            .save_certificate(test_certificate_for_host("cert-admin", "app.localhost"))
            .unwrap();
        let snapshot = Arc::new(RwLock::new(
            parse_mvp_config(
                &https_config_source("cert-admin"),
                ConfigRevisionId::new("tls-hot-install-sni-conflict"),
            )
            .unwrap()
            .snapshot,
        ));
        let mut client =
            MirroredSnapshotCommandClient::new(RecordingCoreCommandClient::default(), snapshot)
                .with_tls_install(
                    FileCertificateStore::new(root.join("certs")),
                    Some(tls.clone()),
                );

        let ack = client.send(CoreCommand::InstallCertificate {
            certificate_ref: CertificateRef::new("cert-admin"),
        });

        assert!(!ack.is_success());
        assert!(client.inner.commands.is_empty());
        assert_eq!(
            tls.read()
                .unwrap()
                .select_certificate_ref_for_sni("app.localhost")
                .unwrap()
                .as_str(),
            "cert-app"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_missing_https_certificate_fails_before_runtime_start() {
        let root = temp_root("startup-https-missing-cert");
        ensure_data_layout(root.to_str().unwrap()).unwrap();
        let config_path = root.join("config/current.toml");
        std::fs::write(&config_path, https_config_source("missing-cert")).unwrap();

        let error = match startup_proxy_config_from_file(
            config_path.to_str().unwrap(),
            root.to_str().unwrap(),
        ) {
            Ok(_) => panic!("startup unexpectedly accepted missing HTTPS certificate"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("CERTIFICATE_NOT_FOUND"));
        assert!(!root.join("config/current").exists());
        let revisions = std::fs::read_dir(root.join("config/revisions"))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(revisions.is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_invalid_primary_config_does_not_import_revision() {
        let root = temp_root("startup-invalid");
        ensure_data_layout(root.to_str().unwrap()).unwrap();
        let config_path = root.join("config/current.toml");
        std::fs::write(
            &config_path,
            "schema_version = 1\n\n[admin]\nbind = \"127.0.0.1:9443\"\nauth_required = true\n",
        )
        .unwrap();

        let result =
            startup_proxy_config_from_file(config_path.to_str().unwrap(), root.to_str().unwrap());

        assert!(result.is_err());
        assert!(!root.join("config/current").exists());
        let revisions = std::fs::read_dir(root.join("config/revisions"))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(revisions.is_empty());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn loads_admin_password_hash_from_secret_store() {
        let root = temp_root("admin-password-hash");
        ensure_data_layout(root.to_str().unwrap()).unwrap();
        let mut secrets = FileSecretStore::new(root.join("secrets"));
        secrets
            .save_secret(edge_ports::SecretRecord {
                name: "admin-password-hash".to_string(),
                value: "hash".to_string(),
            })
            .unwrap();

        let hash = load_optional_admin_password_hash(root.to_str().unwrap())
            .unwrap()
            .unwrap();

        assert_eq!(hash, "hash");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_admin_password_hash_enters_setup_required_mode() {
        let root = temp_root("missing-admin-password-hash");
        ensure_data_layout(root.to_str().unwrap()).unwrap();

        let hash = load_optional_admin_password_hash(root.to_str().unwrap()).unwrap();

        assert!(hash.is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_certificate_expiry_metrics_are_recorded_from_certificate_store() {
        let mut certificates = edge_adapters::MemoryCertificateStore::default();
        certificates
            .save_certificate(test_certificate("cert-metrics"))
            .unwrap();
        let sink = MemoryMetricPublisher::default();

        record_startup_certificate_expiry_metrics(&certificates, &sink).unwrap();

        let metrics = sink.metrics.lock().unwrap();
        assert_eq!(metrics.len(), 1);
        let metric = &metrics[0];
        assert_eq!(
            metric.descriptor,
            edge_ports::MetricDescriptor::CertificateNotAfter
        );
        assert_eq!(
            metric.operation,
            edge_ports::MetricOperation::GaugeSet(4_000_000_000)
        );
        assert!(metric
            .labels
            .iter()
            .any(|(key, value)| key == "certificate_ref" && value == "cert-metrics"));
        assert!(!metric
            .labels
            .iter()
            .any(|(_, value)| value.contains("localhost") || value.contains("PRIVATE KEY")));
    }

    #[test]
    fn process_start_product_log_records_bootstrap_fields_without_secret_values() {
        let config = BootstrapConfig::new(
            "/var/lib/sponzey",
            "/etc/sponzey/current.toml",
            "127.0.0.1:9443",
            LogMode::Product,
        );
        let mut sink = edge_adapters::MemoryLogSink::default();

        record_process_start_log(&mut sink, &config, AcmeClientMode::Fake).unwrap();

        let event = &sink.events()[0];
        assert_eq!(event.component, "edge-proxy");
        assert_eq!(event.event, "process.start");
        assert!(event
            .fields
            .iter()
            .any(|(key, value)| key == "data_dir" && value == "/var/lib/sponzey"));
        assert!(event
            .fields
            .iter()
            .any(|(key, value)| key == "config_file" && value == "/etc/sponzey/current.toml"));
        assert!(event
            .fields
            .iter()
            .any(|(key, value)| key == "admin_bind" && value == "127.0.0.1:9443"));
        assert!(event
            .fields
            .iter()
            .any(|(key, value)| key == "log_mode" && value == "product"));
        assert!(event
            .fields
            .iter()
            .any(|(key, value)| key == "acme_client" && value == "fake"));
        assert!(!event
            .fields
            .iter()
            .any(|(key, value)| key.contains("password") || value.contains("secret")));
    }

    #[test]
    fn audit_startup_product_log_contains_only_bounded_counts_and_state() {
        let mut sink = edge_adapters::MemoryLogSink::default();
        record_audit_startup_log(
            &mut sink,
            &edge_application::InitializeAuditLedgerOutput {
                head: edge_domain::AuditLedgerHead {
                    generation: 4,
                    sequence: 99,
                },
                verified_record_count: 20,
                incomplete_count: 2,
                reconciled_count: 2,
                admission_state: AuditAdmissionState::Healthy,
            },
        )
        .unwrap();
        let event = &sink.events()[0];
        assert_eq!(event.component, "audit");
        assert_eq!(event.event, "audit.startup.ready");
        assert_eq!(
            event.fields,
            vec![
                ("record_count".to_string(), "20".to_string()),
                ("incomplete_count".to_string(), "2".to_string()),
                ("reconciled_count".to_string(), "2".to_string()),
                ("admission_state".to_string(), "healthy".to_string()),
            ]
        );
        assert!(!format!("{event:?}").contains("sequence"));
        assert!(!format!("{event:?}").contains("hash"));
    }

    #[test]
    fn startup_config_product_log_contains_only_origin_and_revision() {
        let mut sink = edge_adapters::MemoryLogSink::default();

        record_startup_config_resolution_log(
            &mut sink,
            StartupConfigOrigin::RevisionCurrent,
            &ConfigRevisionId::new("admin-applied"),
        )
        .unwrap();

        let event = &sink.events()[0];
        assert_eq!(event.event, "config.startup.resolved");
        assert_eq!(
            event.fields,
            vec![
                ("origin".to_string(), "revision_current".to_string()),
                ("revision_id".to_string(), "admin-applied".to_string()),
            ]
        );
    }

    #[derive(Default)]
    struct MemoryMetricPublisher {
        metrics: std::sync::Mutex<Vec<MetricEvent>>,
    }

    impl MetricPublisher for MemoryMetricPublisher {
        fn try_publish(&self, metric: MetricEvent) -> MetricPublishOutcome {
            self.metrics.lock().unwrap().push(metric);
            MetricPublishOutcome::Accepted
        }
    }

    fn https_config_source(certificate_ref: &str) -> String {
        let with_certificate_ref = include_str!("../../../examples/minimal.toml").replace(
            "service = \"example\"\n",
            &format!("service = \"example\"\ncertificate_ref = \"{certificate_ref}\"\n"),
        );
        format!(
            "{with_certificate_ref}\n[[listeners]]\nname = \"https\"\nbind = \"127.0.0.1:8443\"\nprotocol = \"https\"\n"
        )
    }

    fn https_config_source_with_upstream(
        certificate_ref: &str,
        upstream: &str,
        https_bind: &str,
    ) -> String {
        let with_upstream = include_str!("../../../examples/minimal.toml")
            .replace("http://127.0.0.1:3000", &format!("http://{upstream}"));
        let with_certificate_ref = with_upstream.replace(
            "service = \"example\"\n",
            &format!("service = \"example\"\ncertificate_ref = \"{certificate_ref}\"\n"),
        );
        format!(
            "{with_certificate_ref}\n[[listeners]]\nname = \"https\"\nbind = \"{https_bind}\"\nprotocol = \"https\"\n"
        )
    }

    fn https_config_source_with_host_upstream(
        host: &str,
        certificate_ref: &str,
        upstream: &str,
        https_bind: &str,
    ) -> String {
        https_config_source_with_upstream(certificate_ref, upstream, https_bind)
            .replace("hosts = [\"localhost\"]", &format!("hosts = [\"{host}\"]"))
    }

    fn free_loopback_addr() -> std::net::SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    }

    fn spawn_text_backend(
        body: &'static str,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 512];
            loop {
                let read = stream.read(&mut buffer).unwrap();
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
            String::from_utf8_lossy(&request).to_string()
        });
        (address, handle)
    }

    struct TestTrustBundleReader {
        reference: edge_domain::TrustBundleRef,
        bundle: edge_ports::ValidatedTrustBundle,
        load_count: usize,
    }

    impl TestTrustBundleReader {
        fn new(reference: &str, root_pem: &str) -> Self {
            let reference = edge_domain::TrustBundleRef::parse(reference).unwrap();
            let mut validator = edge_adapters::RustlsTrustBundleMaterialValidator;
            let bundle = edge_ports::TrustBundleMaterialValidator::validate_trust_bundle(
                &mut validator,
                &reference,
                root_pem.as_bytes(),
                1,
            )
            .unwrap();
            Self {
                reference,
                bundle,
                load_count: 0,
            }
        }
    }

    impl TrustBundleReader for TestTrustBundleReader {
        fn load_trust_bundle(
            &mut self,
            trust_bundle_ref: &edge_domain::TrustBundleRef,
        ) -> Result<Option<edge_ports::ValidatedTrustBundle>, AppError> {
            self.load_count += 1;
            Ok((trust_bundle_ref == &self.reference).then(|| self.bundle.clone()))
        }
    }

    fn outbound_private_tls_snapshot(
        backend: std::net::SocketAddr,
        server_name: &str,
        trust_bundle_ref: &str,
    ) -> ConfigSnapshot {
        ConfigSnapshot {
            schema_version: 2,
            revision_id: ConfigRevisionId::new("private-tls-runtime"),
            admin: edge_domain::AdminConfig {
                bind: "127.0.0.1:9443".to_string(),
                auth_required: true,
            },
            listeners: vec![],
            routes: vec![edge_domain::Route {
                id: edge_domain::RouteId::new("public-route"),
                route_match: edge_domain::RouteMatch::new(
                    vec![edge_domain::HostMatch::exact("public.example.test")],
                    vec![edge_domain::PathMatch::prefix("/")],
                ),
                service_id: edge_domain::ServiceId::new("private-backend"),
                priority: 0,
                enabled: true,
                redirect_http_to_https: false,
                certificate_resolver_id: None,
                certificate_ref: None,
            }],
            services: vec![edge_domain::Service {
                id: edge_domain::ServiceId::new("private-backend"),
                upstreams: vec![edge_domain::Upstream {
                    id: edge_domain::UpstreamId::new("private-backend-a"),
                    url: format!("https://{backend}"),
                    administrative_state: edge_domain::UpstreamAdministrativeState::Active,
                    tls: edge_domain::UpstreamTlsPolicy::ServerAuthenticated {
                        server_name: edge_domain::TlsServerName::parse(server_name).unwrap(),
                        http_host: edge_domain::UpstreamHttpHost::parse("backend.private.test")
                            .unwrap(),
                        trust_bundle_ref: edge_domain::TrustBundleRef::parse(trust_bundle_ref)
                            .unwrap(),
                    },
                }],
                policy: edge_domain::ServicePolicy::default(),
            }],
            certificate_resolvers: vec![],
            log_mode: edge_domain::LogMode::Product,
            runtime: edge_domain::RuntimeOptions {
                max_connections: 32,
                max_inflight_payload_bytes: 128 * 1024 * 1024,
                max_request_header_bytes: 16 * 1024,
                max_request_body_bytes: 1024 * 1024,
                upstream_read_timeout_ms: edge_domain::DEFAULT_UPSTREAM_READ_TIMEOUT_MS,
                metrics: edge_domain::MetricsConfig::default(),
            },
        }
    }

    fn spawn_private_tls_backend(
        fixture: &PrivatePkiFixture,
    ) -> (
        std::net::SocketAddr,
        std::thread::JoinHandle<Option<String>>,
    ) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_config = load_rustls_server_config(&fixture.stored_certificate("backend"))
            .unwrap()
            .server_config;
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(15)))
                .unwrap();
            let connection = rustls::ServerConnection::new(server_config).unwrap();
            let mut stream = rustls::StreamOwned::new(connection, stream);
            let mut request = Vec::new();
            let mut buffer = [0_u8; 512];
            loop {
                let read = match stream.read(&mut buffer) {
                    Ok(0) | Err(_) => return None,
                    Ok(read) => read,
                };
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecure",
                )
                .unwrap();
            stream.flush().unwrap();
            Some(String::from_utf8_lossy(&request).to_string())
        });
        (address, handle)
    }

    fn spawn_private_tls_websocket_backend(
        fixture: &PrivatePkiFixture,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_config = load_rustls_server_config(&fixture.stored_certificate("backend-ws"))
            .unwrap()
            .server_config;
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(15)))
                .unwrap();
            let connection = rustls::ServerConnection::new(server_config).unwrap();
            let mut stream = rustls::StreamOwned::new(connection, stream);
            let mut request = Vec::new();
            let mut buffer = [0_u8; 512];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).unwrap();
                request.extend_from_slice(&buffer[..read]);
            }
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                )
                .unwrap();
            stream.flush().unwrap();
            let mut ping = [0_u8; 4];
            stream.read_exact(&mut ping).unwrap();
            assert_eq!(&ping, b"ping");
            stream.write_all(b"pong").unwrap();
            stream.flush().unwrap();
            String::from_utf8_lossy(&request).to_string()
        });
        (address, handle)
    }

    fn run_outbound_private_tls_case(
        server_fixture: &PrivatePkiFixture,
        trusted_root_pem: &str,
        server_name: &str,
    ) -> (String, Option<String>) {
        let (backend, backend_thread) = spawn_private_tls_backend(server_fixture);
        let snapshot = outbound_private_tls_snapshot(backend, server_name, "private-server-root");
        let mut reader = TestTrustBundleReader::new("private-server-root", trusted_root_pem);
        let registry = prepare_upstream_tls_runtime(&snapshot, &mut reader)
            .unwrap()
            .request_registry;
        let proxy_addr = free_loopback_addr();
        let (mut command_client, command_receiver) = runtime_command_channel(8);
        let runtime = std::thread::spawn(move || {
            run_snapshot_http_proxy_mio(
                SnapshotProxyConfig::new(proxy_addr, snapshot, HttpLimits::default())
                    .with_client_tls_registry(registry)
                    .with_runtime_commands(command_receiver),
            )
        });
        assert!(command_client
            .send(CoreCommand::RefreshRouteTable)
            .is_success());

        let mut client = std::net::TcpStream::connect(proxy_addr).unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        client
            .write_all(
                b"GET /private HTTP/1.1\r\nHost: public.example.test\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        assert!(command_client.send(CoreCommand::Shutdown).is_success());
        runtime.join().unwrap().unwrap();
        (response, backend_thread.join().unwrap())
    }

    fn spawn_text_backend_for_requests(
        body: &'static str,
        request_count: usize,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<Vec<String>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..request_count {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut buffer = [0_u8; 512];
                loop {
                    let read = stream.read(&mut buffer).unwrap();
                    request.extend_from_slice(&buffer[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).unwrap();
                requests.push(String::from_utf8_lossy(&request).to_string());
            }
            requests
        });
        (address, handle)
    }

    fn spawn_websocket_backend() -> (std::net::SocketAddr, std::thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 512];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).unwrap();
                request.extend_from_slice(&buffer[..read]);
            }
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                )
                .unwrap();
            let mut ping = [0_u8; 4];
            stream.read_exact(&mut ping).unwrap();
            assert_eq!(&ping, b"ping");
            stream.write_all(b"pong").unwrap();
            String::from_utf8_lossy(&request).to_string()
        });
        (address, handle)
    }

    fn https_get(addr: std::net::SocketAddr, certificate_pem: &str) -> String {
        https_get_for_host(addr, "localhost", certificate_pem)
    }

    fn https_get_for_host(addr: std::net::SocketAddr, host: &str, certificate_pem: &str) -> String {
        let mut tls_stream = rustls_test_stream(addr, host, certificate_pem);
        tls_stream
            .write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
            .unwrap();
        read_https_response(&mut tls_stream)
    }

    fn https_get_result(
        addr: std::net::SocketAddr,
        host: &str,
        root_pem: &str,
    ) -> Result<String, String> {
        let mut tls_stream = rustls_test_stream(addr, host, root_pem);
        tls_stream
            .write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
            .map_err(|error| error.to_string())?;
        let mut response = Vec::new();
        tls_stream
            .read_to_end(&mut response)
            .map_err(|error| error.to_string())?;
        String::from_utf8(response).map_err(|error| error.to_string())
    }

    fn https_get_with_client_result(
        addr: std::net::SocketAddr,
        host: &str,
        server_root_pem: &str,
        client_chain_pem: &str,
        client_key_pem: &str,
    ) -> Result<String, String> {
        let mut tls_stream = rustls_mtls_test_stream(
            addr,
            host,
            server_root_pem,
            client_chain_pem,
            client_key_pem,
        );
        tls_stream
            .write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
            .map_err(|error| error.to_string())?;
        let mut response = Vec::new();
        tls_stream
            .read_to_end(&mut response)
            .map_err(|error| error.to_string())?;
        String::from_utf8(response).map_err(|error| error.to_string())
    }

    fn private_tls_handshake(
        server_config: Arc<rustls::ServerConfig>,
        host: &str,
        root_pem: &str,
    ) -> Result<(), String> {
        use rustls_pki_types::pem::PemObject;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut connection = rustls::ServerConnection::new(server_config).unwrap();
            connection.complete_io(&mut stream).map(|_| ())
        });
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(
                rustls_pki_types::CertificateDer::from_pem_slice(root_pem.as_bytes())
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| error.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name = rustls_pki_types::ServerName::try_from(host.to_string())
            .map_err(|error| error.to_string())?;
        let mut connection = rustls::ClientConnection::new(Arc::new(config), server_name)
            .map_err(|error| error.to_string())?;
        let mut stream =
            std::net::TcpStream::connect(address).map_err(|error| error.to_string())?;
        let client_result = connection
            .complete_io(&mut stream)
            .map(|_| ())
            .map_err(|error| error.to_string());
        let _ = server.join();
        client_result
    }

    fn run_private_pki_snapshot_request(
        snapshot: ConfigSnapshot,
        certificate: edge_ports::StoredCertificate,
        host: &str,
        root_pem: &str,
    ) -> String {
        let loaded = load_rustls_server_config(&certificate).unwrap();
        let http_addr = free_loopback_addr();
        let https_addr = free_loopback_addr();
        let (mut command_client, command_receiver) = runtime_command_channel(8);
        let runtime = std::thread::spawn(move || {
            run_snapshot_http_proxy_mio(
                SnapshotProxyConfig::new(http_addr, snapshot, HttpLimits::default())
                    .with_runtime_commands(command_receiver)
                    .with_https_listener(
                        https_addr,
                        RustlsServerTlsSessionFactory::new(loaded.server_config),
                    ),
            )
        });
        assert!(command_client
            .send(CoreCommand::RefreshRouteTable)
            .is_success());
        let unrelated_root = rcgen::generate_simple_self_signed(vec!["unrelated.test".into()])
            .unwrap()
            .cert
            .pem();
        assert!(https_get_result(https_addr, host, &unrelated_root).is_err());
        let response = https_get_result(https_addr, host, root_pem).unwrap();
        assert!(command_client.send(CoreCommand::Shutdown).is_success());
        runtime.join().unwrap().unwrap();
        response
    }

    fn read_https_response(
        tls_stream: &mut rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>,
    ) -> String {
        let mut response = String::new();
        let mut buffer = [0_u8; 1024];
        loop {
            match tls_stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => response.push_str(&String::from_utf8_lossy(&buffer[..read])),
                Err(error)
                    if error.kind() == std::io::ErrorKind::UnexpectedEof
                        && !response.is_empty() =>
                {
                    break;
                }
                Err(error) => panic!("https client read failed: {error}; response={response:?}"),
            }
        }
        response
    }

    fn rustls_test_stream(
        addr: std::net::SocketAddr,
        host: &str,
        certificate_pem: &str,
    ) -> rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream> {
        use rustls_pki_types::pem::PemObject;

        let certificate =
            rustls_pki_types::CertificateDer::from_pem_slice(certificate_pem.as_bytes()).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let client_config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name = rustls_pki_types::ServerName::try_from(host.to_string()).unwrap();
        let connection =
            rustls::ClientConnection::new(std::sync::Arc::new(client_config), server_name).unwrap();
        let stream = std::net::TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        rustls::StreamOwned::new(connection, stream)
    }

    fn rustls_mtls_test_stream(
        addr: std::net::SocketAddr,
        host: &str,
        server_root_pem: &str,
        client_chain_pem: &str,
        client_key_pem: &str,
    ) -> rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream> {
        use rustls_pki_types::pem::PemObject;

        let server_root =
            rustls_pki_types::CertificateDer::from_pem_slice(server_root_pem.as_bytes()).unwrap();
        let client_chain =
            rustls_pki_types::CertificateDer::pem_slice_iter(client_chain_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let client_key =
            rustls_pki_types::PrivateKeyDer::from_pem_slice(client_key_pem.as_bytes()).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(server_root).unwrap();
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let client_config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_client_auth_cert(client_chain, client_key)
            .unwrap();
        let server_name = rustls_pki_types::ServerName::try_from(host.to_string()).unwrap();
        let connection =
            rustls::ClientConnection::new(std::sync::Arc::new(client_config), server_name).unwrap();
        let stream = std::net::TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        rustls::StreamOwned::new(connection, stream)
    }

    fn test_certificate(certificate_ref: &str) -> edge_ports::StoredCertificate {
        test_certificate_for_host(certificate_ref, "localhost")
    }

    fn test_certificate_for_host(
        certificate_ref: &str,
        host: &str,
    ) -> edge_ports::StoredCertificate {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec![host.to_string()]).unwrap();
        edge_ports::StoredCertificate {
            certificate_ref: CertificateRef::new(certificate_ref),
            domains: vec![host.to_string()],
            not_after_epoch_seconds: 4_000_000_000,
            source: "manual".to_string(),
            certificate_pem: cert.pem(),
            private_key_pem: signing_key.serialize_pem(),
        }
    }

    struct PrivatePkiFixture {
        dns_name: String,
        root_pem: String,
        intermediate_pem: String,
        leaf_pem: String,
        fullchain_pem: String,
        leaf_key_pem: String,
    }

    struct PrivateClientPkiFixture {
        root_pem: String,
        fullchain_pem: String,
        leaf_key_pem: String,
    }

    impl PrivateClientPkiFixture {
        fn new() -> Self {
            use rcgen::{
                BasicConstraints, CertificateParams, CertifiedIssuer, DnType,
                ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
            };

            let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
            root_params
                .distinguished_name
                .push(DnType::CommonName, "Sponzey Test Client Root");
            root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
            root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            root_params.not_before = rcgen::date_time_ymd(2025, 1, 1);
            root_params.not_after = rcgen::date_time_ymd(2035, 1, 1);
            let root =
                CertifiedIssuer::self_signed(root_params, KeyPair::generate().unwrap()).unwrap();

            let mut intermediate_params = CertificateParams::new(Vec::<String>::new()).unwrap();
            intermediate_params
                .distinguished_name
                .push(DnType::CommonName, "Sponzey Test Client Issuing CA");
            intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            intermediate_params.key_usages =
                vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            intermediate_params.not_before = rcgen::date_time_ymd(2025, 1, 1);
            intermediate_params.not_after = rcgen::date_time_ymd(2034, 1, 1);
            let intermediate = CertifiedIssuer::signed_by(
                intermediate_params,
                KeyPair::generate().unwrap(),
                &root,
            )
            .unwrap();

            let leaf_key = KeyPair::generate().unwrap();
            let mut leaf_params = CertificateParams::new(Vec::<String>::new()).unwrap();
            leaf_params
                .distinguished_name
                .push(DnType::CommonName, "operator.private.test");
            leaf_params.is_ca = IsCa::ExplicitNoCa;
            leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            leaf_params.not_before = rcgen::date_time_ymd(2025, 1, 1);
            leaf_params.not_after = rcgen::date_time_ymd(2033, 1, 1);
            let leaf = leaf_params.signed_by(&leaf_key, &intermediate).unwrap();
            Self {
                root_pem: root.pem(),
                fullchain_pem: format!("{}{}", leaf.pem(), intermediate.pem()),
                leaf_key_pem: leaf_key.serialize_pem(),
            }
        }
    }

    impl PrivatePkiFixture {
        fn new(dns_name: &str) -> Self {
            Self::new_with_leaf_validity(dns_name, (2025, 1, 1), (2033, 1, 1))
        }

        fn new_with_leaf_validity(
            dns_name: &str,
            not_before: (i32, u8, u8),
            not_after: (i32, u8, u8),
        ) -> Self {
            use rcgen::{
                BasicConstraints, CertificateParams, CertifiedIssuer, DnType,
                ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
            };

            let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
            root_params
                .distinguished_name
                .push(DnType::CommonName, "Sponzey Test Root");
            root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
            root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            root_params.not_before = rcgen::date_time_ymd(2025, 1, 1);
            root_params.not_after = rcgen::date_time_ymd(2035, 1, 1);
            let root =
                CertifiedIssuer::self_signed(root_params, KeyPair::generate().unwrap()).unwrap();

            let mut intermediate_params = CertificateParams::new(Vec::<String>::new()).unwrap();
            intermediate_params
                .distinguished_name
                .push(DnType::CommonName, "Sponzey Test Issuing CA");
            intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            intermediate_params.key_usages =
                vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            intermediate_params.not_before = rcgen::date_time_ymd(2025, 1, 1);
            intermediate_params.not_after = rcgen::date_time_ymd(2034, 1, 1);
            let intermediate = CertifiedIssuer::signed_by(
                intermediate_params,
                KeyPair::generate().unwrap(),
                &root,
            )
            .unwrap();

            let leaf_key = KeyPair::generate().unwrap();
            let mut leaf_params = CertificateParams::new(vec![dns_name.to_string()]).unwrap();
            leaf_params
                .distinguished_name
                .push(DnType::CommonName, dns_name);
            leaf_params.is_ca = IsCa::ExplicitNoCa;
            leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            leaf_params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
            leaf_params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
            let leaf = leaf_params.signed_by(&leaf_key, &intermediate).unwrap();
            let leaf_pem = leaf.pem();
            let intermediate_pem = intermediate.pem();

            Self {
                dns_name: dns_name.to_string(),
                root_pem: root.pem(),
                fullchain_pem: format!("{leaf_pem}{intermediate_pem}"),
                intermediate_pem,
                leaf_pem,
                leaf_key_pem: leaf_key.serialize_pem(),
            }
        }

        fn stored_certificate(&self, certificate_ref: &str) -> edge_ports::StoredCertificate {
            edge_ports::StoredCertificate {
                certificate_ref: CertificateRef::new(certificate_ref),
                domains: vec![self.dns_name.clone()],
                not_after_epoch_seconds: 1_988_150_400,
                source: "manual".to_string(),
                certificate_pem: self.fullchain_pem.clone(),
                private_key_pem: self.leaf_key_pem.clone(),
            }
        }
    }
}
