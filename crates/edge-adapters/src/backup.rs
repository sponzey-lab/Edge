use age::{secrecy::SecretString, stream::StreamWriter, Encryptor};
use edge_application::parse_mvp_config;
use edge_domain::{
    validate_manifest_encoded_size, AppError, BackupArtifactDescriptor, BackupArtifactKind,
    BackupArtifactMode, BackupLimits, BackupManifest, ConfigRevisionId, ErrorCode, SensitiveString,
};
use edge_ports::{
    AuditLedgerReader, AuditLedgerVerifier, BackupArchiveRead, BackupArchiveReader,
    BackupArchiveWriter, BackupArtifact, BackupArtifactSource, BackupManifestDigester,
    BackupRecordSummary, BackupSourceInventory, CertificateStore, Clock, ConfigRevisionRepository,
    OperationIdGenerator, RestoreArchiveExtractor, RestorePreflight, RestorePublisher,
    RestoreReplacePublisher, RestoreRollbackOutcome, RestoreStageSummary, RestoreTransaction,
    RestoreTransactionState, RestoreTransactionStore, SecretStore, TrustBundleMaterialValidator,
    TrustBundleReader, TrustBundleStore,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

const BODY_MAGIC: &[u8] = b"SPONZEY-BACKUP-V1\0";

pub struct SystemClock;
impl Clock for SystemClock {
    fn now_epoch_seconds(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0)
    }
}

pub struct RandomOperationIdGenerator;
impl OperationIdGenerator for RandomOperationIdGenerator {
    fn next_id(&mut self) -> Result<String, AppError> {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| {
            AppError::new(ErrorCode::InternalBug, "cryptographic random source failed")
        })?;
        Ok(hex(&bytes))
    }
}

pub struct AgeBackupArchiveReader {
    input: PathBuf,
}

impl AgeBackupArchiveReader {
    pub fn new(input: impl AsRef<Path>) -> Self {
        Self {
            input: input.as_ref().to_path_buf(),
        }
    }
}

impl BackupArchiveReader for AgeBackupArchiveReader {
    fn read(
        &mut self,
        secret: &SensitiveString,
        limits: &BackupLimits,
    ) -> Result<BackupArchiveRead, AppError> {
        read_archive_records(&self.input, secret, limits, |_, _| Ok(()))
    }
}

fn read_archive_records(
    input: &Path,
    secret: &SensitiveString,
    limits: &BackupLimits,
    mut accept: impl FnMut(&BackupArtifactDescriptor, &[u8]) -> Result<(), AppError>,
) -> Result<BackupArchiveRead, AppError> {
    let file = open_regular_no_follow(input)?;
    let decryptor =
        age::Decryptor::new_buffered(BufReader::new(file)).map_err(|_| authentication_failed())?;
    let identity =
        secret.expose(|value| age::scrypt::Identity::new(SecretString::from(value.to_string())));
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|_| authentication_failed())?;
    let mut magic = [0_u8; BODY_MAGIC.len()];
    read_authenticated(&mut reader, &mut magic)?;
    if magic != BODY_MAGIC {
        return Err(format_invalid());
    }
    let manifest_len = read_u64_authenticated(&mut reader)?;
    validate_manifest_encoded_size(manifest_len, limits)?;
    let manifest_size: usize = manifest_len.try_into().map_err(|_| limit_exceeded())?;
    let mut encoded = vec![0_u8; manifest_size];
    read_authenticated(&mut reader, &mut encoded)?;
    let manifest = decode_manifest(&encoded, limits)?;
    let mut records = Vec::with_capacity(manifest.artifacts.len());
    let mut total = 0_u64;
    for expected in &manifest.artifacts {
        let mut record_magic = [0_u8; 4];
        read_authenticated(&mut reader, &mut record_magic)?;
        if &record_magic != b"REC1" {
            return Err(format_invalid());
        }
        let path = read_string_authenticated(&mut reader, limits.max_logical_path_bytes)?;
        let length = read_u64_authenticated(&mut reader)?;
        if length > limits.max_single_artifact_bytes {
            return Err(limit_exceeded());
        }
        total = total.checked_add(length).ok_or_else(limit_exceeded)?;
        if total > limits.max_total_plaintext_bytes {
            return Err(limit_exceeded());
        }
        let payload_size: usize = length.try_into().map_err(|_| limit_exceeded())?;
        let mut payload = vec![0_u8; payload_size];
        read_authenticated(&mut reader, &mut payload)?;
        let digest = Sha256::digest(&payload);
        records.push(BackupRecordSummary {
            relative_logical_path: path,
            length_bytes: length,
            sha256: digest.into(),
        });
        if records.len() > limits.max_artifacts as usize {
            return Err(limit_exceeded());
        }
        if records.last().unwrap().relative_logical_path != expected.relative_logical_path {
            return Err(AppError::new(
                ErrorCode::BackupPathUnsafe,
                ErrorCode::BackupPathUnsafe.default_user_message(),
            ));
        }
        accept(expected, &payload)?;
    }
    let mut trailing = [0_u8; 1];
    match reader.read(&mut trailing) {
        Ok(0) => {}
        Ok(_) => return Err(format_invalid()),
        Err(_) => return Err(authentication_failed()),
    }
    Ok(BackupArchiveRead { manifest, records })
}

pub struct FileRestoreArchiveExtractor {
    input: PathBuf,
    stage: PathBuf,
}

impl FileRestoreArchiveExtractor {
    pub fn new(input: impl AsRef<Path>, target: impl AsRef<Path>) -> Result<Self, AppError> {
        let target = target.as_ref();
        let parent = target.parent().ok_or_else(restore_target_unsafe)?;
        let name = target
            .file_name()
            .and_then(|v| v.to_str())
            .filter(|v| !v.is_empty())
            .ok_or_else(restore_target_unsafe)?;
        Ok(Self {
            input: input.as_ref().to_path_buf(),
            stage: parent.join(format!(".{name}.restore-stage")),
        })
    }

    pub fn stage_path(&self) -> &Path {
        &self.stage
    }
}

impl RestoreArchiveExtractor for FileRestoreArchiveExtractor {
    fn extract(
        &mut self,
        secret: &SensitiveString,
        limits: &BackupLimits,
    ) -> Result<RestoreStageSummary, AppError> {
        if self.stage.exists() {
            return Err(restore_stage_failed());
        }
        create_private_directory(&self.stage)?;
        let result = read_archive_records(&self.input, secret, limits, |descriptor, payload| {
            let path = restore_artifact_path(&self.stage, descriptor)?;
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|_| restore_stage_failed())?;
                if descriptor.kind == BackupArtifactKind::AuditLedgerSegment {
                    make_private_directory(parent)?;
                }
            }
            write_restored_file(&path, payload, descriptor.mode)
        });
        let archive = match result {
            Ok(value) => value,
            Err(error) => {
                let _ = fs::remove_dir_all(&self.stage);
                return Err(error);
            }
        };
        archive.manifest.validate(limits)?;
        if Sha256BackupManifestDigester.digest(&archive.manifest)?
            != archive.manifest.manifest_digest
            || archive
                .records
                .iter()
                .zip(&archive.manifest.artifacts)
                .any(|(actual, expected)| {
                    actual.relative_logical_path != expected.relative_logical_path
                        || actual.length_bytes != expected.length_bytes
                        || actual.sha256 != expected.sha256
                })
        {
            let _ = fs::remove_dir_all(&self.stage);
            return Err(AppError::new(
                ErrorCode::BackupDigestMismatch,
                ErrorCode::BackupDigestMismatch.default_user_message(),
            ));
        }
        sync_tree_files(&self.stage)?;
        Ok(RestoreStageSummary {
            stage_identity: self
                .stage
                .file_name()
                .and_then(|v| v.to_str())
                .unwrap_or("restore-stage")
                .to_string(),
            archive_id: archive.manifest.archive_id,
            revision_id: ConfigRevisionId::new(archive.manifest.current_revision_id),
            artifact_count: archive.manifest.artifact_count,
            certificate_count: archive
                .manifest
                .artifacts
                .iter()
                .filter(|item| matches!(item.kind, BackupArtifactKind::CertificateChain))
                .count() as u32,
            trust_bundle_count: archive
                .manifest
                .artifacts
                .iter()
                .filter(|item| matches!(item.kind, BackupArtifactKind::TrustBundleRoots))
                .count() as u32,
            audit_segment_count: archive
                .manifest
                .artifacts
                .iter()
                .filter(|item| item.kind == BackupArtifactKind::AuditLedgerSegment)
                .count()
                .try_into()
                .map_err(|_| limit_exceeded())?,
            admin_initialized: archive.manifest.admin_initialized,
            referenced_certificate_refs: archive.manifest.referenced_certificate_refs,
            referenced_trust_bundle_refs: archive.manifest.referenced_trust_bundle_refs,
        })
    }
    fn cleanup(&mut self) -> Result<(), AppError> {
        match fs::remove_dir_all(&self.stage) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(restore_stage_failed()),
        }
    }
}

pub struct FileRestorePreflight {
    stage: PathBuf,
}
impl FileRestorePreflight {
    pub fn new(stage: impl AsRef<Path>) -> Self {
        Self {
            stage: stage.as_ref().to_path_buf(),
        }
    }
}
impl RestorePreflight for FileRestorePreflight {
    fn validate_config(&mut self, stage: &RestoreStageSummary) -> Result<(), AppError> {
        let current = crate::FileRevisionRepository::new(self.stage.join("config"))
            .current()
            .map_err(|_| restore_config_invalid())?
            .ok_or_else(restore_config_invalid)?;
        if current.revision.id != stage.revision_id {
            return Err(restore_config_invalid());
        }
        Ok(())
    }
    fn validate_certificates(&mut self, stage: &RestoreStageSummary) -> Result<(), AppError> {
        let store = crate::FileCertificateStore::new(self.stage.join("certs"));
        for certificate_ref in &stage.referenced_certificate_refs {
            let certificate = store
                .load_certificate(&edge_domain::CertificateRef::new(certificate_ref))
                .map_err(|_| restore_certificate_invalid())?
                .ok_or_else(restore_certificate_invalid)?;
            crate::load_rustls_server_config(&certificate)
                .map_err(|_| restore_certificate_invalid())?;
        }
        Ok(())
    }
    fn validate_secrets(&mut self, stage: &RestoreStageSummary) -> Result<(), AppError> {
        let secret = crate::FileSecretStore::new(self.stage.join("secrets"))
            .load_secret("admin-password-hash")
            .map_err(|_| restore_secret_invalid())?;
        if stage.admin_initialized != secret.is_some() {
            return Err(restore_secret_invalid());
        }
        Ok(())
    }
    fn validate_audit(&mut self, stage: &RestoreStageSummary) -> Result<(), AppError> {
        if stage.audit_segment_count == 0 {
            return Ok(());
        }
        let mut ledger =
            crate::FileAuditLedger::open(&self.stage, crate::AuditLedgerOptions::default())?;
        let report = ledger.verify()?;
        if report.segment_count != stage.audit_segment_count
            || report.incomplete_operation_count != 0
            || !ledger.unresolved_reconciliations()?.is_empty()
        {
            return Err(AppError::new(
                ErrorCode::AuditReconciliationUnknown,
                "restored audit ledger requires reconciliation",
            ));
        }
        Ok(())
    }
    fn preflight_runtime(&mut self, stage: &RestoreStageSummary) -> Result<(), AppError> {
        let current = crate::FileRevisionRepository::new(self.stage.join("config"))
            .current()
            .map_err(|_| restore_config_invalid())?
            .ok_or_else(restore_config_invalid)?;
        let mut config_references = BTreeSet::new();
        collect_snapshot_trust_refs(&current.snapshot, &mut config_references);
        let manifest_references = stage
            .referenced_trust_bundle_refs
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if !config_references.is_subset(&manifest_references) {
            return Err(restore_config_invalid());
        }
        let mut store = crate::FileTrustBundleStore::new(self.stage.join("trust-bundles"));
        let listed = store
            .list_trust_bundles()
            .map_err(|_| restore_certificate_invalid())?;
        if listed.len() as u32 != stage.trust_bundle_count {
            return Err(restore_certificate_invalid());
        }
        let listed_refs = listed
            .iter()
            .map(|item| item.trust_bundle_ref.as_str())
            .collect::<BTreeSet<_>>();
        if !manifest_references
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            .is_subset(&listed_refs)
        {
            return Err(restore_certificate_invalid());
        }
        for metadata in listed {
            let bundle = store
                .load_trust_bundle(&metadata.trust_bundle_ref)
                .map_err(|_| restore_certificate_invalid())?
                .ok_or_else(restore_certificate_invalid)?;
            let validated = crate::RustlsTrustBundleMaterialValidator
                .validate_trust_bundle(
                    &metadata.trust_bundle_ref,
                    bundle.encoded_material(),
                    metadata.imported_at_epoch_seconds,
                )
                .map_err(|_| restore_certificate_invalid())?;
            if validated.metadata != metadata {
                return Err(restore_certificate_invalid());
            }
        }
        Ok(())
    }
}

pub struct FileNewTargetRestorePublisher {
    stage: PathBuf,
    target: PathBuf,
}

pub struct FileRestoreTransactionStore {
    journal: PathBuf,
    temporary: PathBuf,
}
impl FileRestoreTransactionStore {
    pub fn new(target: impl AsRef<Path>) -> Result<Self, AppError> {
        let target = target.as_ref();
        let parent = target.parent().ok_or_else(restore_target_unsafe)?;
        let name = target
            .file_name()
            .and_then(|v| v.to_str())
            .filter(|v| !v.is_empty())
            .ok_or_else(restore_target_unsafe)?;
        let journal = parent.join(format!(".{name}.restore-journal"));
        Ok(Self {
            temporary: journal.with_extension("restore-journal.tmp"),
            journal,
        })
    }
}
impl RestoreTransactionStore for FileRestoreTransactionStore {
    fn persist(&mut self, tx: &RestoreTransaction) -> Result<(), AppError> {
        validate_transaction_values(tx)?;
        let body = format!(
            "version=1\noperation={}\narchive={}\ntarget={}\nstage={}\nrollback={}\nstate={}\n",
            hex(tx.operation_id.as_bytes()),
            hex(tx.archive_id.as_bytes()),
            hex(tx.target_identity.as_bytes()),
            hex(tx.stage_identity.as_bytes()),
            hex(tx.rollback_identity.as_bytes()),
            transaction_state_name(tx.state)
        );
        let mut file = create_private_file(&self.temporary)
            .or_else(|error| {
                if self.temporary.exists() {
                    fs::remove_file(&self.temporary).map_err(|_| restore_commit_failed())?;
                    create_private_file(&self.temporary)
                } else {
                    Err(error)
                }
            })
            .map_err(|_| restore_commit_failed())?;
        file.write_all(body.as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|_| restore_commit_failed())?;
        fs::rename(&self.temporary, &self.journal).map_err(|_| restore_commit_failed())?;
        sync_parent(&self.journal).map_err(|_| restore_commit_failed())
    }
    fn load(&mut self, operation_id: &str) -> Result<Option<RestoreTransaction>, AppError> {
        if !self.journal.exists() {
            return Ok(None);
        }
        let (bytes, _) =
            read_regular_no_follow(&self.journal, ErrorCode::RestoreTransactionUnresolved)?;
        let source = std::str::from_utf8(&bytes).map_err(|_| restore_transaction_unresolved())?;
        let mut values = BTreeMap::new();
        for line in source.lines() {
            let (key, value) = line
                .split_once('=')
                .ok_or_else(restore_transaction_unresolved)?;
            if values.insert(key, value).is_some() {
                return Err(restore_transaction_unresolved());
            }
        }
        if values.remove("version") != Some("1") || values.len() != 6 {
            return Err(restore_transaction_unresolved());
        }
        let decode = |key: &str| -> Result<String, AppError> {
            decode_hex(
                values
                    .get(key)
                    .copied()
                    .ok_or_else(restore_transaction_unresolved)?,
            )
            .ok_or_else(restore_transaction_unresolved)
        };
        let state = match values.get("state").copied() {
            Some("prepared") => RestoreTransactionState::Prepared,
            Some("target_moved") => RestoreTransactionState::TargetMoved,
            Some("stage_published") => RestoreTransactionState::StagePublished,
            _ => return Err(restore_transaction_unresolved()),
        };
        let tx = RestoreTransaction {
            operation_id: decode("operation")?,
            archive_id: decode("archive")?,
            target_identity: decode("target")?,
            stage_identity: decode("stage")?,
            rollback_identity: decode("rollback")?,
            state,
        };
        validate_transaction_values(&tx)?;
        if tx.operation_id != operation_id {
            return Err(restore_transaction_unresolved());
        }
        Ok(Some(tx))
    }
    fn delete(&mut self, _: &str) -> Result<(), AppError> {
        match fs::remove_file(&self.journal) {
            Ok(()) => sync_parent(&self.journal).map_err(|_| restore_commit_failed()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(restore_commit_failed()),
        }
    }
}

pub struct FileReplaceRestorePublisher {
    target: PathBuf,
    stage: PathBuf,
    rollback: PathBuf,
}
impl FileReplaceRestorePublisher {
    pub fn new(target: impl AsRef<Path>, stage: impl AsRef<Path>) -> Result<Self, AppError> {
        let target = target.as_ref().to_path_buf();
        let parent = target.parent().ok_or_else(restore_target_unsafe)?;
        let name = target
            .file_name()
            .and_then(|v| v.to_str())
            .filter(|v| !v.is_empty())
            .ok_or_else(restore_target_unsafe)?;
        Ok(Self {
            stage: stage.as_ref().to_path_buf(),
            rollback: parent.join(format!(".{name}.restore-rollback")),
            target,
        })
    }
    fn validate(&self, tx: &RestoreTransaction) -> Result<(), AppError> {
        if self.target.file_name().and_then(|v| v.to_str()) != Some(tx.target_identity.as_str())
            || self.stage.file_name().and_then(|v| v.to_str()) != Some(tx.stage_identity.as_str())
            || self.rollback.file_name().and_then(|v| v.to_str())
                != Some(tx.rollback_identity.as_str())
        {
            return Err(restore_transaction_unresolved());
        }
        Ok(())
    }
}
impl RestoreReplacePublisher for FileReplaceRestorePublisher {
    fn prepare_replace(
        &mut self,
        operation_id: &str,
        stage: &RestoreStageSummary,
    ) -> Result<RestoreTransaction, AppError> {
        if !self.target.is_dir() || !self.stage.is_dir() || self.rollback.exists() {
            return Err(restore_target_unsafe());
        }
        let tx = RestoreTransaction {
            operation_id: operation_id.to_string(),
            archive_id: stage.archive_id.clone(),
            target_identity: self
                .target
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string(),
            stage_identity: self
                .stage
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string(),
            rollback_identity: self
                .rollback
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string(),
            state: RestoreTransactionState::Prepared,
        };
        validate_transaction_values(&tx)?;
        Ok(tx)
    }
    fn move_target_to_rollback(&mut self, tx: &RestoreTransaction) -> Result<(), AppError> {
        self.validate(tx)?;
        fs::rename(&self.target, &self.rollback).map_err(|_| restore_commit_failed())?;
        sync_parent(&self.target).map_err(|_| restore_commit_failed())
    }
    fn publish_stage(&mut self, tx: &RestoreTransaction) -> Result<(), AppError> {
        self.validate(tx)?;
        fs::rename(&self.stage, &self.target).map_err(|_| restore_commit_failed())?;
        sync_parent(&self.target).map_err(|_| restore_commit_failed())
    }
    fn verify_target(
        &mut self,
        tx: &RestoreTransaction,
        stage: &RestoreStageSummary,
    ) -> Result<(), AppError> {
        self.validate(tx)?;
        let current = crate::FileRevisionRepository::new(self.target.join("config"))
            .current()
            .map_err(|_| restore_commit_failed())?
            .ok_or_else(restore_commit_failed)?;
        if current.revision.id != stage.revision_id {
            return Err(restore_commit_failed());
        }
        Ok(())
    }
    fn rollback_after_failure(
        &mut self,
        tx: &RestoreTransaction,
    ) -> Result<RestoreRollbackOutcome, AppError> {
        self.validate(tx)?;
        if !self.rollback.is_dir() {
            return Ok(RestoreRollbackOutcome::NotRequired);
        }
        if self.target.exists() {
            fs::remove_dir_all(&self.target).map_err(|_| restore_rollback_failed())?;
        }
        fs::rename(&self.rollback, &self.target).map_err(|_| restore_rollback_failed())?;
        if self.stage.exists() {
            fs::remove_dir_all(&self.stage).map_err(|_| restore_rollback_failed())?;
        }
        sync_parent(&self.target).map_err(|_| restore_rollback_failed())?;
        Ok(RestoreRollbackOutcome::Restored)
    }
    fn cleanup_committed(&mut self, tx: &RestoreTransaction) -> Result<(), AppError> {
        self.validate(tx)?;
        if self.rollback.exists() {
            fs::remove_dir_all(&self.rollback).map_err(|_| restore_commit_failed())?;
        }
        if self.stage.exists() {
            fs::remove_dir_all(&self.stage).map_err(|_| restore_commit_failed())?;
        }
        sync_parent(&self.target).map_err(|_| restore_commit_failed())
    }
    fn target_valid(&mut self, tx: &RestoreTransaction) -> Result<bool, AppError> {
        self.validate(tx)?;
        Ok(
            crate::FileRevisionRepository::new(self.target.join("config"))
                .current()
                .ok()
                .flatten()
                .is_some(),
        )
    }
    fn rollback_valid(&mut self, tx: &RestoreTransaction) -> Result<bool, AppError> {
        self.validate(tx)?;
        Ok(
            crate::FileRevisionRepository::new(self.rollback.join("config"))
                .current()
                .ok()
                .flatten()
                .is_some(),
        )
    }
}

fn transaction_state_name(state: RestoreTransactionState) -> &'static str {
    match state {
        RestoreTransactionState::Prepared => "prepared",
        RestoreTransactionState::TargetMoved => "target_moved",
        RestoreTransactionState::StagePublished => "stage_published",
    }
}
fn validate_transaction_values(tx: &RestoreTransaction) -> Result<(), AppError> {
    for value in [
        &tx.operation_id,
        &tx.archive_id,
        &tx.target_identity,
        &tx.stage_identity,
        &tx.rollback_identity,
    ] {
        if value.is_empty() || value.contains(['/', '\\', '\0']) || value == "." || value == ".." {
            return Err(restore_transaction_unresolved());
        }
    }
    Ok(())
}
impl FileNewTargetRestorePublisher {
    pub fn new(stage: impl AsRef<Path>, target: impl AsRef<Path>) -> Self {
        Self {
            stage: stage.as_ref().to_path_buf(),
            target: target.as_ref().to_path_buf(),
        }
    }
}
impl RestorePublisher for FileNewTargetRestorePublisher {
    fn prepare_new_target(&mut self, _: &RestoreStageSummary) -> Result<(), AppError> {
        if self.target.exists() {
            return Err(AppError::new(
                ErrorCode::RestoreTargetNotEmpty,
                ErrorCode::RestoreTargetNotEmpty.default_user_message(),
            ));
        }
        if !self.stage.is_dir() {
            return Err(restore_stage_failed());
        }
        Ok(())
    }
    fn publish_new_target(&mut self, _: &RestoreStageSummary) -> Result<(), AppError> {
        fs::rename(&self.stage, &self.target).map_err(|_| restore_commit_failed())?;
        sync_parent(&self.target).map_err(|_| restore_commit_failed())
    }
    fn verify_published_target(&mut self, stage: &RestoreStageSummary) -> Result<(), AppError> {
        let current = crate::FileRevisionRepository::new(self.target.join("config"))
            .current()
            .map_err(|_| restore_commit_failed())?
            .ok_or_else(restore_commit_failed)?;
        if current.revision.id != stage.revision_id {
            return Err(restore_commit_failed());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentity {
    length: u64,
    modified_nanos: u128,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

#[derive(Debug, Clone)]
struct SourceEntry {
    descriptor: BackupArtifactDescriptor,
    path: PathBuf,
    identity: FileIdentity,
}

struct InspectedConfig {
    current_revision_id: ConfigRevisionId,
    referenced_certificate_refs: Vec<String>,
    referenced_trust_bundle_refs: Vec<String>,
    artifacts: Vec<BackupArtifactDescriptor>,
}

#[derive(Debug)]
pub struct FileBackupArtifactSource {
    root: PathBuf,
    entries: BTreeMap<String, SourceEntry>,
}

impl FileBackupArtifactSource {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            entries: BTreeMap::new(),
        }
    }

    fn inspect(
        &mut self,
        kind: BackupArtifactKind,
        logical_id: &str,
        logical_path: &str,
        physical_path: PathBuf,
        mode: BackupArtifactMode,
    ) -> Result<BackupArtifactDescriptor, AppError> {
        let (payload, identity) =
            read_regular_no_follow(&physical_path, ErrorCode::BackupSourceInvalid)?;
        let descriptor = BackupArtifactDescriptor {
            kind,
            logical_id: logical_id.to_string(),
            relative_logical_path: logical_path.to_string(),
            length_bytes: payload.len().try_into().map_err(|_| source_invalid())?,
            sha256: sha256(&payload),
            mode,
            required_for_restore: true,
        };
        self.entries.insert(
            logical_path.to_string(),
            SourceEntry {
                descriptor: descriptor.clone(),
                path: physical_path,
                identity,
            },
        );
        Ok(descriptor)
    }

    fn inspect_config(&mut self) -> Result<InspectedConfig, AppError> {
        let config = self.root.join("config");
        reject_unknown_names(&config, &["current", "current.toml", "revisions"])?;
        let pointer_path = config.join("current");
        let (pointer, _) = read_regular_no_follow(&pointer_path, ErrorCode::BackupSourceInvalid)?;
        let current = std::str::from_utf8(&pointer)
            .map_err(|_| source_invalid())?
            .trim();
        if current.is_empty() {
            return Err(source_invalid());
        }
        let current_id = ConfigRevisionId::new(current);
        let mut artifacts = vec![self.inspect(
            BackupArtifactKind::ConfigRevisionPointer,
            "current",
            "config/current",
            pointer_path,
            BackupArtifactMode::Public,
        )?];
        let revisions_dir = config.join("revisions");
        let mut revisions = sorted_entries(&revisions_dir)?;
        if revisions.is_empty() {
            return Err(source_invalid());
        }
        let mut current_source = None;
        let mut trust_refs = BTreeSet::new();
        for entry in revisions.drain(..) {
            if entry
                .file_type()
                .map_err(|_| source_invalid())?
                .is_symlink()
            {
                return Err(source_invalid());
            }
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("toml") {
                return Err(source_invalid());
            }
            let stem = path
                .file_stem()
                .and_then(|value| value.to_str())
                .ok_or_else(source_invalid)?;
            let revision_id = decode_hex(stem).ok_or_else(source_invalid)?;
            let logical_path = format!("config/revisions/{revision_id}");
            let descriptor = self.inspect(
                BackupArtifactKind::ConfigRevision,
                &revision_id,
                &logical_path,
                path.clone(),
                BackupArtifactMode::Public,
            )?;
            let revision_source = read_regular_no_follow(&path, ErrorCode::BackupSourceInvalid)?.0;
            let revision_snapshot = parse_mvp_config(
                std::str::from_utf8(&revision_source).map_err(|_| source_invalid())?,
                ConfigRevisionId::new(revision_id.clone()),
            )
            .map_err(|_| source_invalid())?
            .snapshot;
            collect_snapshot_trust_refs(&revision_snapshot, &mut trust_refs);
            if revision_id == current {
                current_source = Some(revision_source);
            }
            artifacts.push(descriptor);
        }
        let current_source = current_source.ok_or_else(source_invalid)?;
        let snapshot = parse_mvp_config(
            std::str::from_utf8(&current_source).map_err(|_| source_invalid())?,
            current_id.clone(),
        )
        .map_err(|_| source_invalid())?
        .snapshot;
        let mut refs = snapshot
            .routes
            .iter()
            .filter_map(|route| {
                route
                    .certificate_ref
                    .as_ref()
                    .map(|value| value.as_str().to_string())
            })
            .collect::<Vec<_>>();
        refs.sort();
        refs.dedup();
        Ok(InspectedConfig {
            current_revision_id: current_id,
            referenced_certificate_refs: refs,
            referenced_trust_bundle_refs: trust_refs.into_iter().collect(),
            artifacts,
        })
    }

    fn inspect_certificates(&mut self) -> Result<Vec<BackupArtifactDescriptor>, AppError> {
        let certs = self.root.join("certs");
        if !certs.exists() {
            return Ok(Vec::new());
        }
        let mut artifacts = Vec::new();
        for entry in sorted_entries(&certs)? {
            let file_type = entry.file_type().map_err(|_| source_invalid())?;
            if file_type.is_symlink() || !file_type.is_dir() {
                return Err(source_invalid());
            }
            let directory_name = entry
                .file_name()
                .to_str()
                .ok_or_else(source_invalid)?
                .to_string();
            let certificate_ref = match directory_name.strip_prefix(".ref-") {
                Some(encoded) => decode_hex(encoded).ok_or_else(source_invalid)?,
                None => directory_name.clone(),
            };
            if crate::certificate_ref_dir_name(&certificate_ref) != directory_name {
                return Err(source_invalid());
            }
            reject_unknown_names(
                &entry.path(),
                &["fullchain.pem", "privkey.pem", "metadata.toml"],
            )?;
            for (kind, file, suffix, mode) in [
                (
                    BackupArtifactKind::CertificateChain,
                    "fullchain.pem",
                    "chain",
                    BackupArtifactMode::Public,
                ),
                (
                    BackupArtifactKind::CertificatePrivateKey,
                    "privkey.pem",
                    "private-key",
                    BackupArtifactMode::OwnerOnly,
                ),
                (
                    BackupArtifactKind::CertificateMetadata,
                    "metadata.toml",
                    "metadata",
                    BackupArtifactMode::Public,
                ),
            ] {
                let logical = format!("certificates/{certificate_ref}/{suffix}");
                artifacts.push(self.inspect(
                    kind,
                    &certificate_ref,
                    &logical,
                    entry.path().join(file),
                    mode,
                )?);
            }
        }
        Ok(artifacts)
    }

    fn inspect_trust_bundles(&mut self) -> Result<Vec<BackupArtifactDescriptor>, AppError> {
        let root = self.root.join("trust-bundles");
        if !root.exists() {
            return Ok(Vec::new());
        }
        let mut artifacts = Vec::new();
        for entry in sorted_entries(&root)? {
            let file_type = entry.file_type().map_err(|_| source_invalid())?;
            if file_type.is_symlink() || !file_type.is_dir() {
                return Err(source_invalid());
            }
            let reference = entry
                .file_name()
                .to_str()
                .ok_or_else(source_invalid)?
                .to_string();
            edge_domain::TrustBundleRef::parse(&reference).map_err(|_| source_invalid())?;
            reject_unknown_names(&entry.path(), &["roots.pem", "metadata.toml"])?;
            for (kind, file, suffix) in [
                (BackupArtifactKind::TrustBundleRoots, "roots.pem", "roots"),
                (
                    BackupArtifactKind::TrustBundleMetadata,
                    "metadata.toml",
                    "metadata",
                ),
            ] {
                let logical = format!("trust-bundles/{reference}/{suffix}");
                artifacts.push(self.inspect(
                    kind,
                    &reference,
                    &logical,
                    entry.path().join(file),
                    BackupArtifactMode::Public,
                )?);
            }
        }
        Ok(artifacts)
    }

    fn inspect_secret(&mut self) -> Result<(bool, Vec<BackupArtifactDescriptor>), AppError> {
        let secrets = self.root.join("secrets");
        if !secrets.exists() {
            return Ok((false, Vec::new()));
        }
        reject_unknown_names(&secrets, &["admin-password-hash.secret"])?;
        let path = secrets.join("admin-password-hash.secret");
        if !path.exists() {
            return Ok((false, Vec::new()));
        }
        let item = self.inspect(
            BackupArtifactKind::AdminPasswordHash,
            "admin-password-hash",
            "secrets/admin-password-hash",
            path,
            BackupArtifactMode::OwnerOnly,
        )?;
        Ok((true, vec![item]))
    }

    fn inspect_audit_ledger(&mut self) -> Result<Vec<BackupArtifactDescriptor>, AppError> {
        let directory = self.root.join("logs/audit");
        if !directory.exists() {
            return Ok(Vec::new());
        }
        let entries = sorted_entries(&directory)?;
        if entries.is_empty() {
            return Err(source_invalid());
        }
        let mut ledger =
            crate::FileAuditLedger::open(&self.root, crate::AuditLedgerOptions::default())
                .map_err(|_| source_invalid())?;
        ledger.verify().map_err(|_| source_invalid())?;

        let mut artifacts = Vec::with_capacity(entries.len());
        for entry in entries {
            let file_type = entry.file_type().map_err(|_| source_invalid())?;
            if file_type.is_symlink() || !file_type.is_file() {
                return Err(source_invalid());
            }
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(source_invalid)?;
            let number = name
                .strip_prefix("segment-")
                .and_then(|value| value.strip_suffix(".audit"))
                .filter(|value| {
                    value.len() == 16 && value.bytes().all(|byte| byte.is_ascii_digit())
                })
                .ok_or_else(source_invalid)?;
            let logical_path = format!("audit/segments/{number}");
            artifacts.push(self.inspect(
                BackupArtifactKind::AuditLedgerSegment,
                number,
                &logical_path,
                entry.path(),
                BackupArtifactMode::Public,
            )?);
        }
        Ok(artifacts)
    }
}

fn collect_snapshot_trust_refs(
    snapshot: &edge_domain::ConfigSnapshot,
    refs: &mut BTreeSet<String>,
) {
    for listener in &snapshot.listeners {
        if let edge_domain::ClientAuthPolicy::Required { trust_bundle_ref } = &listener.client_auth
        {
            refs.insert(trust_bundle_ref.as_str().to_string());
        }
    }
    for service in &snapshot.services {
        for upstream in &service.upstreams {
            if let edge_domain::UpstreamTlsPolicy::ServerAuthenticated {
                trust_bundle_ref, ..
            } = &upstream.tls
            {
                refs.insert(trust_bundle_ref.as_str().to_string());
            }
        }
    }
}

impl BackupArtifactSource for FileBackupArtifactSource {
    fn inventory(&mut self) -> Result<BackupSourceInventory, AppError> {
        self.entries.clear();
        let config = self.inspect_config()?;
        let mut artifacts = config.artifacts;
        artifacts.extend(self.inspect_certificates()?);
        artifacts.extend(self.inspect_trust_bundles()?);
        artifacts.extend(self.inspect_audit_ledger()?);
        let (admin_initialized, secrets) = self.inspect_secret()?;
        artifacts.extend(secrets);
        artifacts
            .sort_by(|left, right| left.relative_logical_path.cmp(&right.relative_logical_path));
        let mut fingerprint = Sha256::new();
        for item in &artifacts {
            fingerprint.update(item.relative_logical_path.as_bytes());
            fingerprint.update(item.sha256);
        }
        Ok(BackupSourceInventory {
            current_revision_id: config.current_revision_id,
            admin_initialized,
            referenced_certificate_refs: config.referenced_certificate_refs,
            referenced_trust_bundle_refs: config.referenced_trust_bundle_refs,
            source_fingerprint: hex(&fingerprint.finalize()),
            artifacts,
        })
    }

    fn read_artifact(
        &mut self,
        descriptor: &BackupArtifactDescriptor,
    ) -> Result<BackupArtifact, AppError> {
        let entry = self
            .entries
            .get(&descriptor.relative_logical_path)
            .ok_or_else(source_changed)?;
        if entry.descriptor != *descriptor {
            return Err(source_changed());
        }
        let (payload, identity) =
            read_regular_no_follow(&entry.path, ErrorCode::BackupSourceChanged)?;
        if identity != entry.identity
            || payload.len() as u64 != descriptor.length_bytes
            || sha256(&payload) != descriptor.sha256
        {
            return Err(source_changed());
        }
        Ok(BackupArtifact {
            descriptor: descriptor.clone(),
            payload,
        })
    }
}

pub struct Sha256BackupManifestDigester;
impl BackupManifestDigester for Sha256BackupManifestDigester {
    fn digest(&self, manifest: &BackupManifest) -> Result<[u8; 32], AppError> {
        Ok(sha256(&encode_manifest(manifest, false)?))
    }
}

pub struct AgeBackupArchiveWriter {
    output: PathBuf,
    temporary: PathBuf,
    stream: Option<StreamWriter<File>>,
    finalized: Option<File>,
    encrypted_bytes: Option<u64>,
}

impl AgeBackupArchiveWriter {
    pub fn new(output: impl AsRef<Path>) -> Result<Self, AppError> {
        let output = output.as_ref().to_path_buf();
        let parent = output.parent().ok_or_else(destination_unsafe)?;
        if fs::symlink_metadata(parent)
            .map_err(|_| destination_unsafe())?
            .file_type()
            .is_symlink()
        {
            return Err(destination_unsafe());
        }
        if fs::symlink_metadata(&output).is_ok() {
            return Err(AppError::new(
                ErrorCode::BackupDestinationExists,
                "backup destination exists",
            ));
        }
        let extension = output
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("backup");
        let temporary = output.with_extension(format!("{extension}.tmp"));
        if fs::symlink_metadata(&temporary).is_ok() {
            return Err(AppError::new(
                ErrorCode::BackupDestinationExists,
                "backup temporary destination exists",
            ));
        }
        Ok(Self {
            output,
            temporary,
            stream: None,
            finalized: None,
            encrypted_bytes: None,
        })
    }
}

impl BackupArchiveWriter for AgeBackupArchiveWriter {
    fn open(
        &mut self,
        manifest: &BackupManifest,
        secret: &SensitiveString,
    ) -> Result<(), AppError> {
        if self.stream.is_some() || self.finalized.is_some() {
            return Err(write_failed());
        }
        let file = create_private_file(&self.temporary)?;
        let encryptor = secret
            .expose(|value| Encryptor::with_user_passphrase(SecretString::from(value.to_string())));
        let mut stream = encryptor
            .wrap_output(file)
            .map_err(|_| encryption_failed())?;
        let encoded = encode_manifest(manifest, true)?;
        validate_manifest_encoded_size(encoded.len() as u64, &BackupLimits::schema_v1())?;
        stream
            .write_all(BODY_MAGIC)
            .and_then(|_| write_u64(&mut stream, encoded.len() as u64))
            .and_then(|_| stream.write_all(&encoded))
            .map_err(|_| write_failed())?;
        self.stream = Some(stream);
        Ok(())
    }

    fn write_record(&mut self, artifact: BackupArtifact) -> Result<(), AppError> {
        let stream = self.stream.as_mut().ok_or_else(write_failed)?;
        stream
            .write_all(b"REC1")
            .and_then(|_| write_string(stream, &artifact.descriptor.relative_logical_path))
            .and_then(|_| write_u64(stream, artifact.payload.len() as u64))
            .and_then(|_| stream.write_all(&artifact.payload))
            .map_err(|_| write_failed())
    }

    fn finalize(&mut self) -> Result<u64, AppError> {
        let stream = self.stream.take().ok_or_else(write_failed)?;
        let file = stream.finish().map_err(|_| encryption_failed())?;
        let bytes = file.metadata().map_err(|_| write_failed())?.len();
        self.encrypted_bytes = Some(bytes);
        self.finalized = Some(file);
        Ok(bytes)
    }
    fn sync(&mut self) -> Result<(), AppError> {
        self.finalized
            .as_ref()
            .ok_or_else(write_failed)?
            .sync_all()
            .map_err(|_| write_failed())
    }
    fn publish(&mut self) -> Result<(), AppError> {
        if self.finalized.take().is_none() {
            return Err(write_failed());
        }
        fs::rename(&self.temporary, &self.output).map_err(|_| publish_failed())?;
        sync_parent(&self.output).map_err(|_| publish_failed())
    }
    fn cleanup(&mut self) -> Result<(), AppError> {
        self.stream = None;
        self.finalized = None;
        match fs::remove_file(&self.temporary) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(write_failed()),
        }
    }
}

fn encode_manifest(manifest: &BackupManifest, include_digest: bool) -> Result<Vec<u8>, AppError> {
    let mut out = Vec::new();
    put_u32(&mut out, manifest.schema_version);
    put_string(&mut out, &manifest.archive_id)?;
    put_u64(&mut out, manifest.created_at_epoch_seconds);
    put_string(&mut out, &manifest.source_app_version)?;
    put_u32(&mut out, manifest.source_layout_version);
    put_string(&mut out, &manifest.current_revision_id)?;
    out.push(u8::from(manifest.admin_initialized));
    put_u32(
        &mut out,
        manifest
            .referenced_certificate_refs
            .len()
            .try_into()
            .map_err(|_| write_failed())?,
    );
    for value in &manifest.referenced_certificate_refs {
        put_string(&mut out, value)?;
    }
    if manifest.schema_version >= 2 {
        put_u32(
            &mut out,
            manifest
                .referenced_trust_bundle_refs
                .len()
                .try_into()
                .map_err(|_| write_failed())?,
        );
        for value in &manifest.referenced_trust_bundle_refs {
            put_string(&mut out, value)?;
        }
    }
    put_u32(&mut out, manifest.artifact_count);
    put_u64(&mut out, manifest.total_plaintext_bytes);
    for item in &manifest.artifacts {
        put_u8(&mut out, kind_id(&item.kind)?);
        put_string(&mut out, &item.logical_id)?;
        put_string(&mut out, &item.relative_logical_path)?;
        put_u64(&mut out, item.length_bytes);
        out.extend_from_slice(&item.sha256);
        put_u8(
            &mut out,
            match item.mode {
                BackupArtifactMode::Public => 0,
                BackupArtifactMode::OwnerOnly => 1,
            },
        );
        put_u8(&mut out, u8::from(item.required_for_restore));
    }
    if include_digest {
        out.extend_from_slice(&manifest.manifest_digest);
    }
    Ok(out)
}

fn decode_manifest(encoded: &[u8], limits: &BackupLimits) -> Result<BackupManifest, AppError> {
    let mut cursor = std::io::Cursor::new(encoded);
    let schema_version = read_u32_format(&mut cursor)?;
    let archive_id = read_string_format(&mut cursor, 240)?;
    let created_at_epoch_seconds = read_u64_format(&mut cursor)?;
    let source_app_version = read_string_format(&mut cursor, 240)?;
    let source_layout_version = read_u32_format(&mut cursor)?;
    let current_revision_id = read_string_format(&mut cursor, 240)?;
    let admin_initialized = read_u8_format(&mut cursor)? != 0;
    let referenced_count = read_u32_format(&mut cursor)?;
    if referenced_count > limits.max_artifacts {
        return Err(limit_exceeded());
    }
    let mut referenced_certificate_refs = Vec::with_capacity(referenced_count as usize);
    for _ in 0..referenced_count {
        referenced_certificate_refs.push(read_string_format(&mut cursor, 240)?);
    }
    let mut referenced_trust_bundle_refs = Vec::new();
    if schema_version >= 2 {
        let referenced_trust_count = read_u32_format(&mut cursor)?;
        if referenced_trust_count > limits.max_artifacts {
            return Err(limit_exceeded());
        }
        referenced_trust_bundle_refs = Vec::with_capacity(referenced_trust_count as usize);
        for _ in 0..referenced_trust_count {
            referenced_trust_bundle_refs.push(read_string_format(&mut cursor, 240)?);
        }
    }
    let artifact_count = read_u32_format(&mut cursor)?;
    if artifact_count > limits.max_artifacts {
        return Err(limit_exceeded());
    }
    let total_plaintext_bytes = read_u64_format(&mut cursor)?;
    if total_plaintext_bytes > limits.max_total_plaintext_bytes {
        return Err(limit_exceeded());
    }
    let mut artifacts = Vec::with_capacity(artifact_count as usize);
    for _ in 0..artifact_count {
        let kind = match read_u8_format(&mut cursor)? {
            1 => BackupArtifactKind::ConfigRevision,
            2 => BackupArtifactKind::ConfigRevisionPointer,
            3 => BackupArtifactKind::CertificateChain,
            4 => BackupArtifactKind::CertificatePrivateKey,
            5 => BackupArtifactKind::CertificateMetadata,
            6 => BackupArtifactKind::AdminPasswordHash,
            7 => BackupArtifactKind::TrustBundleRoots,
            8 => BackupArtifactKind::TrustBundleMetadata,
            9 => BackupArtifactKind::AuditLedgerSegment,
            _ => return Err(format_invalid()),
        };
        let logical_id = read_string_format(&mut cursor, 240)?;
        let relative_logical_path = read_string_format(&mut cursor, limits.max_logical_path_bytes)?;
        let length_bytes = read_u64_format(&mut cursor)?;
        let mut sha256 = [0_u8; 32];
        cursor
            .read_exact(&mut sha256)
            .map_err(|_| format_invalid())?;
        let mode = match read_u8_format(&mut cursor)? {
            0 => BackupArtifactMode::Public,
            1 => BackupArtifactMode::OwnerOnly,
            _ => return Err(format_invalid()),
        };
        let required_for_restore = match read_u8_format(&mut cursor)? {
            0 => false,
            1 => true,
            _ => return Err(format_invalid()),
        };
        artifacts.push(BackupArtifactDescriptor {
            kind,
            logical_id,
            relative_logical_path,
            length_bytes,
            sha256,
            mode,
            required_for_restore,
        });
    }
    let mut manifest_digest = [0_u8; 32];
    cursor
        .read_exact(&mut manifest_digest)
        .map_err(|_| format_invalid())?;
    if cursor.position() != encoded.len() as u64 {
        return Err(format_invalid());
    }
    Ok(BackupManifest {
        schema_version,
        archive_id,
        created_at_epoch_seconds,
        source_app_version,
        source_layout_version,
        current_revision_id,
        admin_initialized,
        referenced_certificate_refs,
        referenced_trust_bundle_refs,
        artifact_count,
        total_plaintext_bytes,
        artifacts,
        manifest_digest,
    })
}

fn read_authenticated(reader: &mut impl Read, output: &mut [u8]) -> Result<(), AppError> {
    reader
        .read_exact(output)
        .map_err(|_| authentication_failed())
}
fn read_u64_authenticated(reader: &mut impl Read) -> Result<u64, AppError> {
    let mut bytes = [0_u8; 8];
    read_authenticated(reader, &mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}
fn read_string_authenticated(reader: &mut impl Read, max: usize) -> Result<String, AppError> {
    let mut bytes = [0_u8; 4];
    read_authenticated(reader, &mut bytes)?;
    let length = u32::from_be_bytes(bytes) as usize;
    if length > max {
        return Err(limit_exceeded());
    }
    let mut value = vec![0_u8; length];
    read_authenticated(reader, &mut value)?;
    String::from_utf8(value).map_err(|_| format_invalid())
}
fn read_u8_format(reader: &mut impl Read) -> Result<u8, AppError> {
    let mut bytes = [0];
    reader
        .read_exact(&mut bytes)
        .map_err(|_| format_invalid())?;
    Ok(bytes[0])
}
fn read_u32_format(reader: &mut impl Read) -> Result<u32, AppError> {
    let mut bytes = [0; 4];
    reader
        .read_exact(&mut bytes)
        .map_err(|_| format_invalid())?;
    Ok(u32::from_be_bytes(bytes))
}
fn read_u64_format(reader: &mut impl Read) -> Result<u64, AppError> {
    let mut bytes = [0; 8];
    reader
        .read_exact(&mut bytes)
        .map_err(|_| format_invalid())?;
    Ok(u64::from_be_bytes(bytes))
}
fn read_string_format(reader: &mut impl Read, max: usize) -> Result<String, AppError> {
    let length = read_u32_format(reader)? as usize;
    if length > max {
        return Err(limit_exceeded());
    }
    let mut value = vec![0; length];
    reader
        .read_exact(&mut value)
        .map_err(|_| format_invalid())?;
    String::from_utf8(value).map_err(|_| format_invalid())
}

fn kind_id(kind: &BackupArtifactKind) -> Result<u8, AppError> {
    match kind {
        BackupArtifactKind::ConfigRevision => Ok(1),
        BackupArtifactKind::ConfigRevisionPointer => Ok(2),
        BackupArtifactKind::CertificateChain => Ok(3),
        BackupArtifactKind::CertificatePrivateKey => Ok(4),
        BackupArtifactKind::CertificateMetadata => Ok(5),
        BackupArtifactKind::AdminPasswordHash => Ok(6),
        BackupArtifactKind::TrustBundleRoots => Ok(7),
        BackupArtifactKind::TrustBundleMetadata => Ok(8),
        BackupArtifactKind::AuditLedgerSegment => Ok(9),
        BackupArtifactKind::Unknown(_) => Err(write_failed()),
    }
}
fn put_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}
fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn put_string(out: &mut Vec<u8>, value: &str) -> Result<(), AppError> {
    let length: u32 = value.len().try_into().map_err(|_| write_failed())?;
    put_u32(out, length);
    out.extend_from_slice(value.as_bytes());
    Ok(())
}
fn write_u64(writer: &mut impl Write, value: u64) -> std::io::Result<()> {
    writer.write_all(&value.to_be_bytes())
}
fn write_string(writer: &mut impl Write, value: &str) -> std::io::Result<()> {
    let length: u32 = value
        .len()
        .try_into()
        .map_err(|_| std::io::Error::other("record identity too long"))?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(value.as_bytes())
}

fn reject_unknown_names(directory: &Path, allowed: &[&str]) -> Result<(), AppError> {
    for entry in sorted_entries(directory)? {
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(source_invalid)?;
        if !allowed.contains(&name) {
            return Err(source_invalid());
        }
    }
    Ok(())
}
fn sorted_entries(directory: &Path) -> Result<Vec<fs::DirEntry>, AppError> {
    let mut entries = fs::read_dir(directory)
        .map_err(|_| source_invalid())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| source_invalid())?;
    entries.sort_by_key(|entry| entry.file_name());
    Ok(entries)
}

#[cfg(unix)]
fn read_regular_no_follow(
    path: &Path,
    error_code: ErrorCode,
) -> Result<(Vec<u8>, FileIdentity), AppError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| AppError::new(error_code, error_code.default_user_message()))?;
    let before = file.metadata().map_err(|_| source_invalid())?;
    if !before.is_file() {
        return Err(source_invalid());
    }
    let initial_identity = identity(&before);
    let mut payload = Vec::new();
    file.read_to_end(&mut payload)
        .map_err(|_| AppError::new(error_code, error_code.default_user_message()))?;
    let after = file.metadata().map_err(|_| source_changed())?;
    if identity(&after) != initial_identity
        || after.dev() != before.dev()
        || after.ino() != before.ino()
    {
        return Err(source_changed());
    }
    Ok((payload, initial_identity))
}
#[cfg(not(unix))]
fn read_regular_no_follow(_: &Path, _: ErrorCode) -> Result<(Vec<u8>, FileIdentity), AppError> {
    Err(source_invalid())
}

fn identity(metadata: &Metadata) -> FileIdentity {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        FileIdentity {
            length: metadata.len(),
            modified_nanos: metadata.mtime() as u128 * 1_000_000_000
                + metadata.mtime_nsec() as u128,
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
    #[cfg(not(unix))]
    {
        FileIdentity {
            length: metadata.len(),
            modified_nanos: 0,
        }
    }
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> Result<File, AppError> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| write_failed())
}
#[cfg(unix)]
fn open_regular_no_follow(path: &Path) -> Result<File, AppError> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| authentication_failed())?;
    if !file
        .metadata()
        .map_err(|_| authentication_failed())?
        .is_file()
    {
        return Err(authentication_failed());
    }
    Ok(file)
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<(), AppError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let mut builder = fs::DirBuilder::new();
    builder
        .mode(0o700)
        .create(path)
        .map_err(|_| restore_stage_failed())?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| restore_stage_failed())
}
#[cfg(not(unix))]
fn create_private_directory(_: &Path) -> Result<(), AppError> {
    Err(restore_target_unsafe())
}

#[cfg(unix)]
fn make_private_directory(path: &Path) -> Result<(), AppError> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::symlink_metadata(path).map_err(|_| restore_stage_failed())?;
    if !metadata.file_type().is_dir() {
        return Err(restore_stage_failed());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| restore_stage_failed())
}

#[cfg(not(unix))]
fn make_private_directory(_: &Path) -> Result<(), AppError> {
    Err(restore_target_unsafe())
}

fn restore_artifact_path(
    stage: &Path,
    descriptor: &BackupArtifactDescriptor,
) -> Result<PathBuf, AppError> {
    let path = match descriptor.kind {
        BackupArtifactKind::ConfigRevisionPointer => stage.join("config/current"),
        BackupArtifactKind::ConfigRevision => stage
            .join("config/revisions")
            .join(format!("{}.toml", hex(descriptor.logical_id.as_bytes()))),
        BackupArtifactKind::CertificateChain => stage
            .join("certs")
            .join(crate::certificate_ref_dir_name(&descriptor.logical_id))
            .join("fullchain.pem"),
        BackupArtifactKind::CertificatePrivateKey => stage
            .join("certs")
            .join(crate::certificate_ref_dir_name(&descriptor.logical_id))
            .join("privkey.pem"),
        BackupArtifactKind::CertificateMetadata => stage
            .join("certs")
            .join(crate::certificate_ref_dir_name(&descriptor.logical_id))
            .join("metadata.toml"),
        BackupArtifactKind::TrustBundleRoots => stage
            .join("trust-bundles")
            .join(&descriptor.logical_id)
            .join("roots.pem"),
        BackupArtifactKind::TrustBundleMetadata => stage
            .join("trust-bundles")
            .join(&descriptor.logical_id)
            .join("metadata.toml"),
        BackupArtifactKind::AdminPasswordHash => stage.join("secrets/admin-password-hash.secret"),
        BackupArtifactKind::AuditLedgerSegment => stage
            .join("logs/audit")
            .join(format!("segment-{}.audit", descriptor.logical_id)),
        BackupArtifactKind::Unknown(_) => {
            return Err(AppError::new(
                ErrorCode::BackupPathUnsafe,
                ErrorCode::BackupPathUnsafe.default_user_message(),
            ))
        }
    };
    Ok(path)
}

#[cfg(unix)]
fn write_restored_file(path: &Path, payload: &[u8], _: BackupArtifactMode) -> Result<(), AppError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| restore_stage_failed())?;
    file.write_all(payload)
        .and_then(|_| file.sync_all())
        .map_err(|_| restore_stage_failed())
}
#[cfg(not(unix))]
fn write_restored_file(_: &Path, _: &[u8], _: BackupArtifactMode) -> Result<(), AppError> {
    Err(restore_target_unsafe())
}

fn sync_tree_files(root: &Path) -> Result<(), AppError> {
    let mut directories = vec![root.to_path_buf()];
    let mut index = 0;
    while index < directories.len() {
        let directory = directories[index].clone();
        for entry in fs::read_dir(&directory).map_err(|_| restore_stage_failed())? {
            let entry = entry.map_err(|_| restore_stage_failed())?;
            let kind = entry.file_type().map_err(|_| restore_stage_failed())?;
            if kind.is_symlink() {
                return Err(restore_stage_failed());
            }
            if kind.is_dir() {
                directories.push(entry.path());
            }
        }
        index += 1;
    }
    for directory in directories.iter().rev() {
        File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| restore_stage_failed())?;
    }
    Ok(())
}
#[cfg(not(unix))]
fn open_regular_no_follow(_: &Path) -> Result<File, AppError> {
    Err(authentication_failed())
}
#[cfg(not(unix))]
fn create_private_file(_: &Path) -> Result<File, AppError> {
    Err(destination_unsafe())
}
fn sync_parent(path: &Path) -> std::io::Result<()> {
    File::open(
        path.parent()
            .ok_or_else(|| std::io::Error::other("missing parent"))?,
    )?
    .sync_all()
}
fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn decode_hex(value: &str) -> Option<String> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let bytes = (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect::<Option<Vec<_>>>()?;
    String::from_utf8(bytes).ok()
}
fn source_invalid() -> AppError {
    AppError::new(
        ErrorCode::BackupSourceInvalid,
        "backup source layout is invalid",
    )
}
fn source_changed() -> AppError {
    AppError::new(
        ErrorCode::BackupSourceChanged,
        "backup source changed after inventory",
    )
}
fn destination_unsafe() -> AppError {
    AppError::new(
        ErrorCode::BackupDestinationUnsafe,
        "backup destination is unsafe",
    )
}
fn encryption_failed() -> AppError {
    AppError::new(
        ErrorCode::BackupEncryptionFailed,
        "backup encryption failed",
    )
}
fn write_failed() -> AppError {
    AppError::new(ErrorCode::BackupWriteFailed, "backup write failed")
}
fn publish_failed() -> AppError {
    AppError::new(ErrorCode::BackupPublishFailed, "backup publish failed")
}
fn authentication_failed() -> AppError {
    AppError::new(
        ErrorCode::BackupAuthenticationFailed,
        ErrorCode::BackupAuthenticationFailed.default_user_message(),
    )
}
fn format_invalid() -> AppError {
    AppError::new(
        ErrorCode::BackupFormatInvalid,
        ErrorCode::BackupFormatInvalid.default_user_message(),
    )
}
fn limit_exceeded() -> AppError {
    AppError::new(
        ErrorCode::BackupLimitExceeded,
        ErrorCode::BackupLimitExceeded.default_user_message(),
    )
}
fn restore_target_unsafe() -> AppError {
    AppError::new(
        ErrorCode::RestoreTargetUnsafe,
        ErrorCode::RestoreTargetUnsafe.default_user_message(),
    )
}
fn restore_stage_failed() -> AppError {
    AppError::new(
        ErrorCode::RestoreStageFailed,
        ErrorCode::RestoreStageFailed.default_user_message(),
    )
}
fn restore_config_invalid() -> AppError {
    AppError::new(
        ErrorCode::RestoreConfigInvalid,
        ErrorCode::RestoreConfigInvalid.default_user_message(),
    )
}
fn restore_certificate_invalid() -> AppError {
    AppError::new(
        ErrorCode::RestoreCertificateInvalid,
        ErrorCode::RestoreCertificateInvalid.default_user_message(),
    )
}
fn restore_secret_invalid() -> AppError {
    AppError::new(
        ErrorCode::RestoreSecretInvalid,
        ErrorCode::RestoreSecretInvalid.default_user_message(),
    )
}
fn restore_commit_failed() -> AppError {
    AppError::new(
        ErrorCode::RestoreCommitFailed,
        ErrorCode::RestoreCommitFailed.default_user_message(),
    )
}
fn restore_rollback_failed() -> AppError {
    AppError::new(
        ErrorCode::RestoreRollbackFailed,
        ErrorCode::RestoreRollbackFailed.default_user_message(),
    )
}
fn restore_transaction_unresolved() -> AppError {
    AppError::new(
        ErrorCode::RestoreTransactionUnresolved,
        ErrorCode::RestoreTransactionUnresolved.default_user_message(),
    )
}
