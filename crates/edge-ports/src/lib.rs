//! Port traits for external systems.
//!
//! Concrete filesystem, network, certificate store, metrics, and audit adapters
//! live outside this crate.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use edge_domain::{
    AppError, AuditAction, AuditAdmissionState, AuditAuthoritativeFact, AuditLedgerHead,
    AuditOperationId, AuditPage, AuditQuery, AuditRecord, AuditTargetId, AuditVerificationReport,
    BackupArtifactDescriptor, BackupManifest, CertificateRef, CommandAck, ConfigRevision,
    ConfigRevisionId, ConfigSnapshot, CoreCommand, DataDirectoryLockState, ErrorCode,
    OfflineUpgradeJournal, OfflineUpgradeRequest, OperationalRuntimeFacts, SensitiveString,
    SupportBundleArchiveReceipt, SupportBundleArtifact, SupportBundleBounds, SupportBundleOmission,
    TlsServerName, TrustBundleRef, UpstreamEndpoint, UpstreamTlsPolicy,
};
pub use edge_domain::{HealthAvailabilitySnapshot, HealthGeneration, UpstreamHealthKey};

/// Returns the crate name for foundation smoke tests.
pub fn crate_name() -> &'static str {
    "edge-ports"
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportBundleRequest {
    pub artifacts: Vec<SupportBundleArtifact>,
    pub bounds: SupportBundleBounds,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportBundleReport {
    pub archive: SupportBundleArchiveReceipt,
    pub collected_artifacts: Vec<SupportBundleArtifact>,
    pub total_bytes: u64,
    /// Present exactly when `BoundedProductLog` is collected; measured at collection time.
    pub oldest_collected_log_age_seconds: Option<u64>,
    pub omissions: Vec<SupportBundleOmission>,
}

/// Blocking archive/file collection belongs to adapters behind this boundary.
pub trait SupportBundleCollector {
    fn collect_support_bundle(
        &mut self,
        request: SupportBundleRequest,
    ) -> Result<SupportBundleReport, AppError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionRecord {
    pub revision: ConfigRevision,
    pub snapshot: ConfigSnapshot,
    pub checksum: String,
}

pub trait ConfigRevisionRepository {
    fn save_revision(&mut self, record: RevisionRecord) -> Result<(), AppError>;
    fn set_current(&mut self, revision_id: &ConfigRevisionId) -> Result<(), AppError>;
    fn current_revision_id(&self) -> Result<Option<ConfigRevisionId>, AppError> {
        Ok(self.current()?.map(|record| record.revision.id))
    }
    fn current(&self) -> Result<Option<RevisionRecord>, AppError>;
    fn find_revision(
        &self,
        revision_id: &ConfigRevisionId,
    ) -> Result<Option<RevisionRecord>, AppError>;
    fn history(&self) -> Result<Vec<RevisionRecord>, AppError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustBundleMetadata {
    pub trust_bundle_ref: TrustBundleRef,
    pub certificate_count: u8,
    pub imported_at_epoch_seconds: u64,
    pub content_sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedTrustBundle {
    pub metadata: TrustBundleMetadata,
    encoded_material: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustBundleOperationEvent {
    pub event: &'static str,
    pub trust_bundle_ref: TrustBundleRef,
    pub certificate_count: Option<u8>,
    pub outcome: &'static str,
    pub error_code: Option<ErrorCode>,
}

impl ValidatedTrustBundle {
    pub fn new(metadata: TrustBundleMetadata, encoded_material: Vec<u8>) -> Self {
        Self {
            metadata,
            encoded_material,
        }
    }

    pub fn encoded_material(&self) -> &[u8] {
        &self.encoded_material
    }
}

pub trait TrustBundleMaterialValidator {
    fn validate_trust_bundle(
        &mut self,
        trust_bundle_ref: &TrustBundleRef,
        encoded_material: &[u8],
        imported_at_epoch_seconds: u64,
    ) -> Result<ValidatedTrustBundle, AppError>;
}

pub trait TrustBundleStore {
    fn create_trust_bundle(&mut self, bundle: ValidatedTrustBundle) -> Result<(), AppError>;
    fn list_trust_bundles(&mut self) -> Result<Vec<TrustBundleMetadata>, AppError>;
    fn delete_trust_bundle(&mut self, trust_bundle_ref: &TrustBundleRef) -> Result<(), AppError>;
}

pub trait TrustBundleReader {
    fn load_trust_bundle(
        &mut self,
        trust_bundle_ref: &TrustBundleRef,
    ) -> Result<Option<ValidatedTrustBundle>, AppError>;
}

pub trait RetainedConfigSnapshots {
    fn retained_config_snapshots(&self) -> Result<Vec<ConfigSnapshot>, AppError>;
}

pub trait TrustBundleEventSink {
    fn record_trust_product_event(&mut self, event: TrustBundleOperationEvent);
    fn record_trust_audit_event(&mut self, event: TrustBundleOperationEvent);
}

pub trait BootstrapConfigSeed {
    fn read_seed(&mut self) -> Result<Option<String>, AppError>;
}

pub trait StartupConfigPreflight {
    fn preflight(&mut self, snapshot: &ConfigSnapshot) -> Result<(), AppError>;
}

pub trait DataDirectoryLockGuard: std::fmt::Debug + Send {
    fn state(&self) -> DataDirectoryLockState;
    fn release(&mut self) -> Result<(), AppError>;
}

pub trait DataDirectoryLockManager {
    fn try_acquire_exclusive(&self) -> Result<Box<dyn DataDirectoryLockGuard>, AppError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupSourceInventory {
    pub current_revision_id: ConfigRevisionId,
    pub admin_initialized: bool,
    pub referenced_certificate_refs: Vec<String>,
    pub referenced_trust_bundle_refs: Vec<String>,
    pub source_fingerprint: String,
    pub artifacts: Vec<BackupArtifactDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupArtifact {
    pub descriptor: BackupArtifactDescriptor,
    pub payload: Vec<u8>,
}

pub trait BackupArtifactSource {
    fn inventory(&mut self) -> Result<BackupSourceInventory, AppError>;
    fn read_artifact(
        &mut self,
        descriptor: &BackupArtifactDescriptor,
    ) -> Result<BackupArtifact, AppError>;
}

pub trait BackupManifestDigester {
    fn digest(&self, manifest: &BackupManifest) -> Result<[u8; 32], AppError>;
}

pub trait BackupArchiveWriter {
    fn open(&mut self, manifest: &BackupManifest, secret: &SensitiveString)
        -> Result<(), AppError>;
    fn write_record(&mut self, artifact: BackupArtifact) -> Result<(), AppError>;
    fn finalize(&mut self) -> Result<u64, AppError>;
    fn sync(&mut self) -> Result<(), AppError>;
    fn publish(&mut self) -> Result<(), AppError>;
    fn cleanup(&mut self) -> Result<(), AppError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupRecordSummary {
    pub relative_logical_path: String,
    pub length_bytes: u64,
    pub sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupArchiveRead {
    pub manifest: BackupManifest,
    pub records: Vec<BackupRecordSummary>,
}

pub trait BackupArchiveReader {
    fn read(
        &mut self,
        secret: &SensitiveString,
        limits: &edge_domain::BackupLimits,
    ) -> Result<BackupArchiveRead, AppError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreStageSummary {
    pub stage_identity: String,
    pub archive_id: String,
    pub revision_id: ConfigRevisionId,
    pub artifact_count: u32,
    pub certificate_count: u32,
    pub trust_bundle_count: u32,
    pub audit_segment_count: u16,
    pub admin_initialized: bool,
    pub referenced_certificate_refs: Vec<String>,
    pub referenced_trust_bundle_refs: Vec<String>,
}

pub trait RestoreArchiveExtractor {
    fn extract(
        &mut self,
        secret: &SensitiveString,
        limits: &edge_domain::BackupLimits,
    ) -> Result<RestoreStageSummary, AppError>;
    fn cleanup(&mut self) -> Result<(), AppError>;
}

pub trait RestorePreflight {
    fn validate_config(&mut self, stage: &RestoreStageSummary) -> Result<(), AppError>;
    fn validate_certificates(&mut self, stage: &RestoreStageSummary) -> Result<(), AppError>;
    fn validate_secrets(&mut self, stage: &RestoreStageSummary) -> Result<(), AppError>;
    fn validate_audit(&mut self, stage: &RestoreStageSummary) -> Result<(), AppError>;
    fn preflight_runtime(&mut self, stage: &RestoreStageSummary) -> Result<(), AppError>;
}

pub trait RestorePublisher {
    fn prepare_new_target(&mut self, stage: &RestoreStageSummary) -> Result<(), AppError>;
    fn publish_new_target(&mut self, stage: &RestoreStageSummary) -> Result<(), AppError>;
    fn verify_published_target(&mut self, stage: &RestoreStageSummary) -> Result<(), AppError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreTransactionState {
    Prepared,
    TargetMoved,
    StagePublished,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreTransaction {
    pub operation_id: String,
    pub archive_id: String,
    pub target_identity: String,
    pub stage_identity: String,
    pub rollback_identity: String,
    pub state: RestoreTransactionState,
}

pub trait RestoreTransactionStore {
    fn persist(&mut self, transaction: &RestoreTransaction) -> Result<(), AppError>;
    fn load(&mut self, operation_id: &str) -> Result<Option<RestoreTransaction>, AppError>;
    fn delete(&mut self, operation_id: &str) -> Result<(), AppError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreRollbackOutcome {
    NotRequired,
    Restored,
}

pub trait RestoreReplacePublisher {
    fn prepare_replace(
        &mut self,
        operation_id: &str,
        stage: &RestoreStageSummary,
    ) -> Result<RestoreTransaction, AppError>;
    fn move_target_to_rollback(&mut self, transaction: &RestoreTransaction)
        -> Result<(), AppError>;
    fn publish_stage(&mut self, transaction: &RestoreTransaction) -> Result<(), AppError>;
    fn verify_target(
        &mut self,
        transaction: &RestoreTransaction,
        stage: &RestoreStageSummary,
    ) -> Result<(), AppError>;
    fn rollback_after_failure(
        &mut self,
        transaction: &RestoreTransaction,
    ) -> Result<RestoreRollbackOutcome, AppError>;
    fn cleanup_committed(&mut self, transaction: &RestoreTransaction) -> Result<(), AppError>;
    fn target_valid(&mut self, transaction: &RestoreTransaction) -> Result<bool, AppError>;
    fn rollback_valid(&mut self, transaction: &RestoreTransaction) -> Result<bool, AppError>;
}

pub trait RestoreProvenanceWriter {
    fn append_restore_provenance(
        &mut self,
        record: AuditRecord,
    ) -> Result<AuditLedgerHead, AppError>;
}

pub trait OperationIdGenerator {
    fn next_id(&mut self) -> Result<String, AppError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub event: String,
    pub revision_id: Option<ConfigRevisionId>,
}

/// Legacy terminal-only audit port retained during the typed ledger migration.
pub trait AuditSink {
    fn record(&mut self, event: AuditEvent) -> Result<(), AppError>;
}

/// Durable typed writer used by new persistent mutation orchestration.
pub trait AuditLedgerWriter {
    fn append_intent(&mut self, record: AuditRecord) -> Result<AuditLedgerHead, AppError>;
    fn append_terminal(
        &mut self,
        record: AuditRecord,
        expected_head: AuditLedgerHead,
    ) -> Result<AuditLedgerHead, AppError>;
    fn append_reconciliation(
        &mut self,
        record: AuditRecord,
        expected_head: AuditLedgerHead,
    ) -> Result<AuditLedgerHead, AppError>;
    fn append_security_observation(
        &mut self,
        record: AuditRecord,
    ) -> Result<AuditLedgerHead, AppError>;
}

pub trait AuditLedgerReader {
    fn query(&self, query: &AuditQuery) -> Result<AuditPage, AppError>;
    fn incomplete_operations(&self) -> Result<Vec<AuditRecord>, AppError>;
    fn unresolved_reconciliations(&self) -> Result<Vec<AuditRecord>, AppError>;
    fn head(&self) -> Result<AuditLedgerHead, AppError>;
}

pub trait AuditLedgerVerifier {
    fn verify(&mut self) -> Result<AuditVerificationReport, AppError>;
}

pub trait AuditAuthoritativeStateInspector {
    fn inspect(
        &mut self,
        operation_id: &AuditOperationId,
        action: AuditAction,
        target_id: &AuditTargetId,
    ) -> Result<AuditAuthoritativeFact, AppError>;
}

pub trait AuditAdmissionController {
    fn state(&self) -> AuditAdmissionState;
    fn replace_state(&mut self, state: AuditAdmissionState);
}

pub trait AuditOperationIdGenerator {
    fn next_audit_operation_id(&mut self) -> Result<AuditOperationId, AppError>;
}

impl<T> AuditSink for &mut T
where
    T: AuditSink + ?Sized,
{
    fn record(&mut self, event: AuditEvent) -> Result<(), AppError> {
        (**self).record(event)
    }
}

pub trait Clock {
    fn now_epoch_seconds(&self) -> u64;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthProbeId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthProbeRequest {
    pub probe_id: HealthProbeId,
    pub revision_id: ConfigRevisionId,
    pub generation: HealthGeneration,
    pub key: UpstreamHealthKey,
    pub endpoint: UpstreamEndpoint,
    pub tls: UpstreamTlsPolicy,
    pub path: String,
    pub timeout_ms: u64,
    pub status_min: u16,
    pub status_max: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthProbeFailure {
    ConnectTimeout,
    ConnectError,
    WriteError,
    MalformedResponse,
    StatusMismatch { status_code: u16 },
    ReadTimeout,
    ResponseTooLarge,
    TlsProfile,
    TlsHandshake,
    TlsHandshakeTimeout,
    Cancelled,
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthProbeOutcome {
    Succeeded { status_code: u16 },
    Failed(HealthProbeFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthProbeResult {
    pub outcome: HealthProbeOutcome,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthProbeCompletion {
    pub request: HealthProbeRequest,
    pub result: HealthProbeResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthProbeSubmit {
    Accepted,
    Full,
    Stopped,
}

pub trait HealthProbeDispatcher {
    fn submit(&self, request: HealthProbeRequest) -> HealthProbeSubmit;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassiveFailureReason {
    Connect,
    ConnectTimeout,
    Write,
    Read,
    ReadTimeout,
    ResetBeforeResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassiveObservationOutcome {
    Succeeded,
    Failed(PassiveFailureReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassiveObservation {
    pub revision_id: ConfigRevisionId,
    pub generation: HealthGeneration,
    pub key: UpstreamHealthKey,
    pub outcome: PassiveObservationOutcome,
    pub observed_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassiveObservationSubmit {
    Accepted,
    Full,
    Stopped,
}

pub trait PassiveObservationDispatcher {
    fn submit(&mut self, observation: PassiveObservation) -> PassiveObservationSubmit;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeDrainState {
    Active,
    Draining,
    Drained,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeUpstreamStatus {
    pub key: UpstreamHealthKey,
    pub state: RuntimeDrainState,
    pub connection_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeUpstreamStatusSnapshot {
    pub revision_id: ConfigRevisionId,
    pub generation: u64,
    pub upstreams: Vec<RuntimeUpstreamStatus>,
}

pub trait RuntimeUpstreamStatusPublisher: Send + Sync {
    fn publish_runtime_status(&self, snapshot: RuntimeUpstreamStatusSnapshot);
}

pub trait RuntimeUpstreamStatusReader: Send + Sync {
    fn read_runtime_status(&self) -> Result<RuntimeUpstreamStatusSnapshot, AppError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeResourcePressure {
    Normal,
    Pressured,
    Exhausted,
    FailedClosed,
}

impl RuntimeResourcePressure {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Pressured => "pressured",
            Self::Exhausted => "exhausted",
            Self::FailedClosed => "failed_closed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeResourceStatusSnapshot {
    pub revision_id: ConfigRevisionId,
    pub generation: u64,
    pub used_payload_bytes: usize,
    pub payload_limit_bytes: usize,
    pub active_connections: usize,
    pub pressure: RuntimeResourcePressure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeResourceStatusPublishOutcome {
    Accepted,
    Full,
    Stopped,
}

pub trait RuntimeResourceStatusPublisher: Send + Sync {
    fn try_publish_resource_status(
        &self,
        snapshot: RuntimeResourceStatusSnapshot,
    ) -> RuntimeResourceStatusPublishOutcome;
}

pub trait RuntimeResourceStatusReader: Send + Sync {
    fn read_resource_status(&self) -> Result<RuntimeResourceStatusSnapshot, AppError>;
}

pub trait OperationalRuntimeStatusPublisher: Send + Sync {
    fn publish_operational_runtime_facts(&self, facts: OperationalRuntimeFacts);
}

pub trait OperationalRuntimeStatusReader: Send + Sync {
    fn read_operational_runtime_facts(&self) -> Result<OperationalRuntimeFacts, AppError>;
}

/// Deployment adapter boundary. Implementations may inspect package/service and
/// filesystem permissions, but never receive a passphrase value.
pub trait OfflineUpgradeDeployment {
    fn admit_upgrade_artifact(&mut self, request: &OfflineUpgradeRequest) -> Result<(), AppError>;
    fn preflight_upgrade(&mut self, request: &OfflineUpgradeRequest) -> Result<(), AppError>;
    fn create_and_verify_upgrade_backup(
        &mut self,
        request: &OfflineUpgradeRequest,
    ) -> Result<OfflineUpgradeBackupReceipt, AppError>;
    fn stage_upgrade_artifact(&mut self, request: &OfflineUpgradeRequest) -> Result<(), AppError>;
    fn drain_and_stop_service(&mut self) -> Result<(), AppError>;
    fn switch_to_staged_artifact(&mut self) -> Result<(), AppError>;
    fn start_and_wait_ready(&mut self) -> Result<(), AppError>;
    fn rollback_upgrade(&mut self, receipt: &OfflineUpgradeBackupReceipt) -> Result<(), AppError>;
}

/// A secret-free deployment command. A concrete runner owns its fixed service
/// identity, working paths, and executable allowlist; callers cannot supply
/// arbitrary argv or environment values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfflineUpgradeCommand {
    AdmitArtifact {
        artifact_file: String,
        image_digest: String,
    },
    Preflight {
        target_version: String,
        image_digest: String,
    },
    CreateAndVerifyBackup {
        passphrase_file: String,
    },
    StageArtifact {
        image_digest: String,
    },
    DrainAndStop,
    SwitchToStagedArtifact,
    StartAndWaitReady,
    Rollback {
        backup_id: String,
        previous_artifact_digest: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfflineUpgradeCommandResult {
    Completed,
    BackupCreated(OfflineUpgradeBackupReceipt),
}

pub trait OfflineUpgradeCommandRunner {
    fn run_upgrade_command(
        &mut self,
        command: OfflineUpgradeCommand,
    ) -> Result<OfflineUpgradeCommandResult, AppError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineUpgradeBackupReceipt {
    pub backup_id: String,
    pub previous_artifact_digest: String,
}

pub trait OfflineUpgradeJournalStore {
    fn persist_upgrade_journal(&mut self, journal: &OfflineUpgradeJournal) -> Result<(), AppError>;
    fn load_upgrade_journal(
        &mut self,
        operation_id: &str,
    ) -> Result<Option<OfflineUpgradeJournal>, AppError>;
}

#[derive(Debug, Clone)]
pub struct BoundedPassiveObservationQueue {
    capacity: usize,
    stopped: bool,
    observations: VecDeque<PassiveObservation>,
}

impl BoundedPassiveObservationQueue {
    pub fn new(capacity: usize) -> Result<Self, AppError> {
        if capacity == 0 {
            return Err(AppError::new(
                ErrorCode::InternalBug,
                "passive observation queue capacity must be positive",
            ));
        }
        Ok(Self {
            capacity,
            stopped: false,
            observations: VecDeque::with_capacity(capacity),
        })
    }

    pub fn pop(&mut self) -> Option<PassiveObservation> {
        self.observations.pop_front()
    }

    pub fn stop(&mut self) {
        self.stopped = true;
    }
}

impl PassiveObservationDispatcher for BoundedPassiveObservationQueue {
    fn submit(&mut self, observation: PassiveObservation) -> PassiveObservationSubmit {
        if self.stopped {
            PassiveObservationSubmit::Stopped
        } else if self.observations.len() >= self.capacity {
            PassiveObservationSubmit::Full
        } else {
            self.observations.push_back(observation);
            PassiveObservationSubmit::Accepted
        }
    }
}

impl HealthProbeResult {
    pub fn succeeded(status_code: u16, duration_ms: u64) -> Self {
        Self {
            outcome: HealthProbeOutcome::Succeeded { status_code },
            duration_ms,
        }
    }

    pub fn failed(reason: HealthProbeFailure, duration_ms: u64) -> Self {
        Self {
            outcome: HealthProbeOutcome::Failed(reason),
            duration_ms,
        }
    }
}

pub trait HealthProbeTransport {
    fn probe(&mut self, request: HealthProbeRequest) -> HealthProbeResult;
}

pub trait HealthStatusReader: Send + Sync {
    fn read_health_status(&self) -> Result<HealthAvailabilitySnapshot, AppError>;
}

impl<T> HealthStatusReader for Arc<T>
where
    T: HealthStatusReader + ?Sized,
{
    fn read_health_status(&self) -> Result<HealthAvailabilitySnapshot, AppError> {
        (**self).read_health_status()
    }
}

#[derive(Debug, Clone)]
pub struct ScriptedHealthProbeTransport {
    results: VecDeque<HealthProbeResult>,
    requests: Vec<HealthProbeRequest>,
}

impl ScriptedHealthProbeTransport {
    pub fn new(results: Vec<HealthProbeResult>) -> Self {
        Self {
            results: results.into(),
            requests: Vec::new(),
        }
    }

    pub fn requests(&self) -> &[HealthProbeRequest] {
        &self.requests
    }
}

impl HealthProbeTransport for ScriptedHealthProbeTransport {
    fn probe(&mut self, request: HealthProbeRequest) -> HealthProbeResult {
        self.requests.push(request);
        self.results
            .pop_front()
            .unwrap_or_else(|| HealthProbeResult::failed(HealthProbeFailure::Internal, 0))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRecord {
    pub name: String,
    pub value: String,
}

impl SecretRecord {
    pub fn masked_value(&self) -> &'static str {
        "***"
    }
}

pub trait SecretStore {
    fn save_secret(&mut self, secret: SecretRecord) -> Result<(), AppError>;
    fn load_secret(&self, name: &str) -> Result<Option<SecretRecord>, AppError>;
}

pub trait CoreCommandClient {
    fn send(&mut self, command: CoreCommand) -> CommandAck;
}

pub trait Http01ChallengeResponder: Send + Sync {
    fn respond(&self, token: &str) -> Option<String>;
}

pub trait Http01ChallengeStore: Http01ChallengeResponder {
    fn insert_http01(&mut self, token: String, key_authorization: String) -> Result<(), AppError>;
    fn clear_http01(&mut self, token: &str) -> Result<(), AppError>;
}

pub trait Http01ChallengeProbe {
    fn verify_http01(
        &mut self,
        token: &str,
        expected_key_authorization: &str,
    ) -> Result<(), AppError>;
}

pub trait AcmeHttp01ChallengeRuntime {
    fn present_http01(&mut self, token: String, key_authorization: String) -> Result<(), AppError>;
    fn verify_http01(
        &mut self,
        token: &str,
        expected_key_authorization: &str,
    ) -> Result<(), AppError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCertificate {
    pub certificate_ref: CertificateRef,
    pub domains: Vec<String>,
    pub not_after_epoch_seconds: u64,
    pub source: String,
    pub certificate_pem: String,
    pub private_key_pem: String,
}

impl StoredCertificate {
    pub fn masked_private_key(&self) -> &'static str {
        "***"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateMaterial {
    pub certificate_pem: String,
    pub private_key_pem: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCertificateMaterial {
    pub not_after_epoch_seconds: u64,
    pub dns_names: Vec<String>,
}

pub trait CertificateMaterialValidator {
    fn validate(
        &mut self,
        material: &CertificateMaterial,
    ) -> Result<ValidatedCertificateMaterial, AppError>;
}

impl<T> CertificateMaterialValidator for &mut T
where
    T: CertificateMaterialValidator + ?Sized,
{
    fn validate(
        &mut self,
        material: &CertificateMaterial,
    ) -> Result<ValidatedCertificateMaterial, AppError> {
        (**self).validate(material)
    }
}

pub trait CertificateStore {
    fn save_certificate(&mut self, certificate: StoredCertificate) -> Result<(), AppError>;
    fn load_certificate(
        &self,
        certificate_ref: &CertificateRef,
    ) -> Result<Option<StoredCertificate>, AppError>;
    fn list_certificates(&self) -> Result<Vec<StoredCertificate>, AppError>;
    fn delete_certificate(&mut self, certificate_ref: &CertificateRef) -> Result<(), AppError>;
}

impl<T> CertificateStore for &mut T
where
    T: CertificateStore + ?Sized,
{
    fn save_certificate(&mut self, certificate: StoredCertificate) -> Result<(), AppError> {
        (**self).save_certificate(certificate)
    }

    fn load_certificate(
        &self,
        certificate_ref: &CertificateRef,
    ) -> Result<Option<StoredCertificate>, AppError> {
        (**self).load_certificate(certificate_ref)
    }

    fn list_certificates(&self) -> Result<Vec<StoredCertificate>, AppError> {
        (**self).list_certificates()
    }

    fn delete_certificate(&mut self, certificate_ref: &CertificateRef) -> Result<(), AppError> {
        (**self).delete_certificate(certificate_ref)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeOrderRequest {
    pub domains: Vec<String>,
    pub account_email: String,
    pub production: bool,
    pub terms_accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeOrderResult {
    pub certificate: StoredCertificate,
}

pub trait AcmeClient {
    fn issue_certificate(&mut self, request: AcmeOrderRequest)
        -> Result<AcmeOrderResult, AppError>;

    fn issue_certificate_http01(
        &mut self,
        request: AcmeOrderRequest,
        challenge_runtime: &mut dyn AcmeHttp01ChallengeRuntime,
    ) -> Result<AcmeOrderResult, AppError> {
        let _ = challenge_runtime;
        self.issue_certificate(request)
    }
}

impl<T> AcmeClient for &mut T
where
    T: AcmeClient + ?Sized,
{
    fn issue_certificate(
        &mut self,
        request: AcmeOrderRequest,
    ) -> Result<AcmeOrderResult, AppError> {
        (**self).issue_certificate(request)
    }

    fn issue_certificate_http01(
        &mut self,
        request: AcmeOrderRequest,
        challenge_runtime: &mut dyn AcmeHttp01ChallengeRuntime,
    ) -> Result<AcmeOrderResult, AppError> {
        (**self).issue_certificate_http01(request, challenge_runtime)
    }
}

impl<T> AcmeClient for Box<T>
where
    T: AcmeClient + ?Sized,
{
    fn issue_certificate(
        &mut self,
        request: AcmeOrderRequest,
    ) -> Result<AcmeOrderResult, AppError> {
        (**self).issue_certificate(request)
    }

    fn issue_certificate_http01(
        &mut self,
        request: AcmeOrderRequest,
        challenge_runtime: &mut dyn AcmeHttp01ChallengeRuntime,
    ) -> Result<AcmeOrderResult, AppError> {
        (**self).issue_certificate_http01(request, challenge_runtime)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MetricDescriptor {
    RequestsTotal,
    RequestDuration,
    ActiveConnections,
    UpstreamSelectionsTotal,
    UpstreamFailuresTotal,
    UpstreamAvailable,
    UpstreamHealthTransitionsTotal,
    UpstreamNoEligibleTotal,
    FailureAwareTransitionsTotal,
    TlsHandshakeFailuresTotal,
    CertificateNotAfter,
    MetricEventsDroppedTotal,
    MetricsReady,
    BuildInfo,
    ProcessStartTime,
    ResourcePayloadBytes,
    ResourcePayloadLimitBytes,
    ResourceAdmissionRejectionsTotal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResourceMetricKind {
    Connection,
    Payload,
}

impl ResourceMetricKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connection => "connection",
            Self::Payload => "payload",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResourceRejectionReason {
    ConnectionLimit,
    PayloadPressure,
    FailedClosed,
}

impl ResourceRejectionReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConnectionLimit => "connection_limit",
            Self::PayloadPressure => "payload_pressure",
            Self::FailedClosed => "failed_closed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricKind {
    Counter,
    Gauge,
    Histogram,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricDefinition {
    pub name: &'static str,
    pub help: &'static str,
    pub kind: MetricKind,
    pub required_labels: &'static [&'static str],
    pub histogram_buckets_ms: &'static [u64],
}

const NO_LABELS: &[&str] = &[];
const NO_BUCKETS: &[u64] = &[];
const REQUEST_BUCKETS_MS: &[u64] = &[5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000];

impl MetricDescriptor {
    pub const ALL: [Self; 18] = [
        Self::RequestsTotal,
        Self::RequestDuration,
        Self::ActiveConnections,
        Self::UpstreamSelectionsTotal,
        Self::UpstreamFailuresTotal,
        Self::UpstreamAvailable,
        Self::UpstreamHealthTransitionsTotal,
        Self::UpstreamNoEligibleTotal,
        Self::FailureAwareTransitionsTotal,
        Self::TlsHandshakeFailuresTotal,
        Self::CertificateNotAfter,
        Self::MetricEventsDroppedTotal,
        Self::MetricsReady,
        Self::BuildInfo,
        Self::ProcessStartTime,
        Self::ResourcePayloadBytes,
        Self::ResourcePayloadLimitBytes,
        Self::ResourceAdmissionRejectionsTotal,
    ];

    pub fn definition(self) -> MetricDefinition {
        use MetricDescriptor::*;
        let (name, help, kind, labels, buckets) = match self {
            RequestsTotal => (
                "sponzey_edge_requests_total",
                "Completed client requests.",
                MetricKind::Counter,
                &["route_id", "status_class"][..],
                NO_BUCKETS,
            ),
            RequestDuration => (
                "sponzey_edge_request_duration_seconds",
                "End-to-end request duration.",
                MetricKind::Histogram,
                &["route_id"][..],
                REQUEST_BUCKETS_MS,
            ),
            ActiveConnections => (
                "sponzey_edge_active_connections",
                "Current client connections.",
                MetricKind::Gauge,
                NO_LABELS,
                NO_BUCKETS,
            ),
            UpstreamSelectionsTotal => (
                "sponzey_edge_upstream_selections_total",
                "Selected upstream attempts.",
                MetricKind::Counter,
                &["service_id", "upstream_id"][..],
                NO_BUCKETS,
            ),
            UpstreamFailuresTotal => (
                "sponzey_edge_upstream_failures_total",
                "Upstream transport failures.",
                MetricKind::Counter,
                &["route_id", "upstream_id", "error_code"][..],
                NO_BUCKETS,
            ),
            UpstreamAvailable => (
                "sponzey_edge_upstream_available",
                "Effective upstream availability.",
                MetricKind::Gauge,
                &["service_id", "upstream_id"][..],
                NO_BUCKETS,
            ),
            UpstreamHealthTransitionsTotal => (
                "sponzey_edge_upstream_health_transitions_total",
                "Upstream health transitions.",
                MetricKind::Counter,
                &["service_id", "upstream_id", "from", "to"][..],
                NO_BUCKETS,
            ),
            UpstreamNoEligibleTotal => (
                "sponzey_edge_upstream_no_eligible_total",
                "Requests without an eligible upstream.",
                MetricKind::Counter,
                &["service_id"][..],
                NO_BUCKETS,
            ),
            FailureAwareTransitionsTotal => (
                "sponzey_edge_failure_aware_transitions_total",
                "Failure-aware runtime transitions.",
                MetricKind::Counter,
                &["event", "reason"][..],
                NO_BUCKETS,
            ),
            TlsHandshakeFailuresTotal => (
                "sponzey_edge_tls_handshake_failures_total",
                "TLS handshake failures.",
                MetricKind::Counter,
                &["error_code"][..],
                NO_BUCKETS,
            ),
            CertificateNotAfter => (
                "sponzey_edge_certificate_not_after_seconds",
                "Certificate expiry epoch.",
                MetricKind::Gauge,
                &["certificate_ref", "source"][..],
                NO_BUCKETS,
            ),
            MetricEventsDroppedTotal => (
                "sponzey_edge_metric_events_dropped_total",
                "Dropped metric observations.",
                MetricKind::Counter,
                &["reason"][..],
                NO_BUCKETS,
            ),
            MetricsReady => (
                "sponzey_edge_metrics_ready",
                "Metrics readiness.",
                MetricKind::Gauge,
                NO_LABELS,
                NO_BUCKETS,
            ),
            BuildInfo => (
                "sponzey_edge_build_info",
                "Build identity.",
                MetricKind::Gauge,
                &["version"][..],
                NO_BUCKETS,
            ),
            ProcessStartTime => (
                "sponzey_edge_process_start_time_seconds",
                "Process start epoch.",
                MetricKind::Gauge,
                NO_LABELS,
                NO_BUCKETS,
            ),
            ResourcePayloadBytes => (
                "sponzey_edge_resource_payload_bytes",
                "Payload bytes currently charged to the active runtime ledger.",
                MetricKind::Gauge,
                NO_LABELS,
                NO_BUCKETS,
            ),
            ResourcePayloadLimitBytes => (
                "sponzey_edge_resource_payload_limit_bytes",
                "Payload byte limit of the active runtime resource policy.",
                MetricKind::Gauge,
                NO_LABELS,
                NO_BUCKETS,
            ),
            ResourceAdmissionRejectionsTotal => (
                "sponzey_edge_resource_admission_rejections_total",
                "Resource admission rejections by bounded kind and reason.",
                MetricKind::Counter,
                &["resource_kind", "reason"][..],
                NO_BUCKETS,
            ),
        };
        MetricDefinition {
            name,
            help,
            kind,
            required_labels: labels,
            histogram_buckets_ms: buckets,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricOperation {
    CounterAdd(u64),
    GaugeSet(i64),
    HistogramObserve(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricObservation {
    pub descriptor: MetricDescriptor,
    pub operation: MetricOperation,
    pub labels: Vec<(String, String)>,
}

impl MetricObservation {
    pub fn counter_add(
        descriptor: MetricDescriptor,
        value: u64,
        labels: Vec<(String, String)>,
    ) -> Result<Self, AppError> {
        Self::new(descriptor, MetricOperation::CounterAdd(value), labels)
    }

    pub fn gauge_set(
        descriptor: MetricDescriptor,
        value: i64,
        labels: Vec<(String, String)>,
    ) -> Result<Self, AppError> {
        Self::new(descriptor, MetricOperation::GaugeSet(value), labels)
    }

    pub fn histogram_observe(
        descriptor: MetricDescriptor,
        value_ms: u64,
        labels: Vec<(String, String)>,
    ) -> Result<Self, AppError> {
        Self::new(
            descriptor,
            MetricOperation::HistogramObserve(value_ms),
            labels,
        )
    }

    pub fn new(
        descriptor: MetricDescriptor,
        operation: MetricOperation,
        mut labels: Vec<(String, String)>,
    ) -> Result<Self, AppError> {
        let definition = descriptor.definition();
        let compatible = matches!(
            (definition.kind, operation),
            (MetricKind::Counter, MetricOperation::CounterAdd(_))
                | (MetricKind::Gauge, MetricOperation::GaugeSet(_))
                | (MetricKind::Histogram, MetricOperation::HistogramObserve(_))
        );
        labels.sort();
        let keys = labels
            .iter()
            .map(|(key, _)| key.as_str())
            .collect::<Vec<_>>();
        let mut required = definition.required_labels.to_vec();
        required.sort_unstable();
        let closed_values = if descriptor == MetricDescriptor::ResourceAdmissionRejectionsTotal {
            let resource_kind = labels
                .iter()
                .find(|(key, _)| key == "resource_kind")
                .map(|(_, value)| value.as_str());
            let reason = labels
                .iter()
                .find(|(key, _)| key == "reason")
                .map(|(_, value)| value.as_str());
            matches!(
                (resource_kind, reason),
                (Some("connection"), Some("connection_limit"))
                    | (Some("payload"), Some("payload_pressure" | "failed_closed"))
            )
        } else {
            true
        };
        if !compatible || keys != required || !closed_values {
            return Err(AppError::new(
                ErrorCode::InternalBug,
                "invalid metric observation contract",
            ));
        }
        Ok(Self {
            descriptor,
            operation,
            labels,
        })
    }
}

pub type MetricEvent = MetricObservation;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricPublishOutcome {
    Accepted,
    Full,
    Stopped,
}

pub trait MetricPublisher: Send + Sync {
    fn try_publish(&self, metric: MetricEvent) -> MetricPublishOutcome;
}

pub trait MetricsSink {
    fn record_metric(&mut self, metric: MetricEvent) -> Result<(), AppError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredLogEvent {
    pub component: String,
    pub event: String,
    pub fields: Vec<(String, String)>,
}

pub trait LogSink {
    fn record_log(&mut self, event: StructuredLogEvent) -> Result<(), AppError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsSessionProgress {
    Handshaking,
    Established,
    Closing,
    PeerClosed,
    Failed { code: ErrorCode },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsSessionInterest {
    pub wants_read: bool,
    pub wants_write: bool,
}

impl TlsSessionInterest {
    pub fn none() -> Self {
        Self {
            wants_read: false,
            wants_write: false,
        }
    }

    pub fn readable() -> Self {
        Self {
            wants_read: true,
            wants_write: false,
        }
    }

    pub fn writable() -> Self {
        Self {
            wants_read: false,
            wants_write: true,
        }
    }

    pub fn read_write() -> Self {
        Self {
            wants_read: true,
            wants_write: true,
        }
    }
}

pub trait ServerTlsSessionFactory {
    fn create_server_session(&self) -> Box<dyn TlsSession + Send>;
}

pub trait ClientTlsSessionFactory {
    fn create_client_session(
        &self,
        server_name: &TlsServerName,
    ) -> Result<Box<dyn TlsSession + Send>, AppError>;
}

/// Bytes currently owned by TLS adapter staging buffers.
///
/// This excludes allocations hidden inside a TLS library implementation. Those
/// allocations must be evaluated through process-level memory measurements.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TlsPendingBytes {
    pub handshake_bytes: usize,
    pub decrypted_bytes: usize,
    pub encrypted_bytes: usize,
}

impl TlsPendingBytes {
    pub const fn new(
        handshake_bytes: usize,
        decrypted_bytes: usize,
        encrypted_bytes: usize,
    ) -> Self {
        Self {
            handshake_bytes,
            decrypted_bytes,
            encrypted_bytes,
        }
    }

    pub fn total_bytes(self) -> Option<usize> {
        self.handshake_bytes
            .checked_add(self.decrypted_bytes)?
            .checked_add(self.encrypted_bytes)
    }

    pub const fn is_zero(self) -> bool {
        self.handshake_bytes == 0 && self.decrypted_bytes == 0 && self.encrypted_bytes == 0
    }
}

pub trait TlsSession {
    fn receive_encrypted(&mut self, bytes: &[u8]) -> Result<usize, AppError>;
    fn take_decrypted(&mut self, max_bytes: usize) -> Vec<u8>;
    fn receive_plaintext(&mut self, bytes: &[u8]) -> Result<usize, AppError>;
    fn take_encrypted(&mut self, max_bytes: usize) -> Vec<u8>;
    fn progress(&self) -> TlsSessionProgress;
    fn interest(&self) -> TlsSessionInterest;
    fn pending_bytes(&self) -> TlsPendingBytes;
    fn sni_hostname(&self) -> Option<&str>;
    fn request_close_notify(&mut self) -> Result<(), AppError>;
}

#[derive(Debug, Clone)]
pub struct ScriptedServerTlsSessionFactory {
    template: ScriptedTlsSession,
}

impl ScriptedServerTlsSessionFactory {
    pub fn new(template: ScriptedTlsSession) -> Self {
        Self { template }
    }
}

impl ServerTlsSessionFactory for ScriptedServerTlsSessionFactory {
    fn create_server_session(&self) -> Box<dyn TlsSession + Send> {
        Box::new(self.template.clone())
    }
}

#[derive(Debug, Clone)]
pub struct ScriptedClientTlsSessionFactory {
    template: ScriptedTlsSession,
    requested_server_names: Arc<Mutex<Vec<TlsServerName>>>,
}

impl ScriptedClientTlsSessionFactory {
    pub fn new(template: ScriptedTlsSession) -> Self {
        Self {
            template,
            requested_server_names: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn requested_server_names(&self) -> Vec<TlsServerName> {
        self.requested_server_names
            .lock()
            .map(|names| names.clone())
            .unwrap_or_default()
    }
}

impl ClientTlsSessionFactory for ScriptedClientTlsSessionFactory {
    fn create_client_session(
        &self,
        server_name: &TlsServerName,
    ) -> Result<Box<dyn TlsSession + Send>, AppError> {
        self.requested_server_names
            .lock()
            .map_err(|_| AppError::new(ErrorCode::InternalBug, "TLS fixture lock poisoned"))?
            .push(server_name.clone());
        Ok(Box::new(self.template.clone()))
    }
}

#[derive(Debug, Clone)]
pub struct ScriptedTlsSession {
    progress: TlsSessionProgress,
    receive_failure: Option<AppError>,
    handshake_marker: Vec<u8>,
    handshake_input: Vec<u8>,
    decrypted: Vec<u8>,
    encrypted: Vec<u8>,
    handshake_response: Vec<u8>,
    sni_hostname: Option<String>,
}

impl ScriptedTlsSession {
    pub fn new() -> Self {
        Self {
            progress: TlsSessionProgress::Handshaking,
            receive_failure: None,
            handshake_marker: b"client-hello".to_vec(),
            handshake_input: Vec::new(),
            decrypted: Vec::new(),
            encrypted: Vec::new(),
            handshake_response: Vec::new(),
            sni_hostname: None,
        }
    }

    pub fn established() -> Self {
        Self {
            progress: TlsSessionProgress::Established,
            ..Self::new()
        }
    }

    pub fn with_sni(mut self, hostname: impl Into<String>) -> Self {
        self.sni_hostname = Some(hostname.into());
        self
    }

    pub fn with_handshake_marker(mut self, marker: &[u8]) -> Self {
        self.handshake_marker = marker.to_vec();
        self
    }

    pub fn with_handshake_response(mut self, response: &[u8]) -> Self {
        self.handshake_response = response.to_vec();
        self
    }

    pub fn with_initial_encrypted(mut self, bytes: &[u8]) -> Self {
        self.encrypted = bytes.to_vec();
        self
    }

    pub fn with_receive_failure(mut self, error: AppError) -> Self {
        self.receive_failure = Some(error);
        self
    }

    pub fn mark_peer_closed(&mut self) {
        self.progress = TlsSessionProgress::PeerClosed;
    }

    pub fn mark_failed(&mut self, error: AppError) {
        self.progress = TlsSessionProgress::Failed { code: error.code };
    }

    fn drain(buffer: &mut Vec<u8>, max_bytes: usize) -> Vec<u8> {
        let drain = buffer.len().min(max_bytes);
        buffer.drain(..drain).collect()
    }
}

impl Default for ScriptedTlsSession {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsSession for ScriptedTlsSession {
    fn receive_encrypted(&mut self, bytes: &[u8]) -> Result<usize, AppError> {
        if let Some(error) = self.receive_failure.take() {
            self.progress = TlsSessionProgress::Failed { code: error.code };
            return Err(error);
        }
        match self.progress {
            TlsSessionProgress::Failed { .. }
            | TlsSessionProgress::Closing
            | TlsSessionProgress::PeerClosed => Ok(0),
            TlsSessionProgress::Handshaking => {
                self.handshake_input.extend_from_slice(bytes);
                if self.handshake_input.starts_with(&self.handshake_marker) {
                    let plaintext = self.handshake_input.split_off(self.handshake_marker.len());
                    self.handshake_input.clear();
                    self.decrypted.extend_from_slice(&plaintext);
                    self.encrypted.extend_from_slice(&self.handshake_response);
                    self.progress = TlsSessionProgress::Established;
                }
                Ok(bytes.len())
            }
            TlsSessionProgress::Established => {
                self.decrypted.extend_from_slice(bytes);
                Ok(bytes.len())
            }
        }
    }

    fn take_decrypted(&mut self, max_bytes: usize) -> Vec<u8> {
        Self::drain(&mut self.decrypted, max_bytes)
    }

    fn receive_plaintext(&mut self, bytes: &[u8]) -> Result<usize, AppError> {
        if self.progress == TlsSessionProgress::Established {
            self.encrypted.extend_from_slice(bytes);
            Ok(bytes.len())
        } else {
            Err(AppError::new(
                ErrorCode::TlsHandshakeTimeout,
                "TLS session is not established",
            ))
        }
    }

    fn take_encrypted(&mut self, max_bytes: usize) -> Vec<u8> {
        let drained = Self::drain(&mut self.encrypted, max_bytes);
        if self.progress == TlsSessionProgress::Closing && self.encrypted.is_empty() {
            self.progress = TlsSessionProgress::PeerClosed;
        }
        drained
    }

    fn progress(&self) -> TlsSessionProgress {
        self.progress
    }

    fn interest(&self) -> TlsSessionInterest {
        match self.progress {
            TlsSessionProgress::Failed { .. } | TlsSessionProgress::PeerClosed => {
                TlsSessionInterest::none()
            }
            TlsSessionProgress::Closing => TlsSessionInterest::writable(),
            _ if !self.encrypted.is_empty() => TlsSessionInterest::writable(),
            _ => TlsSessionInterest::readable(),
        }
    }

    fn pending_bytes(&self) -> TlsPendingBytes {
        TlsPendingBytes::new(
            self.handshake_input.len(),
            self.decrypted.len(),
            self.encrypted.len(),
        )
    }

    fn sni_hostname(&self) -> Option<&str> {
        self.sni_hostname.as_deref()
    }

    fn request_close_notify(&mut self) -> Result<(), AppError> {
        self.encrypted.extend_from_slice(b"close_notify");
        self.progress = TlsSessionProgress::Closing;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeAuditLedger {
        records: Vec<AuditRecord>,
        head: AuditLedgerHead,
        state: AuditAdmissionState,
    }

    impl FakeAuditLedger {
        fn append(&mut self, record: AuditRecord) -> AuditLedgerHead {
            self.records.push(record);
            self.head.sequence += 1;
            self.head
        }
    }

    impl AuditLedgerWriter for FakeAuditLedger {
        fn append_intent(&mut self, record: AuditRecord) -> Result<AuditLedgerHead, AppError> {
            Ok(self.append(record))
        }

        fn append_terminal(
            &mut self,
            record: AuditRecord,
            _expected_head: AuditLedgerHead,
        ) -> Result<AuditLedgerHead, AppError> {
            Ok(self.append(record))
        }

        fn append_reconciliation(
            &mut self,
            record: AuditRecord,
            _expected_head: AuditLedgerHead,
        ) -> Result<AuditLedgerHead, AppError> {
            Ok(self.append(record))
        }

        fn append_security_observation(
            &mut self,
            record: AuditRecord,
        ) -> Result<AuditLedgerHead, AppError> {
            Ok(self.append(record))
        }
    }

    impl AuditLedgerReader for FakeAuditLedger {
        fn query(&self, _query: &AuditQuery) -> Result<AuditPage, AppError> {
            Ok(AuditPage {
                records: self
                    .records
                    .iter()
                    .cloned()
                    .enumerate()
                    .map(|(index, record)| edge_domain::AuditRecordView {
                        sequence: index as u64 + 1,
                        record,
                    })
                    .collect(),
                next_cursor: None,
                head: self.head,
                admission_state: self.state,
            })
        }

        fn incomplete_operations(&self) -> Result<Vec<AuditRecord>, AppError> {
            Ok(Vec::new())
        }

        fn unresolved_reconciliations(&self) -> Result<Vec<AuditRecord>, AppError> {
            Ok(Vec::new())
        }

        fn head(&self) -> Result<AuditLedgerHead, AppError> {
            Ok(self.head)
        }
    }

    impl AuditLedgerVerifier for FakeAuditLedger {
        fn verify(&mut self) -> Result<AuditVerificationReport, AppError> {
            Ok(AuditVerificationReport {
                head: self.head,
                record_count: self.records.len() as u64,
                segment_count: u16::from(!self.records.is_empty()),
                incomplete_operation_count: 0,
            })
        }
    }

    impl AuditAdmissionController for FakeAuditLedger {
        fn state(&self) -> AuditAdmissionState {
            self.state
        }

        fn replace_state(&mut self, state: AuditAdmissionState) {
            self.state = state;
        }
    }

    fn audit_record() -> AuditRecord {
        AuditRecord {
            record_version: 1,
            record_kind: edge_domain::AuditRecordKind::Intent,
            context: edge_domain::AuditContext {
                operation_id: AuditOperationId::parse("operation-1").unwrap(),
                request_id: edge_domain::AuditRequestId::parse("request-1").unwrap(),
                actor_kind: edge_domain::AuditActorKind::BootstrapAdmin,
                received_at_epoch_seconds: 10,
            },
            action: AuditAction::ConfigApply,
            target_kind: edge_domain::AuditTargetKind::ConfigRevision,
            target_id: AuditTargetId::parse("revision-1").unwrap(),
            before_revision: None,
            after_revision: None,
            outcome: None,
            error_code: None,
        }
    }

    #[test]
    fn typed_audit_ports_are_fully_replaceable_with_a_fake() {
        let mut fake = FakeAuditLedger::default();
        fake.replace_state(AuditAdmissionState::Healthy);

        let head = fake.append_intent(audit_record()).unwrap();
        let page = fake.query(&AuditQuery::default()).unwrap();
        let report = fake.verify().unwrap();

        assert_eq!(head.sequence, 1);
        assert_eq!(page.records.len(), 1);
        assert_eq!(report.record_count, 1);
        assert_eq!(fake.state(), AuditAdmissionState::Healthy);
    }

    #[test]
    fn metric_descriptors_define_stable_contract_and_histogram_buckets() {
        let requests = MetricDescriptor::RequestsTotal.definition();
        assert_eq!(requests.name, "sponzey_edge_requests_total");
        assert_eq!(requests.kind, MetricKind::Counter);
        assert_eq!(requests.required_labels, &["route_id", "status_class"]);

        let duration = MetricDescriptor::RequestDuration.definition();
        assert_eq!(duration.kind, MetricKind::Histogram);
        assert_eq!(
            duration.histogram_buckets_ms,
            &[5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000]
        );
        let payload = MetricDescriptor::ResourcePayloadBytes.definition();
        assert_eq!(payload.name, "sponzey_edge_resource_payload_bytes");
        assert_eq!(payload.kind, MetricKind::Gauge);
        assert!(payload.required_labels.is_empty());

        let limit = MetricDescriptor::ResourcePayloadLimitBytes.definition();
        assert_eq!(limit.name, "sponzey_edge_resource_payload_limit_bytes");
        assert_eq!(limit.kind, MetricKind::Gauge);
        assert!(limit.required_labels.is_empty());

        let rejections = MetricDescriptor::ResourceAdmissionRejectionsTotal.definition();
        assert_eq!(
            rejections.name,
            "sponzey_edge_resource_admission_rejections_total"
        );
        assert_eq!(rejections.kind, MetricKind::Counter);
        assert_eq!(rejections.required_labels, &["resource_kind", "reason"]);
        assert_eq!(MetricDescriptor::ALL.len(), 18);
    }

    #[test]
    fn resource_admission_metric_rejects_open_or_invalid_label_combinations() {
        assert!(MetricObservation::counter_add(
            MetricDescriptor::ResourceAdmissionRejectionsTotal,
            1,
            vec![
                ("resource_kind".to_string(), "request-path".to_string()),
                ("reason".to_string(), "custom".to_string()),
            ],
        )
        .is_err());
        assert!(MetricObservation::counter_add(
            MetricDescriptor::ResourceAdmissionRejectionsTotal,
            1,
            vec![
                ("resource_kind".to_string(), "connection".to_string()),
                ("reason".to_string(), "payload_pressure".to_string()),
            ],
        )
        .is_err());
        assert!(MetricObservation::counter_add(
            MetricDescriptor::ResourceAdmissionRejectionsTotal,
            1,
            vec![
                ("resource_kind".to_string(), "payload".to_string()),
                ("reason".to_string(), "failed_closed".to_string()),
            ],
        )
        .is_ok());
    }

    #[test]
    fn metric_observation_rejects_operation_and_label_contract_violations() {
        assert!(
            MetricObservation::counter_add(MetricDescriptor::ActiveConnections, 1, Vec::new())
                .is_err()
        );
        assert!(MetricObservation::counter_add(
            MetricDescriptor::RequestsTotal,
            1,
            vec![("route_id".to_string(), "route-a".to_string())]
        )
        .is_err());
        assert!(MetricObservation::counter_add(
            MetricDescriptor::RequestsTotal,
            1,
            vec![
                ("route_id".to_string(), "route-a".to_string()),
                ("route_id".to_string(), "route-b".to_string()),
                ("status_class".to_string(), "2xx".to_string()),
            ]
        )
        .is_err());

        let valid = MetricObservation::counter_add(
            MetricDescriptor::RequestsTotal,
            1,
            vec![
                ("route_id".to_string(), "route-a".to_string()),
                ("status_class".to_string(), "2xx".to_string()),
            ],
        )
        .unwrap();
        assert_eq!(valid.operation, MetricOperation::CounterAdd(1));
    }

    #[test]
    fn exposes_crate_name() {
        assert_eq!(crate_name(), "edge-ports");
    }

    #[test]
    fn secret_records_mask_values() {
        let secret = SecretRecord {
            name: "admin-password".to_string(),
            value: "secret".to_string(),
        };

        assert_eq!(secret.masked_value(), "***");
    }

    #[test]
    fn tls_session_port_supports_partial_progress() {
        let mut session = ScriptedTlsSession::new()
            .with_sni("app.localhost")
            .with_handshake_marker(b"client-hello");

        assert_eq!(session.progress(), TlsSessionProgress::Handshaking);
        assert_eq!(session.interest(), TlsSessionInterest::readable());
        assert_eq!(session.receive_encrypted(b"client-").unwrap(), 7);
        assert_eq!(session.progress(), TlsSessionProgress::Handshaking);
        assert_eq!(session.receive_encrypted(b"hello").unwrap(), 5);

        assert_eq!(session.progress(), TlsSessionProgress::Established);
        assert_eq!(session.sni_hostname(), Some("app.localhost"));
    }

    #[test]
    fn tls_session_port_hands_off_bytes_coalesced_after_handshake_marker() {
        let mut session = ScriptedTlsSession::new();

        assert_eq!(
            session
                .receive_encrypted(b"client-helloGET / HTTP/1.1\r\n\r\n")
                .unwrap(),
            30
        );

        assert_eq!(session.progress(), TlsSessionProgress::Established);
        assert_eq!(session.take_decrypted(1024), b"GET / HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn tls_session_port_exposes_pending_ciphertext_without_socket_io() {
        let mut session = ScriptedTlsSession::established();

        assert_eq!(session.receive_plaintext(b"HTTP/1.1 200 OK").unwrap(), 15);
        assert_eq!(session.interest(), TlsSessionInterest::writable());
        assert_eq!(session.take_encrypted(5), b"HTTP/".to_vec());
        assert_eq!(session.take_encrypted(64), b"1.1 200 OK".to_vec());
        assert_eq!(session.interest(), TlsSessionInterest::readable());
    }

    #[test]
    fn tls_pending_bytes_reports_exact_components_and_checked_total() {
        let pending = TlsPendingBytes::new(3, 5, 7);

        assert_eq!(pending.handshake_bytes, 3);
        assert_eq!(pending.decrypted_bytes, 5);
        assert_eq!(pending.encrypted_bytes, 7);
        assert_eq!(pending.total_bytes(), Some(15));
        assert!(!pending.is_zero());
        assert!(TlsPendingBytes::default().is_zero());
        assert_eq!(TlsPendingBytes::new(usize::MAX, 1, 0).total_bytes(), None);
    }

    #[test]
    fn scripted_tls_session_reports_pending_owner_transitions() {
        let mut session = ScriptedTlsSession::new().with_handshake_response(b"reply");

        assert_eq!(session.pending_bytes(), TlsPendingBytes::default());
        session.receive_encrypted(b"client-").unwrap();
        assert_eq!(session.pending_bytes(), TlsPendingBytes::new(7, 0, 0));
        session.receive_encrypted(b"helloGET").unwrap();
        assert_eq!(session.pending_bytes(), TlsPendingBytes::new(0, 3, 5));
        assert_eq!(session.take_decrypted(2), b"GE");
        assert_eq!(session.pending_bytes(), TlsPendingBytes::new(0, 1, 5));
        assert_eq!(session.take_encrypted(3), b"rep");
        assert_eq!(session.pending_bytes(), TlsPendingBytes::new(0, 1, 2));

        assert_eq!(session.take_decrypted(8), b"T");
        assert_eq!(session.take_encrypted(8), b"ly");
        assert!(session.pending_bytes().is_zero());
    }

    #[test]
    fn tls_session_close_notify_stays_writable_until_ciphertext_is_drained() {
        let mut session = ScriptedTlsSession::established();

        session.request_close_notify().unwrap();

        assert_eq!(session.progress(), TlsSessionProgress::Closing);
        assert_eq!(session.interest(), TlsSessionInterest::writable());
        assert_eq!(session.take_encrypted(5), b"close".to_vec());
        assert_eq!(session.progress(), TlsSessionProgress::Closing);
        assert_eq!(session.interest(), TlsSessionInterest::writable());
        assert_eq!(session.take_encrypted(64), b"_notify".to_vec());
        assert_eq!(session.progress(), TlsSessionProgress::PeerClosed);
        assert_eq!(session.interest(), TlsSessionInterest::none());
    }

    #[test]
    fn tls_session_port_roundtrips_plaintext_after_established() {
        let mut session = ScriptedTlsSession::established();

        assert_eq!(session.receive_encrypted(b"GET /").unwrap(), 5);

        assert_eq!(session.take_decrypted(64), b"GET /".to_vec());
        assert_eq!(session.take_decrypted(64), Vec::<u8>::new());
    }

    #[test]
    fn tls_session_port_exposes_peer_close_and_failure_as_states() {
        let mut session = ScriptedTlsSession::established();
        session.mark_peer_closed();
        assert_eq!(session.progress(), TlsSessionProgress::PeerClosed);

        session.mark_failed(AppError::new(ErrorCode::TlsHandshakeTimeout, "bad record"));
        assert!(matches!(
            session.progress(),
            TlsSessionProgress::Failed {
                code: ErrorCode::TlsHandshakeTimeout
            }
        ));
    }

    #[test]
    fn tls_session_factory_returns_independent_sessions() {
        let factory = ScriptedServerTlsSessionFactory::new(ScriptedTlsSession::established());
        let mut first = factory.create_server_session();
        let mut second = factory.create_server_session();

        assert_eq!(first.receive_plaintext(b"one").unwrap(), 3);
        assert_eq!(second.receive_plaintext(b"two").unwrap(), 3);

        assert_eq!(first.take_encrypted(8), b"one".to_vec());
        assert_eq!(second.take_encrypted(8), b"two".to_vec());
    }

    #[test]
    fn phase009_directional_tls_factories_preserve_server_name_and_independent_sessions() {
        let server_factory =
            ScriptedServerTlsSessionFactory::new(ScriptedTlsSession::established());
        let _server = server_factory.create_server_session();

        let client_factory =
            ScriptedClientTlsSessionFactory::new(ScriptedTlsSession::established());
        let server_name = edge_domain::TlsServerName::parse("backend.private.test").unwrap();
        let mut first = client_factory.create_client_session(&server_name).unwrap();
        let mut second = client_factory.create_client_session(&server_name).unwrap();

        assert_eq!(
            client_factory.requested_server_names(),
            vec![server_name.clone(), server_name]
        );
        assert_eq!(first.receive_plaintext(b"one").unwrap(), 3);
        assert_eq!(second.receive_plaintext(b"two").unwrap(), 3);
        assert_eq!(first.take_encrypted(8), b"one".to_vec());
        assert_eq!(second.take_encrypted(8), b"two".to_vec());
    }

    fn health_probe_request() -> HealthProbeRequest {
        HealthProbeRequest {
            probe_id: HealthProbeId(9),
            revision_id: ConfigRevisionId::new("rev-health"),
            generation: HealthGeneration(3),
            key: UpstreamHealthKey {
                service_id: edge_domain::ServiceId::new("app"),
                upstream_id: edge_domain::UpstreamId::new("app-a"),
            },
            endpoint: UpstreamEndpoint::parse("http://127.0.0.1:3001").unwrap(),
            tls: UpstreamTlsPolicy::Disabled,
            path: "/health".to_string(),
            timeout_ms: 500,
            status_min: 200,
            status_max: 399,
        }
    }

    #[test]
    fn scripted_health_probe_transport_returns_fifo_results_and_captures_requests() {
        let success = HealthProbeResult::succeeded(204, 12);
        let failure = HealthProbeResult::failed(HealthProbeFailure::ReadTimeout, 500);
        let mut transport = ScriptedHealthProbeTransport::new(vec![success, failure]);

        assert_eq!(transport.probe(health_probe_request()), success);
        assert_eq!(transport.probe(health_probe_request()), failure);
        assert_eq!(transport.requests().len(), 2);
    }

    #[test]
    fn scripted_health_probe_transport_empty_script_returns_bounded_internal_failure() {
        let mut transport = ScriptedHealthProbeTransport::new(vec![]);

        assert_eq!(
            transport.probe(health_probe_request()),
            HealthProbeResult::failed(HealthProbeFailure::Internal, 0)
        );
        assert_eq!(transport.requests().len(), 1);
    }

    #[test]
    fn health_probe_result_preserves_bounded_value_boundaries() {
        assert_eq!(
            HealthProbeResult::succeeded(599, u64::MAX),
            HealthProbeResult {
                outcome: HealthProbeOutcome::Succeeded { status_code: 599 },
                duration_ms: u64::MAX,
            }
        );
        assert_eq!(
            HealthProbeResult::failed(HealthProbeFailure::StatusMismatch { status_code: 100 }, 0,),
            HealthProbeResult {
                outcome: HealthProbeOutcome::Failed(HealthProbeFailure::StatusMismatch {
                    status_code: 100,
                }),
                duration_ms: 0,
            }
        );
    }

    #[test]
    fn bounded_passive_observation_queue_is_nonblocking_fifo_and_reports_full() {
        let mut queue = BoundedPassiveObservationQueue::new(1).unwrap();
        let observation = PassiveObservation {
            revision_id: ConfigRevisionId::new("rev-1"),
            generation: HealthGeneration(7),
            key: UpstreamHealthKey {
                service_id: edge_domain::ServiceId::new("app"),
                upstream_id: edge_domain::UpstreamId::new("a"),
            },
            outcome: PassiveObservationOutcome::Failed(PassiveFailureReason::Connect),
            observed_at_ms: 10,
        };
        assert_eq!(
            queue.submit(observation.clone()),
            PassiveObservationSubmit::Accepted
        );
        assert_eq!(
            queue.submit(observation.clone()),
            PassiveObservationSubmit::Full
        );
        assert_eq!(queue.pop(), Some(observation));
    }

    #[test]
    fn stopped_passive_observation_queue_rejects_without_blocking() {
        let mut queue = BoundedPassiveObservationQueue::new(1).unwrap();
        queue.stop();
        assert_eq!(
            queue.submit(PassiveObservation {
                revision_id: ConfigRevisionId::new("rev-1"),
                generation: HealthGeneration(1),
                key: UpstreamHealthKey {
                    service_id: edge_domain::ServiceId::new("app"),
                    upstream_id: edge_domain::UpstreamId::new("a")
                },
                outcome: PassiveObservationOutcome::Succeeded,
                observed_at_ms: 0,
            }),
            PassiveObservationSubmit::Stopped
        );
    }

    #[test]
    fn runtime_resource_status_contract_is_closed_and_revision_scoped() {
        let status = RuntimeResourceStatusSnapshot {
            revision_id: ConfigRevisionId::new("rev-active"),
            generation: 7,
            used_payload_bytes: 4_096,
            payload_limit_bytes: 8_192,
            active_connections: 3,
            pressure: RuntimeResourcePressure::Pressured,
        };

        assert_eq!(status.revision_id.as_str(), "rev-active");
        assert_eq!(status.pressure.as_str(), "pressured");
        assert_eq!(RuntimeResourcePressure::Normal.as_str(), "normal");
        assert_eq!(RuntimeResourcePressure::Exhausted.as_str(), "exhausted");
        assert_eq!(
            RuntimeResourcePressure::FailedClosed.as_str(),
            "failed_closed"
        );
        assert_ne!(
            RuntimeResourceStatusPublishOutcome::Full,
            RuntimeResourceStatusPublishOutcome::Stopped
        );
    }
}
