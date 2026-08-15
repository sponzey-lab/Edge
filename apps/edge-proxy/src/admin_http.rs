use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    mpsc, Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(test)]
use edge_adapters::{AuditLedgerOptions, FileAuditLedger, MetricChannelPublisher};
use edge_adapters::{
    FakeAcmeClient, FileCertificateStore, FileRevisionRepository, FileSecretStore,
    FileSupportBundleCollector, FileTrustBundleStore, MemoryCertificateStore, MemoryLogSink,
    RustlsCertificateMaterialValidator, RustlsTrustBundleMaterialValidator, SharedAuditAdmission,
    SharedFileAuditLedger,
};
use edge_admin_api::{
    handle_access_logs_http, handle_audit_query_http, handle_certificate_get_http,
    handle_certificate_import_http, handle_certificate_issue_http_with_http01,
    handle_certificate_list_http, handle_certificate_renew_http, handle_config_apply_http,
    handle_config_rollback_http, handle_error_logs_http, handle_metrics_http,
    handle_operational_probe_http, handle_proxy_host_create_http, handle_proxy_host_delete_http,
    handle_proxy_host_update_http, handle_stateful_http_request, handle_status_http_with_resource,
    handle_support_bundle_http, handle_trust_bundle_http, handle_upstream_health_http,
    parse_admin_http_request, render_admin_http_response, require_csrf, require_session,
    AdminAuthenticator, AdminHttpMethod, AdminHttpRequest, AdminHttpResponse,
    AdminHttpRuntimeContext, SessionStore, TrustBundleAdminService,
};
use edge_application::{
    admin_setup_audit_operation, begin_audit_operation, certificate_audit_operation,
    complete_audit_operation, config_activation_state, config_audit_operation, delete_trust_bundle,
    failure_aware_metric, import_trust_bundle, list_trust_bundles, proxy_host_audit_operation,
    record_security_observation, structured_certificate_mutation_log, structured_failure_aware_log,
    structured_manual_certificate_import_log, AccessLogEvent, AuditSecurityObservationInput,
    AuthFailureAuditSampler, CertificateIssuer, CompleteAuditOperationInput, ConfigLifecycle,
    ConfigValidator, FailureAwareEvent, FailureAwareTransition, Http01TokenStore,
    ImportTrustBundleInput, MetricSnapshotReaderPort, RecentAccessLogBuffer, RecentErrorBuffer,
    RecentErrorEvent,
};
use edge_domain::{
    AuditAction, AuditActorKind, AuditContext, AuditEffectState, AuditOperationId, AuditOutcome,
    AuditRequestId, AuditStableErrorCode, AuditTargetId, CertificateRef, ConfigSnapshot, ErrorCode,
    LogMode, OperationalLifecycle, OperationalRuntimeFacts, TrustBundleRef,
};
use edge_ports::{
    AcmeClient, AuditEvent, AuditSink, CertificateMaterialValidator, CertificateStore,
    ConfigRevisionRepository, CoreCommandClient, HealthStatusReader, Http01ChallengeProbe,
    Http01ChallengeResponder, Http01ChallengeStore, LogSink, MetricPublishOutcome, MetricPublisher,
    OperationalRuntimeStatusPublisher, OperationalRuntimeStatusReader, RetainedConfigSnapshots,
    RuntimeResourceStatusPublishOutcome, RuntimeResourceStatusPublisher,
    RuntimeResourceStatusReader, RuntimeResourceStatusSnapshot, RuntimeUpstreamStatusPublisher,
    RuntimeUpstreamStatusReader, RuntimeUpstreamStatusSnapshot, StructuredLogEvent,
    TrustBundleEventSink, TrustBundleMetadata, TrustBundleOperationEvent,
};

const DEFAULT_MAX_ADMIN_REQUEST_BYTES: usize = 512 * 1024;
const DEFAULT_RECENT_LOG_CAPACITY: usize = 100;
const DEFAULT_CERTIFICATE_RENEWAL_WINDOW_SECONDS: u64 = 30 * 24 * 60 * 60;

#[derive(Clone, Default)]
pub struct SharedOperationalRuntimeStatus(Arc<Mutex<Option<OperationalRuntimeFacts>>>);

impl OperationalRuntimeStatusPublisher for SharedOperationalRuntimeStatus {
    fn publish_operational_runtime_facts(&self, facts: OperationalRuntimeFacts) {
        if let Ok(mut current) = self.0.lock() {
            *current = Some(facts);
        }
    }
}

impl OperationalRuntimeStatusReader for SharedOperationalRuntimeStatus {
    fn read_operational_runtime_facts(
        &self,
    ) -> Result<OperationalRuntimeFacts, edge_domain::AppError> {
        self.0
            .lock()
            .map_err(|_| {
                edge_domain::AppError::new(
                    ErrorCode::InternalBug,
                    "operational runtime status lock poisoned",
                )
            })?
            .ok_or_else(|| {
                edge_domain::AppError::new(
                    ErrorCode::RuntimeHealthUnavailable,
                    "operational runtime status unavailable",
                )
            })
    }
}

#[derive(Clone, Default)]
pub struct SharedRuntimeUpstreamStatus {
    snapshot: Arc<Mutex<Option<RuntimeUpstreamStatusSnapshot>>>,
    product_log: Option<mpsc::SyncSender<edge_ports::StructuredLogEvent>>,
    metrics: Option<Arc<dyn MetricPublisher>>,
    dropped: Option<Arc<AtomicU64>>,
}

impl SharedRuntimeUpstreamStatus {
    pub fn with_observability(
        product_log: mpsc::SyncSender<edge_ports::StructuredLogEvent>,
        metrics: Arc<dyn MetricPublisher>,
        dropped: Arc<AtomicU64>,
    ) -> Self {
        Self {
            snapshot: Arc::new(Mutex::new(None)),
            product_log: Some(product_log),
            metrics: Some(metrics),
            dropped: Some(dropped),
        }
    }
}

impl RuntimeUpstreamStatusPublisher for SharedRuntimeUpstreamStatus {
    fn publish_runtime_status(&self, snapshot: RuntimeUpstreamStatusSnapshot) {
        if let Ok(mut current) = self.snapshot.try_lock() {
            if let Some(previous) = current.as_ref() {
                for item in &snapshot.upstreams {
                    let old = previous.upstreams.iter().find(|old| old.key == item.key);
                    let transition = match (old.map(|old| old.state), item.state) {
                        (
                            Some(edge_ports::RuntimeDrainState::Active),
                            edge_ports::RuntimeDrainState::Draining
                            | edge_ports::RuntimeDrainState::Drained,
                        ) => Some(FailureAwareTransition::DrainStarted),
                        (
                            Some(edge_ports::RuntimeDrainState::Draining),
                            edge_ports::RuntimeDrainState::Drained,
                        ) => Some(FailureAwareTransition::DrainCompleted),
                        _ => None,
                    };
                    if let Some(transition) = transition {
                        let event = FailureAwareEvent {
                            transition,
                            revision_id: snapshot.revision_id.clone(),
                            generation: edge_domain::HealthGeneration(snapshot.generation),
                            key: Some(item.key.clone()),
                            reason: Some("config_revision"),
                            connection_count: Some(item.connection_count),
                        };
                        let dropped = self.product_log.as_ref().is_some_and(|sender| {
                            sender
                                .try_send(structured_failure_aware_log(&event))
                                .is_err()
                        }) | self.metrics.as_ref().is_some_and(|publisher| {
                            publisher.try_publish(failure_aware_metric(&event))
                                != MetricPublishOutcome::Accepted
                        });
                        if dropped {
                            if let Some(counter) = &self.dropped {
                                counter.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
            *current = Some(snapshot);
        }
    }
}

impl RuntimeUpstreamStatusReader for SharedRuntimeUpstreamStatus {
    fn read_runtime_status(&self) -> Result<RuntimeUpstreamStatusSnapshot, edge_domain::AppError> {
        self.snapshot
            .lock()
            .map_err(|_| {
                edge_domain::AppError::new(ErrorCode::InternalBug, "runtime status lock poisoned")
            })?
            .clone()
            .ok_or_else(|| {
                edge_domain::AppError::new(
                    ErrorCode::RuntimeHealthUnavailable,
                    "runtime status unavailable",
                )
            })
    }
}

#[derive(Clone, Default)]
pub struct SharedRuntimeResourceStatus {
    snapshot: Arc<Mutex<Option<RuntimeResourceStatusSnapshot>>>,
}

impl RuntimeResourceStatusPublisher for SharedRuntimeResourceStatus {
    fn try_publish_resource_status(
        &self,
        snapshot: RuntimeResourceStatusSnapshot,
    ) -> RuntimeResourceStatusPublishOutcome {
        match self.snapshot.try_lock() {
            Ok(mut current) => {
                *current = Some(snapshot);
                RuntimeResourceStatusPublishOutcome::Accepted
            }
            Err(std::sync::TryLockError::WouldBlock) => RuntimeResourceStatusPublishOutcome::Full,
            Err(std::sync::TryLockError::Poisoned(_)) => {
                RuntimeResourceStatusPublishOutcome::Stopped
            }
        }
    }
}

impl RuntimeResourceStatusReader for SharedRuntimeResourceStatus {
    fn read_resource_status(&self) -> Result<RuntimeResourceStatusSnapshot, edge_domain::AppError> {
        self.snapshot
            .lock()
            .map_err(|_| {
                edge_domain::AppError::new(
                    ErrorCode::InternalBug,
                    "runtime resource status lock poisoned",
                )
            })?
            .clone()
            .ok_or_else(|| {
                edge_domain::AppError::new(
                    ErrorCode::RuntimeHealthUnavailable,
                    "runtime resource status unavailable",
                )
            })
    }
}

#[derive(Clone, Default)]
pub struct SharedHttp01TokenStore {
    inner: Arc<Mutex<Http01TokenStore>>,
}

impl Http01ChallengeResponder for SharedHttp01TokenStore {
    fn respond(&self, token: &str) -> Option<String> {
        self.inner.lock().ok()?.respond(token).map(str::to_string)
    }
}

impl Http01ChallengeStore for SharedHttp01TokenStore {
    fn insert_http01(
        &mut self,
        token: String,
        key_authorization: String,
    ) -> Result<(), edge_domain::AppError> {
        let mut store = self.inner.lock().map_err(|_| {
            edge_domain::AppError::new(
                edge_domain::ErrorCode::InternalBug,
                "HTTP-01 token store lock poisoned",
            )
        })?;
        store.insert(edge_application::Http01Token {
            token,
            key_authorization,
        });
        Ok(())
    }

    fn clear_http01(&mut self, token: &str) -> Result<(), edge_domain::AppError> {
        let mut store = self.inner.lock().map_err(|_| {
            edge_domain::AppError::new(
                edge_domain::ErrorCode::InternalBug,
                "HTTP-01 token store lock poisoned",
            )
        })?;
        store.clear(token);
        Ok(())
    }
}

struct SharedHttp01TokenProbe {
    store: SharedHttp01TokenStore,
}

impl Http01ChallengeProbe for SharedHttp01TokenProbe {
    fn verify_http01(
        &mut self,
        token: &str,
        expected_key_authorization: &str,
    ) -> Result<(), edge_domain::AppError> {
        if self.store.respond(token).as_deref() == Some(expected_key_authorization) {
            Ok(())
        } else {
            Err(edge_domain::AppError::new(
                edge_domain::ErrorCode::AcmeChallengeFailed,
                "HTTP-01 in-memory probe did not observe expected key authorization",
            ))
        }
    }
}

pub struct Http01RuntimeProbe {
    connect_addr: SocketAddr,
    host_header: String,
}

impl Http01RuntimeProbe {
    pub fn new(listener_addr: SocketAddr) -> Self {
        let connect_addr = if listener_addr.ip().is_unspecified() {
            SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                listener_addr.port(),
            )
        } else {
            listener_addr
        };
        Self {
            connect_addr,
            host_header: "localhost".to_string(),
        }
    }
}

impl Http01ChallengeProbe for Http01RuntimeProbe {
    fn verify_http01(
        &mut self,
        token: &str,
        expected_key_authorization: &str,
    ) -> Result<(), edge_domain::AppError> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let error = match self.verify_http01_once(token, expected_key_authorization) {
                Ok(()) => return Ok(()),
                Err(error) => error,
            };
            if Instant::now() >= deadline {
                return Err(error);
            }
            thread::sleep(Duration::from_millis(25));
        }
    }
}

impl Http01RuntimeProbe {
    fn verify_http01_once(
        &self,
        token: &str,
        expected_key_authorization: &str,
    ) -> Result<(), edge_domain::AppError> {
        let mut stream = TcpStream::connect_timeout(&self.connect_addr, Duration::from_millis(500))
            .map_err(|error| {
                edge_domain::AppError::new(
                    edge_domain::ErrorCode::AcmeChallengeFailed,
                    format!("HTTP-01 runtime probe connection failed: {error}"),
                )
            })?;
        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .map_err(|error| {
                edge_domain::AppError::new(
                    edge_domain::ErrorCode::AcmeChallengeFailed,
                    format!("HTTP-01 runtime probe setup failed: {error}"),
                )
            })?;
        stream
            .set_write_timeout(Some(Duration::from_millis(500)))
            .map_err(|error| {
                edge_domain::AppError::new(
                    edge_domain::ErrorCode::AcmeChallengeFailed,
                    format!("HTTP-01 runtime probe setup failed: {error}"),
                )
            })?;
        let request = format!(
            "GET /.well-known/acme-challenge/{token} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            self.host_header
        );
        stream.write_all(request.as_bytes()).map_err(|error| {
            edge_domain::AppError::new(
                edge_domain::ErrorCode::AcmeChallengeFailed,
                format!("HTTP-01 runtime probe request failed: {error}"),
            )
        })?;
        let mut response = String::new();
        stream.read_to_string(&mut response).map_err(|error| {
            edge_domain::AppError::new(
                edge_domain::ErrorCode::AcmeChallengeFailed,
                format!("HTTP-01 runtime probe response failed: {error}"),
            )
        })?;
        if response.contains("HTTP/1.1 200 OK") && response.ends_with(expected_key_authorization) {
            Ok(())
        } else {
            Err(edge_domain::AppError::new(
                edge_domain::ErrorCode::AcmeChallengeFailed,
                "HTTP-01 runtime probe did not observe expected key authorization",
            ))
        }
    }
}

#[derive(Clone)]
pub struct AdminHttpServerState {
    snapshot: Arc<Mutex<ConfigSnapshot>>,
    active_snapshot: Arc<Mutex<ConfigSnapshot>>,
    sessions: Arc<Mutex<SessionStore>>,
    authenticator: Arc<Mutex<Option<AdminAuthenticator>>>,
    secrets: Arc<Mutex<FileSecretStore>>,
    acme: Arc<Mutex<Box<dyn AcmeClient + Send>>>,
    certificates: Arc<Mutex<Box<dyn CertificateStore + Send>>>,
    certificate_validator: Arc<Mutex<Box<dyn CertificateMaterialValidator + Send>>>,
    certificate_audit: Arc<Mutex<NoopLegacyAuditSink>>,
    product_log: Arc<Mutex<Box<dyn LogSink + Send>>>,
    access_logs: Arc<Mutex<RecentAccessLogBuffer>>,
    error_logs: Arc<Mutex<RecentErrorBuffer>>,
    log_drop_counter: Arc<AtomicU64>,
    http01_tokens: SharedHttp01TokenStore,
    http01_probe: Arc<Mutex<Box<dyn Http01ChallengeProbe + Send>>>,
    health_status: Arc<dyn HealthStatusReader>,
    runtime_status: Arc<dyn RuntimeUpstreamStatusReader>,
    resource_status: Arc<dyn RuntimeResourceStatusReader>,
    metrics: Arc<dyn MetricSnapshotReaderPort>,
    operational_lifecycle: Arc<Mutex<OperationalLifecycle>>,
    operational_runtime_status: Arc<dyn OperationalRuntimeStatusReader>,
    mutation: Option<Arc<Mutex<AdminMutationState>>>,
    trust_bundles: Option<Arc<Mutex<TrustBundleRuntimeService>>>,
    durable_audit: Option<(SharedFileAuditLedger, SharedAuditAdmission)>,
    auth_failure_audit_sampler: Arc<Mutex<AuthFailureAuditSampler>>,
    max_request_bytes: usize,
    certificate_renewal_window_seconds: u64,
    support_bundle_paths: Option<AdminHttpSupportBundlePaths>,
}

struct UnavailableHealthStatusReader;

impl HealthStatusReader for UnavailableHealthStatusReader {
    fn read_health_status(
        &self,
    ) -> Result<edge_domain::HealthAvailabilitySnapshot, edge_domain::AppError> {
        Err(edge_domain::AppError::new(
            ErrorCode::RuntimeHealthUnavailable,
            "health status reader is not wired",
        ))
    }
}

struct UnavailableRuntimeStatusReader;

impl RuntimeUpstreamStatusReader for UnavailableRuntimeStatusReader {
    fn read_runtime_status(&self) -> Result<RuntimeUpstreamStatusSnapshot, edge_domain::AppError> {
        Err(edge_domain::AppError::new(
            ErrorCode::RuntimeHealthUnavailable,
            "runtime status reader is not wired",
        ))
    }
}

struct UnavailableMetricSnapshotReader;

struct UnavailableResourceStatusReader;

impl RuntimeResourceStatusReader for UnavailableResourceStatusReader {
    fn read_resource_status(&self) -> Result<RuntimeResourceStatusSnapshot, edge_domain::AppError> {
        Err(edge_domain::AppError::new(
            ErrorCode::RuntimeHealthUnavailable,
            "runtime resource status reader is not wired",
        ))
    }
}

impl MetricSnapshotReaderPort for UnavailableMetricSnapshotReader {
    fn read_metric_snapshot(
        &self,
    ) -> Result<Arc<edge_application::MetricSnapshot>, edge_domain::AppError> {
        Err(edge_domain::AppError::new(
            ErrorCode::InternalBug,
            "metric snapshot reader is not wired",
        ))
    }
}

struct AdminMutationState {
    lifecycle: ConfigLifecycle<FileRevisionRepository, NoopLegacyAuditSink>,
    command_client: Box<dyn CoreCommandClient + Send>,
}

#[derive(Debug, Clone, Copy, Default)]
struct NoopLegacyAuditSink;

impl AuditSink for NoopLegacyAuditSink {
    fn record(&mut self, _event: AuditEvent) -> Result<(), edge_domain::AppError> {
        Ok(())
    }
}

struct RetainedRevisionSnapshots(FileRevisionRepository);

impl RetainedConfigSnapshots for RetainedRevisionSnapshots {
    fn retained_config_snapshots(&self) -> Result<Vec<ConfigSnapshot>, edge_domain::AppError> {
        Ok(self
            .0
            .history()?
            .into_iter()
            .map(|record| record.snapshot)
            .collect())
    }
}

struct TrustBundleRuntimeEvents {
    product_log: Arc<Mutex<Box<dyn LogSink + Send>>>,
    audit: NoopLegacyAuditSink,
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

struct TrustBundleRuntimeService {
    validator: RustlsTrustBundleMaterialValidator,
    store: FileTrustBundleStore,
    revisions: RetainedRevisionSnapshots,
    events: TrustBundleRuntimeEvents,
    durable_audit: Option<(SharedFileAuditLedger, SharedAuditAdmission)>,
}

impl TrustBundleAdminService for TrustBundleRuntimeService {
    fn import(
        &mut self,
        request_id: &str,
        trust_bundle_ref: TrustBundleRef,
        encoded_material: Vec<u8>,
    ) -> Result<TrustBundleMetadata, edge_domain::AppError> {
        let imported_at_epoch_seconds = current_epoch_seconds().map_err(|_| {
            edge_domain::AppError::new(ErrorCode::InternalBug, "system clock is unavailable")
        })?;
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

    fn list(&mut self) -> Result<Vec<TrustBundleMetadata>, edge_domain::AppError> {
        list_trust_bundles(&mut self.store)
    }

    fn delete(&mut self, trust_bundle_ref: TrustBundleRef) -> Result<(), edge_domain::AppError> {
        let timestamp = current_epoch_seconds().map_err(|_| {
            edge_domain::AppError::new(ErrorCode::InternalBug, "system clock is unavailable")
        })?;
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
) -> Result<Option<edge_application::AuditPersistentOperationInput>, edge_domain::AppError> {
    if audit.is_none() {
        return Ok(None);
    }
    let context = AuditContext {
        operation_id: AuditOperationId::parse(format!("operation-{request_id}")).map_err(|_| {
            edge_domain::AppError::new(
                ErrorCode::AuditRecordInvalid,
                "invalid trust audit operation id",
            )
        })?,
        request_id: AuditRequestId::parse(request_id).map_err(|_| {
            edge_domain::AppError::new(
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
            edge_domain::AppError::new(
                ErrorCode::AuditRecordInvalid,
                "invalid trust bundle audit target",
            )
        })?,
    )
    .map(Some)
}

fn begin_optional_audit(
    audit: Option<&(SharedFileAuditLedger, SharedAuditAdmission)>,
    operation: Option<&edge_application::AuditPersistentOperationInput>,
) -> Result<Option<edge_application::BeginAuditOperationOutput>, edge_domain::AppError> {
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
    operation: Option<edge_application::AuditPersistentOperationInput>,
    begin: Option<edge_application::BeginAuditOperationOutput>,
    effect: Result<T, edge_domain::AppError>,
) -> Result<T, edge_domain::AppError> {
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
        Err(failure) => Err(edge_domain::AppError::new(
            failure.error.code,
            if effect_state == AuditEffectState::Committed {
                "trust mutation committed but audit terminal persistence failed"
            } else {
                "trust mutation failed and audit terminal persistence also failed"
            },
        )),
    }
}

pub struct AdminLogReceivers {
    pub access: mpsc::Receiver<AccessLogEvent>,
    pub error: mpsc::Receiver<RecentErrorEvent>,
    pub dropped: Arc<AtomicU64>,
}

pub struct AdminHttpStores {
    pub secrets: FileSecretStore,
    pub revisions: FileRevisionRepository,
    pub certificates: FileCertificateStore,
    pub trust_bundles: FileTrustBundleStore,
}

pub struct AdminHttpChallengeRuntime<P> {
    pub tokens: SharedHttp01TokenStore,
    pub probe: P,
}

pub struct AdminHttpRuntimeWiring<C, A, P> {
    pub acme_client: A,
    pub challenge_runtime: AdminHttpChallengeRuntime<P>,
    pub command_client: C,
    pub health_status_reader: Arc<dyn HealthStatusReader>,
    pub runtime_status_reader: Arc<dyn RuntimeUpstreamStatusReader>,
    pub resource_status_reader: Arc<dyn RuntimeResourceStatusReader>,
    pub metrics_reader: Arc<dyn MetricSnapshotReaderPort>,
    pub operational_lifecycle: Arc<Mutex<OperationalLifecycle>>,
    pub operational_runtime_status_reader: Arc<dyn OperationalRuntimeStatusReader>,
    pub product_log: Box<dyn LogSink + Send>,
    pub log_receivers: AdminLogReceivers,
    pub audit_ledger: SharedFileAuditLedger,
    pub support_bundle_paths: AdminHttpSupportBundlePaths,
}

#[derive(Clone)]
pub struct AdminHttpSupportBundlePaths {
    pub source_root: PathBuf,
    pub output: PathBuf,
}

impl AdminHttpServerState {
    pub fn new(
        snapshot: ConfigSnapshot,
        admin_password_hash: Option<String>,
        secrets: FileSecretStore,
    ) -> Self {
        let http01_tokens = SharedHttp01TokenStore::default();
        let active_snapshot = snapshot.clone();
        Self {
            snapshot: Arc::new(Mutex::new(snapshot)),
            active_snapshot: Arc::new(Mutex::new(active_snapshot)),
            sessions: Arc::new(Mutex::new(SessionStore::default())),
            authenticator: Arc::new(Mutex::new(admin_password_hash.map(AdminAuthenticator::new))),
            secrets: Arc::new(Mutex::new(secrets)),
            acme: Arc::new(Mutex::new(Box::new(FakeAcmeClient::default()))),
            certificates: Arc::new(Mutex::new(Box::new(MemoryCertificateStore::default()))),
            certificate_validator: Arc::new(Mutex::new(Box::new(
                RustlsCertificateMaterialValidator,
            ))),
            certificate_audit: Arc::new(Mutex::new(NoopLegacyAuditSink)),
            product_log: Arc::new(Mutex::new(Box::new(MemoryLogSink::default()))),
            access_logs: Arc::new(Mutex::new(RecentAccessLogBuffer::new(
                DEFAULT_RECENT_LOG_CAPACITY,
            ))),
            error_logs: Arc::new(Mutex::new(RecentErrorBuffer::new(
                DEFAULT_RECENT_LOG_CAPACITY,
            ))),
            log_drop_counter: Arc::new(AtomicU64::new(0)),
            http01_probe: Arc::new(Mutex::new(Box::new(SharedHttp01TokenProbe {
                store: http01_tokens.clone(),
            }))),
            http01_tokens,
            health_status: Arc::new(UnavailableHealthStatusReader),
            runtime_status: Arc::new(UnavailableRuntimeStatusReader),
            resource_status: Arc::new(UnavailableResourceStatusReader),
            metrics: Arc::new(UnavailableMetricSnapshotReader),
            operational_lifecycle: Arc::new(Mutex::new(OperationalLifecycle::Starting)),
            operational_runtime_status: Arc::new(SharedOperationalRuntimeStatus::default()),
            mutation: None,
            trust_bundles: None,
            durable_audit: None,
            auth_failure_audit_sampler: Arc::new(Mutex::new(AuthFailureAuditSampler::default())),
            max_request_bytes: DEFAULT_MAX_ADMIN_REQUEST_BYTES,
            certificate_renewal_window_seconds: DEFAULT_CERTIFICATE_RENEWAL_WINDOW_SECONDS,
            support_bundle_paths: None,
        }
    }

    pub fn with_support_bundle_paths(mut self, paths: AdminHttpSupportBundlePaths) -> Self {
        self.support_bundle_paths = Some(paths);
        self
    }

    pub fn with_mutations<C>(mut self, revisions: FileRevisionRepository, command_client: C) -> Self
    where
        C: CoreCommandClient + Send + 'static,
    {
        self.mutation = Some(Arc::new(Mutex::new(AdminMutationState {
            lifecycle: ConfigLifecycle {
                revisions,
                audit: NoopLegacyAuditSink,
                validator: ConfigValidator::default(),
            },
            command_client: Box::new(command_client),
        })));
        self
    }

    pub fn with_trust_bundles(
        mut self,
        store: FileTrustBundleStore,
        revisions: FileRevisionRepository,
    ) -> Self {
        self.trust_bundles = Some(Arc::new(Mutex::new(TrustBundleRuntimeService {
            validator: RustlsTrustBundleMaterialValidator,
            store,
            revisions: RetainedRevisionSnapshots(revisions),
            events: TrustBundleRuntimeEvents {
                product_log: Arc::clone(&self.product_log),
                audit: NoopLegacyAuditSink,
            },
            durable_audit: self.durable_audit.clone(),
        })));
        self
    }

    pub fn with_durable_audit(mut self, ledger: SharedFileAuditLedger) -> Self {
        self.durable_audit = Some((ledger.clone(), ledger.admission()));
        self
    }

    pub fn with_access_log_receiver(self, receiver: mpsc::Receiver<AccessLogEvent>) -> Self {
        spawn_access_log_collector(Arc::clone(&self.access_logs), receiver);
        self
    }

    pub fn with_error_log_receiver(self, receiver: mpsc::Receiver<RecentErrorEvent>) -> Self {
        spawn_error_log_collector(Arc::clone(&self.error_logs), receiver);
        self
    }

    pub fn with_log_drop_counter(mut self, counter: Arc<AtomicU64>) -> Self {
        self.log_drop_counter = counter;
        self
    }

    pub fn with_certificate_store<S>(mut self, certificates: S) -> Self
    where
        S: CertificateStore + Send + 'static,
    {
        self.certificates = Arc::new(Mutex::new(Box::new(certificates)));
        self
    }

    pub fn with_certificate_validator<V>(mut self, validator: V) -> Self
    where
        V: CertificateMaterialValidator + Send + 'static,
    {
        self.certificate_validator = Arc::new(Mutex::new(Box::new(validator)));
        self
    }

    pub fn with_acme_client<C>(mut self, acme: C) -> Self
    where
        C: AcmeClient + Send + 'static,
    {
        self.acme = Arc::new(Mutex::new(Box::new(acme)));
        self
    }

    pub fn with_http01_probe<P>(mut self, probe: P) -> Self
    where
        P: Http01ChallengeProbe + Send + 'static,
    {
        self.http01_probe = Arc::new(Mutex::new(Box::new(probe)));
        self
    }

    pub fn with_http01_tokens(mut self, tokens: SharedHttp01TokenStore) -> Self {
        self.http01_probe = Arc::new(Mutex::new(Box::new(SharedHttp01TokenProbe {
            store: tokens.clone(),
        })));
        self.http01_tokens = tokens;
        self
    }

    pub fn with_product_log_sink(mut self, sink: Box<dyn LogSink + Send>) -> Self {
        self.product_log = Arc::new(Mutex::new(sink));
        self
    }

    pub fn with_health_status_reader<H>(mut self, reader: H) -> Self
    where
        H: HealthStatusReader + 'static,
    {
        self.health_status = Arc::new(reader);
        self
    }

    pub fn with_runtime_status_reader(
        mut self,
        reader: Arc<dyn RuntimeUpstreamStatusReader>,
    ) -> Self {
        self.runtime_status = reader;
        self
    }

    pub fn with_resource_status_reader(
        mut self,
        reader: Arc<dyn RuntimeResourceStatusReader>,
    ) -> Self {
        self.resource_status = reader;
        self
    }

    pub fn with_metrics_reader(mut self, reader: Arc<dyn MetricSnapshotReaderPort>) -> Self {
        self.metrics = reader;
        self
    }

    pub fn with_operational_lifecycle(
        mut self,
        lifecycle: Arc<Mutex<OperationalLifecycle>>,
    ) -> Self {
        self.operational_lifecycle = lifecycle;
        self
    }

    pub fn with_operational_runtime_status_reader(
        mut self,
        reader: Arc<dyn OperationalRuntimeStatusReader>,
    ) -> Self {
        self.operational_runtime_status = reader;
        self
    }

    #[cfg(test)]
    fn with_observability(
        mut self,
        certificates: MemoryCertificateStore,
        access_logs: RecentAccessLogBuffer,
        error_logs: RecentErrorBuffer,
    ) -> Self {
        self.certificates = Arc::new(Mutex::new(Box::new(certificates)));
        self.access_logs = Arc::new(Mutex::new(access_logs));
        self.error_logs = Arc::new(Mutex::new(error_logs));
        self
    }
}

pub fn spawn_admin_http_server_with_mutations_and_logs<C, A, P>(
    bind: &str,
    snapshot: ConfigSnapshot,
    admin_password_hash: Option<String>,
    stores: AdminHttpStores,
    runtime: AdminHttpRuntimeWiring<C, A, P>,
) -> io::Result<JoinHandle<()>>
where
    C: CoreCommandClient + Send + 'static,
    A: AcmeClient + Send + 'static,
    P: Http01ChallengeProbe + Send + 'static,
{
    let listener = TcpListener::bind(bind)?;
    let trust_revisions = stores.revisions.clone();
    let state = AdminHttpServerState::new(snapshot, admin_password_hash, stores.secrets)
        .with_acme_client(runtime.acme_client)
        .with_certificate_store(stores.certificates)
        .with_certificate_validator(RustlsCertificateMaterialValidator)
        .with_http01_tokens(runtime.challenge_runtime.tokens)
        .with_http01_probe(runtime.challenge_runtime.probe)
        .with_health_status_reader(runtime.health_status_reader)
        .with_runtime_status_reader(runtime.runtime_status_reader)
        .with_resource_status_reader(runtime.resource_status_reader)
        .with_metrics_reader(runtime.metrics_reader)
        .with_operational_lifecycle(runtime.operational_lifecycle)
        .with_operational_runtime_status_reader(runtime.operational_runtime_status_reader)
        .with_product_log_sink(runtime.product_log)
        .with_durable_audit(runtime.audit_ledger)
        .with_trust_bundles(stores.trust_bundles, trust_revisions)
        .with_mutations(stores.revisions, runtime.command_client)
        .with_access_log_receiver(runtime.log_receivers.access)
        .with_error_log_receiver(runtime.log_receivers.error)
        .with_log_drop_counter(runtime.log_receivers.dropped)
        .with_support_bundle_paths(runtime.support_bundle_paths);
    Ok(thread::spawn(move || loop {
        if let Err(error) = serve_next_admin_http_connection(&listener, &state) {
            if error.kind() == io::ErrorKind::WouldBlock {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            eprintln!("admin http connection error: {error}");
        }
    }))
}

fn spawn_access_log_collector(
    access_logs: Arc<Mutex<RecentAccessLogBuffer>>,
    receiver: mpsc::Receiver<AccessLogEvent>,
) {
    thread::spawn(move || {
        while let Ok(event) = receiver.recv() {
            let Ok(mut access_logs) = access_logs.lock() else {
                break;
            };
            access_logs.push(event);
        }
    });
}

fn spawn_error_log_collector(
    error_logs: Arc<Mutex<RecentErrorBuffer>>,
    receiver: mpsc::Receiver<RecentErrorEvent>,
) {
    thread::spawn(move || {
        while let Ok(event) = receiver.recv() {
            let Ok(mut error_logs) = error_logs.lock() else {
                break;
            };
            error_logs.push(event);
        }
    });
}

pub fn serve_next_admin_http_connection(
    listener: &TcpListener,
    state: &AdminHttpServerState,
) -> io::Result<()> {
    let (stream, _) = listener.accept()?;
    handle_admin_http_stream(stream, state)
}

fn handle_admin_http_stream(mut stream: TcpStream, state: &AdminHttpServerState) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let raw = read_admin_http_request(&mut stream, state.max_request_bytes)?;
    if raw.is_empty() {
        return Ok(());
    }
    let request = parse_admin_http_request(&raw, "admin-http").map_err(app_error_to_io)?;
    if let Some(response) = handle_static_admin_asset(&request) {
        let rendered = render_admin_http_response(&response);
        stream.write_all(rendered.as_bytes())?;
        return stream.flush();
    }
    if request.method == AdminHttpMethod::Get && request.path == "/api/v1/status" {
        let desired = state
            .snapshot
            .lock()
            .map_err(|_| io::Error::other("admin snapshot lock poisoned"))?
            .clone();
        let active = state
            .active_snapshot
            .lock()
            .map_err(|_| io::Error::other("admin active snapshot lock poisoned"))?
            .clone();
        let live_resource_status = state.resource_status.read_resource_status().ok();
        let rendered = render_admin_http_response(&handle_status_http_with_resource(
            &desired,
            &active,
            live_resource_status,
        ));
        stream.write_all(rendered.as_bytes())?;
        return stream.flush();
    }
    if request.method == AdminHttpMethod::Get
        && matches!(
            request.path.as_str(),
            "/api/v1/health/live" | "/api/v1/health/ready"
        )
    {
        let lifecycle = *state
            .operational_lifecycle
            .lock()
            .map_err(|_| io::Error::other("operational lifecycle lock poisoned"))?;
        let facts = state
            .operational_runtime_status
            .read_operational_runtime_facts()
            .unwrap_or_default();
        let response = handle_operational_probe_http(
            &request,
            lifecycle,
            facts.has_active_snapshot,
            facts.has_listener,
            facts.has_command_path,
        );
        let rendered = render_admin_http_response(&response);
        stream.write_all(rendered.as_bytes())?;
        return stream.flush();
    }
    let sessions = state
        .sessions
        .lock()
        .map_err(|_| io::Error::other("admin session store lock poisoned"))?;
    let mut sessions = sessions;
    let authenticator = state
        .authenticator
        .lock()
        .map_err(|_| io::Error::other("admin authenticator lock poisoned"))?;
    let mut authenticator = authenticator;

    if request.method == AdminHttpMethod::Post && request.path == "/api/v1/support-bundles" {
        let response = match &state.support_bundle_paths {
            Some(paths) => handle_support_bundle_http(
                &request,
                &sessions,
                FileSupportBundleCollector::new_online(&paths.source_root, &paths.output),
            ),
            None => AdminHttpResponse::from_error(
                503,
                edge_domain::AppError::new(
                    ErrorCode::RuntimeHealthUnavailable,
                    "support bundle collector is not configured",
                ),
                &request.request_id,
            ),
        };
        let rendered = render_admin_http_response(&response);
        stream.write_all(rendered.as_bytes())?;
        return stream.flush();
    }

    if request.method == AdminHttpMethod::Get && request.path == "/api/v1/upstream-health" {
        let response = handle_upstream_health_http(
            &request,
            &sessions,
            state.health_status.as_ref(),
            Some(state.runtime_status.as_ref()),
        );
        let rendered = render_admin_http_response(&response);
        stream.write_all(rendered.as_bytes())?;
        return stream.flush();
    }

    if request.method == AdminHttpMethod::Get && request.path.starts_with("/api/v1/metrics") {
        let response = handle_metrics_http(&request, &sessions, state.metrics.as_ref());
        let rendered = render_admin_http_response(&response);
        stream.write_all(rendered.as_bytes())?;
        return stream.flush();
    }

    if request.method == AdminHttpMethod::Get
        && (request.path == "/api/v1/audit" || request.path.starts_with("/api/v1/audit?"))
    {
        let response = match &state.durable_audit {
            Some((ledger, _)) => handle_audit_query_http(&request, &sessions, ledger),
            None => AdminHttpResponse::from_error(
                503,
                edge_domain::AppError::new(
                    ErrorCode::AuditUnavailable,
                    "audit ledger is unavailable",
                ),
                &request.request_id,
            ),
        };
        let rendered = render_admin_http_response(&response);
        stream.write_all(rendered.as_bytes())?;
        return stream.flush();
    }

    if is_trust_bundle_request(&request) {
        if let Some(service) = &state.trust_bundles {
            let mut service = service
                .lock()
                .map_err(|_| io::Error::other("admin trust bundle service lock poisoned"))?;
            let response = handle_trust_bundle_http(&request, &sessions, &mut *service);
            let rendered = render_admin_http_response(&response);
            stream.write_all(rendered.as_bytes())?;
            return stream.flush();
        }
    }

    if is_observability_request(&request) {
        let certificates = state
            .certificates
            .lock()
            .map_err(|_| io::Error::other("admin certificate store lock poisoned"))?;
        let access_logs = state
            .access_logs
            .lock()
            .map_err(|_| io::Error::other("admin access log buffer lock poisoned"))?
            .recent();
        let mut error_logs = state
            .error_logs
            .lock()
            .map_err(|_| io::Error::other("admin error log buffer lock poisoned"))?
            .recent();
        let log_mode = state
            .snapshot
            .lock()
            .map_err(|_| io::Error::other("admin snapshot lock poisoned"))?
            .log_mode
            .clone();
        append_log_drop_event(
            &mut error_logs,
            &log_mode,
            state.log_drop_counter.load(Ordering::Relaxed),
        );
        let response = handle_observability_request(
            &request,
            &sessions,
            certificates.as_ref(),
            &access_logs,
            &error_logs,
            current_epoch_seconds()?,
            state.certificate_renewal_window_seconds,
        );
        let rendered = render_admin_http_response(&response);
        stream.write_all(rendered.as_bytes())?;
        return stream.flush();
    }

    if is_bound_certificate_mutation_request(&request) && authenticator.is_some() {
        if let Some(mutation) = &state.mutation {
            let acme = state
                .acme
                .lock()
                .map_err(|_| io::Error::other("admin acme client lock poisoned"))?;
            let certificates = state
                .certificates
                .lock()
                .map_err(|_| io::Error::other("admin certificate store lock poisoned"))?;
            let certificate_validator = state
                .certificate_validator
                .lock()
                .map_err(|_| io::Error::other("admin certificate validator lock poisoned"))?;
            let audit = state
                .certificate_audit
                .lock()
                .map_err(|_| io::Error::other("admin certificate audit lock poisoned"))?;
            let http01_probe = state
                .http01_probe
                .lock()
                .map_err(|_| io::Error::other("admin HTTP-01 probe lock poisoned"))?;
            let mutation = mutation
                .lock()
                .map_err(|_| io::Error::other("admin mutation state lock poisoned"))?;
            let mut acme = acme;
            let mut certificates = certificates;
            let mut certificate_validator = certificate_validator;
            let mut audit = audit;
            let mut http01_tokens = state.http01_tokens.clone();
            let mut http01_probe = http01_probe;
            let mut mutation = mutation;
            let mut issuer = CertificateIssuer {
                acme: &mut **acme,
                store: &mut **certificates,
                audit: &mut *audit,
            };
            let revision_id = state
                .snapshot
                .lock()
                .map_err(|_| io::Error::other("admin snapshot lock poisoned"))?
                .revision_id
                .clone();
            let mut durable_certificate = if let Some((ledger, admission)) = &state.durable_audit {
                let session_id = request.session_id.as_deref().unwrap_or_default();
                if require_session(&sessions, request.session_id.as_deref()).is_ok()
                    && require_csrf(&sessions, session_id, request.csrf_token.as_deref()).is_ok()
                {
                    let action = if request.path.ends_with("/renew") {
                        AuditAction::CertificateRenew
                    } else if request.path.ends_with("/import") {
                        AuditAction::CertificateImport
                    } else {
                        AuditAction::CertificateIssue
                    };
                    let operation = match certificate_audit_operation(
                        admin_audit_context(&request).map_err(app_error_to_io)?,
                        action,
                        AuditTargetId::parse(
                            certificate_ref_from_mutation_path(&request.path).as_str(),
                        )
                        .map_err(|_| io::Error::other("certificate audit target is invalid"))?,
                    ) {
                        Ok(operation) => operation,
                        Err(error) => {
                            let response = audit_failure_response(&request, 400, &error, false);
                            let rendered = render_admin_http_response(&response);
                            stream.write_all(rendered.as_bytes())?;
                            return stream.flush();
                        }
                    };
                    let mut ledger = ledger.clone();
                    let admission = admission.clone();
                    let begin =
                        match begin_audit_operation(&mut ledger, &admission, operation.clone()) {
                            Ok(begin) => begin,
                            Err(failure) => {
                                let response =
                                    audit_failure_response(&request, 503, &failure.error, false);
                                let rendered = render_admin_http_response(&response);
                                stream.write_all(rendered.as_bytes())?;
                                return stream.flush();
                            }
                        };
                    Some((ledger, admission, operation, begin))
                } else {
                    None
                }
            } else {
                None
            };
            let response = if request.path.ends_with("/import") {
                handle_certificate_import_http(
                    &request,
                    &sessions,
                    &revision_id,
                    &mut **certificate_validator,
                    &mut issuer.store,
                    &mut issuer.audit,
                    &mut *mutation.command_client,
                )
            } else {
                handle_bound_certificate_mutation_request(
                    &request,
                    &sessions,
                    &mut issuer,
                    &mut http01_tokens,
                    &mut **http01_probe,
                    &mut *mutation.command_client,
                )
            };
            let response =
                if let Some((ledger, admission, operation, begin)) = durable_certificate.as_mut() {
                    complete_audited_admin_response(
                        &request,
                        response,
                        ledger,
                        admission,
                        operation.clone(),
                        begin.head,
                    )
                } else {
                    response
                };
            record_certificate_mutation_product_log(state, &request, &response)?;
            record_runtime_command_failure(state, &request, &response)?;
            let rendered = render_admin_http_response(&response);
            stream.write_all(rendered.as_bytes())?;
            return stream.flush();
        }
    }

    if is_bound_lifecycle_request(&request) && authenticator.is_some() {
        if let Some(mutation) = &state.mutation {
            let mutation = mutation
                .lock()
                .map_err(|_| io::Error::other("admin mutation state lock poisoned"))?;
            let mut mutation = mutation;
            let AdminMutationState {
                lifecycle,
                command_client,
            } = &mut *mutation;
            let response = if let Some((ledger, admission)) = &state.durable_audit {
                let mut ledger = ledger.clone();
                let mut admission = admission.clone();
                handle_audited_lifecycle_request(
                    &request,
                    &sessions,
                    lifecycle,
                    &mut **command_client,
                    &mut ledger,
                    &mut admission,
                    &state
                        .snapshot
                        .lock()
                        .map_err(|_| io::Error::other("admin snapshot lock poisoned"))?
                        .revision_id,
                )
            } else {
                handle_bound_lifecycle_request(
                    &request,
                    &sessions,
                    lifecycle,
                    &mut **command_client,
                )
            };
            if response.status_code == 200 {
                refresh_admin_snapshot(state, &mut lifecycle.revisions)?;
            }
            record_runtime_command_failure(state, &request, &response)?;
            let rendered = render_admin_http_response(&response);
            stream.write_all(rendered.as_bytes())?;
            return stream.flush();
        }
    }

    let secrets = state
        .secrets
        .lock()
        .map_err(|_| io::Error::other("admin secret store lock poisoned"))?;
    let mut secrets = secrets;
    let snapshot = state
        .snapshot
        .lock()
        .map_err(|_| io::Error::other("admin snapshot lock poisoned"))?
        .clone();
    let mut setup_audit = if request.method == AdminHttpMethod::Post
        && request.path == "/api/v1/setup"
    {
        if let Some((ledger, admission)) = &state.durable_audit {
            let operation = admin_setup_audit_operation(
                admin_audit_context(&request).map_err(app_error_to_io)?,
                AuditTargetId::parse("bootstrap-admin")
                    .map_err(|_| io::Error::other("admin setup audit target is invalid"))?,
            );
            let mut ledger = ledger.clone();
            let admission = admission.clone();
            let begin = match begin_audit_operation(&mut ledger, &admission, operation.clone()) {
                Ok(begin) => begin,
                Err(failure) => {
                    let response = audit_failure_response(&request, 503, &failure.error, false);
                    let rendered = render_admin_http_response(&response);
                    stream.write_all(rendered.as_bytes())?;
                    return stream.flush();
                }
            };
            Some((ledger, admission, operation, begin))
        } else {
            None
        }
    } else {
        None
    };
    let response = handle_stateful_http_request(
        &request,
        AdminHttpRuntimeContext {
            snapshot: &snapshot,
            sessions: &mut sessions,
            authenticator: &mut authenticator,
            secrets: &mut *secrets,
        },
    );
    let response = if let Some((ledger, admission, operation, begin)) = setup_audit.as_mut() {
        complete_audited_admin_response(
            &request,
            response,
            ledger,
            admission,
            operation.clone(),
            begin.head,
        )
    } else {
        response
    };
    record_auth_observation(state, &request, &response)?;
    let rendered = render_admin_http_response(&response);
    stream.write_all(rendered.as_bytes())?;
    stream.flush()
}

fn handle_static_admin_asset(request: &AdminHttpRequest) -> Option<AdminHttpResponse> {
    if request.method != AdminHttpMethod::Get {
        return None;
    }
    let path = request
        .path
        .split('?')
        .next()
        .unwrap_or(request.path.as_str());
    let (content_type, body) = match path {
        "/" | "/index.html" => (
            "text/html; charset=utf-8",
            include_str!("../../admin-web/index.html"),
        ),
        "/styles.css" => (
            "text/css; charset=utf-8",
            include_str!("../../admin-web/styles.css"),
        ),
        "/app.js" => (
            "application/javascript; charset=utf-8",
            include_str!("../../admin-web/app.js"),
        ),
        _ => return None,
    };
    Some(AdminHttpResponse {
        status_code: 200,
        headers: vec![("content-type".to_string(), content_type.to_string())],
        body: body.to_string(),
        error_code: None,
    })
}

fn is_bound_lifecycle_request(request: &AdminHttpRequest) -> bool {
    matches!(
        (request.method, request.path.as_str()),
        (AdminHttpMethod::Post, "/api/v1/proxy-hosts")
            | (AdminHttpMethod::Post, "/api/v1/config/apply")
            | (AdminHttpMethod::Post, "/api/v1/config/rollback")
    ) || (request.method == AdminHttpMethod::Delete
        && request.path.starts_with("/api/v1/proxy-hosts/"))
        || (request.method == AdminHttpMethod::Patch
            && request.path.starts_with("/api/v1/proxy-hosts/"))
}

fn record_runtime_command_failure(
    state: &AdminHttpServerState,
    request: &AdminHttpRequest,
    response: &AdminHttpResponse,
) -> io::Result<()> {
    if response.error_code.as_deref() != Some(ErrorCode::RuntimeCommandRejected.as_str()) {
        return Ok(());
    }
    let mut error_logs = state
        .error_logs
        .lock()
        .map_err(|_| io::Error::other("admin error log buffer lock poisoned"))?;
    error_logs.push(RecentErrorEvent {
        request_id: Some(request.request_id.clone()),
        error_code: ErrorCode::RuntimeCommandRejected.as_str().to_string(),
        message: ErrorCode::RuntimeCommandRejected
            .default_user_message()
            .to_string(),
    });
    Ok(())
}

fn record_certificate_mutation_product_log(
    state: &AdminHttpServerState,
    request: &AdminHttpRequest,
    response: &AdminHttpResponse,
) -> io::Result<()> {
    let revision_id = state
        .snapshot
        .lock()
        .map_err(|_| io::Error::other("admin snapshot lock poisoned"))?
        .revision_id
        .clone();
    let certificate_ref = certificate_ref_from_mutation_path(&request.path);
    let success = response.status_code < 400 && response.error_code.is_none();
    let event = if request.path.ends_with("/import") {
        structured_manual_certificate_import_log(
            success,
            &request.request_id,
            &revision_id,
            &certificate_ref,
            response.error_code.as_deref(),
        )
    } else {
        structured_certificate_mutation_log(
            certificate_mutation_operation(&request.path),
            success,
            &request.request_id,
            &revision_id,
            &certificate_ref,
            response.status_code,
            response.error_code.as_deref(),
        )
    };
    state
        .product_log
        .lock()
        .map_err(|_| io::Error::other("admin product log sink lock poisoned"))?
        .record_log(event)
        .map_err(app_error_to_io)
}

fn certificate_mutation_operation(path: &str) -> &'static str {
    if path.ends_with("/renew") {
        "certificate.renew"
    } else if path.ends_with("/import") {
        "certificate.import"
    } else {
        "certificate.issue"
    }
}

fn certificate_ref_from_mutation_path(path: &str) -> CertificateRef {
    let suffix = if path.ends_with("/renew") {
        "/renew"
    } else if path.ends_with("/import") {
        "/import"
    } else {
        "/issue"
    };
    let raw = path
        .strip_prefix("/api/v1/certificates/")
        .and_then(|value| value.strip_suffix(suffix))
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown");
    CertificateRef::new(raw)
}

fn append_log_drop_event(events: &mut Vec<RecentErrorEvent>, log_mode: &LogMode, dropped: u64) {
    if dropped == 0 || matches!(log_mode, LogMode::Product) {
        return;
    }
    events.push(RecentErrorEvent {
        request_id: None,
        error_code: "RUNTIME_LOG_QUEUE_FULL".to_string(),
        message: format!("dropped {dropped} runtime log events because bounded log queue was full"),
    });
}

fn is_bound_certificate_mutation_request(request: &AdminHttpRequest) -> bool {
    request.method == AdminHttpMethod::Post
        && request.path.starts_with("/api/v1/certificates/")
        && (request.path.ends_with("/issue")
            || request.path.ends_with("/renew")
            || request.path.ends_with("/import"))
}

fn handle_bound_certificate_mutation_request<C, S, A, T, P>(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    issuer: &mut CertificateIssuer<C, S, A>,
    challenges: &mut T,
    probe: &mut P,
    command_client: &mut dyn CoreCommandClient,
) -> AdminHttpResponse
where
    C: edge_ports::AcmeClient,
    S: edge_ports::CertificateStore,
    A: edge_ports::AuditSink,
    T: Http01ChallengeStore + ?Sized,
    P: Http01ChallengeProbe + ?Sized,
{
    if request.path.ends_with("/issue") {
        handle_certificate_issue_http_with_http01(
            request,
            sessions,
            issuer,
            challenges,
            probe,
            command_client,
        )
    } else if request.path.ends_with("/renew") {
        handle_certificate_renew_http(request, sessions, issuer, command_client)
    } else {
        unreachable!("bound certificate mutation path was prechecked")
    }
}

fn handle_bound_lifecycle_request(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    lifecycle: &mut ConfigLifecycle<FileRevisionRepository, NoopLegacyAuditSink>,
    command_client: &mut dyn CoreCommandClient,
) -> AdminHttpResponse {
    match request.path.as_str() {
        "/api/v1/proxy-hosts" => {
            handle_proxy_host_create_http(request, sessions, lifecycle, command_client)
        }
        "/api/v1/config/rollback" => {
            handle_config_rollback_http(request, sessions, lifecycle, command_client)
        }
        "/api/v1/config/apply" => {
            handle_config_apply_http(request, sessions, lifecycle, command_client)
        }
        path if request.method == AdminHttpMethod::Delete
            && path.starts_with("/api/v1/proxy-hosts/") =>
        {
            handle_proxy_host_delete_http(request, sessions, lifecycle, command_client)
        }
        path if request.method == AdminHttpMethod::Patch
            && path.starts_with("/api/v1/proxy-hosts/") =>
        {
            handle_proxy_host_update_http(request, sessions, lifecycle, command_client)
        }
        _ => unreachable!("bound lifecycle request path was prechecked"),
    }
}

fn handle_audited_lifecycle_request(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    lifecycle: &mut ConfigLifecycle<FileRevisionRepository, NoopLegacyAuditSink>,
    command_client: &mut dyn CoreCommandClient,
    ledger: &mut SharedFileAuditLedger,
    admission: &mut SharedAuditAdmission,
    current_revision: &edge_domain::ConfigRevisionId,
) -> AdminHttpResponse {
    let session_id = request.session_id.as_deref().unwrap_or_default();
    if require_session(sessions, request.session_id.as_deref()).is_err()
        || require_csrf(sessions, session_id, request.csrf_token.as_deref()).is_err()
    {
        return handle_bound_lifecycle_request(request, sessions, lifecycle, command_client);
    }
    let operation = match lifecycle_audit_operation(request, current_revision) {
        Ok(operation) => operation,
        Err(error) => return audit_failure_response(request, 400, &error, false),
    };
    let begin = match begin_audit_operation(ledger, admission, operation.clone()) {
        Ok(begin) => begin,
        Err(failure) => return audit_failure_response(request, 503, &failure.error, false),
    };
    let response = handle_bound_lifecycle_request(request, sessions, lifecycle, command_client);
    let committed = (200..300).contains(&response.status_code);
    let effect_state = if committed {
        AuditEffectState::Committed
    } else {
        AuditEffectState::Rejected
    };
    let error_code = if committed {
        None
    } else {
        AuditStableErrorCode::parse(
            response
                .error_code
                .as_deref()
                .unwrap_or(ErrorCode::InternalBug.as_str()),
        )
        .ok()
        .or_else(|| AuditStableErrorCode::parse(ErrorCode::InternalBug.as_str()).ok())
    };
    let after_revision = committed
        .then(|| response_revision_id(&response))
        .flatten()
        .and_then(|revision| AuditTargetId::parse(revision).ok());
    match complete_audit_operation(
        ledger,
        admission,
        CompleteAuditOperationInput {
            operation,
            expected_head: begin.head,
            effect_state,
            after_revision,
            error_code,
        },
    ) {
        Ok(_) => response,
        Err(failure) => audit_failure_response(request, 503, &failure.error, committed),
    }
}

fn lifecycle_audit_operation(
    request: &AdminHttpRequest,
    current_revision: &edge_domain::ConfigRevisionId,
) -> Result<edge_application::AuditPersistentOperationInput, edge_domain::AppError> {
    let context = admin_audit_context(request)?;
    let before = Some(
        AuditTargetId::parse(current_revision.as_str()).map_err(|_| {
            edge_domain::AppError::new(
                ErrorCode::AuditRecordInvalid,
                "invalid revision audit target",
            )
        })?,
    );
    match (request.method, request.path.as_str()) {
        (AdminHttpMethod::Post, "/api/v1/config/apply") => config_audit_operation(
            context,
            AuditAction::ConfigApply,
            AuditTargetId::parse(format!("config-{}", request.request_id)).map_err(|_| {
                edge_domain::AppError::new(
                    ErrorCode::AuditRecordInvalid,
                    "invalid config audit target",
                )
            })?,
            before,
        ),
        (AdminHttpMethod::Post, "/api/v1/config/rollback") => config_audit_operation(
            context,
            AuditAction::ConfigRollback,
            json_string_field(&request.body, "revision_id")
                .and_then(|value| AuditTargetId::parse(value).ok())
                .ok_or_else(|| {
                    edge_domain::AppError::new(
                        ErrorCode::AuditRecordInvalid,
                        "rollback revision audit target is invalid",
                    )
                })?,
            before,
        ),
        (AdminHttpMethod::Post, "/api/v1/proxy-hosts") => proxy_host_audit_operation(
            context,
            AuditAction::ProxyHostCreate,
            json_string_field(&request.body, "id")
                .and_then(|value| AuditTargetId::parse(value).ok())
                .ok_or_else(|| {
                    edge_domain::AppError::new(
                        ErrorCode::AuditRecordInvalid,
                        "proxy host audit target is invalid",
                    )
                })?,
            before,
        ),
        (AdminHttpMethod::Patch, path) | (AdminHttpMethod::Delete, path) => {
            let action = if request.method == AdminHttpMethod::Patch {
                AuditAction::ProxyHostUpdate
            } else {
                AuditAction::ProxyHostDelete
            };
            proxy_host_audit_operation(
                context,
                action,
                path.strip_prefix("/api/v1/proxy-hosts/")
                    .and_then(|value| AuditTargetId::parse(value).ok())
                    .ok_or_else(|| {
                        edge_domain::AppError::new(
                            ErrorCode::AuditRecordInvalid,
                            "proxy host audit target is invalid",
                        )
                    })?,
                before,
            )
        }
        _ => Err(edge_domain::AppError::new(
            ErrorCode::AdminRouteNotFound,
            "admin lifecycle audit route not found",
        )),
    }
}

fn admin_audit_context(request: &AdminHttpRequest) -> Result<AuditContext, edge_domain::AppError> {
    let request_id = AuditRequestId::parse(&request.request_id).map_err(|_| {
        edge_domain::AppError::new(
            ErrorCode::AuditRecordInvalid,
            "admin request id is not audit-safe",
        )
    })?;
    let operation_id = AuditOperationId::parse(format!("operation-{}", request.request_id))
        .map_err(|_| {
            edge_domain::AppError::new(
                ErrorCode::AuditRecordInvalid,
                "admin operation id is not audit-safe",
            )
        })?;
    Ok(AuditContext {
        operation_id,
        request_id,
        actor_kind: AuditActorKind::BootstrapAdmin,
        received_at_epoch_seconds: current_epoch_seconds().map_err(|_| {
            edge_domain::AppError::new(ErrorCode::InternalBug, "system clock is unavailable")
        })?,
    })
}

fn json_string_field(body: &str, field: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()?
        .get(field)?
        .as_str()
        .map(str::to_string)
}

fn response_revision_id(response: &AdminHttpResponse) -> Option<String> {
    json_string_field(&response.body, "revision_id")
}

fn audit_failure_response(
    request: &AdminHttpRequest,
    status_code: u16,
    error: &edge_domain::AppError,
    effect_committed: bool,
) -> AdminHttpResponse {
    AdminHttpResponse {
        status_code,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: serde_json::json!({
            "request_id": request.request_id,
            "error_code": error.code.as_str(),
            "message": error.code.default_user_message(),
            "effect_committed": effect_committed,
        })
        .to_string(),
        error_code: Some(error.code.as_str().to_string()),
    }
}

fn complete_audited_admin_response(
    request: &AdminHttpRequest,
    response: AdminHttpResponse,
    ledger: &mut SharedFileAuditLedger,
    admission: &mut SharedAuditAdmission,
    operation: edge_application::AuditPersistentOperationInput,
    expected_head: edge_domain::AuditLedgerHead,
) -> AdminHttpResponse {
    let committed = (200..300).contains(&response.status_code);
    let error_code = if committed {
        None
    } else {
        AuditStableErrorCode::parse(
            response
                .error_code
                .as_deref()
                .unwrap_or(ErrorCode::InternalBug.as_str()),
        )
        .ok()
        .or_else(|| AuditStableErrorCode::parse(ErrorCode::InternalBug.as_str()).ok())
    };
    match complete_audit_operation(
        ledger,
        admission,
        CompleteAuditOperationInput {
            operation,
            expected_head,
            effect_state: if committed {
                AuditEffectState::Committed
            } else {
                AuditEffectState::Rejected
            },
            after_revision: committed
                .then(|| response_revision_id(&response))
                .flatten()
                .and_then(|revision| AuditTargetId::parse(revision).ok()),
            error_code,
        },
    ) {
        Ok(_) => response,
        Err(failure) => audit_failure_response(request, 503, &failure.error, committed),
    }
}

fn record_auth_observation(
    state: &AdminHttpServerState,
    request: &AdminHttpRequest,
    response: &AdminHttpResponse,
) -> io::Result<()> {
    let Some((ledger, admission)) = &state.durable_audit else {
        return Ok(());
    };
    let action = match (request.method, request.path.as_str(), response.status_code) {
        (AdminHttpMethod::Post, "/api/v1/login", 200) => Some(AuditAction::AdminLoginSuccess),
        (AdminHttpMethod::Post, "/api/v1/logout", 200) => Some(AuditAction::AdminLogout),
        (AdminHttpMethod::Post, "/api/v1/login", 401)
            if response.body.contains("too many failed attempts") =>
        {
            Some(AuditAction::AdminLockout)
        }
        (AdminHttpMethod::Post, "/api/v1/login", 401) => {
            let Ok(target) = AuditTargetId::parse("bootstrap-admin") else {
                return Ok(());
            };
            let Ok(now) = current_epoch_seconds() else {
                return Ok(());
            };
            let should_record = state
                .auth_failure_audit_sampler
                .lock()
                .map(|mut sampler| sampler.should_record(&target, now))
                .unwrap_or(false);
            should_record.then_some(AuditAction::AdminAuthFailureSampled)
        }
        _ => None,
    };
    let Some(action) = action else {
        return Ok(());
    };
    let Ok(context) = admin_audit_context(request) else {
        return Ok(());
    };
    let Ok(target_id) = AuditTargetId::parse("bootstrap-admin") else {
        return Ok(());
    };
    let mut ledger = ledger.clone();
    let mut admission = admission.clone();
    let _ = record_security_observation(
        &mut ledger,
        &mut admission,
        AuditSecurityObservationInput {
            context,
            action,
            target_id,
            outcome: AuditOutcome::Observed,
        },
    );
    Ok(())
}

fn is_observability_request(request: &AdminHttpRequest) -> bool {
    request.method == AdminHttpMethod::Get
        && (request.path == "/api/v1/certificates"
            || request.path.starts_with("/api/v1/certificates/")
            || request.path == "/api/v1/logs/access"
            || request.path == "/api/v1/logs/errors")
}

fn is_trust_bundle_request(request: &AdminHttpRequest) -> bool {
    matches!(request.method, AdminHttpMethod::Get | AdminHttpMethod::Post)
        && request.path == "/api/v1/trust-bundles"
        || request.method == AdminHttpMethod::Delete
            && request.path.starts_with("/api/v1/trust-bundles/")
}

fn handle_observability_request(
    request: &AdminHttpRequest,
    sessions: &SessionStore,
    certificates: &dyn CertificateStore,
    access_logs: &[AccessLogEvent],
    error_logs: &[RecentErrorEvent],
    now_epoch_seconds: u64,
    certificate_renewal_window_seconds: u64,
) -> AdminHttpResponse {
    match request.path.as_str() {
        "/api/v1/certificates" => handle_certificate_list_http(
            request,
            sessions,
            certificates,
            now_epoch_seconds,
            certificate_renewal_window_seconds,
        ),
        path if path.starts_with("/api/v1/certificates/") => handle_certificate_get_http(
            request,
            sessions,
            certificates,
            now_epoch_seconds,
            certificate_renewal_window_seconds,
        ),
        "/api/v1/logs/access" => handle_access_logs_http(request, sessions, access_logs),
        "/api/v1/logs/errors" => handle_error_logs_http(request, sessions, error_logs),
        _ => unreachable!("observability request path was prechecked"),
    }
}

fn refresh_admin_snapshot(
    state: &AdminHttpServerState,
    revisions: &mut FileRevisionRepository,
) -> io::Result<()> {
    if let Some(record) = revisions.current().map_err(app_error_to_io)? {
        let desired = record.snapshot;
        let mut active = state
            .active_snapshot
            .lock()
            .map_err(|_| io::Error::other("admin active snapshot lock poisoned"))?;
        if config_activation_state(&active, &desired)
            == edge_application::ConfigActivationState::Aligned
        {
            *active = desired.clone();
        }
        *state
            .snapshot
            .lock()
            .map_err(|_| io::Error::other("admin snapshot lock poisoned"))? = desired;
    }
    Ok(())
}

fn read_admin_http_request(stream: &mut TcpStream, max_bytes: usize) -> io::Result<String> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "admin HTTP request is too large",
            ));
        }
        if request_is_complete(&buffer) {
            break;
        }
    }
    String::from_utf8(buffer).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "admin HTTP request is not valid UTF-8",
        )
    })
}

fn request_is_complete(buffer: &[u8]) -> bool {
    let Some(header_end) = find_header_end(buffer) else {
        return false;
    };
    let headers = String::from_utf8_lossy(&buffer[..header_end]);
    let content_length = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    });
    let body_start = header_end + 4;
    match content_length {
        Some(length) => buffer.len().saturating_sub(body_start) >= length,
        None => true,
    }
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn app_error_to_io(error: edge_domain::AppError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{}: {}", error.code.as_str(), error.message),
    )
}

fn current_epoch_seconds() -> io::Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| io::Error::other("system time is before unix epoch"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_application::{checksum_snapshot, parse_mvp_config, AccessLogEvent, RecentErrorEvent};
    use edge_core::{snapshot_http::handle_snapshot_http_proxy_connection, HttpLimits};
    use edge_domain::{CertificateRef, CommandAck, ConfigRevision, ConfigRevisionId, CoreCommand};
    use edge_ports::{
        AcmeClient, AcmeOrderRequest, AcmeOrderResult, CertificateMaterial,
        CertificateMaterialValidator, CertificateStore, ConfigRevisionRepository, LogSink,
        RevisionRecord, StoredCertificate, StructuredLogEvent, ValidatedCertificateMaterial,
    };
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::path::PathBuf;

    fn snapshot() -> ConfigSnapshot {
        parse_mvp_config(
            include_str!("../../../examples/minimal.toml"),
            ConfigRevisionId::new("file-current"),
        )
        .unwrap()
        .snapshot
    }

    fn request_once(request: &str) -> String {
        let root = temp_root("request-once");
        let state = AdminHttpServerState::new(
            snapshot(),
            Some("hash".to_string()),
            FileSecretStore::new(&root),
        );
        let response = request_once_with_state(state, request);
        std::fs::remove_dir_all(root).ok();
        response
    }

    #[test]
    fn admin_http_listener_ignores_empty_connection_close() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let root = temp_root("empty-connection");
        let state = AdminHttpServerState::new(
            snapshot(),
            Some("hash".to_string()),
            FileSecretStore::new(&root),
        );
        let client = TcpStream::connect(address).unwrap();
        drop(client);
        let handle = thread::spawn(move || serve_next_admin_http_connection(&listener, &state));

        handle.join().unwrap().unwrap();
        std::fs::remove_dir_all(root).ok();
    }

    fn read_test_http_response(client: &mut TcpStream) -> Result<String, (String, io::Error)> {
        client.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];

        loop {
            match client.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => {
                    buffer.extend_from_slice(&chunk[..read]);
                    if request_is_complete(&buffer) {
                        break;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) && std::time::Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => {
                    let partial = String::from_utf8_lossy(&buffer).into_owned();
                    return Err((partial, error));
                }
            }
        }

        String::from_utf8(buffer).map_err(|error| {
            (
                String::new(),
                io::Error::new(io::ErrorKind::InvalidData, error),
            )
        })
    }

    fn temp_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "sponzey-edge-admin-http-{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[derive(Default)]
    struct AcceptingCommandClient {
        commands: Vec<CoreCommand>,
    }

    impl CoreCommandClient for AcceptingCommandClient {
        fn send(&mut self, command: CoreCommand) -> CommandAck {
            self.commands.push(command);
            CommandAck::accepted()
        }
    }

    struct RejectingCommandClient;

    impl CoreCommandClient for RejectingCommandClient {
        fn send(&mut self, _command: CoreCommand) -> CommandAck {
            CommandAck::rejected(edge_domain::AppError::new(
                ErrorCode::RuntimeCommandRejected,
                "runtime queue rejected command",
            ))
        }
    }

    struct FixedHealthStatusReader;

    impl edge_ports::HealthStatusReader for FixedHealthStatusReader {
        fn read_health_status(
            &self,
        ) -> Result<edge_domain::HealthAvailabilitySnapshot, edge_domain::AppError> {
            Ok(edge_domain::HealthAvailabilitySnapshot {
                revision_id: ConfigRevisionId::new("runtime-health-rev"),
                generation: edge_domain::HealthGeneration(9),
                entries: [(
                    edge_domain::UpstreamHealthKey {
                        service_id: edge_domain::ServiceId::new("app"),
                        upstream_id: edge_domain::UpstreamId::new("app-a"),
                    },
                    edge_domain::UpstreamAvailability::Healthy,
                )]
                .into_iter()
                .collect(),
            })
        }
    }

    #[derive(Default)]
    struct AcceptingMaterialValidator;

    impl CertificateMaterialValidator for AcceptingMaterialValidator {
        fn validate(
            &mut self,
            material: &CertificateMaterial,
        ) -> Result<ValidatedCertificateMaterial, edge_domain::AppError> {
            assert!(material.certificate_pem.contains('\n'));
            assert!(material.private_key_pem.contains('\n'));
            Ok(ValidatedCertificateMaterial {
                not_after_epoch_seconds: 4_000_000_000,
                dns_names: vec!["app.example.com".to_string()],
            })
        }
    }

    #[derive(Clone, Default)]
    struct SharedProductLogSink {
        events: Arc<Mutex<Vec<StructuredLogEvent>>>,
    }

    impl LogSink for SharedProductLogSink {
        fn record_log(&mut self, event: StructuredLogEvent) -> Result<(), edge_domain::AppError> {
            self.events.lock().unwrap().push(event);
            Ok(())
        }
    }

    struct SourceAcmeClient {
        source: &'static str,
    }

    impl AcmeClient for SourceAcmeClient {
        fn issue_certificate(
            &mut self,
            request: AcmeOrderRequest,
        ) -> Result<AcmeOrderResult, edge_domain::AppError> {
            Ok(AcmeOrderResult {
                certificate: StoredCertificate {
                    certificate_ref: CertificateRef::new("injected-acme"),
                    domains: request.domains,
                    not_after_epoch_seconds: 4_102_444_800,
                    source: self.source.to_string(),
                    certificate_pem: "cert".to_string(),
                    private_key_pem: "secret-key".to_string(),
                },
            })
        }
    }

    fn revision_repo_with_current(
        root: &std::path::Path,
        snapshot: ConfigSnapshot,
    ) -> FileRevisionRepository {
        let mut revisions = FileRevisionRepository::new(root.join("config"));
        let revision = ConfigRevision {
            id: snapshot.revision_id.clone(),
            schema_version: snapshot.schema_version,
            summary: "test current".to_string(),
        };
        let revision_id = revision.id.clone();
        revisions
            .save_revision(RevisionRecord {
                revision,
                checksum: checksum_snapshot(&snapshot),
                snapshot,
            })
            .unwrap();
        revisions.set_current(&revision_id).unwrap();
        revisions
    }

    #[test]
    fn admin_http_listener_serves_status_over_tcp() {
        let response = request_once("GET /api/v1/status HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n");

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("\"current_revision_id\":\"file-current\""));
        assert!(response.contains("\"desired_revision_id\":\"file-current\""));
        assert!(response.contains("\"active_revision_id\":\"file-current\""));
        assert!(response.contains("\"restart_required\":false"));
    }

    #[test]
    fn admin_status_tracks_pending_hot_apply_and_rollback_activation() {
        let root = temp_root("resource-activation-status");
        let active = snapshot();
        let state = AdminHttpServerState::new(
            active.clone(),
            Some("hash".to_string()),
            FileSecretStore::new(&root),
        );
        let mut revisions = revision_repo_with_current(&root, active.clone());

        let mut pending = active.clone();
        pending.revision_id = ConfigRevisionId::new("resource-pending");
        pending.runtime.max_connections = 100;
        pending.runtime.max_inflight_payload_bytes = 32 * 1024 * 1024;
        let pending_record = RevisionRecord {
            revision: ConfigRevision {
                id: pending.revision_id.clone(),
                schema_version: pending.schema_version,
                summary: "resource pending".to_string(),
            },
            checksum: checksum_snapshot(&pending),
            snapshot: pending.clone(),
        };
        revisions.save_revision(pending_record).unwrap();
        revisions.set_current(&pending.revision_id).unwrap();
        refresh_admin_snapshot(&state, &mut revisions).unwrap();

        assert_eq!(
            state.snapshot.lock().unwrap().revision_id,
            pending.revision_id
        );
        assert_eq!(
            state.active_snapshot.lock().unwrap().revision_id,
            active.revision_id
        );
        let pending_status = edge_admin_api::status_response_with_active(
            &state.snapshot.lock().unwrap(),
            &state.active_snapshot.lock().unwrap(),
        );
        assert!(pending_status.restart_required);
        assert_eq!(pending_status.active_resource_policy.max_connections, 1024);
        assert_eq!(pending_status.desired_resource_policy.max_connections, 100);

        revisions.set_current(&active.revision_id).unwrap();
        refresh_admin_snapshot(&state, &mut revisions).unwrap();
        let rollback_status = edge_admin_api::status_response_with_active(
            &state.snapshot.lock().unwrap(),
            &state.active_snapshot.lock().unwrap(),
        );
        assert!(!rollback_status.restart_required);
        assert_eq!(rollback_status.active_revision_id, "file-current");

        let mut hot = active.clone();
        hot.revision_id = ConfigRevisionId::new("hot-applied");
        let hot_record = RevisionRecord {
            revision: ConfigRevision {
                id: hot.revision_id.clone(),
                schema_version: hot.schema_version,
                summary: "hot apply".to_string(),
            },
            checksum: checksum_snapshot(&hot),
            snapshot: hot.clone(),
        };
        revisions.save_revision(hot_record).unwrap();
        revisions.set_current(&hot.revision_id).unwrap();
        refresh_admin_snapshot(&state, &mut revisions).unwrap();
        assert_eq!(
            state.active_snapshot.lock().unwrap().revision_id,
            hot.revision_id
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn admin_http_listener_serves_health_over_tcp() {
        let response = request_once("GET /api/v1/health HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n");

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("\"status\":\"ok\""));
        assert!(response.contains("\"current_revision_id\":\"file-current\""));
        assert!(!response.contains("upstream_url"));
    }

    #[test]
    fn admin_http_listener_serves_unauthenticated_operational_probes_over_tcp() {
        let state = AdminHttpServerState::new(
            snapshot(),
            Some("hash".to_string()),
            FileSecretStore::new(temp_root("operational-probes")),
        );
        *state.operational_lifecycle.lock().unwrap() = OperationalLifecycle::Draining;
        let live = request_once_with_state(
            state.clone(),
            "GET /api/v1/health/live HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n",
        );
        let ready = request_once_with_state(
            state,
            "GET /api/v1/health/ready HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n",
        );
        assert!(live.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(live.contains(r#"{"status":"live"}"#));
        assert!(ready.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
        assert!(ready.contains(r#"{"status":"not_ready"}"#));
        assert!(!ready.contains("revision"));
    }

    #[test]
    fn shared_operational_runtime_status_is_unavailable_until_core_publishes_facts() {
        let status = SharedOperationalRuntimeStatus::default();
        assert!(
            edge_ports::OperationalRuntimeStatusReader::read_operational_runtime_facts(&status)
                .is_err()
        );

        edge_ports::OperationalRuntimeStatusPublisher::publish_operational_runtime_facts(
            &status,
            OperationalRuntimeFacts {
                has_active_snapshot: true,
                has_listener: true,
                has_command_path: true,
            },
        );

        assert_eq!(
            edge_ports::OperationalRuntimeStatusReader::read_operational_runtime_facts(&status)
                .unwrap(),
            OperationalRuntimeFacts {
                has_active_snapshot: true,
                has_listener: true,
                has_command_path: true,
            }
        );
    }

    #[test]
    fn operational_readiness_requires_published_runtime_facts_over_tcp() {
        let state = AdminHttpServerState::new(
            snapshot(),
            Some("hash".to_string()),
            FileSecretStore::new(temp_root("operational-readiness-facts")),
        );
        *state.operational_lifecycle.lock().unwrap() = OperationalLifecycle::Ready;
        let ready = request_once_with_state(
            state,
            "GET /api/v1/health/ready HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n",
        );
        assert!(ready.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
        assert!(ready.contains(r#"{"status":"not_ready"}"#));
    }

    #[test]
    fn support_bundle_endpoint_uses_fixed_paths_and_requires_csrf() {
        let root = temp_root("support-endpoint");
        let support = root.join("support");
        std::fs::create_dir_all(&support).unwrap();
        std::fs::write(support.join("version.manifest"), "version=v1.2.3\n").unwrap();
        let state = AdminHttpServerState::new(
            snapshot(),
            Some("hash".to_string()),
            FileSecretStore::new(root.join("secrets")),
        )
        .with_support_bundle_paths(AdminHttpSupportBundlePaths {
            source_root: support.clone(),
            output: support.join("latest.tar"),
        });
        state
            .sessions
            .lock()
            .unwrap()
            .insert(edge_admin_api::Session {
                session_id: "session-1".into(),
                csrf_token: "csrf-1".into(),
            });
        let unauthorized = request_once_with_state(
            state.clone(),
            "POST /api/v1/support-bundles HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 0\r\n\r\n",
        );
        assert!(unauthorized.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
        let response = request_once_with_state(state, "POST /api/v1/support-bundles HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\nx-csrf-token: csrf-1\r\ncontent-length: 0\r\n\r\n");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("archive_id"));
        assert!(!response.contains(&support.display().to_string()));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn admin_http_listener_uses_injected_health_status_reader_over_tcp() {
        let root = temp_root("upstream-health");
        let state = AdminHttpServerState::new(
            snapshot(),
            Some("hash".to_string()),
            FileSecretStore::new(&root),
        )
        .with_health_status_reader(FixedHealthStatusReader);
        let login = request_once_with_state(
            state.clone(),
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );
        assert!(login.starts_with("HTTP/1.1 200 OK\r\n"));

        let response = request_once_with_state(
            state,
            "GET /api/v1/upstream-health HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\n\r\n",
        );
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("\"revision_id\":\"runtime-health-rev\""));
        assert!(response.contains("\"generation\":9"));
        assert!(response.contains("\"upstream_id\":\"app-a\""));
        assert!(!response.contains("upstream_url"));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn admin_status_reads_latest_resource_snapshot_without_core_reference() {
        let root = temp_root("resource-status");
        let resource_status = SharedRuntimeResourceStatus::default();
        assert_eq!(
            resource_status.try_publish_resource_status(RuntimeResourceStatusSnapshot {
                revision_id: edge_domain::ConfigRevisionId::new("runtime-resource-rev"),
                generation: 4,
                used_payload_bytes: 8_192,
                payload_limit_bytes: 128 * 1024 * 1024,
                active_connections: 2,
                pressure: edge_ports::RuntimeResourcePressure::Pressured,
            }),
            RuntimeResourceStatusPublishOutcome::Accepted
        );
        let state = AdminHttpServerState::new(
            snapshot(),
            Some("hash".to_string()),
            FileSecretStore::new(&root),
        )
        .with_resource_status_reader(Arc::new(resource_status));

        let response = request_once_with_state(
            state,
            "GET /api/v1/status HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n",
        );

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("\"revision_id\":\"runtime-resource-rev\""));
        assert!(response.contains("\"used_payload_bytes\":8192"));
        assert!(response.contains("\"active_connections\":2"));
        assert!(response.contains("\"pressure\":\"pressured\""));
        assert!(!response.contains("owner"));
        assert!(!response.contains("pid"));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn admin_http_listener_serves_static_admin_web_assets_over_tcp() {
        let index = request_once("GET / HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n");
        assert!(index.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(index.contains("content-type: text/html; charset=utf-8"));
        assert!(index.contains("Sponzey Edge"));
        assert!(index.contains("UI smoke only"));

        let styles = request_once("GET /styles.css HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n");
        assert!(styles.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(styles.contains("content-type: text/css; charset=utf-8"));
        assert!(styles.contains(".mode-label"));

        let app = request_once("GET /app.js HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n");
        assert!(index.contains("id=\"upstreamRows\""));
        assert!(index.contains("id=\"healthCheckEnabled\""));
        assert!(index.contains("Operational health"));
        assert!(app.contains("upstreams:"));
        assert!(app.contains("health_check:"));
        assert!(app.contains("/upstream-health"));
        assert!(app.contains("upstream-health-status"));
        assert!(app.contains("restartRequiredNotice"));
        assert!(app.contains("activeResourcePolicy"));
        assert!(app.contains("desiredResourcePolicy"));
        assert!(app.contains("liveResourceStatus"));
        assert!(index.contains("id=\"liveResourceRevision\""));
        assert!(app.contains("administrative_state"));
        assert!(app.contains("passive_health"));
        assert!(app.contains("max_replay_bytes"));
        assert!(app.contains("drain_state"));
        assert!(app.contains("connection_count"));
        assert!(app.contains("Number.isInteger(value)"));
        assert!(app.contains("[health.interval_ms, 1000, 300000"));
        assert!(app.contains("[health.status_max, 100, 599"));
        assert!(index.contains("data-panel=\"trust-tls\""));
        assert!(index.contains("id=\"trustBundleImportForm\""));
        assert!(index.contains("id=\"trustBundleRows\""));
        assert!(app.contains("/trust-bundles"));
        assert!(app.contains("elements.trustBundlePem.value = \"\""));
        assert!(!app.contains("localStorage"));
        assert!(!app.contains("sessionStorage"));
        assert!(!app.contains("indexedDB"));
        assert!(app.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(app.contains("content-type: application/javascript; charset=utf-8"));
        assert!(app.contains("/api/v1"));
        assert!(app.contains("X-CSRF-Token"));
    }

    #[test]
    fn admin_http_listener_serves_certificates_over_tcp() {
        let root = temp_root("certificates");
        let mut certificates = MemoryCertificateStore::default();
        certificates
            .save_certificate(StoredCertificate {
                certificate_ref: CertificateRef::new("cert-app"),
                domains: vec!["app.example.com".to_string()],
                not_after_epoch_seconds: 4_000_000_000,
                source: "manual".to_string(),
                certificate_pem: "cert".to_string(),
                private_key_pem: "secret-key".to_string(),
            })
            .unwrap();
        let state = AdminHttpServerState::new(
            snapshot(),
            Some("hash".to_string()),
            FileSecretStore::new(&root),
        )
        .with_observability(
            certificates,
            RecentAccessLogBuffer::new(10),
            RecentErrorBuffer::new(10),
        );

        let rejected = request_once_with_state(
            state.clone(),
            "GET /api/v1/certificates HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n",
        );
        assert!(rejected.starts_with("HTTP/1.1 401 Unauthorized\r\n"));

        let login = request_once_with_state(
            state.clone(),
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );
        assert!(login.starts_with("HTTP/1.1 200 OK\r\n"));

        let list = request_once_with_state(
            state.clone(),
            "GET /api/v1/certificates HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\n\r\n",
        );
        assert!(list.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(list.contains("\"certificate_ref\":\"cert-app\""));
        assert!(list.contains("\"private_key\":\"***\""));
        assert!(!list.contains("secret-key"));

        let get = request_once_with_state(
            state,
            "GET /api/v1/certificates/cert-app HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\n\r\n",
        );
        assert!(get.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(get.contains("\"domains\":[\"app.example.com\"]"));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn admin_http_listener_issues_certificate_over_tcp() {
        let root = temp_root("certificate-issue");
        let snapshot = snapshot();
        let revisions = revision_repo_with_current(&root, snapshot.clone());
        let file = FileAuditLedger::open(&root, AuditLedgerOptions::default()).unwrap();
        let ledger = SharedFileAuditLedger::new(file, edge_domain::AuditAdmissionState::Healthy);
        let state = AdminHttpServerState::new(
            snapshot,
            Some("hash".to_string()),
            FileSecretStore::new(root.join("secrets")),
        )
        .with_durable_audit(ledger.clone())
        .with_mutations(revisions, AcceptingCommandClient::default());

        let login = request_once_with_state(
            state.clone(),
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );
        assert!(login.starts_with("HTTP/1.1 200 OK\r\n"));

        let body = r#"{"domains":["app.example.com"],"account_email":"admin@example.com","production":false,"terms_accepted":false}"#;
        let request = format!(
            "POST /api/v1/certificates/proxy-host-app/issue HTTP/1.1\r\nhost: 127.0.0.1\r\nx-request-id: req-cert-product-log\r\ncookie: sponzey_session=session-1\r\nx-csrf-token: csrf-1\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );

        let issue = request_once_with_state(state.clone(), &request);

        assert!(issue.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(issue.contains("\"request_id\":\"req-cert-product-log\""));
        assert!(issue.contains("\"certificate_ref\":\"proxy-host-app\""));
        assert!(issue.contains("\"source\":\"fake-acme-staging\""));
        assert!(issue.contains("\"commands_sent\":1"));
        assert!(!issue.contains("PRIVATE KEY"));

        let list = request_once_with_state(
            state,
            "GET /api/v1/certificates HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\n\r\n",
        );
        assert!(list.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(list.contains("\"certificate_ref\":\"proxy-host-app\""));
        assert!(list.contains("\"private_key\":\"***\""));
        let certificate_records = edge_ports::AuditLedgerReader::query(
            &ledger,
            &edge_domain::AuditQuery::new(
                Some(AuditAction::CertificateIssue),
                None,
                None,
                None,
                None,
                10,
            )
            .unwrap(),
        )
        .unwrap()
        .records;
        assert_eq!(certificate_records.len(), 2);
        assert!(certificate_records
            .iter()
            .all(|record| record.record.target_id.as_str() == "proxy-host-app"));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn admin_http_listener_uses_injected_acme_client_boundary() {
        let root = temp_root("certificate-issue-injected-acme");
        let snapshot = snapshot();
        let revisions = revision_repo_with_current(&root, snapshot.clone());
        let state = AdminHttpServerState::new(
            snapshot,
            Some("hash".to_string()),
            FileSecretStore::new(root.join("secrets")),
        )
        .with_mutations(revisions, AcceptingCommandClient::default())
        .with_acme_client(SourceAcmeClient {
            source: "injected-acme-client",
        });

        let login = request_once_with_state(
            state.clone(),
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );
        assert!(login.starts_with("HTTP/1.1 200 OK\r\n"));

        let body = r#"{"domains":["app.example.com"],"account_email":"admin@example.com","production":false,"terms_accepted":false}"#;
        let request = format!(
            "POST /api/v1/certificates/proxy-host-app/issue HTTP/1.1\r\nhost: 127.0.0.1\r\nx-request-id: req-cert-product-log\r\ncookie: sponzey_session=session-1\r\nx-csrf-token: csrf-1\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );

        let issue = request_once_with_state(state, &request);

        assert!(issue.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(issue.contains("\"request_id\":\"req-cert-product-log\""));
        assert!(issue.contains("\"certificate_ref\":\"proxy-host-app\""));
        assert!(issue.contains("\"source\":\"injected-acme-client\""));
        assert!(!issue.contains("secret-key"));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn admin_http_listener_issues_certificate_after_runtime_http01_probe() {
        let root = temp_root("certificate-issue-http01-runtime");
        let snapshot = snapshot();
        let revisions = revision_repo_with_current(&root, snapshot.clone());
        let tokens = SharedHttp01TokenStore::default();
        let runtime_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        runtime_listener.set_nonblocking(true).unwrap();
        let runtime_addr = runtime_listener.local_addr().unwrap();
        let runtime_snapshot = snapshot.clone();
        let runtime_tokens = tokens.clone();
        let stop_runtime = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_runtime_thread = Arc::clone(&stop_runtime);
        let runtime_thread = thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(15);
            let mut handled = 0_usize;
            loop {
                if stop_runtime_thread.load(Ordering::SeqCst) && handled > 0 {
                    return Ok(());
                }
                match runtime_listener.accept() {
                    Ok((stream, address)) => {
                        handle_snapshot_http_proxy_connection(
                            stream,
                            &runtime_snapshot,
                            &runtime_tokens,
                            HttpLimits::default(),
                            address.ip().to_string(),
                        )?;
                        handled += 1;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() >= deadline {
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "runtime HTTP-01 probe did not connect",
                            ));
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => return Err(error),
                }
            }
        });
        let state = AdminHttpServerState::new(
            snapshot,
            Some("hash".to_string()),
            FileSecretStore::new(root.join("secrets")),
        )
        .with_mutations(revisions, AcceptingCommandClient::default())
        .with_http01_tokens(tokens.clone())
        .with_http01_probe(Http01RuntimeProbe::new(runtime_addr));

        let login = request_once_with_state(
            state.clone(),
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );
        assert!(login.starts_with("HTTP/1.1 200 OK\r\n"));

        let body = r#"{"domains":["app.example.com"],"account_email":"admin@example.com","production":false,"terms_accepted":false}"#;
        let request = format!(
            "POST /api/v1/certificates/proxy-host-app/issue HTTP/1.1\r\nhost: 127.0.0.1\r\nx-request-id: req-cert-http01\r\ncookie: sponzey_session=session-1\r\nx-csrf-token: csrf-1\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );

        let issue = request_once_with_state(state, &request);

        stop_runtime.store(true, Ordering::SeqCst);
        runtime_thread.join().unwrap().unwrap();
        assert!(
            issue.starts_with("HTTP/1.1 200 OK\r\n"),
            "issue response was {issue}"
        );
        assert!(issue.contains("\"request_id\":\"req-cert-http01\""));
        assert!(issue.contains("\"certificate_ref\":\"proxy-host-app\""));
        assert!(issue.contains("\"source\":\"fake-acme-staging\""));
        assert!(issue.contains("\"commands_sent\":1"));
        assert_eq!(tokens.respond("fake-acme-http01-app-example-com"), None);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn admin_http_listener_records_certificate_issue_product_log_over_tcp() {
        let root = temp_root("certificate-issue-product-log");
        let snapshot = snapshot();
        let revisions = revision_repo_with_current(&root, snapshot.clone());
        let product_log = SharedProductLogSink::default();
        let events = Arc::clone(&product_log.events);
        let state = AdminHttpServerState::new(
            snapshot,
            Some("hash".to_string()),
            FileSecretStore::new(root.join("secrets")),
        )
        .with_mutations(revisions, AcceptingCommandClient::default())
        .with_product_log_sink(Box::new(product_log));

        let login = request_once_with_state(
            state.clone(),
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );
        assert!(login.starts_with("HTTP/1.1 200 OK\r\n"));

        let body = r#"{"domains":["app.example.com"],"account_email":"admin@example.com","production":false,"terms_accepted":false}"#;
        let request = format!(
            "POST /api/v1/certificates/proxy-host-app/issue HTTP/1.1\r\nhost: 127.0.0.1\r\nx-request-id: req-cert-product-log\r\ncookie: sponzey_session=session-1\r\nx-csrf-token: csrf-1\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );

        let issue = request_once_with_state(state, &request);

        assert!(issue.starts_with("HTTP/1.1 200 OK\r\n"));
        let events = events.lock().unwrap();
        let event = events
            .iter()
            .find(|event| event.event == "certificate.issue.success")
            .expect("missing certificate issue product log");
        assert_eq!(event.component, "admin-api");
        assert!(
            event
                .fields
                .iter()
                .any(|(key, value)| key == "request_id" && value == "req-cert-product-log"),
            "product log fields were {:?}",
            event.fields
        );
        assert!(event
            .fields
            .iter()
            .any(|(key, value)| key == "revision_id" && value == "file-current"));
        assert!(event
            .fields
            .iter()
            .any(|(key, value)| key == "certificate_ref" && value == "proxy-host-app"));
        assert!(event
            .fields
            .iter()
            .any(|(key, value)| key == "status_code" && value == "200"));
        assert!(!format!("{event:?}").contains("secret"));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn admin_http_listener_records_certificate_issue_failure_product_log_over_tcp() {
        let root = temp_root("certificate-issue-product-log-failure");
        let snapshot = snapshot();
        let revisions = revision_repo_with_current(&root, snapshot.clone());
        let product_log = SharedProductLogSink::default();
        let events = Arc::clone(&product_log.events);
        let state = AdminHttpServerState::new(
            snapshot,
            Some("hash".to_string()),
            FileSecretStore::new(root.join("secrets")),
        )
        .with_mutations(revisions, RejectingCommandClient)
        .with_product_log_sink(Box::new(product_log));

        let login = request_once_with_state(
            state.clone(),
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );
        assert!(login.starts_with("HTTP/1.1 200 OK\r\n"));

        let body = r#"{"domains":["app.example.com"],"account_email":"admin@example.com","production":false,"terms_accepted":false}"#;
        let request = format!(
            "POST /api/v1/certificates/proxy-host-app/issue HTTP/1.1\r\nhost: 127.0.0.1\r\nx-request-id: req-cert-product-log-failure\r\ncookie: sponzey_session=session-1\r\nx-csrf-token: csrf-1\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );

        let issue = request_once_with_state(state, &request);

        assert!(issue.starts_with("HTTP/1.1 500 Internal Server Error\r\n"));
        let events = events.lock().unwrap();
        let event = events
            .iter()
            .find(|event| event.event == "certificate.issue.failure")
            .expect("missing certificate issue failure product log");
        assert!(event
            .fields
            .iter()
            .any(|(key, value)| key == "error_code" && value == "RUNTIME_COMMAND_REJECTED"));
        assert!(event
            .fields
            .iter()
            .any(|(key, value)| key == "revision_id" && value == "file-current"));
        assert!(event
            .fields
            .iter()
            .any(|(key, value)| key == "certificate_ref" && value == "proxy-host-app"));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn admin_http_listener_issues_certificate_to_file_store_over_tcp() {
        let root = temp_root("certificate-issue-file-store");
        let snapshot = snapshot();
        let revisions = revision_repo_with_current(&root, snapshot.clone());
        let state = AdminHttpServerState::new(
            snapshot,
            Some("hash".to_string()),
            FileSecretStore::new(root.join("secrets")),
        )
        .with_mutations(revisions, AcceptingCommandClient::default())
        .with_certificate_store(edge_adapters::FileCertificateStore::new(root.join("certs")));

        let login = request_once_with_state(
            state.clone(),
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );
        assert!(login.starts_with("HTTP/1.1 200 OK\r\n"));

        let body = r#"{"domains":["app.example.com"],"account_email":"admin@example.com","production":false,"terms_accepted":false}"#;
        let request = format!(
            "POST /api/v1/certificates/proxy-host-app/issue HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\nx-csrf-token: csrf-1\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );

        let issue = request_once_with_state(state.clone(), &request);

        assert!(issue.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(root.join("certs/proxy-host-app/fullchain.pem").is_file());
        assert!(root.join("certs/proxy-host-app/privkey.pem").is_file());
        assert!(root.join("certs/proxy-host-app/metadata.toml").is_file());

        let list = request_once_with_state(
            state,
            "GET /api/v1/certificates HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\n\r\n",
        );
        assert!(list.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(list.contains("\"certificate_ref\":\"proxy-host-app\""));
        assert!(list.contains("\"private_key\":\"***\""));
        assert!(!list.contains("PRIVATE KEY"));

        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn admin_http_listener_imports_manual_certificate_over_tcp() {
        let root = temp_root("certificate-import-file-store");
        let snapshot = snapshot();
        let revisions = revision_repo_with_current(&root, snapshot.clone());
        let product_log = SharedProductLogSink::default();
        let events = Arc::clone(&product_log.events);
        let state = AdminHttpServerState::new(
            snapshot,
            Some("hash".to_string()),
            FileSecretStore::new(root.join("secrets")),
        )
        .with_mutations(revisions, AcceptingCommandClient::default())
        .with_certificate_store(edge_adapters::FileCertificateStore::new(root.join("certs")))
        .with_certificate_validator(AcceptingMaterialValidator)
        .with_product_log_sink(Box::new(product_log));

        let login = request_once_with_state(
            state.clone(),
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );
        assert!(login.starts_with("HTTP/1.1 200 OK\r\n"));

        let body = r#"{"domains":["app.example.com"],"fullchain_pem":"-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----","private_key_pem":"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"}"#;
        let request = format!(
            "POST /api/v1/certificates/proxy-host-app/import HTTP/1.1\r\nhost: 127.0.0.1\r\nx-request-id: req-cert-import\r\ncookie: sponzey_session=session-1\r\nx-csrf-token: csrf-1\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );

        let imported = request_once_with_state(state.clone(), &request);

        assert!(imported.starts_with("HTTP/1.1 200 OK\r\n"), "{imported}");
        assert!(imported.contains("\"source\":\"manual\""));
        assert!(imported.contains("\"private_key\":\"***\""));
        assert!(!imported.contains("BEGIN PRIVATE KEY"));
        assert!(root.join("certs/proxy-host-app/fullchain.pem").is_file());
        assert!(root.join("certs/proxy-host-app/privkey.pem").is_file());

        let list = request_once_with_state(
            state,
            "GET /api/v1/certificates HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\n\r\n",
        );
        assert!(list.contains("\"certificate_ref\":\"proxy-host-app\""));
        assert!(list.contains("\"private_key\":\"***\""));
        assert!(!list.contains("BEGIN PRIVATE KEY"));

        let events = events.lock().unwrap();
        let event = events
            .iter()
            .find(|event| event.event == "certificate.import.success")
            .expect("missing certificate import product log");
        assert!(event
            .fields
            .iter()
            .any(|(key, value)| key == "source" && value == "manual"));
        assert!(!format!("{event:?}").contains("secret"));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn admin_http_listener_renews_certificate_over_tcp() {
        let root = temp_root("certificate-renew");
        let snapshot = snapshot();
        let revisions = revision_repo_with_current(&root, snapshot.clone());
        let mut certificates = MemoryCertificateStore::default();
        certificates
            .save_certificate(StoredCertificate {
                certificate_ref: CertificateRef::new("proxy-host-app"),
                domains: vec!["app.example.com".to_string()],
                not_after_epoch_seconds: 1_000,
                source: "fake-acme-staging".to_string(),
                certificate_pem: "old-cert".to_string(),
                private_key_pem: "old-key".to_string(),
            })
            .unwrap();
        let state = AdminHttpServerState::new(
            snapshot,
            Some("hash".to_string()),
            FileSecretStore::new(root.join("secrets")),
        )
        .with_mutations(revisions, AcceptingCommandClient::default())
        .with_observability(
            certificates,
            RecentAccessLogBuffer::new(10),
            RecentErrorBuffer::new(10),
        );

        let login = request_once_with_state(
            state.clone(),
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );
        assert!(login.starts_with("HTTP/1.1 200 OK\r\n"));

        let body =
            r#"{"account_email":"admin@example.com","production":false,"terms_accepted":false}"#;
        let request = format!(
            "POST /api/v1/certificates/proxy-host-app/renew HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\nx-csrf-token: csrf-1\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );

        let renew = request_once_with_state(state.clone(), &request);

        assert!(renew.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(renew.contains("\"certificate_ref\":\"proxy-host-app\""));
        assert!(renew.contains("\"domains\":[\"app.example.com\"]"));
        assert!(renew.contains("\"commands_sent\":1"));

        let get = request_once_with_state(
            state,
            "GET /api/v1/certificates/proxy-host-app HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\n\r\n",
        );
        assert!(get.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(get.contains("\"source\":\"fake-acme-staging\""));
        assert!(!get.contains("old-key"));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn admin_http_listener_serves_recent_logs_over_tcp() {
        let root = temp_root("logs");
        let mut access_logs = RecentAccessLogBuffer::new(10);
        access_logs.push(AccessLogEvent {
            request_id: "req-1".to_string(),
            revision_id: "file-current".to_string(),
            route_id: Some("route-1".to_string()),
            upstream_id: Some("upstream-1".to_string()),
            status_code: 200,
            duration_ms: 14,
            scheme: "https".to_string(),
            method: "GET".to_string(),
            path: "/secret?token=raw".to_string(),
        });
        let mut error_logs = RecentErrorBuffer::new(10);
        error_logs.push(RecentErrorEvent {
            request_id: Some("req-2".to_string()),
            error_code: "RUNTIME_COMMAND_REJECTED".to_string(),
            message: "queue full".to_string(),
        });
        let state = AdminHttpServerState::new(
            snapshot(),
            Some("hash".to_string()),
            FileSecretStore::new(&root),
        )
        .with_observability(MemoryCertificateStore::default(), access_logs, error_logs);

        let login = request_once_with_state(
            state.clone(),
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );
        assert!(login.starts_with("HTTP/1.1 200 OK\r\n"));

        let access = request_once_with_state(
            state.clone(),
            "GET /api/v1/logs/access HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\n\r\n",
        );
        assert!(access.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(access.contains("\"access_logs\":["));
        assert!(access.contains("\"route_id\":\"route-1\""));
        assert!(!access.contains("/secret"));
        assert!(!access.contains("token=raw"));

        let errors = request_once_with_state(
            state,
            "GET /api/v1/logs/errors HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\n\r\n",
        );
        assert!(errors.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(errors.contains("\"error_logs\":["));
        assert!(errors.contains("\"error_code\":\"RUNTIME_COMMAND_REJECTED\""));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn admin_http_listener_serves_access_log_received_from_runtime_queue() {
        let root = temp_root("logs-runtime-queue");
        let (sender, receiver) = mpsc::sync_channel(4);
        let state = AdminHttpServerState::new(
            snapshot(),
            Some("hash".to_string()),
            FileSecretStore::new(&root),
        )
        .with_access_log_receiver(receiver);
        sender
            .try_send(AccessLogEvent {
                request_id: "proxy-1".to_string(),
                revision_id: "file-current".to_string(),
                route_id: Some("route-1".to_string()),
                upstream_id: Some("upstream-1".to_string()),
                status_code: 200,
                duration_ms: 9,
                scheme: "https".to_string(),
                method: "GET".to_string(),
                path: "/secret?token=raw".to_string(),
            })
            .unwrap();
        thread::sleep(Duration::from_millis(20));

        let login = request_once_with_state(
            state.clone(),
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );
        assert!(login.starts_with("HTTP/1.1 200 OK\r\n"));

        let access = request_once_with_state(
            state,
            "GET /api/v1/logs/access HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\n\r\n",
        );

        assert!(access.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(access.contains("\"request_id\":\"proxy-1\""));
        assert!(access.contains("\"revision_id\":\"file-current\""));
        assert!(access.contains("\"route_id\":\"route-1\""));
        assert!(!access.contains("/secret"));
        assert!(!access.contains("token=raw"));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn admin_http_listener_serves_error_log_received_from_runtime_queue() {
        let root = temp_root("errors-runtime-queue");
        let (sender, receiver) = mpsc::sync_channel(4);
        let state = AdminHttpServerState::new(
            snapshot(),
            Some("hash".to_string()),
            FileSecretStore::new(&root),
        )
        .with_error_log_receiver(receiver);
        sender
            .try_send(RecentErrorEvent {
                request_id: Some("proxy-2".to_string()),
                error_code: "RUNTIME_UPSTREAM_TIMEOUT".to_string(),
                message: "upstream timed out".to_string(),
            })
            .unwrap();
        thread::sleep(Duration::from_millis(20));

        let login = request_once_with_state(
            state.clone(),
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );
        assert!(login.starts_with("HTTP/1.1 200 OK\r\n"));

        let errors = request_once_with_state(
            state,
            "GET /api/v1/logs/errors HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\n\r\n",
        );

        assert!(errors.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(errors.contains("\"request_id\":\"proxy-2\""));
        assert!(errors.contains("\"error_code\":\"RUNTIME_UPSTREAM_TIMEOUT\""));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn admin_http_listener_exposes_log_queue_drops_only_in_debug_modes() {
        let product_root = temp_root("log-drops-product");
        let product_counter = Arc::new(AtomicU64::new(2));
        let product_state = AdminHttpServerState::new(
            snapshot(),
            Some("hash".to_string()),
            FileSecretStore::new(&product_root),
        )
        .with_log_drop_counter(product_counter);
        let product_login = request_once_with_state(
            product_state.clone(),
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );
        assert!(product_login.starts_with("HTTP/1.1 200 OK\r\n"));
        let product_errors = request_once_with_state(
            product_state,
            "GET /api/v1/logs/errors HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\n\r\n",
        );
        assert!(!product_errors.contains("RUNTIME_LOG_QUEUE_FULL"));
        std::fs::remove_dir_all(product_root).ok();

        let dev_root = temp_root("log-drops-dev");
        let mut dev_snapshot = snapshot();
        dev_snapshot.log_mode = LogMode::Dev;
        let dev_counter = Arc::new(AtomicU64::new(3));
        let dev_state = AdminHttpServerState::new(
            dev_snapshot,
            Some("hash".to_string()),
            FileSecretStore::new(&dev_root),
        )
        .with_log_drop_counter(dev_counter);
        let dev_login = request_once_with_state(
            dev_state.clone(),
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );
        assert!(dev_login.starts_with("HTTP/1.1 200 OK\r\n"));
        let dev_errors = request_once_with_state(
            dev_state,
            "GET /api/v1/logs/errors HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\n\r\n",
        );
        assert!(dev_errors.contains("\"error_code\":\"RUNTIME_LOG_QUEUE_FULL\""));
        assert!(dev_errors.contains("dropped 3 runtime log events"));
        std::fs::remove_dir_all(dev_root).ok();
    }

    #[test]
    fn admin_http_listener_gets_and_validates_config_over_tcp() {
        let root = temp_root("config-read-validate");
        let state = AdminHttpServerState::new(
            snapshot(),
            Some("hash".to_string()),
            FileSecretStore::new(&root),
        );

        let login = request_once_with_state(
            state.clone(),
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );
        assert!(login.starts_with("HTTP/1.1 200 OK\r\n"));

        let config = request_once_with_state(
            state.clone(),
            "GET /api/v1/config HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\n\r\n",
        );
        assert!(config.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(config.contains("\"revision_id\":\"file-current\""));
        assert!(config.contains("\"config\":\"schema_version = 1\\n"));

        let body = include_str!("../../../examples/minimal.toml");
        let validate_request = format!(
            "POST /api/v1/config/validate HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let validate = request_once_with_state(state, &validate_request);
        assert!(validate.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(validate.contains("\"valid\":true"));
        assert!(validate.contains("\"errors\":[]"));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn admin_http_listener_diffs_and_applies_config_over_tcp() {
        let root = temp_root("config-diff-apply");
        let snapshot = snapshot();
        let revisions = revision_repo_with_current(&root, snapshot.clone());
        let state = AdminHttpServerState::new(
            snapshot,
            Some("hash".to_string()),
            FileSecretStore::new(root.join("secrets")),
        )
        .with_mutations(revisions.clone(), AcceptingCommandClient::default());

        let login = request_once_with_state(
            state.clone(),
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );
        assert!(login.starts_with("HTTP/1.1 200 OK\r\n"));

        let body = include_str!("../../../examples/minimal.toml")
            .replace("http://127.0.0.1:3000", "http://127.0.0.1:5000");
        let diff_request = format!(
            "POST /api/v1/config/diff HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let diff = request_once_with_state(state.clone(), &diff_request);
        assert!(diff.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(diff.contains("\"valid\":true"));
        assert!(diff.contains("\"changed_upstreams\":[\"example\"]"));

        let apply_request = format!(
            "POST /api/v1/config/apply HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\nx-csrf-token: csrf-1\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let apply = request_once_with_state(state.clone(), &apply_request);
        assert!(apply.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(apply.contains("\"revision_id\":\"file-current-config-apply\""));
        assert!(apply.contains("\"commands_sent\":2"));
        let current = revisions.current().unwrap().unwrap();
        assert_eq!(current.revision.id.as_str(), "file-current-config-apply");

        let status = request_once_with_state(
            state,
            "GET /api/v1/status HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n",
        );
        assert!(status.contains("\"current_revision_id\":\"file-current-config-apply\""));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn admin_http_listener_records_runtime_command_failure_in_recent_errors() {
        let root = temp_root("runtime-command-failure");
        let snapshot = snapshot();
        let revisions = revision_repo_with_current(&root, snapshot.clone());
        let state = AdminHttpServerState::new(
            snapshot,
            Some("hash".to_string()),
            FileSecretStore::new(root.join("secrets")),
        )
        .with_mutations(revisions, RejectingCommandClient);

        let login = request_once_with_state(
            state.clone(),
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );
        assert!(login.starts_with("HTTP/1.1 200 OK\r\n"));

        let body = include_str!("../../../examples/minimal.toml")
            .replace("http://127.0.0.1:3000", "http://127.0.0.1:5000");
        let apply_request = format!(
            "POST /api/v1/config/apply HTTP/1.1\r\nhost: 127.0.0.1\r\nx-request-id: req-runtime-command\r\ncookie: sponzey_session=session-1\r\nx-csrf-token: csrf-1\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let apply = request_once_with_state(state.clone(), &apply_request);
        assert!(apply.starts_with("HTTP/1.1 500 Internal Server Error\r\n"));
        assert!(apply.contains("\"code\":\"RUNTIME_COMMAND_REJECTED\""));

        let errors = request_once_with_state(
            state,
            "GET /api/v1/logs/errors HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\n\r\n",
        );
        assert!(errors.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(errors.contains("\"request_id\":\"req-runtime-command\""));
        assert!(errors.contains("\"error_code\":\"RUNTIME_COMMAND_REJECTED\""));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn admin_http_listener_rejects_mutation_without_session_over_tcp() {
        let response = request_once(
            "POST /api/v1/proxy-hosts HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 2\r\n\r\n{}",
        );

        assert!(response.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
        assert!(response.contains("\"code\":\"ADMIN_AUTH_REQUIRED\""));
    }

    #[test]
    fn admin_http_listener_logs_in_and_logs_out_over_tcp() {
        let root = temp_root("login-logout");
        let state = AdminHttpServerState::new(
            snapshot(),
            Some("hash".to_string()),
            FileSecretStore::new(&root),
        );

        let login = request_once_with_state(
            state.clone(),
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );

        assert!(login.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(login.contains(
            "set-cookie: sponzey_session=session-1; Path=/; HttpOnly; Secure; SameSite=Strict\r\n"
        ));
        assert!(login.contains("\"csrf_token\":\"csrf-1\""));

        let logout = request_once_with_state(
            state,
            "POST /api/v1/logout HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\nx-csrf-token: csrf-1\r\ncontent-length: 0\r\n\r\n",
        );

        assert!(logout.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(logout.contains("set-cookie: sponzey_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict\r\n"));
        assert!(logout.contains("\"logged_out\":true"));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn admin_http_listener_sets_up_first_password_over_tcp() {
        let root = temp_root("setup");
        let file = FileAuditLedger::open(&root, AuditLedgerOptions::default()).unwrap();
        let ledger = SharedFileAuditLedger::new(file, edge_domain::AuditAdmissionState::Healthy);
        let state = AdminHttpServerState::new(snapshot(), None, FileSecretStore::new(&root))
            .with_durable_audit(ledger.clone());

        let setup = request_once_with_state(
            state.clone(),
            "POST /api/v1/setup HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );

        assert!(setup.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(setup.contains("\"setup_complete\":true"));
        assert!(root.join("admin-password-hash.secret").is_file());

        let login = request_once_with_state(
            state,
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );

        assert!(login.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(login.contains("\"csrf_token\":\"csrf-1\""));
        let records =
            edge_ports::AuditLedgerReader::query(&ledger, &edge_domain::AuditQuery::default())
                .unwrap()
                .records;
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].record.action, AuditAction::AdminLoginSuccess);
        assert_eq!(records[1].record.action, AuditAction::AdminSetup);
        assert_eq!(records[2].record.action, AuditAction::AdminSetup);
        assert!(records.iter().all(|record| {
            record.record.target_id.as_str() == "bootstrap-admin"
                && record.record.error_code.is_none()
        }));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn admin_http_listener_creates_proxy_host_through_lifecycle_over_tcp() {
        let root = temp_root("proxy-host-create");
        let snapshot = snapshot();
        let revisions = revision_repo_with_current(&root, snapshot.clone());
        let state = AdminHttpServerState::new(
            snapshot,
            Some("hash".to_string()),
            FileSecretStore::new(root.join("secrets")),
        )
        .with_mutations(revisions.clone(), AcceptingCommandClient::default());

        let login = request_once_with_state(
            state.clone(),
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );
        assert!(login.starts_with("HTTP/1.1 200 OK\r\n"));

        let body = r#"{"id":"app","name":"App","domains":["app.example.com"],"path_prefix":"/","upstream_url":"http://127.0.0.1:4000","https_enabled":false,"letsencrypt_enabled":false,"redirect_http_to_https":false,"enabled":true}"#;
        let request = format!(
            "POST /api/v1/proxy-hosts HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\nx-csrf-token: csrf-1\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );

        let response = request_once_with_state(state, &request);

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("\"revision_id\":\"file-current-proxy-host-app\""));
        assert!(response.contains("\"commands_sent\":2"));
        let current = revisions.current().unwrap().unwrap();
        assert_eq!(current.revision.id.as_str(), "file-current-proxy-host-app");
        assert!(current
            .snapshot
            .routes
            .iter()
            .any(|route| route.id.as_str() == "proxy-host-app"));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn durable_admin_candidate_records_intent_before_proxy_host_terminal() {
        use edge_ports::AuditLedgerReader;
        let root = temp_root("durable-proxy-host-create");
        let snapshot = snapshot();
        let revisions = revision_repo_with_current(&root, snapshot.clone());
        let file = FileAuditLedger::open(&root, AuditLedgerOptions::default()).unwrap();
        let ledger = SharedFileAuditLedger::new(file, edge_domain::AuditAdmissionState::Healthy);
        let state = AdminHttpServerState::new(
            snapshot,
            Some("hash".to_string()),
            FileSecretStore::new(root.join("secrets")),
        )
        .with_durable_audit(ledger.clone())
        .with_mutations(revisions, AcceptingCommandClient::default());
        let login = request_once_with_state(
            state.clone(),
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );
        assert!(login.starts_with("HTTP/1.1 200 OK\r\n"));
        let body = r#"{"id":"app","name":"App","domains":["app.example.com"],"path_prefix":"/","upstream_url":"http://127.0.0.1:4000","https_enabled":false,"letsencrypt_enabled":false,"redirect_http_to_https":false,"enabled":true}"#;
        let request = format!(
            "POST /api/v1/proxy-hosts HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\nx-csrf-token: csrf-1\r\ncontent-length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let response = request_once_with_state(state.clone(), &request);
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));

        let unauthenticated = request_once_with_state(
            state.clone(),
            "GET /api/v1/audit HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n",
        );
        assert!(unauthenticated.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
        let query = request_once_with_state(
            state,
            "GET /api/v1/audit?action=proxy_host.create&limit=2 HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\n\r\n",
        );
        assert!(query.starts_with("HTTP/1.1 200 OK\r\n"));
        assert_eq!(query.matches("\"action\":\"proxy_host.create\"").count(), 2);
        assert!(query.contains("\"target_id\":\"app\""));
        assert!(!query.contains("csrf-1"));
        assert!(!query.contains("password_hash"));
        assert!(!query.contains("private_key"));
        assert!(!query.contains("logs/audit"));

        let records = ledger
            .query(&edge_domain::AuditQuery::default())
            .unwrap()
            .records;
        assert_eq!(records.len(), 3);
        assert_eq!(
            records[0].record.record_kind,
            edge_domain::AuditRecordKind::Terminal
        );
        assert_eq!(
            records[1].record.record_kind,
            edge_domain::AuditRecordKind::Intent
        );
        assert_eq!(records[0].record.action, AuditAction::ProxyHostCreate);
        assert_eq!(records[0].record.target_id.as_str(), "app");
        assert_eq!(records[2].record.action, AuditAction::AdminLoginSuccess);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn admin_http_listener_lists_and_gets_proxy_hosts_over_tcp() {
        let root = temp_root("proxy-host-read");
        let snapshot = snapshot();
        let revisions = revision_repo_with_current(&root, snapshot.clone());
        let state = AdminHttpServerState::new(
            snapshot,
            Some("hash".to_string()),
            FileSecretStore::new(root.join("secrets")),
        )
        .with_mutations(revisions, AcceptingCommandClient::default());

        let login = request_once_with_state(
            state.clone(),
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );
        assert!(login.starts_with("HTTP/1.1 200 OK\r\n"));

        let create_body = r#"{"id":"app","name":"App","domains":["app.example.com"],"path_prefix":"/","upstream_url":"http://127.0.0.1:4000","https_enabled":false,"letsencrypt_enabled":false,"redirect_http_to_https":false,"enabled":true}"#;
        let create_request = format!(
            "POST /api/v1/proxy-hosts HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\nx-csrf-token: csrf-1\r\ncontent-length: {}\r\n\r\n{}",
            create_body.len(),
            create_body
        );
        let create = request_once_with_state(state.clone(), &create_request);
        assert!(create.starts_with("HTTP/1.1 200 OK\r\n"));

        let list = request_once_with_state(
            state.clone(),
            "GET /api/v1/proxy-hosts HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\n\r\n",
        );
        assert!(list.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(list.contains("\"proxy_hosts\":["));
        assert!(list.contains("\"id\":\"app\""));
        assert!(list.contains("\"upstream_url\":\"http://127.0.0.1:4000\""));

        let get = request_once_with_state(
            state,
            "GET /api/v1/proxy-hosts/app HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\n\r\n",
        );
        assert!(get.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(get.contains("\"id\":\"app\""));
        assert!(get.contains("\"domains\":[\"app.example.com\"]"));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn admin_http_listener_updates_proxy_host_through_lifecycle_over_tcp() {
        let root = temp_root("proxy-host-update");
        let snapshot = snapshot();
        let revisions = revision_repo_with_current(&root, snapshot.clone());
        let state = AdminHttpServerState::new(
            snapshot,
            Some("hash".to_string()),
            FileSecretStore::new(root.join("secrets")),
        )
        .with_mutations(revisions.clone(), AcceptingCommandClient::default());

        let login = request_once_with_state(
            state.clone(),
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );
        assert!(login.starts_with("HTTP/1.1 200 OK\r\n"));

        let create_body = r#"{"id":"app","name":"App","domains":["app.example.com"],"path_prefix":"/","upstream_url":"http://127.0.0.1:4000","https_enabled":false,"letsencrypt_enabled":false,"redirect_http_to_https":false,"enabled":true}"#;
        let create_request = format!(
            "POST /api/v1/proxy-hosts HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\nx-csrf-token: csrf-1\r\ncontent-length: {}\r\n\r\n{}",
            create_body.len(),
            create_body
        );
        let create = request_once_with_state(state.clone(), &create_request);
        assert!(create.starts_with("HTTP/1.1 200 OK\r\n"));

        let update_body = r#"{"id":"app","name":"App Updated","domains":["app.example.com"],"path_prefix":"/","upstream_url":"http://127.0.0.1:5000","https_enabled":false,"letsencrypt_enabled":false,"redirect_http_to_https":false,"enabled":false}"#;
        let update_request = format!(
            "PATCH /api/v1/proxy-hosts/app HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\nx-csrf-token: csrf-1\r\ncontent-length: {}\r\n\r\n{}",
            update_body.len(),
            update_body
        );

        let update = request_once_with_state(state.clone(), &update_request);

        assert!(update.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(update
            .contains("\"revision_id\":\"file-current-proxy-host-app-update-proxy-host-app\""));
        assert!(update.contains("\"commands_sent\":2"));
        let current = revisions.current().unwrap().unwrap();
        assert_eq!(
            current.revision.id.as_str(),
            "file-current-proxy-host-app-update-proxy-host-app"
        );
        let route = current
            .snapshot
            .routes
            .iter()
            .find(|route| route.id.as_str() == "proxy-host-app")
            .unwrap();
        assert!(!route.enabled);
        let service = current
            .snapshot
            .services
            .iter()
            .find(|service| service.id.as_str() == "proxy-host-app")
            .unwrap();
        assert_eq!(service.upstreams[0].url, "http://127.0.0.1:5000");

        let status = request_once_with_state(
            state,
            "GET /api/v1/status HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n",
        );
        assert!(status.contains(
            "\"current_revision_id\":\"file-current-proxy-host-app-update-proxy-host-app\""
        ));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn admin_http_listener_rolls_back_config_through_lifecycle_over_tcp() {
        let root = temp_root("config-rollback");
        let snapshot = snapshot();
        let revisions = revision_repo_with_current(&root, snapshot.clone());
        let state = AdminHttpServerState::new(
            snapshot,
            Some("hash".to_string()),
            FileSecretStore::new(root.join("secrets")),
        )
        .with_mutations(revisions.clone(), AcceptingCommandClient::default());

        let login = request_once_with_state(
            state.clone(),
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );
        assert!(login.starts_with("HTTP/1.1 200 OK\r\n"));

        let create_body = r#"{"id":"app","name":"App","domains":["app.example.com"],"path_prefix":"/","upstream_url":"http://127.0.0.1:4000","https_enabled":false,"letsencrypt_enabled":false,"redirect_http_to_https":false,"enabled":true}"#;
        let create_request = format!(
            "POST /api/v1/proxy-hosts HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\nx-csrf-token: csrf-1\r\ncontent-length: {}\r\n\r\n{}",
            create_body.len(),
            create_body
        );
        let create = request_once_with_state(state.clone(), &create_request);
        assert!(create.starts_with("HTTP/1.1 200 OK\r\n"));

        let rollback_body = r#"{"revision_id":"file-current"}"#;
        let rollback_request = format!(
            "POST /api/v1/config/rollback HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\nx-csrf-token: csrf-1\r\ncontent-length: {}\r\n\r\n{}",
            rollback_body.len(),
            rollback_body
        );

        let rollback = request_once_with_state(state.clone(), &rollback_request);

        assert!(rollback.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(rollback.contains("\"revision_id\":\"file-current\""));
        assert!(rollback.contains("\"commands_sent\":2"));
        let current = revisions.current().unwrap().unwrap();
        assert_eq!(current.revision.id.as_str(), "file-current");
        assert!(!current
            .snapshot
            .routes
            .iter()
            .any(|route| route.id.as_str() == "proxy-host-app"));

        let status = request_once_with_state(
            state,
            "GET /api/v1/status HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n",
        );
        assert!(status.contains("\"current_revision_id\":\"file-current\""));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn admin_http_listener_deletes_proxy_host_through_lifecycle_over_tcp() {
        let root = temp_root("proxy-host-delete");
        let snapshot = snapshot();
        let revisions = revision_repo_with_current(&root, snapshot.clone());
        let state = AdminHttpServerState::new(
            snapshot,
            Some("hash".to_string()),
            FileSecretStore::new(root.join("secrets")),
        )
        .with_mutations(revisions.clone(), AcceptingCommandClient::default());

        let login = request_once_with_state(
            state.clone(),
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );
        assert!(login.starts_with("HTTP/1.1 200 OK\r\n"));

        let create_body = r#"{"id":"app","name":"App","domains":["app.example.com"],"path_prefix":"/","upstream_url":"http://127.0.0.1:4000","https_enabled":false,"letsencrypt_enabled":false,"redirect_http_to_https":false,"enabled":true}"#;
        let create_request = format!(
            "POST /api/v1/proxy-hosts HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\nx-csrf-token: csrf-1\r\ncontent-length: {}\r\n\r\n{}",
            create_body.len(),
            create_body
        );
        let create = request_once_with_state(state.clone(), &create_request);
        assert!(create.starts_with("HTTP/1.1 200 OK\r\n"));

        let delete = request_once_with_state(
            state.clone(),
            "DELETE /api/v1/proxy-hosts/app HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\nx-csrf-token: csrf-1\r\ncontent-length: 0\r\n\r\n",
        );

        assert!(delete.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(delete
            .contains("\"revision_id\":\"file-current-proxy-host-app-delete-proxy-host-app\""));
        let current = revisions.current().unwrap().unwrap();
        assert_eq!(
            current.revision.id.as_str(),
            "file-current-proxy-host-app-delete-proxy-host-app"
        );
        assert!(!current
            .snapshot
            .routes
            .iter()
            .any(|route| route.id.as_str() == "proxy-host-app"));

        let status = request_once_with_state(
            state,
            "GET /api/v1/status HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n",
        );
        assert!(status.contains(
            "\"current_revision_id\":\"file-current-proxy-host-app-delete-proxy-host-app\""
        ));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn phase009_admin_http_manages_trust_bundles_over_tcp_without_material_disclosure() {
        use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};

        let root = temp_root("trust-bundles");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
        let revisions = FileRevisionRepository::new(root.join("config"));
        let trust_root = root.join("trust-bundles");
        let file = FileAuditLedger::open(&root, AuditLedgerOptions::default()).unwrap();
        let ledger = SharedFileAuditLedger::new(file, edge_domain::AuditAdmissionState::Healthy);
        let state = AdminHttpServerState::new(
            snapshot(),
            Some("hash".to_string()),
            FileSecretStore::new(root.join("secrets")),
        )
        .with_durable_audit(ledger.clone())
        .with_trust_bundles(FileTrustBundleStore::new(&trust_root), revisions);

        let login = request_once_with_state(
            state.clone(),
            "POST /api/v1/login HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 24\r\n\r\n{\"password_hash\":\"hash\"}",
        );
        assert!(login.starts_with("HTTP/1.1 200 OK\r\n"));

        let body = serde_json::json!({
            "trust_bundle_ref": "private-root",
            "encoded_material": ca.pem(),
        })
        .to_string();
        let request = format!(
            "POST /api/v1/trust-bundles HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\nx-csrf-token: csrf-1\r\ncontent-length: {}\r\n\r\n{}",
            body.len(), body
        );
        let imported = request_once_with_state(state.clone(), &request);
        assert!(imported.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(imported.contains("\"trust_bundle_ref\":\"private-root\""));
        assert!(!imported.contains("BEGIN CERTIFICATE"));
        assert!(trust_root.join("private-root/roots.pem").is_file());

        let listed = request_once_with_state(
            state.clone(),
            "GET /api/v1/trust-bundles HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\n\r\n",
        );
        assert!(listed.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(listed.contains("\"trust_bundle_ref\":\"private-root\""));
        assert!(!listed.contains("BEGIN CERTIFICATE"));

        let deleted = request_once_with_state(
            state,
            "DELETE /api/v1/trust-bundles/private-root HTTP/1.1\r\nhost: 127.0.0.1\r\ncookie: sponzey_session=session-1\r\nx-csrf-token: csrf-1\r\ncontent-length: 0\r\n\r\n",
        );
        let trust_records = edge_ports::AuditLedgerReader::query(
            &ledger,
            &edge_domain::AuditQuery::new(
                None,
                None,
                Some(edge_domain::AuditTargetKind::TrustBundle),
                None,
                None,
                10,
            )
            .unwrap(),
        )
        .unwrap()
        .records;
        assert_eq!(trust_records.len(), 4);
        assert!(trust_records
            .iter()
            .all(|record| record.record.target_id.as_str() == "private-root"));
        assert!(deleted.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(deleted.contains("\"deleted\":true"));
        assert!(!trust_root.join("private-root").exists());
        std::fs::remove_dir_all(root).ok();
    }

    fn request_once_with_state(state: AdminHttpServerState, request: &str) -> String {
        assert!(
            request_is_complete(request.as_bytes()),
            "test Admin HTTP request must be complete before sending"
        );

        let mut last_error = None;
        for attempt in 0..3 {
            match request_once_with_state_attempt(state.clone(), request) {
                Ok(response) => return response,
                Err((response, error))
                    if response.is_empty()
                        && matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock
                                | io::ErrorKind::TimedOut
                                | io::ErrorKind::ConnectionReset
                                | io::ErrorKind::ConnectionAborted
                                | io::ErrorKind::NotConnected
                        )
                        && attempt < 2 =>
                {
                    last_error = Some(error);
                    thread::sleep(Duration::from_millis(25));
                }
                Err((response, error)) => {
                    panic!(
                        "test Admin HTTP request failed after {} response bytes: {error}",
                        response.len()
                    );
                }
            }
        }

        panic!(
            "test Admin HTTP request failed after transient empty-response retry: {}",
            last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "unknown error".to_string())
        );
    }

    fn request_once_with_state_attempt(
        state: AdminHttpServerState,
        request: &str,
    ) -> Result<String, (String, io::Error)> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || serve_next_admin_http_connection(&listener, &state));

        let mut client = TcpStream::connect(address).unwrap();
        client.write_all(request.as_bytes()).unwrap();
        let _ = client.shutdown(Shutdown::Write);

        let response = read_test_http_response(&mut client);
        match (response, handle.join()) {
            (Ok(response), Ok(Ok(()))) => Ok(response),
            (Ok(response), Ok(Err(error))) => Err((response, error)),
            (Err(error), Ok(Ok(()))) => Err(error),
            (Err((response, _)), Ok(Err(error))) => Err((response, error)),
            (_, Err(panic)) => std::panic::resume_unwind(panic),
        }
    }
}
#[test]
fn runtime_status_publisher_emits_only_drain_transition_edges() {
    let (log_tx, log_rx) = mpsc::sync_channel(4);
    let (metric_tx, metric_rx) = mpsc::sync_channel(4);
    let dropped = Arc::new(AtomicU64::new(0));
    let publisher = SharedRuntimeUpstreamStatus::with_observability(
        log_tx,
        Arc::new(MetricChannelPublisher::new(metric_tx)),
        Arc::clone(&dropped),
    );
    let status = |generation, state| edge_ports::RuntimeUpstreamStatusSnapshot {
        revision_id: edge_domain::ConfigRevisionId::new(format!("rev-{generation}")),
        generation,
        upstreams: vec![edge_ports::RuntimeUpstreamStatus {
            key: edge_domain::UpstreamHealthKey {
                service_id: edge_domain::ServiceId::new("app"),
                upstream_id: edge_domain::UpstreamId::new("a"),
            },
            state,
            connection_count: 1,
        }],
    };

    publisher.publish_runtime_status(status(1, edge_ports::RuntimeDrainState::Active));
    publisher.publish_runtime_status(status(2, edge_ports::RuntimeDrainState::Draining));
    publisher.publish_runtime_status(status(2, edge_ports::RuntimeDrainState::Draining));
    publisher.publish_runtime_status(status(2, edge_ports::RuntimeDrainState::Drained));

    assert_eq!(
        log_rx
            .try_iter()
            .map(|event| event.event)
            .collect::<Vec<_>>(),
        vec!["upstream.drain_started", "upstream.drain_completed",]
    );
    assert_eq!(metric_rx.try_iter().count(), 2);
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
}
