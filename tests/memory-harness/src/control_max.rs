use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use edge_adapters::{AuditLedgerOptions, FileAuditLedger};
use edge_admin_api::{
    handle_audit_query_http, handle_metrics_http, AdminHttpMethod, AdminHttpRequest,
    AdminHttpResponse, Session, SessionStore,
};
use edge_application::{
    MetricDropReason, MetricRegistry, MetricSnapshot, MetricSnapshotReaderPort,
};
use edge_domain::{
    AuditAction, AuditActorKind, AuditContext, AuditOperationId, AuditOutcome, AuditRecord,
    AuditRecordKind, AuditRequestId, AuditTargetId, AuditTargetKind,
};
use edge_ports::{
    AuditLedgerReader, AuditLedgerVerifier, AuditLedgerWriter, MetricDescriptor, MetricKind,
    MetricObservation,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::report_io::publish_canonical_bytes;
use crate::HarnessError;

pub const PRODUCTION_AUDIT_RECORDS: usize = 100_000;
pub const CONTROL_MAX_QUERY_CYCLES: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlMaxState {
    Created,
    PreparingAudit,
    LoadingAudit,
    LoadingMetrics,
    Ready,
    Querying,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlMaxEvent {
    PrepareAudit,
    AuditPrepared,
    AuditLoaded,
    MetricsLoaded,
    QueryCompleted(usize),
    Finish,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlMaxLifecycle {
    state: ControlMaxState,
    completed_queries: usize,
}

impl Default for ControlMaxLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl ControlMaxLifecycle {
    pub fn new() -> Self {
        Self {
            state: ControlMaxState::Created,
            completed_queries: 0,
        }
    }

    pub fn state(&self) -> ControlMaxState {
        self.state
    }

    pub fn advance(&mut self, event: ControlMaxEvent) -> Result<(), HarnessError> {
        use ControlMaxEvent as Event;
        use ControlMaxState as State;
        let next = match (self.state, event) {
            (State::Created, Event::PrepareAudit) => State::PreparingAudit,
            (State::PreparingAudit, Event::AuditPrepared) => State::LoadingAudit,
            (State::LoadingAudit, Event::AuditLoaded) => State::LoadingMetrics,
            (State::LoadingMetrics, Event::MetricsLoaded) => State::Ready,
            (State::Ready, Event::QueryCompleted(1)) => {
                self.completed_queries = 1;
                State::Querying
            }
            (State::Querying, Event::QueryCompleted(cycle))
                if cycle == self.completed_queries + 1 && cycle <= CONTROL_MAX_QUERY_CYCLES =>
            {
                self.completed_queries = cycle;
                State::Querying
            }
            (State::Querying, Event::Finish)
                if self.completed_queries == CONTROL_MAX_QUERY_CYCLES =>
            {
                State::Completed
            }
            (state, Event::Fail) if !matches!(state, State::Completed | State::Failed) => {
                State::Failed
            }
            _ => {
                self.state = State::Failed;
                return Err(HarnessError::new(
                    "control-max lifecycle transition is invalid",
                ));
            }
        };
        self.state = next;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureManifest {
    pub audit_records: usize,
    pub metric_series: usize,
    pub metric_rejection: String,
    pub fixture_sha256: String,
}

impl FixtureManifest {
    pub fn new(
        audit_records: usize,
        metric_series: usize,
        metric_rejection: impl Into<String>,
        fixture_sha256: impl Into<String>,
    ) -> Result<Self, HarnessError> {
        let manifest = Self {
            audit_records,
            metric_series,
            metric_rejection: metric_rejection.into(),
            fixture_sha256: fixture_sha256.into(),
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), HarnessError> {
        let known_rejection = matches!(
            self.metric_rejection.as_str(),
            "series_limit" | "response_budget"
        );
        if self.audit_records != PRODUCTION_AUDIT_RECORDS
            || self.metric_series == 0
            || !known_rejection
            || self.fixture_sha256.len() != 64
            || !self
                .fixture_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(HarnessError::new("control-max fixture manifest is invalid"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedAuditFixture {
    pub records: usize,
    pub sha256: String,
}

pub fn prepare_audit_fixture(
    root: &Path,
    records: usize,
) -> Result<PreparedAuditFixture, HarnessError> {
    if records == 0 || records > PRODUCTION_AUDIT_RECORDS {
        return Err(HarnessError::new(
            "control-max audit record count is invalid",
        ));
    }
    let mut ledger = FileAuditLedger::open(root, AuditLedgerOptions::default())
        .map_err(|_| HarnessError::new("control-max audit fixture open failed"))?;
    if ledger
        .head()
        .map_err(|_| HarnessError::new("control-max audit head read failed"))?
        .sequence
        != 0
    {
        return Err(HarnessError::new(
            "control-max audit fixture directory is not empty",
        ));
    }
    for index in 1..=records {
        ledger
            .append_security_observation(security_observation(index)?)
            .map_err(|_| HarnessError::new("control-max audit fixture append failed"))?;
    }
    let head = ledger
        .head()
        .map_err(|_| HarnessError::new("control-max audit head read failed"))?;
    if head.sequence != records as u64 {
        return Err(HarnessError::new(
            "control-max audit fixture count mismatch",
        ));
    }
    drop(ledger);
    Ok(PreparedAuditFixture {
        records,
        sha256: audit_fixture_sha256(root)?,
    })
}

fn security_observation(index: usize) -> Result<AuditRecord, HarnessError> {
    let suffix = format!("fixture-{index}");
    let record = AuditRecord {
        record_version: 1,
        record_kind: AuditRecordKind::SecurityObservation,
        context: AuditContext {
            operation_id: AuditOperationId::parse(&suffix)
                .map_err(|_| HarnessError::new("control-max operation id is invalid"))?,
            request_id: AuditRequestId::parse(&suffix)
                .map_err(|_| HarnessError::new("control-max request id is invalid"))?,
            actor_kind: AuditActorKind::BootstrapAdmin,
            received_at_epoch_seconds: index as u64,
        },
        action: AuditAction::AdminAuthFailureSampled,
        target_kind: AuditTargetKind::AdminAccount,
        target_id: AuditTargetId::parse("fixture-admin")
            .map_err(|_| HarnessError::new("control-max target id is invalid"))?,
        before_revision: None,
        after_revision: None,
        outcome: Some(AuditOutcome::Observed),
        error_code: None,
    };
    record
        .validate()
        .map_err(|_| HarnessError::new("control-max audit record is invalid"))?;
    Ok(record)
}

pub fn audit_fixture_sha256(root: &Path) -> Result<String, HarnessError> {
    let directory = root.join("logs/audit");
    let mut paths = fs::read_dir(&directory)
        .map_err(|_| HarnessError::new("control-max audit directory read failed"))?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|_| HarnessError::new("control-max audit entry read failed"))
        })
        .collect::<Result<Vec<PathBuf>, HarnessError>>()?;
    paths.sort();
    if paths.is_empty() {
        return Err(HarnessError::new("control-max audit fixture is empty"));
    }
    let mut digest = Sha256::new();
    for path in paths {
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| HarnessError::new("control-max audit filename is invalid"))?;
        let bytes = fs::read(&path)
            .map_err(|_| HarnessError::new("control-max audit segment read failed"))?;
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name.as_bytes());
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    Ok(format!("{:x}", digest.finalize()))
}

pub struct AuditMaxFixture {
    ledger: FileAuditLedger,
    verified_records: u64,
}

pub fn load_audit_fixture(root: &Path, expected: usize) -> Result<AuditMaxFixture, HarnessError> {
    if expected == 0 || expected > PRODUCTION_AUDIT_RECORDS {
        return Err(HarnessError::new(
            "control-max expected audit count is invalid",
        ));
    }
    let mut ledger = FileAuditLedger::open(root, AuditLedgerOptions::default())
        .map_err(|_| HarnessError::new("control-max audit fixture reopen failed"))?;
    let report = ledger
        .verify()
        .map_err(|_| HarnessError::new("control-max audit verification failed"))?;
    if report.record_count != expected as u64 || report.head.sequence != expected as u64 {
        return Err(HarnessError::new(
            "control-max verified audit count mismatch",
        ));
    }
    Ok(AuditMaxFixture {
        ledger,
        verified_records: report.record_count,
    })
}

impl AuditMaxFixture {
    pub fn verified_records(&self) -> u64 {
        self.verified_records
    }

    pub fn query_admin_page(&mut self) -> Result<AdminHttpResponse, HarnessError> {
        let sessions = fixture_sessions();
        let response = handle_audit_query_http(
            &AdminHttpRequest::new(
                AdminHttpMethod::Get,
                "/api/v1/audit?limit=100",
                "control-max-audit",
            )
            .with_session_id("control-max-session"),
            &sessions,
            &self.ledger,
        );
        if response.status_code != 200 {
            return Err(HarnessError::new("control-max Admin audit query failed"));
        }
        Ok(response)
    }
}

pub struct MetricMaxFixture {
    registry: MetricRegistry,
    snapshot: Arc<MetricSnapshot>,
    cumulative_series: usize,
    rejection: MetricDropReason,
}

pub fn build_metric_max_fixture() -> Result<MetricMaxFixture, HarnessError> {
    let mut registry = MetricRegistry::default();
    for index in 0..4_096 {
        registry
            .observe(
                MetricObservation::gauge_set(
                    MetricDescriptor::CertificateNotAfter,
                    index as i64,
                    vec![
                        ("certificate_ref".into(), format!("c{index:x}")),
                        ("source".into(), "manual".into()),
                    ],
                )
                .map_err(|_| HarnessError::new("control-max gauge observation is invalid"))?,
            )
            .map_err(|_| HarnessError::new("control-max gauge series rejected early"))?;
    }
    for index in 0..12_288 {
        registry
            .observe(
                MetricObservation::counter_add(
                    MetricDescriptor::RequestsTotal,
                    1,
                    vec![
                        ("route_id".into(), format!("r{index:x}")),
                        ("status_class".into(), "2xx".into()),
                    ],
                )
                .map_err(|_| HarnessError::new("control-max counter observation is invalid"))?,
            )
            .map_err(|_| HarnessError::new("control-max counter series rejected early"))?;
    }
    let overflow = MetricObservation::counter_add(
        MetricDescriptor::RequestsTotal,
        1,
        vec![
            ("route_id".into(), "overflow".into()),
            ("status_class".into(), "2xx".into()),
        ],
    )
    .map_err(|_| HarnessError::new("control-max overflow observation is invalid"))?;
    let rejection = registry
        .observe(overflow)
        .expect_err("production metric maximum must reject max+1");
    let snapshot = Arc::new(registry.snapshot());
    let cumulative_series = snapshot
        .series
        .iter()
        .filter(|series| series.key.descriptor.definition().kind != MetricKind::Gauge)
        .count();
    if snapshot.series.len() != 16_384 || cumulative_series != 12_288 {
        return Err(HarnessError::new("control-max metric cardinality mismatch"));
    }
    Ok(MetricMaxFixture {
        registry,
        snapshot,
        cumulative_series,
        rejection,
    })
}

impl MetricMaxFixture {
    pub fn series_count(&self) -> usize {
        self.snapshot.series.len()
    }

    pub fn cumulative_series_count(&self) -> usize {
        self.cumulative_series
    }

    pub fn rejection_reason(&self) -> &'static str {
        metric_rejection_name(self.rejection)
    }

    pub fn estimated_encoded_bytes(&self) -> usize {
        self.snapshot.estimated_encoded_bytes
    }

    pub fn query_admin_summary(&self) -> Result<AdminHttpResponse, HarnessError> {
        let _registry_kept_resident = &self.registry;
        let response = handle_metrics_http(
            &AdminHttpRequest::new(
                AdminHttpMethod::Get,
                "/api/v1/metrics",
                "control-max-metrics",
            )
            .with_session_id("control-max-session"),
            &fixture_sessions(),
            &FixtureMetricReader(Arc::clone(&self.snapshot)),
        );
        if response.status_code != 200 {
            return Err(HarnessError::new("control-max Admin metrics query failed"));
        }
        Ok(response)
    }
}

fn metric_rejection_name(reason: MetricDropReason) -> &'static str {
    match reason {
        MetricDropReason::SeriesLimit => "series_limit",
        MetricDropReason::ResponseBudget => "response_budget",
    }
}

struct FixtureMetricReader(Arc<MetricSnapshot>);

impl MetricSnapshotReaderPort for FixtureMetricReader {
    fn read_metric_snapshot(&self) -> Result<Arc<MetricSnapshot>, edge_domain::AppError> {
        Ok(Arc::clone(&self.0))
    }
}

fn fixture_sessions() -> SessionStore {
    let mut sessions = SessionStore::default();
    sessions.insert(Session {
        session_id: "control-max-session".into(),
        csrf_token: "control-max-csrf".into(),
    });
    sessions
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareControlMaxOptions {
    pub data_dir: PathBuf,
    pub manifest_output: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldControlMaxOptions {
    pub data_dir: PathBuf,
    pub manifest: PathBuf,
    pub ready_output: PathBuf,
    pub stop_file: PathBuf,
    pub summary_output: PathBuf,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMaxCommand {
    Prepare(PrepareControlMaxOptions),
    Hold(HoldControlMaxOptions),
}

pub fn parse_control_max_command(args: &[String]) -> Result<ControlMaxCommand, HarnessError> {
    let (command, options) = args
        .split_first()
        .ok_or_else(|| HarnessError::new("control-max command is missing"))?;
    let values = parse_control_max_pairs(options)?;
    match command.as_str() {
        "prepare" => {
            require_control_max_keys(&values, &["--data-dir", "--manifest-output"])?;
            Ok(ControlMaxCommand::Prepare(PrepareControlMaxOptions {
                data_dir: PathBuf::from(required_control_max(&values, "--data-dir")?),
                manifest_output: PathBuf::from(required_control_max(&values, "--manifest-output")?),
            }))
        }
        "hold" => {
            require_control_max_keys(
                &values,
                &[
                    "--data-dir",
                    "--manifest",
                    "--ready-output",
                    "--stop-file",
                    "--summary-output",
                    "--timeout-ms",
                ],
            )?;
            let timeout_ms = required_control_max(&values, "--timeout-ms")?
                .parse::<u64>()
                .map_err(|_| HarnessError::new("control-max timeout is invalid"))?;
            if timeout_ms == 0 {
                return Err(HarnessError::new("control-max timeout must be positive"));
            }
            Ok(ControlMaxCommand::Hold(HoldControlMaxOptions {
                data_dir: PathBuf::from(required_control_max(&values, "--data-dir")?),
                manifest: PathBuf::from(required_control_max(&values, "--manifest")?),
                ready_output: PathBuf::from(required_control_max(&values, "--ready-output")?),
                stop_file: PathBuf::from(required_control_max(&values, "--stop-file")?),
                summary_output: PathBuf::from(required_control_max(&values, "--summary-output")?),
                timeout_ms,
            }))
        }
        _ => Err(HarnessError::new("control-max command is unknown")),
    }
}

pub fn run_control_max_command(command: ControlMaxCommand) -> Result<String, HarnessError> {
    match command {
        ControlMaxCommand::Prepare(options) => prepare_control_max(options),
        ControlMaxCommand::Hold(options) => hold_control_max(options),
    }
}

fn prepare_control_max(options: PrepareControlMaxOptions) -> Result<String, HarnessError> {
    let prepared = prepare_audit_fixture(&options.data_dir, PRODUCTION_AUDIT_RECORDS)?;
    let metrics = build_metric_max_fixture()?;
    let manifest = FixtureManifest::new(
        prepared.records,
        metrics.series_count(),
        metrics.rejection_reason(),
        prepared.sha256,
    )?;
    let encoded = serde_json::to_vec(&manifest)
        .map_err(|_| HarnessError::new("control-max manifest encoding failed"))?;
    publish_canonical_bytes(&options.manifest_output, &encoded)?;
    Ok(format!(
        "control-max prepared audit_records={} metric_series={} rejection={}",
        manifest.audit_records, manifest.metric_series, manifest.metric_rejection
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlMaxSummary {
    pub schema_version: u16,
    pub audit_records: usize,
    pub audit_head_sequence: u64,
    pub audit_page_records: usize,
    pub metric_series: usize,
    pub cumulative_metric_series: usize,
    pub metric_rejection: String,
    pub metric_estimated_encoded_bytes: usize,
    pub metrics_counters: usize,
    pub metrics_gauges: usize,
    pub metrics_histograms: usize,
    pub query_cycles: usize,
    pub fixture_sha256: String,
    pub state: String,
}

fn hold_control_max(options: HoldControlMaxOptions) -> Result<String, HarnessError> {
    if options.stop_file.exists() {
        return Err(HarnessError::new(
            "control-max stop file exists before start",
        ));
    }
    let manifest_bytes = fs::read(&options.manifest)
        .map_err(|_| HarnessError::new("control-max manifest read failed"))?;
    let manifest: FixtureManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| HarnessError::new("control-max manifest parse failed"))?;
    manifest.validate()?;
    if audit_fixture_sha256(&options.data_dir)? != manifest.fixture_sha256 {
        return Err(HarnessError::new("control-max fixture digest mismatch"));
    }

    let mut lifecycle = ControlMaxLifecycle::new();
    lifecycle.advance(ControlMaxEvent::PrepareAudit)?;
    lifecycle.advance(ControlMaxEvent::AuditPrepared)?;
    let mut audit = load_audit_fixture(&options.data_dir, manifest.audit_records)?;
    lifecycle.advance(ControlMaxEvent::AuditLoaded)?;
    let metrics = build_metric_max_fixture()?;
    if metrics.series_count() != manifest.metric_series
        || metrics.rejection_reason() != manifest.metric_rejection
    {
        return Err(HarnessError::new(
            "control-max metric fixture manifest mismatch",
        ));
    }
    lifecycle.advance(ControlMaxEvent::MetricsLoaded)?;

    let mut expected_audit_body = None;
    let mut expected_metric_body = None;
    let mut audit_page_records = 0;
    let mut audit_head_sequence = 0;
    let mut metrics_counters = 0;
    let mut metrics_gauges = 0;
    let mut metrics_histograms = 0;
    for cycle in 1..=CONTROL_MAX_QUERY_CYCLES {
        let audit_response = audit.query_admin_page()?;
        let audit_json: serde_json::Value = serde_json::from_str(&audit_response.body)
            .map_err(|_| HarnessError::new("control-max audit response parse failed"))?;
        audit_page_records = audit_json["records"]
            .as_array()
            .map(Vec::len)
            .ok_or_else(|| HarnessError::new("control-max audit response records missing"))?;
        audit_head_sequence = audit_json["ledger"]["sequence"]
            .as_u64()
            .ok_or_else(|| HarnessError::new("control-max audit response head missing"))?;
        if audit_page_records != 100 || audit_head_sequence != manifest.audit_records as u64 {
            return Err(HarnessError::new(
                "control-max audit response bounds mismatch",
            ));
        }
        if expected_audit_body
            .as_ref()
            .is_some_and(|body| body != &audit_response.body)
        {
            return Err(HarnessError::new(
                "control-max audit response changed across cycles",
            ));
        }
        expected_audit_body.get_or_insert(audit_response.body);

        let metric_response = metrics.query_admin_summary()?;
        let metric_json: serde_json::Value = serde_json::from_str(&metric_response.body)
            .map_err(|_| HarnessError::new("control-max metrics response parse failed"))?;
        metrics_counters = json_array_len(&metric_json, "counters")?;
        metrics_gauges = json_array_len(&metric_json, "gauges")?;
        metrics_histograms = json_array_len(&metric_json, "histograms")?;
        if metrics_counters != 500 || metrics_gauges != 500 || metrics_histograms != 0 {
            return Err(HarnessError::new(
                "control-max metrics response bounds mismatch",
            ));
        }
        if expected_metric_body
            .as_ref()
            .is_some_and(|body| body != &metric_response.body)
        {
            return Err(HarnessError::new(
                "control-max metrics response changed across cycles",
            ));
        }
        expected_metric_body.get_or_insert(metric_response.body);
        lifecycle.advance(ControlMaxEvent::QueryCompleted(cycle))?;
    }
    drop(expected_audit_body);
    drop(expected_metric_body);

    publish_canonical_bytes(
        &options.ready_output,
        format!("{} {}\n", manifest.audit_records, metrics.series_count()).as_bytes(),
    )?;
    let deadline = Instant::now() + Duration::from_millis(options.timeout_ms);
    while !options.stop_file.exists() {
        if Instant::now() >= deadline {
            return Err(HarnessError::new("control-max hold timeout"));
        }
        std::hint::black_box((&audit, &metrics));
        thread::sleep(Duration::from_millis(50));
    }
    lifecycle.advance(ControlMaxEvent::Finish)?;
    let summary = ControlMaxSummary {
        schema_version: 1,
        audit_records: manifest.audit_records,
        audit_head_sequence,
        audit_page_records,
        metric_series: metrics.series_count(),
        cumulative_metric_series: metrics.cumulative_series_count(),
        metric_rejection: metrics.rejection_reason().into(),
        metric_estimated_encoded_bytes: metrics.estimated_encoded_bytes(),
        metrics_counters,
        metrics_gauges,
        metrics_histograms,
        query_cycles: CONTROL_MAX_QUERY_CYCLES,
        fixture_sha256: manifest.fixture_sha256,
        state: "completed".into(),
    };
    let encoded = serde_json::to_vec(&summary)
        .map_err(|_| HarnessError::new("control-max summary encoding failed"))?;
    publish_canonical_bytes(&options.summary_output, &encoded)?;
    Ok(format!(
        "control-max held audit_records={} metric_series={} query_cycles={}",
        summary.audit_records, summary.metric_series, summary.query_cycles
    ))
}

fn json_array_len(value: &serde_json::Value, key: &str) -> Result<usize, HarnessError> {
    value[key]
        .as_array()
        .map(Vec::len)
        .ok_or_else(|| HarnessError::new(format!("control-max {key} array missing")))
}

fn parse_control_max_pairs(args: &[String]) -> Result<BTreeMap<String, String>, HarnessError> {
    if !args.len().is_multiple_of(2) {
        return Err(HarnessError::new("control-max options are invalid"));
    }
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !pair[0].starts_with("--")
            || pair[1].is_empty()
            || values.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            return Err(HarnessError::new(
                "control-max option is invalid or duplicated",
            ));
        }
    }
    Ok(values)
}

fn require_control_max_keys(
    values: &BTreeMap<String, String>,
    expected: &[&str],
) -> Result<(), HarnessError> {
    if values.len() != expected.len()
        || values.keys().any(|key| !expected.contains(&key.as_str()))
        || expected.iter().any(|key| !values.contains_key(*key))
    {
        return Err(HarnessError::new("control-max option set is invalid"));
    }
    Ok(())
}

fn required_control_max(
    values: &BTreeMap<String, String>,
    key: &str,
) -> Result<String, HarnessError> {
    values
        .get(key)
        .cloned()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| HarnessError::new(format!("control-max {key} is missing")))
}
