use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::full_profile_readiness::{FullProfileEntry, FullProfileInput, FULL_PROFILE_SCENARIOS};
use crate::HarnessError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FullProfileJobContract {
    pub job_id: &'static str,
    pub script_path: &'static str,
    pub output_directory: &'static str,
    pub report_path: &'static str,
    pub digest_path: &'static str,
    pub scenarios: &'static [&'static str],
}

const IDLE: &[&str] = &["idle"];
const STEADY: &[&str] = &["http-steady", "https-steady", "mtls-steady"];
const HTTP_IDLE: &[&str] = &["http-idle-1024"];
const SLOW_HEADER: &[&str] = &["slow-header"];
const SLOW_BODY: &[&str] = &["slow-body"];
const SLOW_RESPONSE: &[&str] = &["slow-response"];
const CHURN: &[&str] = &["connection-churn"];
const HTTPS_IDLE: &[&str] = &["https-idle-512"];
const WEBSOCKET: &[&str] = &["websocket-128"];
const CONTROL_MAX: &[&str] = &["control-max"];

pub const FULL_PROFILE_JOBS: [FullProfileJobContract; 10] = [
    job(
        "idle",
        "scripts/smoke_memory_evidence.sh",
        "idle",
        "idle-v2.json",
        "idle-v2.sha256",
        IDLE,
    ),
    job(
        "steady",
        "scripts/run_three_steady_memory_profiles.sh",
        "steady",
        "aggregate/phase011-steady-3run-v1.json",
        "aggregate/phase011-steady-3run-v1.sha256",
        STEADY,
    ),
    job(
        "http-idle-1024",
        "scripts/smoke_connection_capacity.sh",
        "http-idle-1024",
        "held-1024-v2.json",
        "held-1024-v2.sha256",
        HTTP_IDLE,
    ),
    job(
        "slow-header",
        "scripts/smoke_slow_header_memory.sh",
        "slow-header",
        "slow-header-5cycle-v1.json",
        "slow-header-5cycle-v1.sha256",
        SLOW_HEADER,
    ),
    job(
        "slow-body",
        "scripts/smoke_slow_body_memory.sh",
        "slow-body",
        "slow-body-5cycle-v1.json",
        "slow-body-5cycle-v1.sha256",
        SLOW_BODY,
    ),
    job(
        "slow-response",
        "scripts/smoke_slow_response_memory.sh",
        "slow-response",
        "slow-response-5cycle-v1.json",
        "slow-response-5cycle-v1.sha256",
        SLOW_RESPONSE,
    ),
    job(
        "connection-churn",
        "scripts/smoke_connection_churn_memory.sh",
        "connection-churn",
        "connection-churn-50k-v1.json",
        "connection-churn-50k-v1.sha256",
        CHURN,
    ),
    job(
        "https-idle-512",
        "scripts/smoke_private_https_idle_capacity.sh",
        "https-idle-512",
        "private-https-idle-512-v2.json",
        "private-https-idle-512-v2.sha256",
        HTTPS_IDLE,
    ),
    job(
        "websocket-128",
        "scripts/smoke_websocket_memory.sh",
        "websocket-128",
        "websocket-5cycle-v1.json",
        "websocket-5cycle-v1.sha256",
        WEBSOCKET,
    ),
    job(
        "control-max",
        "scripts/smoke_control_max_memory.sh",
        "control-max",
        "control-max-v1.json",
        "control-max-v1.sha256",
        CONTROL_MAX,
    ),
];

const fn job(
    job_id: &'static str,
    script_path: &'static str,
    output_directory: &'static str,
    report_path: &'static str,
    digest_path: &'static str,
    scenarios: &'static [&'static str],
) -> FullProfileJobContract {
    FullProfileJobContract {
        job_id,
        script_path,
        output_directory,
        report_path,
        digest_path,
        scenarios,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerJobOutcome {
    pub job_id: String,
    pub build_identity: String,
    pub report_sha256: String,
    pub script_passed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FullProfileRunnerState {
    Created,
    Planned,
    Running,
    InventoryBuilt,
    Published,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FullProfileRunnerEvent {
    PlanValidated,
    JobStarted,
    JobVerified,
    InventoryBuilt,
    Published,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerLifecycle {
    state: FullProfileRunnerState,
}

impl RunnerLifecycle {
    pub fn new() -> Self {
        Self {
            state: FullProfileRunnerState::Created,
        }
    }

    pub fn state(&self) -> FullProfileRunnerState {
        self.state
    }

    pub fn transition(&mut self, event: FullProfileRunnerEvent) -> Result<(), HarnessError> {
        let next = match (self.state, event) {
            (FullProfileRunnerState::Created, FullProfileRunnerEvent::PlanValidated) => {
                FullProfileRunnerState::Planned
            }
            (FullProfileRunnerState::Planned, FullProfileRunnerEvent::JobStarted)
            | (FullProfileRunnerState::Running, FullProfileRunnerEvent::JobStarted)
            | (FullProfileRunnerState::Running, FullProfileRunnerEvent::JobVerified) => {
                FullProfileRunnerState::Running
            }
            (FullProfileRunnerState::Running, FullProfileRunnerEvent::InventoryBuilt) => {
                FullProfileRunnerState::InventoryBuilt
            }
            (FullProfileRunnerState::InventoryBuilt, FullProfileRunnerEvent::Published) => {
                FullProfileRunnerState::Published
            }
            (
                FullProfileRunnerState::Created
                | FullProfileRunnerState::Planned
                | FullProfileRunnerState::Running
                | FullProfileRunnerState::InventoryBuilt,
                FullProfileRunnerEvent::Failed,
            ) => FullProfileRunnerState::Failed,
            _ => {
                self.state = FullProfileRunnerState::Failed;
                return Err(HarnessError::new(
                    "full profile runner transition is invalid",
                ));
            }
        };
        self.state = next;
        Ok(())
    }
}

impl Default for RunnerLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

pub fn validate_runner_registry() -> Result<(), HarnessError> {
    let allowed = FULL_PROFILE_SCENARIOS
        .iter()
        .map(|scenario| scenario.scenario_id)
        .collect::<BTreeSet<_>>();
    let mut job_ids = BTreeSet::new();
    let mut covered = BTreeSet::new();
    let mut count = 0usize;
    for job in FULL_PROFILE_JOBS {
        if job.job_id.is_empty()
            || job.script_path.is_empty()
            || job.output_directory.is_empty()
            || job.report_path.is_empty()
            || job.digest_path.is_empty()
            || job.scenarios.is_empty()
            || !job_ids.insert(job.job_id)
        {
            return Err(HarnessError::new("full profile runner job is invalid"));
        }
        for scenario in job.scenarios {
            count += 1;
            if !allowed.contains(scenario) || !covered.insert(*scenario) {
                return Err(HarnessError::new(
                    "full profile runner scenario coverage is invalid",
                ));
            }
        }
    }
    if count != FULL_PROFILE_SCENARIOS.len() || covered != allowed {
        return Err(HarnessError::new(
            "full profile runner coverage is incomplete",
        ));
    }
    Ok(())
}

/// Rejects a full-profile plan whose source-controlled shell entrypoints cannot be executed.
///
/// This is a test/release adapter preflight: it neither invokes scripts nor changes product state.
pub fn validate_runner_entrypoints(root: &Path) -> Result<(), HarnessError> {
    for job in FULL_PROFILE_JOBS {
        let path = root.join(job.script_path);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| HarnessError::new("full profile runner entrypoint is unavailable"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || !is_executable(&metadata) {
            return Err(HarnessError::new(
                "full profile runner entrypoint is not an executable regular file",
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_: &fs::Metadata) -> bool {
    false
}

pub fn build_verified_input(
    current_build_identity: &str,
    platform: &str,
    architecture: &str,
    outcomes: Vec<RunnerJobOutcome>,
) -> Result<FullProfileInput, HarnessError> {
    validate_runner_registry()?;
    if !valid_build_identity(current_build_identity)
        || platform.is_empty()
        || architecture.is_empty()
        || outcomes.len() != FULL_PROFILE_JOBS.len()
    {
        return Err(HarnessError::new("full profile runner identity is invalid"));
    }
    let mut by_job = BTreeMap::new();
    for outcome in outcomes {
        if !outcome.script_passed
            || outcome.build_identity != current_build_identity
            || !valid_digest(&outcome.report_sha256)
            || by_job.insert(outcome.job_id.clone(), outcome).is_some()
        {
            return Err(HarnessError::new("full profile runner outcome is invalid"));
        }
    }
    if FULL_PROFILE_JOBS
        .iter()
        .any(|job| !by_job.contains_key(job.job_id))
    {
        return Err(HarnessError::new(
            "full profile runner outcome is incomplete",
        ));
    }
    let mut entries = Vec::with_capacity(FULL_PROFILE_SCENARIOS.len());
    for scenario in FULL_PROFILE_SCENARIOS {
        let job = FULL_PROFILE_JOBS
            .iter()
            .find(|job| job.scenarios.contains(&scenario.scenario_id))
            .ok_or_else(|| HarnessError::new("full profile runner scenario job is missing"))?;
        let outcome = by_job
            .get(job.job_id)
            .ok_or_else(|| HarnessError::new("full profile runner job outcome is missing"))?;
        entries.push(FullProfileEntry {
            scenario_id: scenario.scenario_id.to_string(),
            evidence_kind: scenario.evidence_kind,
            build_identity: outcome.build_identity.clone(),
            report_sha256: outcome.report_sha256.clone(),
            validation_passed: true,
        });
    }
    Ok(FullProfileInput {
        current_build_identity: current_build_identity.to_string(),
        platform: platform.to_string(),
        architecture: architecture.to_string(),
        entries,
    })
}

fn valid_build_identity(value: &str) -> bool {
    value
        .strip_prefix("source-tree-sha256:")
        .is_some_and(valid_digest)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
