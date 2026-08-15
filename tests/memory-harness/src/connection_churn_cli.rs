use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::connection_churn::{ChurnScenarioRunner, ChurnScenarioSpec, CyclingHttpLoad};
use crate::connection_churn_evidence::{
    ChurnEvidenceExpectations, ChurnEvidenceValidator, ChurnMemoryEvidenceReport,
};
use crate::release_http_scenario::{AdminStatusHttpProbe, AttachedProcessObservation, ThreadDelay};
use crate::report::EvidenceIdentity;
use crate::report_io::{publish_canonical_bytes, publish_digest};
use crate::HarnessError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunChurnOptions {
    pub pid: u32,
    pub proxy_address: SocketAddr,
    pub admin_address: SocketAddr,
    pub host: String,
    pub cycles: usize,
    pub requests_per_cycle: usize,
    pub timeout_ms: u64,
    pub max_response_bytes: usize,
    pub expected_revision: String,
    pub ceiling_bytes: u64,
    pub cooldown_interval_ms: u64,
    pub scenario_id: String,
    pub scenario_version: String,
    pub build_identity: String,
    pub config_sha256: String,
    pub output: PathBuf,
    pub digest_output: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidateChurnOptions {
    pub scenario_id: String,
    pub scenario_version: String,
    pub build_identity: String,
    pub config_sha256: String,
    pub report: PathBuf,
    pub digest: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChurnCommand {
    Run(RunChurnOptions),
    Validate(ValidateChurnOptions),
}

pub fn parse_churn_command(args: &[String]) -> Result<ChurnCommand, HarnessError> {
    let (command, rest) = args
        .split_first()
        .ok_or_else(|| HarnessError::new("connection churn command is missing"))?;
    match command.as_str() {
        "run" => parse_run(rest).map(ChurnCommand::Run),
        "validate" => parse_validate(rest).map(ChurnCommand::Validate),
        _ => Err(HarnessError::new("connection churn command is unknown")),
    }
}

pub fn run_churn_command(command: ChurnCommand) -> Result<String, HarnessError> {
    match command {
        ChurnCommand::Run(options) => run_and_publish(options),
        ChurnCommand::Validate(options) => validate_published(options),
    }
}

fn parse_run(args: &[String]) -> Result<RunChurnOptions, HarnessError> {
    const KEYS: [&str; 17] = [
        "--pid",
        "--proxy-address",
        "--admin-address",
        "--host",
        "--cycles",
        "--requests-per-cycle",
        "--timeout-ms",
        "--max-response-bytes",
        "--expected-revision",
        "--ceiling-bytes",
        "--cooldown-interval-ms",
        "--scenario",
        "--scenario-version",
        "--build-identity",
        "--config-sha256",
        "--output",
        "--digest-output",
    ];
    let values = parse_pairs(args, &KEYS)?;
    Ok(RunChurnOptions {
        pid: positive_u64(&values, "--pid")?
            .try_into()
            .map_err(|_| HarnessError::new("connection churn pid exceeds u32"))?,
        proxy_address: socket_address(&values, "--proxy-address")?,
        admin_address: socket_address(&values, "--admin-address")?,
        host: required(&values, "--host")?,
        cycles: positive_usize(&values, "--cycles")?,
        requests_per_cycle: positive_usize(&values, "--requests-per-cycle")?,
        timeout_ms: positive_u64(&values, "--timeout-ms")?,
        max_response_bytes: positive_usize(&values, "--max-response-bytes")?,
        expected_revision: required(&values, "--expected-revision")?,
        ceiling_bytes: positive_u64(&values, "--ceiling-bytes")?,
        cooldown_interval_ms: positive_u64(&values, "--cooldown-interval-ms")?,
        scenario_id: required(&values, "--scenario")?,
        scenario_version: required(&values, "--scenario-version")?,
        build_identity: required(&values, "--build-identity")?,
        config_sha256: hash(&values, "--config-sha256")?,
        output: PathBuf::from(required(&values, "--output")?),
        digest_output: PathBuf::from(required(&values, "--digest-output")?),
    })
}

fn parse_validate(args: &[String]) -> Result<ValidateChurnOptions, HarnessError> {
    const KEYS: [&str; 6] = [
        "--scenario",
        "--scenario-version",
        "--build-identity",
        "--config-sha256",
        "--report",
        "--digest",
    ];
    let values = parse_pairs(args, &KEYS)?;
    Ok(ValidateChurnOptions {
        scenario_id: required(&values, "--scenario")?,
        scenario_version: required(&values, "--scenario-version")?,
        build_identity: required(&values, "--build-identity")?,
        config_sha256: hash(&values, "--config-sha256")?,
        report: PathBuf::from(required(&values, "--report")?),
        digest: PathBuf::from(required(&values, "--digest")?),
    })
}

fn run_and_publish(options: RunChurnOptions) -> Result<String, HarnessError> {
    let timeout = Duration::from_millis(options.timeout_ms);
    let load = CyclingHttpLoad::new(
        options.proxy_address,
        options.host,
        options.requests_per_cycle,
        timeout,
        options.max_response_bytes,
    )?;
    let status = AdminStatusHttpProbe::new(options.admin_address, timeout, 256 * 1024)?;
    let process = AttachedProcessObservation::attach(options.pid)?;
    let process_start_identity = process.start_identity().to_string();
    let requests_per_cycle: u64 = options
        .requests_per_cycle
        .try_into()
        .map_err(|_| HarnessError::new("connection churn request count exceeds u64"))?;
    let spec = ChurnScenarioSpec::new(
        options.expected_revision,
        options.cycles,
        requests_per_cycle,
        options.ceiling_bytes,
        options.cooldown_interval_ms,
    )?;
    let mut runner = ChurnScenarioRunner::new(process, load, status, ThreadDelay::new());
    let record = runner.run(&spec);
    let report = ChurnMemoryEvidenceReport::new(
        EvidenceIdentity {
            scenario_id: options.scenario_id,
            scenario_version: options.scenario_version,
            platform: std::env::consts::OS.to_string(),
            architecture: std::env::consts::ARCH.to_string(),
            build_identity: options.build_identity,
            config_sha256: options.config_sha256,
            process_start_identity,
        },
        options.ceiling_bytes,
        options.cycles,
        requests_per_cycle,
        record,
    )
    .map_err(|_| HarnessError::new("connection churn evidence validation failed"))?;
    let encoded = report
        .to_canonical_json()
        .map_err(|_| HarnessError::new("connection churn evidence encoding failed"))?;
    let published = publish_canonical_bytes(&options.output, encoded.as_bytes())?;
    publish_digest(&options.digest_output, &published.sha256)?;
    Ok(format!(
        "connection churn evidence published cycles={} expected={} succeeded={} failed={} observed_peak_rss_bytes={} first_cooldown_median_bytes={} last_cooldown_median_bytes={} digest={}",
        report.cycles.len(),
        report.requests.expected,
        report.requests.succeeded,
        report.requests.failed,
        report.rss.observed_peak_bytes,
        report.rss.first_cooldown_median_bytes,
        report.rss.last_cooldown_median_bytes,
        published.sha256
    ))
}

fn validate_published(options: ValidateChurnOptions) -> Result<String, HarnessError> {
    let bytes = fs::read(&options.report)
        .map_err(|_| HarnessError::new("connection churn report read failed"))?;
    let digest = fs::read_to_string(&options.digest)
        .map_err(|_| HarnessError::new("connection churn digest read failed"))?;
    let report = ChurnEvidenceValidator::new(ChurnEvidenceExpectations {
        scenario_id: options.scenario_id,
        scenario_version: options.scenario_version,
        build_identity: options.build_identity,
        config_sha256: options.config_sha256,
    })
    .validate(&bytes, digest.trim())
    .map_err(|_| HarnessError::new("connection churn independent validation failed"))?;
    Ok(format!(
        "connection churn evidence validated cycles={} expected={} observed_peak_rss_bytes={}",
        report.cycles.len(),
        report.requests.expected,
        report.rss.observed_peak_bytes
    ))
}

fn parse_pairs(
    args: &[String],
    allowed: &[&str],
) -> Result<BTreeMap<String, String>, HarnessError> {
    if args.len() != allowed.len() * 2 || !args.len().is_multiple_of(2) {
        return Err(HarnessError::new(
            "connection churn arguments are incomplete",
        ));
    }
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !allowed.contains(&pair[0].as_str())
            || values.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            return Err(HarnessError::new(
                "connection churn argument is unknown or duplicated",
            ));
        }
    }
    Ok(values)
}

fn required(values: &BTreeMap<String, String>, key: &str) -> Result<String, HarnessError> {
    values
        .get(key)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| HarnessError::new(format!("connection churn argument is missing: {key}")))
}

fn positive_u64(values: &BTreeMap<String, String>, key: &str) -> Result<u64, HarnessError> {
    required(values, key)?
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| HarnessError::new("connection churn numeric argument must be positive"))
}

fn positive_usize(values: &BTreeMap<String, String>, key: &str) -> Result<usize, HarnessError> {
    positive_u64(values, key)?
        .try_into()
        .map_err(|_| HarnessError::new("connection churn numeric argument exceeds usize"))
}

fn socket_address(
    values: &BTreeMap<String, String>,
    key: &str,
) -> Result<SocketAddr, HarnessError> {
    required(values, key)?
        .parse()
        .map_err(|_| HarnessError::new("connection churn socket address is invalid"))
}

fn hash(values: &BTreeMap<String, String>, key: &str) -> Result<String, HarnessError> {
    let value = required(values, key)?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(HarnessError::new("connection churn digest is invalid"));
    }
    Ok(value)
}
