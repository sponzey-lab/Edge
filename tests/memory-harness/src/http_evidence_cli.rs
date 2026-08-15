use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use crate::http_evidence::{
    HttpEvidenceExpectations, HttpEvidenceValidator, HttpEvidenceWriter, HttpMemoryEvidenceReport,
};
use crate::release_http_cli::{
    execute_release_http_scenario, parse_release_http_options, ReleaseHttpOptions,
};
use crate::report::EvidenceIdentity;
use crate::report_io::publish_digest;
use crate::HarnessError;

const COMMON_KEYS: [&str; 11] = [
    "--pid",
    "--proxy-address",
    "--admin-address",
    "--host",
    "--requests",
    "--timeout-ms",
    "--max-response-bytes",
    "--expected-revision",
    "--ceiling-bytes",
    "--cooldown-cycles",
    "--cooldown-interval-ms",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunHttpEvidenceOptions {
    pub release: ReleaseHttpOptions,
    pub scenario_id: String,
    pub scenario_version: String,
    pub build_identity: String,
    pub config_sha256: String,
    pub output: PathBuf,
    pub digest_output: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidateHttpEvidenceOptions {
    pub scenario_id: String,
    pub scenario_version: String,
    pub build_identity: String,
    pub config_sha256: String,
    pub report: PathBuf,
    pub digest: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpEvidenceCommand {
    Run(RunHttpEvidenceOptions),
    Validate(ValidateHttpEvidenceOptions),
}

pub fn parse_http_evidence_command(args: &[String]) -> Result<HttpEvidenceCommand, HarnessError> {
    let (command, rest) = args
        .split_first()
        .ok_or_else(|| HarnessError::new("HTTP evidence command is missing"))?;
    match command.as_str() {
        "run" => parse_run(rest).map(HttpEvidenceCommand::Run),
        "validate" => parse_validate(rest).map(HttpEvidenceCommand::Validate),
        _ => Err(HarnessError::new("HTTP evidence command is unknown")),
    }
}

pub fn run_http_evidence_command(command: HttpEvidenceCommand) -> Result<String, HarnessError> {
    match command {
        HttpEvidenceCommand::Run(options) => run_and_publish(options),
        HttpEvidenceCommand::Validate(options) => validate_published(options),
    }
}

fn parse_run(args: &[String]) -> Result<RunHttpEvidenceOptions, HarnessError> {
    const EXTRA_KEYS: [&str; 6] = [
        "--scenario",
        "--scenario-version",
        "--build-identity",
        "--config-sha256",
        "--output",
        "--digest-output",
    ];
    let mut allowed = COMMON_KEYS.to_vec();
    allowed.extend(EXTRA_KEYS);
    let values = parse_pairs(args, &allowed)?;
    let common = COMMON_KEYS
        .iter()
        .flat_map(|key| [(*key).to_string(), values[*key].clone()])
        .collect::<Vec<_>>();
    let options = RunHttpEvidenceOptions {
        release: parse_release_http_options(&common)?,
        scenario_id: required(&values, "--scenario")?,
        scenario_version: required(&values, "--scenario-version")?,
        build_identity: required(&values, "--build-identity")?,
        config_sha256: required_hash(&values, "--config-sha256")?,
        output: PathBuf::from(required(&values, "--output")?),
        digest_output: PathBuf::from(required(&values, "--digest-output")?),
    };
    Ok(options)
}

fn parse_validate(args: &[String]) -> Result<ValidateHttpEvidenceOptions, HarnessError> {
    const KEYS: [&str; 6] = [
        "--scenario",
        "--scenario-version",
        "--build-identity",
        "--config-sha256",
        "--report",
        "--digest",
    ];
    let values = parse_pairs(args, &KEYS)?;
    Ok(ValidateHttpEvidenceOptions {
        scenario_id: required(&values, "--scenario")?,
        scenario_version: required(&values, "--scenario-version")?,
        build_identity: required(&values, "--build-identity")?,
        config_sha256: required_hash(&values, "--config-sha256")?,
        report: PathBuf::from(required(&values, "--report")?),
        digest: PathBuf::from(required(&values, "--digest")?),
    })
}

fn run_and_publish(options: RunHttpEvidenceOptions) -> Result<String, HarnessError> {
    let ceiling = options.release.ceiling_bytes;
    let executed = execute_release_http_scenario(options.release)?;
    let report = HttpMemoryEvidenceReport::new(
        EvidenceIdentity {
            scenario_id: options.scenario_id,
            scenario_version: options.scenario_version,
            platform: std::env::consts::OS.to_string(),
            architecture: std::env::consts::ARCH.to_string(),
            build_identity: options.build_identity,
            config_sha256: options.config_sha256,
            process_start_identity: executed.process_start_identity,
        },
        ceiling,
        executed.record,
    )
    .map_err(|_| HarnessError::new("HTTP evidence report validation failed"))?;
    let published = HttpEvidenceWriter::publish(&options.output, &report)?;
    publish_digest(&options.digest_output, &published.sha256)?;
    Ok(format!(
        "HTTP memory evidence published expected={} succeeded={} failed={} peak_rss_bytes={} active_connections={} used_payload_bytes={} digest={}",
        report.requests.expected,
        report.requests.succeeded,
        report.requests.failed,
        report.rss.peak_bytes,
        report.runtime.active_connections,
        report.runtime.used_payload_bytes,
        published.sha256
    ))
}

fn validate_published(options: ValidateHttpEvidenceOptions) -> Result<String, HarnessError> {
    let bytes = fs::read(&options.report)
        .map_err(|_| HarnessError::new("HTTP evidence report read failed"))?;
    let digest = fs::read_to_string(&options.digest)
        .map_err(|_| HarnessError::new("HTTP evidence digest read failed"))?;
    let report = HttpEvidenceValidator::new(HttpEvidenceExpectations {
        scenario_id: options.scenario_id,
        scenario_version: options.scenario_version,
        build_identity: options.build_identity,
        config_sha256: options.config_sha256,
    })
    .validate(&bytes, digest.trim())
    .map_err(|_| HarnessError::new("HTTP evidence independent validation failed"))?;
    Ok(format!(
        "HTTP memory evidence validated expected={} peak_rss_bytes={}",
        report.requests.expected, report.rss.peak_bytes
    ))
}

fn parse_pairs(
    args: &[String],
    allowed: &[&str],
) -> Result<BTreeMap<String, String>, HarnessError> {
    if args.len() != allowed.len() * 2 || !args.len().is_multiple_of(2) {
        return Err(HarnessError::new("HTTP evidence arguments are incomplete"));
    }
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !allowed.contains(&pair[0].as_str())
            || values.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            return Err(HarnessError::new(
                "HTTP evidence argument is unknown or duplicated",
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
        .ok_or_else(|| HarnessError::new(format!("HTTP evidence argument is missing: {key}")))
}

fn required_hash(values: &BTreeMap<String, String>, key: &str) -> Result<String, HarnessError> {
    let value = required(values, key)?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(HarnessError::new(
            "HTTP evidence digest argument is invalid",
        ));
    }
    Ok(value)
}
