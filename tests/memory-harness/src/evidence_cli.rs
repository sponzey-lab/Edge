use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use crate::orchestrator::{ScenarioOutcome, ScenarioRunRecord};
use crate::ports::RssSampler;
use crate::report::{EvidenceIdentity, MemoryEvidenceReport};
use crate::report_io::{publish_digest, AtomicReportWriter, ReportExpectations, ReportValidator};
use crate::scenario::ScenarioState;
use crate::system_adapters::{
    attach_process, attached_process_identity_matches, attached_process_is_alive,
    PlatformRssSampler,
};
use crate::{HarnessError, MemorySample};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleEvidenceOptions {
    pub pid: u32,
    pub scenario_id: String,
    pub scenario_version: String,
    pub build_identity: String,
    pub config_sha256: String,
    pub sample_count: usize,
    pub interval_ms: u64,
    pub output: PathBuf,
    pub digest_output: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidateEvidenceOptions {
    pub scenario_id: String,
    pub scenario_version: String,
    pub build_identity: String,
    pub config_sha256: String,
    pub report: PathBuf,
    pub digest: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceCommand {
    Sample(SampleEvidenceOptions),
    Validate(ValidateEvidenceOptions),
}

pub fn parse_evidence_command(args: &[String]) -> Result<EvidenceCommand, HarnessError> {
    let (command, rest) = args
        .split_first()
        .ok_or_else(|| HarnessError::new("memory evidence command is missing"))?;
    let values = parse_pairs(rest)?;
    match command.as_str() {
        "sample" => {
            require_exact_keys(
                &values,
                &[
                    "--pid",
                    "--scenario",
                    "--scenario-version",
                    "--build-identity",
                    "--config-sha256",
                    "--samples",
                    "--interval-ms",
                    "--output",
                    "--digest-output",
                ],
            )?;
            let sample_count = parse_positive_usize(&values, "--samples")?;
            let interval_ms = parse_positive_u64(&values, "--interval-ms")?;
            let pid = parse_positive_u64(&values, "--pid")?
                .try_into()
                .map_err(|_| HarnessError::new("memory evidence pid exceeds u32"))?;
            Ok(EvidenceCommand::Sample(SampleEvidenceOptions {
                pid,
                scenario_id: required(&values, "--scenario")?,
                scenario_version: required(&values, "--scenario-version")?,
                build_identity: required(&values, "--build-identity")?,
                config_sha256: required(&values, "--config-sha256")?,
                sample_count,
                interval_ms,
                output: PathBuf::from(required(&values, "--output")?),
                digest_output: PathBuf::from(required(&values, "--digest-output")?),
            }))
        }
        "validate" => {
            require_exact_keys(
                &values,
                &[
                    "--scenario",
                    "--scenario-version",
                    "--build-identity",
                    "--config-sha256",
                    "--report",
                    "--digest",
                ],
            )?;
            Ok(EvidenceCommand::Validate(ValidateEvidenceOptions {
                scenario_id: required(&values, "--scenario")?,
                scenario_version: required(&values, "--scenario-version")?,
                build_identity: required(&values, "--build-identity")?,
                config_sha256: required(&values, "--config-sha256")?,
                report: PathBuf::from(required(&values, "--report")?),
                digest: PathBuf::from(required(&values, "--digest")?),
            }))
        }
        _ => Err(HarnessError::new("memory evidence command is unknown")),
    }
}

pub fn run_evidence_command(command: EvidenceCommand) -> Result<(), HarnessError> {
    match command {
        EvidenceCommand::Sample(options) => collect_attached_process_report(&options),
        EvidenceCommand::Validate(options) => validate_published_report(&options),
    }
}

pub fn collect_attached_process_report(
    options: &SampleEvidenceOptions,
) -> Result<(), HarnessError> {
    validate_identity_inputs(
        &options.scenario_id,
        &options.scenario_version,
        &options.build_identity,
        &options.config_sha256,
    )?;
    if options.sample_count == 0 || options.interval_ms == 0 {
        return Err(HarnessError::new(
            "memory evidence sample count and interval must be positive",
        ));
    }
    let child = attach_process(options.pid)
        .map_err(|_| HarnessError::new("memory evidence process attach failed"))?;
    let mut sampler = PlatformRssSampler;
    let started_at = Instant::now();
    let mut samples = Vec::with_capacity(options.sample_count);
    for index in 0..options.sample_count {
        if !attached_process_is_alive(&child)
            .map_err(|_| HarnessError::new("memory evidence liveness check failed"))?
            || !attached_process_identity_matches(&child)
                .map_err(|_| HarnessError::new("memory evidence identity check failed"))?
        {
            return Err(HarnessError::new(
                "memory evidence process exited or identity changed",
            ));
        }
        samples.push(MemorySample {
            elapsed_ms: if index == 0 {
                0
            } else {
                started_at
                    .elapsed()
                    .as_millis()
                    .try_into()
                    .map_err(|_| HarnessError::new("memory evidence elapsed time exceeds u64"))?
            },
            rss_bytes: sampler
                .sample_rss_bytes(&child)
                .map_err(|_| HarnessError::new("memory evidence RSS sampling failed"))?,
        });
        if index + 1 < options.sample_count {
            thread::sleep(Duration::from_millis(options.interval_ms));
        }
    }
    let report = MemoryEvidenceReport::new(
        EvidenceIdentity {
            scenario_id: options.scenario_id.clone(),
            scenario_version: options.scenario_version.clone(),
            platform: std::env::consts::OS.to_string(),
            architecture: std::env::consts::ARCH.to_string(),
            build_identity: options.build_identity.clone(),
            config_sha256: options.config_sha256.clone(),
            process_start_identity: child.start_identity,
        },
        options.sample_count,
        ScenarioRunRecord {
            state: ScenarioState::Passed,
            outcome: ScenarioOutcome::Passed,
            samples,
            missing_samples: 0,
        },
    )
    .map_err(|_| HarnessError::new("memory evidence report validation failed"))?;
    let published = AtomicReportWriter::publish(&options.output, &report)?;
    publish_digest(&options.digest_output, &published.sha256)
}

pub fn validate_published_report(options: &ValidateEvidenceOptions) -> Result<(), HarnessError> {
    validate_identity_inputs(
        &options.scenario_id,
        &options.scenario_version,
        &options.build_identity,
        &options.config_sha256,
    )?;
    let report = fs::read(&options.report)
        .map_err(|_| HarnessError::new("memory evidence report read failed"))?;
    let digest = fs::read_to_string(&options.digest)
        .map_err(|_| HarnessError::new("memory evidence digest read failed"))?;
    ReportValidator::new(ReportExpectations {
        scenario_id: options.scenario_id.clone(),
        scenario_version: options.scenario_version.clone(),
        build_identity: options.build_identity.clone(),
        config_sha256: options.config_sha256.clone(),
    })
    .validate(&report, digest.trim())
    .map(|_| ())
    .map_err(|_| HarnessError::new("memory evidence independent validation failed"))
}

fn parse_pairs(args: &[String]) -> Result<BTreeMap<String, String>, HarnessError> {
    if !args.len().is_multiple_of(2) {
        return Err(HarnessError::new("memory evidence arguments are invalid"));
    }
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !pair[0].starts_with("--") || values.insert(pair[0].clone(), pair[1].clone()).is_some() {
            return Err(HarnessError::new(
                "memory evidence argument is invalid or duplicated",
            ));
        }
    }
    Ok(values)
}

fn require_exact_keys(
    values: &BTreeMap<String, String>,
    expected: &[&str],
) -> Result<(), HarnessError> {
    if values.len() != expected.len() || expected.iter().any(|key| !values.contains_key(*key)) {
        return Err(HarnessError::new(
            "memory evidence arguments are missing or unknown",
        ));
    }
    Ok(())
}

fn required(values: &BTreeMap<String, String>, key: &str) -> Result<String, HarnessError> {
    values
        .get(key)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| HarnessError::new(format!("memory evidence {key} is missing")))
}

fn parse_positive_usize(
    values: &BTreeMap<String, String>,
    key: &str,
) -> Result<usize, HarnessError> {
    required(values, key)?
        .parse::<usize>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| HarnessError::new(format!("memory evidence {key} must be positive")))
}

fn parse_positive_u64(values: &BTreeMap<String, String>, key: &str) -> Result<u64, HarnessError> {
    required(values, key)?
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| HarnessError::new(format!("memory evidence {key} must be positive")))
}

fn validate_identity_inputs(
    scenario: &str,
    version: &str,
    build: &str,
    config_sha256: &str,
) -> Result<(), HarnessError> {
    if scenario.is_empty()
        || version.is_empty()
        || build.is_empty()
        || config_sha256.len() != 64
        || !config_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(HarnessError::new(
            "memory evidence identity input is invalid",
        ));
    }
    Ok(())
}
