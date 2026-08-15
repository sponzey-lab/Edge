use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use crate::http_driver::{HttpLoadDriver, HttpLoadSpec};
use crate::release_http_scenario::{
    AdminStatusHttpProbe, AttachedProcessObservation, ReleaseHttpScenarioRecord,
    ReleaseHttpScenarioRunner, ReleaseHttpScenarioSpec, ReleaseScenarioOutcome, ThreadDelay,
};
use crate::HarnessError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseHttpOptions {
    pub pid: u32,
    pub proxy_address: SocketAddr,
    pub admin_address: SocketAddr,
    pub host: String,
    pub request_count: usize,
    pub timeout_ms: u64,
    pub max_response_bytes: usize,
    pub expected_revision: String,
    pub ceiling_bytes: u64,
    pub cooldown_cycles: usize,
    pub cooldown_interval_ms: u64,
}

pub fn parse_release_http_options(args: &[String]) -> Result<ReleaseHttpOptions, HarnessError> {
    const KEYS: [&str; 11] = [
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
    if args.len() != KEYS.len() * 2 || !args.len().is_multiple_of(2) {
        return Err(HarnessError::new(
            "release HTTP scenario arguments are incomplete",
        ));
    }
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !KEYS.contains(&pair[0].as_str())
            || values.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            return Err(HarnessError::new(
                "release HTTP scenario argument is unknown or duplicated",
            ));
        }
    }
    Ok(ReleaseHttpOptions {
        pid: positive_u64(&values, "--pid")?
            .try_into()
            .map_err(|_| HarnessError::new("release HTTP PID exceeds u32"))?,
        proxy_address: socket_address(&values, "--proxy-address")?,
        admin_address: socket_address(&values, "--admin-address")?,
        host: nonempty(&values, "--host")?,
        request_count: positive_u64(&values, "--requests")?
            .try_into()
            .map_err(|_| HarnessError::new("release HTTP request count exceeds usize"))?,
        timeout_ms: positive_u64(&values, "--timeout-ms")?,
        max_response_bytes: positive_u64(&values, "--max-response-bytes")?
            .try_into()
            .map_err(|_| HarnessError::new("release HTTP response bound exceeds usize"))?,
        expected_revision: nonempty(&values, "--expected-revision")?,
        ceiling_bytes: positive_u64(&values, "--ceiling-bytes")?,
        cooldown_cycles: positive_u64(&values, "--cooldown-cycles")?
            .try_into()
            .map_err(|_| HarnessError::new("release HTTP cooldown cycles exceed usize"))?,
        cooldown_interval_ms: positive_u64(&values, "--cooldown-interval-ms")?,
    })
}

pub fn run_release_http_scenario(options: ReleaseHttpOptions) -> Result<String, HarnessError> {
    let executed = execute_release_http_scenario(options)?;
    summarize_passed_record(executed.record)
}

pub struct ExecutedReleaseHttpScenario {
    pub record: ReleaseHttpScenarioRecord,
    pub process_start_identity: String,
}

pub fn execute_release_http_scenario(
    options: ReleaseHttpOptions,
) -> Result<ExecutedReleaseHttpScenario, HarnessError> {
    let timeout = Duration::from_millis(options.timeout_ms);
    let load = HttpLoadDriver::new(HttpLoadSpec::new(
        options.proxy_address,
        options.host,
        options.request_count,
        timeout,
        options.max_response_bytes,
    )?);
    let status =
        AdminStatusHttpProbe::new(options.admin_address, timeout, options.max_response_bytes)?;
    let process = AttachedProcessObservation::attach(options.pid)?;
    let process_start_identity = process.start_identity().to_string();
    let spec = ReleaseHttpScenarioSpec::new(
        options.expected_revision,
        options
            .request_count
            .try_into()
            .map_err(|_| HarnessError::new("release HTTP request count exceeds u64"))?,
        options.ceiling_bytes,
        options.cooldown_cycles,
        options.cooldown_interval_ms,
    )?;
    let mut runner = ReleaseHttpScenarioRunner::new(process, load, status, ThreadDelay::new());
    let record = runner.run(&spec);
    Ok(ExecutedReleaseHttpScenario {
        record,
        process_start_identity,
    })
}

fn summarize_passed_record(record: ReleaseHttpScenarioRecord) -> Result<String, HarnessError> {
    if record.outcome != ReleaseScenarioOutcome::Passed {
        return Err(HarnessError::new(
            "release HTTP scenario did not pass acceptance",
        ));
    }
    let counters = record
        .counters
        .ok_or_else(|| HarnessError::new("release HTTP counters are missing"))?;
    let runtime = record
        .runtime_status
        .ok_or_else(|| HarnessError::new("release HTTP runtime status is missing"))?;
    let observation = record
        .observation
        .ok_or_else(|| HarnessError::new("release HTTP observation is missing"))?;
    let first_cooldown = record
        .samples
        .get(2)
        .map(|sample| sample.rss_bytes)
        .ok_or_else(|| HarnessError::new("release HTTP cooldown samples are missing"))?;
    let last_cooldown = record
        .samples
        .last()
        .map(|sample| sample.rss_bytes)
        .ok_or_else(|| HarnessError::new("release HTTP samples are missing"))?;
    Ok(format!(
        "release HTTP scenario passed expected={} succeeded={} failed={} peak_rss_bytes={} first_cooldown_rss_bytes={} last_cooldown_rss_bytes={} active_connections={} used_payload_bytes={} revision={}",
        counters.expected,
        counters.succeeded,
        counters.failed,
        observation.peak_rss_bytes,
        first_cooldown,
        last_cooldown,
        runtime.active_connections,
        runtime.used_payload_bytes,
        runtime.revision_id
    ))
}

fn positive_u64(values: &BTreeMap<String, String>, key: &str) -> Result<u64, HarnessError> {
    let value = nonempty(values, key)?
        .parse::<u64>()
        .map_err(|_| HarnessError::new("release HTTP numeric argument is invalid"))?;
    if value == 0 {
        return Err(HarnessError::new(
            "release HTTP numeric argument must be positive",
        ));
    }
    Ok(value)
}

fn socket_address(
    values: &BTreeMap<String, String>,
    key: &str,
) -> Result<SocketAddr, HarnessError> {
    nonempty(values, key)?
        .parse()
        .map_err(|_| HarnessError::new("release HTTP socket address is invalid"))
}

fn nonempty(values: &BTreeMap<String, String>, key: &str) -> Result<String, HarnessError> {
    let value = values
        .get(key)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| HarnessError::new(format!("release HTTP argument is missing: {key}")))?;
    Ok(value.clone())
}
