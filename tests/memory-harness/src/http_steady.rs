use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::http_driver::{execute_request, HttpLoadCounters, HttpLoadSpec};
use crate::report_io::publish_canonical_bytes;
use crate::HarnessError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SteadyLoadSpec {
    address: SocketAddr,
    host: String,
    total_requests: usize,
    workers: usize,
    timeout: Duration,
    max_response_bytes: usize,
}

impl SteadyLoadSpec {
    pub fn new(
        address: SocketAddr,
        host: impl Into<String>,
        total_requests: usize,
        workers: usize,
        timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<Self, HarnessError> {
        let host = host.into();
        if host.is_empty()
            || total_requests == 0
            || workers == 0
            || workers > total_requests
            || !total_requests.is_multiple_of(workers)
            || timeout.is_zero()
            || max_response_bytes == 0
        {
            return Err(HarnessError::new(
                "HTTP steady load specification is invalid",
            ));
        }
        HttpLoadSpec::new(
            address,
            host.clone(),
            total_requests / workers,
            timeout,
            max_response_bytes,
        )?;
        Ok(Self {
            address,
            host,
            total_requests,
            workers,
            timeout,
            max_response_bytes,
        })
    }

    fn request_spec(&self) -> Result<HttpLoadSpec, HarnessError> {
        HttpLoadSpec::new(
            self.address,
            self.host.clone(),
            1,
            self.timeout,
            self.max_response_bytes,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SteadyLoadState {
    Created,
    Warming,
    Loading,
    Cooling,
    Completed,
    Failed,
}

pub struct SteadyHttpLoadDriver {
    spec: SteadyLoadSpec,
    state: SteadyLoadState,
}

impl SteadyHttpLoadDriver {
    pub fn new(spec: SteadyLoadSpec) -> Self {
        Self {
            spec,
            state: SteadyLoadState::Created,
        }
    }

    pub fn state(&self) -> SteadyLoadState {
        self.state
    }

    pub fn run(&mut self) -> Result<HttpLoadCounters, HarnessError> {
        if self.state != SteadyLoadState::Created {
            self.state = SteadyLoadState::Failed;
            return Err(HarnessError::new(
                "HTTP steady load lifecycle transition is invalid",
            ));
        }
        self.state = SteadyLoadState::Warming;
        let request_spec = self.spec.request_spec()?;
        let requests_per_worker = self.spec.total_requests / self.spec.workers;
        let start_barrier = Arc::new(Barrier::new(self.spec.workers + 1));
        let results = std::thread::scope(|scope| {
            let handles = (0..self.spec.workers)
                .map(|_| {
                    let spec = request_spec.clone();
                    let start_barrier = Arc::clone(&start_barrier);
                    scope.spawn(move || {
                        start_barrier.wait();
                        run_worker(&spec, requests_per_worker)
                    })
                })
                .collect::<Vec<_>>();
            self.state = SteadyLoadState::Loading;
            start_barrier.wait();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .map_err(|_| HarnessError::new("HTTP steady worker panicked"))
                })
                .collect::<Result<Vec<_>, HarnessError>>()
        });
        let results = match results {
            Ok(results) => results,
            Err(error) => {
                self.state = SteadyLoadState::Failed;
                return Err(error);
            }
        };
        self.state = SteadyLoadState::Cooling;
        let mut counters = HttpLoadCounters {
            expected: self.spec.total_requests as u64,
            succeeded: 0,
            failed: 0,
        };
        for result in results {
            counters.succeeded = counters
                .succeeded
                .checked_add(result.succeeded)
                .ok_or_else(|| HarnessError::new("HTTP steady success count overflow"))?;
            counters.failed = counters
                .failed
                .checked_add(result.failed)
                .ok_or_else(|| HarnessError::new("HTTP steady failure count overflow"))?;
        }
        let exact = counters.succeeded.checked_add(counters.failed) == Some(counters.expected)
            && counters.expected == self.spec.total_requests as u64;
        self.state = if exact && counters.failed == 0 {
            SteadyLoadState::Completed
        } else {
            SteadyLoadState::Failed
        };
        if !exact {
            return Err(HarnessError::new("HTTP steady aggregate count mismatch"));
        }
        Ok(counters)
    }
}

fn run_worker(spec: &HttpLoadSpec, requests: usize) -> HttpLoadCounters {
    let mut counters = HttpLoadCounters {
        expected: requests as u64,
        succeeded: 0,
        failed: 0,
    };
    for _ in 0..requests {
        match execute_request(spec) {
            Ok(()) => counters.succeeded += 1,
            Err(_) => counters.failed += 1,
        }
    }
    counters
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SteadyCliOptions {
    pub address: SocketAddr,
    pub host: String,
    pub requests: usize,
    pub workers: usize,
    pub timeout_ms: u64,
    pub max_response_bytes: usize,
    pub ready_output: PathBuf,
    pub start_file: PathBuf,
    pub summary_output: PathBuf,
    pub start_timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SteadyLoadSummary {
    pub schema_version: u16,
    pub expected: u64,
    pub succeeded: u64,
    pub failed: u64,
    pub workers: usize,
    pub state: String,
}

pub fn parse_steady_options(args: &[String]) -> Result<SteadyCliOptions, HarnessError> {
    const KEYS: [&str; 10] = [
        "--address",
        "--host",
        "--requests",
        "--workers",
        "--timeout-ms",
        "--max-response-bytes",
        "--ready-output",
        "--start-file",
        "--summary-output",
        "--start-timeout-ms",
    ];
    if args.len() != KEYS.len() * 2 {
        return Err(HarnessError::new("HTTP steady options are incomplete"));
    }
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !KEYS.contains(&pair[0].as_str())
            || pair[1].is_empty()
            || values.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            return Err(HarnessError::new(
                "HTTP steady option is unknown or duplicated",
            ));
        }
    }
    let address = required(&values, "--address")?
        .parse()
        .map_err(|_| HarnessError::new("HTTP steady address is invalid"))?;
    let host = required(&values, "--host")?;
    let requests = positive_usize(&values, "--requests")?;
    let workers = positive_usize(&values, "--workers")?;
    let timeout_ms = positive_u64(&values, "--timeout-ms")?;
    let max_response_bytes = positive_usize(&values, "--max-response-bytes")?;
    let start_timeout_ms = positive_u64(&values, "--start-timeout-ms")?;
    SteadyLoadSpec::new(
        address,
        host.clone(),
        requests,
        workers,
        Duration::from_millis(timeout_ms),
        max_response_bytes,
    )?;
    Ok(SteadyCliOptions {
        address,
        host,
        requests,
        workers,
        timeout_ms,
        max_response_bytes,
        ready_output: PathBuf::from(required(&values, "--ready-output")?),
        start_file: PathBuf::from(required(&values, "--start-file")?),
        summary_output: PathBuf::from(required(&values, "--summary-output")?),
        start_timeout_ms,
    })
}

pub fn run_steady_options(options: SteadyCliOptions) -> Result<String, HarnessError> {
    if options.start_file.exists() {
        return Err(HarnessError::new(
            "HTTP steady start file exists before readiness",
        ));
    }
    publish_canonical_bytes(
        &options.ready_output,
        format!("{} {}\n", options.requests, options.workers).as_bytes(),
    )?;
    let deadline = Instant::now() + Duration::from_millis(options.start_timeout_ms);
    while !options.start_file.exists() {
        if Instant::now() >= deadline {
            return Err(HarnessError::new("HTTP steady start wait timed out"));
        }
        thread::sleep(Duration::from_millis(10));
    }
    let spec = SteadyLoadSpec::new(
        options.address,
        options.host,
        options.requests,
        options.workers,
        Duration::from_millis(options.timeout_ms),
        options.max_response_bytes,
    )?;
    let mut driver = SteadyHttpLoadDriver::new(spec);
    let counters = driver.run()?;
    let summary = SteadyLoadSummary {
        schema_version: 1,
        expected: counters.expected,
        succeeded: counters.succeeded,
        failed: counters.failed,
        workers: options.workers,
        state: match driver.state() {
            SteadyLoadState::Completed => "completed",
            SteadyLoadState::Failed => "failed",
            _ => "invalid",
        }
        .into(),
    };
    let encoded = serde_json::to_vec(&summary)
        .map_err(|_| HarnessError::new("HTTP steady summary encoding failed"))?;
    publish_canonical_bytes(&options.summary_output, &encoded)?;
    if summary.failed != 0 || summary.succeeded != summary.expected {
        return Err(HarnessError::new(format!(
            "HTTP steady load did not fully succeed: expected={} succeeded={} failed={}",
            summary.expected, summary.succeeded, summary.failed
        )));
    }
    Ok(format!(
        "HTTP steady completed expected={} succeeded={} failed={} workers={}",
        summary.expected, summary.succeeded, summary.failed, summary.workers
    ))
}

fn required(values: &BTreeMap<String, String>, key: &str) -> Result<String, HarnessError> {
    values
        .get(key)
        .cloned()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| HarnessError::new(format!("HTTP steady {key} is missing")))
}

fn positive_usize(values: &BTreeMap<String, String>, key: &str) -> Result<usize, HarnessError> {
    required(values, key)?
        .parse::<usize>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| HarnessError::new(format!("HTTP steady {key} is invalid")))
}

fn positive_u64(values: &BTreeMap<String, String>, key: &str) -> Result<u64, HarnessError> {
    required(values, key)?
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| HarnessError::new(format!("HTTP steady {key} is invalid")))
}
