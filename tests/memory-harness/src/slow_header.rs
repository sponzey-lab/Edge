use std::collections::BTreeMap;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::bounded_net::connect_with_deadline;
use crate::HarnessError;

const INCOMPLETE_REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Slow: ";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlowHeaderState {
    Ready,
    Opening,
    Holding,
    Collecting,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlowHeaderResult {
    pub expected: usize,
    pub succeeded: usize,
    pub failed: usize,
}

pub struct SlowHeaderScenario {
    expected: usize,
    max_response_bytes: usize,
    state: SlowHeaderState,
    observed: usize,
    succeeded: usize,
    failed: usize,
}

impl SlowHeaderScenario {
    pub fn new(expected: usize, max_response_bytes: usize) -> Result<Self, HarnessError> {
        if expected == 0 || max_response_bytes == 0 {
            return Err(HarnessError::new("slow header scenario is invalid"));
        }
        Ok(Self {
            expected,
            max_response_bytes,
            state: SlowHeaderState::Ready,
            observed: 0,
            succeeded: 0,
            failed: 0,
        })
    }

    pub fn state(&self) -> SlowHeaderState {
        self.state
    }

    pub fn start_opening(&mut self) -> Result<(), HarnessError> {
        self.transition(SlowHeaderState::Ready, SlowHeaderState::Opening)
    }

    pub fn opened(&mut self, count: usize) -> Result<(), HarnessError> {
        if self.state != SlowHeaderState::Opening || count != self.expected {
            return self.fail("slow header opened count is invalid");
        }
        self.state = SlowHeaderState::Holding;
        Ok(())
    }

    pub fn begin_collecting(&mut self) -> Result<(), HarnessError> {
        self.transition(SlowHeaderState::Holding, SlowHeaderState::Collecting)
    }

    pub fn record_response(
        &mut self,
        status_code: u16,
        response_bytes: usize,
    ) -> Result<(), HarnessError> {
        if self.state != SlowHeaderState::Collecting || self.observed >= self.expected {
            return self.fail("slow header response transition is invalid");
        }
        self.observed += 1;
        if status_code == 408 && response_bytes > 0 && response_bytes <= self.max_response_bytes {
            self.succeeded += 1;
        } else {
            self.failed += 1;
        }
        Ok(())
    }

    pub fn finish(&mut self) -> Result<SlowHeaderResult, HarnessError> {
        if self.state != SlowHeaderState::Collecting || self.observed != self.expected {
            return self.fail("slow header result is incomplete");
        }
        self.state = SlowHeaderState::Completed;
        Ok(SlowHeaderResult {
            expected: self.expected,
            succeeded: self.succeeded,
            failed: self.failed,
        })
    }

    fn transition(
        &mut self,
        expected: SlowHeaderState,
        next: SlowHeaderState,
    ) -> Result<(), HarnessError> {
        if self.state != expected {
            return self.fail("slow header state transition is invalid");
        }
        self.state = next;
        Ok(())
    }

    fn fail<T>(&mut self, message: &str) -> Result<T, HarnessError> {
        self.state = SlowHeaderState::Failed;
        Err(HarnessError::new(message))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlowHeaderOptions {
    pub address: SocketAddr,
    pub connections: usize,
    pub connect_timeout_ms: u64,
    pub terminal_timeout_ms: u64,
    pub max_response_bytes: usize,
    pub ready_output: PathBuf,
}

pub fn parse_slow_header_options(args: &[String]) -> Result<SlowHeaderOptions, HarnessError> {
    const KEYS: [&str; 6] = [
        "--address",
        "--connections",
        "--connect-timeout-ms",
        "--terminal-timeout-ms",
        "--max-response-bytes",
        "--ready-output",
    ];
    if args.len() != KEYS.len() * 2 || !args.len().is_multiple_of(2) {
        return Err(HarnessError::new("slow header arguments are incomplete"));
    }
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !KEYS.contains(&pair[0].as_str())
            || values.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            return Err(HarnessError::new(
                "slow header argument is unknown or duplicated",
            ));
        }
    }
    Ok(SlowHeaderOptions {
        address: required(&values, "--address")?
            .parse()
            .map_err(|_| HarnessError::new("slow header address is invalid"))?,
        connections: positive(&values, "--connections")?
            .try_into()
            .map_err(|_| HarnessError::new("slow header count exceeds usize"))?,
        connect_timeout_ms: positive(&values, "--connect-timeout-ms")?,
        terminal_timeout_ms: positive(&values, "--terminal-timeout-ms")?,
        max_response_bytes: positive(&values, "--max-response-bytes")?
            .try_into()
            .map_err(|_| HarnessError::new("slow header response bound exceeds usize"))?,
        ready_output: PathBuf::from(required(&values, "--ready-output")?),
    })
}

pub fn run_slow_header(options: SlowHeaderOptions) -> Result<String, HarnessError> {
    let mut scenario = SlowHeaderScenario::new(options.connections, options.max_response_bytes)?;
    scenario.start_opening()?;
    let connect_timeout = Duration::from_millis(options.connect_timeout_ms);
    let terminal_timeout = Duration::from_millis(options.terminal_timeout_ms);
    let mut streams = Vec::with_capacity(options.connections);
    while streams.len() < options.connections {
        let mut stream = connect_with_deadline(
            options.address,
            connect_timeout,
            "slow header connect failed",
        )?;
        stream
            .set_write_timeout(Some(connect_timeout))
            .and_then(|_| stream.write_all(INCOMPLETE_REQUEST))
            .map_err(|_| HarnessError::new("slow header request write failed"))?;
        streams.push(stream);
    }
    scenario.opened(streams.len())?;
    publish_ready(&options.ready_output, streams.len())?;
    scenario.begin_collecting()?;
    for mut stream in streams {
        let (status, bytes) =
            read_timeout_response(&mut stream, terminal_timeout, options.max_response_bytes);
        scenario.record_response(status, bytes)?;
    }
    let result = scenario.finish()?;
    Ok(format!(
        "slow header completed expected={} succeeded={} failed={}",
        result.expected, result.succeeded, result.failed
    ))
}

fn read_timeout_response(
    stream: &mut TcpStream,
    timeout: Duration,
    maximum: usize,
) -> (u16, usize) {
    if stream.set_read_timeout(Some(timeout)).is_err() {
        return (0, 0);
    }
    let mut response = Vec::new();
    let mut buffer = [0_u8; 512];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) if response.len().saturating_add(read) <= maximum => {
                response.extend_from_slice(&buffer[..read]);
            }
            Ok(read) => return (0, maximum.saturating_add(read)),
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
                ) =>
            {
                break;
            }
            Err(_) => return (0, response.len()),
        }
    }
    (parse_status(&response), response.len())
}

fn parse_status(response: &[u8]) -> u16 {
    std::str::from_utf8(response)
        .ok()
        .and_then(|text| text.lines().next())
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

fn publish_ready(path: &Path, count: usize) -> Result<(), HarnessError> {
    let parent = path
        .parent()
        .ok_or_else(|| HarnessError::new("slow header ready path has no parent"))?;
    fs::create_dir_all(parent)
        .and_then(|_| fs::write(path, format!("{count}\n")))
        .map_err(|_| HarnessError::new("slow header ready publish failed"))
}

fn positive(values: &BTreeMap<String, String>, key: &str) -> Result<u64, HarnessError> {
    let value = required(values, key)?
        .parse::<u64>()
        .map_err(|_| HarnessError::new("slow header numeric argument is invalid"))?;
    if value == 0 {
        return Err(HarnessError::new(
            "slow header numeric argument must be positive",
        ));
    }
    Ok(value)
}

fn required(values: &BTreeMap<String, String>, key: &str) -> Result<String, HarnessError> {
    values
        .get(key)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| HarnessError::new(format!("slow header argument is missing: {key}")))
}
