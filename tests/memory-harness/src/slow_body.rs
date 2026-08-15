use std::collections::BTreeMap;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::bounded_net::connect_with_deadline;
use crate::HarnessError;

const MAX_DECLARED_BODY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlowBodyState {
    Ready,
    Opening,
    Holding,
    Collecting,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlowBodyResult {
    pub expected: usize,
    pub succeeded: usize,
    pub failed: usize,
}

pub struct SlowBodyScenario {
    expected: usize,
    max_response_bytes: usize,
    state: SlowBodyState,
    observed: usize,
    succeeded: usize,
    failed: usize,
}

impl SlowBodyScenario {
    pub fn new(expected: usize, max_response_bytes: usize) -> Result<Self, HarnessError> {
        if expected == 0 || max_response_bytes == 0 {
            return Err(HarnessError::new("slow body scenario is invalid"));
        }
        Ok(Self {
            expected,
            max_response_bytes,
            state: SlowBodyState::Ready,
            observed: 0,
            succeeded: 0,
            failed: 0,
        })
    }

    pub fn state(&self) -> SlowBodyState {
        self.state
    }

    pub fn start_opening(&mut self) -> Result<(), HarnessError> {
        self.transition(SlowBodyState::Ready, SlowBodyState::Opening)
    }

    pub fn opened(&mut self, count: usize) -> Result<(), HarnessError> {
        if self.state != SlowBodyState::Opening || count != self.expected {
            return self.fail("slow body opened count is invalid");
        }
        self.state = SlowBodyState::Holding;
        Ok(())
    }

    pub fn begin_collecting(&mut self) -> Result<(), HarnessError> {
        self.transition(SlowBodyState::Holding, SlowBodyState::Collecting)
    }

    pub fn record_response(
        &mut self,
        status_code: u16,
        response_bytes: usize,
    ) -> Result<(), HarnessError> {
        if self.state != SlowBodyState::Collecting || self.observed >= self.expected {
            return self.fail("slow body response transition is invalid");
        }
        self.observed += 1;
        if status_code == 408 && response_bytes > 0 && response_bytes <= self.max_response_bytes {
            self.succeeded += 1;
        } else {
            self.failed += 1;
        }
        Ok(())
    }

    pub fn finish(&mut self) -> Result<SlowBodyResult, HarnessError> {
        if self.state != SlowBodyState::Collecting || self.observed != self.expected {
            return self.fail("slow body result is incomplete");
        }
        self.state = SlowBodyState::Completed;
        Ok(SlowBodyResult {
            expected: self.expected,
            succeeded: self.succeeded,
            failed: self.failed,
        })
    }

    fn transition(
        &mut self,
        expected: SlowBodyState,
        next: SlowBodyState,
    ) -> Result<(), HarnessError> {
        if self.state != expected {
            return self.fail("slow body state transition is invalid");
        }
        self.state = next;
        Ok(())
    }

    fn fail<T>(&mut self, message: &str) -> Result<T, HarnessError> {
        self.state = SlowBodyState::Failed;
        Err(HarnessError::new(message))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlowBodyOptions {
    pub address: SocketAddr,
    pub connections: usize,
    pub declared_body_bytes: usize,
    pub sent_body_bytes: usize,
    pub connect_timeout_ms: u64,
    pub terminal_timeout_ms: u64,
    pub max_response_bytes: usize,
    pub ready_output: PathBuf,
}

pub fn parse_slow_body_options(args: &[String]) -> Result<SlowBodyOptions, HarnessError> {
    const KEYS: [&str; 8] = [
        "--address",
        "--connections",
        "--declared-body-bytes",
        "--sent-body-bytes",
        "--connect-timeout-ms",
        "--terminal-timeout-ms",
        "--max-response-bytes",
        "--ready-output",
    ];
    if args.len() != KEYS.len() * 2 || !args.len().is_multiple_of(2) {
        return Err(HarnessError::new("slow body arguments are incomplete"));
    }
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !KEYS.contains(&pair[0].as_str())
            || values.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            return Err(HarnessError::new(
                "slow body argument is unknown or duplicated",
            ));
        }
    }
    let declared_body_bytes = positive_usize(&values, "--declared-body-bytes")?;
    let sent_body_bytes = positive_usize(&values, "--sent-body-bytes")?;
    if declared_body_bytes > MAX_DECLARED_BODY_BYTES || sent_body_bytes >= declared_body_bytes {
        return Err(HarnessError::new("slow body size relation is invalid"));
    }
    Ok(SlowBodyOptions {
        address: required(&values, "--address")?
            .parse()
            .map_err(|_| HarnessError::new("slow body address is invalid"))?,
        connections: positive_usize(&values, "--connections")?,
        declared_body_bytes,
        sent_body_bytes,
        connect_timeout_ms: positive(&values, "--connect-timeout-ms")?,
        terminal_timeout_ms: positive(&values, "--terminal-timeout-ms")?,
        max_response_bytes: positive_usize(&values, "--max-response-bytes")?,
        ready_output: PathBuf::from(required(&values, "--ready-output")?),
    })
}

pub fn run_slow_body(options: SlowBodyOptions) -> Result<String, HarnessError> {
    let mut scenario = SlowBodyScenario::new(options.connections, options.max_response_bytes)?;
    let request = partial_request(options.declared_body_bytes, options.sent_body_bytes);
    scenario.start_opening()?;
    let connect_timeout = Duration::from_millis(options.connect_timeout_ms);
    let terminal_timeout = Duration::from_millis(options.terminal_timeout_ms);
    let mut streams = Vec::with_capacity(options.connections);
    while streams.len() < options.connections {
        let mut stream =
            connect_with_deadline(options.address, connect_timeout, "slow body connect failed")?;
        stream
            .set_write_timeout(Some(connect_timeout))
            .and_then(|_| stream.write_all(&request))
            .map_err(|_| HarnessError::new("slow body request write failed"))?;
        streams.push(stream);
    }
    scenario.opened(streams.len())?;
    publish_ready(
        &options.ready_output,
        streams.len(),
        options.sent_body_bytes,
    )?;
    scenario.begin_collecting()?;
    for mut stream in streams {
        let (status, bytes) =
            read_timeout_response(&mut stream, terminal_timeout, options.max_response_bytes);
        scenario.record_response(status, bytes)?;
    }
    let result = scenario.finish()?;
    Ok(format!(
        "slow body completed expected={} succeeded={} failed={}",
        result.expected, result.succeeded, result.failed
    ))
}

fn partial_request(declared_body_bytes: usize, sent_body_bytes: usize) -> Vec<u8> {
    let header = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {declared_body_bytes}\r\nConnection: close\r\n\r\n"
    );
    let mut request = Vec::with_capacity(header.len() + sent_body_bytes);
    request.extend_from_slice(header.as_bytes());
    request.resize(header.len() + sent_body_bytes, b'x');
    request
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

fn publish_ready(path: &Path, count: usize, sent_body_bytes: usize) -> Result<(), HarnessError> {
    let parent = path
        .parent()
        .ok_or_else(|| HarnessError::new("slow body ready path has no parent"))?;
    fs::create_dir_all(parent)
        .and_then(|_| fs::write(path, format!("{count} {sent_body_bytes}\n")))
        .map_err(|_| HarnessError::new("slow body ready publish failed"))
}

fn positive_usize(values: &BTreeMap<String, String>, key: &str) -> Result<usize, HarnessError> {
    positive(values, key)?
        .try_into()
        .map_err(|_| HarnessError::new("slow body numeric argument exceeds usize"))
}

fn positive(values: &BTreeMap<String, String>, key: &str) -> Result<u64, HarnessError> {
    let value = required(values, key)?
        .parse::<u64>()
        .map_err(|_| HarnessError::new("slow body numeric argument is invalid"))?;
    if value == 0 {
        return Err(HarnessError::new(
            "slow body numeric argument must be positive",
        ));
    }
    Ok(value)
}

fn required(values: &BTreeMap<String, String>, key: &str) -> Result<String, HarnessError> {
    values
        .get(key)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| HarnessError::new(format!("slow body argument is missing: {key}")))
}
