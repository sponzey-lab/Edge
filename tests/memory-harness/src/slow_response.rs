use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use socket2::SockRef;

use crate::bounded_net::connect_with_deadline;
use crate::HarnessError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlowResponseSpec {
    address: SocketAddr,
    host: String,
    maximum_connections: usize,
    timeout: Duration,
    max_header_bytes: usize,
    receive_buffer_bytes: usize,
}

impl SlowResponseSpec {
    pub fn new(
        address: SocketAddr,
        host: impl Into<String>,
        maximum_connections: usize,
        timeout: Duration,
        max_header_bytes: usize,
        receive_buffer_bytes: usize,
    ) -> Result<Self, HarnessError> {
        let host = host.into();
        if host.is_empty()
            || maximum_connections == 0
            || timeout.is_zero()
            || max_header_bytes == 0
            || max_header_bytes > 16 * 1024
            || receive_buffer_bytes == 0
        {
            return Err(HarnessError::new("slow response specification is invalid"));
        }
        Ok(Self {
            address,
            host,
            maximum_connections,
            timeout,
            max_header_bytes,
            receive_buffer_bytes,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlowResponseState {
    Ready,
    Ramping,
    Holding,
    Releasing,
    Completed,
    Failed,
}

pub struct SlowResponseHolder {
    spec: SlowResponseSpec,
    state: SlowResponseState,
    streams: Vec<TcpStream>,
}

impl SlowResponseHolder {
    pub fn new(spec: SlowResponseSpec) -> Self {
        Self {
            streams: Vec::with_capacity(spec.maximum_connections),
            spec,
            state: SlowResponseState::Ready,
        }
    }

    pub fn state(&self) -> SlowResponseState {
        self.state
    }

    pub fn held_count(&self) -> usize {
        self.streams.len()
    }

    pub fn ramp_to(&mut self, target: usize) -> Result<(), HarnessError> {
        if !matches!(
            self.state,
            SlowResponseState::Ready | SlowResponseState::Holding
        ) || target <= self.streams.len()
            || target > self.spec.maximum_connections
        {
            return self.fail("slow response ramp transition is invalid");
        }
        self.state = SlowResponseState::Ramping;
        while self.streams.len() < target {
            match open_slow_reader(&self.spec) {
                Ok(stream) => self.streams.push(stream),
                Err(error) => {
                    self.close_all();
                    self.state = SlowResponseState::Failed;
                    return Err(error);
                }
            }
        }
        self.state = SlowResponseState::Holding;
        Ok(())
    }

    pub fn release(&mut self) -> Result<usize, HarnessError> {
        if self.state != SlowResponseState::Holding {
            return self.fail("slow response release transition is invalid");
        }
        self.state = SlowResponseState::Releasing;
        let released = self.streams.len();
        self.close_all();
        self.state = SlowResponseState::Completed;
        Ok(released)
    }

    fn close_all(&mut self) {
        for stream in self.streams.drain(..) {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    fn fail<T>(&mut self, message: &str) -> Result<T, HarnessError> {
        self.close_all();
        self.state = SlowResponseState::Failed;
        Err(HarnessError::new(message))
    }
}

fn open_slow_reader(spec: &SlowResponseSpec) -> Result<TcpStream, HarnessError> {
    let mut stream = connect_with_deadline(
        spec.address,
        spec.timeout,
        "slow response connection failed",
    )?;
    stream
        .set_read_timeout(Some(spec.timeout))
        .and_then(|_| stream.set_write_timeout(Some(spec.timeout)))
        .map_err(|_| HarnessError::new("slow response timeout setup failed"))?;
    SockRef::from(&stream)
        .set_recv_buffer_size(spec.receive_buffer_bytes)
        .map_err(|_| HarnessError::new("slow response receive buffer setup failed"))?;
    let request = format!(
        "GET /slow-response HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        spec.host
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|_| HarnessError::new("slow response request write failed"))?;
    let headers = read_headers(&mut stream, spec.max_header_bytes)?;
    validate_response_headers(&headers)?;
    Ok(stream)
}

fn read_headers(stream: &mut TcpStream, maximum: usize) -> Result<Vec<u8>, HarnessError> {
    let mut headers = Vec::with_capacity(maximum.min(1024));
    let mut byte = [0_u8; 1];
    while !headers.ends_with(b"\r\n\r\n") {
        if headers.len() >= maximum {
            return Err(HarnessError::new("slow response headers exceed bound"));
        }
        let read = stream
            .read(&mut byte)
            .map_err(|_| HarnessError::new("slow response headers read failed"))?;
        if read == 0 {
            return Err(HarnessError::new("slow response headers are incomplete"));
        }
        headers.push(byte[0]);
    }
    Ok(headers)
}

fn validate_response_headers(headers: &[u8]) -> Result<(), HarnessError> {
    let text = std::str::from_utf8(headers)
        .map_err(|_| HarnessError::new("slow response headers are invalid"))?;
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| HarnessError::new("slow response status is invalid"))?;
    let lengths = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then_some(value.trim())
        })
        .collect::<Vec<_>>();
    if status != 200 || lengths.len() != 1 {
        return Err(HarnessError::new(
            "slow response status or length is invalid",
        ));
    }
    let length = lengths[0]
        .parse::<u64>()
        .map_err(|_| HarnessError::new("slow response length is invalid"))?;
    if length == 0 {
        return Err(HarnessError::new("slow response length must be positive"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlowResponseOptions {
    pub address: SocketAddr,
    pub host: String,
    pub connections: usize,
    pub timeout_ms: u64,
    pub hold_timeout_ms: u64,
    pub max_header_bytes: usize,
    pub receive_buffer_bytes: usize,
    pub ready_output: PathBuf,
    pub stop_file: PathBuf,
}

pub fn parse_slow_response_options(args: &[String]) -> Result<SlowResponseOptions, HarnessError> {
    const KEYS: [&str; 9] = [
        "--address",
        "--host",
        "--connections",
        "--timeout-ms",
        "--hold-timeout-ms",
        "--max-header-bytes",
        "--receive-buffer-bytes",
        "--ready-output",
        "--stop-file",
    ];
    if args.len() != KEYS.len() * 2 || !args.len().is_multiple_of(2) {
        return Err(HarnessError::new("slow response arguments are incomplete"));
    }
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !KEYS.contains(&pair[0].as_str())
            || values.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            return Err(HarnessError::new(
                "slow response argument is unknown or duplicated",
            ));
        }
    }
    Ok(SlowResponseOptions {
        address: required(&values, "--address")?
            .parse()
            .map_err(|_| HarnessError::new("slow response address is invalid"))?,
        host: required(&values, "--host")?,
        connections: positive_usize(&values, "--connections")?,
        timeout_ms: positive(&values, "--timeout-ms")?,
        hold_timeout_ms: positive(&values, "--hold-timeout-ms")?,
        max_header_bytes: positive_usize(&values, "--max-header-bytes")?,
        receive_buffer_bytes: positive_usize(&values, "--receive-buffer-bytes")?,
        ready_output: PathBuf::from(required(&values, "--ready-output")?),
        stop_file: PathBuf::from(required(&values, "--stop-file")?),
    })
}

pub fn run_slow_response(options: SlowResponseOptions) -> Result<String, HarnessError> {
    let spec = SlowResponseSpec::new(
        options.address,
        options.host,
        options.connections,
        Duration::from_millis(options.timeout_ms),
        options.max_header_bytes,
        options.receive_buffer_bytes,
    )?;
    let mut holder = SlowResponseHolder::new(spec);
    for target in [32, 64, 128, options.connections]
        .into_iter()
        .filter(|target| *target <= options.connections)
    {
        if target > holder.held_count() {
            holder.ramp_to(target)?;
        }
    }
    publish_ready(&options.ready_output, holder.held_count())?;
    let deadline = Instant::now() + Duration::from_millis(options.hold_timeout_ms);
    while !options.stop_file.exists() {
        if Instant::now() >= deadline {
            let _ = holder.release();
            return Err(HarnessError::new("slow response stop deadline exceeded"));
        }
        thread::sleep(Duration::from_millis(50));
    }
    let released = holder.release()?;
    Ok(format!(
        "slow response released held={} released={} remaining={}",
        options.connections,
        released,
        holder.held_count()
    ))
}

fn publish_ready(path: &Path, count: usize) -> Result<(), HarnessError> {
    let parent = path
        .parent()
        .ok_or_else(|| HarnessError::new("slow response ready path has no parent"))?;
    fs::create_dir_all(parent)
        .and_then(|_| fs::write(path, format!("{count}\n")))
        .map_err(|_| HarnessError::new("slow response ready publish failed"))
}

fn positive_usize(values: &BTreeMap<String, String>, key: &str) -> Result<usize, HarnessError> {
    positive(values, key)?
        .try_into()
        .map_err(|_| HarnessError::new("slow response value exceeds usize"))
}

fn positive(values: &BTreeMap<String, String>, key: &str) -> Result<u64, HarnessError> {
    required(values, key)?
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| HarnessError::new("slow response value must be positive"))
}

fn required(values: &BTreeMap<String, String>, key: &str) -> Result<String, HarnessError> {
    values
        .get(key)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| HarnessError::new(format!("slow response argument is missing: {key}")))
}
