use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use crate::bounded_net::connect_with_deadline;
use crate::HarnessError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionHolderSpec {
    address: SocketAddr,
    maximum_connections: usize,
    timeout: Duration,
}

impl ConnectionHolderSpec {
    pub fn new(
        address: SocketAddr,
        maximum_connections: usize,
        timeout: Duration,
    ) -> Result<Self, HarnessError> {
        if maximum_connections == 0 || timeout.is_zero() {
            return Err(HarnessError::new(
                "connection holder specification is invalid",
            ));
        }
        Ok(Self {
            address,
            maximum_connections,
            timeout,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionHolderState {
    Ready,
    Ramping,
    Held,
    Releasing,
    Released,
    Failed,
}

pub struct ConnectionHolder {
    spec: ConnectionHolderSpec,
    state: ConnectionHolderState,
    streams: Vec<TcpStream>,
}

impl ConnectionHolder {
    pub fn new(spec: ConnectionHolderSpec) -> Self {
        Self {
            streams: Vec::with_capacity(spec.maximum_connections),
            spec,
            state: ConnectionHolderState::Ready,
        }
    }

    pub fn state(&self) -> ConnectionHolderState {
        self.state
    }

    pub fn held_count(&self) -> usize {
        self.streams.len()
    }

    pub fn ramp_to(&mut self, target: usize) -> Result<(), HarnessError> {
        if !matches!(
            self.state,
            ConnectionHolderState::Ready | ConnectionHolderState::Held
        ) || target <= self.streams.len()
            || target > self.spec.maximum_connections
        {
            return self.fail("connection holder ramp transition is invalid");
        }
        self.state = ConnectionHolderState::Ramping;
        while self.streams.len() < target {
            let result = connect_with_deadline(
                self.spec.address,
                self.spec.timeout,
                "connection holder connect failed",
            )
            .and_then(|mut stream| {
                stream
                    .set_write_timeout(Some(self.spec.timeout))
                    .and_then(|_| stream.write_all(b"G"))
                    .map_err(|_| HarnessError::new("connection holder write failed"))?;
                Ok(stream)
            });
            match result {
                Ok(stream) => self.streams.push(stream),
                Err(error) => {
                    self.streams.clear();
                    self.state = ConnectionHolderState::Failed;
                    return Err(error);
                }
            }
        }
        self.state = ConnectionHolderState::Held;
        Ok(())
    }

    pub fn release(&mut self) -> Result<(), HarnessError> {
        if self.state != ConnectionHolderState::Held {
            return self.fail("connection holder release transition is invalid");
        }
        self.state = ConnectionHolderState::Releasing;
        self.streams.clear();
        self.state = ConnectionHolderState::Released;
        Ok(())
    }

    fn fail<T>(&mut self, message: &str) -> Result<T, HarnessError> {
        self.streams.clear();
        self.state = ConnectionHolderState::Failed;
        Err(HarnessError::new(message))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionHolderOptions {
    pub address: SocketAddr,
    pub connection_count: usize,
    pub timeout_ms: u64,
    pub hold_timeout_ms: u64,
    pub ready_output: PathBuf,
    pub stop_file: PathBuf,
}

pub fn parse_connection_holder_options(
    args: &[String],
) -> Result<ConnectionHolderOptions, HarnessError> {
    const KEYS: [&str; 6] = [
        "--address",
        "--connections",
        "--timeout-ms",
        "--hold-timeout-ms",
        "--ready-output",
        "--stop-file",
    ];
    if args.len() != KEYS.len() * 2 || !args.len().is_multiple_of(2) {
        return Err(HarnessError::new(
            "connection holder arguments are incomplete",
        ));
    }
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !KEYS.contains(&pair[0].as_str())
            || values.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            return Err(HarnessError::new(
                "connection holder argument is unknown or duplicated",
            ));
        }
    }
    Ok(ConnectionHolderOptions {
        address: required(&values, "--address")?
            .parse()
            .map_err(|_| HarnessError::new("connection holder address is invalid"))?,
        connection_count: positive(&values, "--connections")?
            .try_into()
            .map_err(|_| HarnessError::new("connection holder count exceeds usize"))?,
        timeout_ms: positive(&values, "--timeout-ms")?,
        hold_timeout_ms: positive(&values, "--hold-timeout-ms")?,
        ready_output: PathBuf::from(required(&values, "--ready-output")?),
        stop_file: PathBuf::from(required(&values, "--stop-file")?),
    })
}

pub fn run_connection_holder(options: ConnectionHolderOptions) -> Result<String, HarnessError> {
    let spec = ConnectionHolderSpec::new(
        options.address,
        options.connection_count,
        Duration::from_millis(options.timeout_ms),
    )?;
    let mut holder = ConnectionHolder::new(spec);
    for target in [64, 256, 512, options.connection_count]
        .into_iter()
        .filter(|target| *target <= options.connection_count)
    {
        if target > holder.held_count() {
            holder.ramp_to(target)?;
        }
    }
    if holder.held_count() != options.connection_count {
        return Err(HarnessError::new(
            "connection holder final count is inconsistent",
        ));
    }
    publish_ready(&options.ready_output, holder.held_count())?;
    let deadline = Instant::now() + Duration::from_millis(options.hold_timeout_ms);
    while !options.stop_file.exists() {
        if Instant::now() >= deadline {
            let _ = holder.release();
            return Err(HarnessError::new(
                "connection holder stop deadline exceeded",
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
    let released = holder.held_count();
    holder.release()?;
    Ok(format!(
        "connection holder released held={} remaining={}",
        released,
        holder.held_count()
    ))
}

fn publish_ready(path: &Path, count: usize) -> Result<(), HarnessError> {
    let parent = path
        .parent()
        .ok_or_else(|| HarnessError::new("connection holder ready path has no parent"))?;
    fs::create_dir_all(parent)
        .map_err(|_| HarnessError::new("connection holder ready directory failed"))?;
    let temporary = path.with_file_name(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("ready"),
        std::process::id()
    ));
    fs::write(&temporary, format!("{count}\n"))
        .and_then(|_| fs::rename(&temporary, path))
        .map_err(|_| HarnessError::new("connection holder ready publish failed"))
}

fn positive(values: &BTreeMap<String, String>, key: &str) -> Result<u64, HarnessError> {
    let value = required(values, key)?
        .parse::<u64>()
        .map_err(|_| HarnessError::new("connection holder numeric argument is invalid"))?;
    if value == 0 {
        return Err(HarnessError::new(
            "connection holder numeric argument must be positive",
        ));
    }
    Ok(value)
}

fn required(values: &BTreeMap<String, String>, key: &str) -> Result<String, HarnessError> {
    values
        .get(key)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| HarnessError::new(format!("connection holder argument is missing: {key}")))
}
