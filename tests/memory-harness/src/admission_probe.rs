use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::time::Duration;

use crate::bounded_net::connect_with_deadline;
use crate::HarnessError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionProbeSpec {
    address: SocketAddr,
    connect_timeout: Duration,
    terminal_timeout: Duration,
}

impl AdmissionProbeSpec {
    pub fn new(
        address: SocketAddr,
        connect_timeout: Duration,
        terminal_timeout: Duration,
    ) -> Result<Self, HarnessError> {
        if connect_timeout.is_zero() || terminal_timeout.is_zero() {
            return Err(HarnessError::new("admission probe timeout is invalid"));
        }
        Ok(Self {
            address,
            connect_timeout,
            terminal_timeout,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionProbeState {
    Ready,
    Connecting,
    AwaitingTerminal,
    Rejected,
    UnexpectedlyOpen,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionProbeObservation {
    TerminalClosed,
    TimedOutOpen,
    ApplicationBytes,
    IoFailure,
}

pub struct AdmissionProbe {
    spec: AdmissionProbeSpec,
    state: AdmissionProbeState,
}

impl AdmissionProbe {
    pub fn new(spec: AdmissionProbeSpec) -> Self {
        Self {
            spec,
            state: AdmissionProbeState::Ready,
        }
    }

    pub fn state(&self) -> AdmissionProbeState {
        self.state
    }

    pub fn begin(&mut self) -> Result<(), HarnessError> {
        if self.state != AdmissionProbeState::Ready {
            self.state = AdmissionProbeState::Failed;
            return Err(HarnessError::new("admission probe transition is invalid"));
        }
        self.state = AdmissionProbeState::Connecting;
        Ok(())
    }

    pub fn connected(&mut self) -> Result<(), HarnessError> {
        if self.state != AdmissionProbeState::Connecting {
            self.state = AdmissionProbeState::Failed;
            return Err(HarnessError::new("admission probe transition is invalid"));
        }
        self.state = AdmissionProbeState::AwaitingTerminal;
        Ok(())
    }

    pub fn observe(&mut self, observation: AdmissionProbeObservation) -> Result<(), HarnessError> {
        if self.state != AdmissionProbeState::AwaitingTerminal {
            self.state = AdmissionProbeState::Failed;
            return Err(HarnessError::new("admission probe transition is invalid"));
        }
        match observation {
            AdmissionProbeObservation::TerminalClosed => {
                self.state = AdmissionProbeState::Rejected;
                Ok(())
            }
            AdmissionProbeObservation::TimedOutOpen => {
                self.unexpectedly_open("admission probe remained open until timeout")
            }
            AdmissionProbeObservation::ApplicationBytes => {
                self.unexpectedly_open("admission probe received application bytes")
            }
            AdmissionProbeObservation::IoFailure => {
                self.state = AdmissionProbeState::Failed;
                Err(HarnessError::new("admission probe I/O failed"))
            }
        }
    }

    pub fn expect_rejection(&mut self) -> Result<(), HarnessError> {
        self.begin()?;
        let mut stream = match connect_with_deadline(
            self.spec.address,
            self.spec.connect_timeout,
            "admission probe connect failed",
        ) {
            Ok(stream) => stream,
            Err(error) => {
                self.state = AdmissionProbeState::Failed;
                return Err(error);
            }
        };
        self.connected()?;
        if let Err(error) = stream
            .set_read_timeout(Some(self.spec.terminal_timeout))
            .and_then(|_| stream.set_write_timeout(Some(self.spec.terminal_timeout)))
            .and_then(|_| stream.write_all(b"G"))
        {
            let observation = if is_rejection_terminal(error.kind()) {
                AdmissionProbeObservation::TerminalClosed
            } else {
                AdmissionProbeObservation::IoFailure
            };
            return self.observe(observation);
        }
        let mut byte = [0_u8; 1];
        let observation = match stream.read(&mut byte) {
            Ok(0) => AdmissionProbeObservation::TerminalClosed,
            Ok(_) => AdmissionProbeObservation::ApplicationBytes,
            Err(error) if is_rejection_terminal(error.kind()) => {
                AdmissionProbeObservation::TerminalClosed
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                AdmissionProbeObservation::TimedOutOpen
            }
            Err(_) => AdmissionProbeObservation::IoFailure,
        };
        self.observe(observation)
    }

    fn unexpectedly_open(&mut self, message: &str) -> Result<(), HarnessError> {
        self.state = AdmissionProbeState::UnexpectedlyOpen;
        Err(HarnessError::new(message))
    }
}

fn is_rejection_terminal(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionProbeOptions {
    pub address: SocketAddr,
    pub connect_timeout_ms: u64,
    pub terminal_timeout_ms: u64,
}

pub fn parse_admission_probe_options(
    args: &[String],
) -> Result<AdmissionProbeOptions, HarnessError> {
    const KEYS: [&str; 3] = ["--address", "--connect-timeout-ms", "--terminal-timeout-ms"];
    if args.len() != KEYS.len() * 2 || !args.len().is_multiple_of(2) {
        return Err(HarnessError::new(
            "admission probe arguments are incomplete",
        ));
    }
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !KEYS.contains(&pair[0].as_str())
            || values.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            return Err(HarnessError::new(
                "admission probe argument is unknown or duplicated",
            ));
        }
    }
    let address = required(&values, "--address")?
        .parse()
        .map_err(|_| HarnessError::new("admission probe address is invalid"))?;
    let connect_timeout_ms = parse_timeout(&values, "--connect-timeout-ms")?;
    let terminal_timeout_ms = parse_timeout(&values, "--terminal-timeout-ms")?;
    if connect_timeout_ms == 0 || terminal_timeout_ms == 0 {
        return Err(HarnessError::new(
            "admission probe timeout must be positive",
        ));
    }
    Ok(AdmissionProbeOptions {
        address,
        connect_timeout_ms,
        terminal_timeout_ms,
    })
}

pub fn run_admission_probe(options: AdmissionProbeOptions) -> Result<String, HarnessError> {
    let spec = AdmissionProbeSpec::new(
        options.address,
        Duration::from_millis(options.connect_timeout_ms),
        Duration::from_millis(options.terminal_timeout_ms),
    )?;
    let mut probe = AdmissionProbe::new(spec);
    probe.expect_rejection()?;
    Ok("connection admission probe rejected terminal=closed".to_string())
}

fn parse_timeout(values: &BTreeMap<String, String>, key: &str) -> Result<u64, HarnessError> {
    required(values, key)?
        .parse::<u64>()
        .map_err(|_| HarnessError::new("admission probe timeout is invalid"))
}

fn required(values: &BTreeMap<String, String>, key: &str) -> Result<String, HarnessError> {
    values
        .get(key)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| HarnessError::new(format!("admission probe argument is missing: {key}")))
}
