use std::collections::BTreeMap;
use std::fs;
use std::net::{Shutdown, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rustls_pki_types::pem::PemObject;

use crate::bounded_net::connect_with_deadline;
use crate::HarnessError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsHolderState {
    Ready,
    Ramping,
    Holding,
    Releasing,
    Completed,
    Failed,
}

pub struct TlsHolderLifecycle {
    maximum: usize,
    held: usize,
    state: TlsHolderState,
}

impl TlsHolderLifecycle {
    pub fn new(maximum: usize) -> Result<Self, HarnessError> {
        if maximum == 0 {
            return Err(HarnessError::new("TLS holder maximum is invalid"));
        }
        Ok(Self {
            maximum,
            held: 0,
            state: TlsHolderState::Ready,
        })
    }

    pub fn state(&self) -> TlsHolderState {
        self.state
    }

    pub fn held_count(&self) -> usize {
        self.held
    }

    pub fn ramp_completed(&mut self, target: usize) -> Result<(), HarnessError> {
        self.ramp_result(target, target)
    }

    pub fn ramp_result(&mut self, target: usize, opened: usize) -> Result<(), HarnessError> {
        if !matches!(self.state, TlsHolderState::Ready | TlsHolderState::Holding)
            || target <= self.held
            || target > self.maximum
            || opened != target
        {
            return self.fail("TLS holder ramp transition is invalid");
        }
        self.state = TlsHolderState::Ramping;
        self.held = opened;
        self.state = TlsHolderState::Holding;
        Ok(())
    }

    pub fn release(&mut self) -> Result<usize, HarnessError> {
        if self.state != TlsHolderState::Holding || self.held != self.maximum {
            return self.fail("TLS holder release transition is invalid");
        }
        self.state = TlsHolderState::Releasing;
        let released = self.held;
        self.held = 0;
        self.state = TlsHolderState::Completed;
        Ok(released)
    }

    fn fail<T>(&mut self, message: &str) -> Result<T, HarnessError> {
        self.held = 0;
        self.state = TlsHolderState::Failed;
        Err(HarnessError::new(message))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsHolderOptions {
    pub address: SocketAddr,
    pub connections: usize,
    pub server_name: String,
    pub root_pem: PathBuf,
    pub timeout_ms: u64,
    pub hold_timeout_ms: u64,
    pub ready_output: PathBuf,
    pub stop_file: PathBuf,
}

pub fn parse_tls_holder_options(args: &[String]) -> Result<TlsHolderOptions, HarnessError> {
    const KEYS: [&str; 8] = [
        "--address",
        "--connections",
        "--server-name",
        "--root-pem",
        "--timeout-ms",
        "--hold-timeout-ms",
        "--ready-output",
        "--stop-file",
    ];
    if args.len() != KEYS.len() * 2 || !args.len().is_multiple_of(2) {
        return Err(HarnessError::new("TLS holder arguments are incomplete"));
    }
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !KEYS.contains(&pair[0].as_str())
            || values.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            return Err(HarnessError::new(
                "TLS holder argument is unknown or duplicated",
            ));
        }
    }
    Ok(TlsHolderOptions {
        address: required(&values, "--address")?
            .parse()
            .map_err(|_| HarnessError::new("TLS holder address is invalid"))?,
        connections: positive(&values, "--connections")?
            .try_into()
            .map_err(|_| HarnessError::new("TLS holder count exceeds usize"))?,
        server_name: required(&values, "--server-name")?,
        root_pem: PathBuf::from(required(&values, "--root-pem")?),
        timeout_ms: positive(&values, "--timeout-ms")?,
        hold_timeout_ms: positive(&values, "--hold-timeout-ms")?,
        ready_output: PathBuf::from(required(&values, "--ready-output")?),
        stop_file: PathBuf::from(required(&values, "--stop-file")?),
    })
}

pub fn run_tls_holder(options: TlsHolderOptions) -> Result<String, HarnessError> {
    let root_pem = fs::read(&options.root_pem)
        .map_err(|_| HarnessError::new("TLS holder root read failed"))?;
    let certificate = rustls_pki_types::CertificateDer::from_pem_slice(&root_pem)
        .map_err(|_| HarnessError::new("TLS holder root parse failed"))?;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(certificate)
        .map_err(|_| HarnessError::new("TLS holder root is invalid"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| HarnessError::new("TLS holder protocol config failed"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    run_tls_holder_with_config(options, Arc::new(config))
}

pub(crate) fn run_tls_holder_with_config(
    options: TlsHolderOptions,
    config: Arc<rustls::ClientConfig>,
) -> Result<String, HarnessError> {
    let timeout = Duration::from_millis(options.timeout_ms);
    let mut lifecycle = TlsHolderLifecycle::new(options.connections)?;
    let mut sessions = Vec::with_capacity(options.connections);
    for target in [64, 128, 256, 512, options.connections]
        .into_iter()
        .filter(|target| *target <= options.connections)
    {
        if target <= sessions.len() {
            continue;
        }
        while sessions.len() < target {
            let server_name =
                rustls_pki_types::ServerName::try_from(options.server_name.clone())
                    .map_err(|_| HarnessError::new("TLS holder server name is invalid"))?;
            let mut connection = rustls::ClientConnection::new(Arc::clone(&config), server_name)
                .map_err(|_| HarnessError::new("TLS holder client creation failed"))?;
            let mut stream =
                connect_with_deadline(options.address, timeout, "TLS holder connection failed")?;
            stream
                .set_read_timeout(Some(timeout))
                .and_then(|_| stream.set_write_timeout(Some(timeout)))
                .map_err(|_| HarnessError::new("TLS holder timeout config failed"))?;
            connection
                .complete_io(&mut stream)
                .map_err(|_| HarnessError::new("TLS holder handshake failed"))?;
            sessions.push((connection, stream));
        }
        lifecycle.ramp_result(target, sessions.len())?;
    }
    fs::write(&options.ready_output, format!("{}\n", sessions.len()))
        .map_err(|_| HarnessError::new("TLS holder ready publish failed"))?;
    let deadline = Instant::now() + Duration::from_millis(options.hold_timeout_ms);
    while !options.stop_file.exists() {
        if Instant::now() >= deadline {
            return Err(HarnessError::new("TLS holder stop deadline exceeded"));
        }
        thread::sleep(Duration::from_millis(50));
    }
    let released = lifecycle.release()?;
    for (connection, stream) in &mut sessions {
        connection.send_close_notify();
        while connection.wants_write() {
            match connection.write_tls(stream) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        let _ = stream.shutdown(Shutdown::Both);
    }
    sessions.clear();
    Ok(format!(
        "TLS holder released held={released} remaining={}",
        sessions.len()
    ))
}

fn positive(values: &BTreeMap<String, String>, key: &str) -> Result<u64, HarnessError> {
    let value = required(values, key)?
        .parse::<u64>()
        .map_err(|_| HarnessError::new("TLS holder numeric argument is invalid"))?;
    if value == 0 {
        return Err(HarnessError::new("TLS holder value must be positive"));
    }
    Ok(value)
}

fn required(values: &BTreeMap<String, String>, key: &str) -> Result<String, HarnessError> {
    values
        .get(key)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| HarnessError::new(format!("TLS holder argument is missing: {key}")))
}
