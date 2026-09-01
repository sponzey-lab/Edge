use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use crate::bounded_net::connect_with_deadline;
use crate::HarnessError;

const CLIENT_MASK: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketState {
    Ready,
    Ramping,
    Holding,
    Releasing,
    Completed,
    Failed,
}

pub struct WebSocketLifecycle {
    maximum: usize,
    held: usize,
    state: WebSocketState,
}

impl WebSocketLifecycle {
    pub fn new(maximum: usize) -> Result<Self, HarnessError> {
        if maximum == 0 {
            return Err(HarnessError::new("WebSocket maximum is invalid"));
        }
        Ok(Self {
            maximum,
            held: 0,
            state: WebSocketState::Ready,
        })
    }

    pub fn state(&self) -> WebSocketState {
        self.state
    }

    pub fn held_count(&self) -> usize {
        self.held
    }

    pub fn ramp_verified(&mut self, target: usize, verified: usize) -> Result<(), HarnessError> {
        if !matches!(self.state, WebSocketState::Ready | WebSocketState::Holding)
            || target <= self.held
            || target > self.maximum
            || verified != target
        {
            return self.fail("WebSocket ramp transition is invalid");
        }
        self.state = WebSocketState::Ramping;
        self.held = verified;
        self.state = WebSocketState::Holding;
        Ok(())
    }

    pub fn release(&mut self) -> Result<usize, HarnessError> {
        if self.state != WebSocketState::Holding || self.held != self.maximum {
            return self.fail("WebSocket release transition is invalid");
        }
        self.state = WebSocketState::Releasing;
        let released = self.held;
        self.held = 0;
        self.state = WebSocketState::Completed;
        Ok(released)
    }

    fn fail<T>(&mut self, message: &str) -> Result<T, HarnessError> {
        self.held = 0;
        self.state = WebSocketState::Failed;
        Err(HarnessError::new(message))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSocketOptions {
    pub address: SocketAddr,
    pub connections: usize,
    pub timeout_ms: u64,
    pub hold_timeout_ms: u64,
    pub max_header_bytes: usize,
    pub ready_output: PathBuf,
    pub stop_file: PathBuf,
}

pub fn parse_websocket_options(args: &[String]) -> Result<WebSocketOptions, HarnessError> {
    const KEYS: [&str; 7] = [
        "--address",
        "--connections",
        "--timeout-ms",
        "--hold-timeout-ms",
        "--max-header-bytes",
        "--ready-output",
        "--stop-file",
    ];
    if args.len() != KEYS.len() * 2 || !args.len().is_multiple_of(2) {
        return Err(HarnessError::new("WebSocket arguments are incomplete"));
    }
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !KEYS.contains(&pair[0].as_str())
            || values.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            return Err(HarnessError::new(
                "WebSocket argument is unknown or duplicated",
            ));
        }
    }
    Ok(WebSocketOptions {
        address: required(&values, "--address")?
            .parse()
            .map_err(|_| HarnessError::new("WebSocket address is invalid"))?,
        connections: positive(&values, "--connections")?
            .try_into()
            .map_err(|_| HarnessError::new("WebSocket count exceeds usize"))?,
        timeout_ms: positive(&values, "--timeout-ms")?,
        hold_timeout_ms: positive(&values, "--hold-timeout-ms")?,
        max_header_bytes: positive(&values, "--max-header-bytes")?
            .try_into()
            .map_err(|_| HarnessError::new("WebSocket header bound exceeds usize"))?,
        ready_output: PathBuf::from(required(&values, "--ready-output")?),
        stop_file: PathBuf::from(required(&values, "--stop-file")?),
    })
}

pub fn encode_masked_client_frame(payload: &[u8]) -> Result<Vec<u8>, HarnessError> {
    encode_masked_frame(0x2, payload)
}

pub fn encode_masked_text_frame(payload: &[u8]) -> Result<Vec<u8>, HarnessError> {
    encode_masked_frame(0x1, payload)
}

fn encode_masked_frame(opcode: u8, payload: &[u8]) -> Result<Vec<u8>, HarnessError> {
    let length = u8::try_from(payload.len())
        .ok()
        .filter(|length| *length <= 125)
        .ok_or_else(|| HarnessError::new("WebSocket client frame exceeds bound"))?;
    let mut frame = Vec::with_capacity(payload.len() + 6);
    frame.extend_from_slice(&[0x80 | opcode, 0x80 | length]);
    frame.extend_from_slice(&CLIENT_MASK);
    frame.extend(
        payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ CLIENT_MASK[index % CLIENT_MASK.len()]),
    );
    Ok(frame)
}

pub fn decode_server_frame(bytes: &[u8], maximum: usize) -> Result<Vec<u8>, HarnessError> {
    if bytes.len() < 2 || bytes[0] & 0x80 == 0 || !matches!(bytes[0] & 0x0f, 0x1 | 0x2) {
        return Err(HarnessError::new(
            "WebSocket server frame header is invalid",
        ));
    }
    if bytes[1] & 0x80 != 0 || bytes[1] & 0x7f > 125 {
        return Err(HarnessError::new(
            "WebSocket server frame encoding is invalid",
        ));
    }
    let length = usize::from(bytes[1] & 0x7f);
    if length > maximum || bytes.len() != length + 2 {
        return Err(HarnessError::new(
            "WebSocket server frame length is invalid",
        ));
    }
    Ok(bytes[2..].to_vec())
}

pub fn run_websocket_driver(options: WebSocketOptions) -> Result<String, HarnessError> {
    let timeout = Duration::from_millis(options.timeout_ms);
    let (mut lifecycle, mut sessions) = open_verified_sessions(
        options.address,
        "localhost",
        options.connections,
        timeout,
        options.max_header_bytes,
    )?;
    fs::write(&options.ready_output, format!("{}\n", sessions.len()))
        .map_err(|_| HarnessError::new("WebSocket ready publish failed"))?;
    let deadline = Instant::now() + Duration::from_millis(options.hold_timeout_ms);
    while !options.stop_file.exists() {
        if Instant::now() >= deadline {
            return Err(HarnessError::new("WebSocket stop deadline exceeded"));
        }
        thread::sleep(Duration::from_millis(50));
    }
    let released = release_verified_sessions(&mut lifecycle, &mut sessions)?;
    Ok(format!(
        "WebSocket driver released held={released} remaining={}",
        sessions.len()
    ))
}

pub fn run_websocket_lifecycles(
    address: SocketAddr,
    connections: usize,
    timeout: Duration,
    max_header_bytes: usize,
) -> Result<usize, HarnessError> {
    run_websocket_lifecycles_for_host(address, "localhost", connections, timeout, max_header_bytes)
}

pub fn run_websocket_lifecycles_for_host(
    address: SocketAddr,
    host: &str,
    connections: usize,
    timeout: Duration,
    max_header_bytes: usize,
) -> Result<usize, HarnessError> {
    if timeout.is_zero() || max_header_bytes == 0 {
        return Err(HarnessError::new(
            "WebSocket lifecycle specification is invalid",
        ));
    }
    let (mut lifecycle, mut sessions) =
        open_verified_sessions(address, host, connections, timeout, max_header_bytes)?;
    release_verified_sessions(&mut lifecycle, &mut sessions)
}

pub fn websocket_upgrade_request(host: &str) -> Result<Vec<u8>, HarnessError> {
    if host.is_empty() || host.contains(['\r', '\n']) {
        return Err(HarnessError::new("WebSocket upgrade host is invalid"));
    }
    Ok(format!(
        "GET /ws/echo HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    )
    .into_bytes())
}

fn open_verified_sessions(
    address: SocketAddr,
    host: &str,
    connections: usize,
    timeout: Duration,
    max_header_bytes: usize,
) -> Result<(WebSocketLifecycle, Vec<TcpStream>), HarnessError> {
    let mut lifecycle = WebSocketLifecycle::new(connections)?;
    let mut sessions = Vec::with_capacity(connections);
    for target in [32, 64, 128, connections]
        .into_iter()
        .filter(|target| *target <= connections)
    {
        if target <= sessions.len() {
            continue;
        }
        while sessions.len() < target {
            sessions.push(open_verified_tunnel(
                address,
                host,
                timeout,
                max_header_bytes,
            )?);
        }
        lifecycle.ramp_verified(target, sessions.len())?;
    }
    Ok((lifecycle, sessions))
}

fn release_verified_sessions(
    lifecycle: &mut WebSocketLifecycle,
    sessions: &mut Vec<TcpStream>,
) -> Result<usize, HarnessError> {
    let released = lifecycle.release()?;
    let close = encode_masked_frame(0x8, &[])?;
    for stream in sessions.iter_mut() {
        let _ = stream.write_all(&close);
        let _ = stream.shutdown(Shutdown::Both);
    }
    sessions.clear();
    Ok(released)
}

fn open_verified_tunnel(
    address: SocketAddr,
    host: &str,
    timeout: Duration,
    max_header_bytes: usize,
) -> Result<TcpStream, HarnessError> {
    let mut stream = connect_with_deadline(address, timeout, "WebSocket connect failed")?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|_| stream.set_write_timeout(Some(timeout)))
        .map_err(|_| HarnessError::new("WebSocket timeout config failed"))?;
    let request = websocket_upgrade_request(host)?;
    stream
        .write_all(&request)
        .map_err(|_| HarnessError::new("WebSocket upgrade write failed"))?;
    let header = read_header(&mut stream, max_header_bytes)?;
    let header = std::str::from_utf8(&header)
        .map_err(|_| HarnessError::new("WebSocket upgrade header is not ASCII"))?;
    if !header.starts_with("HTTP/1.1 101 ")
        || !header
            .to_ascii_lowercase()
            .contains("upgrade: websocket\r\n")
    {
        return Err(HarnessError::new("WebSocket upgrade response is invalid"));
    }
    let payload = b"edge-websocket-probe";
    stream
        .write_all(&encode_masked_text_frame(payload)?)
        .map_err(|_| HarnessError::new("WebSocket probe write failed"))?;
    let mut frame_header = [0_u8; 2];
    stream
        .read_exact(&mut frame_header)
        .map_err(|_| HarnessError::new("WebSocket echo header read failed"))?;
    let length = usize::from(frame_header[1] & 0x7f);
    if length > 125 {
        return Err(HarnessError::new("WebSocket echo exceeds frame bound"));
    }
    let mut frame = Vec::with_capacity(length + 2);
    frame.extend_from_slice(&frame_header);
    frame.resize(length + 2, 0);
    stream
        .read_exact(&mut frame[2..])
        .map_err(|_| HarnessError::new("WebSocket echo payload read failed"))?;
    if decode_server_frame(&frame, payload.len())? != payload {
        return Err(HarnessError::new("WebSocket echo payload mismatch"));
    }
    Ok(stream)
}

fn read_header(stream: &mut TcpStream, maximum: usize) -> Result<Vec<u8>, HarnessError> {
    let mut header = Vec::new();
    while header.len() < maximum {
        let mut byte = [0_u8; 1];
        stream
            .read_exact(&mut byte)
            .map_err(|_| HarnessError::new("WebSocket upgrade read failed"))?;
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            return Ok(header);
        }
    }
    Err(HarnessError::new("WebSocket upgrade header exceeds bound"))
}

fn positive(values: &BTreeMap<String, String>, key: &str) -> Result<u64, HarnessError> {
    let value = required(values, key)?
        .parse::<u64>()
        .map_err(|_| HarnessError::new("WebSocket numeric argument is invalid"))?;
    if value == 0 {
        return Err(HarnessError::new("WebSocket value must be positive"));
    }
    Ok(value)
}

fn required(values: &BTreeMap<String, String>, key: &str) -> Result<String, HarnessError> {
    values
        .get(key)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| HarnessError::new(format!("WebSocket argument is missing: {key}")))
}
