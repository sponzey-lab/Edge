//! Synchronous HTTP/HTTPS health probe transport over caller-prepared TLS.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use edge_domain::{UpstreamScheme, UpstreamTlsPolicy};
use edge_ports::{
    HealthProbeFailure, HealthProbeRequest, HealthProbeResult, HealthProbeTransport, TlsSession,
    TlsSessionProgress,
};

use crate::PreparedHealthTlsRegistry;

const MAX_HEALTH_RESPONSE_HEADER_BYTES: usize = 8 * 1024;

#[derive(Clone, Default)]
pub struct HttpHealthProbeTransport {
    tls_registry: PreparedHealthTlsRegistry,
}

impl HttpHealthProbeTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_tls_registry(tls_registry: PreparedHealthTlsRegistry) -> Self {
        Self { tls_registry }
    }

    fn execute(&self, request: &HealthProbeRequest) -> Result<u16, HealthProbeFailure> {
        let address = request
            .endpoint
            .connect_address()
            .parse::<SocketAddr>()
            .map_err(|_| HealthProbeFailure::Internal)?;
        let timeout = Duration::from_millis(request.timeout_ms);
        let mut stream =
            TcpStream::connect_timeout(&address, timeout).map_err(classify_connect_failure)?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|_| HealthProbeFailure::Internal)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|_| HealthProbeFailure::Internal)?;
        let target = request.endpoint.join_path(&request.path);
        let host = match (&request.endpoint.scheme(), &request.tls) {
            (UpstreamScheme::Http, UpstreamTlsPolicy::Disabled) => {
                request.endpoint.authority().to_string()
            }
            (UpstreamScheme::Https, UpstreamTlsPolicy::ServerAuthenticated { http_host, .. }) => {
                http_host.as_str().to_string()
            }
            _ => return Err(HealthProbeFailure::TlsProfile),
        };
        let wire_request = format!(
            "GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: sponzey-edge-health/1\r\n\r\n"
        );
        match &request.tls {
            UpstreamTlsPolicy::Disabled => {
                stream
                    .write_all(wire_request.as_bytes())
                    .map_err(|_| HealthProbeFailure::WriteError)?;
                read_health_status(&mut stream)
            }
            UpstreamTlsPolicy::ServerAuthenticated { server_name, .. } => {
                let mut session = self
                    .tls_registry
                    .create_session(&request.key, server_name)?;
                drive_health_tls_handshake(session.as_mut(), &mut stream, timeout)?;
                session
                    .receive_plaintext(wire_request.as_bytes())
                    .map_err(|_| HealthProbeFailure::WriteError)?;
                flush_health_tls_output(session.as_mut(), &mut stream)?;
                read_tls_health_status(session.as_mut(), &mut stream)
            }
        }
    }
}

impl HealthProbeTransport for HttpHealthProbeTransport {
    fn probe(&mut self, request: HealthProbeRequest) -> HealthProbeResult {
        let started_at = Instant::now();
        match self.execute(&request) {
            Ok(status_code) if (request.status_min..=request.status_max).contains(&status_code) => {
                HealthProbeResult::succeeded(status_code, elapsed_millis(started_at))
            }
            Ok(status_code) => HealthProbeResult::failed(
                HealthProbeFailure::StatusMismatch { status_code },
                elapsed_millis(started_at),
            ),
            Err(failure) => HealthProbeResult::failed(failure, elapsed_millis(started_at)),
        }
    }
}

fn flush_health_tls_output(
    session: &mut dyn TlsSession,
    stream: &mut TcpStream,
) -> Result<(), HealthProbeFailure> {
    loop {
        let encrypted = session.take_encrypted(16 * 1024);
        if encrypted.is_empty() {
            return Ok(());
        }
        stream
            .write_all(&encrypted)
            .map_err(|_| HealthProbeFailure::WriteError)?;
    }
}

fn drive_health_tls_handshake(
    session: &mut dyn TlsSession,
    stream: &mut TcpStream,
    timeout: Duration,
) -> Result<(), HealthProbeFailure> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(HealthProbeFailure::TlsHandshakeTimeout)?;
    let mut encrypted = [0_u8; 16 * 1024];
    loop {
        flush_health_tls_output(session, stream)?;
        match session.progress() {
            TlsSessionProgress::Established => return Ok(()),
            TlsSessionProgress::Handshaking => {}
            TlsSessionProgress::Closing
            | TlsSessionProgress::PeerClosed
            | TlsSessionProgress::Failed { .. } => return Err(HealthProbeFailure::TlsHandshake),
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(HealthProbeFailure::TlsHandshakeTimeout)?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| HealthProbeFailure::Internal)?;
        let read = stream
            .read(&mut encrypted)
            .map_err(|error| match error.kind() {
                ErrorKind::TimedOut | ErrorKind::WouldBlock => {
                    HealthProbeFailure::TlsHandshakeTimeout
                }
                _ => HealthProbeFailure::TlsHandshake,
            })?;
        if read == 0 {
            return Err(HealthProbeFailure::TlsHandshake);
        }
        session
            .receive_encrypted(&encrypted[..read])
            .map_err(|_| HealthProbeFailure::TlsHandshake)?;
    }
}

fn read_tls_health_status(
    session: &mut dyn TlsSession,
    stream: &mut TcpStream,
) -> Result<u16, HealthProbeFailure> {
    let mut headers = Vec::with_capacity(1024);
    let mut encrypted = [0_u8; 16 * 1024];
    loop {
        let remaining = (MAX_HEALTH_RESPONSE_HEADER_BYTES + 1).saturating_sub(headers.len());
        if remaining == 0 {
            return Err(HealthProbeFailure::ResponseTooLarge);
        }
        let decrypted = session.take_decrypted(remaining);
        headers.extend_from_slice(&decrypted);
        if let Some(end) = headers
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
        {
            if end > MAX_HEALTH_RESPONSE_HEADER_BYTES {
                return Err(HealthProbeFailure::ResponseTooLarge);
            }
            return parse_health_status_line(&headers[..end]);
        }
        if headers.len() > MAX_HEALTH_RESPONSE_HEADER_BYTES {
            return Err(HealthProbeFailure::ResponseTooLarge);
        }
        flush_health_tls_output(session, stream)?;
        let read = stream
            .read(&mut encrypted)
            .map_err(|error| match error.kind() {
                ErrorKind::TimedOut | ErrorKind::WouldBlock => HealthProbeFailure::ReadTimeout,
                _ => HealthProbeFailure::MalformedResponse,
            })?;
        if read == 0 {
            return Err(HealthProbeFailure::MalformedResponse);
        }
        session
            .receive_encrypted(&encrypted[..read])
            .map_err(|_| HealthProbeFailure::MalformedResponse)?;
    }
}

pub(crate) fn classify_connect_failure(error: std::io::Error) -> HealthProbeFailure {
    match error.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => HealthProbeFailure::ConnectTimeout,
        _ => HealthProbeFailure::ConnectError,
    }
}

pub(crate) fn read_health_status(stream: &mut TcpStream) -> Result<u16, HealthProbeFailure> {
    let mut headers = Vec::with_capacity(1024);
    let mut buffer = [0_u8; 1024];
    loop {
        let remaining_with_overflow_byte =
            (MAX_HEALTH_RESPONSE_HEADER_BYTES + 1).saturating_sub(headers.len());
        let read_limit = remaining_with_overflow_byte.min(buffer.len());
        if read_limit == 0 {
            return Err(HealthProbeFailure::ResponseTooLarge);
        }
        let read = stream
            .read(&mut buffer[..read_limit])
            .map_err(|error| match error.kind() {
                ErrorKind::TimedOut | ErrorKind::WouldBlock => HealthProbeFailure::ReadTimeout,
                _ => HealthProbeFailure::MalformedResponse,
            })?;
        if read == 0 {
            return Err(HealthProbeFailure::MalformedResponse);
        }
        headers.extend_from_slice(&buffer[..read]);
        if let Some(end) = headers
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
        {
            if end > MAX_HEALTH_RESPONSE_HEADER_BYTES {
                return Err(HealthProbeFailure::ResponseTooLarge);
            }
            return parse_health_status_line(&headers[..end]);
        }
        if headers.len() > MAX_HEALTH_RESPONSE_HEADER_BYTES {
            return Err(HealthProbeFailure::ResponseTooLarge);
        }
    }
}

fn parse_health_status_line(headers: &[u8]) -> Result<u16, HealthProbeFailure> {
    let status_line_end = headers
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or(HealthProbeFailure::MalformedResponse)?;
    let status_line = std::str::from_utf8(&headers[..status_line_end])
        .map_err(|_| HealthProbeFailure::MalformedResponse)?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().ok_or(HealthProbeFailure::MalformedResponse)?;
    let status = parts.next().ok_or(HealthProbeFailure::MalformedResponse)?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || status.len() != 3
        || !status.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(HealthProbeFailure::MalformedResponse);
    }
    let status_code = status
        .parse::<u16>()
        .map_err(|_| HealthProbeFailure::MalformedResponse)?;
    if !(100..=599).contains(&status_code) {
        return Err(HealthProbeFailure::MalformedResponse);
    }
    Ok(status_code)
}

fn elapsed_millis(started_at: Instant) -> u64 {
    u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
}
