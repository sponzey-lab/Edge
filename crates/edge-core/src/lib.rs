//! mio-based proxy core.
//!
//! The first implementation step provides the event-loop data structures,
//! command boundary, timers, and resource limits. Actual HTTP proxying is added
//! in later tasks.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use edge_domain::{
    AppError, CertificateRef, CommandAck, ConfigSnapshot, CoreCommand, ErrorCode,
    HttpUpstreamEndpoint, ResourceChargeState, RuntimeResourcePolicy, ServiceId, TlsServerName,
    UpstreamEndpoint, UpstreamId, UpstreamTlsPolicy, DEFAULT_MAX_CONNECTIONS,
    DEFAULT_MAX_REQUEST_BODY_BYTES, FIXED_REQUEST_HEADER_RESERVE_BYTES,
    FIXED_RESPONSE_BUFFER_RESERVE_BYTES,
};
use edge_ports::{
    ClientTlsSessionFactory, ServerTlsSessionFactory, TlsPendingBytes, TlsSession,
    TlsSessionProgress,
};
use mio::Token;

/// Foundation smoke helper.
pub fn crate_name() -> &'static str {
    "edge-core"
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpLimits {
    pub max_request_line_bytes: usize,
    pub max_header_bytes: usize,
    pub max_header_count: usize,
    pub max_body_bytes: usize,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            max_request_line_bytes: 8 * 1024,
            max_header_bytes: FIXED_REQUEST_HEADER_RESERVE_BYTES,
            max_header_count: 100,
            max_body_bytes: DEFAULT_MAX_REQUEST_BODY_BYTES,
        }
    }
}

pub fn parse_http_request(input: &[u8], limits: &HttpLimits) -> Result<HttpRequest, AppError> {
    let header_end = input
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| AppError::new(ErrorCode::HttpMalformedRequest, "missing header end"))?;
    let header_bytes = &input[..header_end];
    let body = input[(header_end + 4)..].to_vec();

    if header_bytes.len() > limits.max_header_bytes {
        return Err(AppError::new(
            ErrorCode::HttpHeaderTooLarge,
            "headers exceed limit",
        ));
    }
    if body.len() > limits.max_body_bytes {
        return Err(AppError::new(
            ErrorCode::HttpRequestBodyTooLarge,
            "body exceeds limit",
        ));
    }

    let header_text = std::str::from_utf8(header_bytes)
        .map_err(|_| AppError::new(ErrorCode::HttpMalformedRequest, "headers are not UTF-8"))?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| AppError::new(ErrorCode::HttpMalformedRequest, "missing request line"))?;

    if request_line.len() > limits.max_request_line_bytes {
        return Err(AppError::new(
            ErrorCode::HttpRequestLineTooLarge,
            "request line exceeds limit",
        ));
    }

    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| AppError::new(ErrorCode::HttpMalformedRequest, "missing method"))?
        .to_string();
    let path = request_parts
        .next()
        .ok_or_else(|| AppError::new(ErrorCode::HttpMalformedRequest, "missing path"))?
        .to_string();
    let version = request_parts
        .next()
        .ok_or_else(|| AppError::new(ErrorCode::HttpMalformedRequest, "missing version"))?
        .to_string();

    if method.eq_ignore_ascii_case("CONNECT") {
        return Err(AppError::new(
            ErrorCode::HttpConnectMethodRejected,
            "CONNECT is not supported",
        ));
    }

    let mut headers = Vec::new();
    for line in lines {
        if headers.len() >= limits.max_header_count {
            return Err(AppError::new(
                ErrorCode::HttpHeaderTooLarge,
                "too many headers",
            ));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| AppError::new(ErrorCode::HttpMalformedRequest, "malformed header"))?;
        headers.push(Header {
            name: name.trim().to_string(),
            value: value.trim().to_string(),
        });
    }

    let expected_body_len = expected_request_body_len_from_headers(&headers)?;
    if expected_body_len > limits.max_body_bytes {
        return Err(AppError::new(
            ErrorCode::HttpRequestBodyTooLarge,
            "body exceeds limit",
        ));
    }

    Ok(HttpRequest {
        method,
        path,
        version,
        headers,
        body,
    })
}

fn expected_request_body_len_from_headers(headers: &[Header]) -> Result<usize, AppError> {
    let mut content_length = None;
    let mut has_transfer_encoding = false;

    for header in headers {
        if header.name.eq_ignore_ascii_case("Transfer-Encoding") && !header.value.trim().is_empty()
        {
            has_transfer_encoding = true;
        }

        if header.name.eq_ignore_ascii_case("Content-Length") {
            let parsed = header.value.trim().parse::<usize>().map_err(|_| {
                AppError::new(ErrorCode::HttpMalformedRequest, "invalid content length")
            })?;
            if let Some(existing) = content_length {
                if existing != parsed {
                    return Err(AppError::new(
                        ErrorCode::HttpTransferEncodingContentLengthConflict,
                        "conflicting content length headers",
                    ));
                }
            } else {
                content_length = Some(parsed);
            }
        }
    }

    if has_transfer_encoding && content_length.is_some() {
        return Err(AppError::new(
            ErrorCode::HttpTransferEncodingContentLengthConflict,
            "ambiguous transfer length",
        ));
    }
    if has_transfer_encoding {
        return Err(AppError::new(
            ErrorCode::HttpMalformedRequest,
            "transfer encoding is not supported by the MVP runtime",
        ));
    }

    Ok(content_length.unwrap_or(0))
}

fn expected_request_body_len_from_header_bytes(header_bytes: &[u8]) -> Result<usize, AppError> {
    let text = std::str::from_utf8(header_bytes)
        .map_err(|_| AppError::new(ErrorCode::HttpMalformedRequest, "headers are not UTF-8"))?;
    let mut lines = text.split("\r\n");
    let _request_line = lines
        .next()
        .ok_or_else(|| AppError::new(ErrorCode::HttpMalformedRequest, "missing request line"))?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| AppError::new(ErrorCode::HttpMalformedRequest, "malformed header"))?;
        headers.push(Header {
            name: name.trim().to_string(),
            value: value.trim().to_string(),
        });
    }
    expected_request_body_len_from_headers(&headers)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestReadOutcome {
    Incomplete,
    Complete(Vec<u8>),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientRequestBuffer {
    bytes: Vec<u8>,
    header_end: Option<usize>,
}

impl ClientRequestBuffer {
    pub fn push(
        &mut self,
        chunk: &[u8],
        limits: &HttpLimits,
    ) -> Result<RequestReadOutcome, AppError> {
        self.bytes.extend_from_slice(chunk);

        if self.header_end.is_none() {
            self.header_end = self
                .bytes
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|position| position + 4);
        }

        let Some(header_end) = self.header_end else {
            if self.bytes.len() > limits.max_header_bytes {
                return Err(AppError::new(
                    ErrorCode::HttpHeaderTooLarge,
                    "headers exceed limit",
                ));
            }
            return Ok(RequestReadOutcome::Incomplete);
        };

        if header_end.saturating_sub(4) > limits.max_header_bytes {
            return Err(AppError::new(
                ErrorCode::HttpHeaderTooLarge,
                "headers exceed limit",
            ));
        }

        let expected_body_len =
            expected_request_body_len_from_header_bytes(&self.bytes[..header_end - 4])?;
        if expected_body_len > limits.max_body_bytes {
            return Err(AppError::new(
                ErrorCode::HttpRequestBodyTooLarge,
                "body exceeds limit",
            ));
        }
        if self.bytes.len() > header_end + limits.max_body_bytes {
            return Err(AppError::new(
                ErrorCode::HttpRequestBodyTooLarge,
                "request exceeds configured body limit",
            ));
        }
        if self.bytes.len() >= header_end + expected_body_len {
            self.header_end = None;
            return Ok(RequestReadOutcome::Complete(std::mem::take(
                &mut self.bytes,
            )));
        }

        Ok(RequestReadOutcome::Incomplete)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WriteBuffer {
    bytes: Vec<u8>,
    written: usize,
}

impl WriteBuffer {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, written: 0 }
    }

    pub fn try_append(&mut self, chunk: &[u8]) -> Result<(), AppError> {
        self.try_reserve_append(chunk.len())?;
        self.bytes.extend_from_slice(chunk);
        Ok(())
    }

    fn try_reserve_append(&mut self, additional_bytes: usize) -> Result<(), AppError> {
        self.bytes
            .len()
            .checked_add(additional_bytes)
            .ok_or_else(resource_allocation_error)?;
        self.bytes
            .try_reserve_exact(additional_bytes)
            .map_err(|_| resource_allocation_error())
    }

    pub fn remaining(&self) -> &[u8] {
        &self.bytes[self.written..]
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn remaining_len(&self) -> usize {
        self.remaining().len()
    }

    pub fn is_complete(&self) -> bool {
        self.written >= self.bytes.len()
    }

    pub fn advance(&mut self, byte_count: usize) -> usize {
        let advanced = byte_count.min(self.remaining_len());
        self.written += advanced;
        advanced
    }

    pub fn advance_and_clear_if_complete(&mut self, byte_count: usize) -> usize {
        let advanced = self.advance(byte_count);
        self.clear_if_complete();
        advanced
    }

    pub fn clear_if_complete(&mut self) -> bool {
        if !self.is_complete() || self.bytes.is_empty() {
            return false;
        }
        self.bytes.clear();
        self.written = 0;
        true
    }

    pub fn try_replace_if_complete(&mut self, bytes: &[u8]) -> Result<bool, AppError> {
        if !self.is_complete() {
            return Ok(false);
        }
        let additional = bytes.len().saturating_sub(self.bytes.len());
        self.bytes
            .try_reserve_exact(additional)
            .map_err(|_| resource_allocation_error())?;
        self.bytes.clear();
        self.bytes.extend_from_slice(bytes);
        self.written = 0;
        Ok(true)
    }
}

fn resource_allocation_error() -> AppError {
    AppError::new(
        ErrorCode::ResourceAllocationFailed,
        "managed buffer allocation failed",
    )
}

pub fn remove_hop_by_hop_headers(headers: &[Header]) -> Vec<Header> {
    let mut connection_tokens = Vec::new();
    for header in headers {
        if header.name.eq_ignore_ascii_case("Connection") {
            connection_tokens.extend(
                header
                    .value
                    .split(',')
                    .map(|value| value.trim().to_ascii_lowercase()),
            );
        }
    }

    headers
        .iter()
        .filter(|header| {
            let name = header.name.to_ascii_lowercase();
            !matches!(
                name.as_str(),
                "connection"
                    | "keep-alive"
                    | "proxy-authenticate"
                    | "proxy-authorization"
                    | "te"
                    | "trailer"
                    | "transfer-encoding"
                    | "upgrade"
            ) && !connection_tokens.iter().any(|token| token == &name)
        })
        .cloned()
        .collect()
}

pub fn forwarded_headers(client_ip: &str, scheme: &str, host: &str) -> [Header; 3] {
    [
        Header {
            name: "X-Forwarded-For".to_string(),
            value: client_ip.to_string(),
        },
        Header {
            name: "X-Forwarded-Proto".to_string(),
            value: scheme.to_string(),
        },
        Header {
            name: "X-Forwarded-Host".to_string(),
            value: host.to_string(),
        },
    ]
}

pub fn is_websocket_upgrade(request: &HttpRequest) -> bool {
    request
        .header_value("Connection")
        .is_some_and(|value| value.to_ascii_lowercase().contains("upgrade"))
        && request
            .header_value("Upgrade")
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
}

pub fn https_redirect_location(host: &str, path: &str) -> String {
    format!("https://{host}{path}")
}

pub type UpstreamTarget = HttpUpstreamEndpoint;

trait UpstreamRequestTarget {
    fn join_request_path(&self, request_path: &str) -> String;
}

impl UpstreamRequestTarget for HttpUpstreamEndpoint {
    fn join_request_path(&self, request_path: &str) -> String {
        self.join_path(request_path)
    }
}

impl UpstreamRequestTarget for UpstreamEndpoint {
    fn join_request_path(&self, request_path: &str) -> String {
        self.join_path(request_path)
    }
}

pub mod legacy_single_upstream {
    use std::io::{self, Read, Write};
    use std::net::{SocketAddr, TcpListener as StdTcpListener, TcpStream as StdTcpStream};
    use std::thread;
    use std::time::Duration;

    use mio::net::TcpListener;
    use mio::{Events, Interest, Poll, Token};

    use super::{
        forwarded_headers, is_websocket_upgrade, parse_http_request, remove_hop_by_hop_headers,
        AppError, ErrorCode, HttpLimits, HttpRequest, UpstreamTarget,
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SingleUpstreamProxyConfig {
        pub listen: SocketAddr,
        pub upstream: UpstreamTarget,
        pub limits: HttpLimits,
    }

    pub fn run_single_upstream_proxy(config: SingleUpstreamProxyConfig) -> io::Result<()> {
        const LISTENER: Token = Token(0);

        let std_listener = StdTcpListener::bind(config.listen)?;
        std_listener.set_nonblocking(true)?;
        let registry_listener = std_listener.try_clone()?;
        let mut listener = TcpListener::from_std(registry_listener);
        let mut poll = Poll::new()?;
        poll.registry()
            .register(&mut listener, LISTENER, Interest::READABLE)?;
        let mut events = Events::with_capacity(128);

        loop {
            poll.poll(&mut events, None)?;
            for event in &events {
                if event.token() != LISTENER {
                    continue;
                }

                loop {
                    match std_listener.accept() {
                        Ok((stream, peer_addr)) => {
                            let upstream = config.upstream.clone();
                            let limits = config.limits.clone();
                            thread::spawn(move || {
                                let client_ip = peer_addr.ip().to_string();
                                let _ = handle_http_proxy_connection(
                                    stream, upstream, limits, client_ip,
                                );
                            });
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) => return Err(error),
                    }
                }
            }
        }
    }

    pub fn handle_http_proxy_connection(
        mut client: StdTcpStream,
        upstream: UpstreamTarget,
        limits: HttpLimits,
        client_ip: String,
    ) -> io::Result<()> {
        client.set_read_timeout(Some(Duration::from_secs(30)))?;
        client.set_write_timeout(Some(Duration::from_secs(30)))?;

        let request_bytes = match read_http_request_bytes(&mut client, &limits) {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = write_error_response(&mut client, error.code);
                return Ok(());
            }
        };
        let request = match parse_http_request(&request_bytes, &limits) {
            Ok(request) => request,
            Err(error) => {
                let _ = write_error_response(&mut client, error.code);
                return Ok(());
            }
        };

        if is_websocket_upgrade(&request) {
            return tunnel_websocket(client, &request, &upstream, &client_ip);
        }

        let upstream_response = match forward_http_request(&request, &upstream, &client_ip) {
            Ok(response) => response,
            Err(_) => http_error_response(502, "Bad Gateway"),
        };
        client.write_all(&upstream_response)?;
        client.flush()
    }

    pub fn forward_http_request(
        request: &HttpRequest,
        upstream: &UpstreamTarget,
        client_ip: &str,
    ) -> io::Result<Vec<u8>> {
        let mut upstream_stream = StdTcpStream::connect(upstream.address())?;
        upstream_stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        upstream_stream.set_write_timeout(Some(Duration::from_secs(30)))?;

        let upstream_request = build_upstream_request(request, upstream, client_ip, false)?;
        upstream_stream.write_all(&upstream_request)?;
        upstream_stream.flush()?;

        let mut response = Vec::new();
        upstream_stream.read_to_end(&mut response)?;
        Ok(response)
    }

    fn tunnel_websocket(
        mut client: StdTcpStream,
        request: &HttpRequest,
        upstream: &UpstreamTarget,
        client_ip: &str,
    ) -> io::Result<()> {
        let mut upstream_stream = StdTcpStream::connect(upstream.address())?;
        upstream_stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        upstream_stream.set_write_timeout(Some(Duration::from_secs(30)))?;

        let upstream_request = build_upstream_request(request, upstream, client_ip, true)?;
        upstream_stream.write_all(&upstream_request)?;
        upstream_stream.flush()?;

        let response_headers = read_response_headers(&mut upstream_stream)?;
        client.write_all(&response_headers)?;
        client.flush()?;

        if !response_headers.starts_with(b"HTTP/1.1 101")
            && !response_headers.starts_with(b"HTTP/1.0 101")
        {
            return Ok(());
        }

        let mut client_to_upstream_source = client.try_clone()?;
        let mut client_to_upstream_target = upstream_stream.try_clone()?;
        let _client_to_upstream = thread::spawn(move || {
            let result = io::copy(
                &mut client_to_upstream_source,
                &mut client_to_upstream_target,
            );
            let _ = client_to_upstream_target.shutdown(std::net::Shutdown::Write);
            result
        });

        let upstream_to_client = io::copy(&mut upstream_stream, &mut client);
        let _ = client.shutdown(std::net::Shutdown::Write);
        upstream_to_client.map(|_| ())
    }

    fn build_upstream_request(
        request: &HttpRequest,
        upstream: &UpstreamTarget,
        client_ip: &str,
        preserve_upgrade_headers: bool,
    ) -> io::Result<Vec<u8>> {
        let host = request
            .header_value("Host")
            .unwrap_or(upstream.host.as_str())
            .to_string();
        let mut headers = if preserve_upgrade_headers {
            request
                .headers
                .iter()
                .filter(|header| {
                    !matches!(
                        header.name.to_ascii_lowercase().as_str(),
                        "x-forwarded-for" | "x-forwarded-proto" | "x-forwarded-host"
                    )
                })
                .cloned()
                .collect()
        } else {
            remove_hop_by_hop_headers(&request.headers)
        };
        headers.retain(|header| {
            !matches!(
                header.name.to_ascii_lowercase().as_str(),
                "x-forwarded-for" | "x-forwarded-proto" | "x-forwarded-host"
            )
        });
        headers.extend(forwarded_headers(client_ip, "http", &host));

        let mut upstream_request = Vec::new();
        write!(
            upstream_request,
            "{} {} {}\r\n",
            request.method,
            upstream.join_path(&request.path),
            request.version
        )?;
        for header in headers {
            write!(upstream_request, "{}: {}\r\n", header.name, header.value)?;
        }
        if !preserve_upgrade_headers {
            upstream_request.extend_from_slice(b"Connection: close\r\n");
        }
        upstream_request.extend_from_slice(b"\r\n");
        upstream_request.extend_from_slice(&request.body);

        Ok(upstream_request)
    }

    fn read_response_headers(stream: &mut StdTcpStream) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..read]);
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        Ok(bytes)
    }

    fn read_http_request_bytes(
        stream: &mut StdTcpStream,
        limits: &HttpLimits,
    ) -> Result<Vec<u8>, AppError> {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 4096];
        let mut header_end = None;

        loop {
            let read = stream.read(&mut buffer).map_err(|error| {
                AppError::new(ErrorCode::HttpMalformedRequest, error.to_string())
            })?;
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..read]);
            if bytes.len() > limits.max_header_bytes + limits.max_body_bytes + 4 {
                return Err(AppError::new(
                    ErrorCode::HttpRequestBodyTooLarge,
                    "request exceeds configured limits",
                ));
            }
            if header_end.is_none() {
                header_end = bytes
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|position| position + 4);
                if header_end.is_none() && bytes.len() > limits.max_header_bytes {
                    return Err(AppError::new(
                        ErrorCode::HttpHeaderTooLarge,
                        "headers exceed limit",
                    ));
                }
            }
            if let Some(header_end) = header_end {
                let body_len = content_length_from_header_bytes(&bytes[..header_end])?;
                if body_len > limits.max_body_bytes {
                    return Err(AppError::new(
                        ErrorCode::HttpRequestBodyTooLarge,
                        "body exceeds limit",
                    ));
                }
                if bytes.len() >= header_end + body_len {
                    return Ok(bytes);
                }
            }
        }

        Ok(bytes)
    }

    fn content_length_from_header_bytes(header_bytes: &[u8]) -> Result<usize, AppError> {
        let text = std::str::from_utf8(header_bytes)
            .map_err(|_| AppError::new(ErrorCode::HttpMalformedRequest, "headers are not UTF-8"))?;
        for line in text.split("\r\n") {
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("Content-Length") {
                    return value.trim().parse::<usize>().map_err(|_| {
                        AppError::new(ErrorCode::HttpMalformedRequest, "invalid content length")
                    });
                }
            }
        }
        Ok(0)
    }

    fn write_error_response(stream: &mut StdTcpStream, code: ErrorCode) -> io::Result<()> {
        stream.write_all(&error_response_for_code(code))
    }

    fn error_response_for_code(code: ErrorCode) -> Vec<u8> {
        let (status, reason) = match code {
            ErrorCode::HttpRequestBodyTooLarge => (413, "Payload Too Large"),
            ErrorCode::HttpRequestLineTooLarge => (414, "URI Too Long"),
            ErrorCode::HttpHeaderTooLarge => (431, "Request Header Fields Too Large"),
            ErrorCode::HttpConnectMethodRejected => (405, "Method Not Allowed"),
            ErrorCode::HttpMalformedRequest
            | ErrorCode::HttpTransferEncodingContentLengthConflict => (400, "Bad Request"),
            _ => (500, "Internal Server Error"),
        };
        http_error_response(status, reason)
    }

    fn http_error_response(status: u16, reason: &str) -> Vec<u8> {
        let body = format!("{status} {reason}\n");
        format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }
}

pub mod snapshot_http {
    use std::collections::BTreeMap;
    use std::io::{self, Read, Write};
    use std::net::{SocketAddr, TcpListener as StdTcpListener, TcpStream as StdTcpStream};
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        mpsc, Arc, Mutex,
    };
    use std::thread;
    use std::time::{Duration, Instant};

    use edge_application::{
        active_connection_metric, failure_aware_metric, no_eligible_upstream_metric,
        request_metrics, resource_admission_rejection_metric, resource_payload_bytes_metric,
        resource_payload_limit_bytes_metric, select_http_route_action,
        structured_failure_aware_log, structured_resource_admission_log,
        structured_resource_policy_active_log, structured_resource_pressure_log,
        tls_handshake_failure_metric, upstream_failure_metric, upstream_selection_metric,
        AccessLogEvent, DrainAcquireResult, DrainGeneration, DrainReference, FailureAwareEvent,
        FailureAwareTransition, HttpRouteAction, RecentErrorEvent, RequestedBytesBucket,
        ResourceAdmissionLogKey, ResourceAdmissionLogSampler, ResourceLogContext,
        ResourcePressureLevel, ResourcePressureTransition, TlsFailureComponent,
        TlsFailureObservation, UpstreamDrainTracker,
    };
    use edge_domain::{
        select_upstream, ConfigRevisionId, LogMode, Service, ServiceId, TlsServerName, UpstreamId,
        UpstreamScheme, UpstreamSelection, UpstreamTlsPolicy,
    };
    use edge_ports::{
        CoreCommandClient, HealthAvailabilitySnapshot, HealthGeneration, Http01ChallengeResponder,
        MetricEvent, MetricPublishOutcome, MetricPublisher, PassiveFailureReason,
        PassiveObservation, PassiveObservationDispatcher, PassiveObservationOutcome,
        PassiveObservationSubmit, ResourceMetricKind, ResourceRejectionReason,
        RuntimeResourcePressure, RuntimeResourceStatusPublishOutcome,
        RuntimeResourceStatusPublisher, RuntimeResourceStatusSnapshot,
        RuntimeUpstreamStatusPublisher, ServerTlsSessionFactory,
    };
    use mio::net::{TcpListener, TcpStream as MioTcpStream};
    use mio::{Events, Interest, Poll, Token, Waker};

    use super::{
        connection_admission_decision, forwarded_headers, invalid_upstream_attempt_transition,
        is_websocket_upgrade, parse_http_request, remove_hop_by_hop_headers,
        resource_accounting_error, response_read_interest_action, runtime_generation_error,
        timeout_decision_for_state, AppError, BTreeSet, ClientTransport, CommandAck,
        ConfigSnapshot, ConnectionAdmissionDecision, ConnectionEvent, ConnectionInterest,
        ConnectionPayloadCharges, ConnectionState, ConnectionTimeoutKind, ConnectionToken,
        CoreCommand, ErrorCode, Header, HttpConnectionIo, HttpLimits, HttpRequest,
        PayloadBudgetLedger, PendingSocketOutput, PreparedClientTlsRegistry,
        PreparedServerTlsRegistry, RequestReadOutcome, ResourceLimits, ResourcePressureState,
        ResponseReadInterestAction, RuntimeResourcePolicy, TlsTransportState,
        UpstreamAttemptFailure, UpstreamEndpoint, UpstreamRequestTarget, UpstreamTarget,
        UpstreamTransport, WriteBuffer,
    };

    #[derive(Debug)]
    pub struct NoopHttp01ChallengeResponder;

    impl Http01ChallengeResponder for NoopHttp01ChallengeResponder {
        fn respond(&self, _token: &str) -> Option<String> {
            None
        }
    }

    pub struct SnapshotProxyConfig {
        pub listen: SocketAddr,
        pub snapshot: ConfigSnapshot,
        pub limits: HttpLimits,
        pub resource_limits: ResourceLimits,
        pub resource_policy: RuntimeResourcePolicy,
        pub challenge_responder: Arc<dyn Http01ChallengeResponder>,
        runtime_commands: Option<SnapshotRuntimeCommandReceiver>,
        access_log_sender: Option<mpsc::SyncSender<AccessLogEvent>>,
        error_log_sender: Option<mpsc::SyncSender<RecentErrorEvent>>,
        tls_failure_sender: Option<mpsc::SyncSender<TlsFailureObservation>>,
        metric_publisher: Option<Arc<dyn MetricPublisher>>,
        product_log_sender: Option<mpsc::SyncSender<edge_ports::StructuredLogEvent>>,
        log_drop_counter: Option<Arc<AtomicU64>>,
        tls_session_factory: Option<Arc<dyn ServerTlsSessionFactory + Send + Sync>>,
        additional_listeners: Vec<SnapshotListenerConfig>,
        passive_observation_dispatcher: Option<Box<dyn PassiveObservationDispatcher + Send>>,
        runtime_status_publisher: Option<Arc<dyn RuntimeUpstreamStatusPublisher>>,
        resource_status_publisher: Option<Arc<dyn RuntimeResourceStatusPublisher>>,
        client_tls_registry: PreparedClientTlsRegistry,
        #[cfg(test)]
        stall_upstream_connect: bool,
        #[cfg(test)]
        backpressure_events: Option<std::sync::mpsc::Sender<BackpressureEvent>>,
        #[cfg(test)]
        resource_accounting_events: Option<std::sync::mpsc::Sender<ResourceAccountingEvent>>,
    }

    struct SnapshotListenerConfig {
        listen: SocketAddr,
        tls_session_factory: Option<Arc<dyn ServerTlsSessionFactory + Send + Sync>>,
    }

    #[cfg(test)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum BackpressureEvent {
        UpstreamReadPaused,
        UpstreamReadResumed,
    }

    #[cfg(test)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct ResourceAccountingEvent {
        pub used_bytes: usize,
        pub live_charges: usize,
        pub client_response_bytes: usize,
        pub tls_pending_bytes: usize,
        pub websocket_client_to_upstream_bytes: usize,
        pub websocket_upstream_to_client_bytes: usize,
    }

    impl SnapshotProxyConfig {
        pub fn new(listen: SocketAddr, snapshot: ConfigSnapshot, limits: HttpLimits) -> Self {
            Self {
                listen,
                snapshot,
                limits,
                resource_limits: ResourceLimits::default(),
                resource_policy: RuntimeResourcePolicy::default(),
                challenge_responder: Arc::new(NoopHttp01ChallengeResponder),
                runtime_commands: None,
                access_log_sender: None,
                error_log_sender: None,
                tls_failure_sender: None,
                metric_publisher: None,
                product_log_sender: None,
                log_drop_counter: None,
                tls_session_factory: None,
                additional_listeners: Vec::new(),
                passive_observation_dispatcher: None,
                runtime_status_publisher: None,
                resource_status_publisher: None,
                client_tls_registry: PreparedClientTlsRegistry::new(),
                #[cfg(test)]
                stall_upstream_connect: false,
                #[cfg(test)]
                backpressure_events: None,
                #[cfg(test)]
                resource_accounting_events: None,
            }
        }

        pub fn with_resource_limits(mut self, resource_limits: ResourceLimits) -> Self {
            self.resource_limits = resource_limits;
            self
        }

        pub fn with_resource_policy(mut self, resource_policy: RuntimeResourcePolicy) -> Self {
            self.resource_policy = resource_policy;
            self
        }

        pub fn with_challenge_responder<R>(mut self, responder: R) -> Self
        where
            R: Http01ChallengeResponder + 'static,
        {
            self.challenge_responder = Arc::new(responder);
            self
        }

        pub fn with_runtime_commands(mut self, commands: SnapshotRuntimeCommandReceiver) -> Self {
            self.runtime_commands = Some(commands);
            self
        }

        pub fn with_access_log_sender(mut self, sender: mpsc::SyncSender<AccessLogEvent>) -> Self {
            self.access_log_sender = Some(sender);
            self
        }

        pub fn with_error_log_sender(mut self, sender: mpsc::SyncSender<RecentErrorEvent>) -> Self {
            self.error_log_sender = Some(sender);
            self
        }

        pub fn with_tls_failure_sender(
            mut self,
            sender: mpsc::SyncSender<TlsFailureObservation>,
        ) -> Self {
            self.tls_failure_sender = Some(sender);
            self
        }

        pub fn with_metric_publisher(mut self, publisher: Arc<dyn MetricPublisher>) -> Self {
            self.metric_publisher = Some(publisher);
            self
        }

        pub fn with_product_log_sender(
            mut self,
            sender: mpsc::SyncSender<edge_ports::StructuredLogEvent>,
        ) -> Self {
            self.product_log_sender = Some(sender);
            self
        }

        pub fn with_log_drop_counter(mut self, counter: Arc<AtomicU64>) -> Self {
            self.log_drop_counter = Some(counter);
            self
        }

        pub fn with_passive_observation_dispatcher<D>(mut self, dispatcher: D) -> Self
        where
            D: PassiveObservationDispatcher + Send + 'static,
        {
            self.passive_observation_dispatcher = Some(Box::new(dispatcher));
            self
        }

        pub fn with_runtime_status_publisher<P>(mut self, publisher: P) -> Self
        where
            P: RuntimeUpstreamStatusPublisher + 'static,
        {
            self.runtime_status_publisher = Some(Arc::new(publisher));
            self
        }

        pub fn with_resource_status_publisher<P>(mut self, publisher: P) -> Self
        where
            P: RuntimeResourceStatusPublisher + 'static,
        {
            self.resource_status_publisher = Some(Arc::new(publisher));
            self
        }

        pub fn with_client_tls_registry(mut self, registry: PreparedClientTlsRegistry) -> Self {
            self.client_tls_registry = registry;
            self
        }

        pub fn with_tls_session_factory<F>(mut self, factory: F) -> Self
        where
            F: ServerTlsSessionFactory + Send + Sync + 'static,
        {
            self.tls_session_factory = Some(Arc::new(factory));
            self
        }

        pub fn with_https_listener<F>(mut self, listen: SocketAddr, factory: F) -> Self
        where
            F: ServerTlsSessionFactory + Send + Sync + 'static,
        {
            self.additional_listeners.push(SnapshotListenerConfig {
                listen,
                tls_session_factory: Some(Arc::new(factory)),
            });
            self
        }

        #[cfg(test)]
        pub(crate) fn with_stalled_upstream_connect(mut self) -> Self {
            self.stall_upstream_connect = true;
            self
        }

        #[cfg(test)]
        pub(crate) fn with_backpressure_events(
            mut self,
            events: std::sync::mpsc::Sender<BackpressureEvent>,
        ) -> Self {
            self.backpressure_events = Some(events);
            self
        }

        #[cfg(test)]
        pub(crate) fn with_resource_accounting_events(
            mut self,
            sender: std::sync::mpsc::Sender<ResourceAccountingEvent>,
        ) -> Self {
            self.resource_accounting_events = Some(sender);
            self
        }
    }

    #[derive(Clone)]
    pub struct SnapshotRuntimeCommandClient {
        sender: mpsc::SyncSender<RuntimeCommandEnvelope>,
        waker: Arc<Mutex<Option<Waker>>>,
    }

    pub struct SnapshotRuntimeCommandReceiver {
        receiver: mpsc::Receiver<RuntimeCommandEnvelope>,
        waker: Arc<Mutex<Option<Waker>>>,
    }

    struct RuntimeCommandEnvelope {
        payload: RuntimeCommandPayload,
        ack: mpsc::Sender<CommandAck>,
    }

    enum RuntimeCommandPayload {
        Core(CoreCommand),
        InstallTlsSessionFactory(Arc<dyn ServerTlsSessionFactory + Send + Sync>),
        InstallServerTlsRegistry(PreparedServerTlsRegistry),
        ApplySnapshotAndTlsSessionFactory {
            snapshot: ConfigSnapshot,
            factory: Arc<dyn ServerTlsSessionFactory + Send + Sync>,
        },
        ActivateSnapshotAndTlsSessionFactory {
            snapshot: ConfigSnapshot,
            availability: HealthAvailabilitySnapshot,
            factory: Arc<dyn ServerTlsSessionFactory + Send + Sync>,
        },
        ActivateRuntimeGeneration {
            snapshot: ConfigSnapshot,
            availability: HealthAvailabilitySnapshot,
            server_tls_registry: PreparedServerTlsRegistry,
            client_tls_registry: PreparedClientTlsRegistry,
        },
    }

    pub fn runtime_command_channel(
        capacity: usize,
    ) -> (SnapshotRuntimeCommandClient, SnapshotRuntimeCommandReceiver) {
        let (sender, receiver) = mpsc::sync_channel(capacity);
        let waker = Arc::new(Mutex::new(None));
        (
            SnapshotRuntimeCommandClient {
                sender,
                waker: Arc::clone(&waker),
            },
            SnapshotRuntimeCommandReceiver { receiver, waker },
        )
    }

    impl SnapshotRuntimeCommandClient {
        pub fn install_tls_session_factory<F>(&mut self, factory: F) -> CommandAck
        where
            F: ServerTlsSessionFactory + Send + Sync + 'static,
        {
            self.send_payload(RuntimeCommandPayload::InstallTlsSessionFactory(Arc::new(
                factory,
            )))
        }

        pub fn install_server_tls_registry(
            &mut self,
            registry: PreparedServerTlsRegistry,
        ) -> CommandAck {
            self.send_payload(RuntimeCommandPayload::InstallServerTlsRegistry(registry))
        }

        pub fn apply_snapshot_with_tls_session_factory<F>(
            &mut self,
            snapshot: ConfigSnapshot,
            factory: F,
        ) -> CommandAck
        where
            F: ServerTlsSessionFactory + Send + Sync + 'static,
        {
            self.send_payload(RuntimeCommandPayload::ApplySnapshotAndTlsSessionFactory {
                snapshot,
                factory: Arc::new(factory),
            })
        }

        pub fn activate_snapshot_with_tls_session_factory<F>(
            &mut self,
            snapshot: ConfigSnapshot,
            availability: HealthAvailabilitySnapshot,
            factory: F,
        ) -> CommandAck
        where
            F: ServerTlsSessionFactory + Send + Sync + 'static,
        {
            self.send_payload(
                RuntimeCommandPayload::ActivateSnapshotAndTlsSessionFactory {
                    snapshot,
                    availability,
                    factory: Arc::new(factory),
                },
            )
        }

        pub fn activate_runtime_generation(
            &mut self,
            snapshot: ConfigSnapshot,
            availability: HealthAvailabilitySnapshot,
            server_tls_registry: PreparedServerTlsRegistry,
            client_tls_registry: PreparedClientTlsRegistry,
        ) -> CommandAck {
            self.send_payload(RuntimeCommandPayload::ActivateRuntimeGeneration {
                snapshot,
                availability,
                server_tls_registry,
                client_tls_registry,
            })
        }

        fn send_payload(&mut self, payload: RuntimeCommandPayload) -> CommandAck {
            let (ack, result) = mpsc::channel();
            let envelope = RuntimeCommandEnvelope { payload, ack };
            match self.sender.try_send(envelope) {
                Ok(()) => {
                    if let Ok(waker) = self.waker.lock() {
                        if let Some(waker) = waker.as_ref() {
                            let _ = waker.wake();
                        }
                    }
                    result.recv().unwrap_or_else(|_| {
                        CommandAck::rejected(AppError::new(
                            ErrorCode::RuntimeCommandRejected,
                            "runtime command acknowledgement channel closed",
                        ))
                    })
                }
                Err(mpsc::TrySendError::Full(_)) => CommandAck::rejected(AppError::new(
                    ErrorCode::RuntimeCommandRejected,
                    "runtime command queue full",
                )),
                Err(mpsc::TrySendError::Disconnected(_)) => CommandAck::rejected(AppError::new(
                    ErrorCode::RuntimeCommandRejected,
                    "runtime command queue closed",
                )),
            }
        }
    }

    impl CoreCommandClient for SnapshotRuntimeCommandClient {
        fn send(&mut self, command: CoreCommand) -> CommandAck {
            self.send_payload(RuntimeCommandPayload::Core(command))
        }
    }

    impl SnapshotRuntimeCommandReceiver {
        pub(crate) fn install_waker(
            &mut self,
            registry: &mio::Registry,
            token: Token,
        ) -> io::Result<()> {
            let waker = Waker::new(registry, token)?;
            let mut target = self
                .waker
                .lock()
                .map_err(|_| io::Error::other("runtime command waker lock poisoned"))?;
            *target = Some(waker);
            Ok(())
        }
    }

    pub fn run_snapshot_http_proxy(config: SnapshotProxyConfig) -> io::Result<()> {
        const LISTENER: Token = Token(0);

        let std_listener = StdTcpListener::bind(config.listen)?;
        std_listener.set_nonblocking(true)?;
        let registry_listener = std_listener.try_clone()?;
        let mut listener = TcpListener::from_std(registry_listener);
        let mut poll = Poll::new()?;
        poll.registry()
            .register(&mut listener, LISTENER, Interest::READABLE)?;
        let mut events = Events::with_capacity(128);
        let snapshot = Arc::new(config.snapshot);
        let limits = config.limits;
        let challenge_responder = config.challenge_responder;

        loop {
            poll.poll(&mut events, None)?;
            for event in &events {
                if event.token() != LISTENER {
                    continue;
                }

                loop {
                    match std_listener.accept() {
                        Ok((stream, peer_addr)) => {
                            let snapshot = Arc::clone(&snapshot);
                            let limits = limits.clone();
                            let challenge_responder = Arc::clone(&challenge_responder);
                            thread::spawn(move || {
                                let client_ip = peer_addr.ip().to_string();
                                let _ = handle_snapshot_http_proxy_connection(
                                    stream,
                                    snapshot.as_ref(),
                                    challenge_responder.as_ref(),
                                    limits,
                                    client_ip,
                                );
                            });
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) => return Err(error),
                    }
                }
            }
        }
    }

    pub fn run_snapshot_http_proxy_mio(config: SnapshotProxyConfig) -> io::Result<()> {
        let std_listener = StdTcpListener::bind(config.listen)?;
        std_listener.set_nonblocking(true)?;
        run_snapshot_http_proxy_mio_with_listener(std_listener, config, None, None)
    }

    #[cfg(test)]
    pub(crate) fn run_snapshot_http_proxy_mio_for_test(
        std_listener: StdTcpListener,
        config: SnapshotProxyConfig,
        completed_limit: usize,
        ready: std::sync::mpsc::Sender<()>,
    ) -> io::Result<()> {
        std_listener.set_nonblocking(true)?;
        run_snapshot_http_proxy_mio_with_listener(
            std_listener,
            config,
            Some(completed_limit),
            Some(ready),
        )
    }

    struct RegisteredSnapshotListener {
        std_listener: StdTcpListener,
        _mio_listener: TcpListener,
        tls_session_factory: Option<Arc<dyn ServerTlsSessionFactory + Send + Sync>>,
        resource_id: String,
    }

    fn register_snapshot_listener(
        poll: &Poll,
        std_listener: StdTcpListener,
        tls_session_factory: Option<Arc<dyn ServerTlsSessionFactory + Send + Sync>>,
        index: usize,
        resource_id: String,
    ) -> io::Result<RegisteredSnapshotListener> {
        std_listener.set_nonblocking(true)?;
        let registry_listener = std_listener.try_clone()?;
        let mut mio_listener = TcpListener::from_std(registry_listener);
        poll.registry()
            .register(&mut mio_listener, listener_token(index), Interest::READABLE)?;
        Ok(RegisteredSnapshotListener {
            std_listener,
            _mio_listener: mio_listener,
            tls_session_factory,
            resource_id,
        })
    }

    fn listener_resource_id(snapshot: &ConfigSnapshot, bind: SocketAddr) -> String {
        snapshot
            .listeners
            .iter()
            .find(|listener| listener.bind.parse::<SocketAddr>().ok() == Some(bind))
            .map(|listener| listener.id.as_str().to_string())
            .unwrap_or_else(|| "unmapped-listener".to_string())
    }

    fn run_snapshot_http_proxy_mio_with_listener(
        std_listener: StdTcpListener,
        mut config: SnapshotProxyConfig,
        completed_limit: Option<usize>,
        ready: Option<std::sync::mpsc::Sender<()>>,
    ) -> io::Result<()> {
        const COMMAND_WAKER: Token = Token(usize::MAX);

        let mut poll = Poll::new()?;
        let primary_resource_id =
            listener_resource_id(&config.snapshot, std_listener.local_addr()?);
        let mut listeners = vec![register_snapshot_listener(
            &poll,
            std_listener,
            config.tls_session_factory.take(),
            0,
            primary_resource_id,
        )?];
        for listener in std::mem::take(&mut config.additional_listeners) {
            let std_listener = StdTcpListener::bind(listener.listen)?;
            let index = listeners.len();
            let resource_id = listener_resource_id(&config.snapshot, std_listener.local_addr()?);
            listeners.push(register_snapshot_listener(
                &poll,
                std_listener,
                listener.tls_session_factory,
                index,
                resource_id,
            )?);
        }
        let mut runtime_commands = config.runtime_commands;
        if let Some(commands) = runtime_commands.as_mut() {
            commands.install_waker(poll.registry(), COMMAND_WAKER)?;
        }
        if let Some(ready) = ready {
            let _ = ready.send(());
        }
        let mut events = Events::with_capacity(128);
        let mut snapshot = Arc::new(config.snapshot);
        let mut upstream_selector = RuntimeUpstreamSelector::from_snapshot(snapshot.as_ref())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.message))?;
        upstream_selector.install_runtime_status_publisher(config.runtime_status_publisher.take());
        let mut runtime = SnapshotMioRuntime::new(
            SnapshotMioRuntimeOptions {
                limits: config.limits,
                resource_limits: config.resource_limits,
                resource_policy: config.resource_policy,
                active_revision_id: snapshot.revision_id.clone(),
                log_mode: snapshot.log_mode.clone(),
                challenge_responder: config.challenge_responder,
                access_log_sender: config.access_log_sender,
                error_log_sender: config.error_log_sender,
                tls_failure_sender: config.tls_failure_sender,
                metric_publisher: config.metric_publisher,
                product_log_sender: config.product_log_sender,
                log_drop_counter: config.log_drop_counter,
                resource_status_publisher: config.resource_status_publisher,
                passive_observation_dispatcher: config.passive_observation_dispatcher,
                client_tls_registry: config.client_tls_registry,
                #[cfg(test)]
                stall_upstream_connect: config.stall_upstream_connect,
                #[cfg(test)]
                backpressure_events: config.backpressure_events,
                #[cfg(test)]
                resource_accounting_events: config.resource_accounting_events,
            },
            upstream_selector,
        );
        let mut idle_polls = 0_usize;

        loop {
            let command_result = drain_runtime_commands_with_listeners(
                &mut runtime_commands,
                &mut snapshot,
                &mut listeners,
                &mut runtime.upstream_selector,
                &mut runtime.client_tls_registry,
            );
            runtime.sync_active_revision(snapshot.as_ref());
            if command_result.shutdown_requested {
                return Ok(());
            }
            for listener in &listeners {
                runtime.accept_ready(
                    &listener.std_listener,
                    listener.tls_session_factory.as_ref(),
                    &listener.resource_id,
                    poll.registry(),
                )?;
            }
            runtime.drive_client_reads(poll.registry(), snapshot.as_ref())?;
            let expired =
                runtime.expire_due_deadlines(poll.registry(), snapshot.as_ref(), Instant::now())?;
            let poll_timeout = poll_timeout_with_runtime_commands(
                runtime.next_poll_timeout(Instant::now(), completed_limit),
                runtime_commands.is_some(),
            );
            poll.poll(&mut events, poll_timeout)?;
            let command_result = drain_runtime_commands_with_listeners(
                &mut runtime_commands,
                &mut snapshot,
                &mut listeners,
                &mut runtime.upstream_selector,
                &mut runtime.client_tls_registry,
            );
            runtime.sync_active_revision(snapshot.as_ref());
            if command_result.shutdown_requested {
                return Ok(());
            }
            let expired_after_poll =
                runtime.expire_due_deadlines(poll.registry(), snapshot.as_ref(), Instant::now())?;
            if completed_limit.is_some_and(|limit| runtime.completed >= limit) {
                return Ok(());
            }
            if events.is_empty() && completed_limit.is_some() && !expired && !expired_after_poll {
                idle_polls += 1;
                if idle_polls > 500 {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "snapshot mio runtime test did not complete: completed={}, connections={}",
                            runtime.completed,
                            runtime.debug_state_summary()
                        ),
                    ));
                }
                continue;
            }
            if !events.is_empty() || expired || expired_after_poll {
                idle_polls = 0;
            }
            for event in &events {
                if event.token() == COMMAND_WAKER {
                    continue;
                }
                if let Some(index) = listener_index(event.token(), listeners.len()) {
                    let listener = &listeners[index];
                    runtime.accept_ready(
                        &listener.std_listener,
                        listener.tls_session_factory.as_ref(),
                        &listener.resource_id,
                        poll.registry(),
                    )?;
                    continue;
                }

                match token_side(event.token()) {
                    Some(TokenSide::Client(connection_id)) => {
                        runtime.client_ready(
                            connection_id,
                            poll.registry(),
                            snapshot.as_ref(),
                            event.is_readable()
                                || event.is_read_closed()
                                || event.is_write_closed(),
                            event.is_writable(),
                            event.is_error(),
                        )?;
                    }
                    Some(TokenSide::Upstream(connection_id)) => {
                        runtime.upstream_ready(
                            connection_id,
                            poll.registry(),
                            snapshot.as_ref(),
                            event.is_readable(),
                            event.is_writable(),
                        )?;
                    }
                    None => {}
                }
            }

            runtime.cleanup_closed(poll.registry())?;
            if completed_limit.is_some_and(|limit| runtime.completed >= limit) {
                return Ok(());
            }
        }
    }

    fn poll_timeout_with_runtime_commands(
        current: Option<Duration>,
        has_runtime_commands: bool,
    ) -> Option<Duration> {
        if !has_runtime_commands {
            return current;
        }
        current
    }

    #[cfg(test)]
    pub(crate) fn drain_runtime_commands(
        commands: &mut Option<SnapshotRuntimeCommandReceiver>,
        snapshot: &mut Arc<ConfigSnapshot>,
    ) -> bool {
        let Ok(mut selector) = RuntimeUpstreamSelector::from_snapshot(snapshot) else {
            return false;
        };
        drain_runtime_commands_with_listeners(
            commands,
            snapshot,
            &mut [],
            &mut selector,
            &mut PreparedClientTlsRegistry::new(),
        )
        .handled
    }

    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    struct RuntimeCommandDrainOutcome {
        handled: bool,
        shutdown_requested: bool,
    }

    fn drain_runtime_commands_with_listeners(
        commands: &mut Option<SnapshotRuntimeCommandReceiver>,
        snapshot: &mut Arc<ConfigSnapshot>,
        listeners: &mut [RegisteredSnapshotListener],
        upstream_selector: &mut RuntimeUpstreamSelector,
        client_tls_registry: &mut PreparedClientTlsRegistry,
    ) -> RuntimeCommandDrainOutcome {
        let Some(commands) = commands else {
            return RuntimeCommandDrainOutcome::default();
        };
        let mut outcome = RuntimeCommandDrainOutcome::default();
        while let Ok(envelope) = commands.receiver.try_recv() {
            let ack = match envelope.payload {
                RuntimeCommandPayload::Core(command) => {
                    let shutdown_requested = matches!(command, CoreCommand::Shutdown);
                    let ack = handle_runtime_command(command, snapshot, upstream_selector);
                    if shutdown_requested && ack.is_success() {
                        outcome.shutdown_requested = true;
                    }
                    ack
                }
                RuntimeCommandPayload::InstallTlsSessionFactory(factory) => {
                    replace_tls_listener_factories(listeners, factory)
                }
                RuntimeCommandPayload::InstallServerTlsRegistry(registry) => {
                    replace_tls_listener_registry(listeners, registry)
                }
                RuntimeCommandPayload::ApplySnapshotAndTlsSessionFactory {
                    snapshot: next,
                    factory,
                } => apply_snapshot_and_tls_factory(
                    snapshot,
                    listeners,
                    upstream_selector,
                    next,
                    factory,
                ),
                RuntimeCommandPayload::ActivateSnapshotAndTlsSessionFactory {
                    snapshot: next,
                    availability,
                    factory,
                } => activate_snapshot_and_tls_factory(
                    snapshot,
                    listeners,
                    upstream_selector,
                    next,
                    availability,
                    factory,
                ),
                RuntimeCommandPayload::ActivateRuntimeGeneration {
                    snapshot: next,
                    availability,
                    server_tls_registry,
                    client_tls_registry: next_client_tls_registry,
                } => activate_runtime_generation(
                    snapshot,
                    listeners,
                    upstream_selector,
                    client_tls_registry,
                    next,
                    availability,
                    server_tls_registry,
                    next_client_tls_registry,
                ),
            };
            let _ = envelope.ack.send(ack);
            outcome.handled = true;
        }
        outcome
    }

    fn replace_tls_listener_factories(
        listeners: &mut [RegisteredSnapshotListener],
        factory: Arc<dyn ServerTlsSessionFactory + Send + Sync>,
    ) -> CommandAck {
        let tls_listener_count = listeners
            .iter()
            .filter(|listener| listener.tls_session_factory.is_some())
            .count();
        if tls_listener_count == 0 {
            return CommandAck::rejected(AppError::new(
                ErrorCode::RuntimeCommandRejected,
                "runtime has no TLS listener",
            ));
        }
        for listener in listeners
            .iter_mut()
            .filter(|listener| listener.tls_session_factory.is_some())
        {
            listener.tls_session_factory = Some(Arc::clone(&factory));
        }
        CommandAck::accepted()
    }

    fn replace_tls_listener_registry(
        listeners: &mut [RegisteredSnapshotListener],
        registry: PreparedServerTlsRegistry,
    ) -> CommandAck {
        let tls_listener_count = listeners
            .iter()
            .filter(|listener| listener.tls_session_factory.is_some())
            .count();
        if registry.len() != tls_listener_count {
            return CommandAck::rejected(runtime_generation_error());
        }
        let mut factories = Vec::with_capacity(listeners.len());
        for listener in listeners.iter() {
            if listener.tls_session_factory.is_some() {
                let bind = match listener.std_listener.local_addr() {
                    Ok(bind) => bind,
                    Err(_) => return CommandAck::rejected(runtime_generation_error()),
                };
                let Some(factory) = registry.factory_for(&bind) else {
                    return CommandAck::rejected(runtime_generation_error());
                };
                factories.push(Some(factory));
            } else {
                factories.push(None);
            }
        }
        for (listener, factory) in listeners.iter_mut().zip(factories) {
            if factory.is_some() {
                listener.tls_session_factory = factory;
            }
        }
        CommandAck::accepted()
    }

    fn apply_snapshot_and_tls_factory(
        snapshot: &mut Arc<ConfigSnapshot>,
        listeners: &mut [RegisteredSnapshotListener],
        upstream_selector: &mut RuntimeUpstreamSelector,
        next: ConfigSnapshot,
        factory: Arc<dyn ServerTlsSessionFactory + Send + Sync>,
    ) -> CommandAck {
        if !listeners
            .iter()
            .any(|listener| listener.tls_session_factory.is_some())
        {
            return CommandAck::rejected(AppError::new(
                ErrorCode::RuntimeCommandRejected,
                "runtime has no TLS listener",
            ));
        }
        if let Err(error) = upstream_selector.reconcile(snapshot, &next) {
            return CommandAck::rejected(error);
        }
        for listener in listeners
            .iter_mut()
            .filter(|listener| listener.tls_session_factory.is_some())
        {
            listener.tls_session_factory = Some(Arc::clone(&factory));
        }
        *snapshot = Arc::new(next);
        CommandAck::accepted()
    }

    fn activate_snapshot_and_tls_factory(
        snapshot: &mut Arc<ConfigSnapshot>,
        listeners: &mut [RegisteredSnapshotListener],
        upstream_selector: &mut RuntimeUpstreamSelector,
        next: ConfigSnapshot,
        availability: HealthAvailabilitySnapshot,
        factory: Arc<dyn ServerTlsSessionFactory + Send + Sync>,
    ) -> CommandAck {
        if !listeners
            .iter()
            .any(|listener| listener.tls_session_factory.is_some())
        {
            return CommandAck::rejected(AppError::new(
                ErrorCode::RuntimeCommandRejected,
                "runtime has no TLS listener",
            ));
        }
        let mut candidate = upstream_selector.clone();
        if let Err(error) = candidate.reconcile(snapshot, &next) {
            return CommandAck::rejected(error);
        }
        if let Err(error) = candidate.apply_availability(&next, availability) {
            return CommandAck::rejected(error);
        }
        for listener in listeners
            .iter_mut()
            .filter(|listener| listener.tls_session_factory.is_some())
        {
            listener.tls_session_factory = Some(Arc::clone(&factory));
        }
        *upstream_selector = candidate;
        *snapshot = Arc::new(next);
        CommandAck::accepted()
    }

    #[allow(clippy::too_many_arguments)]
    fn activate_runtime_generation(
        snapshot: &mut Arc<ConfigSnapshot>,
        listeners: &mut [RegisteredSnapshotListener],
        upstream_selector: &mut RuntimeUpstreamSelector,
        client_tls_registry: &mut PreparedClientTlsRegistry,
        next: ConfigSnapshot,
        availability: HealthAvailabilitySnapshot,
        server_tls_registry: PreparedServerTlsRegistry,
        next_client_tls_registry: PreparedClientTlsRegistry,
    ) -> CommandAck {
        let mut candidate = upstream_selector.clone();
        if let Err(error) = candidate.reconcile(snapshot, &next) {
            return CommandAck::rejected(error);
        }
        if let Err(error) = candidate.apply_availability(&next, availability) {
            return CommandAck::rejected(error);
        }
        if let Err(error) = next_client_tls_registry.validate_for_snapshot(&next) {
            return CommandAck::rejected(error);
        }
        let tls_listener_count = listeners
            .iter()
            .filter(|listener| listener.tls_session_factory.is_some())
            .count();
        if server_tls_registry.len() != tls_listener_count {
            return CommandAck::rejected(runtime_generation_error());
        }
        let mut next_server_factories = Vec::with_capacity(listeners.len());
        for listener in listeners.iter() {
            if listener.tls_session_factory.is_some() {
                let bind = match listener.std_listener.local_addr() {
                    Ok(bind) => bind,
                    Err(_) => return CommandAck::rejected(runtime_generation_error()),
                };
                let Some(factory) = server_tls_registry.factory_for(&bind) else {
                    return CommandAck::rejected(runtime_generation_error());
                };
                next_server_factories.push(Some(factory));
            } else {
                next_server_factories.push(None);
            }
        }
        for (listener, factory) in listeners.iter_mut().zip(next_server_factories) {
            if factory.is_some() {
                listener.tls_session_factory = factory;
            }
        }
        *upstream_selector = candidate;
        *client_tls_registry = next_client_tls_registry;
        *snapshot = Arc::new(next);
        CommandAck::accepted()
    }

    pub(crate) fn handle_runtime_command(
        command: CoreCommand,
        snapshot: &mut Arc<ConfigSnapshot>,
        upstream_selector: &mut RuntimeUpstreamSelector,
    ) -> CommandAck {
        match command {
            CoreCommand::ActivateConfigSnapshot {
                snapshot: next,
                availability,
            } => activate_snapshot(snapshot, upstream_selector, next, availability),
            CoreCommand::ApplyConfigSnapshot { snapshot: next } => {
                if let Err(error) = upstream_selector.reconcile(snapshot, &next) {
                    return CommandAck::rejected(error);
                }
                *snapshot = Arc::new(next);
                CommandAck::accepted()
            }
            CoreCommand::PublishUpstreamAvailability {
                snapshot: availability,
            } => match upstream_selector.apply_availability(snapshot, availability) {
                Ok(()) => CommandAck::accepted(),
                Err(error) => CommandAck::rejected(error),
            },
            CoreCommand::RollbackConfigSnapshot { .. }
            | CoreCommand::InstallCertificate { .. }
            | CoreCommand::RefreshRouteTable
            | CoreCommand::Shutdown => CommandAck::accepted(),
        }
    }

    fn activate_snapshot(
        snapshot: &mut Arc<ConfigSnapshot>,
        upstream_selector: &mut RuntimeUpstreamSelector,
        next: ConfigSnapshot,
        availability: HealthAvailabilitySnapshot,
    ) -> CommandAck {
        let mut candidate = upstream_selector.clone();
        if let Err(error) = candidate.reconcile(snapshot, &next) {
            return CommandAck::rejected(error);
        }
        if let Err(error) = candidate.apply_availability(&next, availability) {
            return CommandAck::rejected(error);
        }
        *upstream_selector = candidate;
        *snapshot = Arc::new(next);
        CommandAck::accepted()
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum TokenSide {
        Client(usize),
        Upstream(usize),
    }

    const LISTENER_TOKEN_BASE: usize = usize::MAX / 2;

    pub(crate) fn listener_token(listener_index: usize) -> Token {
        Token(LISTENER_TOKEN_BASE + listener_index)
    }

    pub(crate) fn listener_index(token: Token, listener_count: usize) -> Option<usize> {
        token
            .0
            .checked_sub(LISTENER_TOKEN_BASE)
            .filter(|index| *index < listener_count)
    }

    fn client_token(connection_id: usize) -> Token {
        Token(connection_id * 2 + 1)
    }

    fn upstream_token(connection_id: usize) -> Token {
        Token(connection_id * 2 + 2)
    }

    pub(crate) fn token_side(token: Token) -> Option<TokenSide> {
        if token.0 >= LISTENER_TOKEN_BASE {
            return None;
        }
        match token.0 {
            0 => None,
            value if value % 2 == 1 => Some(TokenSide::Client((value - 1) / 2)),
            value => Some(TokenSide::Upstream((value - 2) / 2)),
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct RuntimeUpstreamSelection {
        pub(crate) upstream_id: UpstreamId,
        pub(crate) endpoint: UpstreamEndpoint,
        pub(crate) tls: UpstreamTlsPolicy,
        pub(crate) drain_reference: DrainReference,
    }

    #[derive(Clone)]
    pub(crate) struct RuntimeUpstreamSelector {
        sequences: BTreeMap<ServiceId, u64>,
        endpoints: BTreeMap<(ServiceId, UpstreamId), UpstreamEndpoint>,
        availability: BTreeMap<ServiceId, BTreeMap<UpstreamId, edge_domain::UpstreamAvailability>>,
        availability_generation: Option<HealthGeneration>,
        pub(crate) drain_generation: DrainGeneration,
        pub(crate) drain_tracker: UpstreamDrainTracker,
        drain_snapshot: ConfigSnapshot,
        runtime_status_publisher: Option<Arc<dyn RuntimeUpstreamStatusPublisher>>,
    }

    impl RuntimeUpstreamSelector {
        pub(crate) fn from_snapshot(snapshot: &ConfigSnapshot) -> Result<Self, AppError> {
            let drain_generation = DrainGeneration(1);
            let mut selector = Self {
                sequences: BTreeMap::new(),
                endpoints: normalized_endpoint_map(snapshot)?,
                availability: BTreeMap::new(),
                availability_generation: None,
                drain_generation,
                drain_tracker: UpstreamDrainTracker::from_snapshot(snapshot, drain_generation),
                drain_snapshot: snapshot.clone(),
                runtime_status_publisher: None,
            };
            selector.apply_availability(snapshot, initial_availability_snapshot(snapshot))?;
            Ok(selector)
        }

        pub(crate) fn install_runtime_status_publisher(
            &mut self,
            publisher: Option<Arc<dyn RuntimeUpstreamStatusPublisher>>,
        ) {
            self.runtime_status_publisher = publisher;
            self.publish_runtime_status();
        }

        fn publish_runtime_status(&self) {
            if let Some(publisher) = &self.runtime_status_publisher {
                publisher.publish_runtime_status(
                    self.drain_tracker
                        .operational_snapshot(&self.drain_snapshot),
                );
            }
        }

        fn release_drain_reference(&mut self, reference: &DrainReference) {
            let _ = self.drain_tracker.release(reference);
            self.publish_runtime_status();
        }

        pub(crate) fn select(&mut self, service: &Service) -> Option<RuntimeUpstreamSelection> {
            let sequence = self.sequences.get(&service.id).copied().unwrap_or(0);
            let empty = BTreeMap::new();
            let availability = self.availability.get(&service.id).unwrap_or(&empty);
            match select_upstream(service, availability, sequence) {
                UpstreamSelection::Selected {
                    upstream_id,
                    next_sequence,
                } => {
                    let endpoint = self
                        .endpoints
                        .get(&(service.id.clone(), upstream_id.clone()))?
                        .clone();
                    self.sequences.insert(service.id.clone(), next_sequence);
                    let key = edge_domain::UpstreamHealthKey {
                        service_id: service.id.clone(),
                        upstream_id: upstream_id.clone(),
                    };
                    let (DrainAcquireResult::Acquired, Some(drain_reference)) =
                        self.drain_tracker.acquire(self.drain_generation, &key)
                    else {
                        return None;
                    };
                    self.publish_runtime_status();
                    Some(RuntimeUpstreamSelection {
                        tls: service
                            .upstreams
                            .iter()
                            .find(|upstream| upstream.id == upstream_id)?
                            .tls
                            .clone(),
                        upstream_id,
                        endpoint,
                        drain_reference,
                    })
                }
                UpstreamSelection::NoEligibleUpstream => None,
            }
        }

        pub(crate) fn select_retry(
            &mut self,
            service: &Service,
            attempted: &BTreeSet<UpstreamId>,
        ) -> Option<RuntimeUpstreamSelection> {
            let mut retry_service = service.clone();
            retry_service
                .upstreams
                .retain(|upstream| !attempted.contains(&upstream.id));
            let empty = BTreeMap::new();
            let availability = self.availability.get(&service.id).unwrap_or(&empty);
            let sequence = self.sequences.get(&service.id).copied().unwrap_or(0);
            match select_upstream(&retry_service, availability, sequence) {
                UpstreamSelection::Selected { upstream_id, .. } => {
                    let endpoint = self
                        .endpoints
                        .get(&(service.id.clone(), upstream_id.clone()))?
                        .clone();
                    let key = edge_domain::UpstreamHealthKey {
                        service_id: service.id.clone(),
                        upstream_id: upstream_id.clone(),
                    };
                    let (DrainAcquireResult::Acquired, Some(drain_reference)) =
                        self.drain_tracker.acquire(self.drain_generation, &key)
                    else {
                        return None;
                    };
                    self.publish_runtime_status();
                    Some(RuntimeUpstreamSelection {
                        tls: service
                            .upstreams
                            .iter()
                            .find(|upstream| upstream.id == upstream_id)?
                            .tls
                            .clone(),
                        endpoint,
                        upstream_id,
                        drain_reference,
                    })
                }
                UpstreamSelection::NoEligibleUpstream => None,
            }
        }

        pub(crate) fn reconcile(
            &mut self,
            current: &ConfigSnapshot,
            next: &ConfigSnapshot,
        ) -> Result<(), AppError> {
            let endpoints = normalized_endpoint_map(next)?;
            self.sequences.retain(|service_id, _| {
                let Some(current_service) = current.find_service(service_id) else {
                    return false;
                };
                let Some(next_service) = next.find_service(service_id) else {
                    return false;
                };
                current_service.policy.load_balancing == next_service.policy.load_balancing
                    && current_service
                        .upstreams
                        .iter()
                        .map(|upstream| &upstream.id)
                        .eq(next_service.upstreams.iter().map(|upstream| &upstream.id))
            });
            self.endpoints = endpoints;
            self.drain_generation = DrainGeneration(self.drain_generation.0.wrapping_add(1));
            self.drain_tracker.reconcile(next, self.drain_generation);
            self.drain_snapshot = next.clone();
            self.publish_runtime_status();
            if current.revision_id != next.revision_id {
                self.availability.clear();
                self.availability_generation = None;
            }
            Ok(())
        }

        pub(crate) fn apply_availability(
            &mut self,
            current: &ConfigSnapshot,
            snapshot: HealthAvailabilitySnapshot,
        ) -> Result<(), AppError> {
            if snapshot.revision_id != current.revision_id {
                return Err(runtime_availability_error(
                    "availability revision does not match active config",
                ));
            }
            if self
                .availability_generation
                .is_some_and(|generation| snapshot.generation.0 < generation.0)
            {
                return Err(runtime_availability_error(
                    "availability generation is stale",
                ));
            }
            let expected_count = current
                .services
                .iter()
                .map(|service| service.upstreams.len())
                .sum::<usize>();
            if snapshot.entries.len() != expected_count
                || current.services.iter().any(|service| {
                    service.upstreams.iter().any(|upstream| {
                        !snapshot
                            .entries
                            .contains_key(&edge_ports::UpstreamHealthKey {
                                service_id: service.id.clone(),
                                upstream_id: upstream.id.clone(),
                            })
                    })
                })
            {
                return Err(runtime_availability_error(
                    "availability keys do not match active config",
                ));
            }

            let mut availability = BTreeMap::new();
            for (key, value) in snapshot.entries {
                availability
                    .entry(key.service_id)
                    .or_insert_with(BTreeMap::new)
                    .insert(key.upstream_id, value);
            }
            self.availability = availability;
            self.availability_generation = Some(snapshot.generation);
            Ok(())
        }
    }

    fn runtime_availability_error(message: &str) -> AppError {
        AppError::new(ErrorCode::RuntimeCommandRejected, message)
    }

    pub(crate) fn initial_availability_snapshot(
        snapshot: &ConfigSnapshot,
    ) -> HealthAvailabilitySnapshot {
        let mut entries = BTreeMap::new();
        for service in &snapshot.services {
            let initial = if matches!(
                service.policy.health_check,
                edge_domain::HealthCheckPolicy::Disabled
            ) {
                edge_domain::UpstreamAvailability::Disabled
            } else {
                edge_domain::UpstreamAvailability::Unknown
            };
            for upstream in &service.upstreams {
                entries.insert(
                    edge_ports::UpstreamHealthKey {
                        service_id: service.id.clone(),
                        upstream_id: upstream.id.clone(),
                    },
                    initial,
                );
            }
        }
        HealthAvailabilitySnapshot {
            revision_id: snapshot.revision_id.clone(),
            generation: HealthGeneration(0),
            entries,
        }
    }

    fn normalized_endpoint_map(
        snapshot: &ConfigSnapshot,
    ) -> Result<BTreeMap<(ServiceId, UpstreamId), UpstreamEndpoint>, AppError> {
        let mut endpoints = BTreeMap::new();
        for service in &snapshot.services {
            for upstream in &service.upstreams {
                let endpoint = UpstreamEndpoint::parse(&upstream.url)
                    .map_err(|error| AppError::new(error.code, error.message))?;
                endpoints.insert((service.id.clone(), upstream.id.clone()), endpoint);
            }
        }
        Ok(endpoints)
    }

    struct SnapshotMioRuntime {
        next_connection_id: usize,
        connections: BTreeMap<usize, SnapshotMioConnection>,
        limits: HttpLimits,
        resource_limits: ResourceLimits,
        resource_policy: RuntimeResourcePolicy,
        payload_ledger: PayloadBudgetLedger,
        last_resource_payload_bytes: Option<usize>,
        last_resource_pressure_state: ResourcePressureState,
        last_resource_status: Option<RuntimeResourceStatusSnapshot>,
        resource_status_generation: u64,
        resource_status_publisher: Option<Arc<dyn RuntimeResourceStatusPublisher>>,
        active_revision_id: ConfigRevisionId,
        log_mode: LogMode,
        resource_log_started_at: Instant,
        resource_admission_log_sampler: ResourceAdmissionLogSampler,
        challenge_responder: Arc<dyn Http01ChallengeResponder>,
        access_log_sender: Option<mpsc::SyncSender<AccessLogEvent>>,
        error_log_sender: Option<mpsc::SyncSender<RecentErrorEvent>>,
        tls_failure_sender: Option<mpsc::SyncSender<TlsFailureObservation>>,
        metric_publisher: Option<Arc<dyn MetricPublisher>>,
        product_log_sender: Option<mpsc::SyncSender<edge_ports::StructuredLogEvent>>,
        log_drop_counter: Option<Arc<AtomicU64>>,
        passive_observation_dispatcher: Option<Box<dyn PassiveObservationDispatcher + Send>>,
        client_tls_registry: PreparedClientTlsRegistry,
        upstream_selector: RuntimeUpstreamSelector,
        #[cfg(test)]
        stall_upstream_connect: bool,
        #[cfg(test)]
        backpressure_events: Option<std::sync::mpsc::Sender<BackpressureEvent>>,
        #[cfg(test)]
        resource_accounting_events: Option<std::sync::mpsc::Sender<ResourceAccountingEvent>>,
        completed: usize,
    }

    struct SnapshotMioRuntimeOptions {
        limits: HttpLimits,
        resource_limits: ResourceLimits,
        resource_policy: RuntimeResourcePolicy,
        active_revision_id: ConfigRevisionId,
        log_mode: LogMode,
        challenge_responder: Arc<dyn Http01ChallengeResponder>,
        access_log_sender: Option<mpsc::SyncSender<AccessLogEvent>>,
        error_log_sender: Option<mpsc::SyncSender<RecentErrorEvent>>,
        tls_failure_sender: Option<mpsc::SyncSender<TlsFailureObservation>>,
        metric_publisher: Option<Arc<dyn MetricPublisher>>,
        product_log_sender: Option<mpsc::SyncSender<edge_ports::StructuredLogEvent>>,
        log_drop_counter: Option<Arc<AtomicU64>>,
        resource_status_publisher: Option<Arc<dyn RuntimeResourceStatusPublisher>>,
        passive_observation_dispatcher: Option<Box<dyn PassiveObservationDispatcher + Send>>,
        client_tls_registry: PreparedClientTlsRegistry,
        #[cfg(test)]
        stall_upstream_connect: bool,
        #[cfg(test)]
        backpressure_events: Option<std::sync::mpsc::Sender<BackpressureEvent>>,
        #[cfg(test)]
        resource_accounting_events: Option<std::sync::mpsc::Sender<ResourceAccountingEvent>>,
    }

    impl SnapshotMioRuntime {
        fn new(
            options: SnapshotMioRuntimeOptions,
            upstream_selector: RuntimeUpstreamSelector,
        ) -> Self {
            let mut runtime = Self {
                next_connection_id: 0,
                connections: BTreeMap::new(),
                limits: options.limits,
                resource_limits: options.resource_limits,
                resource_policy: options.resource_policy,
                payload_ledger: PayloadBudgetLedger::new(options.resource_policy, 1),
                last_resource_payload_bytes: None,
                last_resource_pressure_state: ResourcePressureState::Normal,
                last_resource_status: None,
                resource_status_generation: 0,
                resource_status_publisher: options.resource_status_publisher,
                active_revision_id: options.active_revision_id,
                log_mode: options.log_mode,
                resource_log_started_at: Instant::now(),
                resource_admission_log_sampler: ResourceAdmissionLogSampler::new(60, 8_192),
                challenge_responder: options.challenge_responder,
                access_log_sender: options.access_log_sender,
                error_log_sender: options.error_log_sender,
                tls_failure_sender: options.tls_failure_sender,
                metric_publisher: options.metric_publisher,
                product_log_sender: options.product_log_sender,
                log_drop_counter: options.log_drop_counter,
                passive_observation_dispatcher: options.passive_observation_dispatcher,
                client_tls_registry: options.client_tls_registry,
                upstream_selector,
                #[cfg(test)]
                stall_upstream_connect: options.stall_upstream_connect,
                #[cfg(test)]
                backpressure_events: options.backpressure_events,
                #[cfg(test)]
                resource_accounting_events: options.resource_accounting_events,
                completed: 0,
            };
            runtime.emit_metric(resource_payload_limit_bytes_metric(
                runtime.resource_policy.max_inflight_payload_bytes(),
            ));
            runtime.emit_resource_payload_metric_if_changed();
            runtime.emit_product_log(structured_resource_policy_active_log(
                &runtime.resource_log_context(),
            ));
            runtime.emit_resource_status_if_changed();
            runtime
        }

        fn next_poll_timeout(
            &self,
            now: Instant,
            completed_limit: Option<usize>,
        ) -> Option<Duration> {
            let deadline_timeout = self
                .connections
                .values()
                .filter_map(|connection| connection.deadline)
                .min()
                .map(|deadline| deadline.saturating_duration_since(now));
            let test_timeout = completed_limit.map(|_| Duration::from_millis(10));

            match (deadline_timeout, test_timeout) {
                (Some(deadline_timeout), Some(test_timeout)) => {
                    Some(deadline_timeout.min(test_timeout))
                }
                (Some(deadline_timeout), None) => Some(deadline_timeout),
                (None, Some(test_timeout)) => Some(test_timeout),
                (None, None) => None,
            }
        }

        fn expire_due_deadlines(
            &mut self,
            registry: &mio::Registry,
            snapshot: &ConfigSnapshot,
            now: Instant,
        ) -> io::Result<bool> {
            let expired_connections: Vec<_> = self
                .connections
                .iter()
                .filter(|(_, connection)| {
                    connection.deadline.is_some_and(|deadline| deadline <= now)
                })
                .map(|(connection_id, _)| *connection_id)
                .collect();

            let expired = !expired_connections.is_empty();
            for connection_id in expired_connections {
                self.expire_connection(connection_id, registry, snapshot, now)?;
            }
            self.enforce_resource_pressure_interests(registry)?;
            Ok(expired)
        }

        fn accept_ready(
            &mut self,
            listener: &StdTcpListener,
            tls_session_factory: Option<&Arc<dyn ServerTlsSessionFactory + Send + Sync>>,
            listener_resource_id: &str,
            registry: &mio::Registry,
        ) -> io::Result<()> {
            loop {
                match listener.accept() {
                    Ok((client, peer_addr)) => {
                        let admission = connection_admission_decision(
                            self.payload_ledger.pressure_state(),
                            self.connections.len(),
                            self.resource_policy.max_connections(),
                        );
                        if admission != ConnectionAdmissionDecision::Accepted {
                            self.emit_resource_admission_rejection(admission);
                            continue;
                        }
                        let connection_id = self.next_connection_id;
                        self.next_connection_id += 1;
                        let accepted_at = Instant::now();
                        client.set_nonblocking(true)?;
                        let mut client = MioTcpStream::from_std(client);
                        registry.register(
                            &mut client,
                            client_token(connection_id),
                            Interest::READABLE,
                        )?;
                        let client_transport = tls_session_factory
                            .map(|factory| ClientTransport::tls(factory.create_server_session()))
                            .unwrap_or_else(ClientTransport::plaintext);
                        self.connections.insert(
                            connection_id,
                            SnapshotMioConnection {
                                client,
                                client_transport,
                                pending_client_output: PendingSocketOutput::new(),
                                pending_client_response: PendingClientResponseBatch::Empty,
                                upstream: None,
                                upstream_transport: UpstreamTransport::plaintext(),
                                pending_upstream_output: WriteBuffer::default(),
                                pending_upstream_tls: None,
                                io: HttpConnectionIo::new(ConnectionToken::new(connection_id)),
                                client_ip: peer_addr.ip().to_string(),
                                listener_resource_id: listener_resource_id.to_string(),
                                accepted_at,
                                access_log: None,
                                close_after_write: false,
                                pending_upstream_request: None,
                                websocket_requested: false,
                                websocket_response: Vec::new(),
                                client_registered: true,
                                upstream_registered: false,
                                tunnel_client_to_upstream: WriteBuffer::default(),
                                tunnel_upstream_to_client: WriteBuffer::default(),
                                deadline: deadline_for_state(
                                    &self.resource_limits,
                                    &ConnectionState::Accepted,
                                    accepted_at,
                                ),
                                retry: None,
                                drain_reference: None,
                                resource_charges: ConnectionPayloadCharges::default(),
                                response_framing: None,
                            },
                        );
                        self.emit_active_connection_metric();
                        self.emit_resource_status_if_changed();
                        self.reconcile_transport_payload_charges(connection_id, registry)?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                    Err(error) => return Err(error),
                }
            }
        }

        fn client_ready(
            &mut self,
            connection_id: usize,
            registry: &mio::Registry,
            snapshot: &ConfigSnapshot,
            readable: bool,
            writable: bool,
            transport_error: bool,
        ) -> io::Result<()> {
            let websocket_tunnel = self
                .connections
                .get(&connection_id)
                .is_some_and(|connection| {
                    connection.io.connection.state == ConnectionState::TunnelingWebSocket
                });
            if websocket_tunnel {
                if readable && self.payload_ledger.pressure_state() == ResourcePressureState::Normal
                {
                    self.read_client_tunnel(connection_id, registry)?;
                }
                if writable {
                    self.write_client_tunnel(connection_id, registry)?;
                }
                return self.reconcile_transport_payload_charges(connection_id, registry);
            }

            let client_read_allowed =
                self.connections
                    .get(&connection_id)
                    .is_some_and(|connection| {
                        matches!(
                            connection.io.connection.state,
                            ConnectionState::Accepted | ConnectionState::ReadingClientRequest
                        )
                    });
            if !client_read_allowed && transport_error {
                self.drop_upstream(connection_id, registry)?;
                self.remove_connection(connection_id, true);
                return Ok(());
            }
            if readable && client_read_allowed {
                self.read_client(connection_id, registry, snapshot)?;
            }
            if writable {
                self.write_client(connection_id, registry)?;
            }
            self.reconcile_transport_payload_charges(connection_id, registry)
        }

        fn upstream_ready(
            &mut self,
            connection_id: usize,
            registry: &mio::Registry,
            snapshot: &ConfigSnapshot,
            readable: bool,
            writable: bool,
        ) -> io::Result<()> {
            let websocket_tunnel = self
                .connections
                .get(&connection_id)
                .is_some_and(|connection| {
                    connection.io.connection.state == ConnectionState::TunnelingWebSocket
                });
            if websocket_tunnel {
                if readable && self.payload_ledger.pressure_state() == ResourcePressureState::Normal
                {
                    self.read_upstream_tunnel(connection_id, registry)?;
                }
                if writable {
                    self.write_upstream_tunnel(connection_id, registry)?;
                }
                return self.reconcile_transport_payload_charges(connection_id, registry);
            }

            if writable {
                self.write_upstream(connection_id, registry, snapshot)?;
            }
            if readable {
                self.read_upstream(connection_id, registry, snapshot)?;
            }
            self.reconcile_transport_payload_charges(connection_id, registry)
        }

        fn read_client(
            &mut self,
            connection_id: usize,
            registry: &mio::Registry,
            snapshot: &ConfigSnapshot,
        ) -> io::Result<()> {
            let mut completed_request = None;
            let mut response = None;
            let mut progressed = false;
            let mut transport_output_ready = false;
            let mut transport_failure = None;
            #[cfg(test)]
            let mut resource_accounting_changed = false;

            {
                let (connections, payload_ledger) =
                    (&mut self.connections, &mut self.payload_ledger);
                let Some(connection) = connections.get_mut(&connection_id) else {
                    return Ok(());
                };
                let mut buffer = [0_u8; 4096];
                loop {
                    match connection.client.read(&mut buffer) {
                        Ok(0) => {
                            let _ = connection
                                .io
                                .connection
                                .handle_event(ConnectionEvent::IoError);
                            connection.close_after_write = true;
                            connection.deadline = None;
                            let _ = registry.deregister(&mut connection.client);
                            let (code, message) =
                                if connection.client_transport.forwarded_scheme() == "https" {
                                    (
                                        ErrorCode::TlsHandshakeFailed,
                                        "client closed during TLS handshake",
                                    )
                                } else {
                                    (
                                        ErrorCode::HttpMalformedRequest,
                                        "client closed before completing the request",
                                    )
                                };
                            transport_failure = Some(AppError::new(code, message));
                            break;
                        }
                        Ok(read) => {
                            progressed = true;
                            let plaintext = match connection
                                .client_transport
                                .receive_socket_bytes(&buffer[..read])
                            {
                                Ok(plaintext) => plaintext,
                                Err(error) => {
                                    let _ = connection
                                        .io
                                        .connection
                                        .handle_event(ConnectionEvent::IoError);
                                    connection.close_after_write = true;
                                    connection.deadline = None;
                                    let _ = registry.deregister(&mut connection.client);
                                    transport_failure = Some(error);
                                    break;
                                }
                            };
                            if connection.pending_client_output.is_empty()
                                && connection
                                    .pending_client_output
                                    .pull_from(&mut connection.client_transport, usize::MAX)
                                    > 0
                            {
                                transport_output_ready = true;
                            }
                            if plaintext.is_empty() {
                                continue;
                            }
                            if let Err(error) = connection.resource_charges.grow_request(
                                payload_ledger,
                                connection_id,
                                plaintext.len(),
                            ) {
                                response = Some(error_response_for_code(error.code));
                                break;
                            }
                            #[cfg(test)]
                            {
                                resource_accounting_changed = true;
                            }
                            match connection.io.receive_client_bytes(&plaintext, &self.limits) {
                                Ok(RequestReadOutcome::Incomplete) => {}
                                Ok(RequestReadOutcome::Complete(bytes)) => {
                                    completed_request = Some(bytes);
                                    break;
                                }
                                Err(error) => {
                                    response = Some(error_response_for_code(error.code));
                                    break;
                                }
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(_) => {
                            response = Some(http_error_response(400, "Bad Request"));
                            break;
                        }
                    }
                }
            }

            self.emit_resource_payload_metric_if_changed();
            #[cfg(test)]
            if resource_accounting_changed {
                self.emit_resource_accounting_event();
            }

            if transport_output_ready {
                if let Some(connection) = self.connections.get_mut(&connection_id) {
                    registry.reregister(
                        &mut connection.client,
                        client_token(connection_id),
                        Interest::READABLE | Interest::WRITABLE,
                    )?;
                }
            }

            if let Some(error) = transport_failure {
                self.emit_error_log(connection_id, error.code, &error.message);
                self.drop_upstream(connection_id, registry)?;
                self.remove_connection(connection_id, false);
                return Ok(());
            }

            if let Some(response) = response {
                self.queue_client_response(connection_id, registry, response)?;
                return Ok(());
            }

            if let Some(bytes) = completed_request {
                let route_result =
                    self.route_completed_request(connection_id, registry, snapshot, &bytes);
                self.release_request_charge(connection_id);
                route_result?;
            } else if progressed {
                self.refresh_connection_deadline(connection_id, Instant::now());
            }

            Ok(())
        }

        fn drive_client_reads(
            &mut self,
            registry: &mio::Registry,
            snapshot: &ConfigSnapshot,
        ) -> io::Result<()> {
            let readable_connections: Vec<_> = self
                .connections
                .iter()
                .filter(|(_, connection)| {
                    matches!(
                        connection.io.connection.state,
                        ConnectionState::Accepted | ConnectionState::ReadingClientRequest
                    )
                })
                .map(|(connection_id, _)| *connection_id)
                .collect();

            for connection_id in readable_connections {
                self.read_client(connection_id, registry, snapshot)?;
            }
            Ok(())
        }

        fn route_completed_request(
            &mut self,
            connection_id: usize,
            registry: &mio::Registry,
            snapshot: &ConfigSnapshot,
            request_bytes: &[u8],
        ) -> io::Result<()> {
            let request = match parse_http_request(request_bytes, &self.limits) {
                Ok(request) => request,
                Err(error) => {
                    self.queue_client_response(
                        connection_id,
                        registry,
                        error_response_for_code(error.code),
                    )?;
                    return Ok(());
                }
            };
            self.begin_access_log(connection_id, snapshot, &request);

            let Some(authority) = request.header_value("Host") else {
                self.queue_client_response(
                    connection_id,
                    registry,
                    http_error_response(400, "Bad Request"),
                )?;
                return Ok(());
            };
            let match_host = host_for_route_match(authority);

            match select_http_route_action(snapshot, &match_host, &request.path) {
                HttpRouteAction::Proxy {
                    route_id,
                    service_id,
                } => {
                    let Some(service) = snapshot.find_service(&service_id) else {
                        self.queue_client_response(
                            connection_id,
                            registry,
                            http_error_response(502, "Bad Gateway"),
                        )?;
                        return Ok(());
                    };
                    let Some(selection) = self.upstream_selector.select(service) else {
                        self.emit_metric(no_eligible_upstream_metric(&service.id));
                        self.queue_client_response(
                            connection_id,
                            registry,
                            http_error_response(503, "Service Unavailable"),
                        )?;
                        return Ok(());
                    };
                    self.emit_metric(upstream_selection_metric(&edge_domain::UpstreamHealthKey {
                        service_id: service.id.clone(),
                        upstream_id: selection.upstream_id.clone(),
                    }));
                    let upstream_id = selection.upstream_id.as_str().to_string();
                    let upstream_target = selection.endpoint;
                    let tls_policy = selection.tls;
                    if upstream_target.scheme() == UpstreamScheme::Https
                        && !self
                            .client_tls_registry
                            .contains(&service.id, &selection.upstream_id)
                    {
                        self.upstream_selector
                            .release_drain_reference(&selection.drain_reference);
                        self.queue_client_response(
                            connection_id,
                            registry,
                            http_error_response(502, "Bad Gateway"),
                        )?;
                        return Ok(());
                    }
                    if let Some(connection) = self.connections.get_mut(&connection_id) {
                        connection.drain_reference = Some(selection.drain_reference);
                    }
                    let upstream_addr =
                        match upstream_target.connect_address().parse::<SocketAddr>() {
                            Ok(address) => address,
                            Err(_) => {
                                self.queue_client_response(
                                    connection_id,
                                    registry,
                                    http_error_response(502, "Bad Gateway"),
                                )?;
                                return Ok(());
                            }
                        };
                    let websocket_requested = is_websocket_upgrade(&request);
                    let connection = &self.connections[&connection_id];
                    let original_authority = authority.to_string();
                    let forwarded_scheme =
                        connection.client_transport.forwarded_scheme().to_string();
                    let planned_upstream_bytes = match planned_selected_upstream_request_len(
                        &request,
                        &upstream_target,
                        &tls_policy,
                        &connection.client_ip,
                        &forwarded_scheme,
                        authority,
                        websocket_requested,
                    ) {
                        Ok(planned) => planned,
                        Err(_) => {
                            self.queue_client_response(
                                connection_id,
                                registry,
                                error_response_for_code(ErrorCode::ResourceAllocationFailed),
                            )?;
                            return Ok(());
                        }
                    };
                    let retry_replay_bytes = request_bytes.len();
                    let reservation = {
                        let (connections, payload_ledger) =
                            (&mut self.connections, &mut self.payload_ledger);
                        let Some(connection) = connections.get_mut(&connection_id) else {
                            return Ok(());
                        };
                        connection.resource_charges.reserve_upstream_and_retry(
                            payload_ledger,
                            connection_id,
                            planned_upstream_bytes,
                            retry_replay_bytes,
                        )
                    };
                    if let Err(error) = reservation {
                        self.queue_client_response(
                            connection_id,
                            registry,
                            error_response_for_code(error.code),
                        )?;
                        return Ok(());
                    }
                    self.emit_resource_payload_metric_if_changed();
                    #[cfg(test)]
                    self.emit_resource_accounting_event();
                    let connection = &self.connections[&connection_id];
                    let upstream_request = match build_selected_upstream_request(
                        &request,
                        &upstream_target,
                        &tls_policy,
                        &connection.client_ip,
                        &forwarded_scheme,
                        authority,
                        websocket_requested,
                    ) {
                        Ok(request) => request,
                        Err(_) => {
                            let release_result = {
                                let (connections, payload_ledger) =
                                    (&mut self.connections, &mut self.payload_ledger);
                                connections.get_mut(&connection_id).map(|connection| {
                                    connection
                                        .resource_charges
                                        .release_upstream_allocation_failure(payload_ledger)
                                })
                            };
                            if let Some(Err(error)) = release_result {
                                self.emit_error_log(connection_id, error.code, &error.message);
                            }
                            self.emit_resource_payload_metric_if_changed();
                            #[cfg(test)]
                            self.emit_resource_accounting_event();
                            self.queue_client_response(
                                connection_id,
                                registry,
                                error_response_for_code(ErrorCode::ResourceAllocationFailed),
                            )?;
                            return Ok(());
                        }
                    };
                    let commit_result = {
                        let (connections, payload_ledger) =
                            (&self.connections, &mut self.payload_ledger);
                        let Some(connection) = connections.get(&connection_id) else {
                            return Ok(());
                        };
                        connection.resource_charges.commit_upstream_and_retry(
                            payload_ledger,
                            upstream_request.len(),
                            retry_replay_bytes,
                        )
                    };
                    if let Err(error) = commit_result {
                        self.emit_error_log(connection_id, error.code, &error.message);
                        self.queue_client_response(
                            connection_id,
                            registry,
                            error_response_for_code(error.code),
                        )?;
                        return Ok(());
                    }
                    if let Some(connection) = self.connections.get_mut(&connection_id) {
                        connection.retry = Some(RetryContext {
                            service_id: service.id.clone(),
                            policy: service.policy.retry,
                            method: match request.method.as_str() {
                                "GET" => edge_domain::ReplayMethod::Get,
                                "HEAD" => edge_domain::ReplayMethod::Head,
                                _ => edge_domain::ReplayMethod::Other,
                            },
                            body_bytes: request.body.len() as u64,
                            attempted: BTreeSet::from([selection.upstream_id.clone()]),
                            current_upstream_id: selection.upstream_id.clone(),
                            retries_used: 0,
                            replay_wire_len: upstream_request.len(),
                            original_request: request,
                            original_authority,
                            forwarded_scheme,
                            websocket_requested,
                        });
                    }
                    self.update_access_log_route(
                        connection_id,
                        Some(route_id.as_str().to_string()),
                        Some(upstream_id),
                    );
                    self.connect_upstream(
                        connection_id,
                        registry,
                        snapshot,
                        UpstreamConnectPlan {
                            address: upstream_addr,
                            request: upstream_request,
                            websocket_requested,
                            service_id: service.id.clone(),
                            upstream_id: selection.upstream_id,
                            tls_policy,
                        },
                    )
                }
                HttpRouteAction::Redirect { status_code, .. } => self.queue_client_response(
                    connection_id,
                    registry,
                    redirect_response(status_code, authority, &request.path),
                ),
                HttpRouteAction::AcmeChallengeBypass { token } => {
                    if let Some(body) = self.challenge_responder.respond(&token) {
                        self.queue_client_response(
                            connection_id,
                            registry,
                            plain_response(200, "OK", body.as_bytes()),
                        )
                    } else {
                        self.queue_client_response(
                            connection_id,
                            registry,
                            http_error_response(404, "Not Found"),
                        )
                    }
                }
                HttpRouteAction::NotFound => self.queue_client_response(
                    connection_id,
                    registry,
                    http_error_response(404, "Not Found"),
                ),
            }
        }

        fn connect_upstream(
            &mut self,
            connection_id: usize,
            registry: &mio::Registry,
            snapshot: &ConfigSnapshot,
            plan: UpstreamConnectPlan,
        ) -> io::Result<()> {
            let UpstreamConnectPlan {
                address: upstream_addr,
                request: upstream_request,
                websocket_requested,
                service_id,
                upstream_id,
                tls_policy,
            } = plan;
            #[cfg(test)]
            if self.stall_upstream_connect {
                let Some(connection) = self.connections.get_mut(&connection_id) else {
                    return Ok(());
                };
                if connection.io.begin_upstream_connect().is_err() {
                    self.queue_client_response(
                        connection_id,
                        registry,
                        http_error_response(502, "Bad Gateway"),
                    )?;
                    return Ok(());
                }
                connection.pending_upstream_request = Some(upstream_request);
                connection.websocket_requested = websocket_requested;
                connection
                    .begin_response_framing(self.limits.max_header_bytes, websocket_requested);
                connection.pending_upstream_tls =
                    pending_upstream_tls(service_id, upstream_id, &tls_policy);
                refresh_deadline_for_connection(connection, &self.resource_limits, Instant::now());
                return Ok(());
            }

            let Some(connection) = self.connections.get_mut(&connection_id) else {
                return Ok(());
            };
            if connection.io.begin_upstream_connect().is_err() {
                self.queue_client_response(
                    connection_id,
                    registry,
                    upstream_failure_response(UpstreamAttemptFailure::Connect),
                )?;
                return Ok(());
            }
            connection.pending_upstream_request = Some(upstream_request);
            connection.websocket_requested = websocket_requested;
            connection.begin_response_framing(self.limits.max_header_bytes, websocket_requested);
            connection.upstream_transport = UpstreamTransport::plaintext();
            connection.pending_upstream_output = WriteBuffer::default();
            connection.pending_upstream_tls =
                pending_upstream_tls(service_id, upstream_id, &tls_policy);

            let mut upstream = match MioTcpStream::connect(upstream_addr) {
                Ok(upstream) => upstream,
                Err(_) => {
                    if let Some(connection) = self.connections.get_mut(&connection_id) {
                        let _ = connection
                            .io
                            .fail_upstream_attempt(UpstreamAttemptFailure::Connect);
                    }
                    let _ = self.submit_passive_observation(
                        connection_id,
                        snapshot,
                        PassiveObservationOutcome::Failed(PassiveFailureReason::Connect),
                    );
                    if !self.retry_upstream(
                        connection_id,
                        registry,
                        snapshot,
                        UpstreamAttemptFailure::Connect,
                    )? {
                        self.queue_client_response(
                            connection_id,
                            registry,
                            upstream_failure_response(UpstreamAttemptFailure::Connect),
                        )?;
                    }
                    return Ok(());
                }
            };
            registry.register(
                &mut upstream,
                upstream_token(connection_id),
                Interest::WRITABLE,
            )?;

            let Some(connection) = self.connections.get_mut(&connection_id) else {
                return Ok(());
            };
            connection.upstream = Some(upstream);
            connection.upstream_registered = true;
            refresh_deadline_for_connection(connection, &self.resource_limits, Instant::now());
            Ok(())
        }

        fn write_upstream(
            &mut self,
            connection_id: usize,
            registry: &mio::Registry,
            snapshot: &ConfigSnapshot,
        ) -> io::Result<()> {
            let mut attempt_failure = None;
            {
                let Some(connection) = self.connections.get_mut(&connection_id) else {
                    return Ok(());
                };
                let Some(upstream) = connection.upstream.as_mut() else {
                    return Ok(());
                };
                if connection.io.connection.state == ConnectionState::ConnectingUpstream {
                    if let Some(error) = upstream.take_error()? {
                        let _ = error;
                        let failure = UpstreamAttemptFailure::Connect;
                        let _ = connection.io.fail_upstream_attempt(failure);
                        attempt_failure = Some(failure);
                    } else if let Some(tls) = connection.pending_upstream_tls.take() {
                        match self.client_tls_registry.create_session(
                            &tls.service_id,
                            &tls.upstream_id,
                            &tls.server_name,
                        ) {
                            Ok(session) => {
                                connection.upstream_transport = UpstreamTransport::tls(session);
                                let session_failed = matches!(
                                    connection.upstream_transport.tls_state(),
                                    Some(TlsTransportState::Failed(_))
                                        | Some(TlsTransportState::PeerClosed)
                                );
                                let transition_failed = !session_failed
                                    && connection
                                        .io
                                        .connection
                                        .handle_event(ConnectionEvent::UpstreamTlsHandshakeStarted)
                                        .is_err();
                                if session_failed || transition_failed {
                                    let failure = UpstreamAttemptFailure::TlsHandshake;
                                    let _ = connection.io.fail_upstream_attempt(failure);
                                    attempt_failure = Some(failure);
                                }
                            }
                            Err(_) => {
                                let failure = UpstreamAttemptFailure::TlsHandshake;
                                let _ = connection.io.fail_upstream_attempt(failure);
                                attempt_failure = Some(failure);
                            }
                        }
                    } else if let Some(upstream_request) =
                        connection.pending_upstream_request.take()
                    {
                        connection.upstream_transport = UpstreamTransport::plaintext();
                        if connection.io.upstream_connected(upstream_request).is_err() {
                            let failure = UpstreamAttemptFailure::Connect;
                            let _ = connection.io.fail_upstream_attempt(failure);
                            attempt_failure = Some(failure);
                        }
                    } else {
                        let failure = UpstreamAttemptFailure::Connect;
                        let _ = connection.io.fail_upstream_attempt(failure);
                        attempt_failure = Some(failure);
                    }
                }

                if attempt_failure.is_none() {
                    loop {
                        if connection.pending_upstream_output.is_complete() {
                            if connection.io.connection.state
                                == ConnectionState::HandshakingUpstreamTls
                            {
                                connection.pending_upstream_output = WriteBuffer::new(
                                    connection.upstream_transport.take_socket_bytes(usize::MAX),
                                );
                            } else if connection.io.connection.state
                                == ConnectionState::WritingUpstreamRequest
                            {
                                let plaintext = connection.io.upstream_write_buffer().remaining();
                                if plaintext.is_empty() {
                                    break;
                                }
                                match connection.upstream_transport.queue_http_bytes(plaintext) {
                                    Ok(accepted) if accepted > 0 => {
                                        if connection.io.advance_upstream_write(accepted).is_err() {
                                            let failure = UpstreamAttemptFailure::Write;
                                            let _ = connection.io.fail_upstream_attempt(failure);
                                            attempt_failure = Some(failure);
                                            break;
                                        }
                                        connection.pending_upstream_output = WriteBuffer::new(
                                            connection
                                                .upstream_transport
                                                .take_socket_bytes(usize::MAX),
                                        );
                                    }
                                    Ok(_) => break,
                                    Err(_) => {
                                        let failure = UpstreamAttemptFailure::Write;
                                        let _ = connection.io.fail_upstream_attempt(failure);
                                        attempt_failure = Some(failure);
                                        break;
                                    }
                                }
                            } else {
                                break;
                            }
                        }
                        let chunk = connection.pending_upstream_output.remaining();
                        if chunk.is_empty() {
                            break;
                        }
                        match upstream.write(chunk) {
                            Ok(0) => {
                                let failure = UpstreamAttemptFailure::Write;
                                let _ = connection.io.fail_upstream_attempt(failure);
                                attempt_failure = Some(failure);
                                break;
                            }
                            Ok(written) => {
                                connection.pending_upstream_output.advance(written);
                            }
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                            Err(_) => {
                                let failure = UpstreamAttemptFailure::Write;
                                let _ = connection.io.fail_upstream_attempt(failure);
                                attempt_failure = Some(failure);
                                break;
                            }
                        }
                    }
                    if attempt_failure.is_none() {
                        let interest = upstream_transport_interest(
                            &connection.upstream_transport,
                            &connection.io.connection.state,
                            connection.pending_upstream_output.is_complete(),
                        );
                        registry.reregister(upstream, upstream_token(connection_id), interest)?;
                        refresh_deadline_for_connection(
                            connection,
                            &self.resource_limits,
                            Instant::now(),
                        );
                    }
                }
            }

            if let Some(failure) = attempt_failure {
                if let Some(reason) = passive_failure_reason(failure) {
                    let _ = self.submit_passive_observation(
                        connection_id,
                        snapshot,
                        PassiveObservationOutcome::Failed(reason),
                    );
                }
                self.drop_upstream(connection_id, registry)?;
                if !self.retry_upstream(connection_id, registry, snapshot, failure)? {
                    self.queue_client_response(
                        connection_id,
                        registry,
                        upstream_failure_response(failure),
                    )?;
                }
            } else {
                self.refresh_connection_deadline(connection_id, Instant::now());
            }
            Ok(())
        }

        fn read_upstream(
            &mut self,
            connection_id: usize,
            registry: &mio::Registry,
            snapshot: &ConfigSnapshot,
        ) -> io::Result<()> {
            if self
                .connections
                .get(&connection_id)
                .is_some_and(|connection| {
                    connection.io.connection.state == ConnectionState::HandshakingUpstreamTls
                })
            {
                return self.read_upstream_tls_handshake(connection_id, registry, snapshot);
            }
            let websocket_upgrade_pending =
                self.connections
                    .get(&connection_id)
                    .is_some_and(|connection| {
                        connection.websocket_requested
                            && connection.io.connection.state
                                == ConnectionState::ReadingUpstreamResponse
                    });
            if websocket_upgrade_pending {
                return self.read_websocket_upgrade_response(connection_id, registry);
            }

            let mut finish_response = false;
            let mut failure_response = None;
            let mut received_response_bytes = false;
            let mut first_response_bytes = false;
            let mut pause_upstream_read = false;
            let mut close_partial_response = false;
            #[cfg(test)]
            let mut response_accounting_changed = false;
            {
                let (connections, payload_ledger) =
                    (&mut self.connections, &mut self.payload_ledger);
                let Some(connection) = connections.get_mut(&connection_id) else {
                    return Ok(());
                };
                let Some(upstream) = connection.upstream.as_mut() else {
                    return Ok(());
                };
                let mut buffer = [0_u8; 4096];
                loop {
                    match upstream.read(&mut buffer) {
                        Ok(0) => {
                            if !connection.io.upstream_attempt().response_started() {
                                let failure = UpstreamAttemptFailure::ResetBeforeResponse;
                                let _ = connection.io.fail_upstream_attempt(failure);
                                failure_response = Some(upstream_failure_response(failure));
                            } else if connection
                                .response_framing
                                .as_mut()
                                .ok_or_else(|| {
                                    AppError::new(
                                        ErrorCode::RuntimeUpstreamBadGateway,
                                        "response framing owner is missing",
                                    )
                                })
                                .and_then(HttpResponseFraming::finish_on_eof)
                                .is_ok()
                            {
                                finish_response = true;
                            } else {
                                let failure = UpstreamAttemptFailure::ResetAfterResponse;
                                let _ = connection.io.fail_upstream_attempt(failure);
                                close_partial_response = true;
                            }
                            break;
                        }
                        Ok(read) => {
                            let plaintext = match connection
                                .upstream_transport
                                .receive_socket_bytes(&buffer[..read])
                            {
                                Ok(plaintext) => plaintext,
                                Err(_) => {
                                    let failure = UpstreamAttemptFailure::Read;
                                    let _ = connection.io.fail_upstream_attempt(failure);
                                    failure_response = Some(upstream_failure_response(failure));
                                    break;
                                }
                            };
                            if plaintext.is_empty() {
                                continue;
                            }
                            let response_started =
                                connection.io.upstream_attempt().response_started();
                            let progress = match connection
                                .response_framing
                                .as_mut()
                                .ok_or_else(|| {
                                    AppError::new(
                                        ErrorCode::RuntimeUpstreamBadGateway,
                                        "response framing owner is missing",
                                    )
                                })
                                .and_then(|framing| framing.push(&plaintext))
                            {
                                Ok(progress) => progress,
                                Err(_) => {
                                    let failure = if response_started {
                                        UpstreamAttemptFailure::ResetAfterResponse
                                    } else {
                                        UpstreamAttemptFailure::Read
                                    };
                                    let _ = connection.io.fail_upstream_attempt(failure);
                                    if response_started {
                                        close_partial_response = true;
                                    } else {
                                        failure_response = Some(upstream_failure_response(failure));
                                    }
                                    break;
                                }
                            };
                            let response_bytes = &plaintext[..progress.consumed];
                            let Some(next_response_bytes) = connection
                                .resource_charges
                                .client_response_bytes(payload_ledger)
                                .checked_add(response_bytes.len())
                            else {
                                failure_response = Some(error_response_for_code(
                                    ErrorCode::ResourceAllocationFailed,
                                ));
                                break;
                            };
                            let response_change = match connection
                                .resource_charges
                                .prepare_client_response_bytes(
                                    payload_ledger,
                                    connection_id,
                                    next_response_bytes,
                                ) {
                                Ok(change) => change,
                                Err(error) => {
                                    failure_response = Some(error_response_for_code(error.code));
                                    break;
                                }
                            };
                            if let Err(error) = connection.io.receive_upstream_bytes(response_bytes)
                            {
                                let _ = connection
                                    .resource_charges
                                    .rollback_client_response_allocation(
                                        payload_ledger,
                                        response_change,
                                    );
                                let failure = UpstreamAttemptFailure::Read;
                                let _ = connection.io.fail_upstream_attempt(failure);
                                failure_response = Some(error_response_for_code(error.code));
                                break;
                            }
                            if let Err(error) = connection
                                .resource_charges
                                .commit_client_response_bytes(payload_ledger, response_change)
                            {
                                let failure = UpstreamAttemptFailure::Read;
                                let _ = connection.io.fail_upstream_attempt(failure);
                                failure_response = Some(error_response_for_code(error.code));
                                break;
                            }
                            #[cfg(test)]
                            {
                                response_accounting_changed = true;
                            }
                            first_response_bytes |= !response_started && !response_bytes.is_empty();
                            received_response_bytes |= !response_bytes.is_empty();
                            if progress.phase == ResponseFramingPhase::Complete {
                                finish_response = true;
                                break;
                            }
                            if connection.io.client_write_buffer().remaining_len()
                                + connection.pending_client_output.remaining_len()
                                >= self.resource_limits.max_response_buffer_bytes
                            {
                                pause_upstream_read = true;
                                break;
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(_) => {
                            let failure = UpstreamAttemptFailure::Read;
                            let _ = connection.io.fail_upstream_attempt(failure);
                            failure_response = Some(upstream_failure_response(failure));
                            break;
                        }
                    }
                }
            }

            self.emit_resource_payload_metric_if_changed();
            #[cfg(test)]
            if response_accounting_changed {
                self.emit_resource_accounting_event();
            }

            if first_response_bytes {
                let _ = self.submit_passive_observation(
                    connection_id,
                    snapshot,
                    PassiveObservationOutcome::Succeeded,
                );
            }

            if close_partial_response {
                self.drop_upstream(connection_id, registry)?;
                if let Some(connection) = self.connections.get_mut(&connection_id) {
                    let _ = connection
                        .io
                        .connection
                        .transition_to(ConnectionState::Failed);
                    let _ = registry.deregister(&mut connection.client);
                }
                self.remove_connection(connection_id, true);
            } else if let Some(response) = failure_response {
                self.drop_upstream(connection_id, registry)?;
                self.queue_client_response(connection_id, registry, response)?;
            } else if finish_response {
                if let Some(connection) = self.connections.get_mut(&connection_id) {
                    if let Some(status_code) = connection
                        .response_framing
                        .as_ref()
                        .and_then(HttpResponseFraming::status_code)
                    {
                        if let Some(log) = connection.access_log.as_mut() {
                            log.status_code = Some(status_code);
                        }
                    }
                }
                self.drop_upstream(connection_id, registry)?;
                let Some(connection) = self.connections.get_mut(&connection_id) else {
                    return Ok(());
                };
                if connection.io.finish_upstream_response().is_err() {
                    connection.close_after_write = true;
                    connection.deadline = None;
                } else {
                    registry.reregister(
                        &mut connection.client,
                        client_token(connection_id),
                        Interest::WRITABLE,
                    )?;
                    refresh_deadline_for_connection(
                        connection,
                        &self.resource_limits,
                        Instant::now(),
                    );
                }
            } else {
                if received_response_bytes {
                    if let Some(connection) = self.connections.get_mut(&connection_id) {
                        registry.reregister(
                            &mut connection.client,
                            client_token(connection_id),
                            Interest::WRITABLE,
                        )?;
                    }
                }
                if pause_upstream_read {
                    self.pause_upstream_read_if_needed(connection_id, registry)?;
                }
                self.refresh_connection_deadline(connection_id, Instant::now());
            }
            Ok(())
        }

        fn read_upstream_tls_handshake(
            &mut self,
            connection_id: usize,
            registry: &mio::Registry,
            snapshot: &ConfigSnapshot,
        ) -> io::Result<()> {
            let mut failed = false;
            let mut established = false;
            {
                let Some(connection) = self.connections.get_mut(&connection_id) else {
                    return Ok(());
                };
                let Some(upstream) = connection.upstream.as_mut() else {
                    return Ok(());
                };
                let mut buffer = [0_u8; 4096];
                loop {
                    match upstream.read(&mut buffer) {
                        Ok(0) => {
                            failed = true;
                            break;
                        }
                        Ok(read) => {
                            if connection
                                .upstream_transport
                                .receive_socket_bytes(&buffer[..read])
                                .is_err()
                            {
                                failed = true;
                                break;
                            }
                            if connection.upstream_transport.tls_state()
                                == Some(&TlsTransportState::Established)
                            {
                                established = true;
                                break;
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(_) => {
                            failed = true;
                            break;
                        }
                    }
                }
                if connection.pending_upstream_output.is_complete() {
                    connection.pending_upstream_output = WriteBuffer::new(
                        connection.upstream_transport.take_socket_bytes(usize::MAX),
                    );
                }
                if established {
                    let request = connection.pending_upstream_request.take();
                    if request
                        .map(|request| connection.io.upstream_connected(request).is_err())
                        .unwrap_or(true)
                    {
                        failed = true;
                    }
                }
                if failed {
                    let _ = connection
                        .io
                        .fail_upstream_attempt(UpstreamAttemptFailure::TlsHandshake);
                } else {
                    let interest = upstream_transport_interest(
                        &connection.upstream_transport,
                        &connection.io.connection.state,
                        connection.pending_upstream_output.is_complete(),
                    );
                    registry.reregister(upstream, upstream_token(connection_id), interest)?;
                    refresh_deadline_for_connection(
                        connection,
                        &self.resource_limits,
                        Instant::now(),
                    );
                }
            }

            if failed {
                let failure = UpstreamAttemptFailure::TlsHandshake;
                if let Some(reason) = passive_failure_reason(failure) {
                    let _ = self.submit_passive_observation(
                        connection_id,
                        snapshot,
                        PassiveObservationOutcome::Failed(reason),
                    );
                }
                self.drop_upstream(connection_id, registry)?;
                if !self.retry_upstream(connection_id, registry, snapshot, failure)? {
                    self.queue_client_response(
                        connection_id,
                        registry,
                        upstream_failure_response(failure),
                    )?;
                }
            }
            Ok(())
        }

        fn retry_upstream(
            &mut self,
            connection_id: usize,
            registry: &mio::Registry,
            snapshot: &ConfigSnapshot,
            failure: UpstreamAttemptFailure,
        ) -> io::Result<bool> {
            let Some(connection) = self.connections.get(&connection_id) else {
                return Ok(false);
            };
            let Some(context) = connection.retry.as_ref() else {
                return Ok(false);
            };
            let domain_failure = match failure {
                UpstreamAttemptFailure::Connect => edge_domain::RetryFailureKind::Connect,
                UpstreamAttemptFailure::ConnectTimeout => {
                    edge_domain::RetryFailureKind::ConnectTimeout
                }
                UpstreamAttemptFailure::TlsHandshake => edge_domain::RetryFailureKind::Connect,
                UpstreamAttemptFailure::TlsHandshakeTimeout => {
                    edge_domain::RetryFailureKind::ConnectTimeout
                }
                UpstreamAttemptFailure::Write => edge_domain::RetryFailureKind::Write,
                UpstreamAttemptFailure::Read => edge_domain::RetryFailureKind::Read,
                UpstreamAttemptFailure::ReadTimeout => edge_domain::RetryFailureKind::ReadTimeout,
                UpstreamAttemptFailure::ResetBeforeResponse => {
                    edge_domain::RetryFailureKind::ResetBeforeResponse
                }
                UpstreamAttemptFailure::ResetAfterResponse => return Ok(false),
            };
            let decision = edge_domain::evaluate_retry(edge_domain::RetryInput {
                policy: &context.policy,
                method: context.method,
                body_bytes: context.body_bytes,
                request_bytes_written: connection.io.upstream_attempt().request_bytes_written(),
                response_started: connection.io.upstream_attempt().response_started(),
                attempts_used: context.retries_used,
                replay_reserved: context.replay_wire_len as u64 <= context.policy.max_replay_bytes,
                failure: domain_failure,
            });
            if decision
                == edge_domain::RetryDecision::DoNotRetry(
                    edge_domain::RetryDenialReason::RetryBudgetExhausted,
                )
            {
                let event = FailureAwareEvent {
                    transition: FailureAwareTransition::RetryExhausted,
                    revision_id: snapshot.revision_id.clone(),
                    generation: self
                        .upstream_selector
                        .availability_generation
                        .unwrap_or(HealthGeneration(0)),
                    key: Some(edge_domain::UpstreamHealthKey {
                        service_id: context.service_id.clone(),
                        upstream_id: context.current_upstream_id.clone(),
                    }),
                    reason: Some("retry_budget_exhausted"),
                    connection_count: None,
                };
                self.emit_failure_aware_event(&event);
            }
            if decision != edge_domain::RetryDecision::Retry {
                return Ok(false);
            }
            let Some(service) = snapshot.find_service(&context.service_id) else {
                return Ok(false);
            };
            let Some(selection) = self
                .upstream_selector
                .select_retry(service, &context.attempted)
            else {
                return Ok(false);
            };
            let address = match selection.endpoint.connect_address().parse::<SocketAddr>() {
                Ok(address) => address,
                Err(_) => {
                    let _ = self
                        .upstream_selector
                        .drain_tracker
                        .release(&selection.drain_reference);
                    return Ok(false);
                }
            };
            let (planned_upstream_bytes, websocket_requested) = {
                let Some(connection) = self.connections.get(&connection_id) else {
                    self.upstream_selector
                        .release_drain_reference(&selection.drain_reference);
                    return Ok(false);
                };
                let Some(context) = connection.retry.as_ref() else {
                    self.upstream_selector
                        .release_drain_reference(&selection.drain_reference);
                    return Ok(false);
                };
                let planned = match planned_selected_upstream_request_len(
                    &context.original_request,
                    &selection.endpoint,
                    &selection.tls,
                    &connection.client_ip,
                    &context.forwarded_scheme,
                    &context.original_authority,
                    context.websocket_requested,
                ) {
                    Ok(planned) => planned,
                    Err(_) => {
                        self.upstream_selector
                            .release_drain_reference(&selection.drain_reference);
                        self.queue_client_response(
                            connection_id,
                            registry,
                            error_response_for_code(ErrorCode::ResourceAllocationFailed),
                        )?;
                        return Ok(true);
                    }
                };
                (planned, context.websocket_requested)
            };
            let replacement = {
                let (connections, payload_ledger) = (&self.connections, &mut self.payload_ledger);
                let Some(connection) = connections.get(&connection_id) else {
                    self.upstream_selector
                        .release_drain_reference(&selection.drain_reference);
                    return Ok(false);
                };
                connection.resource_charges.reserve_upstream_replacement(
                    payload_ledger,
                    connection_id,
                    planned_upstream_bytes,
                )
            };
            let replacement = match replacement {
                Ok(replacement) => replacement,
                Err(error) => {
                    self.upstream_selector
                        .release_drain_reference(&selection.drain_reference);
                    self.queue_client_response(
                        connection_id,
                        registry,
                        error_response_for_code(error.code),
                    )?;
                    return Ok(true);
                }
            };
            self.emit_resource_payload_metric_if_changed();
            #[cfg(test)]
            self.emit_resource_accounting_event();
            let upstream_request = {
                let Some(connection) = self.connections.get(&connection_id) else {
                    let _ = self
                        .payload_ledger
                        .release(replacement, self.payload_ledger.generation());
                    self.upstream_selector
                        .release_drain_reference(&selection.drain_reference);
                    return Ok(false);
                };
                let Some(context) = connection.retry.as_ref() else {
                    let _ = self
                        .payload_ledger
                        .release(replacement, self.payload_ledger.generation());
                    self.upstream_selector
                        .release_drain_reference(&selection.drain_reference);
                    return Ok(false);
                };
                build_selected_upstream_request(
                    &context.original_request,
                    &selection.endpoint,
                    &selection.tls,
                    &connection.client_ip,
                    &context.forwarded_scheme,
                    &context.original_authority,
                    context.websocket_requested,
                )
            };
            let upstream_request = match upstream_request {
                Ok(request) => request,
                Err(_) => {
                    let release_result = {
                        let (connections, payload_ledger) =
                            (&self.connections, &mut self.payload_ledger);
                        connections.get(&connection_id).map(|connection| {
                            connection
                                .resource_charges
                                .release_upstream_replacement_after_allocation_failure(
                                    payload_ledger,
                                    replacement,
                                )
                        })
                    };
                    if let Some(Err(error)) = release_result {
                        self.emit_error_log(connection_id, error.code, &error.message);
                    }
                    self.emit_resource_payload_metric_if_changed();
                    #[cfg(test)]
                    self.emit_resource_accounting_event();
                    self.upstream_selector
                        .release_drain_reference(&selection.drain_reference);
                    self.queue_client_response(
                        connection_id,
                        registry,
                        error_response_for_code(ErrorCode::ResourceAllocationFailed),
                    )?;
                    return Ok(true);
                }
            };
            let transition_result = (|| -> Result<Option<DrainReference>, AppError> {
                let (connections, payload_ledger) =
                    (&mut self.connections, &mut self.payload_ledger);
                let connection = connections
                    .get_mut(&connection_id)
                    .ok_or_else(invalid_upstream_attempt_transition)?;
                if connection.retry.is_none() {
                    return Err(invalid_upstream_attempt_transition());
                }
                connection.io.prepare_upstream_retry()?;
                connection.pending_upstream_request = None;
                connection.resource_charges.commit_upstream_replacement(
                    payload_ledger,
                    replacement,
                    upstream_request.len(),
                )?;
                let context = connection
                    .retry
                    .as_mut()
                    .ok_or_else(invalid_upstream_attempt_transition)?;
                context.retries_used = context.retries_used.saturating_add(1);
                context.attempted.insert(selection.upstream_id.clone());
                context.current_upstream_id = selection.upstream_id.clone();
                context.replay_wire_len = upstream_request.len();
                Ok(connection.drain_reference.take())
            })();
            let previous_reference = match transition_result {
                Ok(previous) => {
                    let Some(connection) = self.connections.get_mut(&connection_id) else {
                        self.upstream_selector
                            .release_drain_reference(&selection.drain_reference);
                        return Ok(false);
                    };
                    connection.drain_reference = Some(selection.drain_reference);
                    previous
                }
                Err(error) => {
                    let cleanup_result = {
                        let (connections, payload_ledger) =
                            (&self.connections, &mut self.payload_ledger);
                        let replacement_is_current =
                            connections.get(&connection_id).is_some_and(|connection| {
                                connection.resource_charges.upstream == Some(replacement)
                            });
                        if !replacement_is_current && payload_ledger.charge(replacement).is_some() {
                            payload_ledger.release(replacement, payload_ledger.generation())
                        } else {
                            Ok(())
                        }
                    };
                    if let Err(cleanup_error) = cleanup_result {
                        self.emit_error_log(
                            connection_id,
                            cleanup_error.code,
                            &cleanup_error.message,
                        );
                    }
                    self.emit_error_log(connection_id, error.code, &error.message);
                    self.upstream_selector
                        .release_drain_reference(&selection.drain_reference);
                    self.queue_client_response(
                        connection_id,
                        registry,
                        error_response_for_code(error.code),
                    )?;
                    return Ok(true);
                }
            };
            if let Some(reference) = previous_reference {
                self.upstream_selector.release_drain_reference(&reference);
            }
            self.update_access_log_route(
                connection_id,
                None,
                Some(selection.upstream_id.as_str().to_string()),
            );
            self.connect_upstream(
                connection_id,
                registry,
                snapshot,
                UpstreamConnectPlan {
                    address,
                    request: upstream_request,
                    websocket_requested,
                    service_id: service.id.clone(),
                    upstream_id: selection.upstream_id,
                    tls_policy: selection.tls,
                },
            )?;
            Ok(true)
        }

        fn submit_passive_observation(
            &mut self,
            connection_id: usize,
            snapshot: &ConfigSnapshot,
            outcome: PassiveObservationOutcome,
        ) -> PassiveObservationSubmit {
            let Some(dispatcher) = self.passive_observation_dispatcher.as_mut() else {
                return PassiveObservationSubmit::Stopped;
            };
            let Some(connection) = self.connections.get(&connection_id) else {
                return PassiveObservationSubmit::Stopped;
            };
            let Some(context) = connection.retry.as_ref() else {
                return PassiveObservationSubmit::Stopped;
            };
            let Some(service) = snapshot.find_service(&context.service_id) else {
                return PassiveObservationSubmit::Stopped;
            };
            if !matches!(
                service.policy.passive_health,
                edge_domain::PassiveHealthMode::Enabled(_)
            ) {
                return PassiveObservationSubmit::Stopped;
            }
            dispatcher.submit(PassiveObservation {
                revision_id: snapshot.revision_id.clone(),
                generation: self
                    .upstream_selector
                    .availability_generation
                    .unwrap_or(HealthGeneration(0)),
                key: edge_domain::UpstreamHealthKey {
                    service_id: context.service_id.clone(),
                    upstream_id: context.current_upstream_id.clone(),
                },
                outcome,
                observed_at_ms: connection.accepted_at.elapsed().as_millis() as u64,
            })
        }

        fn queue_client_response(
            &mut self,
            connection_id: usize,
            registry: &mio::Registry,
            response: Vec<u8>,
        ) -> io::Result<()> {
            let mut runtime_error = None;
            #[cfg(test)]
            let mut response_accounting_changed = false;
            let reregister_result = {
                let (connections, payload_ledger) =
                    (&mut self.connections, &mut self.payload_ledger);
                let Some(connection) = connections.get_mut(&connection_id) else {
                    return Ok(());
                };
                let response_change = match connection
                    .resource_charges
                    .prepare_client_response_bytes(payload_ledger, connection_id, response.len())
                {
                    Ok(change) => change,
                    Err(_) => {
                        connection.close_after_write = true;
                        connection.deadline = None;
                        let _ = registry.deregister(&mut connection.client);
                        return Ok(());
                    }
                };
                if let Some(status_code) = parse_response_status_code(&response) {
                    if let Some(log) = connection.access_log.as_mut() {
                        log.status_code = Some(status_code);
                    }
                    if let Some((error_code, message)) = runtime_error_log_for_status(status_code) {
                        runtime_error = Some((error_code, message));
                    }
                }
                if connection.io.queue_client_response(response).is_err() {
                    let _ = connection
                        .resource_charges
                        .rollback_client_response_allocation(payload_ledger, response_change);
                    connection.close_after_write = true;
                    connection.deadline = None;
                    None
                } else if connection
                    .resource_charges
                    .commit_client_response_bytes(payload_ledger, response_change)
                    .is_err()
                {
                    connection.close_after_write = true;
                    connection.deadline = None;
                    None
                } else {
                    #[cfg(test)]
                    {
                        response_accounting_changed = true;
                    }
                    refresh_deadline_for_connection(
                        connection,
                        &self.resource_limits,
                        Instant::now(),
                    );
                    Some(registry.reregister(
                        &mut connection.client,
                        client_token(connection_id),
                        Interest::WRITABLE,
                    ))
                }
            };

            self.emit_resource_payload_metric_if_changed();
            #[cfg(test)]
            if response_accounting_changed {
                self.emit_resource_accounting_event();
            }

            if let Some((error_code, message)) = runtime_error {
                self.emit_error_log(connection_id, error_code, message);
            }

            reregister_result.unwrap_or(Ok(()))
        }

        fn write_client(
            &mut self,
            connection_id: usize,
            registry: &mio::Registry,
        ) -> io::Result<()> {
            let mut resume_upstream_read = false;
            let mut wait_for_upstream = false;
            let mut wait_for_client_read = false;
            #[cfg(test)]
            let mut response_accounting_changed = false;
            let resource_limits = self.resource_limits.clone();
            {
                let (connections, payload_ledger) =
                    (&mut self.connections, &mut self.payload_ledger);
                let Some(connection) = connections.get_mut(&connection_id) else {
                    return Ok(());
                };
                loop {
                    if connection.pending_client_output.is_empty() {
                        match connection.pending_client_response {
                            PendingClientResponseBatch::SocketDraining { .. } => {
                                if connection
                                    .release_drained_client_response(payload_ledger)
                                    .is_err()
                                {
                                    connection.close_after_write = true;
                                    connection.deadline = None;
                                    break;
                                }
                                #[cfg(test)]
                                {
                                    response_accounting_changed = true;
                                }
                            }
                            PendingClientResponseBatch::TransportOwned { plaintext_bytes } => {
                                let pulled = connection
                                    .pending_client_output
                                    .pull_from(&mut connection.client_transport, usize::MAX);
                                if pulled == 0 {
                                    break;
                                }
                                connection.pending_client_response =
                                    PendingClientResponseBatch::SocketDraining { plaintext_bytes };
                                continue;
                            }
                            PendingClientResponseBatch::Empty => {}
                        }
                        let plaintext = connection.io.client_write_buffer().remaining();
                        if plaintext.is_empty() {
                            if connection.io.connection.state
                                == ConnectionState::WritingClientResponse
                            {
                                connection.close_after_write = true;
                                connection.deadline = None;
                                if connection
                                    .client_transport
                                    .request_close_notify()
                                    .unwrap_or(false)
                                {
                                    connection
                                        .pending_client_output
                                        .pull_from(&mut connection.client_transport, usize::MAX);
                                    if !connection.pending_client_output.is_empty() {
                                        continue;
                                    }
                                }
                            }
                            break;
                        }
                        let consumed = match connection.client_transport.queue_http_bytes(plaintext)
                        {
                            Ok(consumed) => consumed,
                            Err(_) => {
                                connection.close_after_write = true;
                                connection.deadline = None;
                                break;
                            }
                        };
                        if consumed == 0 {
                            break;
                        }
                        if connection
                            .install_transport_owned_client_response(consumed)
                            .is_err()
                        {
                            connection.close_after_write = true;
                            connection.deadline = None;
                            break;
                        }
                        if connection.io.advance_client_write(consumed).is_err() {
                            connection.close_after_write = true;
                            connection.deadline = None;
                            break;
                        }
                        continue;
                    }
                    match connection
                        .client
                        .write(connection.pending_client_output.remaining())
                    {
                        Ok(0) => break,
                        Ok(written) => {
                            connection.pending_client_output.advance(written);
                            if connection.pending_client_output.is_empty() {
                                match connection.release_drained_client_response(payload_ledger) {
                                    Ok(true) => {
                                        #[cfg(test)]
                                        {
                                            response_accounting_changed = true;
                                        }
                                    }
                                    Ok(false) => {}
                                    Err(_) => {
                                        connection.close_after_write = true;
                                        connection.deadline = None;
                                        break;
                                    }
                                }
                            }
                            let streaming_response = connection.io.connection.state
                                == ConnectionState::ReadingUpstreamResponse;
                            let remaining = connection.buffered_client_output_len();
                            if streaming_response
                                && remaining < resource_limits.max_response_buffer_bytes
                            {
                                resume_upstream_read = true;
                            }
                            if remaining == 0 {
                                if streaming_response {
                                    wait_for_upstream = true;
                                    refresh_deadline_for_connection(
                                        connection,
                                        &resource_limits,
                                        Instant::now(),
                                    );
                                } else if matches!(
                                    connection.io.connection.state,
                                    ConnectionState::Accepted
                                        | ConnectionState::ReadingClientRequest
                                        | ConnectionState::SelectingRoute
                                        | ConnectionState::ConnectingUpstream
                                        | ConnectionState::WritingUpstreamRequest
                                ) {
                                    wait_for_client_read = true;
                                    refresh_deadline_for_connection(
                                        connection,
                                        &resource_limits,
                                        Instant::now(),
                                    );
                                } else {
                                    connection.close_after_write = true;
                                    connection.deadline = None;
                                    if connection
                                        .client_transport
                                        .request_close_notify()
                                        .unwrap_or(false)
                                    {
                                        connection.pending_client_output.pull_from(
                                            &mut connection.client_transport,
                                            usize::MAX,
                                        );
                                        if !connection.pending_client_output.is_empty() {
                                            continue;
                                        }
                                    }
                                }
                                break;
                            }
                            refresh_deadline_for_connection(
                                connection,
                                &resource_limits,
                                Instant::now(),
                            );
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(_) => {
                            connection.close_after_write = true;
                            connection.deadline = None;
                            break;
                        }
                    }
                }

                if connection.pending_client_output.is_empty()
                    && (connection.close_after_write
                        || matches!(
                            connection.io.connection.state,
                            ConnectionState::Draining
                                | ConnectionState::Closed
                                | ConnectionState::Failed
                        ))
                {
                    let _ = connection.client.shutdown(std::net::Shutdown::Write);
                    registry.deregister(&mut connection.client)?;
                } else if wait_for_client_read || wait_for_upstream {
                    registry.reregister(
                        &mut connection.client,
                        client_token(connection_id),
                        Interest::READABLE,
                    )?;
                }
            }
            self.emit_resource_payload_metric_if_changed();
            #[cfg(test)]
            if response_accounting_changed {
                self.emit_resource_accounting_event();
            }
            if resume_upstream_read {
                self.resume_upstream_read_if_needed(connection_id, registry)?;
            }
            Ok(())
        }

        fn read_websocket_upgrade_response(
            &mut self,
            connection_id: usize,
            registry: &mio::Registry,
        ) -> io::Result<()> {
            let mut failure_response = None;
            let mut switch_to_tunnel = false;
            let mut non_upgrade_response = None;
            {
                let Some(connection) = self.connections.get_mut(&connection_id) else {
                    return Ok(());
                };
                let Some(upstream) = connection.upstream.as_mut() else {
                    return Ok(());
                };
                let mut buffer = [0_u8; 4096];
                loop {
                    match upstream.read(&mut buffer) {
                        Ok(0) => {
                            if connection.websocket_response.is_empty() {
                                failure_response = Some(http_error_response(502, "Bad Gateway"));
                            } else {
                                non_upgrade_response =
                                    Some(std::mem::take(&mut connection.websocket_response));
                            }
                            break;
                        }
                        Ok(read) => {
                            let plaintext = match connection
                                .upstream_transport
                                .receive_socket_bytes(&buffer[..read])
                            {
                                Ok(plaintext) => plaintext,
                                Err(_) => {
                                    failure_response =
                                        Some(http_error_response(502, "Bad Gateway"));
                                    break;
                                }
                            };
                            connection.websocket_response.extend_from_slice(&plaintext);
                            if connection.pending_upstream_output.is_complete() {
                                connection.pending_upstream_output = WriteBuffer::new(
                                    connection.upstream_transport.take_socket_bytes(usize::MAX),
                                );
                            }
                            if websocket_response_headers_ready(&connection.websocket_response) {
                                if websocket_response_is_switching_protocols(
                                    &connection.websocket_response,
                                ) {
                                    switch_to_tunnel = true;
                                } else {
                                    non_upgrade_response =
                                        Some(std::mem::take(&mut connection.websocket_response));
                                }
                                break;
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(_) => {
                            failure_response = Some(http_error_response(502, "Bad Gateway"));
                            break;
                        }
                    }
                }
            }

            if let Some(response) = failure_response {
                self.drop_upstream(connection_id, registry)?;
                self.queue_client_response(connection_id, registry, response)?;
            } else if switch_to_tunnel {
                self.start_websocket_tunnel(connection_id, registry)?;
            } else if let Some(response) = non_upgrade_response {
                self.drop_upstream(connection_id, registry)?;
                self.queue_client_response(connection_id, registry, response)?;
            } else {
                self.refresh_connection_deadline(connection_id, Instant::now());
            }
            Ok(())
        }

        fn start_websocket_tunnel(
            &mut self,
            connection_id: usize,
            registry: &mio::Registry,
        ) -> io::Result<()> {
            let Some(connection) = self.connections.get_mut(&connection_id) else {
                return Ok(());
            };
            let response = std::mem::take(&mut connection.websocket_response);
            if connection
                .tunnel_upstream_to_client
                .try_append(&response)
                .is_err()
            {
                connection.close_after_write = true;
                connection.deadline = None;
                return Ok(());
            }
            if connection
                .io
                .connection
                .transition_to(ConnectionState::TunnelingWebSocket)
                .is_err()
            {
                connection.close_after_write = true;
                connection.deadline = None;
                return Ok(());
            }
            connection.deadline = None;
            self.reregister_tunnel_interests(connection_id, registry)
        }

        fn read_client_tunnel(
            &mut self,
            connection_id: usize,
            registry: &mio::Registry,
        ) -> io::Result<()> {
            {
                let Some(connection) = self.connections.get_mut(&connection_id) else {
                    return Ok(());
                };
                let flow = tunnel_flow_control(
                    connection.tunnel_client_to_upstream.remaining_len(),
                    connection.pending_upstream_output.remaining_len(),
                    connection.tunnel_upstream_to_client.remaining_len(),
                    connection.pending_client_output.remaining_len(),
                    &self.resource_limits,
                );
                if !flow.client_readable {
                    return self.reregister_tunnel_interests(connection_id, registry);
                }
                let mut buffer = [0_u8; 4096];
                match connection.client.read(&mut buffer) {
                    Ok(0) => {
                        connection.close_after_write = true;
                    }
                    Ok(read) => {
                        match connection
                            .client_transport
                            .receive_socket_bytes(&buffer[..read])
                        {
                            Ok(plaintext) => {
                                if connection
                                    .tunnel_client_to_upstream
                                    .try_append(&plaintext)
                                    .is_err()
                                {
                                    connection.close_after_write = true;
                                }
                            }
                            Err(_) => connection.close_after_write = true,
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => {
                        connection.close_after_write = true;
                    }
                }
            }
            self.reregister_tunnel_interests(connection_id, registry)
        }

        fn write_client_tunnel(
            &mut self,
            connection_id: usize,
            registry: &mio::Registry,
        ) -> io::Result<()> {
            {
                let Some(connection) = self.connections.get_mut(&connection_id) else {
                    return Ok(());
                };
                loop {
                    if connection.pending_client_output.is_empty() {
                        let plaintext = connection.tunnel_upstream_to_client.remaining();
                        if plaintext.is_empty() {
                            break;
                        }
                        let consumed = match connection
                            .pending_client_output
                            .pull_tunnel_plaintext(&mut connection.client_transport, plaintext)
                        {
                            Ok(consumed) => consumed,
                            Err(_) => {
                                connection.close_after_write = true;
                                break;
                            }
                        };
                        connection
                            .tunnel_upstream_to_client
                            .advance_and_clear_if_complete(consumed);
                        if connection.pending_client_output.is_empty() {
                            break;
                        }
                    }
                    match connection
                        .client
                        .write(connection.pending_client_output.remaining())
                    {
                        Ok(0) => break,
                        Ok(written) => {
                            connection.pending_client_output.advance(written);
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(_) => {
                            connection.close_after_write = true;
                            break;
                        }
                    }
                }
            }
            self.reregister_tunnel_interests(connection_id, registry)
        }

        fn read_upstream_tunnel(
            &mut self,
            connection_id: usize,
            registry: &mio::Registry,
        ) -> io::Result<()> {
            {
                let Some(connection) = self.connections.get_mut(&connection_id) else {
                    return Ok(());
                };
                let Some(upstream) = connection.upstream.as_mut() else {
                    return Ok(());
                };
                let flow = tunnel_flow_control(
                    connection.tunnel_client_to_upstream.remaining_len(),
                    connection.pending_upstream_output.remaining_len(),
                    connection.tunnel_upstream_to_client.remaining_len(),
                    connection.pending_client_output.remaining_len(),
                    &self.resource_limits,
                );
                if !flow.upstream_readable {
                    return self.reregister_tunnel_interests(connection_id, registry);
                }
                let mut buffer = [0_u8; 4096];
                match upstream.read(&mut buffer) {
                    Ok(0) => {
                        connection.close_after_write = true;
                    }
                    Ok(read) => {
                        match connection
                            .upstream_transport
                            .receive_socket_bytes(&buffer[..read])
                        {
                            Ok(plaintext) => {
                                if connection
                                    .tunnel_upstream_to_client
                                    .try_append(&plaintext)
                                    .is_err()
                                {
                                    connection.close_after_write = true;
                                }
                                if connection.pending_upstream_output.is_complete() {
                                    connection.pending_upstream_output = WriteBuffer::new(
                                        connection.upstream_transport.take_socket_bytes(usize::MAX),
                                    );
                                }
                            }
                            Err(_) => connection.close_after_write = true,
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => {
                        connection.close_after_write = true;
                    }
                }
            }
            self.reregister_tunnel_interests(connection_id, registry)
        }

        fn write_upstream_tunnel(
            &mut self,
            connection_id: usize,
            registry: &mio::Registry,
        ) -> io::Result<()> {
            {
                let Some(connection) = self.connections.get_mut(&connection_id) else {
                    return Ok(());
                };
                let Some(upstream) = connection.upstream.as_mut() else {
                    return Ok(());
                };
                loop {
                    if connection.pending_upstream_output.is_complete() {
                        let plaintext = connection.tunnel_client_to_upstream.remaining();
                        if plaintext.is_empty() {
                            connection.pending_upstream_output = WriteBuffer::new(
                                connection.upstream_transport.take_socket_bytes(usize::MAX),
                            );
                            if connection.pending_upstream_output.is_complete() {
                                break;
                            }
                        } else {
                            match connection.upstream_transport.queue_tunnel_plaintext(
                                plaintext,
                                &mut connection.pending_upstream_output,
                            ) {
                                Ok(consumed) if consumed > 0 => {
                                    connection
                                        .tunnel_client_to_upstream
                                        .advance_and_clear_if_complete(consumed);
                                }
                                Ok(_) => break,
                                Err(_) => {
                                    connection.close_after_write = true;
                                    break;
                                }
                            }
                        }
                    }
                    match upstream.write(connection.pending_upstream_output.remaining()) {
                        Ok(0) => break,
                        Ok(written) => {
                            connection.pending_upstream_output.advance(written);
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(_) => {
                            connection.close_after_write = true;
                            break;
                        }
                    }
                }
            }
            self.reregister_tunnel_interests(connection_id, registry)
        }

        fn reregister_tunnel_interests(
            &mut self,
            connection_id: usize,
            registry: &mio::Registry,
        ) -> io::Result<()> {
            let Some(connection) = self.connections.get_mut(&connection_id) else {
                return Ok(());
            };
            if connection.close_after_write {
                return Ok(());
            }

            let client_writable = connection.tunnel_upstream_to_client.remaining_len() > 0
                || !connection.pending_client_output.is_empty();
            let pressure_state = self.payload_ledger.pressure_state();
            let flow = tunnel_pressure_flow(
                pressure_state,
                tunnel_flow_control(
                    connection.tunnel_client_to_upstream.remaining_len(),
                    connection.pending_upstream_output.remaining_len(),
                    connection.tunnel_upstream_to_client.remaining_len(),
                    connection.pending_client_output.remaining_len(),
                    &self.resource_limits,
                ),
            );
            reconcile_mio_registration(
                registry,
                &mut connection.client,
                client_token(connection_id),
                tunnel_interest(flow.client_readable, client_writable),
                &mut connection.client_registered,
            )?;

            let upstream_writable = connection.tunnel_client_to_upstream.remaining_len() > 0
                || !connection.pending_upstream_output.is_complete();
            if let Some(upstream) = connection.upstream.as_mut() {
                let mut merged = connection
                    .upstream_transport
                    .merge_interest(ConnectionInterest {
                        upstream_readable: flow.upstream_readable,
                        upstream_writable,
                        ..ConnectionInterest::default()
                    });
                if pressure_state != ResourcePressureState::Normal {
                    merged.upstream_readable = false;
                }
                reconcile_mio_registration(
                    registry,
                    upstream,
                    upstream_token(connection_id),
                    tunnel_interest(merged.upstream_readable, merged.upstream_writable),
                    &mut connection.upstream_registered,
                )?;
            }
            Ok(())
        }

        fn expire_connection(
            &mut self,
            connection_id: usize,
            registry: &mio::Registry,
            snapshot: &ConfigSnapshot,
            now: Instant,
        ) -> io::Result<()> {
            let tls_timeout = if let Some(connection) = self.connections.get_mut(&connection_id) {
                if connection.deadline.is_some_and(|deadline| deadline <= now) {
                    connection
                        .client_transport
                        .mark_handshake_timeout_if_pending()
                        .inspect(|_| {
                            let _ = connection
                                .io
                                .connection
                                .handle_event(ConnectionEvent::IoError);
                            connection.close_after_write = true;
                            connection.deadline = None;
                            let _ = registry.deregister(&mut connection.client);
                        })
                } else {
                    None
                }
            } else {
                None
            };
            if let Some(error) = tls_timeout {
                self.emit_error_log(connection_id, error.code, &error.message);
                return Ok(());
            }

            let Some(decision) = self.connections.get(&connection_id).and_then(|connection| {
                if connection.deadline.is_some_and(|deadline| deadline <= now) {
                    timeout_decision_for_state(&connection.io.connection.state)
                } else {
                    None
                }
            }) else {
                return Ok(());
            };

            let upstream_timeout_failure = match decision.kind {
                ConnectionTimeoutKind::UpstreamConnect => {
                    Some(UpstreamAttemptFailure::ConnectTimeout)
                }
                ConnectionTimeoutKind::UpstreamTlsHandshake => {
                    Some(UpstreamAttemptFailure::TlsHandshakeTimeout)
                }
                ConnectionTimeoutKind::UpstreamRead => Some(UpstreamAttemptFailure::ReadTimeout),
                ConnectionTimeoutKind::ClientIdle | ConnectionTimeoutKind::ClientWrite => None,
            };
            if let Some(failure) = upstream_timeout_failure {
                if let Some(connection) = self.connections.get_mut(&connection_id) {
                    let _ = connection.io.fail_upstream_attempt(failure);
                }
                if let Some(reason) = passive_failure_reason(failure) {
                    let _ = self.submit_passive_observation(
                        connection_id,
                        snapshot,
                        PassiveObservationOutcome::Failed(reason),
                    );
                }
            }

            self.drop_upstream(connection_id, registry)?;
            if let Some(failure) = upstream_timeout_failure {
                if self.retry_upstream(connection_id, registry, snapshot, failure)? {
                    return Ok(());
                }
            }
            if let Some(status_code) = decision.status_code {
                let response = upstream_timeout_failure.map_or_else(
                    || http_error_response(status_code, decision.reason),
                    upstream_failure_response,
                );
                self.queue_client_response(connection_id, registry, response)?;
            } else if let Some(connection) = self.connections.get_mut(&connection_id) {
                let _ = connection
                    .io
                    .connection
                    .transition_to(decision.next_state.clone());
                connection.close_after_write = true;
                connection.deadline = None;
                let _ = registry.deregister(&mut connection.client);
            }
            Ok(())
        }

        fn refresh_connection_deadline(&mut self, connection_id: usize, now: Instant) {
            if let Some(connection) = self.connections.get_mut(&connection_id) {
                refresh_deadline_for_connection(connection, &self.resource_limits, now);
            }
        }

        fn begin_access_log(
            &mut self,
            connection_id: usize,
            snapshot: &ConfigSnapshot,
            request: &HttpRequest,
        ) {
            if let Some(connection) = self.connections.get_mut(&connection_id) {
                let request_id = request
                    .header_value("X-Request-Id")
                    .filter(|value| !value.trim().is_empty())
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("proxy-{connection_id}"));
                connection.access_log = Some(AccessLogDraft {
                    request_id,
                    revision_id: snapshot.revision_id.as_str().to_string(),
                    route_id: None,
                    upstream_id: None,
                    scheme: connection.client_transport.forwarded_scheme().to_string(),
                    method: request.method.clone(),
                    path: request.path.clone(),
                    status_code: None,
                });
            }
        }

        fn update_access_log_route(
            &mut self,
            connection_id: usize,
            route_id: Option<String>,
            upstream_id: Option<String>,
        ) {
            if let Some(log) = self
                .connections
                .get_mut(&connection_id)
                .and_then(|connection| connection.access_log.as_mut())
            {
                log.route_id = route_id;
                log.upstream_id = upstream_id;
            }
        }

        fn emit_access_log(&self, connection: &SnapshotMioConnection) {
            let Some(log) = &connection.access_log else {
                return;
            };
            let Some(status_code) = log.status_code else {
                return;
            };
            let duration_ms = connection.accepted_at.elapsed().as_millis() as u64;
            let event = AccessLogEvent {
                request_id: log.request_id.clone(),
                revision_id: log.revision_id.clone(),
                route_id: log.route_id.clone(),
                upstream_id: log.upstream_id.clone(),
                status_code,
                duration_ms,
                scheme: log.scheme.clone(),
                method: log.method.clone(),
                path: log.path.clone(),
            };
            if let Some(sender) = &self.access_log_sender {
                if let Err(error) = sender.try_send(event.clone()) {
                    self.record_log_queue_drop(error);
                }
            }
            self.emit_request_metrics(&event);
        }

        fn emit_error_log(&self, connection_id: usize, error_code: ErrorCode, message: &str) {
            let access_log = self
                .connections
                .get(&connection_id)
                .and_then(|connection| connection.access_log.as_ref());
            let request_id = access_log.map(|log| log.request_id.clone());
            if let Some(sender) = &self.error_log_sender {
                if let Err(error) = sender.try_send(RecentErrorEvent {
                    request_id,
                    error_code: error_code.as_str().to_string(),
                    message: message.to_string(),
                }) {
                    self.record_log_queue_drop(error);
                }
            }
            if matches!(
                error_code,
                ErrorCode::RuntimeUpstreamBadGateway | ErrorCode::RuntimeUpstreamTimeout
            ) {
                self.emit_metric(upstream_failure_metric(
                    access_log.and_then(|log| log.route_id.as_deref()),
                    access_log.and_then(|log| log.upstream_id.as_deref()),
                    error_code,
                ));
            }
            if matches!(
                error_code,
                ErrorCode::TlsHandshakeFailed | ErrorCode::TlsHandshakeTimeout
            ) {
                let observation = if let Some(upstream_id) =
                    access_log.and_then(|log| log.upstream_id.as_deref())
                {
                    TlsFailureObservation::new(
                        TlsFailureComponent::Upstream,
                        upstream_id,
                        error_code.as_str(),
                    )
                } else {
                    let listener_id = self
                        .connections
                        .get(&connection_id)
                        .map(|connection| connection.listener_resource_id.as_str())
                        .unwrap_or("unmapped-listener");
                    TlsFailureObservation::new(
                        TlsFailureComponent::Listener,
                        listener_id,
                        error_code.as_str(),
                    )
                };
                if let Some(sender) = &self.tls_failure_sender {
                    if let Err(error) = sender.try_send(observation) {
                        self.record_log_queue_drop(error);
                    }
                }
                self.emit_metric(tls_handshake_failure_metric(error_code));
            }
        }

        fn emit_request_metrics(&self, event: &AccessLogEvent) {
            for metric in request_metrics(event) {
                self.emit_metric(metric);
            }
        }

        fn emit_active_connection_metric(&self) {
            self.emit_metric(active_connection_metric(self.connections.len() as i64));
        }

        fn emit_resource_payload_metric_if_changed(&mut self) {
            let used_bytes = self.payload_ledger.used_bytes();
            if self.last_resource_payload_bytes != Some(used_bytes) {
                self.last_resource_payload_bytes = Some(used_bytes);
                self.emit_metric(resource_payload_bytes_metric(used_bytes));
            }
            self.emit_resource_pressure_transition_if_changed();
            self.emit_resource_status_if_changed();
        }

        #[cfg(test)]
        fn install_resource_status_publisher(
            &mut self,
            publisher: Option<Arc<dyn RuntimeResourceStatusPublisher>>,
        ) {
            self.resource_status_publisher = publisher;
            self.last_resource_status = None;
            self.emit_resource_status_if_changed();
        }

        fn emit_resource_status_if_changed(&mut self) {
            let pressure = match self.payload_ledger.pressure_state() {
                ResourcePressureState::Normal => RuntimeResourcePressure::Normal,
                ResourcePressureState::Pressured => RuntimeResourcePressure::Pressured,
                ResourcePressureState::Exhausted => RuntimeResourcePressure::Exhausted,
                ResourcePressureState::FailedClosed => RuntimeResourcePressure::FailedClosed,
            };
            let changed = self.last_resource_status.as_ref().map_or(true, |previous| {
                previous.revision_id != self.active_revision_id
                    || previous.used_payload_bytes != self.payload_ledger.used_bytes()
                    || previous.payload_limit_bytes
                        != self.resource_policy.max_inflight_payload_bytes()
                    || previous.active_connections != self.connections.len()
                    || previous.pressure != pressure
            });
            if !changed {
                return;
            }
            self.resource_status_generation = self.resource_status_generation.saturating_add(1);
            let snapshot = RuntimeResourceStatusSnapshot {
                revision_id: self.active_revision_id.clone(),
                generation: self.resource_status_generation,
                used_payload_bytes: self.payload_ledger.used_bytes(),
                payload_limit_bytes: self.resource_policy.max_inflight_payload_bytes(),
                active_connections: self.connections.len(),
                pressure,
            };
            self.last_resource_status = Some(snapshot.clone());
            if let Some(publisher) = &self.resource_status_publisher {
                if publisher.try_publish_resource_status(snapshot)
                    != RuntimeResourceStatusPublishOutcome::Accepted
                {
                    if let Some(counter) = &self.log_drop_counter {
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }

        fn emit_resource_pressure_transition_if_changed(&mut self) {
            let current = self.payload_ledger.pressure_state();
            let previous = self.last_resource_pressure_state;
            let transition = match (previous, current) {
                (ResourcePressureState::Normal, ResourcePressureState::Pressured) => Some(
                    ResourcePressureTransition::Entered(ResourcePressureLevel::Pressured),
                ),
                (ResourcePressureState::Normal, ResourcePressureState::Exhausted) => Some(
                    ResourcePressureTransition::Entered(ResourcePressureLevel::Exhausted),
                ),
                (ResourcePressureState::Normal, ResourcePressureState::FailedClosed)
                | (
                    ResourcePressureState::Pressured | ResourcePressureState::Exhausted,
                    ResourcePressureState::FailedClosed,
                ) => Some(ResourcePressureTransition::Entered(
                    ResourcePressureLevel::FailedClosed,
                )),
                (
                    ResourcePressureState::Pressured | ResourcePressureState::Exhausted,
                    ResourcePressureState::Normal,
                ) => Some(ResourcePressureTransition::Recovered),
                _ => None,
            };
            self.last_resource_pressure_state = current;
            if let Some(transition) = transition {
                self.emit_product_log(structured_resource_pressure_log(
                    transition,
                    &self.resource_log_context(),
                ));
            }
        }

        fn emit_resource_admission_rejection(&mut self, decision: ConnectionAdmissionDecision) {
            let (resource_kind, reason) = match decision {
                ConnectionAdmissionDecision::Accepted => return,
                ConnectionAdmissionDecision::RejectedConnectionLimit => (
                    ResourceMetricKind::Connection,
                    ResourceRejectionReason::ConnectionLimit,
                ),
                ConnectionAdmissionDecision::RejectedPayloadPressure => (
                    ResourceMetricKind::Payload,
                    ResourceRejectionReason::PayloadPressure,
                ),
                ConnectionAdmissionDecision::RejectedFailedClosed => (
                    ResourceMetricKind::Payload,
                    ResourceRejectionReason::FailedClosed,
                ),
            };
            self.emit_metric(resource_admission_rejection_metric(resource_kind, reason));
            let key = ResourceAdmissionLogKey::new(
                resource_kind,
                reason,
                RequestedBytesBucket::NotApplicable,
            );
            let now_seconds = self.resource_log_started_at.elapsed().as_secs();
            if self
                .resource_admission_log_sampler
                .should_emit(key, now_seconds)
            {
                self.emit_product_log(structured_resource_admission_log(
                    &self.log_mode,
                    &self.resource_log_context(),
                    key,
                ));
            }
        }

        fn resource_log_context(&self) -> ResourceLogContext {
            ResourceLogContext::new(
                self.active_revision_id.clone(),
                self.resource_policy,
                self.payload_ledger.used_bytes(),
            )
        }

        fn sync_active_revision(&mut self, snapshot: &ConfigSnapshot) {
            if self.active_revision_id != snapshot.revision_id {
                self.active_revision_id = snapshot.revision_id.clone();
                self.emit_resource_status_if_changed();
            }
        }

        fn emit_product_log(&self, event: edge_ports::StructuredLogEvent) {
            if let Some(sender) = &self.product_log_sender {
                if let Err(error) = sender.try_send(event) {
                    self.record_log_queue_drop(error);
                }
            }
        }

        fn emit_metric(&self, metric: MetricEvent) {
            if let Some(publisher) = &self.metric_publisher {
                if publisher.try_publish(metric) != MetricPublishOutcome::Accepted {
                    if let Some(counter) = &self.log_drop_counter {
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }

        fn emit_failure_aware_event(&self, event: &FailureAwareEvent) {
            self.emit_product_log(structured_failure_aware_log(event));
            self.emit_metric(failure_aware_metric(event));
        }

        fn record_log_queue_drop<T>(&self, error: mpsc::TrySendError<T>) {
            if matches!(
                error,
                mpsc::TrySendError::Full(_) | mpsc::TrySendError::Disconnected(_)
            ) {
                if let Some(counter) = &self.log_drop_counter {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        fn drop_upstream(
            &mut self,
            connection_id: usize,
            registry: &mio::Registry,
        ) -> io::Result<()> {
            if let Some(connection) = self.connections.get_mut(&connection_id) {
                if let Some(mut upstream) = connection.upstream.take() {
                    if connection.upstream_registered {
                        registry.deregister(&mut upstream)?;
                    }
                    connection.upstream_registered = false;
                }
            }
            Ok(())
        }

        fn pause_upstream_read_if_needed(
            &mut self,
            connection_id: usize,
            registry: &mio::Registry,
        ) -> io::Result<()> {
            self.reconcile_response_read_interest(connection_id, registry)
        }

        fn resume_upstream_read_if_needed(
            &mut self,
            connection_id: usize,
            registry: &mio::Registry,
        ) -> io::Result<()> {
            self.reconcile_response_read_interest(connection_id, registry)
        }

        fn enforce_response_pressure_interests(
            &mut self,
            registry: &mio::Registry,
        ) -> io::Result<()> {
            let connection_ids = self.connections.keys().copied().collect::<Vec<_>>();
            for connection_id in connection_ids {
                self.reconcile_response_read_interest(connection_id, registry)?;
            }
            Ok(())
        }

        fn enforce_resource_pressure_interests(
            &mut self,
            registry: &mio::Registry,
        ) -> io::Result<()> {
            self.enforce_response_pressure_interests(registry)?;
            let tunnel_ids = self
                .connections
                .iter()
                .filter(|(_, connection)| {
                    connection.io.connection.state == ConnectionState::TunnelingWebSocket
                })
                .map(|(connection_id, _)| *connection_id)
                .collect::<Vec<_>>();
            for connection_id in tunnel_ids {
                self.reregister_tunnel_interests(connection_id, registry)?;
            }
            Ok(())
        }

        fn reconcile_response_read_interest(
            &mut self,
            connection_id: usize,
            registry: &mio::Registry,
        ) -> io::Result<()> {
            let pressure_state = self.payload_ledger.pressure_state();
            let Some(connection) = self.connections.get_mut(&connection_id) else {
                return Ok(());
            };
            let action = response_read_interest_action(
                pressure_state,
                &connection.io.connection.state,
                connection.upstream_registered,
                connection.buffered_client_output_len(),
                self.resource_limits.max_response_buffer_bytes,
            );
            let Some(upstream) = connection.upstream.as_mut() else {
                return Ok(());
            };
            match action {
                ResponseReadInterestAction::Keep => {}
                ResponseReadInterestAction::Pause => {
                    registry.deregister(upstream)?;
                    connection.upstream_registered = false;
                    #[cfg(test)]
                    if let Some(events) = &self.backpressure_events {
                        let _ = events.send(BackpressureEvent::UpstreamReadPaused);
                    }
                }
                ResponseReadInterestAction::Resume => {
                    registry.register(
                        upstream,
                        upstream_token(connection_id),
                        Interest::READABLE,
                    )?;
                    connection.upstream_registered = true;
                    #[cfg(test)]
                    if let Some(events) = &self.backpressure_events {
                        let _ = events.send(BackpressureEvent::UpstreamReadResumed);
                    }
                }
            }
            Ok(())
        }

        fn cleanup_closed(&mut self, registry: &mio::Registry) -> io::Result<()> {
            let completed: Vec<_> = self
                .connections
                .iter()
                .filter(|(_, connection)| {
                    let terminal_websocket =
                        connection.io.connection.state == ConnectionState::TunnelingWebSocket;
                    connection.close_after_write
                        && (connection.pending_client_output.is_empty() || terminal_websocket)
                        && matches!(
                            connection.io.connection.state,
                            ConnectionState::Draining
                                | ConnectionState::Closed
                                | ConnectionState::Failed
                                | ConnectionState::WritingClientResponse
                                | ConnectionState::TunnelingWebSocket
                        )
                })
                .map(|(connection_id, _)| *connection_id)
                .collect();

            for connection_id in completed {
                self.drop_upstream(connection_id, registry)?;
                self.remove_connection(connection_id, true);
            }
            self.enforce_resource_pressure_interests(registry)
        }

        fn remove_connection(&mut self, connection_id: usize, emit_access_log: bool) -> bool {
            if emit_access_log {
                if let Some(connection) = self.connections.get(&connection_id) {
                    self.emit_access_log(connection);
                }
            }
            let release_result = {
                let (connections, payload_ledger) =
                    (&mut self.connections, &mut self.payload_ledger);
                connections
                    .get_mut(&connection_id)
                    .map(|connection| connection.resource_charges.release_all(payload_ledger))
            };
            if let Some(Err(error)) = release_result {
                self.emit_error_log(connection_id, error.code, &error.message);
            }
            self.emit_resource_payload_metric_if_changed();
            #[cfg(test)]
            self.emit_resource_accounting_event();
            let Some(mut connection) = self.connections.remove(&connection_id) else {
                return false;
            };
            if let Some(reference) = connection.drain_reference.take() {
                self.upstream_selector.release_drain_reference(&reference);
            }
            self.completed += 1;
            self.emit_active_connection_metric();
            self.emit_resource_status_if_changed();
            true
        }

        fn reconcile_transport_payload_charges(
            &mut self,
            connection_id: usize,
            registry: &mio::Registry,
        ) -> io::Result<()> {
            let result = {
                let (connections, payload_ledger) =
                    (&mut self.connections, &mut self.payload_ledger);
                connections.get_mut(&connection_id).map(|connection| {
                    connection.sync_transport_payload_charges(payload_ledger, connection_id)
                })
            };
            match result {
                None | Some(Ok(false)) => {}
                Some(Ok(true)) => {
                    self.emit_resource_payload_metric_if_changed();
                    #[cfg(test)]
                    self.emit_resource_accounting_event();
                }
                Some(Err(error)) => {
                    self.emit_error_log(connection_id, error.code, &error.message);
                    self.drop_upstream(connection_id, registry)?;
                    if let Some(connection) = self.connections.get_mut(&connection_id) {
                        let _ = registry.deregister(&mut connection.client);
                    }
                    self.remove_connection(connection_id, false);
                }
            }
            self.enforce_resource_pressure_interests(registry)
        }

        fn release_request_charge(&mut self, connection_id: usize) {
            let result = {
                let (connections, payload_ledger) =
                    (&mut self.connections, &mut self.payload_ledger);
                connections
                    .get_mut(&connection_id)
                    .map(|connection| connection.resource_charges.release_request(payload_ledger))
            };
            if let Some(Err(error)) = result {
                self.emit_error_log(connection_id, error.code, &error.message);
            }
            self.emit_resource_payload_metric_if_changed();
            #[cfg(test)]
            self.emit_resource_accounting_event();
        }

        #[cfg(test)]
        fn emit_resource_accounting_event(&self) {
            if let Some(sender) = &self.resource_accounting_events {
                let _ = sender.send(ResourceAccountingEvent {
                    used_bytes: self.payload_ledger.used_bytes(),
                    live_charges: self.payload_ledger.live_charge_count(),
                    client_response_bytes: self
                        .connections
                        .values()
                        .map(|connection| {
                            connection
                                .resource_charges
                                .client_response_bytes(&self.payload_ledger)
                        })
                        .sum(),
                    tls_pending_bytes: self
                        .connections
                        .values()
                        .map(|connection| {
                            connection
                                .resource_charges
                                .tls_pending_bytes(&self.payload_ledger)
                        })
                        .sum(),
                    websocket_client_to_upstream_bytes: self
                        .connections
                        .values()
                        .map(|connection| {
                            connection
                                .resource_charges
                                .websocket_client_to_upstream_bytes(&self.payload_ledger)
                        })
                        .sum(),
                    websocket_upstream_to_client_bytes: self
                        .connections
                        .values()
                        .map(|connection| {
                            connection
                                .resource_charges
                                .websocket_upstream_to_client_bytes(&self.payload_ledger)
                        })
                        .sum(),
                });
            }
        }

        fn debug_state_summary(&self) -> String {
            self.connections
                .iter()
                .map(|(connection_id, connection)| {
                    format!(
                        "{}:{:?}:upstream={}:registered={}:close={}:client_remaining={}:upstream_remaining={}:framing={:?}:pending_response={:?}:response_charge={}:tls_charge={}:ws_c2u_charge={}:ws_u2c_charge={}",
                        connection_id,
                        connection.io.connection.state,
                        connection.upstream.is_some(),
                        connection.upstream_registered,
                        connection.close_after_write,
                        connection.buffered_client_output_len(),
                        connection.io.upstream_write_buffer().remaining_len(),
                        connection
                            .response_framing
                            .as_ref()
                            .map(HttpResponseFraming::phase),
                        connection.pending_client_response,
                        connection
                            .resource_charges
                            .client_response_bytes(&self.payload_ledger),
                        connection
                            .resource_charges
                            .tls_pending_bytes(&self.payload_ledger),
                        connection
                            .resource_charges
                            .websocket_client_to_upstream_bytes(&self.payload_ledger),
                        connection
                            .resource_charges
                            .websocket_upstream_to_client_bytes(&self.payload_ledger),
                    )
                })
                .collect::<Vec<_>>()
                .join(",")
        }
    }

    struct SnapshotMioConnection {
        client: MioTcpStream,
        client_transport: ClientTransport,
        pending_client_output: PendingSocketOutput,
        pending_client_response: PendingClientResponseBatch,
        upstream: Option<MioTcpStream>,
        upstream_transport: UpstreamTransport,
        pending_upstream_output: WriteBuffer,
        pending_upstream_tls: Option<PendingUpstreamTls>,
        io: HttpConnectionIo,
        client_ip: String,
        listener_resource_id: String,
        accepted_at: Instant,
        access_log: Option<AccessLogDraft>,
        close_after_write: bool,
        pending_upstream_request: Option<Vec<u8>>,
        websocket_requested: bool,
        websocket_response: Vec<u8>,
        client_registered: bool,
        upstream_registered: bool,
        tunnel_client_to_upstream: WriteBuffer,
        tunnel_upstream_to_client: WriteBuffer,
        deadline: Option<Instant>,
        retry: Option<RetryContext>,
        drain_reference: Option<DrainReference>,
        resource_charges: ConnectionPayloadCharges,
        response_framing: Option<HttpResponseFraming>,
    }

    struct RetryContext {
        service_id: ServiceId,
        policy: edge_domain::RetryPolicy,
        method: edge_domain::ReplayMethod,
        body_bytes: u64,
        attempted: BTreeSet<UpstreamId>,
        current_upstream_id: UpstreamId,
        retries_used: u8,
        replay_wire_len: usize,
        original_request: HttpRequest,
        original_authority: String,
        forwarded_scheme: String,
        websocket_requested: bool,
    }

    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    enum PendingClientResponseBatch {
        #[default]
        Empty,
        TransportOwned {
            plaintext_bytes: usize,
        },
        SocketDraining {
            plaintext_bytes: usize,
        },
    }

    struct PendingUpstreamTls {
        service_id: ServiceId,
        upstream_id: UpstreamId,
        server_name: TlsServerName,
    }

    struct UpstreamConnectPlan {
        address: SocketAddr,
        request: Vec<u8>,
        websocket_requested: bool,
        service_id: ServiceId,
        upstream_id: UpstreamId,
        tls_policy: UpstreamTlsPolicy,
    }

    fn pending_upstream_tls(
        service_id: ServiceId,
        upstream_id: UpstreamId,
        policy: &UpstreamTlsPolicy,
    ) -> Option<PendingUpstreamTls> {
        match policy {
            UpstreamTlsPolicy::Disabled => None,
            UpstreamTlsPolicy::ServerAuthenticated { server_name, .. } => {
                Some(PendingUpstreamTls {
                    service_id,
                    upstream_id,
                    server_name: server_name.clone(),
                })
            }
        }
    }

    impl SnapshotMioConnection {
        fn begin_response_framing(&mut self, max_header_bytes: usize, websocket_requested: bool) {
            self.response_framing = if websocket_requested {
                None
            } else if self
                .retry
                .as_ref()
                .is_some_and(|retry| retry.method == edge_domain::ReplayMethod::Head)
            {
                Some(HttpResponseFraming::new_for_head_response(
                    max_header_bytes,
                    max_header_bytes,
                ))
            } else {
                Some(HttpResponseFraming::new(max_header_bytes, max_header_bytes))
            };
        }

        fn buffered_client_output_len(&self) -> usize {
            self.io.client_write_buffer().remaining_len()
                + self.pending_client_output.remaining_len()
        }

        fn sync_transport_payload_charges(
            &mut self,
            ledger: &mut PayloadBudgetLedger,
            connection_id: usize,
        ) -> Result<bool, AppError> {
            let tls_bytes = super::tls_pending_owner_bytes(
                &self.client_transport,
                &self.pending_client_output,
                &self.upstream_transport,
                &self.pending_upstream_output,
            )?;
            let (websocket_client_to_upstream, websocket_upstream_to_client) =
                if self.io.connection.state == ConnectionState::TunnelingWebSocket {
                    super::websocket_pending_owner_bytes(
                        self.tunnel_upstream_to_client.remaining_len(),
                        self.tunnel_client_to_upstream.remaining_len(),
                        &self.client_transport,
                        &self.pending_client_output,
                        &self.upstream_transport,
                        &self.pending_upstream_output,
                    )?
                } else {
                    (0, 0)
                };
            let mut changed = self.resource_charges.sync_websocket_client_to_upstream(
                ledger,
                connection_id,
                websocket_client_to_upstream,
            )?;
            changed |= self.resource_charges.sync_websocket_upstream_to_client(
                ledger,
                connection_id,
                websocket_upstream_to_client,
            )?;
            changed |= self
                .resource_charges
                .sync_tls_pending(ledger, connection_id, tls_bytes)?;
            Ok(changed)
        }

        fn install_transport_owned_client_response(
            &mut self,
            plaintext_bytes: usize,
        ) -> Result<(), AppError> {
            if plaintext_bytes == 0
                || self.pending_client_response != PendingClientResponseBatch::Empty
            {
                return Err(resource_accounting_error(
                    "client response pending batch transition is invalid",
                ));
            }
            self.pending_client_response =
                PendingClientResponseBatch::TransportOwned { plaintext_bytes };
            Ok(())
        }

        fn release_drained_client_response(
            &mut self,
            ledger: &mut PayloadBudgetLedger,
        ) -> Result<bool, AppError> {
            if !self.pending_client_output.is_empty() {
                return Ok(false);
            }
            let PendingClientResponseBatch::SocketDraining { plaintext_bytes } =
                self.pending_client_response
            else {
                return Ok(false);
            };
            let current_bytes = self.resource_charges.client_response_bytes(ledger);
            let next_bytes = current_bytes.checked_sub(plaintext_bytes).ok_or_else(|| {
                resource_accounting_error("client response pending bytes exceed current charge")
            })?;
            self.resource_charges
                .resize_client_response_in_use(ledger, next_bytes)?;
            self.pending_client_response = PendingClientResponseBatch::Empty;
            Ok(true)
        }
    }

    #[derive(Debug, Clone)]
    struct AccessLogDraft {
        request_id: String,
        revision_id: String,
        route_id: Option<String>,
        upstream_id: Option<String>,
        scheme: String,
        method: String,
        path: String,
        status_code: Option<u16>,
    }

    fn refresh_deadline_for_connection(
        connection: &mut SnapshotMioConnection,
        resource_limits: &ResourceLimits,
        now: Instant,
    ) {
        connection.deadline =
            deadline_for_state(resource_limits, &connection.io.connection.state, now);
    }

    fn deadline_for_state(
        resource_limits: &ResourceLimits,
        state: &ConnectionState,
        now: Instant,
    ) -> Option<Instant> {
        timeout_duration_for_state(resource_limits, state)
            .and_then(|duration| now.checked_add(duration))
    }

    fn timeout_duration_for_state(
        resource_limits: &ResourceLimits,
        state: &ConnectionState,
    ) -> Option<Duration> {
        match state {
            ConnectionState::Accepted | ConnectionState::ReadingClientRequest => {
                Some(resource_limits.idle_timeout)
            }
            ConnectionState::ConnectingUpstream => Some(resource_limits.connect_timeout),
            ConnectionState::HandshakingUpstreamTls => Some(resource_limits.connect_timeout),
            ConnectionState::WritingUpstreamRequest | ConnectionState::ReadingUpstreamResponse => {
                Some(resource_limits.upstream_read_timeout)
            }
            ConnectionState::WritingClientResponse => Some(resource_limits.client_write_timeout),
            _ => None,
        }
    }

    pub(crate) fn tunnel_interest(readable: bool, writable: bool) -> Option<Interest> {
        match (readable, writable) {
            (true, true) => Some(Interest::READABLE | Interest::WRITABLE),
            (true, false) => Some(Interest::READABLE),
            (false, true) => Some(Interest::WRITABLE),
            (false, false) => None,
        }
    }

    fn reconcile_mio_registration(
        registry: &mio::Registry,
        stream: &mut MioTcpStream,
        token: Token,
        interest: Option<Interest>,
        registered: &mut bool,
    ) -> io::Result<()> {
        match (interest, *registered) {
            (Some(interest), true) => registry.reregister(stream, token, interest),
            (Some(interest), false) => {
                registry.register(stream, token, interest)?;
                *registered = true;
                Ok(())
            }
            (None, true) => {
                registry.deregister(stream)?;
                *registered = false;
                Ok(())
            }
            (None, false) => Ok(()),
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct TunnelFlowControl {
        pub client_readable: bool,
        pub upstream_readable: bool,
    }

    pub(crate) fn tunnel_pressure_flow(
        pressure_state: ResourcePressureState,
        local_flow: TunnelFlowControl,
    ) -> TunnelFlowControl {
        if pressure_state == ResourcePressureState::Normal {
            local_flow
        } else {
            TunnelFlowControl {
                client_readable: false,
                upstream_readable: false,
            }
        }
    }

    pub(crate) fn tunnel_flow_control(
        client_to_upstream_plaintext: usize,
        pending_upstream_socket: usize,
        upstream_to_client_plaintext: usize,
        pending_client_socket: usize,
        limits: &ResourceLimits,
    ) -> TunnelFlowControl {
        TunnelFlowControl {
            client_readable: client_to_upstream_plaintext.saturating_add(pending_upstream_socket)
                < limits.max_request_body_bytes,
            upstream_readable: upstream_to_client_plaintext.saturating_add(pending_client_socket)
                < limits.max_response_buffer_bytes,
        }
    }

    fn upstream_transport_interest(
        transport: &UpstreamTransport,
        state: &ConnectionState,
        pending_output_complete: bool,
    ) -> Interest {
        let merged = transport.merge_interest(state.io_interest());
        let writable = merged.upstream_writable || !pending_output_complete;
        match (merged.upstream_readable, writable) {
            (true, true) => Interest::READABLE | Interest::WRITABLE,
            (true, false) => Interest::READABLE,
            (false, true) => Interest::WRITABLE,
            (false, false) => Interest::READABLE,
        }
    }

    fn websocket_response_headers_ready(bytes: &[u8]) -> bool {
        bytes.windows(4).any(|window| window == b"\r\n\r\n")
    }

    fn websocket_response_is_switching_protocols(bytes: &[u8]) -> bool {
        bytes.starts_with(b"HTTP/1.1 101") || bytes.starts_with(b"HTTP/1.0 101")
    }

    pub fn handle_snapshot_http_proxy_connection(
        mut client: StdTcpStream,
        snapshot: &ConfigSnapshot,
        challenge_responder: &dyn Http01ChallengeResponder,
        limits: HttpLimits,
        client_ip: String,
    ) -> io::Result<()> {
        client.set_read_timeout(Some(Duration::from_secs(30)))?;
        client.set_write_timeout(Some(Duration::from_secs(30)))?;
        handle_snapshot_http_proxy_stream(
            &mut client,
            snapshot,
            challenge_responder,
            limits,
            client_ip,
        )
    }

    pub fn handle_snapshot_http_proxy_stream<S>(
        client: &mut S,
        snapshot: &ConfigSnapshot,
        challenge_responder: &dyn Http01ChallengeResponder,
        limits: HttpLimits,
        client_ip: String,
    ) -> io::Result<()>
    where
        S: Read + Write + ?Sized,
    {
        handle_snapshot_http_proxy_stream_with_scheme(
            client,
            snapshot,
            challenge_responder,
            limits,
            client_ip,
            "http",
        )
    }

    pub fn handle_snapshot_http_proxy_stream_with_scheme<S>(
        client: &mut S,
        snapshot: &ConfigSnapshot,
        challenge_responder: &dyn Http01ChallengeResponder,
        limits: HttpLimits,
        client_ip: String,
        scheme: &str,
    ) -> io::Result<()>
    where
        S: Read + Write + ?Sized,
    {
        let request_bytes = match read_http_request_bytes(client, &limits) {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = write_error_response(client, error.code);
                return Ok(());
            }
        };
        let request = match parse_http_request(&request_bytes, &limits) {
            Ok(request) => request,
            Err(error) => {
                let _ = write_error_response(client, error.code);
                return Ok(());
            }
        };

        let Some(authority) = request.header_value("Host") else {
            client.write_all(&http_error_response(400, "Bad Request"))?;
            return client.flush();
        };
        let match_host = host_for_route_match(authority);

        match select_http_route_action(snapshot, &match_host, &request.path) {
            HttpRouteAction::Proxy {
                route_id: _,
                service_id,
            } => {
                let Some(upstream) = snapshot.primary_upstream_for_service(&service_id) else {
                    client.write_all(&http_error_response(502, "Bad Gateway"))?;
                    return client.flush();
                };
                let upstream_target = match UpstreamTarget::parse_http(&upstream.url) {
                    Ok(upstream) => upstream,
                    Err(_) => {
                        client.write_all(&http_error_response(502, "Bad Gateway"))?;
                        return client.flush();
                    }
                };
                let upstream_response = match forward_http_request(
                    &request,
                    &upstream_target,
                    &client_ip,
                    scheme,
                    authority,
                ) {
                    Ok(response) => response,
                    Err(_) => http_error_response(502, "Bad Gateway"),
                };
                client.write_all(&upstream_response)?;
                client.flush()
            }
            HttpRouteAction::Redirect { status_code, .. } => {
                client.write_all(&redirect_response(status_code, authority, &request.path))?;
                client.flush()
            }
            HttpRouteAction::AcmeChallengeBypass { token } => {
                if let Some(body) = challenge_responder.respond(&token) {
                    client.write_all(&plain_response(200, "OK", body.as_bytes()))?;
                } else {
                    client.write_all(&http_error_response(404, "Not Found"))?;
                }
                client.flush()
            }
            HttpRouteAction::NotFound => {
                client.write_all(&http_error_response(404, "Not Found"))?;
                client.flush()
            }
        }
    }

    pub fn host_for_route_match(authority: &str) -> String {
        let trimmed = authority.trim();
        if let Some(rest) = trimmed.strip_prefix('[') {
            if let Some(end) = rest.find(']') {
                return rest[..end].to_string();
            }
        }
        trimmed
            .split_once(':')
            .map(|(host, _)| host)
            .unwrap_or(trimmed)
            .to_string()
    }

    fn forward_http_request(
        request: &HttpRequest,
        upstream: &UpstreamTarget,
        client_ip: &str,
        scheme: &str,
        original_host: &str,
    ) -> io::Result<Vec<u8>> {
        let mut upstream_stream = StdTcpStream::connect(upstream.address())?;
        upstream_stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        upstream_stream.set_write_timeout(Some(Duration::from_secs(30)))?;

        let upstream_request =
            build_upstream_request(request, upstream, client_ip, scheme, original_host, false)?;
        upstream_stream.write_all(&upstream_request)?;
        upstream_stream.flush()?;

        let mut response = Vec::new();
        upstream_stream.read_to_end(&mut response)?;
        Ok(response)
    }

    fn build_upstream_request<T>(
        request: &HttpRequest,
        upstream: &T,
        client_ip: &str,
        scheme: &str,
        original_host: &str,
        preserve_upgrade_headers: bool,
    ) -> io::Result<Vec<u8>>
    where
        T: UpstreamRequestTarget + ?Sized,
    {
        build_upstream_request_with_host_override(
            request,
            upstream,
            client_ip,
            scheme,
            original_host,
            preserve_upgrade_headers,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_upstream_request_with_host_override<T>(
        request: &HttpRequest,
        upstream: &T,
        client_ip: &str,
        scheme: &str,
        original_host: &str,
        preserve_upgrade_headers: bool,
        host_override: Option<&str>,
    ) -> io::Result<Vec<u8>>
    where
        T: UpstreamRequestTarget + ?Sized,
    {
        let mut headers = if preserve_upgrade_headers {
            request.headers.clone()
        } else {
            remove_hop_by_hop_headers(&request.headers)
        };
        headers.retain(|header| {
            !matches!(
                header.name.to_ascii_lowercase().as_str(),
                "x-forwarded-for" | "x-forwarded-proto" | "x-forwarded-host"
            )
        });
        headers.extend(forwarded_headers(client_ip, scheme, original_host));
        if let Some(host_override) = host_override {
            if let Some(host) = headers
                .iter_mut()
                .find(|header| header.name.eq_ignore_ascii_case("Host"))
            {
                host.value = host_override.to_string();
            }
        }

        let request_path = upstream.join_request_path(&request.path);
        let planned_len = planned_upstream_request_len(
            request,
            &request_path,
            &headers,
            preserve_upgrade_headers,
        )?;

        let mut upstream_request = Vec::new();
        upstream_request
            .try_reserve_exact(planned_len)
            .map_err(|_| resource_allocation_io_error("upstream wire reserve failed"))?;
        write!(
            upstream_request,
            "{} {} {}\r\n",
            request.method, request_path, request.version
        )?;
        for Header { name, value } in headers {
            write!(upstream_request, "{name}: {value}\r\n")?;
        }
        if !preserve_upgrade_headers {
            upstream_request.extend_from_slice(b"Connection: close\r\n");
        }
        upstream_request.extend_from_slice(b"\r\n");
        upstream_request.extend_from_slice(&request.body);

        if upstream_request.len() != planned_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "RESOURCE_ACCOUNTING_INVARIANT_FAILED: upstream wire length mismatch",
            ));
        }

        Ok(upstream_request)
    }

    fn planned_upstream_request_len(
        request: &HttpRequest,
        request_path: &str,
        headers: &[Header],
        preserve_upgrade_headers: bool,
    ) -> io::Result<usize> {
        let mut total = checked_wire_length(&[
            request.method.len(),
            1,
            request_path.len(),
            1,
            request.version.len(),
            2,
        ])?;
        for header in headers {
            total = checked_wire_length(&[total, header.name.len(), 2, header.value.len(), 2])?;
        }
        if !preserve_upgrade_headers {
            total = checked_wire_length(&[total, b"Connection: close\r\n".len()])?;
        }
        checked_wire_length(&[total, 2, request.body.len()])
    }

    pub(crate) fn checked_wire_length(parts: &[usize]) -> io::Result<usize> {
        parts.iter().try_fold(0_usize, |total, part| {
            total
                .checked_add(*part)
                .ok_or_else(|| resource_allocation_io_error("upstream wire length overflowed"))
        })
    }

    fn resource_allocation_io_error(message: &'static str) -> io::Error {
        io::Error::new(
            io::ErrorKind::OutOfMemory,
            format!(
                "{}: {message}",
                ErrorCode::ResourceAllocationFailed.as_str()
            ),
        )
    }

    pub(crate) fn build_selected_upstream_request(
        request: &HttpRequest,
        upstream: &UpstreamEndpoint,
        tls_policy: &UpstreamTlsPolicy,
        client_ip: &str,
        scheme: &str,
        original_host: &str,
        preserve_upgrade_headers: bool,
    ) -> io::Result<Vec<u8>> {
        let planned_len = planned_selected_upstream_request_len(
            request,
            upstream,
            tls_policy,
            client_ip,
            scheme,
            original_host,
            preserve_upgrade_headers,
        )?;
        let host_override = match tls_policy {
            UpstreamTlsPolicy::Disabled => None,
            UpstreamTlsPolicy::ServerAuthenticated { http_host, .. } => Some(http_host.as_str()),
        };
        let output = build_upstream_request_with_host_override(
            request,
            upstream,
            client_ip,
            scheme,
            original_host,
            preserve_upgrade_headers,
            host_override,
        )?;
        if output.len() != planned_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "RESOURCE_ACCOUNTING_INVARIANT_FAILED: selected wire length mismatch",
            ));
        }
        Ok(output)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn planned_selected_upstream_request_len(
        request: &HttpRequest,
        upstream: &UpstreamEndpoint,
        tls_policy: &UpstreamTlsPolicy,
        client_ip: &str,
        scheme: &str,
        original_host: &str,
        preserve_upgrade_headers: bool,
    ) -> io::Result<usize> {
        let host_override = match tls_policy {
            UpstreamTlsPolicy::Disabled => None,
            UpstreamTlsPolicy::ServerAuthenticated { http_host, .. } => Some(http_host.as_str()),
        };
        let mut headers = if preserve_upgrade_headers {
            request.headers.clone()
        } else {
            remove_hop_by_hop_headers(&request.headers)
        };
        headers.retain(|header| {
            !matches!(
                header.name.to_ascii_lowercase().as_str(),
                "x-forwarded-for" | "x-forwarded-proto" | "x-forwarded-host"
            )
        });
        headers.extend(forwarded_headers(client_ip, scheme, original_host));
        if let Some(host_override) = host_override {
            if let Some(host) = headers
                .iter_mut()
                .find(|header| header.name.eq_ignore_ascii_case("Host"))
            {
                host.value = host_override.to_string();
            }
        }
        planned_upstream_request_len(
            request,
            &upstream.join_request_path(&request.path),
            &headers,
            preserve_upgrade_headers,
        )
    }

    fn read_http_request_bytes<S>(stream: &mut S, limits: &HttpLimits) -> Result<Vec<u8>, AppError>
    where
        S: Read + ?Sized,
    {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 4096];
        let mut header_end = None;

        loop {
            let read = stream.read(&mut buffer).map_err(|error| {
                AppError::new(ErrorCode::HttpMalformedRequest, error.to_string())
            })?;
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..read]);
            if bytes.len() > limits.max_header_bytes + limits.max_body_bytes + 4 {
                return Err(AppError::new(
                    ErrorCode::HttpRequestBodyTooLarge,
                    "request exceeds configured limits",
                ));
            }
            if header_end.is_none() {
                header_end = bytes
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|position| position + 4);
                if header_end.is_none() && bytes.len() > limits.max_header_bytes {
                    return Err(AppError::new(
                        ErrorCode::HttpHeaderTooLarge,
                        "headers exceed limit",
                    ));
                }
            }
            if let Some(header_end) = header_end {
                let body_len = content_length_from_header_bytes(&bytes[..header_end])?;
                if body_len > limits.max_body_bytes {
                    return Err(AppError::new(
                        ErrorCode::HttpRequestBodyTooLarge,
                        "body exceeds limit",
                    ));
                }
                if bytes.len() >= header_end + body_len {
                    return Ok(bytes);
                }
            }
        }

        Ok(bytes)
    }

    fn content_length_from_header_bytes(header_bytes: &[u8]) -> Result<usize, AppError> {
        let text = std::str::from_utf8(header_bytes)
            .map_err(|_| AppError::new(ErrorCode::HttpMalformedRequest, "headers are not UTF-8"))?;
        for line in text.split("\r\n") {
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("Content-Length") {
                    return value.trim().parse::<usize>().map_err(|_| {
                        AppError::new(ErrorCode::HttpMalformedRequest, "invalid content length")
                    });
                }
            }
        }
        Ok(0)
    }

    fn write_error_response<S>(stream: &mut S, code: ErrorCode) -> io::Result<()>
    where
        S: Write + ?Sized,
    {
        stream.write_all(&error_response_for_code(code))
    }

    pub(crate) fn error_response_for_code(code: ErrorCode) -> Vec<u8> {
        let (status, reason) = match code {
            ErrorCode::HttpRequestBodyTooLarge => (413, "Payload Too Large"),
            ErrorCode::HttpRequestLineTooLarge => (414, "URI Too Long"),
            ErrorCode::HttpHeaderTooLarge => (431, "Request Header Fields Too Large"),
            ErrorCode::HttpConnectMethodRejected => (405, "Method Not Allowed"),
            ErrorCode::HttpMalformedRequest
            | ErrorCode::HttpTransferEncodingContentLengthConflict => (400, "Bad Request"),
            ErrorCode::ResourcePayloadCapacityReached | ErrorCode::ResourceAllocationFailed => {
                (503, "Service Unavailable")
            }
            _ => (500, "Internal Server Error"),
        };
        http_error_response(status, reason)
    }

    fn redirect_response(status: u16, host: &str, path: &str) -> Vec<u8> {
        let reason = match status {
            301 => "Moved Permanently",
            308 => "Permanent Redirect",
            _ => "Redirect",
        };
        let location = format!("https://{host}{path}");
        let body = format!("{status} {reason}\n");
        format!(
            "HTTP/1.1 {status} {reason}\r\nLocation: {location}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn plain_response(status: u16, reason: &str, body: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ResponseFramingPhase {
        Headers,
        ContentLength,
        ChunkSize,
        ChunkData,
        ChunkDataCrlf,
        Trailers,
        CloseDelimited,
        Complete,
        Failed,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ResponseFramingProgress {
        pub consumed: usize,
        pub input_len: usize,
        pub phase: ResponseFramingPhase,
        pub status_code: Option<u16>,
    }

    #[derive(Debug)]
    enum ResponseFramingState {
        Headers(Vec<u8>),
        ContentLength { remaining: usize },
        ChunkSize { line: Vec<u8> },
        ChunkData { remaining: usize },
        ChunkDataCrlf { matched: usize },
        Trailers { line: Vec<u8> },
        CloseDelimited,
        Complete,
        Failed,
    }

    #[derive(Debug)]
    pub struct HttpResponseFraming {
        state: ResponseFramingState,
        max_header_bytes: usize,
        max_line_bytes: usize,
        body_expectation: ResponseBodyExpectation,
        status_code: Option<u16>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ResponseBodyExpectation {
        Normal,
        HeadResponse,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ResponseBodyFraming {
        Interim,
        None,
        ContentLength(usize),
        Chunked,
        CloseDelimited,
    }

    impl HttpResponseFraming {
        pub fn new(max_header_bytes: usize, max_line_bytes: usize) -> Self {
            Self::with_body_expectation(
                max_header_bytes,
                max_line_bytes,
                ResponseBodyExpectation::Normal,
            )
        }

        pub fn new_for_head_response(max_header_bytes: usize, max_line_bytes: usize) -> Self {
            Self::with_body_expectation(
                max_header_bytes,
                max_line_bytes,
                ResponseBodyExpectation::HeadResponse,
            )
        }

        fn with_body_expectation(
            max_header_bytes: usize,
            max_line_bytes: usize,
            body_expectation: ResponseBodyExpectation,
        ) -> Self {
            Self {
                state: ResponseFramingState::Headers(Vec::new()),
                max_header_bytes,
                max_line_bytes,
                body_expectation,
                status_code: None,
            }
        }

        pub fn phase(&self) -> ResponseFramingPhase {
            match self.state {
                ResponseFramingState::Headers(_) => ResponseFramingPhase::Headers,
                ResponseFramingState::ContentLength { .. } => ResponseFramingPhase::ContentLength,
                ResponseFramingState::ChunkSize { .. } => ResponseFramingPhase::ChunkSize,
                ResponseFramingState::ChunkData { .. } => ResponseFramingPhase::ChunkData,
                ResponseFramingState::ChunkDataCrlf { .. } => ResponseFramingPhase::ChunkDataCrlf,
                ResponseFramingState::Trailers { .. } => ResponseFramingPhase::Trailers,
                ResponseFramingState::CloseDelimited => ResponseFramingPhase::CloseDelimited,
                ResponseFramingState::Complete => ResponseFramingPhase::Complete,
                ResponseFramingState::Failed => ResponseFramingPhase::Failed,
            }
        }

        pub fn status_code(&self) -> Option<u16> {
            self.status_code
        }

        pub fn push(&mut self, input: &[u8]) -> Result<ResponseFramingProgress, AppError> {
            if matches!(
                self.state,
                ResponseFramingState::Complete | ResponseFramingState::Failed
            ) {
                return self.fail("response framing is already terminal");
            }

            let mut cursor = 0;
            while cursor < input.len() {
                match &mut self.state {
                    ResponseFramingState::Headers(headers) => {
                        if let Err(error) =
                            try_push_bounded(headers, input[cursor], self.max_header_bytes)
                        {
                            self.state = ResponseFramingState::Failed;
                            return Err(error);
                        }
                        cursor += 1;
                        if headers.ends_with(b"\r\n\r\n") {
                            let headers = match std::mem::replace(
                                &mut self.state,
                                ResponseFramingState::Failed,
                            ) {
                                ResponseFramingState::Headers(headers) => headers,
                                _ => unreachable!(),
                            };
                            let (status_code, body_framing) =
                                parse_response_framing_headers(&headers, self.body_expectation)?;
                            self.status_code = Some(status_code);
                            self.state = match body_framing {
                                ResponseBodyFraming::Interim => {
                                    ResponseFramingState::Headers(Vec::new())
                                }
                                ResponseBodyFraming::None
                                | ResponseBodyFraming::ContentLength(0) => {
                                    ResponseFramingState::Complete
                                }
                                ResponseBodyFraming::ContentLength(remaining) => {
                                    ResponseFramingState::ContentLength { remaining }
                                }
                                ResponseBodyFraming::Chunked => {
                                    ResponseFramingState::ChunkSize { line: Vec::new() }
                                }
                                ResponseBodyFraming::CloseDelimited => {
                                    ResponseFramingState::CloseDelimited
                                }
                            };
                        }
                    }
                    ResponseFramingState::ContentLength { remaining } => {
                        let consumed = (*remaining).min(input.len() - cursor);
                        *remaining -= consumed;
                        cursor += consumed;
                        if *remaining == 0 {
                            self.state = ResponseFramingState::Complete;
                        }
                    }
                    ResponseFramingState::ChunkSize { line } => {
                        if let Err(error) =
                            try_push_bounded(line, input[cursor], self.max_line_bytes)
                        {
                            self.state = ResponseFramingState::Failed;
                            return Err(error);
                        }
                        cursor += 1;
                        if line.ends_with(b"\r\n") {
                            let line = match std::mem::replace(
                                &mut self.state,
                                ResponseFramingState::Failed,
                            ) {
                                ResponseFramingState::ChunkSize { line } => line,
                                _ => unreachable!(),
                            };
                            let size = parse_chunk_size(&line[..line.len() - 2])?;
                            self.state = if size == 0 {
                                ResponseFramingState::Trailers { line: Vec::new() }
                            } else {
                                ResponseFramingState::ChunkData { remaining: size }
                            };
                        }
                    }
                    ResponseFramingState::ChunkData { remaining } => {
                        let consumed = (*remaining).min(input.len() - cursor);
                        *remaining -= consumed;
                        cursor += consumed;
                        if *remaining == 0 {
                            self.state = ResponseFramingState::ChunkDataCrlf { matched: 0 };
                        }
                    }
                    ResponseFramingState::ChunkDataCrlf { matched } => {
                        let expected = b"\r\n"[*matched];
                        if input[cursor] != expected {
                            return self.fail("chunk data is not followed by CRLF");
                        }
                        *matched += 1;
                        cursor += 1;
                        if *matched == 2 {
                            self.state = ResponseFramingState::ChunkSize { line: Vec::new() };
                        }
                    }
                    ResponseFramingState::Trailers { line } => {
                        if let Err(error) =
                            try_push_bounded(line, input[cursor], self.max_line_bytes)
                        {
                            self.state = ResponseFramingState::Failed;
                            return Err(error);
                        }
                        cursor += 1;
                        if line.ends_with(b"\r\n") {
                            if line.len() == 2 {
                                self.state = ResponseFramingState::Complete;
                            } else if validate_trailer_line(&line[..line.len() - 2]).is_err() {
                                return self.fail("malformed chunk trailer");
                            } else {
                                line.clear();
                            }
                        }
                    }
                    ResponseFramingState::CloseDelimited => {
                        cursor = input.len();
                    }
                    ResponseFramingState::Complete | ResponseFramingState::Failed => break,
                }
            }

            Ok(self.progress(cursor, input.len()))
        }

        pub fn finish_on_eof(&mut self) -> Result<ResponseFramingProgress, AppError> {
            match self.state {
                ResponseFramingState::CloseDelimited => {
                    self.state = ResponseFramingState::Complete;
                    Ok(self.progress(0, 0))
                }
                ResponseFramingState::Complete => Ok(self.progress(0, 0)),
                ResponseFramingState::Failed => self.fail("response framing has failed"),
                _ => self.fail("upstream closed before response framing completed"),
            }
        }

        fn progress(&self, consumed: usize, input_len: usize) -> ResponseFramingProgress {
            ResponseFramingProgress {
                consumed,
                input_len,
                phase: self.phase(),
                status_code: self.status_code,
            }
        }

        fn fail<T>(&mut self, message: &'static str) -> Result<T, AppError> {
            self.state = ResponseFramingState::Failed;
            Err(AppError::new(ErrorCode::RuntimeUpstreamBadGateway, message))
        }
    }

    fn try_push_bounded(bytes: &mut Vec<u8>, byte: u8, max_bytes: usize) -> Result<(), AppError> {
        if bytes.len() >= max_bytes {
            return Err(AppError::new(
                ErrorCode::ResourcePayloadCapacityReached,
                "response framing buffer limit reached",
            ));
        }
        if bytes.len() == bytes.capacity() {
            bytes.try_reserve(1).map_err(|_| {
                AppError::new(
                    ErrorCode::ResourceAllocationFailed,
                    "response framing buffer allocation failed",
                )
            })?;
        }
        bytes.push(byte);
        Ok(())
    }

    fn parse_response_framing_headers(
        headers: &[u8],
        body_expectation: ResponseBodyExpectation,
    ) -> Result<(u16, ResponseBodyFraming), AppError> {
        let header_text = std::str::from_utf8(headers)
            .map_err(|_| malformed_upstream_response("response headers are not UTF-8"))?;
        let header_text = header_text
            .strip_suffix("\r\n\r\n")
            .ok_or_else(|| malformed_upstream_response("response header terminator is missing"))?;
        let mut lines = header_text.split("\r\n");
        let status_line = lines
            .next()
            .ok_or_else(|| malformed_upstream_response("response status line is missing"))?;
        let mut status_parts = status_line.split_whitespace();
        let version = status_parts
            .next()
            .ok_or_else(|| malformed_upstream_response("response HTTP version is missing"))?;
        if !version.starts_with("HTTP/") {
            return Err(malformed_upstream_response(
                "response HTTP version is invalid",
            ));
        }
        let status_code = status_parts
            .next()
            .ok_or_else(|| malformed_upstream_response("response status code is missing"))?
            .parse::<u16>()
            .map_err(|_| malformed_upstream_response("response status code is invalid"))?;
        if !(100..=999).contains(&status_code) {
            return Err(malformed_upstream_response(
                "response status code is outside the valid range",
            ));
        }

        let mut content_length = None;
        let mut transfer_encoding_present = false;
        let mut transfer_encoding_chunked = false;
        let mut chunked_coding_seen = false;
        for line in lines {
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| malformed_upstream_response("response header is malformed"))?;
            if name.eq_ignore_ascii_case("Content-Length") {
                if content_length.is_some() {
                    return Err(malformed_upstream_response(
                        "duplicate response content length",
                    ));
                }
                content_length = Some(value.trim().parse::<usize>().map_err(|_| {
                    malformed_upstream_response("response content length is invalid")
                })?);
            }
            if name.eq_ignore_ascii_case("Transfer-Encoding") {
                transfer_encoding_present = true;
                for coding in value.split(',') {
                    let coding = coding.trim();
                    if coding.is_empty() {
                        return Err(malformed_upstream_response(
                            "response transfer encoding is empty",
                        ));
                    }
                    transfer_encoding_chunked = coding.eq_ignore_ascii_case("chunked");
                    chunked_coding_seen |= transfer_encoding_chunked;
                }
            }
        }
        if transfer_encoding_present && content_length.is_some() {
            return Err(malformed_upstream_response(
                "response transfer encoding conflicts with content length",
            ));
        }
        if chunked_coding_seen && !transfer_encoding_chunked {
            return Err(malformed_upstream_response(
                "chunked must be the final response transfer coding",
            ));
        }
        if (100..200).contains(&status_code) && status_code != 101 {
            return Ok((status_code, ResponseBodyFraming::Interim));
        }
        if body_expectation == ResponseBodyExpectation::HeadResponse
            || matches!(status_code, 101 | 204 | 304)
        {
            return Ok((status_code, ResponseBodyFraming::None));
        }
        let framing = if transfer_encoding_chunked {
            ResponseBodyFraming::Chunked
        } else if let Some(content_length) = content_length {
            ResponseBodyFraming::ContentLength(content_length)
        } else {
            ResponseBodyFraming::CloseDelimited
        };
        Ok((status_code, framing))
    }

    fn parse_chunk_size(line: &[u8]) -> Result<usize, AppError> {
        let line = std::str::from_utf8(line)
            .map_err(|_| malformed_upstream_response("chunk size is not UTF-8"))?;
        let size = line.split(';').next().unwrap_or("").trim();
        if size.is_empty() {
            return Err(malformed_upstream_response("chunk size is missing"));
        }
        usize::from_str_radix(size, 16)
            .map_err(|_| malformed_upstream_response("chunk size is invalid"))
    }

    fn validate_trailer_line(line: &[u8]) -> Result<(), AppError> {
        let line = std::str::from_utf8(line)
            .map_err(|_| malformed_upstream_response("chunk trailer is not UTF-8"))?;
        let (name, _) = line
            .split_once(':')
            .ok_or_else(|| malformed_upstream_response("chunk trailer is malformed"))?;
        if name.trim().is_empty() {
            return Err(malformed_upstream_response("chunk trailer name is empty"));
        }
        Ok(())
    }

    fn malformed_upstream_response(message: &'static str) -> AppError {
        AppError::new(ErrorCode::RuntimeUpstreamBadGateway, message)
    }

    fn parse_response_status_code(bytes: &[u8]) -> Option<u16> {
        let line_end = bytes.windows(2).position(|window| window == b"\r\n")?;
        let status_line = std::str::from_utf8(&bytes[..line_end]).ok()?;
        let mut parts = status_line.split_whitespace();
        let version = parts.next()?;
        if !version.starts_with("HTTP/") {
            return None;
        }
        parts.next()?.parse::<u16>().ok()
    }

    fn runtime_error_log_for_status(status_code: u16) -> Option<(ErrorCode, &'static str)> {
        match status_code {
            502 => Some((
                ErrorCode::RuntimeUpstreamBadGateway,
                "upstream returned bad gateway",
            )),
            504 => Some((ErrorCode::RuntimeUpstreamTimeout, "upstream timed out")),
            _ => None,
        }
    }

    fn http_error_response(status: u16, reason: &str) -> Vec<u8> {
        let body = format!("{status} {reason}\n");
        format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn upstream_failure_response(failure: UpstreamAttemptFailure) -> Vec<u8> {
        let (status_code, reason) = super::upstream_failure_response_spec(failure);
        http_error_response(status_code, reason)
    }

    fn passive_failure_reason(failure: UpstreamAttemptFailure) -> Option<PassiveFailureReason> {
        match failure {
            UpstreamAttemptFailure::Connect => Some(PassiveFailureReason::Connect),
            UpstreamAttemptFailure::ConnectTimeout => Some(PassiveFailureReason::ConnectTimeout),
            UpstreamAttemptFailure::TlsHandshake => Some(PassiveFailureReason::Connect),
            UpstreamAttemptFailure::TlsHandshakeTimeout => {
                Some(PassiveFailureReason::ConnectTimeout)
            }
            UpstreamAttemptFailure::Write => Some(PassiveFailureReason::Write),
            UpstreamAttemptFailure::Read => Some(PassiveFailureReason::Read),
            UpstreamAttemptFailure::ReadTimeout => Some(PassiveFailureReason::ReadTimeout),
            UpstreamAttemptFailure::ResetBeforeResponse => {
                Some(PassiveFailureReason::ResetBeforeResponse)
            }
            UpstreamAttemptFailure::ResetAfterResponse => None,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{PayloadClass, ResourcePressureState};
        use edge_domain::{AdminConfig, ConfigRevisionId, LogMode, RuntimeOptions};

        fn empty_snapshot() -> ConfigSnapshot {
            ConfigSnapshot {
                schema_version: 1,
                revision_id: ConfigRevisionId::new("resource-pressure-test"),
                admin: AdminConfig {
                    bind: "127.0.0.1:9443".to_string(),
                    auth_required: true,
                },
                listeners: vec![],
                routes: vec![],
                services: vec![],
                certificate_resolvers: vec![],
                log_mode: LogMode::Product,
                runtime: RuntimeOptions {
                    max_connections: 1_024,
                    max_inflight_payload_bytes: 128 * 1_024 * 1_024,
                    max_request_header_bytes: 16 * 1_024,
                    max_request_body_bytes: 1_024 * 1_024,
                    metrics: edge_domain::MetricsConfig::default(),
                },
            }
        }

        fn empty_runtime(resource_policy: RuntimeResourcePolicy) -> SnapshotMioRuntime {
            let snapshot = empty_snapshot();
            let upstream_selector = RuntimeUpstreamSelector::from_snapshot(&snapshot).unwrap();
            SnapshotMioRuntime::new(
                SnapshotMioRuntimeOptions {
                    limits: HttpLimits::default(),
                    resource_limits: ResourceLimits::default(),
                    resource_policy,
                    active_revision_id: snapshot.revision_id.clone(),
                    log_mode: snapshot.log_mode.clone(),
                    challenge_responder: Arc::new(NoopHttp01ChallengeResponder),
                    access_log_sender: None,
                    error_log_sender: None,
                    tls_failure_sender: None,
                    metric_publisher: None,
                    product_log_sender: None,
                    log_drop_counter: None,
                    resource_status_publisher: None,
                    passive_observation_dispatcher: None,
                    client_tls_registry: PreparedClientTlsRegistry::new(),
                    stall_upstream_connect: false,
                    backpressure_events: None,
                    resource_accounting_events: None,
                },
                upstream_selector,
            )
        }

        struct RecordingMetricPublisher {
            outcome: MetricPublishOutcome,
            events: Mutex<Vec<MetricEvent>>,
        }

        impl RecordingMetricPublisher {
            fn new(outcome: MetricPublishOutcome) -> Self {
                Self {
                    outcome,
                    events: Mutex::new(Vec::new()),
                }
            }

            fn events(&self) -> Vec<MetricEvent> {
                self.events.lock().unwrap().clone()
            }
        }

        impl MetricPublisher for RecordingMetricPublisher {
            fn try_publish(&self, metric: MetricEvent) -> MetricPublishOutcome {
                self.events.lock().unwrap().push(metric);
                self.outcome
            }
        }

        fn runtime_with_metric_publisher(
            resource_policy: RuntimeResourcePolicy,
            publisher: Arc<RecordingMetricPublisher>,
            drop_counter: Arc<AtomicU64>,
        ) -> SnapshotMioRuntime {
            let snapshot = empty_snapshot();
            let upstream_selector = RuntimeUpstreamSelector::from_snapshot(&snapshot).unwrap();
            SnapshotMioRuntime::new(
                SnapshotMioRuntimeOptions {
                    limits: HttpLimits::default(),
                    resource_limits: ResourceLimits::default(),
                    resource_policy,
                    active_revision_id: snapshot.revision_id.clone(),
                    log_mode: snapshot.log_mode.clone(),
                    challenge_responder: Arc::new(NoopHttp01ChallengeResponder),
                    access_log_sender: None,
                    error_log_sender: None,
                    tls_failure_sender: None,
                    metric_publisher: Some(publisher),
                    product_log_sender: None,
                    log_drop_counter: Some(drop_counter),
                    resource_status_publisher: None,
                    passive_observation_dispatcher: None,
                    client_tls_registry: PreparedClientTlsRegistry::new(),
                    stall_upstream_connect: false,
                    backpressure_events: None,
                    resource_accounting_events: None,
                },
                upstream_selector,
            )
        }

        fn runtime_with_resource_logs(
            resource_policy: RuntimeResourcePolicy,
            sender: mpsc::SyncSender<edge_ports::StructuredLogEvent>,
            drop_counter: Arc<AtomicU64>,
        ) -> SnapshotMioRuntime {
            let snapshot = empty_snapshot();
            let upstream_selector = RuntimeUpstreamSelector::from_snapshot(&snapshot).unwrap();
            SnapshotMioRuntime::new(
                SnapshotMioRuntimeOptions {
                    limits: HttpLimits::default(),
                    resource_limits: ResourceLimits::default(),
                    resource_policy,
                    active_revision_id: snapshot.revision_id.clone(),
                    log_mode: snapshot.log_mode.clone(),
                    challenge_responder: Arc::new(NoopHttp01ChallengeResponder),
                    access_log_sender: None,
                    error_log_sender: None,
                    tls_failure_sender: None,
                    metric_publisher: None,
                    product_log_sender: Some(sender),
                    log_drop_counter: Some(drop_counter),
                    resource_status_publisher: None,
                    passive_observation_dispatcher: None,
                    client_tls_registry: PreparedClientTlsRegistry::new(),
                    stall_upstream_connect: false,
                    backpressure_events: None,
                    resource_accounting_events: None,
                },
                upstream_selector,
            )
        }

        #[test]
        fn resource_logs_publish_policy_pressure_edges_and_sampled_rejection() {
            let policy = RuntimeResourcePolicy::default();
            let (sender, receiver) = mpsc::sync_channel(16);
            let mut runtime =
                runtime_with_resource_logs(policy, sender, Arc::new(AtomicU64::new(0)));
            let generation = runtime.payload_ledger.generation();
            let charge = runtime
                .payload_ledger
                .reserve(
                    51,
                    PayloadClass::ClientResponse,
                    policy.max_inflight_payload_bytes() * 80 / 100,
                    generation,
                )
                .unwrap();
            runtime.emit_resource_payload_metric_if_changed();
            runtime.emit_resource_admission_rejection(
                ConnectionAdmissionDecision::RejectedPayloadPressure,
            );
            runtime.emit_resource_admission_rejection(
                ConnectionAdmissionDecision::RejectedPayloadPressure,
            );
            runtime.payload_ledger.release(charge, generation).unwrap();
            runtime.emit_resource_payload_metric_if_changed();

            let events = receiver.try_iter().collect::<Vec<_>>();
            assert_eq!(
                events
                    .iter()
                    .map(|event| event.event.as_str())
                    .collect::<Vec<_>>(),
                vec![
                    "resource.policy.active",
                    "resource.pressure.entered",
                    "resource.admission.rejected",
                    "resource.pressure.recovered",
                ]
            );
        }

        #[test]
        fn saturated_resource_log_queue_does_not_change_ledger_progression() {
            let policy = RuntimeResourcePolicy::default();
            let (sender, _receiver) = mpsc::sync_channel(0);
            let drop_counter = Arc::new(AtomicU64::new(0));
            let mut runtime = runtime_with_resource_logs(policy, sender, Arc::clone(&drop_counter));
            let generation = runtime.payload_ledger.generation();
            let charge = runtime
                .payload_ledger
                .reserve(52, PayloadClass::ClientResponse, 4_096, generation)
                .unwrap();
            runtime.emit_resource_payload_metric_if_changed();
            runtime.payload_ledger.release(charge, generation).unwrap();
            runtime.emit_resource_payload_metric_if_changed();

            assert_eq!(runtime.payload_ledger.used_bytes(), 0);
            assert!(drop_counter.load(Ordering::Relaxed) >= 1);
        }

        fn accept_until_connection_count(
            runtime: &mut SnapshotMioRuntime,
            listener: &StdTcpListener,
            registry: &mio::Registry,
            expected: usize,
        ) {
            for _ in 0..100 {
                runtime
                    .accept_ready(listener, None, "listener", registry)
                    .unwrap();
                if runtime.connections.len() == expected {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(runtime.connections.len(), expected);
        }

        #[test]
        fn resource_metrics_publish_active_limit_and_charge_release_sequence() {
            let policy = RuntimeResourcePolicy::default();
            let publisher = Arc::new(RecordingMetricPublisher::new(
                MetricPublishOutcome::Accepted,
            ));
            let mut runtime = runtime_with_metric_publisher(
                policy,
                Arc::clone(&publisher),
                Arc::new(AtomicU64::new(0)),
            );
            let generation = runtime.payload_ledger.generation();

            let charge = runtime
                .payload_ledger
                .reserve(41, PayloadClass::ClientResponse, 4_096, generation)
                .unwrap();
            runtime.emit_resource_payload_metric_if_changed();
            runtime.payload_ledger.release(charge, generation).unwrap();
            runtime.emit_resource_payload_metric_if_changed();

            let events = publisher.events();
            assert!(events.iter().any(|metric| {
                metric.descriptor == edge_ports::MetricDescriptor::ResourcePayloadLimitBytes
                    && metric.operation
                        == edge_ports::MetricOperation::GaugeSet(
                            policy.max_inflight_payload_bytes() as i64,
                        )
            }));
            let used_values = events
                .iter()
                .filter_map(|metric| {
                    (metric.descriptor == edge_ports::MetricDescriptor::ResourcePayloadBytes)
                        .then_some(metric.operation)
                })
                .collect::<Vec<_>>();
            assert_eq!(
                used_values,
                vec![
                    edge_ports::MetricOperation::GaugeSet(0),
                    edge_ports::MetricOperation::GaugeSet(4_096),
                    edge_ports::MetricOperation::GaugeSet(0),
                ]
            );
        }

        #[test]
        fn full_and_stopped_metric_publishers_do_not_block_ledger_progression() {
            for outcome in [MetricPublishOutcome::Full, MetricPublishOutcome::Stopped] {
                let policy = RuntimeResourcePolicy::default();
                let publisher = Arc::new(RecordingMetricPublisher::new(outcome));
                let drop_counter = Arc::new(AtomicU64::new(0));
                let mut runtime = runtime_with_metric_publisher(
                    policy,
                    Arc::clone(&publisher),
                    Arc::clone(&drop_counter),
                );
                let generation = runtime.payload_ledger.generation();
                let charge = runtime
                    .payload_ledger
                    .reserve(42, PayloadClass::ClientResponse, 2_048, generation)
                    .unwrap();
                runtime.emit_resource_payload_metric_if_changed();
                runtime.payload_ledger.release(charge, generation).unwrap();
                runtime.emit_resource_payload_metric_if_changed();

                assert_eq!(runtime.payload_ledger.used_bytes(), 0);
                assert_eq!(publisher.events().len(), 4);
                assert_eq!(drop_counter.load(Ordering::Relaxed), 4);
            }
        }

        struct RecordingResourceStatusPublisher {
            outcome: edge_ports::RuntimeResourceStatusPublishOutcome,
            events: Mutex<Vec<edge_ports::RuntimeResourceStatusSnapshot>>,
        }

        impl edge_ports::RuntimeResourceStatusPublisher for RecordingResourceStatusPublisher {
            fn try_publish_resource_status(
                &self,
                status: edge_ports::RuntimeResourceStatusSnapshot,
            ) -> edge_ports::RuntimeResourceStatusPublishOutcome {
                self.events.lock().unwrap().push(status);
                self.outcome
            }
        }

        #[test]
        fn runtime_resource_status_publishes_startup_changes_and_deduplicates() {
            let policy = RuntimeResourcePolicy::default();
            let publisher = Arc::new(RecordingResourceStatusPublisher {
                outcome: edge_ports::RuntimeResourceStatusPublishOutcome::Accepted,
                events: Mutex::new(Vec::new()),
            });
            let mut runtime = empty_runtime(policy);
            runtime.install_resource_status_publisher(Some(publisher.clone()));
            runtime.emit_resource_payload_metric_if_changed();
            let generation = runtime.payload_ledger.generation();
            let charge = runtime
                .payload_ledger
                .reserve(61, PayloadClass::ClientResponse, 4_096, generation)
                .unwrap();
            runtime.emit_resource_payload_metric_if_changed();
            runtime.payload_ledger.release(charge, generation).unwrap();
            runtime.emit_resource_payload_metric_if_changed();

            let events = publisher.events.lock().unwrap().clone();
            assert_eq!(events.len(), 3);
            assert_eq!(events[0].used_payload_bytes, 0);
            assert_eq!(events[1].used_payload_bytes, 4_096);
            assert_eq!(events[2].used_payload_bytes, 0);
            assert_eq!(events[0].revision_id.as_str(), "resource-pressure-test");
        }

        #[test]
        fn runtime_resource_status_tracks_connection_count_and_active_revision() {
            let publisher = Arc::new(RecordingResourceStatusPublisher {
                outcome: edge_ports::RuntimeResourceStatusPublishOutcome::Accepted,
                events: Mutex::new(Vec::new()),
            });
            let mut runtime = empty_runtime(RuntimeResourcePolicy::default());
            runtime.install_resource_status_publisher(Some(publisher.clone()));
            let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let listen = listener.local_addr().unwrap();
            let poll = Poll::new().unwrap();
            let _client = StdTcpStream::connect(listen).unwrap();

            accept_until_connection_count(&mut runtime, &listener, poll.registry(), 1);
            assert!(runtime.remove_connection(0, false));
            let mut next = empty_snapshot();
            next.revision_id = ConfigRevisionId::new("resource-pressure-next");
            runtime.sync_active_revision(&next);

            let events = publisher.events.lock().unwrap().clone();
            assert_eq!(
                events
                    .iter()
                    .map(|status| status.active_connections)
                    .collect::<Vec<_>>(),
                vec![0, 1, 0, 0]
            );
            assert_eq!(
                events.last().unwrap().revision_id.as_str(),
                "resource-pressure-next"
            );
        }

        #[test]
        fn full_and_stopped_resource_status_publishers_do_not_change_ledger_progression() {
            for outcome in [
                edge_ports::RuntimeResourceStatusPublishOutcome::Full,
                edge_ports::RuntimeResourceStatusPublishOutcome::Stopped,
            ] {
                let publisher = Arc::new(RecordingResourceStatusPublisher {
                    outcome,
                    events: Mutex::new(Vec::new()),
                });
                let drop_counter = Arc::new(AtomicU64::new(0));
                let mut runtime = empty_runtime(RuntimeResourcePolicy::default());
                runtime.log_drop_counter = Some(Arc::clone(&drop_counter));
                runtime.install_resource_status_publisher(Some(publisher));
                let generation = runtime.payload_ledger.generation();
                let charge = runtime
                    .payload_ledger
                    .reserve(62, PayloadClass::ClientResponse, 2_048, generation)
                    .unwrap();
                runtime.emit_resource_payload_metric_if_changed();
                runtime.payload_ledger.release(charge, generation).unwrap();
                runtime.emit_resource_payload_metric_if_changed();

                assert_eq!(runtime.payload_ledger.used_bytes(), 0);
                assert_eq!(drop_counter.load(Ordering::Relaxed), 3);
            }
        }

        #[test]
        fn listener_rejects_new_connections_during_pressure_and_recovers() {
            let policy = RuntimeResourcePolicy::default();
            let limit = policy.max_inflight_payload_bytes();
            let publisher = Arc::new(RecordingMetricPublisher::new(
                MetricPublishOutcome::Accepted,
            ));
            let mut runtime = runtime_with_metric_publisher(
                policy,
                Arc::clone(&publisher),
                Arc::new(AtomicU64::new(0)),
            );
            let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let listen = listener.local_addr().unwrap();
            let poll = Poll::new().unwrap();

            let _existing_client = StdTcpStream::connect(listen).unwrap();
            accept_until_connection_count(&mut runtime, &listener, poll.registry(), 1);
            assert_eq!(runtime.connections.len(), 1);

            let generation = runtime.payload_ledger.generation();
            let pressure_charge = runtime
                .payload_ledger
                .reserve(
                    9_999,
                    PayloadClass::ClientResponse,
                    limit * 80 / 100,
                    generation,
                )
                .unwrap();
            assert_eq!(
                runtime.payload_ledger.pressure_state(),
                ResourcePressureState::Pressured
            );

            let _rejected_client = StdTcpStream::connect(listen).unwrap();
            for _ in 0..100 {
                runtime
                    .accept_ready(&listener, None, "listener", poll.registry())
                    .unwrap();
                if publisher.events().iter().any(|metric| {
                    metric.descriptor
                        == edge_ports::MetricDescriptor::ResourceAdmissionRejectionsTotal
                        && metric
                            .labels
                            .contains(&("resource_kind".to_string(), "payload".to_string()))
                        && metric
                            .labels
                            .contains(&("reason".to_string(), "payload_pressure".to_string()))
                }) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(runtime.connections.len(), 1);
            assert_eq!(runtime.next_connection_id, 1);
            assert!(publisher.events().iter().any(|metric| {
                metric.descriptor == edge_ports::MetricDescriptor::ResourceAdmissionRejectionsTotal
                    && metric
                        .labels
                        .contains(&("resource_kind".to_string(), "payload".to_string()))
                    && metric
                        .labels
                        .contains(&("reason".to_string(), "payload_pressure".to_string()))
            }));

            runtime
                .payload_ledger
                .release(pressure_charge, generation)
                .unwrap();
            let _recovered_client = StdTcpStream::connect(listen).unwrap();
            for _ in 0..100 {
                runtime
                    .accept_ready(&listener, None, "listener", poll.registry())
                    .unwrap();
                if runtime.connections.len() == 2 {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(runtime.connections.len(), 2);
            assert_eq!(runtime.next_connection_id, 2);
        }

        #[test]
        fn listener_publishes_connection_limit_and_failed_closed_rejection_reasons() {
            let policy =
                RuntimeResourcePolicy::try_new(1, edge_domain::MIN_MAX_INFLIGHT_PAYLOAD_BYTES)
                    .unwrap();
            let publisher = Arc::new(RecordingMetricPublisher::new(
                MetricPublishOutcome::Accepted,
            ));
            let mut runtime = runtime_with_metric_publisher(
                policy,
                Arc::clone(&publisher),
                Arc::new(AtomicU64::new(0)),
            );
            let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let listen = listener.local_addr().unwrap();
            let poll = Poll::new().unwrap();

            let _accepted = StdTcpStream::connect(listen).unwrap();
            accept_until_connection_count(&mut runtime, &listener, poll.registry(), 1);
            let _rejected = StdTcpStream::connect(listen).unwrap();
            for _ in 0..100 {
                runtime
                    .accept_ready(&listener, None, "listener", poll.registry())
                    .unwrap();
                if publisher.events().iter().any(|metric| {
                    metric
                        .labels
                        .contains(&("reason".to_string(), "connection_limit".to_string()))
                }) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            runtime.emit_resource_admission_rejection(
                ConnectionAdmissionDecision::RejectedFailedClosed,
            );

            let events = publisher.events();
            assert!(events.iter().any(|metric| {
                metric
                    .labels
                    .contains(&("reason".to_string(), "connection_limit".to_string()))
            }));
            assert!(events.iter().any(|metric| {
                metric
                    .labels
                    .contains(&("reason".to_string(), "failed_closed".to_string()))
            }));
        }

        #[test]
        fn completed_client_response_with_empty_buffers_enters_cleanup_terminal() {
            let mut runtime = empty_runtime(RuntimeResourcePolicy::default());
            let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let listen = listener.local_addr().unwrap();
            let poll = Poll::new().unwrap();
            let _client = StdTcpStream::connect(listen).unwrap();
            accept_until_connection_count(&mut runtime, &listener, poll.registry(), 1);

            let connection = runtime.connections.get_mut(&0).unwrap();
            connection.io.connection.state = ConnectionState::WritingClientResponse;
            assert!(connection.io.client_write_buffer().remaining().is_empty());
            assert!(connection.pending_client_output.is_empty());
            assert!(!connection.close_after_write);

            runtime.write_client(0, poll.registry()).unwrap();

            assert!(runtime.connections.get(&0).unwrap().close_after_write);
            runtime.cleanup_closed(poll.registry()).unwrap();
            assert!(runtime.connections.is_empty());
        }

        #[test]
        fn terminal_websocket_with_pending_client_output_releases_connection_and_charge() {
            let mut runtime = empty_runtime(RuntimeResourcePolicy::default());
            let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let listen = listener.local_addr().unwrap();
            let poll = Poll::new().unwrap();
            let _client = StdTcpStream::connect(listen).unwrap();
            accept_until_connection_count(&mut runtime, &listener, poll.registry(), 1);

            let connection = runtime.connections.get_mut(&0).unwrap();
            connection.io.connection.state = ConnectionState::TunnelingWebSocket;
            connection
                .client_transport
                .queue_http_bytes(b"pending tunnel output")
                .unwrap();
            connection
                .pending_client_output
                .pull_from(&mut connection.client_transport, usize::MAX);
            connection.close_after_write = true;
            connection
                .sync_transport_payload_charges(&mut runtime.payload_ledger, 0)
                .unwrap();
            assert!(!connection.pending_client_output.is_empty());
            assert!(runtime.payload_ledger.used_bytes() > 0);

            runtime.cleanup_closed(poll.registry()).unwrap();

            assert!(runtime.connections.is_empty());
            assert_eq!(runtime.payload_ledger.used_bytes(), 0);
        }

        #[test]
        fn closed_slow_response_client_releases_pending_output_and_charge() {
            let mut runtime = empty_runtime(RuntimeResourcePolicy::default());
            let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let listen = listener.local_addr().unwrap();
            let poll = Poll::new().unwrap();
            let client = StdTcpStream::connect(listen).unwrap();
            accept_until_connection_count(&mut runtime, &listener, poll.registry(), 1);

            let (connections, payload_ledger) =
                (&mut runtime.connections, &mut runtime.payload_ledger);
            let connection = connections.get_mut(&0).unwrap();
            connection.io.connection.state = ConnectionState::ReadingUpstreamResponse;
            connection
                .client_transport
                .queue_http_bytes(b"pending HTTP response output")
                .unwrap();
            connection
                .pending_client_output
                .pull_from(&mut connection.client_transport, usize::MAX);
            let response_bytes = connection.pending_client_output.remaining_len();
            let change = connection
                .resource_charges
                .prepare_client_response_bytes(payload_ledger, 0, response_bytes)
                .unwrap();
            connection
                .resource_charges
                .commit_client_response_bytes(payload_ledger, change)
                .unwrap();
            connection.pending_client_response = PendingClientResponseBatch::SocketDraining {
                plaintext_bytes: response_bytes,
            };
            assert!(!connection.pending_client_output.is_empty());
            assert!(runtime.payload_ledger.used_bytes() > 0);

            client.shutdown(std::net::Shutdown::Both).unwrap();
            drop(client);
            runtime
                .client_ready(0, poll.registry(), &empty_snapshot(), true, false, true)
                .unwrap();

            assert!(runtime.connections.is_empty());
            assert_eq!(runtime.payload_ledger.used_bytes(), 0);
        }

        #[test]
        fn response_upstream_is_deregistered_during_pressure_and_resumed_after_recovery() {
            let policy = RuntimeResourcePolicy::default();
            let limit = policy.max_inflight_payload_bytes();
            let mut runtime = empty_runtime(policy);
            let client_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
            client_listener.set_nonblocking(true).unwrap();
            let client_listen = client_listener.local_addr().unwrap();
            let poll = Poll::new().unwrap();
            let _client = StdTcpStream::connect(client_listen).unwrap();
            accept_until_connection_count(&mut runtime, &client_listener, poll.registry(), 1);

            let upstream_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
            let _upstream_peer =
                StdTcpStream::connect(upstream_listener.local_addr().unwrap()).unwrap();
            let (upstream, _) = upstream_listener.accept().unwrap();
            upstream.set_nonblocking(true).unwrap();
            let mut upstream = MioTcpStream::from_std(upstream);
            poll.registry()
                .register(&mut upstream, upstream_token(0), Interest::READABLE)
                .unwrap();

            let connection = runtime.connections.get_mut(&0).unwrap();
            connection.upstream = Some(upstream);
            connection.upstream_registered = true;
            connection.io.connection.state = ConnectionState::ReadingUpstreamResponse;
            connection.deadline = Some(Instant::now() + Duration::from_secs(30));
            let deadline = connection.deadline;

            let generation = runtime.payload_ledger.generation();
            let pressure_charge = runtime
                .payload_ledger
                .reserve(
                    10_001,
                    PayloadClass::ClientResponse,
                    limit * 80 / 100,
                    generation,
                )
                .unwrap();
            runtime
                .enforce_response_pressure_interests(poll.registry())
                .unwrap();
            let connection = runtime.connections.get(&0).unwrap();
            assert!(!connection.upstream_registered);
            assert_eq!(connection.deadline, deadline);
            assert_eq!(runtime.connections.len(), 1);

            runtime
                .payload_ledger
                .release(pressure_charge, generation)
                .unwrap();
            runtime
                .enforce_response_pressure_interests(poll.registry())
                .unwrap();
            let connection = runtime.connections.get(&0).unwrap();
            assert!(connection.upstream_registered);
            assert_eq!(connection.deadline, deadline);
            assert_eq!(runtime.connections.len(), 1);
        }

        #[test]
        fn websocket_pressure_preserves_writes_and_recovers_deregistered_sources() {
            let policy = RuntimeResourcePolicy::default();
            let limit = policy.max_inflight_payload_bytes();
            let mut runtime = empty_runtime(policy);
            let client_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
            client_listener.set_nonblocking(true).unwrap();
            let listen = client_listener.local_addr().unwrap();
            let poll = Poll::new().unwrap();
            let _client = StdTcpStream::connect(listen).unwrap();
            accept_until_connection_count(&mut runtime, &client_listener, poll.registry(), 1);

            let upstream_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
            let _upstream_peer =
                StdTcpStream::connect(upstream_listener.local_addr().unwrap()).unwrap();
            let (upstream, _) = upstream_listener.accept().unwrap();
            upstream.set_nonblocking(true).unwrap();
            let mut upstream = MioTcpStream::from_std(upstream);
            poll.registry()
                .register(&mut upstream, upstream_token(0), Interest::READABLE)
                .unwrap();

            let connection = runtime.connections.get_mut(&0).unwrap();
            connection.upstream = Some(upstream);
            connection.upstream_registered = true;
            connection.io.connection.state = ConnectionState::TunnelingWebSocket;
            connection.tunnel_client_to_upstream = WriteBuffer::new(b"request".to_vec());
            connection.tunnel_upstream_to_client = WriteBuffer::new(b"response".to_vec());

            let generation = runtime.payload_ledger.generation();
            let pressure_charge = runtime
                .payload_ledger
                .reserve(
                    10_002,
                    PayloadClass::ClientResponse,
                    limit * 80 / 100,
                    generation,
                )
                .unwrap();
            runtime
                .reregister_tunnel_interests(0, poll.registry())
                .unwrap();
            let connection = runtime.connections.get(&0).unwrap();
            assert!(connection.client_registered);
            assert!(connection.upstream_registered);

            let connection = runtime.connections.get_mut(&0).unwrap();
            connection.tunnel_client_to_upstream = WriteBuffer::default();
            connection.tunnel_upstream_to_client = WriteBuffer::default();
            runtime
                .reregister_tunnel_interests(0, poll.registry())
                .unwrap();
            let connection = runtime.connections.get(&0).unwrap();
            assert!(!connection.client_registered);
            assert!(!connection.upstream_registered);

            runtime
                .payload_ledger
                .release(pressure_charge, generation)
                .unwrap();
            runtime
                .reregister_tunnel_interests(0, poll.registry())
                .unwrap();
            let connection = runtime.connections.get(&0).unwrap();
            assert!(connection.client_registered);
            assert!(connection.upstream_registered);
        }

        #[test]
        fn incremental_framing_completes_fragmented_content_length_response() {
            let response = b"HTTP/1.1 201 Created\r\nContent-Length: 5\r\n\r\nhello";
            let mut framing = HttpResponseFraming::new(256, 64);

            for byte in response {
                framing.push(std::slice::from_ref(byte)).unwrap();
            }

            assert_eq!(framing.phase(), ResponseFramingPhase::Complete);
            assert_eq!(framing.status_code(), Some(201));
        }

        #[test]
        fn incremental_framing_completes_no_body_status_at_headers() {
            let mut framing = HttpResponseFraming::new(256, 64);
            let progress = framing
                .push(b"HTTP/1.1 204 No Content\r\nDate: now\r\n\r\nunconsumed")
                .unwrap();

            assert_eq!(framing.phase(), ResponseFramingPhase::Complete);
            assert_eq!(progress.consumed, progress.input_len - b"unconsumed".len());
            assert_eq!(framing.status_code(), Some(204));
        }

        #[test]
        fn incremental_framing_continues_after_interim_response() {
            let mut framing = HttpResponseFraming::new(256, 64);
            framing
                .push(
                    b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                )
                .unwrap();

            assert_eq!(framing.phase(), ResponseFramingPhase::Complete);
            assert_eq!(framing.status_code(), Some(200));
        }

        #[test]
        fn incremental_framing_completes_head_response_at_headers() {
            let mut framing = HttpResponseFraming::new_for_head_response(256, 64);
            framing
                .push(b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n")
                .unwrap();

            assert_eq!(framing.phase(), ResponseFramingPhase::Complete);
            assert_eq!(framing.status_code(), Some(200));
        }

        #[test]
        fn incremental_framing_requires_eof_for_close_delimited_response() {
            let mut framing = HttpResponseFraming::new(256, 64);
            framing
                .push(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody")
                .unwrap();

            assert_eq!(framing.phase(), ResponseFramingPhase::CloseDelimited);
            framing.finish_on_eof().unwrap();
            assert_eq!(framing.phase(), ResponseFramingPhase::Complete);
        }

        #[test]
        fn incremental_framing_rejects_premature_fixed_length_eof() {
            let mut framing = HttpResponseFraming::new(256, 64);
            framing
                .push(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhi")
                .unwrap();

            let error = framing.finish_on_eof().unwrap_err();

            assert_eq!(error.code, ErrorCode::RuntimeUpstreamBadGateway);
            assert_eq!(framing.phase(), ResponseFramingPhase::Failed);
        }

        #[test]
        fn incremental_framing_completes_byte_fragmented_chunked_response_with_trailer() {
            let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n4;name=value\r\nwiki\r\n5\r\npedia\r\n0\r\nExpires: now\r\n\r\n";
            let mut framing = HttpResponseFraming::new(512, 128);

            for byte in response {
                framing.push(std::slice::from_ref(byte)).unwrap();
            }

            assert_eq!(framing.phase(), ResponseFramingPhase::Complete);
            assert_eq!(framing.status_code(), Some(200));
        }

        #[test]
        fn incremental_framing_rejects_conflicting_or_duplicate_content_length() {
            for response in [
                b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n".as_slice(),
                b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n"
                    .as_slice(),
            ] {
                let mut framing = HttpResponseFraming::new(256, 64);
                let error = framing.push(response).unwrap_err();

                assert_eq!(error.code, ErrorCode::RuntimeUpstreamBadGateway);
                assert_eq!(framing.phase(), ResponseFramingPhase::Failed);
            }
        }

        #[test]
        fn incremental_framing_rejects_invalid_chunk_delimiter_and_size() {
            for response in [
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\n".as_slice(),
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\naX".as_slice(),
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n".as_slice(),
            ] {
                let mut framing = HttpResponseFraming::new(256, 64);
                let error = framing.push(response).unwrap_err();

                assert_eq!(error.code, ErrorCode::RuntimeUpstreamBadGateway);
                assert_eq!(framing.phase(), ResponseFramingPhase::Failed);
            }
        }

        #[test]
        fn incremental_framing_rejects_chunked_eof_before_terminal_trailer() {
            let mut framing = HttpResponseFraming::new(256, 64);
            framing
                .push(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwiki\r\n0\r\n")
                .unwrap();

            let error = framing.finish_on_eof().unwrap_err();

            assert_eq!(error.code, ErrorCode::RuntimeUpstreamBadGateway);
            assert_eq!(framing.phase(), ResponseFramingPhase::Failed);
        }

        #[test]
        fn incremental_framing_enforces_header_and_chunk_line_bounds() {
            let mut headers = HttpResponseFraming::new(16, 64);
            let header_error = headers
                .push(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .unwrap_err();
            assert_eq!(header_error.code, ErrorCode::ResourcePayloadCapacityReached);

            let mut chunk_line = HttpResponseFraming::new(128, 3);
            let line_error = chunk_line
                .push(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1234")
                .unwrap_err();
            assert_eq!(line_error.code, ErrorCode::ResourcePayloadCapacityReached);
        }

        #[test]
        fn incremental_framing_terminal_states_reject_more_input() {
            let mut complete = HttpResponseFraming::new(128, 64);
            complete
                .push(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            assert_eq!(
                complete.push(b"extra").unwrap_err().code,
                ErrorCode::RuntimeUpstreamBadGateway
            );

            let mut failed = HttpResponseFraming::new(128, 64);
            failed.push(b"not-http\r\n\r\n").unwrap_err();
            assert_eq!(
                failed.push(b"extra").unwrap_err().code,
                ErrorCode::RuntimeUpstreamBadGateway
            );
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsHandshakeState {
    WaitingForClientHello,
    SelectingCertificate,
    Handshaking,
    Established,
    Failed(AppError),
}

impl TlsHandshakeState {
    pub fn io_interest(&self) -> ConnectionInterest {
        match self {
            Self::WaitingForClientHello => ConnectionInterest {
                client_readable: true,
                ..ConnectionInterest::default()
            },
            Self::SelectingCertificate | Self::Established | Self::Failed(_) => {
                ConnectionInterest::default()
            }
            Self::Handshaking => ConnectionInterest {
                client_readable: true,
                client_writable: true,
                ..ConnectionInterest::default()
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateSelection {
    pub server_name: String,
    pub certificate_ref: CertificateRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsHandshakeEvent {
    ClientHello { server_name: Option<String> },
    HandshakeCompleted,
    TimeoutExpired,
    HandshakeFailed(AppError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsHandshakeOutcome {
    CertificateSelected(CertificateSelection),
    StateChanged,
}

pub fn select_certificate_for_sni(
    snapshot: &ConfigSnapshot,
    server_name: &str,
) -> Option<CertificateSelection> {
    let route = snapshot.select_route(server_name, "/")?;
    let certificate_ref = route.certificate_ref.clone()?;
    Some(CertificateSelection {
        server_name: server_name.to_ascii_lowercase(),
        certificate_ref,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsHandshakeMachine {
    state: TlsHandshakeState,
    server_name: Option<String>,
    certificate_ref: Option<CertificateRef>,
}

impl TlsHandshakeMachine {
    pub fn new() -> Self {
        Self {
            state: TlsHandshakeState::WaitingForClientHello,
            server_name: None,
            certificate_ref: None,
        }
    }

    pub fn state(&self) -> &TlsHandshakeState {
        &self.state
    }

    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    pub fn certificate_ref(&self) -> Option<&CertificateRef> {
        self.certificate_ref.as_ref()
    }

    pub fn io_interest(&self) -> ConnectionInterest {
        self.state.io_interest()
    }

    pub fn handle_event(
        &mut self,
        snapshot: &ConfigSnapshot,
        event: TlsHandshakeEvent,
    ) -> Result<TlsHandshakeOutcome, AppError> {
        match event {
            TlsHandshakeEvent::ClientHello { server_name } => self
                .receive_client_hello(snapshot, server_name.as_deref())
                .map(TlsHandshakeOutcome::CertificateSelected),
            TlsHandshakeEvent::HandshakeCompleted => {
                self.mark_established()?;
                Ok(TlsHandshakeOutcome::StateChanged)
            }
            TlsHandshakeEvent::TimeoutExpired => self
                .mark_timeout()
                .map(|_| TlsHandshakeOutcome::StateChanged),
            TlsHandshakeEvent::HandshakeFailed(error) => Err(self.fail(error)),
        }
    }

    pub fn receive_client_hello(
        &mut self,
        snapshot: &ConfigSnapshot,
        server_name: Option<&str>,
    ) -> Result<CertificateSelection, AppError> {
        if self.state != TlsHandshakeState::WaitingForClientHello {
            return Err(self.fail(AppError::new(
                ErrorCode::InternalBug,
                "TLS client hello received in invalid state",
            )));
        }

        self.state = TlsHandshakeState::SelectingCertificate;
        let Some(server_name) = server_name.map(str::trim).filter(|value| !value.is_empty()) else {
            return Err(self.fail(AppError::new(
                ErrorCode::CertificateNotFound,
                "TLS client hello did not include SNI",
            )));
        };
        let Some(selection) = select_certificate_for_sni(snapshot, server_name) else {
            return Err(self.fail(AppError::new(
                ErrorCode::CertificateNotFound,
                format!("no certificate matches SNI: {server_name}"),
            )));
        };

        self.server_name = Some(selection.server_name.clone());
        self.certificate_ref = Some(selection.certificate_ref.clone());
        self.state = TlsHandshakeState::Handshaking;
        Ok(selection)
    }

    pub fn mark_established(&mut self) -> Result<(), AppError> {
        if self.state != TlsHandshakeState::Handshaking {
            return Err(self.fail(AppError::new(
                ErrorCode::InternalBug,
                "TLS established in invalid state",
            )));
        }
        self.state = TlsHandshakeState::Established;
        Ok(())
    }

    pub fn mark_timeout(&mut self) -> Result<(), AppError> {
        Err(self.fail(AppError::new(
            ErrorCode::TlsHandshakeTimeout,
            "TLS handshake timed out",
        )))
    }

    fn fail(&mut self, error: AppError) -> AppError {
        self.state = TlsHandshakeState::Failed(error.clone());
        error
    }
}

impl Default for TlsHandshakeMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsTransportState {
    Handshaking,
    Established,
    Closing,
    PeerClosed,
    Failed(AppError),
}

pub struct TlsTransport {
    state: TlsTransportState,
    session: Box<dyn TlsSession + Send>,
}

impl TlsTransport {
    pub fn new(session: Box<dyn TlsSession + Send>) -> Self {
        let state = Self::state_from_progress(session.progress());
        Self { state, session }
    }

    pub fn state(&self) -> &TlsTransportState {
        &self.state
    }

    pub fn sni_hostname(&self) -> Option<&str> {
        self.session.sni_hostname()
    }

    pub fn pending_tls_bytes(&self) -> TlsPendingBytes {
        self.session.pending_bytes()
    }

    pub fn io_interest(&self) -> ConnectionInterest {
        if self.is_terminal() {
            return ConnectionInterest::default();
        }
        let interest = self.session.interest();
        ConnectionInterest {
            client_readable: interest.wants_read,
            client_writable: interest.wants_write,
            ..ConnectionInterest::default()
        }
    }

    pub fn receive_encrypted(&mut self, bytes: &[u8]) -> Result<usize, AppError> {
        if self.is_terminal() {
            return Ok(0);
        }
        let consumed = self.session.receive_encrypted(bytes).inspect_err(|error| {
            self.state = TlsTransportState::Failed(error.clone());
        })?;
        self.sync_state();
        Ok(consumed)
    }

    pub fn take_decrypted(&mut self, max_bytes: usize) -> Vec<u8> {
        if self.is_terminal() {
            return Vec::new();
        }
        self.session.take_decrypted(max_bytes)
    }

    pub fn receive_plaintext(&mut self, bytes: &[u8]) -> Result<usize, AppError> {
        if self.is_terminal() {
            return Ok(0);
        }
        let consumed = self.session.receive_plaintext(bytes).inspect_err(|error| {
            self.state = TlsTransportState::Failed(error.clone());
        })?;
        self.sync_state();
        Ok(consumed)
    }

    pub fn take_encrypted(&mut self, max_bytes: usize) -> Vec<u8> {
        let drained = self.session.take_encrypted(max_bytes);
        self.sync_state();
        drained
    }

    pub fn request_close_notify(&mut self) -> Result<(), AppError> {
        if self.is_terminal() {
            return Ok(());
        }
        self.session.request_close_notify().inspect_err(|error| {
            self.state = TlsTransportState::Failed(error.clone());
        })?;
        self.sync_state();
        Ok(())
    }

    pub fn mark_handshake_timeout(&mut self) -> Result<(), AppError> {
        if self.state != TlsTransportState::Handshaking {
            return Ok(());
        }
        let error = AppError::new(
            ErrorCode::TlsHandshakeTimeout,
            "TLS transport handshake timed out",
        );
        self.state = TlsTransportState::Failed(error.clone());
        Err(error)
    }

    fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            TlsTransportState::PeerClosed | TlsTransportState::Failed(_)
        )
    }

    fn sync_state(&mut self) {
        self.state = Self::state_from_progress(self.session.progress());
    }

    fn state_from_progress(progress: TlsSessionProgress) -> TlsTransportState {
        match progress {
            TlsSessionProgress::Handshaking => TlsTransportState::Handshaking,
            TlsSessionProgress::Established => TlsTransportState::Established,
            TlsSessionProgress::Closing => TlsTransportState::Closing,
            TlsSessionProgress::PeerClosed => TlsTransportState::PeerClosed,
            TlsSessionProgress::Failed { code } => TlsTransportState::Failed(AppError::new(
                code,
                "TLS session reported a terminal failure",
            )),
        }
    }
}

#[derive(Debug, Default)]
pub struct PlaintextClientTransport {
    socket_output: Vec<u8>,
}

pub enum ClientTransport {
    Plaintext(PlaintextClientTransport),
    Tls(TlsTransport),
}

impl ClientTransport {
    pub fn plaintext() -> Self {
        Self::Plaintext(PlaintextClientTransport::default())
    }

    pub fn tls(session: Box<dyn TlsSession + Send>) -> Self {
        Self::Tls(TlsTransport::new(session))
    }

    pub fn forwarded_scheme(&self) -> &'static str {
        match self {
            Self::Plaintext(_) => "http",
            Self::Tls(_) => "https",
        }
    }

    pub fn pending_tls_bytes(&self) -> TlsPendingBytes {
        match self {
            Self::Plaintext(_) => TlsPendingBytes::default(),
            Self::Tls(transport) => transport.pending_tls_bytes(),
        }
    }

    pub const fn is_tls(&self) -> bool {
        matches!(self, Self::Tls(_))
    }

    pub fn request_close_notify(&mut self) -> Result<bool, AppError> {
        match self {
            Self::Plaintext(_) => Ok(false),
            Self::Tls(transport) => {
                transport.request_close_notify()?;
                Ok(true)
            }
        }
    }

    pub fn mark_handshake_timeout_if_pending(&mut self) -> Option<AppError> {
        match self {
            Self::Tls(transport) if transport.state() == &TlsTransportState::Handshaking => {
                transport.mark_handshake_timeout().err()
            }
            Self::Plaintext(_) | Self::Tls(_) => None,
        }
    }

    pub fn receive_socket_bytes(&mut self, bytes: &[u8]) -> Result<Vec<u8>, AppError> {
        match self {
            Self::Plaintext(_) => Ok(bytes.to_vec()),
            Self::Tls(transport) => {
                transport.receive_encrypted(bytes)?;
                Ok(transport.take_decrypted(usize::MAX))
            }
        }
    }

    pub fn queue_http_bytes(&mut self, bytes: &[u8]) -> Result<usize, AppError> {
        match self {
            Self::Plaintext(transport) => {
                transport.socket_output.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            Self::Tls(transport) => transport.receive_plaintext(bytes),
        }
    }

    pub fn take_socket_bytes(&mut self, max_bytes: usize) -> Vec<u8> {
        match self {
            Self::Plaintext(transport) => {
                let drain = transport.socket_output.len().min(max_bytes);
                transport.socket_output.drain(..drain).collect()
            }
            Self::Tls(transport) => transport.take_encrypted(max_bytes),
        }
    }

    pub fn merge_interest(&self, base: ConnectionInterest) -> ConnectionInterest {
        let Self::Tls(transport) = self else {
            return base;
        };
        let tls = transport.io_interest();
        let (client_readable, client_writable) = match transport.state() {
            TlsTransportState::Handshaking | TlsTransportState::Closing => {
                (tls.client_readable, tls.client_writable)
            }
            TlsTransportState::Established => (
                base.client_readable || tls.client_readable,
                base.client_writable || tls.client_writable,
            ),
            TlsTransportState::PeerClosed | TlsTransportState::Failed(_) => (false, false),
        };
        ConnectionInterest {
            client_readable,
            client_writable,
            upstream_readable: base.upstream_readable,
            upstream_writable: base.upstream_writable,
        }
    }
}

#[derive(Clone, Default)]
pub struct PreparedClientTlsRegistry {
    factories: BTreeMap<
        (ServiceId, UpstreamId),
        std::sync::Arc<dyn ClientTlsSessionFactory + Send + Sync>,
    >,
}

impl PreparedClientTlsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert<F>(
        &mut self,
        service_id: ServiceId,
        upstream_id: UpstreamId,
        factory: F,
    ) -> Result<(), AppError>
    where
        F: ClientTlsSessionFactory + Send + Sync + 'static,
    {
        self.insert_shared(service_id, upstream_id, std::sync::Arc::new(factory))
    }

    pub fn insert_shared(
        &mut self,
        service_id: ServiceId,
        upstream_id: UpstreamId,
        factory: std::sync::Arc<dyn ClientTlsSessionFactory + Send + Sync>,
    ) -> Result<(), AppError> {
        let key = (service_id, upstream_id);
        if self.factories.contains_key(&key) {
            return Err(upstream_tls_registry_error());
        }
        self.factories.insert(key, factory);
        Ok(())
    }

    pub fn create_session(
        &self,
        service_id: &ServiceId,
        upstream_id: &UpstreamId,
        server_name: &TlsServerName,
    ) -> Result<Box<dyn TlsSession + Send>, AppError> {
        self.factories
            .get(&(service_id.clone(), upstream_id.clone()))
            .ok_or_else(upstream_tls_registry_error)?
            .create_client_session(server_name)
    }

    pub fn contains(&self, service_id: &ServiceId, upstream_id: &UpstreamId) -> bool {
        self.factories
            .contains_key(&(service_id.clone(), upstream_id.clone()))
    }

    pub fn len(&self) -> usize {
        self.factories.len()
    }

    pub fn is_empty(&self) -> bool {
        self.factories.is_empty()
    }

    fn validate_for_snapshot(&self, snapshot: &ConfigSnapshot) -> Result<(), AppError> {
        let mut expected = 0_usize;
        for service in &snapshot.services {
            for upstream in &service.upstreams {
                if matches!(upstream.tls, UpstreamTlsPolicy::ServerAuthenticated { .. }) {
                    expected = expected.saturating_add(1);
                    if !self.contains(&service.id, &upstream.id) {
                        return Err(upstream_tls_registry_error());
                    }
                }
            }
        }
        if self.len() != expected {
            return Err(upstream_tls_registry_error());
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct PreparedServerTlsRegistry {
    factories: BTreeMap<SocketAddr, std::sync::Arc<dyn ServerTlsSessionFactory + Send + Sync>>,
}

impl PreparedServerTlsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert<F>(&mut self, bind: SocketAddr, factory: F) -> Result<(), AppError>
    where
        F: ServerTlsSessionFactory + Send + Sync + 'static,
    {
        if self.factories.contains_key(&bind) {
            return Err(runtime_generation_error());
        }
        self.factories.insert(bind, std::sync::Arc::new(factory));
        Ok(())
    }

    fn factory_for(
        &self,
        bind: &SocketAddr,
    ) -> Option<std::sync::Arc<dyn ServerTlsSessionFactory + Send + Sync>> {
        self.factories.get(bind).cloned()
    }

    pub fn len(&self) -> usize {
        self.factories.len()
    }

    pub fn is_empty(&self) -> bool {
        self.factories.is_empty()
    }
}

fn upstream_tls_registry_error() -> AppError {
    AppError::new(
        ErrorCode::UpstreamTlsProfileInvalid,
        "prepared upstream TLS profile is invalid",
    )
}

fn runtime_generation_error() -> AppError {
    AppError::new(
        ErrorCode::RuntimeCommandRejected,
        "prepared TLS runtime generation does not match the active snapshot",
    )
}

#[derive(Debug, Default)]
pub struct PlaintextUpstreamTransport {
    socket_output: Vec<u8>,
}

pub enum UpstreamTransport {
    Plaintext(PlaintextUpstreamTransport),
    Tls(TlsTransport),
}

impl UpstreamTransport {
    pub fn plaintext() -> Self {
        Self::Plaintext(PlaintextUpstreamTransport::default())
    }

    pub fn tls(session: Box<dyn TlsSession + Send>) -> Self {
        Self::Tls(TlsTransport::new(session))
    }

    pub fn tls_state(&self) -> Option<&TlsTransportState> {
        match self {
            Self::Plaintext(_) => None,
            Self::Tls(transport) => Some(transport.state()),
        }
    }

    pub fn pending_tls_bytes(&self) -> TlsPendingBytes {
        match self {
            Self::Plaintext(_) => TlsPendingBytes::default(),
            Self::Tls(transport) => transport.pending_tls_bytes(),
        }
    }

    pub const fn is_tls(&self) -> bool {
        matches!(self, Self::Tls(_))
    }

    pub fn receive_socket_bytes(&mut self, bytes: &[u8]) -> Result<Vec<u8>, AppError> {
        match self {
            Self::Plaintext(_) => Ok(bytes.to_vec()),
            Self::Tls(transport) => {
                transport.receive_encrypted(bytes)?;
                Ok(transport.take_decrypted(usize::MAX))
            }
        }
    }

    pub fn queue_http_bytes(&mut self, bytes: &[u8]) -> Result<usize, AppError> {
        match self {
            Self::Plaintext(transport) => {
                transport.socket_output.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            Self::Tls(transport) if transport.state() == &TlsTransportState::Established => {
                transport.receive_plaintext(bytes)
            }
            Self::Tls(_) => Ok(0),
        }
    }

    pub fn queue_tunnel_plaintext(
        &mut self,
        plaintext: &[u8],
        output: &mut WriteBuffer,
    ) -> Result<usize, AppError> {
        if !output.is_complete() {
            return Ok(0);
        }
        match self {
            Self::Plaintext(_) => {
                output.try_replace_if_complete(plaintext)?;
                Ok(plaintext.len())
            }
            Self::Tls(transport) if transport.state() == &TlsTransportState::Established => {
                let consumed = transport.receive_plaintext(plaintext)?;
                let socket_bytes = transport.take_encrypted(usize::MAX);
                output.try_replace_if_complete(&socket_bytes)?;
                Ok(consumed)
            }
            Self::Tls(_) => Ok(0),
        }
    }

    pub fn take_socket_bytes(&mut self, max_bytes: usize) -> Vec<u8> {
        match self {
            Self::Plaintext(transport) => {
                let drain = transport.socket_output.len().min(max_bytes);
                transport.socket_output.drain(..drain).collect()
            }
            Self::Tls(transport) => transport.take_encrypted(max_bytes),
        }
    }

    pub fn merge_interest(&self, base: ConnectionInterest) -> ConnectionInterest {
        let Self::Tls(transport) = self else {
            return base;
        };
        let tls = transport.io_interest();
        let (upstream_readable, upstream_writable) = match transport.state() {
            TlsTransportState::Handshaking | TlsTransportState::Closing => {
                (tls.client_readable, tls.client_writable)
            }
            TlsTransportState::Established => (
                base.upstream_readable || tls.client_readable,
                base.upstream_writable || tls.client_writable,
            ),
            TlsTransportState::PeerClosed | TlsTransportState::Failed(_) => (false, false),
        };
        ConnectionInterest {
            client_readable: base.client_readable,
            client_writable: base.client_writable,
            upstream_readable,
            upstream_writable,
        }
    }

    pub fn mark_handshake_timeout_if_pending(&mut self) -> Option<AppError> {
        match self {
            Self::Tls(transport) if transport.state() == &TlsTransportState::Handshaking => {
                transport.mark_handshake_timeout().err()
            }
            Self::Plaintext(_) | Self::Tls(_) => None,
        }
    }
}

#[derive(Debug, Default)]
pub struct PendingSocketOutput {
    buffer: WriteBuffer,
}

impl PendingSocketOutput {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pull_from(&mut self, transport: &mut ClientTransport, max_bytes: usize) -> usize {
        if !self.is_empty() {
            return 0;
        }
        let bytes = transport.take_socket_bytes(max_bytes);
        let pulled = bytes.len();
        self.buffer = WriteBuffer::new(bytes);
        pulled
    }

    pub fn pull_tunnel_plaintext(
        &mut self,
        transport: &mut ClientTransport,
        plaintext: &[u8],
    ) -> Result<usize, AppError> {
        if !self.is_empty() {
            return Ok(0);
        }
        match transport {
            ClientTransport::Plaintext(_) => {
                self.buffer.try_replace_if_complete(plaintext)?;
                Ok(plaintext.len())
            }
            ClientTransport::Tls(transport) => {
                let consumed = transport.receive_plaintext(plaintext)?;
                let socket_bytes = transport.take_encrypted(usize::MAX);
                self.buffer.try_replace_if_complete(&socket_bytes)?;
                Ok(consumed)
            }
        }
    }

    pub fn remaining(&self) -> &[u8] {
        self.buffer.remaining()
    }

    pub fn remaining_len(&self) -> usize {
        self.buffer.remaining_len()
    }

    pub fn advance(&mut self, byte_count: usize) -> usize {
        let advanced = self.buffer.advance(byte_count);
        self.buffer.clear_if_complete();
        advanced
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_complete()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionToken(Token);

impl ConnectionToken {
    pub fn new(value: usize) -> Self {
        Self(Token(value))
    }

    pub fn as_usize(&self) -> usize {
        self.0 .0
    }
}

#[derive(Debug, Default)]
pub struct TokenAllocator {
    next: usize,
    recycled: Vec<usize>,
}

impl TokenAllocator {
    pub fn allocate(&mut self) -> ConnectionToken {
        if let Some(value) = self.recycled.pop() {
            ConnectionToken::new(value)
        } else {
            let token = ConnectionToken::new(self.next);
            self.next += 1;
            token
        }
    }

    pub fn release(&mut self, token: ConnectionToken) {
        self.recycled.push(token.as_usize());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Accepted,
    ReadingClientRequest,
    SelectingRoute,
    ConnectingUpstream,
    HandshakingUpstreamTls,
    WritingUpstreamRequest,
    ReadingUpstreamResponse,
    WritingClientResponse,
    TunnelingWebSocket,
    Draining,
    Closed,
    Failed,
}

impl ConnectionState {
    pub fn can_transition_to(&self, next: &Self) -> bool {
        use ConnectionState::*;
        matches!(
            (self, next),
            (Accepted, ReadingClientRequest)
                | (Accepted, WritingClientResponse)
                | (ReadingClientRequest, SelectingRoute)
                | (ReadingClientRequest, WritingClientResponse)
                | (SelectingRoute, ConnectingUpstream)
                | (SelectingRoute, WritingClientResponse)
                | (ConnectingUpstream, WritingUpstreamRequest)
                | (ConnectingUpstream, HandshakingUpstreamTls)
                | (HandshakingUpstreamTls, WritingUpstreamRequest)
                | (HandshakingUpstreamTls, WritingClientResponse)
                | (ConnectingUpstream, WritingClientResponse)
                | (WritingUpstreamRequest, ReadingUpstreamResponse)
                | (WritingUpstreamRequest, WritingClientResponse)
                | (ReadingUpstreamResponse, WritingClientResponse)
                | (ReadingUpstreamResponse, TunnelingWebSocket)
                | (WritingClientResponse, Draining)
                | (TunnelingWebSocket, Draining)
                | (_, Closed)
                | (_, Failed)
        )
    }

    pub fn io_interest(&self) -> ConnectionInterest {
        match self {
            Self::Accepted | Self::ReadingClientRequest => ConnectionInterest {
                client_readable: true,
                ..ConnectionInterest::default()
            },
            Self::SelectingRoute | Self::Draining | Self::Closed | Self::Failed => {
                ConnectionInterest::default()
            }
            Self::ConnectingUpstream | Self::WritingUpstreamRequest => ConnectionInterest {
                upstream_writable: true,
                ..ConnectionInterest::default()
            },
            Self::HandshakingUpstreamTls => ConnectionInterest {
                upstream_readable: true,
                upstream_writable: true,
                ..ConnectionInterest::default()
            },
            Self::ReadingUpstreamResponse => ConnectionInterest {
                upstream_readable: true,
                ..ConnectionInterest::default()
            },
            Self::WritingClientResponse => ConnectionInterest {
                client_writable: true,
                ..ConnectionInterest::default()
            },
            Self::TunnelingWebSocket => ConnectionInterest {
                client_readable: true,
                upstream_readable: true,
                ..ConnectionInterest::default()
            },
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConnectionInterest {
    pub client_readable: bool,
    pub client_writable: bool,
    pub upstream_readable: bool,
    pub upstream_writable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteSelectionTarget {
    Proxy,
    ImmediateResponse,
    WebSocketTunnel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionEvent {
    ClientReadable,
    ClientWritable,
    UpstreamConnectReady,
    UpstreamTlsHandshakeStarted,
    UpstreamTlsEstablished,
    UpstreamReadable,
    UpstreamWritable,
    RequestParsed,
    RouteSelected(RouteSelectionTarget),
    TimeoutExpired,
    ClientClosed,
    UpstreamClosed,
    CommandShutdown,
    IoError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionTimeoutKind {
    ClientIdle,
    UpstreamConnect,
    UpstreamTlsHandshake,
    UpstreamRead,
    ClientWrite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionTimeoutDecision {
    pub kind: ConnectionTimeoutKind,
    pub status_code: Option<u16>,
    pub reason: &'static str,
    pub next_state: ConnectionState,
}

pub fn timeout_decision_for_state(state: &ConnectionState) -> Option<ConnectionTimeoutDecision> {
    match state {
        ConnectionState::Accepted | ConnectionState::ReadingClientRequest => {
            Some(ConnectionTimeoutDecision {
                kind: ConnectionTimeoutKind::ClientIdle,
                status_code: Some(408),
                reason: "Request Timeout",
                next_state: ConnectionState::WritingClientResponse,
            })
        }
        ConnectionState::ConnectingUpstream => Some(ConnectionTimeoutDecision {
            kind: ConnectionTimeoutKind::UpstreamConnect,
            status_code: Some(504),
            reason: "Gateway Timeout",
            next_state: ConnectionState::WritingClientResponse,
        }),
        ConnectionState::HandshakingUpstreamTls => Some(ConnectionTimeoutDecision {
            kind: ConnectionTimeoutKind::UpstreamTlsHandshake,
            status_code: Some(504),
            reason: "Gateway Timeout",
            next_state: ConnectionState::WritingClientResponse,
        }),
        ConnectionState::WritingUpstreamRequest | ConnectionState::ReadingUpstreamResponse => {
            Some(ConnectionTimeoutDecision {
                kind: ConnectionTimeoutKind::UpstreamRead,
                status_code: Some(504),
                reason: "Gateway Timeout",
                next_state: ConnectionState::WritingClientResponse,
            })
        }
        ConnectionState::WritingClientResponse => Some(ConnectionTimeoutDecision {
            kind: ConnectionTimeoutKind::ClientWrite,
            status_code: None,
            reason: "Client Write Timeout",
            next_state: ConnectionState::Failed,
        }),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum UpstreamAttemptPhase {
    #[default]
    NotStarted,
    Writing,
    AwaitingResponse,
    ResponseStarted,
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamAttemptFailure {
    Connect,
    ConnectTimeout,
    TlsHandshake,
    TlsHandshakeTimeout,
    Write,
    Read,
    ReadTimeout,
    ResetBeforeResponse,
    ResetAfterResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamAttemptTerminal {
    Succeeded,
    Failed(UpstreamAttemptFailure),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UpstreamAttemptProgress {
    phase: UpstreamAttemptPhase,
    request_bytes_written: u64,
    response_started: bool,
    terminal: Option<UpstreamAttemptTerminal>,
}

impl UpstreamAttemptProgress {
    pub fn begin(&mut self) -> Result<(), AppError> {
        self.require_phase(UpstreamAttemptPhase::NotStarted)?;
        self.phase = UpstreamAttemptPhase::Writing;
        Ok(())
    }

    pub fn record_request_write(&mut self, byte_count: u64) -> Result<(), AppError> {
        self.require_phase(UpstreamAttemptPhase::Writing)?;
        self.request_bytes_written = self.request_bytes_written.saturating_add(byte_count);
        Ok(())
    }

    pub fn request_write_completed(&mut self) -> Result<(), AppError> {
        self.require_phase(UpstreamAttemptPhase::Writing)?;
        self.phase = UpstreamAttemptPhase::AwaitingResponse;
        Ok(())
    }

    pub fn record_response_bytes(&mut self, byte_count: usize) -> Result<(), AppError> {
        if !matches!(
            self.phase,
            UpstreamAttemptPhase::AwaitingResponse | UpstreamAttemptPhase::ResponseStarted
        ) {
            return Err(invalid_upstream_attempt_transition());
        }
        if byte_count > 0 {
            self.response_started = true;
            self.phase = UpstreamAttemptPhase::ResponseStarted;
        }
        Ok(())
    }

    pub fn succeed(&mut self) -> Result<(), AppError> {
        if !matches!(
            self.phase,
            UpstreamAttemptPhase::AwaitingResponse | UpstreamAttemptPhase::ResponseStarted
        ) {
            return Err(invalid_upstream_attempt_transition());
        }
        self.complete(UpstreamAttemptTerminal::Succeeded)
    }

    pub fn fail(&mut self, failure: UpstreamAttemptFailure) -> Result<(), AppError> {
        if self.phase == UpstreamAttemptPhase::Terminal {
            return Err(invalid_upstream_attempt_transition());
        }
        self.complete(UpstreamAttemptTerminal::Failed(failure))
    }

    pub fn phase(&self) -> UpstreamAttemptPhase {
        self.phase
    }

    pub fn request_bytes_written(&self) -> u64 {
        self.request_bytes_written
    }

    pub fn response_started(&self) -> bool {
        self.response_started
    }

    pub fn terminal(&self) -> Option<UpstreamAttemptTerminal> {
        self.terminal
    }

    fn require_phase(&self, expected: UpstreamAttemptPhase) -> Result<(), AppError> {
        if self.phase != expected {
            return Err(invalid_upstream_attempt_transition());
        }
        Ok(())
    }

    fn complete(&mut self, terminal: UpstreamAttemptTerminal) -> Result<(), AppError> {
        if self.terminal.is_some() {
            return Err(invalid_upstream_attempt_transition());
        }
        self.terminal = Some(terminal);
        self.phase = UpstreamAttemptPhase::Terminal;
        Ok(())
    }
}

fn invalid_upstream_attempt_transition() -> AppError {
    AppError::new(
        ErrorCode::RuntimeCommandRejected,
        "invalid upstream attempt transition",
    )
}

fn upstream_failure_response_spec(failure: UpstreamAttemptFailure) -> (u16, &'static str) {
    match failure {
        UpstreamAttemptFailure::Connect
        | UpstreamAttemptFailure::TlsHandshake
        | UpstreamAttemptFailure::Write
        | UpstreamAttemptFailure::Read
        | UpstreamAttemptFailure::ResetBeforeResponse
        | UpstreamAttemptFailure::ResetAfterResponse => (502, "Bad Gateway"),
        UpstreamAttemptFailure::ConnectTimeout
        | UpstreamAttemptFailure::TlsHandshakeTimeout
        | UpstreamAttemptFailure::ReadTimeout => (504, "Gateway Timeout"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    pub token: ConnectionToken,
    pub state: ConnectionState,
}

impl Connection {
    pub fn transition_to(&mut self, next: ConnectionState) -> Result<(), AppError> {
        if !self.state.can_transition_to(&next) {
            return Err(AppError::new(
                ErrorCode::RuntimeCommandRejected,
                "invalid connection state transition",
            ));
        }
        self.state = next;
        Ok(())
    }

    pub fn handle_event(&mut self, event: ConnectionEvent) -> Result<(), AppError> {
        use ConnectionEvent::*;
        use ConnectionState::*;
        use RouteSelectionTarget::*;

        if event == TimeoutExpired {
            return self.handle_timeout().map(|_| ()).ok_or_else(|| {
                AppError::new(
                    ErrorCode::RuntimeCommandRejected,
                    "no timeout policy for current connection state",
                )
            });
        }

        let next = match (&self.state, event) {
            (_, IoError) => Failed,
            (_, ClientClosed | CommandShutdown) => Closed,
            (Accepted, ClientReadable) => ReadingClientRequest,
            (ReadingClientRequest, RequestParsed) => SelectingRoute,
            (SelectingRoute, RouteSelected(Proxy)) => ConnectingUpstream,
            (SelectingRoute, RouteSelected(ImmediateResponse)) => WritingClientResponse,
            (ConnectingUpstream, UpstreamConnectReady) => WritingUpstreamRequest,
            (ConnectingUpstream, UpstreamTlsHandshakeStarted) => HandshakingUpstreamTls,
            (HandshakingUpstreamTls, UpstreamTlsEstablished) => WritingUpstreamRequest,
            (WritingUpstreamRequest, UpstreamWritable) => ReadingUpstreamResponse,
            (ReadingUpstreamResponse, UpstreamReadable) => WritingClientResponse,
            (ReadingUpstreamResponse, RouteSelected(WebSocketTunnel)) => TunnelingWebSocket,
            (WritingClientResponse, ClientWritable) => Draining,
            (Draining, UpstreamClosed) => Closed,
            _ => {
                return Err(AppError::new(
                    ErrorCode::RuntimeCommandRejected,
                    "event is not valid for current connection state",
                ));
            }
        };

        self.transition_to(next)
    }

    pub fn handle_timeout(&mut self) -> Option<ConnectionTimeoutDecision> {
        let decision = timeout_decision_for_state(&self.state)?;
        self.state = decision.next_state.clone();
        Some(decision)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpConnectionIo {
    pub connection: Connection,
    upstream_attempt: UpstreamAttemptProgress,
    client_request: ClientRequestBuffer,
    upstream_write: WriteBuffer,
    client_write: WriteBuffer,
}

impl HttpConnectionIo {
    pub fn new(token: ConnectionToken) -> Self {
        Self {
            connection: Connection {
                token,
                state: ConnectionState::Accepted,
            },
            upstream_attempt: UpstreamAttemptProgress::default(),
            client_request: ClientRequestBuffer::default(),
            upstream_write: WriteBuffer::default(),
            client_write: WriteBuffer::default(),
        }
    }

    pub fn receive_client_bytes(
        &mut self,
        chunk: &[u8],
        limits: &HttpLimits,
    ) -> Result<RequestReadOutcome, AppError> {
        if self.connection.state == ConnectionState::Accepted {
            self.connection
                .handle_event(ConnectionEvent::ClientReadable)?;
        }
        if self.connection.state != ConnectionState::ReadingClientRequest {
            return Err(invalid_connection_io_state());
        }

        let outcome = self.client_request.push(chunk, limits)?;
        if let RequestReadOutcome::Complete(bytes) = &outcome {
            parse_http_request(bytes, limits)?;
            self.connection
                .handle_event(ConnectionEvent::RequestParsed)?;
        }
        Ok(outcome)
    }

    pub fn begin_upstream_connect(&mut self) -> Result<(), AppError> {
        self.connection
            .handle_event(ConnectionEvent::RouteSelected(RouteSelectionTarget::Proxy))?;
        self.upstream_attempt.begin()
    }

    pub fn upstream_connected(&mut self, upstream_request: Vec<u8>) -> Result<(), AppError> {
        let event = match self.connection.state {
            ConnectionState::ConnectingUpstream => ConnectionEvent::UpstreamConnectReady,
            ConnectionState::HandshakingUpstreamTls => ConnectionEvent::UpstreamTlsEstablished,
            _ => return Err(invalid_connection_io_state()),
        };
        self.upstream_write = WriteBuffer::new(upstream_request);
        self.connection.handle_event(event)
    }

    pub fn advance_upstream_write(&mut self, byte_count: usize) -> Result<usize, AppError> {
        if self.connection.state != ConnectionState::WritingUpstreamRequest {
            return Err(invalid_connection_io_state());
        }
        let advanced = self.upstream_write.advance(byte_count);
        self.upstream_attempt
            .record_request_write(advanced as u64)?;
        if self.upstream_write.is_complete() {
            self.upstream_attempt.request_write_completed()?;
            self.connection
                .handle_event(ConnectionEvent::UpstreamWritable)?;
            self.upstream_write.clear_if_complete();
        }
        Ok(advanced)
    }

    pub fn receive_upstream_bytes(&mut self, chunk: &[u8]) -> Result<usize, AppError> {
        if self.connection.state != ConnectionState::ReadingUpstreamResponse {
            return Err(invalid_connection_io_state());
        }
        self.client_write.try_append(chunk)?;
        self.upstream_attempt.record_response_bytes(chunk.len())?;
        Ok(chunk.len())
    }

    pub fn finish_upstream_response(&mut self) -> Result<(), AppError> {
        self.connection
            .handle_event(ConnectionEvent::UpstreamReadable)?;
        self.upstream_attempt.succeed()
    }

    pub fn fail_upstream_attempt(
        &mut self,
        failure: UpstreamAttemptFailure,
    ) -> Result<(), AppError> {
        self.upstream_attempt.fail(failure)
    }

    pub fn upstream_attempt(&self) -> &UpstreamAttemptProgress {
        &self.upstream_attempt
    }

    pub fn prepare_upstream_retry(&mut self) -> Result<(), AppError> {
        if !matches!(
            self.connection.state,
            ConnectionState::ConnectingUpstream | ConnectionState::WritingUpstreamRequest
        ) || self.upstream_attempt.terminal().is_none()
        {
            return Err(invalid_upstream_attempt_transition());
        }
        self.connection.state = ConnectionState::SelectingRoute;
        self.upstream_attempt = UpstreamAttemptProgress::default();
        self.upstream_write = WriteBuffer::default();
        Ok(())
    }

    pub fn queue_client_response(&mut self, response: Vec<u8>) -> Result<(), AppError> {
        if !self
            .connection
            .state
            .can_transition_to(&ConnectionState::WritingClientResponse)
        {
            return Err(invalid_connection_io_state());
        }
        self.client_write = WriteBuffer::new(response);
        self.connection
            .transition_to(ConnectionState::WritingClientResponse)
    }

    pub fn advance_client_write(&mut self, byte_count: usize) -> Result<usize, AppError> {
        if !matches!(
            self.connection.state,
            ConnectionState::ReadingUpstreamResponse | ConnectionState::WritingClientResponse
        ) {
            return Err(invalid_connection_io_state());
        }
        let advanced = self.client_write.advance(byte_count);
        if self.connection.state == ConnectionState::WritingClientResponse
            && self.client_write.is_complete()
        {
            self.connection
                .handle_event(ConnectionEvent::ClientWritable)?;
        }
        if self.client_write.is_complete() {
            self.client_write.clear_if_complete();
        }
        Ok(advanced)
    }

    pub fn upstream_write_buffer(&self) -> &WriteBuffer {
        &self.upstream_write
    }

    pub fn client_write_buffer(&self) -> &WriteBuffer {
        &self.client_write
    }
}

fn invalid_connection_io_state() -> AppError {
    AppError::new(
        ErrorCode::RuntimeCommandRejected,
        "operation is not valid for current connection state",
    )
}

#[derive(Debug, Default)]
pub struct ConnectionTable {
    entries: BTreeMap<usize, Connection>,
}

impl ConnectionTable {
    pub fn insert(&mut self, connection: Connection) -> Option<Connection> {
        self.entries.insert(connection.token.as_usize(), connection)
    }

    pub fn get(&self, token: ConnectionToken) -> Option<&Connection> {
        self.entries.get(&token.as_usize())
    }

    pub fn remove(&mut self, token: ConnectionToken) -> Option<Connection> {
        self.entries.remove(&token.as_usize())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn cleanup_closed(&mut self) -> Vec<ConnectionToken> {
        let removable: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, connection)| {
                matches!(
                    connection.state,
                    ConnectionState::Closed | ConnectionState::Failed
                )
            })
            .map(|(token, _)| ConnectionToken::new(*token))
            .collect();

        for token in &removable {
            self.entries.remove(&token.as_usize());
        }

        removable
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceLimits {
    pub max_connections: usize,
    pub max_request_header_bytes: usize,
    pub max_request_body_bytes: usize,
    pub idle_timeout: Duration,
    pub connect_timeout: Duration,
    pub upstream_read_timeout: Duration,
    pub client_write_timeout: Duration,
    pub max_response_buffer_bytes: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_request_header_bytes: FIXED_REQUEST_HEADER_RESERVE_BYTES,
            max_request_body_bytes: DEFAULT_MAX_REQUEST_BODY_BYTES,
            idle_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(5),
            upstream_read_timeout: Duration::from_secs(30),
            client_write_timeout: Duration::from_secs(30),
            max_response_buffer_bytes: FIXED_RESPONSE_BUFFER_RESERVE_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResourceChargeId(u64);

impl ResourceChargeId {
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadClass {
    Request,
    UpstreamRequest,
    RetryReplay,
    ClientResponse,
    WebSocketClientToUpstream,
    WebSocketUpstreamToClient,
    TlsPending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourcePressureState {
    Normal,
    Pressured,
    Exhausted,
    FailedClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionAdmissionDecision {
    Accepted,
    RejectedConnectionLimit,
    RejectedPayloadPressure,
    RejectedFailedClosed,
}

pub fn connection_admission_decision(
    pressure_state: ResourcePressureState,
    active_connections: usize,
    max_connections: usize,
) -> ConnectionAdmissionDecision {
    match pressure_state {
        ResourcePressureState::FailedClosed => ConnectionAdmissionDecision::RejectedFailedClosed,
        ResourcePressureState::Pressured | ResourcePressureState::Exhausted => {
            ConnectionAdmissionDecision::RejectedPayloadPressure
        }
        ResourcePressureState::Normal if active_connections >= max_connections => {
            ConnectionAdmissionDecision::RejectedConnectionLimit
        }
        ResourcePressureState::Normal => ConnectionAdmissionDecision::Accepted,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseReadInterestAction {
    Keep,
    Pause,
    Resume,
}

pub fn response_read_interest_action(
    pressure_state: ResourcePressureState,
    connection_state: &ConnectionState,
    upstream_registered: bool,
    buffered_client_output_bytes: usize,
    max_response_buffer_bytes: usize,
) -> ResponseReadInterestAction {
    if connection_state != &ConnectionState::ReadingUpstreamResponse {
        return ResponseReadInterestAction::Keep;
    }

    let read_must_pause = pressure_state != ResourcePressureState::Normal
        || buffered_client_output_bytes >= max_response_buffer_bytes;
    match (upstream_registered, read_must_pause) {
        (true, true) => ResponseReadInterestAction::Pause,
        (false, false) => ResponseReadInterestAction::Resume,
        (true, false) | (false, true) => ResponseReadInterestAction::Keep,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadCharge {
    id: ResourceChargeId,
    connection_id: usize,
    payload_class: PayloadClass,
    charged_bytes: usize,
    generation: u64,
    state: ResourceChargeState,
}

impl PayloadCharge {
    pub fn id(self) -> ResourceChargeId {
        self.id
    }

    pub fn connection_id(self) -> usize {
        self.connection_id
    }

    pub fn payload_class(self) -> PayloadClass {
        self.payload_class
    }

    pub fn charged_bytes(self) -> usize {
        self.charged_bytes
    }

    pub fn generation(self) -> u64 {
        self.generation
    }

    pub fn state(self) -> ResourceChargeState {
        self.state
    }
}

#[derive(Debug)]
pub struct PayloadBudgetLedger {
    limit_bytes: usize,
    used_bytes: usize,
    generation: u64,
    next_charge_id: u64,
    charges: BTreeMap<ResourceChargeId, PayloadCharge>,
    pressure_state: ResourcePressureState,
}

impl PayloadBudgetLedger {
    pub fn new(policy: RuntimeResourcePolicy, generation: u64) -> Self {
        Self {
            limit_bytes: policy.max_inflight_payload_bytes(),
            used_bytes: 0,
            generation,
            next_charge_id: 1,
            charges: BTreeMap::new(),
            pressure_state: ResourcePressureState::Normal,
        }
    }

    pub fn limit_bytes(&self) -> usize {
        self.limit_bytes
    }

    pub fn used_bytes(&self) -> usize {
        self.used_bytes
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn live_charge_count(&self) -> usize {
        self.charges.len()
    }

    pub fn pressure_state(&self) -> ResourcePressureState {
        self.pressure_state
    }

    pub fn charge(&self, id: ResourceChargeId) -> Option<&PayloadCharge> {
        self.charges.get(&id)
    }

    pub fn reserve(
        &mut self,
        connection_id: usize,
        payload_class: PayloadClass,
        requested_bytes: usize,
        generation: u64,
    ) -> Result<ResourceChargeId, AppError> {
        if self.pressure_state == ResourcePressureState::FailedClosed {
            return Err(resource_accounting_error(
                "resource admission is failed closed",
            ));
        }
        self.require_generation(generation)?;
        if requested_bytes == 0 {
            return self.fail_accounting("zero-byte resource charge is not allowed");
        }
        let next_used = self
            .used_bytes
            .checked_add(requested_bytes)
            .ok_or_else(resource_capacity_error)?;
        if next_used > self.limit_bytes {
            self.pressure_state = ResourcePressureState::Exhausted;
            return Err(resource_capacity_error());
        }
        let next_charge_id = self.next_charge_id.checked_add(1).ok_or_else(|| {
            self.pressure_state = ResourcePressureState::FailedClosed;
            resource_accounting_error("resource charge identity exhausted")
        })?;
        let id = ResourceChargeId(self.next_charge_id);
        self.next_charge_id = next_charge_id;
        self.used_bytes = next_used;
        self.charges.insert(
            id,
            PayloadCharge {
                id,
                connection_id,
                payload_class,
                charged_bytes: requested_bytes,
                generation,
                state: ResourceChargeState::Granted,
            },
        );
        self.refresh_pressure_after_usage_change();
        Ok(id)
    }

    pub fn commit(
        &mut self,
        id: ResourceChargeId,
        actual_logical_bytes: usize,
        generation: u64,
    ) -> Result<(), AppError> {
        self.require_generation(generation)?;
        let charge = self.live_charge(id, generation)?;
        if charge.state != ResourceChargeState::Granted {
            return self.fail_accounting("only granted charges can be committed");
        }
        self.replace_charge_bytes(id, actual_logical_bytes)?;
        let Some(charge) = self.charges.get_mut(&id) else {
            return self.fail_accounting("committed resource charge disappeared");
        };
        charge.state = ResourceChargeState::InUse;
        Ok(())
    }

    pub fn resize(
        &mut self,
        id: ResourceChargeId,
        next_logical_bytes: usize,
        generation: u64,
    ) -> Result<(), AppError> {
        self.require_generation(generation)?;
        let charge = self.live_charge(id, generation)?;
        if !matches!(
            charge.state,
            ResourceChargeState::Granted
                | ResourceChargeState::InUse
                | ResourceChargeState::Transferred
        ) {
            return self.fail_accounting("charge cannot be resized in its current state");
        }
        self.replace_charge_bytes(id, next_logical_bytes)
    }

    pub fn grow(
        &mut self,
        id: ResourceChargeId,
        additional_bytes: usize,
        generation: u64,
    ) -> Result<(), AppError> {
        self.require_generation(generation)?;
        if additional_bytes == 0 {
            return Ok(());
        }
        let charge = self.live_charge(id, generation)?;
        let Some(next_logical_bytes) = charge.charged_bytes.checked_add(additional_bytes) else {
            self.pressure_state = ResourcePressureState::Exhausted;
            return Err(resource_capacity_error());
        };
        self.resize(id, next_logical_bytes, generation)
    }

    pub fn transfer(
        &mut self,
        id: ResourceChargeId,
        next_connection_id: usize,
        next_payload_class: PayloadClass,
        generation: u64,
    ) -> Result<(), AppError> {
        self.require_generation(generation)?;
        let charge = self.live_charge(id, generation)?;
        if !matches!(
            charge.state,
            ResourceChargeState::Granted
                | ResourceChargeState::InUse
                | ResourceChargeState::Transferred
        ) {
            return self.fail_accounting("charge cannot be transferred in its current state");
        }
        let Some(charge) = self.charges.get_mut(&id) else {
            return self.fail_accounting("transferred resource charge disappeared");
        };
        charge.connection_id = next_connection_id;
        charge.payload_class = next_payload_class;
        charge.state = ResourceChargeState::Transferred;
        Ok(())
    }

    pub fn release(&mut self, id: ResourceChargeId, generation: u64) -> Result<(), AppError> {
        self.require_generation(generation)?;
        self.remove_live_charge(id, generation, ResourceChargeState::Released)?;
        Ok(())
    }

    pub fn release_after_allocation_failure(
        &mut self,
        id: ResourceChargeId,
        generation: u64,
    ) -> Result<(), AppError> {
        self.require_generation(generation)?;
        self.remove_live_charge(id, generation, ResourceChargeState::AllocationFailed)?;
        Ok(())
    }

    fn require_generation(&mut self, generation: u64) -> Result<(), AppError> {
        if generation != self.generation {
            return self.fail_accounting("resource generation is stale");
        }
        Ok(())
    }

    fn live_charge(
        &mut self,
        id: ResourceChargeId,
        generation: u64,
    ) -> Result<PayloadCharge, AppError> {
        let Some(charge) = self.charges.get(&id).copied() else {
            return self.fail_accounting("resource charge is not live");
        };
        if charge.generation != generation || charge.state.is_terminal() {
            return self.fail_accounting("resource charge identity is invalid");
        }
        Ok(charge)
    }

    fn replace_charge_bytes(
        &mut self,
        id: ResourceChargeId,
        next_logical_bytes: usize,
    ) -> Result<(), AppError> {
        if next_logical_bytes == 0 {
            return self.fail_accounting("live resource charge cannot be resized to zero");
        }
        let Some(previous_bytes) = self.charges.get(&id).map(|charge| charge.charged_bytes) else {
            return self.fail_accounting("resized resource charge disappeared");
        };
        let without_previous = self.used_bytes.checked_sub(previous_bytes).ok_or_else(|| {
            self.pressure_state = ResourcePressureState::FailedClosed;
            resource_accounting_error("resource total is below live charge")
        })?;
        let next_used = without_previous
            .checked_add(next_logical_bytes)
            .ok_or_else(resource_capacity_error)?;
        if next_used > self.limit_bytes {
            self.pressure_state = ResourcePressureState::Exhausted;
            return Err(resource_capacity_error());
        }
        self.used_bytes = next_used;
        let Some(charge) = self.charges.get_mut(&id) else {
            return self.fail_accounting("resized resource charge disappeared");
        };
        charge.charged_bytes = next_logical_bytes;
        self.refresh_pressure_after_usage_change();
        Ok(())
    }

    fn remove_live_charge(
        &mut self,
        id: ResourceChargeId,
        generation: u64,
        terminal_state: ResourceChargeState,
    ) -> Result<PayloadCharge, AppError> {
        debug_assert!(terminal_state.is_terminal());
        let charge = self.live_charge(id, generation)?;
        let Some(next_used) = self.used_bytes.checked_sub(charge.charged_bytes) else {
            return self.fail_accounting("resource release exceeds current total");
        };
        let Some(live_charge) = self.charges.get_mut(&id) else {
            return self.fail_accounting("released resource charge disappeared");
        };
        live_charge.state = terminal_state;
        self.charges.remove(&id);
        self.used_bytes = next_used;
        self.refresh_pressure_after_usage_change();
        Ok(charge)
    }

    fn refresh_pressure_after_usage_change(&mut self) {
        if self.pressure_state == ResourcePressureState::FailedClosed {
            return;
        }
        let high_watermark = self.limit_bytes * 80 / 100;
        let low_watermark = self.limit_bytes * 60 / 100;
        self.pressure_state = match self.pressure_state {
            ResourcePressureState::Normal if self.used_bytes < high_watermark => {
                ResourcePressureState::Normal
            }
            ResourcePressureState::Pressured | ResourcePressureState::Exhausted
                if self.used_bytes <= low_watermark =>
            {
                ResourcePressureState::Normal
            }
            ResourcePressureState::Normal
            | ResourcePressureState::Pressured
            | ResourcePressureState::Exhausted => ResourcePressureState::Pressured,
            ResourcePressureState::FailedClosed => ResourcePressureState::FailedClosed,
        };
    }

    fn fail_accounting<T>(&mut self, message: &'static str) -> Result<T, AppError> {
        self.pressure_state = ResourcePressureState::FailedClosed;
        Err(resource_accounting_error(message))
    }
}

fn resource_capacity_error() -> AppError {
    AppError::new(
        ErrorCode::ResourcePayloadCapacityReached,
        "logical payload capacity reached",
    )
}

fn resource_accounting_error(message: &'static str) -> AppError {
    AppError::new(ErrorCode::ResourceAccountingInvariantFailed, message)
}

#[derive(Debug, Default)]
struct ConnectionPayloadCharges {
    request: Option<ResourceChargeId>,
    upstream: Option<ResourceChargeId>,
    retry_replay: Option<ResourceChargeId>,
    client_response: Option<ResourceChargeId>,
    tls_pending: Option<ResourceChargeId>,
    websocket_client_to_upstream: Option<ResourceChargeId>,
    websocket_upstream_to_client: Option<ResourceChargeId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ClientResponseChargeChange {
    charge_id: ResourceChargeId,
    previous_bytes: Option<usize>,
    next_bytes: usize,
}

impl ConnectionPayloadCharges {
    fn grow_request(
        &mut self,
        ledger: &mut PayloadBudgetLedger,
        connection_id: usize,
        additional_bytes: usize,
    ) -> Result<(), AppError> {
        if additional_bytes == 0 {
            return Ok(());
        }
        let generation = ledger.generation();
        if let Some(charge_id) = self.request {
            ledger.grow(charge_id, additional_bytes, generation)
        } else {
            let charge_id = ledger.reserve(
                connection_id,
                PayloadClass::Request,
                additional_bytes,
                generation,
            )?;
            self.request = Some(charge_id);
            Ok(())
        }
    }

    #[cfg(test)]
    fn request_bytes(&self, ledger: &PayloadBudgetLedger) -> usize {
        charge_bytes(ledger, self.request)
    }

    #[cfg(test)]
    fn upstream_bytes(&self, ledger: &PayloadBudgetLedger) -> usize {
        charge_bytes(ledger, self.upstream)
    }

    #[cfg(test)]
    fn retry_replay_bytes(&self, ledger: &PayloadBudgetLedger) -> usize {
        charge_bytes(ledger, self.retry_replay)
    }

    fn client_response_bytes(&self, ledger: &PayloadBudgetLedger) -> usize {
        charge_bytes(ledger, self.client_response)
    }

    fn tls_pending_bytes(&self, ledger: &PayloadBudgetLedger) -> usize {
        charge_bytes(ledger, self.tls_pending)
    }

    fn sync_tls_pending(
        &mut self,
        ledger: &mut PayloadBudgetLedger,
        connection_id: usize,
        next_bytes: usize,
    ) -> Result<bool, AppError> {
        let current_bytes = self.tls_pending_bytes(ledger);
        if current_bytes == next_bytes {
            return Ok(false);
        }
        if next_bytes == 0 {
            release_charge_slot(&mut self.tls_pending, ledger)?;
            return Ok(true);
        }
        if let Some(charge_id) = self.tls_pending {
            ledger.resize(charge_id, next_bytes, ledger.generation())?;
            return Ok(true);
        }

        let generation = ledger.generation();
        let charge_id = ledger.reserve(
            connection_id,
            PayloadClass::TlsPending,
            next_bytes,
            generation,
        )?;
        if let Err(error) = ledger.commit(charge_id, next_bytes, generation) {
            let _ = ledger.release(charge_id, generation);
            return Err(error);
        }
        self.tls_pending = Some(charge_id);
        Ok(true)
    }

    fn websocket_client_to_upstream_bytes(&self, ledger: &PayloadBudgetLedger) -> usize {
        charge_bytes(ledger, self.websocket_client_to_upstream)
    }

    fn websocket_upstream_to_client_bytes(&self, ledger: &PayloadBudgetLedger) -> usize {
        charge_bytes(ledger, self.websocket_upstream_to_client)
    }

    fn sync_websocket_client_to_upstream(
        &mut self,
        ledger: &mut PayloadBudgetLedger,
        connection_id: usize,
        next_bytes: usize,
    ) -> Result<bool, AppError> {
        sync_payload_charge_slot(
            &mut self.websocket_client_to_upstream,
            PayloadClass::WebSocketClientToUpstream,
            ledger,
            connection_id,
            next_bytes,
        )
    }

    fn sync_websocket_upstream_to_client(
        &mut self,
        ledger: &mut PayloadBudgetLedger,
        connection_id: usize,
        next_bytes: usize,
    ) -> Result<bool, AppError> {
        sync_payload_charge_slot(
            &mut self.websocket_upstream_to_client,
            PayloadClass::WebSocketUpstreamToClient,
            ledger,
            connection_id,
            next_bytes,
        )
    }

    fn resize_client_response_in_use(
        &mut self,
        ledger: &mut PayloadBudgetLedger,
        next_bytes: usize,
    ) -> Result<(), AppError> {
        let Some(charge_id) = self.client_response else {
            return ledger.fail_accounting("client response charge is not installed");
        };
        if next_bytes == 0 {
            ledger.release(charge_id, ledger.generation())?;
            self.client_response = None;
            Ok(())
        } else {
            ledger.resize(charge_id, next_bytes, ledger.generation())
        }
    }

    fn prepare_client_response_bytes(
        &mut self,
        ledger: &mut PayloadBudgetLedger,
        connection_id: usize,
        next_bytes: usize,
    ) -> Result<ClientResponseChargeChange, AppError> {
        let generation = ledger.generation();
        if let Some(charge_id) = self.client_response {
            let previous_bytes = ledger
                .charge(charge_id)
                .map(|charge| charge.charged_bytes())
                .ok_or_else(|| resource_accounting_error("client response charge disappeared"))?;
            ledger.resize(charge_id, next_bytes, generation)?;
            Ok(ClientResponseChargeChange {
                charge_id,
                previous_bytes: Some(previous_bytes),
                next_bytes,
            })
        } else {
            let charge_id = ledger.reserve(
                connection_id,
                PayloadClass::ClientResponse,
                next_bytes,
                generation,
            )?;
            self.client_response = Some(charge_id);
            Ok(ClientResponseChargeChange {
                charge_id,
                previous_bytes: None,
                next_bytes,
            })
        }
    }

    fn commit_client_response_bytes(
        &self,
        ledger: &mut PayloadBudgetLedger,
        change: ClientResponseChargeChange,
    ) -> Result<(), AppError> {
        if self.client_response != Some(change.charge_id) {
            return ledger.fail_accounting("client response change is not current");
        }
        if change.previous_bytes.is_none() {
            ledger.commit(change.charge_id, change.next_bytes, ledger.generation())?;
        }
        Ok(())
    }

    fn rollback_client_response_allocation(
        &mut self,
        ledger: &mut PayloadBudgetLedger,
        change: ClientResponseChargeChange,
    ) -> Result<(), AppError> {
        if self.client_response != Some(change.charge_id) {
            return ledger.fail_accounting("client response rollback is not current");
        }
        let generation = ledger.generation();
        if let Some(previous_bytes) = change.previous_bytes {
            ledger.resize(change.charge_id, previous_bytes, generation)
        } else {
            ledger.release_after_allocation_failure(change.charge_id, generation)?;
            self.client_response = None;
            Ok(())
        }
    }

    fn reserve_upstream_and_retry(
        &mut self,
        ledger: &mut PayloadBudgetLedger,
        connection_id: usize,
        upstream_bytes: usize,
        retry_replay_bytes: usize,
    ) -> Result<(), AppError> {
        if self.upstream.is_some() || self.retry_replay.is_some() {
            return ledger.fail_accounting("upstream payload charges are already installed");
        }
        let generation = ledger.generation();
        let upstream = ledger.reserve(
            connection_id,
            PayloadClass::UpstreamRequest,
            upstream_bytes,
            generation,
        )?;
        let retry_replay = match ledger.reserve(
            connection_id,
            PayloadClass::RetryReplay,
            retry_replay_bytes,
            generation,
        ) {
            Ok(charge_id) => charge_id,
            Err(error) => {
                ledger.release(upstream, generation)?;
                return Err(error);
            }
        };
        self.upstream = Some(upstream);
        self.retry_replay = Some(retry_replay);
        Ok(())
    }

    fn commit_upstream_and_retry(
        &self,
        ledger: &mut PayloadBudgetLedger,
        upstream_bytes: usize,
        retry_replay_bytes: usize,
    ) -> Result<(), AppError> {
        let generation = ledger.generation();
        let Some(upstream) = self.upstream else {
            return ledger.fail_accounting("upstream charge is not installed");
        };
        let Some(retry_replay) = self.retry_replay else {
            return ledger.fail_accounting("retry replay charge is not installed");
        };
        ledger.commit(upstream, upstream_bytes, generation)?;
        ledger.commit(retry_replay, retry_replay_bytes, generation)
    }

    fn reserve_upstream_replacement(
        &self,
        ledger: &mut PayloadBudgetLedger,
        connection_id: usize,
        upstream_bytes: usize,
    ) -> Result<ResourceChargeId, AppError> {
        if self.upstream.is_none() {
            return ledger.fail_accounting("current upstream charge is not installed");
        }
        ledger.reserve(
            connection_id,
            PayloadClass::UpstreamRequest,
            upstream_bytes,
            ledger.generation(),
        )
    }

    fn commit_upstream_replacement(
        &mut self,
        ledger: &mut PayloadBudgetLedger,
        replacement: ResourceChargeId,
        upstream_bytes: usize,
    ) -> Result<(), AppError> {
        let Some(current) = self.upstream else {
            return ledger.fail_accounting("current upstream charge is not installed");
        };
        if current == replacement {
            return ledger.fail_accounting("replacement upstream charge must be distinct");
        }
        let generation = ledger.generation();
        let Some(replacement_charge) = ledger.charge(replacement) else {
            return ledger.fail_accounting("replacement upstream charge is not live");
        };
        if replacement_charge.payload_class() != PayloadClass::UpstreamRequest {
            return ledger.fail_accounting("replacement charge has the wrong payload class");
        }
        ledger.commit(replacement, upstream_bytes, generation)?;
        if let Err(error) = ledger.release(current, generation) {
            let _ = ledger.release(replacement, generation);
            return Err(error);
        }
        self.upstream = Some(replacement);
        Ok(())
    }

    fn release_upstream_replacement_after_allocation_failure(
        &self,
        ledger: &mut PayloadBudgetLedger,
        replacement: ResourceChargeId,
    ) -> Result<(), AppError> {
        if self.upstream == Some(replacement) {
            return ledger.fail_accounting("current upstream charge cannot be failed as pending");
        }
        ledger.release_after_allocation_failure(replacement, ledger.generation())
    }

    fn release_upstream_allocation_failure(
        &mut self,
        ledger: &mut PayloadBudgetLedger,
    ) -> Result<(), AppError> {
        let generation = ledger.generation();
        if let Some(upstream) = self.upstream {
            ledger.release_after_allocation_failure(upstream, generation)?;
            self.upstream = None;
        }
        if let Some(retry_replay) = self.retry_replay {
            ledger.release(retry_replay, generation)?;
            self.retry_replay = None;
        }
        Ok(())
    }

    fn release_request(&mut self, ledger: &mut PayloadBudgetLedger) -> Result<(), AppError> {
        let Some(charge_id) = self.request else {
            return Ok(());
        };
        ledger.release(charge_id, ledger.generation())?;
        self.request = None;
        Ok(())
    }

    fn release_all(&mut self, ledger: &mut PayloadBudgetLedger) -> Result<(), AppError> {
        self.release_request(ledger)?;
        release_charge_slot(&mut self.upstream, ledger)?;
        release_charge_slot(&mut self.retry_replay, ledger)?;
        release_charge_slot(&mut self.client_response, ledger)?;
        release_charge_slot(&mut self.tls_pending, ledger)?;
        release_charge_slot(&mut self.websocket_client_to_upstream, ledger)?;
        release_charge_slot(&mut self.websocket_upstream_to_client, ledger)
    }
}

fn sync_payload_charge_slot(
    slot: &mut Option<ResourceChargeId>,
    payload_class: PayloadClass,
    ledger: &mut PayloadBudgetLedger,
    connection_id: usize,
    next_bytes: usize,
) -> Result<bool, AppError> {
    let current_bytes = charge_bytes(ledger, *slot);
    if current_bytes == next_bytes {
        return Ok(false);
    }
    if next_bytes == 0 {
        release_charge_slot(slot, ledger)?;
        return Ok(true);
    }
    if let Some(charge_id) = *slot {
        ledger.resize(charge_id, next_bytes, ledger.generation())?;
        return Ok(true);
    }

    let generation = ledger.generation();
    let charge_id = ledger.reserve(connection_id, payload_class, next_bytes, generation)?;
    if let Err(error) = ledger.commit(charge_id, next_bytes, generation) {
        let _ = ledger.release(charge_id, generation);
        return Err(error);
    }
    *slot = Some(charge_id);
    Ok(true)
}

fn tls_pending_owner_bytes(
    client_transport: &ClientTransport,
    pending_client_output: &PendingSocketOutput,
    upstream_transport: &UpstreamTransport,
    pending_upstream_output: &WriteBuffer,
) -> Result<usize, AppError> {
    let client_session = client_transport
        .pending_tls_bytes()
        .total_bytes()
        .ok_or_else(|| resource_accounting_error("client TLS pending bytes overflowed"))?;
    let upstream_session = upstream_transport
        .pending_tls_bytes()
        .total_bytes()
        .ok_or_else(|| resource_accounting_error("upstream TLS pending bytes overflowed"))?;
    let client_socket = if client_transport.is_tls() {
        pending_client_output.remaining().len()
    } else {
        0
    };
    let upstream_socket = if upstream_transport.is_tls() {
        pending_upstream_output.remaining_len()
    } else {
        0
    };

    client_session
        .checked_add(client_socket)
        .and_then(|bytes| bytes.checked_add(upstream_session))
        .and_then(|bytes| bytes.checked_add(upstream_socket))
        .ok_or_else(|| resource_accounting_error("connection TLS pending bytes overflowed"))
}

fn websocket_pending_owner_bytes(
    upstream_to_client_plaintext: usize,
    client_to_upstream_plaintext: usize,
    client_transport: &ClientTransport,
    pending_client_output: &PendingSocketOutput,
    upstream_transport: &UpstreamTransport,
    pending_upstream_output: &WriteBuffer,
) -> Result<(usize, usize), AppError> {
    let client_to_upstream_socket = if upstream_transport.is_tls() {
        0
    } else {
        pending_upstream_output.remaining_len()
    };
    let upstream_to_client_socket = if client_transport.is_tls() {
        0
    } else {
        pending_client_output.remaining().len()
    };
    let client_to_upstream = client_to_upstream_plaintext
        .checked_add(client_to_upstream_socket)
        .ok_or_else(|| resource_accounting_error("client WebSocket pending bytes overflowed"))?;
    let upstream_to_client = upstream_to_client_plaintext
        .checked_add(upstream_to_client_socket)
        .ok_or_else(|| resource_accounting_error("upstream WebSocket pending bytes overflowed"))?;
    Ok((client_to_upstream, upstream_to_client))
}

fn charge_bytes(ledger: &PayloadBudgetLedger, charge_id: Option<ResourceChargeId>) -> usize {
    charge_id
        .and_then(|charge_id| ledger.charge(charge_id))
        .map(|charge| charge.charged_bytes())
        .unwrap_or(0)
}

fn release_charge_slot(
    slot: &mut Option<ResourceChargeId>,
    ledger: &mut PayloadBudgetLedger,
) -> Result<(), AppError> {
    let Some(charge_id) = *slot else {
        return Ok(());
    };
    ledger.release(charge_id, ledger.generation())?;
    *slot = None;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueError {
    Full,
}

#[derive(Debug)]
pub struct BoundedCommandQueue {
    capacity: usize,
    queue: VecDeque<CoreCommand>,
}

impl BoundedCommandQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            queue: VecDeque::new(),
        }
    }

    pub fn push(&mut self, command: CoreCommand) -> Result<(), QueueError> {
        if self.queue.len() >= self.capacity {
            return Err(QueueError::Full);
        }
        self.queue.push_back(command);
        Ok(())
    }

    pub fn pop(&mut self) -> Option<CoreCommand> {
        self.queue.pop_front()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

#[derive(Debug, Clone)]
pub enum WorkerEvent {
    ConfigSnapshotReady(ConfigSnapshot),
    Failed(AppError),
}

#[derive(Debug, Default)]
pub struct WorkerEventQueue {
    events: VecDeque<WorkerEvent>,
}

impl WorkerEventQueue {
    pub fn push(&mut self, event: WorkerEvent) {
        self.events.push_back(event);
    }

    pub fn pop(&mut self) -> Option<WorkerEvent> {
        self.events.pop_front()
    }
}

#[derive(Debug, Default)]
pub struct TimerQueue {
    timers: Vec<(Instant, ConnectionToken)>,
}

impl TimerQueue {
    pub fn schedule(&mut self, token: ConnectionToken, deadline: Instant) {
        self.timers.push((deadline, token));
        self.timers.sort_by_key(|(deadline, _)| *deadline);
    }

    pub fn pop_expired(&mut self, now: Instant) -> Vec<ConnectionToken> {
        let split = self
            .timers
            .iter()
            .position(|(deadline, _)| *deadline > now)
            .unwrap_or(self.timers.len());
        self.timers.drain(..split).map(|(_, token)| token).collect()
    }
}

#[derive(Debug, Default)]
pub struct CoreRuntime {
    pub connections: ConnectionTable,
    pub commands: BoundedCommandQueue,
    pub worker_events: WorkerEventQueue,
    pub current_snapshot: Option<ConfigSnapshot>,
    pub shutting_down: bool,
}

impl CoreRuntime {
    pub fn new(command_capacity: usize) -> Self {
        Self {
            connections: ConnectionTable::default(),
            commands: BoundedCommandQueue::new(command_capacity),
            worker_events: WorkerEventQueue::default(),
            current_snapshot: None,
            shutting_down: false,
        }
    }

    pub fn accept_connection(
        &mut self,
        token: ConnectionToken,
        limits: &ResourceLimits,
    ) -> Result<(), AppError> {
        if self.connections.len() >= limits.max_connections {
            return Err(AppError::new(
                ErrorCode::RuntimeCommandRejected,
                "max connections reached",
            ));
        }
        self.connections.insert(Connection {
            token,
            state: ConnectionState::Accepted,
        });
        Ok(())
    }

    pub fn handle_command(&mut self, command: CoreCommand) -> CommandAck {
        match command {
            CoreCommand::ApplyConfigSnapshot { snapshot } => {
                self.current_snapshot = Some(snapshot);
                CommandAck::accepted()
            }
            CoreCommand::ActivateConfigSnapshot { snapshot, .. } => {
                self.current_snapshot = Some(snapshot);
                CommandAck::accepted()
            }
            CoreCommand::PublishUpstreamAvailability { .. } => CommandAck::accepted(),
            CoreCommand::RollbackConfigSnapshot { .. } => CommandAck::accepted(),
            CoreCommand::InstallCertificate { .. } => CommandAck::accepted(),
            CoreCommand::RefreshRouteTable => CommandAck::accepted(),
            CoreCommand::Shutdown => {
                self.shutting_down = true;
                CommandAck::accepted()
            }
        }
    }

    pub fn cleanup_closed_connections(&mut self) -> Vec<ConnectionToken> {
        self.connections.cleanup_closed()
    }
}

impl Default for BoundedCommandQueue {
    fn default() -> Self {
        Self::new(128)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy_single_upstream::handle_http_proxy_connection;
    use crate::snapshot_http::{
        build_selected_upstream_request, checked_wire_length, drain_runtime_commands,
        error_response_for_code, handle_runtime_command, handle_snapshot_http_proxy_connection,
        handle_snapshot_http_proxy_stream, handle_snapshot_http_proxy_stream_with_scheme,
        host_for_route_match, initial_availability_snapshot, planned_selected_upstream_request_len,
        run_snapshot_http_proxy_mio_for_test, runtime_command_channel, tunnel_flow_control,
        tunnel_interest, tunnel_pressure_flow, BackpressureEvent, NoopHttp01ChallengeResponder,
        ResourceAccountingEvent, RuntimeUpstreamSelector, SnapshotProxyConfig, TunnelFlowControl,
    };
    use edge_application::{Http01Token, Http01TokenStore};
    use edge_domain::{
        AdminConfig, CertificateRef, ConfigRevisionId, CoreCommand, HostMatch, LogMode, PathMatch,
        Route, RouteId, RouteMatch, RuntimeOptions, Service, ServiceId, Upstream,
        UpstreamAvailability, UpstreamId, UpstreamTlsPolicy, MIN_MAX_INFLIGHT_PAYLOAD_BYTES,
    };
    use edge_ports::{
        CoreCommandClient, PassiveObservation, PassiveObservationDispatcher,
        PassiveObservationSubmit, ScriptedServerTlsSessionFactory, ScriptedTlsSession,
    };
    use mio::Interest;
    use std::io::{Read, Write};
    use std::net::{TcpListener as StdTcpListener, TcpStream as StdTcpStream};
    use std::thread;

    struct ChannelPassiveObservationDispatcher(std::sync::mpsc::SyncSender<PassiveObservation>);

    impl PassiveObservationDispatcher for ChannelPassiveObservationDispatcher {
        fn submit(&mut self, observation: PassiveObservation) -> PassiveObservationSubmit {
            match self.0.try_send(observation) {
                Ok(()) => PassiveObservationSubmit::Accepted,
                Err(std::sync::mpsc::TrySendError::Full(_)) => PassiveObservationSubmit::Full,
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                    PassiveObservationSubmit::Stopped
                }
            }
        }
    }

    fn snapshot() -> ConfigSnapshot {
        ConfigSnapshot {
            schema_version: 1,
            revision_id: ConfigRevisionId::new("rev-1"),
            admin: AdminConfig {
                bind: "127.0.0.1:9443".to_string(),
                auth_required: true,
            },
            listeners: vec![],
            routes: vec![],
            services: vec![],
            certificate_resolvers: vec![],
            log_mode: LogMode::Product,
            runtime: RuntimeOptions {
                max_connections: 1024,
                max_inflight_payload_bytes: 128 * 1024 * 1024,
                max_request_header_bytes: 16 * 1024,
                max_request_body_bytes: 1024 * 1024,
                metrics: edge_domain::MetricsConfig::default(),
            },
        }
    }

    fn tls_snapshot() -> ConfigSnapshot {
        let mut snapshot = snapshot();
        snapshot.routes.push(Route {
            id: RouteId::new("app"),
            route_match: RouteMatch::new(
                vec![HostMatch::exact("app.example.com")],
                vec![PathMatch::prefix("/")],
            ),
            service_id: ServiceId::new("app"),
            priority: 0,
            enabled: true,
            redirect_http_to_https: false,
            certificate_resolver_id: None,
            certificate_ref: Some(CertificateRef::new("cert-app")),
        });
        snapshot
    }

    fn route_to_service(route_id: &str, host: &str, path: &str, service_id: &str) -> Route {
        Route {
            id: RouteId::new(route_id),
            route_match: RouteMatch::new(
                vec![HostMatch::exact(host)],
                vec![PathMatch::prefix(path)],
            ),
            service_id: ServiceId::new(service_id),
            priority: 100,
            enabled: true,
            redirect_http_to_https: false,
            certificate_resolver_id: None,
            certificate_ref: None,
        }
    }

    fn service_with_upstream(service_id: &str, address: std::net::SocketAddr) -> Service {
        Service {
            policy: edge_domain::ServicePolicy::default(),
            id: ServiceId::new(service_id),
            upstreams: vec![Upstream {
                id: UpstreamId::new(format!("{service_id}-1")),
                url: format!("http://{}:{}", address.ip(), address.port()),
                administrative_state: edge_domain::UpstreamAdministrativeState::Active,
                tls: edge_domain::UpstreamTlsPolicy::Disabled,
            }],
        }
    }

    fn snapshot_for_runtime(routes: Vec<Route>, services: Vec<Service>) -> ConfigSnapshot {
        ConfigSnapshot {
            schema_version: 1,
            revision_id: ConfigRevisionId::new("rev-runtime"),
            admin: AdminConfig {
                bind: "127.0.0.1:9443".to_string(),
                auth_required: true,
            },
            listeners: vec![],
            routes,
            services,
            certificate_resolvers: vec![],
            log_mode: LogMode::Product,
            runtime: RuntimeOptions {
                max_connections: 1024,
                max_inflight_payload_bytes: 128 * 1024 * 1024,
                max_request_header_bytes: 16 * 1024,
                max_request_body_bytes: 1024 * 1024,
                metrics: edge_domain::MetricsConfig::default(),
            },
        }
    }

    fn service_with_upstreams(service_id: &str, addresses: &[std::net::SocketAddr]) -> Service {
        Service {
            policy: edge_domain::ServicePolicy::default(),
            id: ServiceId::new(service_id),
            upstreams: addresses
                .iter()
                .enumerate()
                .map(|(index, address)| Upstream {
                    id: UpstreamId::new(format!("{service_id}-{}", index + 1)),
                    url: format!("http://{}:{}", address.ip(), address.port()),
                    administrative_state: edge_domain::UpstreamAdministrativeState::Active,
                    tls: edge_domain::UpstreamTlsPolicy::Disabled,
                })
                .collect(),
        }
    }

    fn phase009_private_tls_snapshot(
        address: std::net::SocketAddr,
    ) -> (ConfigSnapshot, ServiceId, UpstreamId) {
        let service_id = ServiceId::new("private-service");
        let upstream_id = UpstreamId::new("private-upstream");
        let mut snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "private-route",
                "public.example.test",
                "/",
                service_id.as_str(),
            )],
            vec![Service {
                id: service_id.clone(),
                policy: edge_domain::ServicePolicy::default(),
                upstreams: vec![Upstream {
                    id: upstream_id.clone(),
                    url: format!("https://{}:{}", address.ip(), address.port()),
                    administrative_state: edge_domain::UpstreamAdministrativeState::Active,
                    tls: edge_domain::UpstreamTlsPolicy::ServerAuthenticated {
                        server_name: edge_domain::TlsServerName::parse("backend.private.test")
                            .unwrap(),
                        http_host: edge_domain::UpstreamHttpHost::parse("backend.private.test")
                            .unwrap(),
                        trust_bundle_ref: edge_domain::TrustBundleRef::parse("private-root")
                            .unwrap(),
                    },
                }],
            }],
        );
        snapshot.schema_version = 2;
        (snapshot, service_id, upstream_id)
    }

    #[test]
    fn runtime_upstream_selector_advances_per_service_and_reconciles_pool_changes() {
        let addresses = [
            "127.0.0.1:3001".parse().unwrap(),
            "127.0.0.1:3002".parse().unwrap(),
        ];
        let service = service_with_upstreams("app", &addresses);
        let snapshot = snapshot_for_runtime(vec![], vec![service.clone()]);
        let mut selector = RuntimeUpstreamSelector::from_snapshot(&snapshot).unwrap();

        assert_eq!(
            selector.select(&service).unwrap().upstream_id.as_str(),
            "app-1"
        );
        let mut invalid = snapshot.clone();
        invalid.services[0].upstreams[0].url = "http://upstream.internal:3001".to_string();
        assert_eq!(
            selector.reconcile(&snapshot, &invalid).unwrap_err().code,
            ErrorCode::ConfigInvalidUpstreamUrl
        );
        selector.reconcile(&snapshot, &snapshot).unwrap();
        assert_eq!(
            selector.select(&service).unwrap().upstream_id.as_str(),
            "app-2"
        );

        let reordered = service_with_upstreams("app", &[addresses[1], addresses[0]]);
        let next = snapshot_for_runtime(vec![], vec![reordered.clone()]);
        selector.reconcile(&snapshot, &next).unwrap();
        assert_eq!(
            selector.select(&reordered).unwrap().upstream_id.as_str(),
            "app-1"
        );
    }

    #[test]
    fn runtime_selector_tracks_drain_references_across_config_generations() {
        use edge_application::{DrainReleaseResult, UpstreamDrainState};

        let address = "127.0.0.1:3001".parse().unwrap();
        let service = service_with_upstream("app", address);
        let snapshot = snapshot_for_runtime(vec![], vec![service.clone()]);
        let mut selector = RuntimeUpstreamSelector::from_snapshot(&snapshot).unwrap();
        let selected = selector.select(&service).unwrap();
        let first_generation = selector.drain_generation;

        let mut draining = snapshot.clone();
        draining.revision_id = ConfigRevisionId::new("draining");
        draining.services[0].upstreams[0].administrative_state =
            edge_domain::UpstreamAdministrativeState::Draining;
        selector.reconcile(&snapshot, &draining).unwrap();
        let key = edge_domain::UpstreamHealthKey {
            service_id: ServiceId::new("app"),
            upstream_id: UpstreamId::new("app-1"),
        };

        assert!(selector.select(&draining.services[0]).is_none());
        assert_eq!(
            selector
                .drain_tracker
                .status(first_generation, &key)
                .unwrap()
                .state,
            UpstreamDrainState::Draining
        );
        assert_eq!(
            selector.drain_tracker.release(&selected.drain_reference),
            DrainReleaseResult::DrainCompleted
        );

        let mut reactivated = draining.clone();
        reactivated.revision_id = ConfigRevisionId::new("reactivated");
        reactivated.services[0].upstreams[0].administrative_state =
            edge_domain::UpstreamAdministrativeState::Active;
        selector.reconcile(&draining, &reactivated).unwrap();
        let current_generation = selector.drain_generation;
        let current = selector.select(&reactivated.services[0]).unwrap();
        assert_eq!(
            selector.drain_tracker.release(&selected.drain_reference),
            DrainReleaseResult::Underflow
        );
        assert_eq!(
            selector
                .drain_tracker
                .status(current_generation, &key)
                .unwrap()
                .connection_count,
            1
        );
        assert_eq!(
            selector.drain_tracker.release(&current.drain_reference),
            DrainReleaseResult::Released
        );
    }

    #[test]
    fn runtime_selector_publishes_initial_and_acquired_drain_status() {
        #[derive(Default)]
        struct RecordingPublisher(std::sync::Mutex<Vec<edge_ports::RuntimeUpstreamStatusSnapshot>>);
        impl edge_ports::RuntimeUpstreamStatusPublisher for RecordingPublisher {
            fn publish_runtime_status(&self, snapshot: edge_ports::RuntimeUpstreamStatusSnapshot) {
                self.0.lock().unwrap().push(snapshot);
            }
        }

        let address = "127.0.0.1:3001".parse().unwrap();
        let service = service_with_upstream("app", address);
        let snapshot = snapshot_for_runtime(vec![], vec![service.clone()]);
        let mut selector = RuntimeUpstreamSelector::from_snapshot(&snapshot).unwrap();
        let publisher = std::sync::Arc::new(RecordingPublisher::default());
        selector.install_runtime_status_publisher(Some(publisher.clone()));

        let _selection = selector.select(&service).unwrap();

        let published = publisher.0.lock().unwrap();
        assert_eq!(published.len(), 2);
        assert_eq!(published[0].upstreams[0].connection_count, 0);
        assert_eq!(published[1].upstreams[0].connection_count, 1);
        assert_eq!(published[1].revision_id, snapshot.revision_id);
    }

    #[test]
    fn runtime_selector_applies_generation_fenced_health_availability() {
        use edge_ports::{HealthAvailabilitySnapshot, HealthGeneration, UpstreamHealthKey};

        let addresses = [
            "127.0.0.1:3001".parse().unwrap(),
            "127.0.0.1:3002".parse().unwrap(),
        ];
        let mut service = service_with_upstreams("app", &addresses);
        service.policy.health_check = edge_domain::HealthCheckPolicy::Http(
            edge_domain::HttpHealthCheckPolicy::new("/health", 1_000, 100, 1, 1, 200, 399).unwrap(),
        );
        let snapshot = snapshot_for_runtime(vec![], vec![service.clone()]);
        let mut selector = RuntimeUpstreamSelector::from_snapshot(&snapshot).unwrap();
        let key = |upstream: &str| UpstreamHealthKey {
            service_id: ServiceId::new("app"),
            upstream_id: UpstreamId::new(upstream),
        };
        let availability = |generation, first, second| HealthAvailabilitySnapshot {
            revision_id: snapshot.revision_id.clone(),
            generation: HealthGeneration(generation),
            entries: BTreeMap::from([(key("app-1"), first), (key("app-2"), second)]),
        };

        selector
            .apply_availability(
                &snapshot,
                availability(
                    2,
                    UpstreamAvailability::Unhealthy,
                    UpstreamAvailability::Healthy,
                ),
            )
            .unwrap();
        assert_eq!(
            selector.select(&service).unwrap().upstream_id.as_str(),
            "app-2"
        );
        selector
            .apply_availability(
                &snapshot,
                availability(
                    2,
                    UpstreamAvailability::Unhealthy,
                    UpstreamAvailability::Unhealthy,
                ),
            )
            .unwrap();
        assert!(selector.select(&service).is_none());
        let mut disabled_service = service.clone();
        disabled_service.policy.health_check = edge_domain::HealthCheckPolicy::Disabled;
        assert!(selector.select(&disabled_service).is_some());

        let stale = selector
            .apply_availability(
                &snapshot,
                availability(
                    1,
                    UpstreamAvailability::Healthy,
                    UpstreamAvailability::Healthy,
                ),
            )
            .unwrap_err();
        assert_eq!(stale.code, ErrorCode::RuntimeCommandRejected);
        selector
            .apply_availability(
                &snapshot,
                availability(
                    3,
                    UpstreamAvailability::Healthy,
                    UpstreamAvailability::Healthy,
                ),
            )
            .unwrap();
        let mut wrong_revision = availability(
            4,
            UpstreamAvailability::Unhealthy,
            UpstreamAvailability::Unhealthy,
        );
        wrong_revision.revision_id = ConfigRevisionId::new("wrong");
        assert_eq!(
            selector
                .apply_availability(&snapshot, wrong_revision)
                .unwrap_err()
                .code,
            ErrorCode::RuntimeCommandRejected
        );
        assert!(selector.select(&service).is_some());
    }

    #[test]
    fn activate_config_command_commits_config_and_availability_atomically() {
        use edge_ports::{HealthAvailabilitySnapshot, HealthGeneration, UpstreamHealthKey};

        let address = "127.0.0.1:3001".parse().unwrap();
        let mut service = service_with_upstream("app", address);
        service.policy.health_check = edge_domain::HealthCheckPolicy::Http(
            edge_domain::HttpHealthCheckPolicy::new("/health", 1_000, 100, 1, 1, 200, 399).unwrap(),
        );
        let current = snapshot_for_runtime(vec![], vec![service.clone()]);
        let mut active = std::sync::Arc::new(current.clone());
        let mut selector = RuntimeUpstreamSelector::from_snapshot(&current).unwrap();
        let mut next = current.clone();
        next.revision_id = ConfigRevisionId::new("rev-next");
        let key = UpstreamHealthKey {
            service_id: ServiceId::new("app"),
            upstream_id: UpstreamId::new("app-1"),
        };
        let availability = HealthAvailabilitySnapshot {
            revision_id: next.revision_id.clone(),
            generation: HealthGeneration(5),
            entries: BTreeMap::from([(key.clone(), UpstreamAvailability::Unhealthy)]),
        };

        let ack = handle_runtime_command(
            CoreCommand::ActivateConfigSnapshot {
                snapshot: next.clone(),
                availability,
            },
            &mut active,
            &mut selector,
        );
        assert!(ack.is_success());
        assert_eq!(active.revision_id, next.revision_id);
        assert!(selector.select(&service).is_none());

        let mut invalid_next = next.clone();
        invalid_next.revision_id = ConfigRevisionId::new("rev-invalid");
        let invalid = HealthAvailabilitySnapshot {
            revision_id: invalid_next.revision_id.clone(),
            generation: HealthGeneration(6),
            entries: BTreeMap::new(),
        };
        let rejected = handle_runtime_command(
            CoreCommand::ActivateConfigSnapshot {
                snapshot: invalid_next,
                availability: invalid,
            },
            &mut active,
            &mut selector,
        );
        assert!(!rejected.is_success());
        assert_eq!(active.revision_id, next.revision_id);
        assert!(selector.select(&service).is_none());
    }

    fn spawn_text_backend(
        body: &'static str,
    ) -> (std::net::SocketAddr, thread::JoinHandle<String>) {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 512];
            loop {
                let read = stream.read(&mut buffer).unwrap();
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
            String::from_utf8_lossy(&request).to_string()
        });
        (address, handle)
    }

    fn spawn_text_backend_for_requests(
        body: &'static str,
        expected_requests: usize,
    ) -> (std::net::SocketAddr, thread::JoinHandle<Vec<String>>) {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..expected_requests {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut buffer = [0_u8; 512];
                loop {
                    let read = stream.read(&mut buffer).unwrap();
                    request.extend_from_slice(&buffer[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).unwrap();
                requests.push(String::from_utf8_lossy(&request).to_string());
            }
            requests
        });
        (address, handle)
    }

    fn request_host(listen: std::net::SocketAddr, host: &str) -> String {
        request_host_path(listen, host, "/")
    }

    fn request_host_path(listen: std::net::SocketAddr, host: &str, path: &str) -> String {
        let mut client = StdTcpStream::connect(listen).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        write!(
            client,
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        response
    }

    fn request_fake_tls_host(
        listen: std::net::SocketAddr,
        handshake_marker: &[u8],
        host: &str,
    ) -> String {
        let mut client = StdTcpStream::connect(listen).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(handshake_marker).unwrap();
        write!(client, "GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        response
    }

    fn spawn_reset_backend() -> (std::net::SocketAddr, thread::JoinHandle<String>) {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 512];
            loop {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            drop(stream);
            String::from_utf8_lossy(&request).to_string()
        });
        (address, handle)
    }

    fn spawn_slow_response_backend(
        hold_for: Duration,
    ) -> (std::net::SocketAddr, thread::JoinHandle<String>) {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let accept_deadline = std::time::Instant::now() + Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() >= accept_deadline {
                            return String::new();
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("slow response backend accept failed: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 512];
            loop {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            thread::sleep(hold_for);
            String::from_utf8_lossy(&request).to_string()
        });
        (address, handle)
    }

    fn spawn_chunked_hold_backend(
        hold_for: Duration,
    ) -> (std::net::SocketAddr, thread::JoinHandle<String>) {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(15)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 512];
            loop {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n4\r\nwiki\r\n0\r\n\r\n",
                )
                .unwrap();
            thread::sleep(hold_for);
            String::from_utf8_lossy(&request).to_string()
        });
        (address, handle)
    }

    fn spawn_raw_response_backend(
        response: &'static [u8],
    ) -> (std::net::SocketAddr, thread::JoinHandle<String>) {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 512];
            loop {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream.write_all(response).unwrap();
            String::from_utf8_lossy(&request).to_string()
        });
        (address, handle)
    }

    fn run_raw_response_through_mio(
        method: &str,
        raw_response: &'static [u8],
    ) -> (Vec<u8>, String, Vec<ResourceAccountingEvent>) {
        let (api_addr, api_backend) = spawn_raw_response_backend(raw_response);
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "api",
                "api.example.test",
                "/",
                "api-service",
            )],
            vec![service_with_upstream("api-service", api_addr)],
        );
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (resource_tx, resource_rx) = std::sync::mpsc::channel();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_resource_accounting_events(resource_tx),
                1,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let mut client = StdTcpStream::connect(listen).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        write!(
            client,
            "{method} / HTTP/1.1\r\nHost: api.example.test\r\n\r\n"
        )
        .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = Vec::new();
        let _ = client.read_to_end(&mut response);

        let upstream_request = api_backend.join().unwrap();
        runtime_thread.join().unwrap();
        let resource_events = resource_rx.try_iter().collect();
        (response, upstream_request, resource_events)
    }

    fn spawn_large_response_backend(
        body_len: usize,
    ) -> (std::net::SocketAddr, thread::JoinHandle<String>) {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(15)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 512];
            loop {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }

            let headers = format!("HTTP/1.1 200 OK\r\nContent-Length: {body_len}\r\n\r\n");
            stream.write_all(headers.as_bytes()).unwrap();
            let chunk = vec![b'a'; 1024];
            let mut remaining = body_len;
            while remaining > 0 {
                let write_len = remaining.min(chunk.len());
                stream.write_all(&chunk[..write_len]).unwrap();
                remaining -= write_len;
            }
            String::from_utf8_lossy(&request).to_string()
        });
        (address, handle)
    }

    fn spawn_websocket_backend() -> (std::net::SocketAddr, thread::JoinHandle<String>) {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(15)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 512];
            loop {
                let read = stream.read(&mut buffer).unwrap();
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                )
                .unwrap();
            let mut message = [0_u8; 4];
            stream.read_exact(&mut message).unwrap();
            stream.write_all(b"pong").unwrap();
            String::from_utf8_lossy(&request).to_string()
        });
        (address, handle)
    }

    #[test]
    fn exposes_crate_name() {
        assert_eq!(crate_name(), "edge-core");
    }

    #[test]
    fn token_allocator_does_not_duplicate_tokens() {
        let mut allocator = TokenAllocator::default();

        assert_ne!(allocator.allocate(), allocator.allocate());
    }

    #[test]
    fn token_allocator_recycles_tokens() {
        let mut allocator = TokenAllocator::default();
        let token = allocator.allocate();
        allocator.release(token);

        assert_eq!(allocator.allocate(), token);
    }

    #[test]
    fn connection_table_insert_get_remove() {
        let token = ConnectionToken::new(1);
        let mut table = ConnectionTable::default();
        table.insert(Connection {
            token,
            state: ConnectionState::Accepted,
        });

        assert_eq!(table.get(token).unwrap().state, ConnectionState::Accepted);
        assert!(table.remove(token).is_some());
        assert!(table.is_empty());
    }

    #[test]
    fn connection_table_cleans_closed_and_failed_connections() {
        let mut table = ConnectionTable::default();
        table.insert(Connection {
            token: ConnectionToken::new(1),
            state: ConnectionState::ReadingClientRequest,
        });
        table.insert(Connection {
            token: ConnectionToken::new(2),
            state: ConnectionState::Closed,
        });
        table.insert(Connection {
            token: ConnectionToken::new(3),
            state: ConnectionState::Failed,
        });

        let removed = table.cleanup_closed();

        assert_eq!(
            removed,
            vec![ConnectionToken::new(2), ConnectionToken::new(3)]
        );
        assert_eq!(table.len(), 1);
        assert!(table.get(ConnectionToken::new(1)).is_some());
    }

    #[test]
    fn state_transition_rules_are_explicit() {
        assert!(ConnectionState::Accepted.can_transition_to(&ConnectionState::ReadingClientRequest));
        assert!(
            !ConnectionState::Accepted.can_transition_to(&ConnectionState::ReadingUpstreamResponse)
        );
    }

    #[test]
    fn connection_state_machine_covers_mvp_http_lifecycle() {
        use ConnectionState::*;

        assert!(Accepted.can_transition_to(&ReadingClientRequest));
        assert!(ReadingClientRequest.can_transition_to(&SelectingRoute));
        assert!(SelectingRoute.can_transition_to(&ConnectingUpstream));
        assert!(SelectingRoute.can_transition_to(&WritingClientResponse));
        assert!(ConnectingUpstream.can_transition_to(&WritingUpstreamRequest));
        assert!(WritingUpstreamRequest.can_transition_to(&ReadingUpstreamResponse));
        assert!(ReadingUpstreamResponse.can_transition_to(&WritingClientResponse));
        assert!(WritingClientResponse.can_transition_to(&Draining));
        assert!(Draining.can_transition_to(&Closed));
        assert!(ReadingUpstreamResponse.can_transition_to(&TunnelingWebSocket));
        assert!(TunnelingWebSocket.can_transition_to(&Draining));
        assert!(ReadingUpstreamResponse.can_transition_to(&Failed));
        assert!(!ReadingClientRequest.can_transition_to(&ReadingUpstreamResponse));
        assert!(!ReadingClientRequest.can_transition_to(&TunnelingWebSocket));
        assert!(!SelectingRoute.can_transition_to(&ReadingUpstreamResponse));
    }

    #[test]
    fn phase009_websocket_flow_control_pauses_each_ingress_at_its_owned_limit() {
        let limits = ResourceLimits {
            max_request_body_bytes: 8,
            max_response_buffer_bytes: 12,
            ..ResourceLimits::default()
        };

        assert_eq!(
            tunnel_flow_control(3, 4, 5, 6, &limits),
            crate::snapshot_http::TunnelFlowControl {
                client_readable: true,
                upstream_readable: true,
            }
        );
        assert_eq!(
            tunnel_flow_control(4, 4, 6, 6, &limits),
            crate::snapshot_http::TunnelFlowControl {
                client_readable: false,
                upstream_readable: false,
            }
        );
        assert_eq!(
            tunnel_flow_control(0, usize::MAX, 0, usize::MAX, &limits),
            crate::snapshot_http::TunnelFlowControl {
                client_readable: false,
                upstream_readable: false,
            }
        );
    }

    #[test]
    fn phase009_retry_request_rebuilds_selected_tls_host_and_preserves_upgrade() {
        let request = parse_http_request(
            b"GET /socket HTTP/1.1\r\nHost: public.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            &HttpLimits::default(),
        )
        .unwrap();
        let endpoint = UpstreamEndpoint::parse("https://127.0.0.1:9443/base").unwrap();
        let tls = UpstreamTlsPolicy::ServerAuthenticated {
            server_name: edge_domain::TlsServerName::parse("second.private.test").unwrap(),
            http_host: edge_domain::UpstreamHttpHost::parse("second-http.private.test").unwrap(),
            trust_bundle_ref: edge_domain::TrustBundleRef::parse("private-root").unwrap(),
        };

        let rebuilt = build_selected_upstream_request(
            &request,
            &endpoint,
            &tls,
            "127.0.0.1",
            "https",
            "public.example.test",
            true,
        )
        .unwrap();
        let rebuilt = String::from_utf8(rebuilt).unwrap();

        assert!(rebuilt.starts_with("GET /base/socket HTTP/1.1\r\n"));
        assert!(rebuilt.contains("\r\nHost: second-http.private.test\r\n"));
        assert!(rebuilt.contains("\r\nUpgrade: websocket\r\n"));
        assert!(rebuilt.contains("\r\nX-Forwarded-Host: public.example.test\r\n"));
    }

    #[test]
    fn upstream_attempt_progress_tracks_write_response_and_success() {
        let mut attempt = UpstreamAttemptProgress::default();

        attempt.begin().unwrap();
        attempt.record_request_write(7).unwrap();
        attempt.request_write_completed().unwrap();
        attempt.record_response_bytes(11).unwrap();
        attempt.succeed().unwrap();

        assert_eq!(attempt.phase(), UpstreamAttemptPhase::Terminal);
        assert_eq!(attempt.request_bytes_written(), 7);
        assert!(attempt.response_started());
        assert_eq!(attempt.terminal(), Some(UpstreamAttemptTerminal::Succeeded));
    }

    #[test]
    fn upstream_attempt_progress_saturates_byte_count_and_ignores_empty_response_chunk() {
        let mut attempt = UpstreamAttemptProgress::default();

        attempt.begin().unwrap();
        attempt.record_request_write(u64::MAX).unwrap();
        attempt.record_request_write(1).unwrap();
        attempt.request_write_completed().unwrap();
        attempt.record_response_bytes(0).unwrap();

        assert_eq!(attempt.request_bytes_written(), u64::MAX);
        assert!(!attempt.response_started());
        assert_eq!(attempt.phase(), UpstreamAttemptPhase::AwaitingResponse);
    }

    #[test]
    fn upstream_attempt_progress_rejects_changes_after_terminal() {
        let mut attempt = UpstreamAttemptProgress::default();

        attempt.begin().unwrap();
        attempt.fail(UpstreamAttemptFailure::Connect).unwrap();

        assert!(attempt.record_request_write(1).is_err());
        assert!(attempt.fail(UpstreamAttemptFailure::Read).is_err());
        assert!(attempt.succeed().is_err());
        assert_eq!(
            attempt.terminal(),
            Some(UpstreamAttemptTerminal::Failed(
                UpstreamAttemptFailure::Connect
            ))
        );
    }

    #[test]
    fn upstream_attempt_failure_mapping_preserves_gateway_responses() {
        for failure in [
            UpstreamAttemptFailure::Connect,
            UpstreamAttemptFailure::Write,
            UpstreamAttemptFailure::Read,
            UpstreamAttemptFailure::ResetBeforeResponse,
            UpstreamAttemptFailure::ResetAfterResponse,
        ] {
            assert_eq!(
                upstream_failure_response_spec(failure),
                (502, "Bad Gateway")
            );
        }
        for failure in [
            UpstreamAttemptFailure::ConnectTimeout,
            UpstreamAttemptFailure::ReadTimeout,
        ] {
            assert_eq!(
                upstream_failure_response_spec(failure),
                (504, "Gateway Timeout")
            );
        }
    }

    #[test]
    fn connection_interest_follows_current_state() {
        let client_read = ConnectionState::ReadingClientRequest.io_interest();
        assert!(client_read.client_readable);
        assert!(!client_read.client_writable);
        assert!(!client_read.upstream_readable);
        assert!(!client_read.upstream_writable);

        let selecting = ConnectionState::SelectingRoute.io_interest();
        assert_eq!(selecting, ConnectionInterest::default());

        let upstream_connect = ConnectionState::ConnectingUpstream.io_interest();
        assert!(upstream_connect.upstream_writable);
        assert!(!upstream_connect.client_readable);

        let upstream_read = ConnectionState::ReadingUpstreamResponse.io_interest();
        assert!(upstream_read.upstream_readable);
        assert!(!upstream_read.upstream_writable);

        let client_write = ConnectionState::WritingClientResponse.io_interest();
        assert!(client_write.client_writable);
        assert!(!client_write.client_readable);

        let websocket = ConnectionState::TunnelingWebSocket.io_interest();
        assert!(websocket.client_readable);
        assert!(websocket.upstream_readable);
    }

    #[test]
    fn connection_events_drive_valid_state_transitions() {
        let mut connection = Connection {
            token: ConnectionToken::new(7),
            state: ConnectionState::Accepted,
        };

        connection
            .handle_event(ConnectionEvent::ClientReadable)
            .unwrap();
        assert_eq!(connection.state, ConnectionState::ReadingClientRequest);

        connection
            .handle_event(ConnectionEvent::RequestParsed)
            .unwrap();
        assert_eq!(connection.state, ConnectionState::SelectingRoute);

        connection
            .handle_event(ConnectionEvent::RouteSelected(RouteSelectionTarget::Proxy))
            .unwrap();
        assert_eq!(connection.state, ConnectionState::ConnectingUpstream);

        connection
            .handle_event(ConnectionEvent::UpstreamConnectReady)
            .unwrap();
        assert_eq!(connection.state, ConnectionState::WritingUpstreamRequest);

        connection
            .handle_event(ConnectionEvent::UpstreamWritable)
            .unwrap();
        assert_eq!(connection.state, ConnectionState::ReadingUpstreamResponse);

        connection
            .handle_event(ConnectionEvent::UpstreamReadable)
            .unwrap();
        assert_eq!(connection.state, ConnectionState::WritingClientResponse);

        connection
            .handle_event(ConnectionEvent::ClientWritable)
            .unwrap();
        assert_eq!(connection.state, ConnectionState::Draining);

        connection
            .handle_event(ConnectionEvent::ClientClosed)
            .unwrap();
        assert_eq!(connection.state, ConnectionState::Closed);
    }

    #[test]
    fn connection_events_reject_invalid_transition_without_mutating_state() {
        let mut connection = Connection {
            token: ConnectionToken::new(8),
            state: ConnectionState::Accepted,
        };

        let error = connection
            .handle_event(ConnectionEvent::UpstreamReadable)
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::RuntimeCommandRejected);
        assert_eq!(connection.state, ConnectionState::Accepted);
    }

    #[test]
    fn route_selection_can_write_immediate_response_without_upstream() {
        let mut connection = Connection {
            token: ConnectionToken::new(9),
            state: ConnectionState::SelectingRoute,
        };

        connection
            .handle_event(ConnectionEvent::RouteSelected(
                RouteSelectionTarget::ImmediateResponse,
            ))
            .unwrap();

        assert_eq!(connection.state, ConnectionState::WritingClientResponse);
        assert!(connection.state.io_interest().client_writable);
    }

    #[test]
    fn io_error_moves_connection_to_failed() {
        let mut connection = Connection {
            token: ConnectionToken::new(10),
            state: ConnectionState::ReadingUpstreamResponse,
        };

        connection.handle_event(ConnectionEvent::IoError).unwrap();

        assert_eq!(connection.state, ConnectionState::Failed);
    }

    #[test]
    fn timeout_policy_maps_state_to_explicit_runtime_action() {
        assert_eq!(
            timeout_decision_for_state(&ConnectionState::ReadingClientRequest),
            Some(ConnectionTimeoutDecision {
                kind: ConnectionTimeoutKind::ClientIdle,
                status_code: Some(408),
                reason: "Request Timeout",
                next_state: ConnectionState::WritingClientResponse,
            })
        );
        assert_eq!(
            timeout_decision_for_state(&ConnectionState::ConnectingUpstream),
            Some(ConnectionTimeoutDecision {
                kind: ConnectionTimeoutKind::UpstreamConnect,
                status_code: Some(504),
                reason: "Gateway Timeout",
                next_state: ConnectionState::WritingClientResponse,
            })
        );
        assert_eq!(
            timeout_decision_for_state(&ConnectionState::ReadingUpstreamResponse),
            Some(ConnectionTimeoutDecision {
                kind: ConnectionTimeoutKind::UpstreamRead,
                status_code: Some(504),
                reason: "Gateway Timeout",
                next_state: ConnectionState::WritingClientResponse,
            })
        );
        assert_eq!(timeout_decision_for_state(&ConnectionState::Closed), None);
    }

    #[test]
    fn state_specific_timeout_transitions_to_response_or_failure() {
        let mut upstream = Connection {
            token: ConnectionToken::new(11),
            state: ConnectionState::ConnectingUpstream,
        };

        let decision = upstream.handle_timeout().unwrap();

        assert_eq!(decision.kind, ConnectionTimeoutKind::UpstreamConnect);
        assert_eq!(decision.status_code, Some(504));
        assert_eq!(upstream.state, ConnectionState::WritingClientResponse);

        let mut client = Connection {
            token: ConnectionToken::new(12),
            state: ConnectionState::WritingClientResponse,
        };

        let decision = client.handle_timeout().unwrap();

        assert_eq!(decision.kind, ConnectionTimeoutKind::ClientWrite);
        assert_eq!(decision.status_code, None);
        assert_eq!(client.state, ConnectionState::Failed);
    }

    #[test]
    fn http_connection_io_reads_request_before_route_selection() {
        let mut io = HttpConnectionIo::new(ConnectionToken::new(13));
        let limits = HttpLimits::default();

        assert_eq!(
            io.receive_client_bytes(b"GET /", &limits).unwrap(),
            RequestReadOutcome::Incomplete
        );
        assert_eq!(io.connection.state, ConnectionState::ReadingClientRequest);

        let completed = io
            .receive_client_bytes(b" HTTP/1.1\r\nHost: example.com\r\n\r\n", &limits)
            .unwrap();

        assert!(matches!(completed, RequestReadOutcome::Complete(_)));
        assert_eq!(io.connection.state, ConnectionState::SelectingRoute);
    }

    #[test]
    fn http_connection_io_writes_upstream_request_with_backpressure() {
        let mut io = HttpConnectionIo::new(ConnectionToken::new(14));
        io.connection.state = ConnectionState::SelectingRoute;

        io.begin_upstream_connect().unwrap();
        assert_eq!(io.connection.state, ConnectionState::ConnectingUpstream);

        io.upstream_connected(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec())
            .unwrap();
        assert_eq!(io.connection.state, ConnectionState::WritingUpstreamRequest);
        assert!(io.connection.state.io_interest().upstream_writable);

        assert_eq!(io.advance_upstream_write(8).unwrap(), 8);
        assert_eq!(io.connection.state, ConnectionState::WritingUpstreamRequest);
        assert!(io.upstream_write_buffer().remaining_len() > 0);

        let remaining = io.upstream_write_buffer().remaining_len();
        assert_eq!(io.advance_upstream_write(remaining).unwrap(), remaining);
        assert_eq!(
            io.connection.state,
            ConnectionState::ReadingUpstreamResponse
        );
        assert!(io.connection.state.io_interest().upstream_readable);
    }

    #[test]
    fn http_connection_io_streams_upstream_response_to_client_buffer() {
        let mut io = HttpConnectionIo::new(ConnectionToken::new(15));
        io.connection.state = ConnectionState::SelectingRoute;
        io.begin_upstream_connect().unwrap();
        io.upstream_connected(vec![b'x']).unwrap();
        io.advance_upstream_write(1).unwrap();

        io.receive_upstream_bytes(b"HTTP/1.1 200 OK\r\n").unwrap();
        io.receive_upstream_bytes(b"Content-Length: 2\r\n\r\nok")
            .unwrap();
        assert_eq!(io.client_write_buffer().remaining_len(), 40);

        io.finish_upstream_response().unwrap();
        assert_eq!(io.connection.state, ConnectionState::WritingClientResponse);
        assert!(io.connection.state.io_interest().client_writable);

        assert_eq!(io.advance_client_write(10).unwrap(), 10);
        assert_eq!(io.connection.state, ConnectionState::WritingClientResponse);

        let remaining = io.client_write_buffer().remaining_len();
        assert_eq!(io.advance_client_write(remaining).unwrap(), remaining);
        assert_eq!(io.connection.state, ConnectionState::Draining);
    }

    #[test]
    fn http_connection_io_drains_client_buffer_before_upstream_response_finishes() {
        let mut io = HttpConnectionIo::new(ConnectionToken::new(151));
        io.connection.state = ConnectionState::SelectingRoute;
        io.begin_upstream_connect().unwrap();
        io.upstream_connected(vec![b'x']).unwrap();
        io.advance_upstream_write(1).unwrap();

        io.receive_upstream_bytes(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe")
            .unwrap();
        assert_eq!(io.advance_client_write(8).unwrap(), 8);

        assert_eq!(
            io.connection.state,
            ConnectionState::ReadingUpstreamResponse
        );
        assert!(io.client_write_buffer().remaining_len() > 0);
    }

    #[test]
    fn http_connection_io_clears_completed_streaming_response_history() {
        let mut io = HttpConnectionIo::new(ConnectionToken::new(152));
        io.connection.state = ConnectionState::SelectingRoute;
        io.begin_upstream_connect().unwrap();
        io.upstream_connected(vec![b'x']).unwrap();
        io.advance_upstream_write(1).unwrap();
        io.receive_upstream_bytes(b"part").unwrap();

        assert_eq!(io.advance_client_write(4).unwrap(), 4);

        assert_eq!(
            io.connection.state,
            ConnectionState::ReadingUpstreamResponse
        );
        assert!(io.client_write_buffer().bytes().is_empty());
        assert_eq!(io.client_write_buffer().remaining_len(), 0);
    }

    #[test]
    fn http_connection_io_queues_immediate_error_response_after_route_selection() {
        let mut io = HttpConnectionIo::new(ConnectionToken::new(16));
        io.connection.state = ConnectionState::SelectingRoute;

        io.queue_client_response(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec())
            .unwrap();

        assert_eq!(io.connection.state, ConnectionState::WritingClientResponse);
        assert_eq!(io.client_write_buffer().remaining_len(), 45);
    }

    #[test]
    fn timer_queue_expires_in_order() {
        let now = Instant::now();
        let mut timers = TimerQueue::default();
        timers.schedule(ConnectionToken::new(2), now + Duration::from_secs(2));
        timers.schedule(ConnectionToken::new(1), now + Duration::from_secs(1));

        assert_eq!(
            timers.pop_expired(now + Duration::from_secs(1)),
            vec![ConnectionToken::new(1)]
        );
        assert_eq!(
            timers.pop_expired(now + Duration::from_secs(2)),
            vec![ConnectionToken::new(2)]
        );
    }

    #[test]
    fn bounded_command_queue_reports_full() {
        let mut queue = BoundedCommandQueue::new(1);
        queue.push(CoreCommand::RefreshRouteTable).unwrap();

        assert_eq!(queue.push(CoreCommand::Shutdown), Err(QueueError::Full));
    }

    #[test]
    fn command_ack_success_and_failure_are_represented() {
        assert!(CommandAck::accepted().is_success());
        assert!(!CommandAck::rejected(AppError::new(
            ErrorCode::RuntimeCommandRejected,
            "rejected",
        ))
        .is_success());
    }

    #[test]
    fn runtime_command_channel_wakes_registered_mio_poll() {
        let mut poll = mio::Poll::new().unwrap();
        let mut events = mio::Events::with_capacity(8);
        let waker_token = mio::Token(99);
        let (mut client, mut receiver) = runtime_command_channel(1);
        receiver
            .install_waker(poll.registry(), waker_token)
            .unwrap();

        let sender = thread::spawn(move || client.send(CoreCommand::RefreshRouteTable));

        poll.poll(&mut events, Some(Duration::from_secs(1)))
            .unwrap();
        assert!(events.iter().any(|event| event.token() == waker_token));

        let mut commands = Some(receiver);
        let mut current_snapshot = std::sync::Arc::new(snapshot());
        assert!(drain_runtime_commands(&mut commands, &mut current_snapshot));
        assert!(sender.join().unwrap().is_success());
    }

    #[test]
    fn worker_event_queue_wakes_with_event() {
        let mut queue = WorkerEventQueue::default();
        queue.push(WorkerEvent::ConfigSnapshotReady(snapshot()));

        assert!(matches!(
            queue.pop(),
            Some(WorkerEvent::ConfigSnapshotReady(_))
        ));
    }

    #[test]
    fn resource_limit_rejects_excess_connections() {
        let mut runtime = CoreRuntime::new(8);
        let limits = ResourceLimits {
            max_connections: 1,
            ..ResourceLimits::default()
        };
        runtime
            .accept_connection(ConnectionToken::new(1), &limits)
            .unwrap();

        assert!(runtime
            .accept_connection(ConnectionToken::new(2), &limits)
            .is_err());
    }

    #[test]
    fn runtime_cleanup_removes_closed_connections() {
        let mut runtime = CoreRuntime::new(8);
        runtime.connections.insert(Connection {
            token: ConnectionToken::new(1),
            state: ConnectionState::Accepted,
        });
        runtime.connections.insert(Connection {
            token: ConnectionToken::new(2),
            state: ConnectionState::Closed,
        });

        let removed = runtime.cleanup_closed_connections();

        assert_eq!(removed, vec![ConnectionToken::new(2)]);
        assert_eq!(runtime.connections.len(), 1);
    }

    #[test]
    fn apply_config_snapshot_command_swaps_snapshot() {
        let mut runtime = CoreRuntime::new(8);
        let ack = runtime.handle_command(CoreCommand::ApplyConfigSnapshot {
            snapshot: snapshot(),
        });

        assert!(ack.is_success());
        assert_eq!(
            runtime.current_snapshot.unwrap().revision_id.as_str(),
            "rev-1"
        );
    }

    #[test]
    fn shutdown_command_marks_runtime() {
        let mut runtime = CoreRuntime::new(8);

        runtime.handle_command(CoreCommand::Shutdown);

        assert!(runtime.shutting_down);
    }

    #[test]
    fn parses_basic_get_request() {
        let request = parse_http_request(
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            &HttpLimits::default(),
        )
        .unwrap();

        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/");
        assert_eq!(request.header_value("Host"), Some("example.com"));
    }

    #[test]
    fn rejects_transfer_encoding_content_length_conflict() {
        let error = parse_http_request(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\nabc",
            &HttpLimits::default(),
        )
        .unwrap_err();

        assert_eq!(
            error.code,
            ErrorCode::HttpTransferEncodingContentLengthConflict
        );
    }

    #[test]
    fn rejects_malformed_content_length() {
        let error = parse_http_request(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: nope\r\n\r\nabc",
            &HttpLimits::default(),
        )
        .unwrap_err();

        assert_eq!(error.code, ErrorCode::HttpMalformedRequest);
    }

    #[test]
    fn rejects_conflicting_duplicate_content_length() {
        let error = parse_http_request(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd",
            &HttpLimits::default(),
        )
        .unwrap_err();

        assert_eq!(
            error.code,
            ErrorCode::HttpTransferEncodingContentLengthConflict
        );
    }

    #[test]
    fn rejects_chunked_request_for_mvp() {
        let error = parse_http_request(
            b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
            &HttpLimits::default(),
        )
        .unwrap_err();

        assert_eq!(error.code, ErrorCode::HttpMalformedRequest);
    }

    #[test]
    fn client_request_buffer_waits_for_complete_body() {
        let mut buffer = ClientRequestBuffer::default();
        let limits = HttpLimits::default();

        assert_eq!(
            buffer
                .push(
                    b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhe",
                    &limits
                )
                .unwrap(),
            RequestReadOutcome::Incomplete
        );
        assert_eq!(
            buffer.push(b"llo", &limits).unwrap(),
            RequestReadOutcome::Complete(
                b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello".to_vec()
            )
        );
    }

    #[test]
    fn client_request_buffer_transfers_completed_bytes_and_resets_for_reuse() {
        let mut buffer = ClientRequestBuffer::default();
        let limits = HttpLimits::default();
        let first = b"GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let second = b"GET /second HTTP/1.1\r\nHost: example.com\r\n\r\n";

        assert_eq!(
            buffer.push(first, &limits).unwrap(),
            RequestReadOutcome::Complete(first.to_vec())
        );
        assert_eq!(
            buffer.push(second, &limits).unwrap(),
            RequestReadOutcome::Complete(second.to_vec())
        );
    }

    #[test]
    fn write_buffer_try_append_preserves_history_and_remaining_byte_order() {
        let mut buffer = WriteBuffer::new(b"abc".to_vec());
        assert_eq!(buffer.advance(2), 2);

        buffer.try_append(b"def").unwrap();

        assert_eq!(buffer.bytes(), b"abcdef");
        assert_eq!(buffer.remaining(), b"cdef");
        assert_eq!(buffer.remaining_len(), 4);
    }

    #[test]
    fn write_buffer_failed_growth_and_early_reset_do_not_mutate_owner() {
        let mut buffer = WriteBuffer::new(b"payload".to_vec());
        assert_eq!(buffer.advance(3), 3);
        let before = buffer.clone();

        let error = buffer.try_reserve_append(usize::MAX).unwrap_err();

        assert_eq!(error.code, ErrorCode::ResourceAllocationFailed);
        assert_eq!(buffer, before);
        assert!(!buffer.clear_if_complete());
        assert_eq!(buffer, before);
    }

    #[test]
    fn write_buffer_complete_owner_can_be_explicitly_reset() {
        let mut buffer = WriteBuffer::new(b"done".to_vec());
        assert_eq!(buffer.advance(4), 4);

        assert!(buffer.clear_if_complete());
        assert!(buffer.bytes().is_empty());
        assert!(buffer.remaining().is_empty());
        assert!(buffer.is_complete());
    }

    #[test]
    fn write_buffer_drain_resets_complete_history_and_preserves_partial_tail() {
        let mut buffer = WriteBuffer::new(b"abcdef".to_vec());
        let capacity = buffer.bytes.capacity();

        assert_eq!(buffer.advance_and_clear_if_complete(2), 2);
        assert_eq!(buffer.bytes(), b"abcdef");
        assert_eq!(buffer.remaining(), b"cdef");

        assert_eq!(buffer.advance_and_clear_if_complete(4), 4);
        assert!(buffer.bytes().is_empty());
        assert!(buffer.remaining().is_empty());
        assert_eq!(buffer.bytes.capacity(), capacity);
    }

    #[test]
    fn plaintext_client_tunnel_transfer_bypasses_staging_and_reuses_output_capacity() {
        let payload = vec![b'x'; FIXED_RESPONSE_BUFFER_RESERVE_BYTES];
        let mut transport = ClientTransport::plaintext();
        let mut output = PendingSocketOutput::new();

        assert_eq!(
            output
                .pull_tunnel_plaintext(&mut transport, &payload)
                .unwrap(),
            payload.len()
        );
        assert_eq!(output.remaining(), payload);
        let first_capacity = output.buffer.bytes.capacity();
        assert_eq!(output.advance(payload.len()), payload.len());

        assert_eq!(
            output
                .pull_tunnel_plaintext(&mut transport, &payload)
                .unwrap(),
            payload.len()
        );
        assert_eq!(output.buffer.bytes.capacity(), first_capacity);
        let ClientTransport::Plaintext(transport) = transport else {
            panic!("expected plaintext transport");
        };
        assert!(transport.socket_output.is_empty());
    }

    #[test]
    fn plaintext_upstream_tunnel_transfer_bypasses_staging_and_reuses_output_capacity() {
        let payload = vec![b'y'; FIXED_RESPONSE_BUFFER_RESERVE_BYTES];
        let mut transport = UpstreamTransport::plaintext();
        let mut output = WriteBuffer::default();

        assert_eq!(
            transport
                .queue_tunnel_plaintext(&payload, &mut output)
                .unwrap(),
            payload.len()
        );
        assert_eq!(output.remaining(), payload);
        let first_capacity = output.bytes.capacity();
        assert_eq!(output.advance(payload.len()), payload.len());

        assert_eq!(
            transport
                .queue_tunnel_plaintext(&payload, &mut output)
                .unwrap(),
            payload.len()
        );
        assert_eq!(output.bytes.capacity(), first_capacity);
        let UpstreamTransport::Plaintext(transport) = transport else {
            panic!("expected plaintext transport");
        };
        assert!(transport.socket_output.is_empty());
    }

    fn payload_policy(limit_bytes: usize) -> RuntimeResourcePolicy {
        RuntimeResourcePolicy::try_new(1, limit_bytes).unwrap()
    }

    #[test]
    fn payload_budget_ledger_accepts_exact_fit_and_rejects_fit_plus_one_atomically() {
        let policy = payload_policy(MIN_MAX_INFLIGHT_PAYLOAD_BYTES);
        let mut ledger = PayloadBudgetLedger::new(policy, 7);

        let charge = ledger
            .reserve(
                11,
                PayloadClass::Request,
                policy.max_inflight_payload_bytes(),
                7,
            )
            .unwrap();
        assert_eq!(ledger.used_bytes(), policy.max_inflight_payload_bytes());
        assert_eq!(ledger.live_charge_count(), 1);

        let error = ledger
            .reserve(12, PayloadClass::ClientResponse, 1, 7)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ResourcePayloadCapacityReached);
        assert_eq!(ledger.used_bytes(), policy.max_inflight_payload_bytes());
        assert_eq!(ledger.live_charge_count(), 1);
        assert_eq!(
            ledger.charge(charge).unwrap().charged_bytes(),
            policy.max_inflight_payload_bytes()
        );
    }

    #[test]
    fn payload_budget_ledger_commits_resizes_transfers_and_releases_exactly_once() {
        let mut ledger =
            PayloadBudgetLedger::new(payload_policy(MIN_MAX_INFLIGHT_PAYLOAD_BYTES), 3);
        let charge = ledger.reserve(21, PayloadClass::Request, 100, 3).unwrap();

        ledger.commit(charge, 80, 3).unwrap();
        assert_eq!(ledger.used_bytes(), 80);
        assert_eq!(
            ledger.charge(charge).unwrap().state(),
            ResourceChargeState::InUse
        );

        ledger.resize(charge, 120, 3).unwrap();
        let rejected = ledger
            .resize(charge, MIN_MAX_INFLIGHT_PAYLOAD_BYTES + 1, 3)
            .unwrap_err();
        assert_eq!(rejected.code, ErrorCode::ResourcePayloadCapacityReached);
        assert_eq!(ledger.used_bytes(), 120);
        assert_eq!(ledger.charge(charge).unwrap().charged_bytes(), 120);
        ledger
            .transfer(charge, 22, PayloadClass::RetryReplay, 3)
            .unwrap();
        let snapshot = ledger.charge(charge).unwrap();
        assert_eq!(snapshot.connection_id(), 22);
        assert_eq!(snapshot.payload_class(), PayloadClass::RetryReplay);
        assert_eq!(snapshot.charged_bytes(), 120);
        assert_eq!(snapshot.state(), ResourceChargeState::Transferred);
        assert_eq!(ledger.used_bytes(), 120);

        ledger.release(charge, 3).unwrap();
        assert_eq!(ledger.used_bytes(), 0);
        assert_eq!(ledger.live_charge_count(), 0);
    }

    #[test]
    fn payload_budget_ledger_allocation_failure_releases_the_grant() {
        let mut ledger =
            PayloadBudgetLedger::new(payload_policy(MIN_MAX_INFLIGHT_PAYLOAD_BYTES), 5);
        let charge = ledger
            .reserve(31, PayloadClass::ClientResponse, 4_096, 5)
            .unwrap();

        ledger.release_after_allocation_failure(charge, 5).unwrap();

        assert_eq!(ledger.used_bytes(), 0);
        assert_eq!(ledger.live_charge_count(), 0);
        assert_eq!(
            ErrorCode::ResourceAllocationFailed.as_str(),
            "RESOURCE_ALLOCATION_FAILED"
        );
    }

    #[test]
    fn payload_budget_ledger_fails_closed_on_stale_generation_and_double_release() {
        let mut ledger =
            PayloadBudgetLedger::new(payload_policy(MIN_MAX_INFLIGHT_PAYLOAD_BYTES), 9);
        let charge = ledger
            .reserve(41, PayloadClass::WebSocketClientToUpstream, 64, 9)
            .unwrap();

        let stale = ledger.resize(charge, 32, 8).unwrap_err();
        assert_eq!(stale.code, ErrorCode::ResourceAccountingInvariantFailed);
        assert_eq!(ledger.pressure_state(), ResourcePressureState::FailedClosed);
        assert_eq!(ledger.used_bytes(), 64);

        let rejected = ledger.reserve(42, PayloadClass::Request, 1, 9).unwrap_err();
        assert_eq!(rejected.code, ErrorCode::ResourceAccountingInvariantFailed);

        ledger.release(charge, 9).unwrap();
        let duplicate = ledger.release(charge, 9).unwrap_err();
        assert_eq!(duplicate.code, ErrorCode::ResourceAccountingInvariantFailed);
        assert_eq!(ledger.used_bytes(), 0);
    }

    #[test]
    fn payload_budget_ledger_pressure_uses_eighty_sixty_hysteresis() {
        let policy = payload_policy(MIN_MAX_INFLIGHT_PAYLOAD_BYTES);
        let limit = policy.max_inflight_payload_bytes();
        let high = limit * 80 / 100;
        let tail = limit - high;
        let mut ledger = PayloadBudgetLedger::new(policy, 12);

        let high_charge = ledger.reserve(51, PayloadClass::Request, high, 12).unwrap();
        assert_eq!(ledger.pressure_state(), ResourcePressureState::Pressured);
        let tail_charge = ledger
            .reserve(52, PayloadClass::ClientResponse, tail, 12)
            .unwrap();
        let error = ledger
            .reserve(53, PayloadClass::TlsPending, 1, 12)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ResourcePayloadCapacityReached);
        assert_eq!(ledger.pressure_state(), ResourcePressureState::Exhausted);

        ledger.release(tail_charge, 12).unwrap();
        assert_eq!(ledger.pressure_state(), ResourcePressureState::Pressured);
        ledger.release(high_charge, 12).unwrap();
        assert_eq!(ledger.pressure_state(), ResourcePressureState::Normal);
    }

    #[test]
    fn connection_admission_decision_is_explicit_and_fail_closed_first() {
        assert_eq!(
            connection_admission_decision(ResourcePressureState::Normal, 2, 3),
            ConnectionAdmissionDecision::Accepted
        );
        assert_eq!(
            connection_admission_decision(ResourcePressureState::Normal, 3, 3),
            ConnectionAdmissionDecision::RejectedConnectionLimit
        );
        assert_eq!(
            connection_admission_decision(ResourcePressureState::Pressured, 0, 3),
            ConnectionAdmissionDecision::RejectedPayloadPressure
        );
        assert_eq!(
            connection_admission_decision(ResourcePressureState::Exhausted, 3, 3),
            ConnectionAdmissionDecision::RejectedPayloadPressure
        );
        assert_eq!(
            connection_admission_decision(ResourcePressureState::FailedClosed, 3, 3),
            ConnectionAdmissionDecision::RejectedFailedClosed
        );
    }

    #[test]
    fn response_read_action_combines_global_pressure_and_local_capacity() {
        use ResponseReadInterestAction::{Keep, Pause, Resume};

        assert_eq!(
            response_read_interest_action(
                ResourcePressureState::Pressured,
                &ConnectionState::ReadingUpstreamResponse,
                true,
                0,
                64,
            ),
            Pause
        );
        assert_eq!(
            response_read_interest_action(
                ResourcePressureState::Exhausted,
                &ConnectionState::ReadingUpstreamResponse,
                false,
                0,
                64,
            ),
            Keep
        );
        assert_eq!(
            response_read_interest_action(
                ResourcePressureState::Normal,
                &ConnectionState::ReadingUpstreamResponse,
                false,
                63,
                64,
            ),
            Resume
        );
        assert_eq!(
            response_read_interest_action(
                ResourcePressureState::Normal,
                &ConnectionState::ReadingUpstreamResponse,
                true,
                64,
                64,
            ),
            Pause
        );
        assert_eq!(
            response_read_interest_action(
                ResourcePressureState::Normal,
                &ConnectionState::ReadingUpstreamResponse,
                false,
                64,
                64,
            ),
            Keep
        );
        assert_eq!(
            response_read_interest_action(
                ResourcePressureState::FailedClosed,
                &ConnectionState::HandshakingUpstreamTls,
                true,
                0,
                64,
            ),
            Keep
        );
    }

    #[test]
    fn tunnel_pressure_flow_disables_reads_without_disabling_pending_writes() {
        let local = TunnelFlowControl {
            client_readable: true,
            upstream_readable: true,
        };
        assert_eq!(
            tunnel_pressure_flow(ResourcePressureState::Normal, local),
            local
        );
        for pressure in [
            ResourcePressureState::Pressured,
            ResourcePressureState::Exhausted,
            ResourcePressureState::FailedClosed,
        ] {
            assert_eq!(
                tunnel_pressure_flow(pressure, local),
                TunnelFlowControl {
                    client_readable: false,
                    upstream_readable: false,
                }
            );
        }
        assert_eq!(tunnel_interest(false, false), None);
        assert_eq!(tunnel_interest(false, true), Some(Interest::WRITABLE));
    }

    #[test]
    fn connection_request_charge_reserves_grows_and_releases_exactly_once() {
        let policy = payload_policy(MIN_MAX_INFLIGHT_PAYLOAD_BYTES);
        let mut ledger = PayloadBudgetLedger::new(policy, 1);
        let mut charges = ConnectionPayloadCharges::default();

        charges.grow_request(&mut ledger, 61, 100).unwrap();
        charges.grow_request(&mut ledger, 61, 40).unwrap();
        assert_eq!(charges.request_bytes(&ledger), 140);
        assert_eq!(ledger.used_bytes(), 140);

        charges.release_request(&mut ledger).unwrap();
        assert_eq!(charges.request_bytes(&ledger), 0);
        assert_eq!(ledger.used_bytes(), 0);
        charges.release_request(&mut ledger).unwrap();
        assert_eq!(ledger.used_bytes(), 0);
    }

    #[test]
    fn connection_request_charge_preserves_existing_bytes_when_growth_is_rejected() {
        let policy = payload_policy(MIN_MAX_INFLIGHT_PAYLOAD_BYTES);
        let mut ledger = PayloadBudgetLedger::new(policy, 1);
        let mut charges = ConnectionPayloadCharges::default();

        charges
            .grow_request(&mut ledger, 62, policy.max_inflight_payload_bytes())
            .unwrap();
        let error = charges.grow_request(&mut ledger, 62, 1).unwrap_err();

        assert_eq!(error.code, ErrorCode::ResourcePayloadCapacityReached);
        assert_eq!(
            charges.request_bytes(&ledger),
            policy.max_inflight_payload_bytes()
        );
        charges.release_all(&mut ledger).unwrap();
        assert_eq!(ledger.used_bytes(), 0);
    }

    #[test]
    fn connection_tls_pending_charge_syncs_exact_owner_and_releases_at_zero() {
        let policy = payload_policy(MIN_MAX_INFLIGHT_PAYLOAD_BYTES);
        let mut ledger = PayloadBudgetLedger::new(policy, 1);
        let mut charges = ConnectionPayloadCharges::default();

        assert!(!charges.sync_tls_pending(&mut ledger, 63, 0).unwrap());
        assert!(charges.sync_tls_pending(&mut ledger, 63, 120).unwrap());
        assert_eq!(charges.tls_pending_bytes(&ledger), 120);
        assert_eq!(ledger.live_charge_count(), 1);
        assert!(!charges.sync_tls_pending(&mut ledger, 63, 120).unwrap());
        assert!(charges.sync_tls_pending(&mut ledger, 63, 45).unwrap());
        assert_eq!(charges.tls_pending_bytes(&ledger), 45);
        assert!(charges.sync_tls_pending(&mut ledger, 63, 0).unwrap());
        assert_eq!(charges.tls_pending_bytes(&ledger), 0);
        assert_eq!(ledger.live_charge_count(), 0);

        assert!(charges.sync_tls_pending(&mut ledger, 63, 8).unwrap());
        charges.release_all(&mut ledger).unwrap();
        assert_eq!(ledger.used_bytes(), 0);
        assert_eq!(ledger.live_charge_count(), 0);
    }

    #[test]
    fn connection_tls_pending_rejection_preserves_existing_accounting() {
        let policy = payload_policy(MIN_MAX_INFLIGHT_PAYLOAD_BYTES);
        let mut ledger = PayloadBudgetLedger::new(policy, 1);
        let filler = ledger
            .reserve(
                64,
                PayloadClass::Request,
                policy.max_inflight_payload_bytes() - 16,
                1,
            )
            .unwrap();
        let mut charges = ConnectionPayloadCharges::default();

        let error = charges.sync_tls_pending(&mut ledger, 65, 17).unwrap_err();

        assert_eq!(error.code, ErrorCode::ResourcePayloadCapacityReached);
        assert_eq!(charges.tls_pending_bytes(&ledger), 0);
        assert_eq!(ledger.live_charge_count(), 1);
        assert_eq!(
            ledger.used_bytes(),
            policy.max_inflight_payload_bytes() - 16
        );
        ledger.release(filler, 1).unwrap();
        assert_eq!(ledger.used_bytes(), 0);
    }

    #[test]
    fn connection_websocket_directional_charges_sync_and_release_independently() {
        let policy = payload_policy(MIN_MAX_INFLIGHT_PAYLOAD_BYTES);
        let mut ledger = PayloadBudgetLedger::new(policy, 1);
        let mut charges = ConnectionPayloadCharges::default();

        assert!(charges
            .sync_websocket_client_to_upstream(&mut ledger, 66, 7)
            .unwrap());
        assert!(charges
            .sync_websocket_upstream_to_client(&mut ledger, 66, 11)
            .unwrap());
        assert_eq!(charges.websocket_client_to_upstream_bytes(&ledger), 7);
        assert_eq!(charges.websocket_upstream_to_client_bytes(&ledger), 11);
        assert_eq!(ledger.used_bytes(), 18);
        assert!(!charges
            .sync_websocket_client_to_upstream(&mut ledger, 66, 7)
            .unwrap());
        assert!(charges
            .sync_websocket_client_to_upstream(&mut ledger, 66, 3)
            .unwrap());
        assert!(charges
            .sync_websocket_upstream_to_client(&mut ledger, 66, 0)
            .unwrap());
        assert_eq!(ledger.used_bytes(), 3);

        charges.release_all(&mut ledger).unwrap();
        assert_eq!(ledger.used_bytes(), 0);
        assert_eq!(ledger.live_charge_count(), 0);
    }

    #[test]
    fn connection_websocket_charge_rejection_keeps_both_direction_slots_absent() {
        let policy = payload_policy(MIN_MAX_INFLIGHT_PAYLOAD_BYTES);
        let mut ledger = PayloadBudgetLedger::new(policy, 1);
        let filler = ledger
            .reserve(
                67,
                PayloadClass::Request,
                policy.max_inflight_payload_bytes() - 5,
                1,
            )
            .unwrap();
        let mut charges = ConnectionPayloadCharges::default();

        let error = charges
            .sync_websocket_client_to_upstream(&mut ledger, 68, 6)
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::ResourcePayloadCapacityReached);
        assert_eq!(charges.websocket_client_to_upstream_bytes(&ledger), 0);
        assert_eq!(charges.websocket_upstream_to_client_bytes(&ledger), 0);
        assert_eq!(ledger.live_charge_count(), 1);
        ledger.release(filler, 1).unwrap();
        assert_eq!(ledger.used_bytes(), 0);
    }

    #[test]
    fn websocket_owner_sum_transfers_plaintext_socket_bytes_and_excludes_tls_ciphertext() {
        let mut plaintext_client = ClientTransport::plaintext();
        let mut plaintext_client_output = PendingSocketOutput::new();
        plaintext_client.queue_http_bytes(b"pong").unwrap();
        plaintext_client_output.pull_from(&mut plaintext_client, usize::MAX);
        let mut plaintext_upstream = UpstreamTransport::plaintext();
        plaintext_upstream.queue_http_bytes(b"ping").unwrap();
        let plaintext_upstream_output =
            WriteBuffer::new(plaintext_upstream.take_socket_bytes(usize::MAX));

        assert_eq!(
            websocket_pending_owner_bytes(
                2,
                3,
                &plaintext_client,
                &plaintext_client_output,
                &plaintext_upstream,
                &plaintext_upstream_output,
            ),
            Ok((7, 6))
        );

        let mut tls_client = ClientTransport::tls(Box::new(ScriptedTlsSession::established()));
        let mut tls_client_output = PendingSocketOutput::new();
        tls_client.queue_http_bytes(b"pong").unwrap();
        tls_client_output.pull_from(&mut tls_client, usize::MAX);
        let mut tls_upstream = UpstreamTransport::tls(Box::new(ScriptedTlsSession::established()));
        tls_upstream.queue_http_bytes(b"ping").unwrap();
        let tls_upstream_output = WriteBuffer::new(tls_upstream.take_socket_bytes(usize::MAX));

        assert_eq!(
            websocket_pending_owner_bytes(
                2,
                3,
                &tls_client,
                &tls_client_output,
                &tls_upstream,
                &tls_upstream_output,
            ),
            Ok((3, 2))
        );
    }

    #[test]
    fn tls_pending_owner_sum_tracks_session_to_socket_transfer_without_plaintext() {
        let mut client = ClientTransport::tls(Box::new(ScriptedTlsSession::established()));
        let mut pending_client = PendingSocketOutput::new();
        let mut upstream = UpstreamTransport::tls(Box::new(ScriptedTlsSession::established()));
        let mut pending_upstream = WriteBuffer::default();

        client.queue_http_bytes(b"response").unwrap();
        upstream.queue_http_bytes(b"request").unwrap();
        assert_eq!(
            tls_pending_owner_bytes(&client, &pending_client, &upstream, &pending_upstream),
            Ok(15)
        );

        assert_eq!(pending_client.pull_from(&mut client, 3), 3);
        pending_upstream = WriteBuffer::new(upstream.take_socket_bytes(4));
        assert_eq!(
            tls_pending_owner_bytes(&client, &pending_client, &upstream, &pending_upstream),
            Ok(15)
        );
        pending_client.advance(2);
        pending_upstream.advance(4);
        assert_eq!(
            tls_pending_owner_bytes(&client, &pending_client, &upstream, &pending_upstream),
            Ok(9)
        );

        let mut plaintext_client = ClientTransport::plaintext();
        plaintext_client.queue_http_bytes(b"not-tls").unwrap();
        let mut plaintext_pending = PendingSocketOutput::new();
        plaintext_pending.pull_from(&mut plaintext_client, usize::MAX);
        assert_eq!(
            tls_pending_owner_bytes(
                &plaintext_client,
                &plaintext_pending,
                &UpstreamTransport::plaintext(),
                &WriteBuffer::default()
            ),
            Ok(0)
        );
    }

    #[test]
    fn upstream_and_retry_pair_reservation_rolls_back_when_second_charge_is_rejected() {
        let policy = payload_policy(MIN_MAX_INFLIGHT_PAYLOAD_BYTES);
        let limit = policy.max_inflight_payload_bytes();
        let mut ledger = PayloadBudgetLedger::new(policy, 1);
        let existing = ledger
            .reserve(70, PayloadClass::Request, limit - 100, 1)
            .unwrap();
        let mut charges = ConnectionPayloadCharges::default();

        let error = charges
            .reserve_upstream_and_retry(&mut ledger, 71, 60, 60)
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::ResourcePayloadCapacityReached);
        assert_eq!(ledger.used_bytes(), limit - 100);
        assert_eq!(ledger.live_charge_count(), 1);
        assert_eq!(charges.upstream_bytes(&ledger), 0);
        assert_eq!(charges.retry_replay_bytes(&ledger), 0);
        ledger.release(existing, 1).unwrap();
    }

    #[test]
    fn upstream_and_retry_pair_reservation_releases_exact_bytes_at_terminal() {
        let policy = payload_policy(MIN_MAX_INFLIGHT_PAYLOAD_BYTES);
        let mut ledger = PayloadBudgetLedger::new(policy, 1);
        let mut charges = ConnectionPayloadCharges::default();

        charges
            .reserve_upstream_and_retry(&mut ledger, 72, 512, 512)
            .unwrap();

        assert_eq!(charges.upstream_bytes(&ledger), 512);
        assert_eq!(charges.retry_replay_bytes(&ledger), 512);
        assert_eq!(ledger.used_bytes(), 1_024);
        assert_eq!(ledger.live_charge_count(), 2);
        charges.release_all(&mut ledger).unwrap();
        assert_eq!(ledger.used_bytes(), 0);
        assert_eq!(ledger.live_charge_count(), 0);
    }

    #[test]
    fn upstream_replacement_grant_swaps_charge_only_after_success() {
        let policy = payload_policy(MIN_MAX_INFLIGHT_PAYLOAD_BYTES);
        let mut ledger = PayloadBudgetLedger::new(policy, 1);
        let mut charges = ConnectionPayloadCharges::default();
        charges
            .reserve_upstream_and_retry(&mut ledger, 73, 120, 80)
            .unwrap();
        charges
            .commit_upstream_and_retry(&mut ledger, 120, 80)
            .unwrap();

        let replacement = charges
            .reserve_upstream_replacement(&mut ledger, 73, 150)
            .unwrap();
        assert_eq!(ledger.used_bytes(), 350);
        assert_eq!(ledger.live_charge_count(), 3);
        assert_eq!(charges.upstream_bytes(&ledger), 120);

        charges
            .commit_upstream_replacement(&mut ledger, replacement, 150)
            .unwrap();
        assert_eq!(charges.upstream_bytes(&ledger), 150);
        assert_eq!(charges.retry_replay_bytes(&ledger), 80);
        assert_eq!(ledger.used_bytes(), 230);
        assert_eq!(ledger.live_charge_count(), 2);
        charges.release_all(&mut ledger).unwrap();
        assert_eq!(ledger.used_bytes(), 0);
    }

    #[test]
    fn upstream_replacement_allocation_failure_preserves_current_charge() {
        let policy = payload_policy(MIN_MAX_INFLIGHT_PAYLOAD_BYTES);
        let mut ledger = PayloadBudgetLedger::new(policy, 1);
        let mut charges = ConnectionPayloadCharges::default();
        charges
            .reserve_upstream_and_retry(&mut ledger, 74, 120, 80)
            .unwrap();
        charges
            .commit_upstream_and_retry(&mut ledger, 120, 80)
            .unwrap();

        let replacement = charges
            .reserve_upstream_replacement(&mut ledger, 74, 150)
            .unwrap();
        charges
            .release_upstream_replacement_after_allocation_failure(&mut ledger, replacement)
            .unwrap();

        assert_eq!(charges.upstream_bytes(&ledger), 120);
        assert_eq!(charges.retry_replay_bytes(&ledger), 80);
        assert_eq!(ledger.used_bytes(), 200);
        assert_eq!(ledger.live_charge_count(), 2);
        charges.release_all(&mut ledger).unwrap();
        assert_eq!(ledger.used_bytes(), 0);
    }

    #[test]
    fn client_response_charge_grows_commits_and_releases_exactly() {
        let policy = payload_policy(MIN_MAX_INFLIGHT_PAYLOAD_BYTES);
        let mut ledger = PayloadBudgetLedger::new(policy, 1);
        let mut charges = ConnectionPayloadCharges::default();

        let first = charges
            .prepare_client_response_bytes(&mut ledger, 75, 100)
            .unwrap();
        charges
            .commit_client_response_bytes(&mut ledger, first)
            .unwrap();
        let second = charges
            .prepare_client_response_bytes(&mut ledger, 75, 140)
            .unwrap();
        charges
            .commit_client_response_bytes(&mut ledger, second)
            .unwrap();

        assert_eq!(charges.client_response_bytes(&ledger), 140);
        assert_eq!(ledger.used_bytes(), 140);
        charges.release_all(&mut ledger).unwrap();
        assert_eq!(ledger.used_bytes(), 0);
        assert_eq!(ledger.live_charge_count(), 0);
    }

    #[test]
    fn client_response_allocation_rollback_restores_previous_owner_bytes() {
        let policy = payload_policy(MIN_MAX_INFLIGHT_PAYLOAD_BYTES);
        let mut ledger = PayloadBudgetLedger::new(policy, 1);
        let mut charges = ConnectionPayloadCharges::default();
        let initial = charges
            .prepare_client_response_bytes(&mut ledger, 76, 100)
            .unwrap();
        charges
            .commit_client_response_bytes(&mut ledger, initial)
            .unwrap();

        let growth = charges
            .prepare_client_response_bytes(&mut ledger, 76, 180)
            .unwrap();
        charges
            .rollback_client_response_allocation(&mut ledger, growth)
            .unwrap();
        assert_eq!(charges.client_response_bytes(&ledger), 100);
        assert_eq!(ledger.used_bytes(), 100);

        charges.release_all(&mut ledger).unwrap();
        let fresh = charges
            .prepare_client_response_bytes(&mut ledger, 76, 80)
            .unwrap();
        charges
            .rollback_client_response_allocation(&mut ledger, fresh)
            .unwrap();
        assert_eq!(charges.client_response_bytes(&ledger), 0);
        assert_eq!(ledger.used_bytes(), 0);
        assert_eq!(ledger.live_charge_count(), 0);
    }

    #[test]
    fn client_response_rejected_growth_preserves_existing_charge() {
        let policy = payload_policy(MIN_MAX_INFLIGHT_PAYLOAD_BYTES);
        let limit = policy.max_inflight_payload_bytes();
        let mut ledger = PayloadBudgetLedger::new(policy, 1);
        let mut charges = ConnectionPayloadCharges::default();
        let initial = charges
            .prepare_client_response_bytes(&mut ledger, 77, limit)
            .unwrap();
        charges
            .commit_client_response_bytes(&mut ledger, initial)
            .unwrap();

        let error = charges
            .prepare_client_response_bytes(&mut ledger, 77, limit + 1)
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::ResourcePayloadCapacityReached);
        assert_eq!(charges.client_response_bytes(&ledger), limit);
        assert_eq!(ledger.used_bytes(), limit);
        charges.release_all(&mut ledger).unwrap();
    }

    #[test]
    fn client_response_in_use_charge_shrinks_to_live_pending_plaintext() {
        let policy = payload_policy(MIN_MAX_INFLIGHT_PAYLOAD_BYTES);
        let mut ledger = PayloadBudgetLedger::new(policy, 1);
        let mut charges = ConnectionPayloadCharges::default();
        let initial = charges
            .prepare_client_response_bytes(&mut ledger, 78, 100)
            .unwrap();
        charges
            .commit_client_response_bytes(&mut ledger, initial)
            .unwrap();

        charges
            .resize_client_response_in_use(&mut ledger, 40)
            .unwrap();

        assert_eq!(charges.client_response_bytes(&ledger), 40);
        assert_eq!(ledger.used_bytes(), 40);
        assert_eq!(ledger.live_charge_count(), 1);
        charges
            .resize_client_response_in_use(&mut ledger, 0)
            .unwrap();
        assert_eq!(ledger.used_bytes(), 0);
        assert_eq!(ledger.live_charge_count(), 0);

        let next = charges
            .prepare_client_response_bytes(&mut ledger, 78, 20)
            .unwrap();
        charges
            .commit_client_response_bytes(&mut ledger, next)
            .unwrap();
        assert_eq!(charges.client_response_bytes(&ledger), 20);
        charges.release_all(&mut ledger).unwrap();
    }

    #[test]
    fn payload_capacity_error_maps_to_safe_service_unavailable_response() {
        let response = String::from_utf8(error_response_for_code(
            ErrorCode::ResourcePayloadCapacityReached,
        ))
        .unwrap();

        assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
        assert!(response.contains("Connection: close\r\n"));
        assert!(error_response_for_code(ErrorCode::HttpRequestBodyTooLarge)
            .starts_with(b"HTTP/1.1 413 Payload Too Large\r\n"));
        assert!(error_response_for_code(ErrorCode::HttpHeaderTooLarge)
            .starts_with(b"HTTP/1.1 431 Request Header Fields Too Large\r\n"));
        assert!(error_response_for_code(ErrorCode::ResourceAllocationFailed)
            .starts_with(b"HTTP/1.1 503 Service Unavailable\r\n"));
    }

    #[test]
    fn selected_upstream_wire_plan_matches_output_without_mutating_request() {
        let request = parse_http_request(
            b"POST /items HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 4\r\n\r\ndata",
            &HttpLimits::default(),
        )
        .unwrap();
        let original = request.clone();
        let upstream = UpstreamEndpoint::parse("http://127.0.0.1:8080/base").unwrap();
        let tls = UpstreamTlsPolicy::Disabled;

        let planned = planned_selected_upstream_request_len(
            &request,
            &upstream,
            &tls,
            "127.0.0.1",
            "http",
            "api.example.test",
            false,
        )
        .unwrap();
        let output = build_selected_upstream_request(
            &request,
            &upstream,
            &tls,
            "127.0.0.1",
            "http",
            "api.example.test",
            false,
        )
        .unwrap();

        assert_eq!(planned, output.len());
        assert_eq!(request, original);
        assert!(output.ends_with(b"\r\ndata"));
    }

    #[test]
    fn upstream_wire_length_rejects_checked_overflow() {
        assert_eq!(checked_wire_length(&[1, 2, 3]).unwrap(), 6);

        let error = checked_wire_length(&[usize::MAX, 1]).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::OutOfMemory);
        assert!(error.to_string().contains("RESOURCE_ALLOCATION_FAILED"));
    }

    #[test]
    fn client_request_buffer_rejects_oversized_header_before_parse() {
        let mut buffer = ClientRequestBuffer::default();
        let limits = HttpLimits {
            max_header_bytes: 16,
            ..HttpLimits::default()
        };

        let error = buffer
            .push(b"GET / HTTP/1.1\r\nHost: example.com", &limits)
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::HttpHeaderTooLarge);
    }

    #[test]
    fn client_request_buffer_rejects_body_larger_than_limit() {
        let mut buffer = ClientRequestBuffer::default();
        let limits = HttpLimits {
            max_body_bytes: 3,
            ..HttpLimits::default()
        };

        let error = buffer
            .push(
                b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n",
                &limits,
            )
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::HttpRequestBodyTooLarge);
    }

    #[test]
    fn rejects_connect_method() {
        let error = parse_http_request(
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n",
            &HttpLimits::default(),
        )
        .unwrap_err();

        assert_eq!(error.code, ErrorCode::HttpConnectMethodRejected);
    }

    #[test]
    fn rejects_malformed_header() {
        let error = parse_http_request(
            b"GET / HTTP/1.1\r\nHost example.com\r\n\r\n",
            &HttpLimits::default(),
        )
        .unwrap_err();

        assert_eq!(error.code, ErrorCode::HttpMalformedRequest);
    }

    #[test]
    fn rejects_oversized_headers() {
        let limits = HttpLimits {
            max_header_bytes: 10,
            ..HttpLimits::default()
        };
        let error = parse_http_request(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", &limits)
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::HttpHeaderTooLarge);
    }

    #[test]
    fn removes_standard_and_connection_named_hop_by_hop_headers() {
        let headers = vec![
            Header {
                name: "Connection".to_string(),
                value: "keep-alive, X-Custom-Hop".to_string(),
            },
            Header {
                name: "X-Custom-Hop".to_string(),
                value: "drop".to_string(),
            },
            Header {
                name: "Host".to_string(),
                value: "example.com".to_string(),
            },
        ];

        let filtered = remove_hop_by_hop_headers(&headers);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "Host");
    }

    #[test]
    fn forwarded_headers_are_generated() {
        let headers = forwarded_headers("127.0.0.1", "http", "example.com");

        assert_eq!(headers[0].name, "X-Forwarded-For");
        assert_eq!(headers[0].value, "127.0.0.1");
        assert_eq!(headers[1].value, "http");
        assert_eq!(headers[2].value, "example.com");
    }

    #[test]
    fn detects_websocket_upgrade() {
        let request = parse_http_request(
            b"GET /socket HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            &HttpLimits::default(),
        )
        .unwrap();

        assert!(is_websocket_upgrade(&request));
    }

    #[test]
    fn builds_https_redirect_location() {
        assert_eq!(
            https_redirect_location("example.com", "/api"),
            "https://example.com/api"
        );
    }

    #[test]
    fn upstream_target_parses_http_url() {
        let target = UpstreamTarget::parse_http("http://127.0.0.1:5678").unwrap();

        assert_eq!(target.host, "127.0.0.1");
        assert_eq!(target.port, 5678);
        assert_eq!(target.address(), "127.0.0.1:5678");
    }

    #[test]
    fn upstream_target_rejects_https_for_mvp() {
        let error = UpstreamTarget::parse_http("https://example.com").unwrap_err();

        assert_eq!(error.code, ErrorCode::ConfigInvalidUpstreamUrl);
    }

    #[test]
    fn route_match_host_strips_port_for_snapshot_runtime() {
        assert_eq!(
            host_for_route_match("app.example.test:8080"),
            "app.example.test"
        );
    }

    #[test]
    fn snapshot_runtime_routes_by_host_to_different_upstreams() {
        let (api_addr, api_backend) = spawn_text_backend("api");
        let snapshot = snapshot_for_runtime(
            vec![
                route_to_service("app", "app.example.test", "/", "app-service"),
                route_to_service("api", "api.example.test", "/", "api-service"),
            ],
            vec![
                Service {
                    policy: edge_domain::ServicePolicy::default(),
                    id: ServiceId::new("app-service"),
                    upstreams: vec![Upstream {
                        id: UpstreamId::new("app-service-1"),
                        url: "http://127.0.0.1:1".to_string(),
                        administrative_state: edge_domain::UpstreamAdministrativeState::Active,
                        tls: edge_domain::UpstreamTlsPolicy::Disabled,
                    }],
                },
                service_with_upstream("api-service", api_addr),
            ],
        );

        let client_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let proxy_thread = thread::spawn(move || {
            let (client, _) = client_listener.accept().unwrap();
            handle_snapshot_http_proxy_connection(
                client,
                &snapshot,
                &NoopHttp01ChallengeResponder,
                HttpLimits::default(),
                "127.0.0.1".to_string(),
            )
            .unwrap();
        });

        let mut client = StdTcpStream::connect(client_addr).unwrap();
        client
            .write_all(
                b"GET / HTTP/1.1\r\nHost: api.example.test\r\nX-Request-Id: req-client-1\r\n\r\n",
            )
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        let api_request = api_backend.join().unwrap();
        proxy_thread.join().unwrap();

        assert!(
            response.contains("HTTP/1.1 200 OK"),
            "response was {response:?}; upstream request was {api_request:?}"
        );
        assert!(response.ends_with("api"), "response was {response:?}");
        assert!(
            api_request.contains("Host: api.example.test"),
            "upstream request was {api_request:?}"
        );
    }

    #[test]
    fn snapshot_mio_runtime_routes_request_without_per_connection_thread() {
        let (api_addr, api_backend) = spawn_text_backend("api");
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "api",
                "api.example.test",
                "/",
                "api-service",
            )],
            vec![service_with_upstream("api-service", api_addr)],
        );
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (resource_tx, resource_rx) = std::sync::mpsc::channel::<ResourceAccountingEvent>();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_resource_accounting_events(resource_tx),
                1,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let mut client = StdTcpStream::connect(listen).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .write_all(
                b"GET / HTTP/1.1\r\nHost: api.example.test\r\nX-Request-Id: req-client-1\r\n\r\n",
            )
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        let api_request = api_backend.join().unwrap();
        runtime_thread.join().unwrap();
        let resource_events: Vec<_> = resource_rx.try_iter().collect();

        assert!(
            response.contains("HTTP/1.1 200 OK"),
            "response was {response:?}; upstream request was {api_request:?}"
        );
        assert!(response.ends_with("api"), "response was {response:?}");
        assert!(
            api_request.contains("Host: api.example.test"),
            "upstream request was {api_request:?}"
        );
        assert!(resource_events.iter().any(|event| event.used_bytes > 0));
        assert!(
            resource_events
                .iter()
                .any(|event| event.client_response_bytes > 0),
            "expected a charged client response: {resource_events:?}"
        );
        assert!(
            resource_events.iter().any(|event| event.live_charges >= 3),
            "expected request, upstream wire, and retry replay charges: {resource_events:?}"
        );
        assert_eq!(
            resource_events.last(),
            Some(&ResourceAccountingEvent {
                used_bytes: 0,
                live_charges: 0,
                client_response_bytes: 0,
                tls_pending_bytes: 0,
                websocket_client_to_upstream_bytes: 0,
                websocket_upstream_to_client_bytes: 0,
            })
        );
    }

    #[test]
    fn snapshot_mio_runtime_tls_transport_uses_https_pipeline_without_threads() {
        let (api_addr, api_backend) = spawn_text_backend("secure");
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "api",
                "api.example.test",
                "/",
                "api-service",
            )],
            vec![service_with_upstream("api-service", api_addr)],
        );
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (resource_tx, resource_rx) = std::sync::mpsc::channel();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_tls_session_factory(ScriptedServerTlsSessionFactory::new(
                        ScriptedTlsSession::new().with_handshake_response(b"server-hello"),
                    ))
                    .with_resource_accounting_events(resource_tx),
                1,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let mut client = StdTcpStream::connect(listen).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .write_all(
                b"client-helloGET / HTTP/1.1\r\nHost: api.example.test\r\nX-Request-Id: req-tls-1\r\n\r\n",
            )
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        let api_request = api_backend.join().unwrap();
        runtime_thread.join().unwrap();
        let resource_events: Vec<_> = resource_rx.try_iter().collect();

        assert!(
            response.contains("HTTP/1.1 200 OK"),
            "response={response:?}"
        );
        assert!(
            response.ends_with("secureclose_notify"),
            "response={response:?}"
        );
        assert!(
            api_request.contains("X-Forwarded-Proto: https"),
            "upstream request={api_request:?}"
        );
        // A writable loopback socket can drain scripted TLS output before the
        // next aggregate publication. Exact TLS pending charge transitions are
        // covered by the deterministic owner-accounting tests; this runtime
        // test requires observable work and terminal zero accounting.
        assert!(
            resource_events.iter().any(|event| event.used_bytes > 0),
            "expected observable runtime charge: {resource_events:?}"
        );
        assert_eq!(
            resource_events.last(),
            Some(&ResourceAccountingEvent {
                used_bytes: 0,
                live_charges: 0,
                client_response_bytes: 0,
                tls_pending_bytes: 0,
                websocket_client_to_upstream_bytes: 0,
                websocket_upstream_to_client_bytes: 0,
            })
        );
    }

    #[test]
    fn snapshot_mio_runtime_flushes_tls_handshake_output_before_request() {
        let (api_addr, api_backend) = spawn_text_backend("secure");
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "api",
                "api.example.test",
                "/",
                "api-service",
            )],
            vec![service_with_upstream("api-service", api_addr)],
        );
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_tls_session_factory(ScriptedServerTlsSessionFactory::new(
                        ScriptedTlsSession::new().with_handshake_response(b"server-hello"),
                    )),
                1,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let mut client = StdTcpStream::connect(listen).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(b"client-hello").unwrap();
        let mut server_hello = [0_u8; 12];
        client.read_exact(&mut server_hello).unwrap();
        assert_eq!(&server_hello, b"server-hello");
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n")
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        let api_request = api_backend.join().unwrap();
        runtime_thread.join().unwrap();
        assert!(
            response.contains("HTTP/1.1 200 OK"),
            "response={response:?}"
        );
        assert!(api_request.contains("X-Forwarded-Proto: https"));
    }

    #[test]
    fn snapshot_mio_runtime_serves_http_and_https_from_one_poll_loop() {
        let (api_addr, api_backend) = spawn_text_backend_for_requests("mixed", 2);
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "api",
                "api.example.test",
                "/",
                "api-service",
            )],
            vec![service_with_upstream("api-service", api_addr)],
        );
        let http_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let http_addr = http_listener.local_addr().unwrap();
        let https_reservation = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let https_addr = https_reservation.local_addr().unwrap();
        drop(https_reservation);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                http_listener,
                SnapshotProxyConfig::new(http_addr, snapshot, HttpLimits::default())
                    .with_https_listener(
                        https_addr,
                        ScriptedServerTlsSessionFactory::new(ScriptedTlsSession::new()),
                    ),
                2,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let http_response = request_host(http_addr, "api.example.test");
        let mut https_client = StdTcpStream::connect(https_addr).unwrap();
        https_client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        https_client
            .write_all(b"client-helloGET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n")
            .unwrap();
        https_client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut https_response = String::new();
        https_client.read_to_string(&mut https_response).unwrap();

        let requests = api_backend.join().unwrap();
        runtime_thread.join().unwrap();
        assert!(http_response.ends_with("mixed"));
        assert!(https_response.ends_with("mixedclose_notify"));
        assert!(requests
            .iter()
            .any(|request| request.contains("X-Forwarded-Proto: http")));
        assert!(requests
            .iter()
            .any(|request| request.contains("X-Forwarded-Proto: https")));
    }

    #[test]
    fn snapshot_listener_tokens_never_decode_as_connection_tokens() {
        for index in 0..4 {
            let token = crate::snapshot_http::listener_token(index);
            assert_eq!(crate::snapshot_http::listener_index(token, 4), Some(index));
            assert_eq!(crate::snapshot_http::token_side(token), None);
        }
    }

    #[test]
    fn snapshot_mio_runtime_hot_replaces_tls_factory_for_new_connections() {
        let (api_addr, api_backend) = spawn_text_backend_for_requests("hot", 2);
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "api",
                "api.example.test",
                "/",
                "api-service",
            )],
            vec![service_with_upstream("api-service", api_addr)],
        );
        let http_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let http_addr = http_listener.local_addr().unwrap();
        let https_reservation = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let https_addr = https_reservation.local_addr().unwrap();
        drop(https_reservation);
        let (mut command_client, command_receiver) = runtime_command_channel(4);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                http_listener,
                SnapshotProxyConfig::new(http_addr, snapshot, HttpLimits::default())
                    .with_runtime_commands(command_receiver)
                    .with_https_listener(
                        https_addr,
                        ScriptedServerTlsSessionFactory::new(
                            ScriptedTlsSession::new().with_handshake_marker(b"old-hello"),
                        ),
                    ),
                2,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let old_response = request_fake_tls_host(https_addr, b"old-hello", "api.example.test");
        let ack = command_client.install_tls_session_factory(ScriptedServerTlsSessionFactory::new(
            ScriptedTlsSession::new().with_handshake_marker(b"new-hello"),
        ));
        assert!(ack.is_success(), "ack={ack:?}");
        let new_response = request_fake_tls_host(https_addr, b"new-hello", "api.example.test");

        let requests = api_backend.join().unwrap();
        runtime_thread.join().unwrap();
        assert!(old_response.ends_with("hotclose_notify"));
        assert!(new_response.ends_with("hotclose_notify"));
        assert_eq!(requests.len(), 2);
    }

    #[test]
    fn phase009_runtime_generation_atomically_replaces_snapshot_and_server_registry() {
        let (api_addr, api_backend) = spawn_text_backend_for_requests("generation", 2);
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "api",
                "api.example.test",
                "/",
                "api-service",
            )],
            vec![service_with_upstream("api-service", api_addr)],
        );
        let mut next = snapshot.clone();
        next.revision_id = ConfigRevisionId::new("generation-next");
        let http_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let http_addr = http_listener.local_addr().unwrap();
        let https_reservation = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let https_addr = https_reservation.local_addr().unwrap();
        drop(https_reservation);
        let (mut command_client, command_receiver) = runtime_command_channel(4);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                http_listener,
                SnapshotProxyConfig::new(http_addr, snapshot, HttpLimits::default())
                    .with_runtime_commands(command_receiver)
                    .with_https_listener(
                        https_addr,
                        ScriptedServerTlsSessionFactory::new(
                            ScriptedTlsSession::new().with_handshake_marker(b"old-generation"),
                        ),
                    ),
                2,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let old = request_fake_tls_host(https_addr, b"old-generation", "api.example.test");
        let mut server_registry = PreparedServerTlsRegistry::new();
        server_registry
            .insert(
                https_addr,
                ScriptedServerTlsSessionFactory::new(
                    ScriptedTlsSession::new().with_handshake_marker(b"new-generation"),
                ),
            )
            .unwrap();
        let availability = initial_availability_snapshot(&next);
        let ack = command_client.activate_runtime_generation(
            next,
            availability,
            server_registry,
            PreparedClientTlsRegistry::new(),
        );
        assert!(ack.is_success(), "ack={ack:?}");
        let new = request_fake_tls_host(https_addr, b"new-generation", "api.example.test");

        let requests = api_backend.join().unwrap();
        runtime_thread.join().unwrap();
        assert!(old.ends_with("generationclose_notify"));
        assert!(new.ends_with("generationclose_notify"));
        assert_eq!(requests.len(), 2);
    }

    #[test]
    fn phase009_runtime_generation_rejection_preserves_old_server_registry_and_snapshot() {
        let (api_addr, api_backend) = spawn_text_backend("preserved");
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "api",
                "api.example.test",
                "/",
                "api-service",
            )],
            vec![service_with_upstream("api-service", api_addr)],
        );
        let mut next = snapshot.clone();
        next.revision_id = ConfigRevisionId::new("rejected-generation");
        let availability = initial_availability_snapshot(&next);
        let http_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let http_addr = http_listener.local_addr().unwrap();
        let https_reservation = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let https_addr = https_reservation.local_addr().unwrap();
        drop(https_reservation);
        let (mut command_client, command_receiver) = runtime_command_channel(4);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                http_listener,
                SnapshotProxyConfig::new(http_addr, snapshot, HttpLimits::default())
                    .with_runtime_commands(command_receiver)
                    .with_https_listener(
                        https_addr,
                        ScriptedServerTlsSessionFactory::new(
                            ScriptedTlsSession::new().with_handshake_marker(b"still-old"),
                        ),
                    ),
                1,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let ack = command_client.activate_runtime_generation(
            next,
            availability,
            PreparedServerTlsRegistry::new(),
            PreparedClientTlsRegistry::new(),
        );
        assert!(matches!(
            ack,
            CommandAck::Rejected(error) if error.code == ErrorCode::RuntimeCommandRejected
        ));
        let response = request_fake_tls_host(https_addr, b"still-old", "api.example.test");

        api_backend.join().unwrap();
        runtime_thread.join().unwrap();
        assert!(response.ends_with("preservedclose_notify"));
    }

    #[test]
    fn snapshot_mio_runtime_rejects_tls_factory_without_tls_listener() {
        let (api_addr, api_backend) = spawn_text_backend("http");
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "api",
                "api.example.test",
                "/",
                "api-service",
            )],
            vec![service_with_upstream("api-service", api_addr)],
        );
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (mut command_client, command_receiver) = runtime_command_channel(2);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_runtime_commands(command_receiver),
                1,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let ack = command_client.install_tls_session_factory(ScriptedServerTlsSessionFactory::new(
            ScriptedTlsSession::new(),
        ));
        assert!(!ack.is_success());
        assert!(matches!(
            ack,
            CommandAck::Rejected(error) if error.code == ErrorCode::RuntimeCommandRejected
        ));
        let response = request_host(listen, "api.example.test");

        api_backend.join().unwrap();
        runtime_thread.join().unwrap();
        assert!(response.ends_with("http"));
    }

    #[test]
    fn snapshot_mio_runtime_rejects_combined_tls_apply_without_changing_snapshot() {
        let (api_addr, api_backend) = spawn_text_backend("original");
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "api",
                "api.example.test",
                "/",
                "api-service",
            )],
            vec![service_with_upstream("api-service", api_addr)],
        );
        let replacement = snapshot_for_runtime(vec![], vec![]);
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (mut command_client, command_receiver) = runtime_command_channel(2);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_runtime_commands(command_receiver),
                1,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let availability = initial_availability_snapshot(&replacement);
        let ack = command_client.activate_snapshot_with_tls_session_factory(
            replacement,
            availability,
            ScriptedServerTlsSessionFactory::new(ScriptedTlsSession::new()),
        );
        assert!(!ack.is_success());
        assert!(matches!(
            ack,
            CommandAck::Rejected(error) if error.code == ErrorCode::RuntimeCommandRejected
        ));

        let response = request_host(listen, "api.example.test");
        api_backend.join().unwrap();
        runtime_thread.join().unwrap();
        assert!(response.ends_with("original"));
    }

    #[test]
    fn snapshot_mio_runtime_shutdown_command_stops_poll_loop() {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (mut command_client, command_receiver) = runtime_command_channel(2);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(
                    listen,
                    snapshot_for_runtime(vec![], vec![]),
                    HttpLimits::default(),
                )
                .with_runtime_commands(command_receiver),
                usize::MAX,
                ready_tx,
            )
        });
        ready_rx.recv().unwrap();

        let ack = command_client.send(CoreCommand::Shutdown);

        assert!(ack.is_success());
        runtime_thread.join().unwrap().unwrap();
    }

    #[test]
    fn snapshot_mio_runtime_emits_access_log_without_blocking_runtime() {
        let (api_addr, api_backend) = spawn_text_backend("api");
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "api",
                "api.example.test",
                "/",
                "api-service",
            )],
            vec![service_with_upstream("api-service", api_addr)],
        );
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (access_log_tx, access_log_rx) = std::sync::mpsc::sync_channel(4);
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_access_log_sender(access_log_tx),
                1,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let mut client = StdTcpStream::connect(listen).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .write_all(
                b"GET / HTTP/1.1\r\nHost: api.example.test\r\nX-Request-Id: req-client-1\r\n\r\n",
            )
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        let api_request = api_backend.join().unwrap();
        runtime_thread.join().unwrap();
        let event = access_log_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("access log event");

        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(api_request.contains("Host: api.example.test"));
        assert_eq!(event.status_code, 200);
        assert_eq!(event.route_id.as_deref(), Some("api"));
        assert_eq!(event.upstream_id.as_deref(), Some("api-service-1"));
        assert_eq!(event.method, "GET");
        assert_eq!(event.path, "/");
        assert_eq!(event.request_id, "req-client-1");
        assert_eq!(event.revision_id, "rev-runtime");
    }

    #[test]
    fn snapshot_mio_runtime_emits_request_and_active_connection_metrics_without_blocking_runtime() {
        let (api_addr, api_backend) = spawn_text_backend("api");
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "api",
                "api.example.test",
                "/",
                "api-service",
            )],
            vec![service_with_upstream("api-service", api_addr)],
        );
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let mut client = StdTcpStream::connect(listen).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: api.example.test\r\nConnection: close\r\n\r\n")
            .unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (metric_tx, metric_rx) = std::sync::mpsc::sync_channel(128);
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_metric_publisher(std::sync::Arc::new(
                        edge_adapters::MetricChannelPublisher::new(metric_tx),
                    )),
                1,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        let api_request = api_backend.join().unwrap();
        runtime_thread.join().unwrap();
        let metrics: Vec<_> = metric_rx.try_iter().collect();

        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(api_request.contains("Host: api.example.test"));
        assert!(metrics.iter().any(|metric| metric.descriptor
            == edge_ports::MetricDescriptor::ActiveConnections
            && metric.operation == edge_ports::MetricOperation::GaugeSet(1)));
        assert!(metrics.iter().any(|metric| metric.descriptor
            == edge_ports::MetricDescriptor::ActiveConnections
            && metric.operation == edge_ports::MetricOperation::GaugeSet(0)));
        assert!(metrics.iter().any(|metric| {
            metric.descriptor == edge_ports::MetricDescriptor::RequestsTotal
                && metric
                    .labels
                    .iter()
                    .any(|(key, value)| key == "status_class" && value == "2xx")
        }));
        assert!(metrics
            .iter()
            .any(|metric| metric.descriptor == edge_ports::MetricDescriptor::RequestDuration));
        assert!(metrics.iter().any(|metric| {
            metric.descriptor == edge_ports::MetricDescriptor::UpstreamSelectionsTotal
                && metric
                    .labels
                    .contains(&("upstream_id".to_string(), "api-service-1".to_string()))
        }));
        assert!(metrics.iter().any(|metric| {
            metric.descriptor == edge_ports::MetricDescriptor::ResourcePayloadLimitBytes
        }));
        assert!(metrics.iter().any(|metric| {
            metric.descriptor == edge_ports::MetricDescriptor::ResourcePayloadBytes
                && matches!(metric.operation, edge_ports::MetricOperation::GaugeSet(value) if value > 0)
        }));
        assert!(metrics.iter().any(|metric| {
            metric.descriptor == edge_ports::MetricDescriptor::ResourcePayloadBytes
                && metric.operation == edge_ports::MetricOperation::GaugeSet(0)
        }));
    }

    #[test]
    fn snapshot_mio_runtime_counts_full_log_queue_drops_without_blocking_runtime() {
        let (api_addr, api_backend) = spawn_text_backend("api");
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "api",
                "api.example.test",
                "/",
                "api-service",
            )],
            vec![service_with_upstream("api-service", api_addr)],
        );
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (access_log_tx, _access_log_rx) = std::sync::mpsc::sync_channel(0);
        let drop_counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let runtime_drop_counter = std::sync::Arc::clone(&drop_counter);
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_access_log_sender(access_log_tx)
                    .with_log_drop_counter(runtime_drop_counter),
                1,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let mut client = StdTcpStream::connect(listen).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n")
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        let api_request = api_backend.join().unwrap();
        runtime_thread.join().unwrap();

        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(api_request.contains("Host: api.example.test"));
        assert_eq!(drop_counter.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn snapshot_mio_runtime_drops_full_tls_failure_queue_without_blocking() {
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "api",
                "api.example.test",
                "/",
                "api-service",
            )],
            vec![service_with_upstream(
                "api-service",
                "127.0.0.1:9".parse().unwrap(),
            )],
        );
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (tls_failure_tx, _tls_failure_rx) = std::sync::mpsc::sync_channel(0);
        let drop_counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let runtime_drop_counter = std::sync::Arc::clone(&drop_counter);
        let failed_tls = ScriptedTlsSession::new().with_receive_failure(AppError::new(
            ErrorCode::TlsHandshakeFailed,
            "scripted TLS failure",
        ));
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_tls_session_factory(ScriptedServerTlsSessionFactory::new(failed_tls))
                    .with_tls_failure_sender(tls_failure_tx)
                    .with_log_drop_counter(runtime_drop_counter),
                1,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let mut client = StdTcpStream::connect(listen).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        client.write_all(b"invalid-client-hello").unwrap();
        let _ = client.shutdown(std::net::Shutdown::Write);
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        runtime_thread.join().unwrap();

        assert!(response.is_empty());
        assert_eq!(drop_counter.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn snapshot_mio_runtime_emits_error_log_for_upstream_timeout_without_blocking_runtime() {
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "api",
                "api.example.test",
                "/",
                "api-service",
            )],
            vec![Service {
                policy: edge_domain::ServicePolicy::default(),
                id: ServiceId::new("api-service"),
                upstreams: vec![Upstream {
                    id: UpstreamId::new("api-service-1"),
                    url: "http://127.0.0.1:9".to_string(),
                    administrative_state: edge_domain::UpstreamAdministrativeState::Active,
                    tls: edge_domain::UpstreamTlsPolicy::Disabled,
                }],
            }],
        );
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (error_log_tx, error_log_rx) = std::sync::mpsc::sync_channel(4);
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_resource_limits(ResourceLimits {
                        idle_timeout: Duration::from_secs(10),
                        connect_timeout: Duration::from_millis(100),
                        upstream_read_timeout: Duration::from_secs(2),
                        client_write_timeout: Duration::from_secs(10),
                        ..ResourceLimits::default()
                    })
                    .with_stalled_upstream_connect()
                    .with_error_log_sender(error_log_tx),
                1,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let mut client = StdTcpStream::connect(listen).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: api.example.test\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        runtime_thread.join().unwrap();
        assert!(response.contains("HTTP/1.1 504 Gateway Timeout"));
        let event = error_log_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("runtime error log event");

        assert_eq!(event.error_code, "RUNTIME_UPSTREAM_TIMEOUT");
        assert_eq!(event.message, "upstream timed out");
        assert!(event
            .request_id
            .as_deref()
            .is_some_and(|id| id.starts_with("proxy-")));
    }

    #[test]
    fn snapshot_mio_runtime_routes_by_host_to_different_upstreams() {
        let (app_addr, app_backend) = spawn_text_backend("app");
        let (api_addr, api_backend) = spawn_text_backend("api");
        let snapshot = snapshot_for_runtime(
            vec![
                route_to_service("app", "app.example.test", "/", "app-service"),
                route_to_service("api", "api.example.test", "/", "api-service"),
            ],
            vec![
                service_with_upstream("app-service", app_addr),
                service_with_upstream("api-service", api_addr),
            ],
        );
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let mut app_client = StdTcpStream::connect(listen).unwrap();
        app_client
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        app_client
            .write_all(b"GET / HTTP/1.1\r\nHost: app.example.test\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut api_client = StdTcpStream::connect(listen).unwrap();
        api_client
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        api_client
            .write_all(b"GET / HTTP/1.1\r\nHost: api.example.test\r\nConnection: close\r\n\r\n")
            .unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default()),
                2,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let mut app_response = String::new();
        app_client.read_to_string(&mut app_response).unwrap();

        let mut api_response = String::new();
        api_client.read_to_string(&mut api_response).unwrap();

        let app_request = app_backend.join().unwrap();
        let api_request = api_backend.join().unwrap();
        runtime_thread.join().unwrap();

        assert!(
            app_response.ends_with("app"),
            "app response was {app_response:?}"
        );
        assert!(
            api_response.ends_with("api"),
            "api response was {api_response:?}"
        );
        assert!(
            app_request.contains("Host: app.example.test"),
            "app upstream request was {app_request:?}"
        );
        assert!(
            api_request.contains("Host: api.example.test"),
            "api upstream request was {api_request:?}"
        );
    }

    #[test]
    fn snapshot_mio_runtime_round_robins_new_requests_across_service_upstreams() {
        let (first_addr, first_backend) = spawn_text_backend_for_requests("first", 2);
        let (second_addr, second_backend) = spawn_text_backend_for_requests("second", 2);
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "app",
                "app.example.test",
                "/",
                "app-service",
            )],
            vec![service_with_upstreams(
                "app-service",
                &[first_addr, second_addr],
            )],
        );
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (access_log_tx, access_log_rx) = std::sync::mpsc::sync_channel(8);
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_access_log_sender(access_log_tx),
                4,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let responses: Vec<_> = (0..4)
            .map(|_| request_host(listen, "app.example.test"))
            .collect();

        let first_requests = first_backend.join().unwrap();
        let second_requests = second_backend.join().unwrap();
        runtime_thread.join().unwrap();
        let selected_upstreams: Vec<_> = access_log_rx
            .try_iter()
            .map(|event| event.upstream_id.unwrap())
            .collect();
        assert!(responses[0].ends_with("first"));
        assert!(responses[1].ends_with("second"));
        assert!(responses[2].ends_with("first"));
        assert!(responses[3].ends_with("second"));
        assert_eq!(first_requests.len(), 2);
        assert_eq!(second_requests.len(), 2);
        assert_eq!(
            selected_upstreams,
            [
                "app-service-1",
                "app-service-2",
                "app-service-1",
                "app-service-2",
            ]
        );
    }

    #[test]
    fn snapshot_mio_runtime_retries_safe_get_once_on_distinct_upstream() {
        let dead_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let dead_addr = dead_listener.local_addr().unwrap();
        drop(dead_listener);
        let (healthy_addr, healthy_backend) = spawn_text_backend("retried");
        let mut service = service_with_upstreams("app-service", &[dead_addr, healthy_addr]);
        service.policy.retry = edge_domain::RetryPolicy::new(true, 1, 32_768).unwrap();
        service.policy.passive_health = edge_domain::PassiveHealthMode::Enabled(
            edge_domain::PassiveHealthPolicy::new(2, 1_000).unwrap(),
        );
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "app",
                "app.example.test",
                "/",
                "app-service",
            )],
            vec![service],
        );
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (observation_tx, observation_rx) = std::sync::mpsc::sync_channel(2);
        let (resource_tx, resource_rx) = std::sync::mpsc::channel::<ResourceAccountingEvent>();
        let mut client = StdTcpStream::connect(listen).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: app.example.test\r\nConnection: close\r\n\r\n")
            .unwrap();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_passive_observation_dispatcher(ChannelPassiveObservationDispatcher(
                        observation_tx,
                    ))
                    .with_resource_accounting_events(resource_tx),
                1,
                ready_tx,
            )
        });
        ready_rx.recv().unwrap();

        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        runtime_thread.join().unwrap().unwrap();
        assert!(response.ends_with("retried"), "response was {response:?}");
        let observations: Vec<_> = observation_rx.try_iter().collect();
        assert_eq!(observations.len(), 2);
        assert!(matches!(
            observations[0].outcome,
            edge_ports::PassiveObservationOutcome::Failed(_)
        ));
        assert_eq!(
            observations[1].outcome,
            edge_ports::PassiveObservationOutcome::Succeeded
        );
        let resource_events: Vec<_> = resource_rx.try_iter().collect();
        assert!(
            resource_events
                .iter()
                .filter(|event| event.live_charges >= 3)
                .count()
                >= 2,
            "expected initial and replacement admission events: {resource_events:?}"
        );
        assert_eq!(
            resource_events.last(),
            Some(&ResourceAccountingEvent {
                used_bytes: 0,
                live_charges: 0,
                client_response_bytes: 0,
                tls_pending_bytes: 0,
                websocket_client_to_upstream_bytes: 0,
                websocket_upstream_to_client_bytes: 0,
            })
        );
        assert!(healthy_backend.join().unwrap().starts_with("GET "));
    }

    #[test]
    fn snapshot_mio_runtime_submits_first_response_passive_success() {
        let (backend_addr, backend) = spawn_text_backend("observed");
        let mut service = service_with_upstream("app-service", backend_addr);
        service.policy.passive_health = edge_domain::PassiveHealthMode::Enabled(
            edge_domain::PassiveHealthPolicy::new(2, 1_000).unwrap(),
        );
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "app",
                "app.example.test",
                "/",
                "app-service",
            )],
            vec![service],
        );
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (observation_tx, observation_rx) = std::sync::mpsc::sync_channel(1);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_passive_observation_dispatcher(ChannelPassiveObservationDispatcher(
                        observation_tx,
                    )),
                1,
                ready_tx,
            )
        });
        ready_rx.recv().unwrap();

        let response = request_host(listen, "app.example.test");
        let observation = observation_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        runtime_thread.join().unwrap().unwrap();
        assert!(response.ends_with("observed"));
        assert_eq!(
            observation.outcome,
            edge_ports::PassiveObservationOutcome::Succeeded
        );
        assert_eq!(
            observation.key.upstream_id,
            UpstreamId::new("app-service-1")
        );
        backend.join().unwrap();
    }

    #[test]
    fn snapshot_mio_runtime_does_not_retry_post_after_connect_failure() {
        let dead_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let dead_addr = dead_listener.local_addr().unwrap();
        drop(dead_listener);
        let second_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let second_addr = second_listener.local_addr().unwrap();
        second_listener.set_nonblocking(true).unwrap();
        let mut service = service_with_upstreams("app-service", &[dead_addr, second_addr]);
        service.policy.retry = edge_domain::RetryPolicy::new(true, 1, 32_768).unwrap();
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "app",
                "app.example.test",
                "/",
                "app-service",
            )],
            vec![service],
        );
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default()),
                1,
                ready_tx,
            )
        });
        ready_rx.recv().unwrap();
        let mut client = StdTcpStream::connect(listen).unwrap();
        client
            .write_all(b"POST / HTTP/1.1\r\nHost: app.example.test\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        runtime_thread.join().unwrap().unwrap();
        assert!(response.starts_with("HTTP/1.1 502 Bad Gateway"));
        assert!(
            matches!(second_listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }

    #[test]
    fn snapshot_mio_runtime_round_robins_https_requests_across_service_upstreams() {
        let (first_addr, first_backend) = spawn_text_backend_for_requests("first", 2);
        let (second_addr, second_backend) = spawn_text_backend_for_requests("second", 2);
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "app",
                "app.example.test",
                "/",
                "app-service",
            )],
            vec![service_with_upstreams(
                "app-service",
                &[first_addr, second_addr],
            )],
        );
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (access_log_tx, access_log_rx) = std::sync::mpsc::sync_channel(8);
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_access_log_sender(access_log_tx)
                    .with_tls_session_factory(ScriptedServerTlsSessionFactory::new(
                        ScriptedTlsSession::new(),
                    )),
                4,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let responses: Vec<_> = (0..4)
            .map(|_| request_fake_tls_host(listen, b"client-hello", "app.example.test"))
            .collect();

        let first_requests = first_backend.join().unwrap();
        let second_requests = second_backend.join().unwrap();
        runtime_thread.join().unwrap();
        let selected_upstreams: Vec<_> = access_log_rx
            .try_iter()
            .map(|event| event.upstream_id.unwrap())
            .collect();
        assert!(responses[0].contains("first"));
        assert!(responses[1].contains("second"));
        assert!(responses[2].contains("first"));
        assert!(responses[3].contains("second"));
        assert_eq!(first_requests.len(), 2);
        assert_eq!(second_requests.len(), 2);
        assert_eq!(
            selected_upstreams,
            [
                "app-service-1",
                "app-service-2",
                "app-service-1",
                "app-service-2",
            ]
        );
    }

    #[test]
    fn snapshot_mio_runtime_returns_503_without_connect_for_empty_upstream_pool() {
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "app",
                "app.example.test",
                "/",
                "app-service",
            )],
            vec![service_with_upstreams("app-service", &[])],
        );
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (metric_tx, metric_rx) = std::sync::mpsc::sync_channel(64);
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_metric_publisher(std::sync::Arc::new(
                        edge_adapters::MetricChannelPublisher::new(metric_tx),
                    )),
                1,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let response = request_host(listen, "app.example.test");

        runtime_thread.join().unwrap();
        assert!(response.contains("HTTP/1.1 503 Service Unavailable"));
        assert!(metric_rx.try_iter().any(|metric| {
            metric.descriptor == edge_ports::MetricDescriptor::UpstreamNoEligibleTotal
                && metric
                    .labels
                    .contains(&("service_id".to_string(), "app-service".to_string()))
        }));
    }

    #[test]
    fn snapshot_mio_runtime_publishes_health_503_and_recovery_through_command_queue() {
        use edge_ports::{HealthAvailabilitySnapshot, HealthGeneration, UpstreamHealthKey};

        let (backend_addr, backend) = spawn_text_backend("recovered");
        let mut service = service_with_upstream("app-service", backend_addr);
        service.policy.health_check = edge_domain::HealthCheckPolicy::Http(
            edge_domain::HttpHealthCheckPolicy::new("/health", 1_000, 100, 1, 1, 200, 399).unwrap(),
        );
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "app",
                "app.example.test",
                "/",
                "app-service",
            )],
            vec![service],
        );
        let key = UpstreamHealthKey {
            service_id: ServiceId::new("app-service"),
            upstream_id: UpstreamId::new("app-service-1"),
        };
        let availability = |generation, revision_id, value| HealthAvailabilitySnapshot {
            revision_id,
            generation: HealthGeneration(generation),
            entries: BTreeMap::from([(key.clone(), value)]),
        };
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (mut command_client, command_receiver) = runtime_command_channel(8);
        let runtime_snapshot = snapshot.clone();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, runtime_snapshot, HttpLimits::default())
                    .with_runtime_commands(command_receiver),
                2,
                ready_tx,
            )
        });
        ready_rx.recv().unwrap();

        assert!(command_client
            .send(CoreCommand::PublishUpstreamAvailability {
                snapshot: availability(
                    1,
                    snapshot.revision_id.clone(),
                    UpstreamAvailability::Unhealthy,
                ),
            })
            .is_success());
        let unavailable = request_host(listen, "app.example.test");
        assert!(unavailable.starts_with("HTTP/1.1 503 Service Unavailable"));

        assert!(!command_client
            .send(CoreCommand::PublishUpstreamAvailability {
                snapshot: availability(
                    0,
                    snapshot.revision_id.clone(),
                    UpstreamAvailability::Healthy,
                ),
            })
            .is_success());
        assert!(command_client
            .send(CoreCommand::PublishUpstreamAvailability {
                snapshot: availability(
                    1,
                    snapshot.revision_id.clone(),
                    UpstreamAvailability::Healthy,
                ),
            })
            .is_success());
        assert!(!command_client
            .send(CoreCommand::PublishUpstreamAvailability {
                snapshot: availability(
                    2,
                    ConfigRevisionId::new("wrong"),
                    UpstreamAvailability::Unhealthy,
                ),
            })
            .is_success());
        let recovered = request_host(listen, "app.example.test");

        assert!(recovered.ends_with("recovered"));
        assert!(backend.join().unwrap().contains("Host: app.example.test"));
        runtime_thread.join().unwrap().unwrap();
    }

    #[test]
    fn snapshot_mio_runtime_applies_config_snapshot_command_to_new_requests() {
        let (first_addr, first_backend) = spawn_text_backend("first");
        let (second_addr, second_backend) = spawn_text_backend("second");
        let mut first_snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "app",
                "app.example.test",
                "/",
                "app-service",
            )],
            vec![service_with_upstream("app-service", first_addr)],
        );
        first_snapshot.revision_id = ConfigRevisionId::new("rev-first");
        let mut second_snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "app",
                "app.example.test",
                "/",
                "app-service",
            )],
            vec![service_with_upstream("app-service", second_addr)],
        );
        second_snapshot.revision_id = ConfigRevisionId::new("rev-second");
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (mut command_client, command_receiver) = runtime_command_channel(8);
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, first_snapshot, HttpLimits::default())
                    .with_runtime_commands(command_receiver),
                2,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let mut first_client = StdTcpStream::connect(listen).unwrap();
        first_client
            .write_all(b"GET / HTTP/1.1\r\nHost: app.example.test\r\n\r\n")
            .unwrap();
        first_client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut first_response = String::new();
        first_client.read_to_string(&mut first_response).unwrap();
        assert!(
            first_response.ends_with("first"),
            "first response was {first_response:?}"
        );

        let ack = command_client.send(CoreCommand::ApplyConfigSnapshot {
            snapshot: second_snapshot,
        });
        assert!(ack.is_success(), "ack was {ack:?}");

        let mut second_client = StdTcpStream::connect(listen).unwrap();
        second_client
            .write_all(b"GET / HTTP/1.1\r\nHost: app.example.test\r\n\r\n")
            .unwrap();
        second_client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut second_response = String::new();
        second_client.read_to_string(&mut second_response).unwrap();

        let first_request = first_backend.join().unwrap();
        let second_request = second_backend.join().unwrap();
        runtime_thread.join().unwrap();

        assert!(
            second_response.ends_with("second"),
            "second response was {second_response:?}"
        );
        assert!(
            first_request.contains("Host: app.example.test"),
            "first upstream request was {first_request:?}"
        );
        assert!(
            second_request.contains("Host: app.example.test"),
            "second upstream request was {second_request:?}"
        );
    }

    #[test]
    fn snapshot_mio_runtime_rollback_apply_preserves_previous_route() {
        let (first_addr, first_backend) = spawn_text_backend_for_requests("first", 2);
        let (second_addr, second_backend) = spawn_text_backend("second");
        let mut first_snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "app",
                "app.example.test",
                "/",
                "app-service",
            )],
            vec![service_with_upstream("app-service", first_addr)],
        );
        first_snapshot.revision_id = ConfigRevisionId::new("rev-first");
        let mut second_snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "app",
                "app.example.test",
                "/",
                "app-service",
            )],
            vec![service_with_upstream("app-service", second_addr)],
        );
        second_snapshot.revision_id = ConfigRevisionId::new("rev-second");
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (mut command_client, command_receiver) = runtime_command_channel(8);
        let runtime_thread = thread::spawn({
            let initial_snapshot = first_snapshot.clone();
            move || {
                run_snapshot_http_proxy_mio_for_test(
                    listener,
                    SnapshotProxyConfig::new(listen, initial_snapshot, HttpLimits::default())
                        .with_runtime_commands(command_receiver),
                    3,
                    ready_tx,
                )
                .unwrap();
            }
        });
        ready_rx.recv().unwrap();

        let first_response = request_host(listen, "app.example.test");
        assert!(
            first_response.ends_with("first"),
            "first response was {first_response:?}"
        );

        let apply_ack = command_client.send(CoreCommand::ApplyConfigSnapshot {
            snapshot: second_snapshot,
        });
        assert!(apply_ack.is_success(), "apply ack was {apply_ack:?}");
        let second_response = request_host(listen, "app.example.test");
        assert!(
            second_response.ends_with("second"),
            "second response was {second_response:?}"
        );

        let rollback_ack = command_client.send(CoreCommand::ApplyConfigSnapshot {
            snapshot: first_snapshot,
        });
        assert!(
            rollback_ack.is_success(),
            "rollback ack was {rollback_ack:?}"
        );
        let rollback_response = request_host(listen, "app.example.test");
        assert!(
            rollback_response.ends_with("first"),
            "rollback response was {rollback_response:?}"
        );

        let first_requests = first_backend.join().unwrap();
        let second_request = second_backend.join().unwrap();
        runtime_thread.join().unwrap();

        assert_eq!(first_requests.len(), 2);
        assert!(
            first_requests
                .iter()
                .all(|request| request.contains("Host: app.example.test")),
            "first upstream requests were {first_requests:?}"
        );
        assert!(
            second_request.contains("Host: app.example.test"),
            "second upstream request was {second_request:?}"
        );
    }

    #[test]
    fn snapshot_mio_runtime_maps_backend_reset_to_502() {
        let (api_addr, api_backend) = spawn_reset_backend();
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "api",
                "api.example.test",
                "/",
                "api-service",
            )],
            vec![service_with_upstream("api-service", api_addr)],
        );
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (error_log_tx, error_log_rx) = std::sync::mpsc::sync_channel(4);
        let (metric_tx, metric_rx) = std::sync::mpsc::sync_channel(64);
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_error_log_sender(error_log_tx)
                    .with_metric_publisher(std::sync::Arc::new(
                        edge_adapters::MetricChannelPublisher::new(metric_tx),
                    )),
                1,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let mut client = StdTcpStream::connect(listen).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n")
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        let api_request = api_backend.join().unwrap();
        runtime_thread.join().unwrap();
        let event = error_log_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("runtime error log event");
        let metrics: Vec<_> = metric_rx.try_iter().collect();

        assert!(
            response.contains("HTTP/1.1 502 Bad Gateway"),
            "response was {response:?}; upstream request was {api_request:?}"
        );
        assert_eq!(event.error_code, "RUNTIME_UPSTREAM_BAD_GATEWAY");
        assert_eq!(event.message, "upstream returned bad gateway");
        assert!(
            api_request.contains("Host: api.example.test"),
            "upstream request was {api_request:?}"
        );
        assert!(metrics.iter().any(|metric| {
            metric.descriptor == edge_ports::MetricDescriptor::UpstreamFailuresTotal
                && metric.labels.iter().any(|(key, value)| {
                    key == "error_code" && value == "RUNTIME_UPSTREAM_BAD_GATEWAY"
                })
                && metric
                    .labels
                    .iter()
                    .any(|(key, value)| key == "route_id" && value == "api")
                && metric
                    .labels
                    .iter()
                    .any(|(key, value)| key == "upstream_id" && value == "api-service-1")
        }));
    }

    #[test]
    fn snapshot_mio_runtime_maps_upstream_read_timeout_to_504() {
        let (api_addr, api_backend) = spawn_slow_response_backend(Duration::from_millis(600));
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "api",
                "api.example.test",
                "/",
                "api-service",
            )],
            vec![service_with_upstream("api-service", api_addr)],
        );
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_resource_limits(ResourceLimits {
                        idle_timeout: Duration::from_secs(10),
                        connect_timeout: Duration::from_secs(10),
                        upstream_read_timeout: Duration::from_millis(200),
                        client_write_timeout: Duration::from_secs(10),
                        ..ResourceLimits::default()
                    }),
                1,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let mut client = StdTcpStream::connect(listen).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n")
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        let api_request = api_backend.join().unwrap();
        runtime_thread.join().unwrap();

        assert!(
            response.contains("HTTP/1.1 504 Gateway Timeout"),
            "response was {response:?}; upstream request was {api_request:?}"
        );
        assert!(
            api_request.contains("Host: api.example.test"),
            "upstream request was {api_request:?}"
        );
    }

    #[test]
    fn snapshot_mio_runtime_passes_chunked_response_without_upstream_close() {
        let (api_addr, api_backend) = spawn_chunked_hold_backend(Duration::from_millis(600));
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "api",
                "api.example.test",
                "/",
                "api-service",
            )],
            vec![service_with_upstream("api-service", api_addr)],
        );
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_resource_limits(ResourceLimits {
                        idle_timeout: Duration::from_secs(10),
                        connect_timeout: Duration::from_secs(10),
                        upstream_read_timeout: Duration::from_millis(200),
                        client_write_timeout: Duration::from_secs(10),
                        ..ResourceLimits::default()
                    }),
                1,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let mut client = StdTcpStream::connect(listen).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n")
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        runtime_thread.join().unwrap();

        assert!(
            response.contains("HTTP/1.1 200 OK"),
            "response was {response:?}"
        );
        assert!(
            response.contains("Transfer-Encoding: chunked"),
            "response was {response:?}"
        );
        assert!(response.contains("4\r\nwiki\r\n0\r\n\r\n"));
        let api_request = api_backend.join().unwrap();
        assert!(
            api_request.contains("Host: api.example.test"),
            "upstream request was {api_request:?}"
        );
    }

    #[test]
    fn snapshot_mio_runtime_completes_head_response_without_waiting_for_body() {
        let (response, upstream_request, resource_events) = run_raw_response_through_mio(
            "HEAD",
            b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\nConnection: keep-alive\r\n\r\n",
        );

        assert_eq!(
            response,
            b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\nConnection: keep-alive\r\n\r\n"
        );
        assert!(upstream_request.starts_with("HEAD / HTTP/1.1\r\n"));
        assert_eq!(
            resource_events.last(),
            Some(&ResourceAccountingEvent {
                used_bytes: 0,
                live_charges: 0,
                client_response_bytes: 0,
                tls_pending_bytes: 0,
                websocket_client_to_upstream_bytes: 0,
                websocket_upstream_to_client_bytes: 0,
            })
        );
    }

    #[test]
    fn snapshot_mio_runtime_completes_close_delimited_response_on_eof() {
        let (response, _, resource_events) = run_raw_response_through_mio(
            "GET",
            b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nclose-body",
        );

        assert!(response.ends_with(b"close-body"), "response={response:?}");
        assert_eq!(
            resource_events.last(),
            Some(&ResourceAccountingEvent {
                used_bytes: 0,
                live_charges: 0,
                client_response_bytes: 0,
                tls_pending_bytes: 0,
                websocket_client_to_upstream_bytes: 0,
                websocket_upstream_to_client_bytes: 0,
            })
        );
    }

    #[test]
    fn snapshot_mio_runtime_replaces_malformed_unstarted_response_with_502() {
        let (response, _, resource_events) =
            run_raw_response_through_mio("GET", b"not-http\r\nHeader: value\r\n\r\n");
        let response = String::from_utf8_lossy(&response);

        assert!(
            response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
            "response={response:?}"
        );
        assert_eq!(
            resource_events.last(),
            Some(&ResourceAccountingEvent {
                used_bytes: 0,
                live_charges: 0,
                client_response_bytes: 0,
                tls_pending_bytes: 0,
                websocket_client_to_upstream_bytes: 0,
                websocket_upstream_to_client_bytes: 0,
            })
        );
    }

    #[test]
    fn snapshot_mio_runtime_closes_premature_started_response_without_inserting_502() {
        let (response, _, resource_events) = run_raw_response_through_mio(
            "GET",
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc",
        );
        let response = String::from_utf8_lossy(&response);

        assert!(
            !response.contains("502 Bad Gateway"),
            "response={response:?}"
        );
        assert_eq!(
            resource_events.last(),
            Some(&ResourceAccountingEvent {
                used_bytes: 0,
                live_charges: 0,
                client_response_bytes: 0,
                tls_pending_bytes: 0,
                websocket_client_to_upstream_bytes: 0,
                websocket_upstream_to_client_bytes: 0,
            })
        );
    }

    #[test]
    fn snapshot_mio_runtime_pauses_upstream_reads_when_client_backpressures() {
        let body_len = 8 * 1024 * 1024;
        let (api_addr, api_backend) = spawn_large_response_backend(body_len);
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "api",
                "api.example.test",
                "/",
                "api-service",
            )],
            vec![service_with_upstream("api-service", api_addr)],
        );
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let mut client = StdTcpStream::connect(listen).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        client
            .write_all(
                b"GET /large HTTP/1.1\r\nHost: api.example.test\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (backpressure_tx, backpressure_rx) = std::sync::mpsc::channel();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_resource_limits(ResourceLimits {
                        idle_timeout: Duration::from_secs(10),
                        connect_timeout: Duration::from_secs(10),
                        upstream_read_timeout: Duration::from_secs(10),
                        client_write_timeout: Duration::from_secs(10),
                        max_response_buffer_bytes: 4 * 1024,
                        ..ResourceLimits::default()
                    })
                    .with_backpressure_events(backpressure_tx),
                1,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        assert_eq!(
            backpressure_rx
                .recv_timeout(Duration::from_secs(15))
                .unwrap(),
            BackpressureEvent::UpstreamReadPaused
        );

        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();

        let api_request = api_backend.join().unwrap();
        runtime_thread.join().unwrap();

        let response_text = String::from_utf8_lossy(&response);
        assert!(
            response_text.starts_with("HTTP/1.1 200 OK"),
            "response was {response_text:?}; upstream request was {api_request:?}"
        );
        assert!(
            response_text.contains(&format!("Content-Length: {body_len}")),
            "response was {response_text:?}"
        );
        assert_eq!(
            response.len(),
            format!("HTTP/1.1 200 OK\r\nContent-Length: {body_len}\r\n\r\n").len() + body_len
        );
        assert!(
            api_request.contains("Host: api.example.test"),
            "upstream request was {api_request:?}"
        );
    }

    #[test]
    fn snapshot_mio_runtime_maps_slow_client_header_to_408() {
        let snapshot = snapshot_for_runtime(vec![], vec![]);
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_resource_limits(ResourceLimits {
                        idle_timeout: Duration::from_millis(100),
                        connect_timeout: Duration::from_secs(2),
                        upstream_read_timeout: Duration::from_secs(2),
                        client_write_timeout: Duration::from_secs(2),
                        ..ResourceLimits::default()
                    }),
                1,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let mut client = StdTcpStream::connect(listen).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: api.example.test")
            .unwrap();
        let mut response_bytes = Vec::new();
        match client.read_to_end(&mut response_bytes) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
            Err(error) => panic!("slow client read failed: {error}"),
        }
        let response = String::from_utf8_lossy(&response_bytes).to_string();

        runtime_thread.join().unwrap();

        assert!(
            response.contains("HTTP/1.1 408 Request Timeout"),
            "response was {response:?}"
        );
    }

    #[test]
    fn snapshot_mio_runtime_maps_upstream_connect_timeout_to_504() {
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "api",
                "api.example.test",
                "/",
                "api-service",
            )],
            vec![Service {
                policy: edge_domain::ServicePolicy::default(),
                id: ServiceId::new("api-service"),
                upstreams: vec![Upstream {
                    id: UpstreamId::new("api-service-1"),
                    url: "http://127.0.0.1:9".to_string(),
                    administrative_state: edge_domain::UpstreamAdministrativeState::Active,
                    tls: edge_domain::UpstreamTlsPolicy::Disabled,
                }],
            }],
        );
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_resource_limits(ResourceLimits {
                        idle_timeout: Duration::from_secs(10),
                        connect_timeout: Duration::from_millis(100),
                        upstream_read_timeout: Duration::from_secs(2),
                        client_write_timeout: Duration::from_secs(10),
                        ..ResourceLimits::default()
                    })
                    .with_stalled_upstream_connect(),
                1,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let mut client = StdTcpStream::connect(listen).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: api.example.test\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        runtime_thread.join().unwrap();

        assert!(
            response.contains("HTTP/1.1 504 Gateway Timeout"),
            "response was {response:?}"
        );
    }

    #[test]
    fn snapshot_mio_runtime_tunnels_websocket_upgrade_after_101_response() {
        let (api_addr, api_backend) = spawn_websocket_backend();
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "api",
                "api.example.test",
                "/",
                "api-service",
            )],
            vec![service_with_upstream("api-service", api_addr)],
        );
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let mut client = StdTcpStream::connect(listen).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        client
            .write_all(
                b"GET /ws HTTP/1.1\r\nHost: api.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (resource_tx, resource_rx) = std::sync::mpsc::channel();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_resource_accounting_events(resource_tx),
                1,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let mut response_headers = Vec::new();
        let mut buffer = [0_u8; 128];
        loop {
            let read = client.read(&mut buffer).unwrap();
            response_headers.extend_from_slice(&buffer[..read]);
            if response_headers
                .windows(4)
                .any(|window| window == b"\r\n\r\n")
            {
                break;
            }
        }
        client.write_all(b"ping").unwrap();
        let mut tunneled = [0_u8; 4];
        client.read_exact(&mut tunneled).unwrap();
        let _ = client.shutdown(std::net::Shutdown::Both);

        let upstream_request = api_backend.join().unwrap();
        runtime_thread.join().unwrap();
        let resource_events: Vec<_> = resource_rx.try_iter().collect();

        assert!(String::from_utf8_lossy(&response_headers).contains("101 Switching Protocols"));
        assert!(upstream_request.contains("Connection: Upgrade"));
        assert!(upstream_request.contains("Upgrade: websocket"));
        assert_eq!(&tunneled, b"pong");
        assert!(
            resource_events
                .iter()
                .any(|event| event.websocket_client_to_upstream_bytes > 0),
            "missing client-to-upstream charge: {resource_events:?}"
        );
        assert!(
            resource_events
                .iter()
                .any(|event| event.websocket_upstream_to_client_bytes > 0),
            "missing upstream-to-client charge: {resource_events:?}"
        );
        assert_eq!(
            resource_events.last(),
            Some(&ResourceAccountingEvent {
                used_bytes: 0,
                live_charges: 0,
                client_response_bytes: 0,
                tls_pending_bytes: 0,
                websocket_client_to_upstream_bytes: 0,
                websocket_upstream_to_client_bytes: 0,
            })
        );
    }

    #[test]
    fn snapshot_mio_runtime_keeps_selected_websocket_during_health_change() {
        use edge_ports::{HealthAvailabilitySnapshot, HealthGeneration, UpstreamHealthKey};

        let skipped_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let skipped_addr = skipped_listener.local_addr().unwrap();
        let (healthy_addr, healthy_backend) = spawn_websocket_backend();
        let mut service = service_with_upstreams("api-service", &[skipped_addr, healthy_addr]);
        service.policy.health_check = edge_domain::HealthCheckPolicy::Http(
            edge_domain::HttpHealthCheckPolicy::new("/health", 1_000, 100, 1, 1, 200, 399).unwrap(),
        );
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "api",
                "api.example.test",
                "/",
                "api-service",
            )],
            vec![service],
        );
        let revision_id = snapshot.revision_id.clone();
        let health_snapshot = |generation, first, second| HealthAvailabilitySnapshot {
            revision_id: revision_id.clone(),
            generation: HealthGeneration(generation),
            entries: BTreeMap::from([
                (
                    UpstreamHealthKey {
                        service_id: ServiceId::new("api-service"),
                        upstream_id: UpstreamId::new("api-service-1"),
                    },
                    first,
                ),
                (
                    UpstreamHealthKey {
                        service_id: ServiceId::new("api-service"),
                        upstream_id: UpstreamId::new("api-service-2"),
                    },
                    second,
                ),
            ]),
        };
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (mut command_client, command_receiver) = runtime_command_channel(8);
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_runtime_commands(command_receiver),
                2,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        assert!(command_client
            .send(CoreCommand::PublishUpstreamAvailability {
                snapshot: health_snapshot(
                    1,
                    UpstreamAvailability::Unhealthy,
                    UpstreamAvailability::Healthy,
                ),
            })
            .is_success());

        let mut websocket = StdTcpStream::connect(listen).unwrap();
        websocket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        websocket
            .write_all(
                b"GET /ws HTTP/1.1\r\nHost: api.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .unwrap();
        let mut response_headers = Vec::new();
        let mut buffer = [0_u8; 128];
        while !response_headers
            .windows(4)
            .any(|window| window == b"\r\n\r\n")
        {
            let read = websocket.read(&mut buffer).unwrap();
            response_headers.extend_from_slice(&buffer[..read]);
        }
        assert!(String::from_utf8_lossy(&response_headers).contains("101 Switching Protocols"));

        assert!(command_client
            .send(CoreCommand::PublishUpstreamAvailability {
                snapshot: health_snapshot(
                    2,
                    UpstreamAvailability::Unhealthy,
                    UpstreamAvailability::Unhealthy,
                ),
            })
            .is_success());
        let unavailable = request_host(listen, "api.example.test");
        assert!(unavailable.starts_with("HTTP/1.1 503 Service Unavailable"));

        websocket.write_all(b"ping").unwrap();
        let mut tunneled = [0_u8; 4];
        websocket.read_exact(&mut tunneled).unwrap();
        let _ = websocket.shutdown(std::net::Shutdown::Both);

        let upstream_request = healthy_backend.join().unwrap();
        runtime_thread.join().unwrap();
        skipped_listener.set_nonblocking(true).unwrap();
        assert!(matches!(
            skipped_listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
        assert!(upstream_request.contains("Upgrade: websocket"));
        assert_eq!(&tunneled, b"pong");
    }

    #[test]
    fn snapshot_runtime_returns_404_for_unknown_host() {
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "app",
                "app.example.test",
                "/",
                "app-service",
            )],
            vec![Service {
                policy: edge_domain::ServicePolicy::default(),
                id: ServiceId::new("app-service"),
                upstreams: vec![Upstream {
                    id: UpstreamId::new("app-service-1"),
                    url: "http://127.0.0.1:1".to_string(),
                    administrative_state: edge_domain::UpstreamAdministrativeState::Active,
                    tls: edge_domain::UpstreamTlsPolicy::Disabled,
                }],
            }],
        );

        let client_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let proxy_thread = thread::spawn(move || {
            let (client, _) = client_listener.accept().unwrap();
            handle_snapshot_http_proxy_connection(
                client,
                &snapshot,
                &NoopHttp01ChallengeResponder,
                HttpLimits::default(),
                "127.0.0.1".to_string(),
            )
            .unwrap();
        });

        let mut client = StdTcpStream::connect(client_addr).unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: missing.example.test\r\n\r\n")
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        proxy_thread.join().unwrap();

        assert!(response.contains("HTTP/1.1 404 Not Found"));
    }

    #[test]
    fn snapshot_http_handler_accepts_generic_read_write_stream() {
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "app",
                "app.example.test",
                "/",
                "app-service",
            )],
            vec![Service {
                policy: edge_domain::ServicePolicy::default(),
                id: ServiceId::new("app-service"),
                upstreams: vec![Upstream {
                    id: UpstreamId::new("app-service-1"),
                    url: "http://127.0.0.1:1".to_string(),
                    administrative_state: edge_domain::UpstreamAdministrativeState::Active,
                    tls: edge_domain::UpstreamTlsPolicy::Disabled,
                }],
            }],
        );
        let mut stream =
            std::io::Cursor::new(b"GET / HTTP/1.1\r\nHost: missing.example.test\r\n\r\n".to_vec());

        handle_snapshot_http_proxy_stream(
            &mut stream,
            &snapshot,
            &NoopHttp01ChallengeResponder,
            HttpLimits::default(),
            "127.0.0.1".to_string(),
        )
        .unwrap();

        let response = String::from_utf8(stream.into_inner()).unwrap();
        assert!(response.contains("HTTP/1.1 404 Not Found"));
    }

    #[test]
    fn snapshot_http_scheme_aware_stream_sets_forwarded_proto() {
        let (api_addr, api_backend) = spawn_text_backend("api");
        let snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "api",
                "api.example.test",
                "/",
                "api-service",
            )],
            vec![service_with_upstream("api-service", api_addr)],
        );
        let mut stream =
            std::io::Cursor::new(b"GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n".to_vec());

        handle_snapshot_http_proxy_stream_with_scheme(
            &mut stream,
            &snapshot,
            &NoopHttp01ChallengeResponder,
            HttpLimits::default(),
            "127.0.0.1".to_string(),
            "https",
        )
        .unwrap();

        let upstream_request = api_backend.join().unwrap();
        let response = String::from_utf8(stream.into_inner()).unwrap();
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(upstream_request.contains("X-Forwarded-Proto: https"));
    }

    #[test]
    fn snapshot_runtime_redirect_preserves_host_authority() {
        let mut route = route_to_service("app", "app.example.test", "/", "app-service");
        route.redirect_http_to_https = true;
        route.certificate_ref = Some(CertificateRef::new("cert-app"));
        let snapshot = snapshot_for_runtime(
            vec![route],
            vec![Service {
                policy: edge_domain::ServicePolicy::default(),
                id: ServiceId::new("app-service"),
                upstreams: vec![Upstream {
                    id: UpstreamId::new("app-service-1"),
                    url: "http://127.0.0.1:1".to_string(),
                    administrative_state: edge_domain::UpstreamAdministrativeState::Active,
                    tls: edge_domain::UpstreamTlsPolicy::Disabled,
                }],
            }],
        );

        let client_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let proxy_thread = thread::spawn(move || {
            let (client, _) = client_listener.accept().unwrap();
            handle_snapshot_http_proxy_connection(
                client,
                &snapshot,
                &NoopHttp01ChallengeResponder,
                HttpLimits::default(),
                "127.0.0.1".to_string(),
            )
            .unwrap();
        });

        let mut client = StdTcpStream::connect(client_addr).unwrap();
        client
            .write_all(b"GET /login HTTP/1.1\r\nHost: app.example.test:8080\r\n\r\n")
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        proxy_thread.join().unwrap();

        assert!(response.contains("HTTP/1.1 308 Permanent Redirect"));
        assert!(response.contains("Location: https://app.example.test:8080/login"));
    }

    #[test]
    fn snapshot_mio_runtime_serves_http01_challenge_from_token_store() {
        let mut route = route_to_service("app", "app.example.test", "/", "app-service");
        route.redirect_http_to_https = true;
        route.certificate_ref = Some(CertificateRef::new("cert-app"));
        let snapshot = snapshot_for_runtime(
            vec![route],
            vec![Service {
                policy: edge_domain::ServicePolicy::default(),
                id: ServiceId::new("app-service"),
                upstreams: vec![Upstream {
                    id: UpstreamId::new("app-service-1"),
                    url: "http://127.0.0.1:1".to_string(),
                    administrative_state: edge_domain::UpstreamAdministrativeState::Active,
                    tls: edge_domain::UpstreamTlsPolicy::Disabled,
                }],
            }],
        );
        let mut tokens = Http01TokenStore::default();
        tokens.insert(Http01Token {
            token: "token-1".to_string(),
            key_authorization: "token-1.key".to_string(),
        });
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_challenge_responder(tokens),
                2,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let known_response = request_host_path(
            listen,
            "app.example.test",
            "/.well-known/acme-challenge/token-1",
        );
        let unknown_response = request_host_path(
            listen,
            "app.example.test",
            "/.well-known/acme-challenge/missing",
        );
        runtime_thread.join().unwrap();

        assert!(
            known_response.contains("HTTP/1.1 200 OK"),
            "known response was {known_response:?}"
        );
        assert!(
            known_response.ends_with("token-1.key"),
            "known response was {known_response:?}"
        );
        assert!(
            unknown_response.contains("HTTP/1.1 404 Not Found"),
            "unknown response was {unknown_response:?}"
        );
    }

    #[test]
    fn forwards_get_request_to_upstream() {
        let backend = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let backend_thread = thread::spawn(move || {
            let (mut stream, _) = backend.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 512];
            loop {
                let read = stream.read(&mut buffer).unwrap();
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request_text = String::from_utf8_lossy(&request).to_string();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
            request_text
        });

        let client_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let proxy_thread = thread::spawn(move || {
            let (client, _) = client_listener.accept().unwrap();
            handle_http_proxy_connection(
                client,
                UpstreamTarget::parse(&format!("http://{backend_addr}")).unwrap(),
                HttpLimits::default(),
                "127.0.0.1".to_string(),
            )
            .unwrap();
        });

        let mut client = StdTcpStream::connect(client_addr).unwrap();
        client
            .write_all(b"GET /hello HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        let upstream_request = backend_thread.join().unwrap();
        proxy_thread.join().unwrap();

        assert!(upstream_request.starts_with("GET /hello HTTP/1.1"));
        assert!(upstream_request.contains("X-Forwarded-For: 127.0.0.1"));
        assert!(upstream_request.contains("X-Forwarded-Proto: http"));
        assert!(upstream_request.contains("X-Forwarded-Host: example.test"));
        assert!(response.contains("HTTP/1.1 200 OK"));
        assert!(response.ends_with("ok"));
    }

    #[test]
    fn forwards_post_body_to_upstream() {
        let backend = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let backend_thread = thread::spawn(move || {
            let (mut stream, _) = backend.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 512];
            loop {
                let read = stream.read(&mut buffer).unwrap();
                request.extend_from_slice(&buffer[..read]);
                if request.ends_with(b"hello") {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 7\r\nConnection: close\r\n\r\ncreated")
                .unwrap();
            String::from_utf8_lossy(&request).to_string()
        });

        let client_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let proxy_thread = thread::spawn(move || {
            let (client, _) = client_listener.accept().unwrap();
            handle_http_proxy_connection(
                client,
                UpstreamTarget::parse(&format!("http://{backend_addr}")).unwrap(),
                HttpLimits::default(),
                "127.0.0.1".to_string(),
            )
            .unwrap();
        });

        let mut client = StdTcpStream::connect(client_addr).unwrap();
        client
            .write_all(
                b"POST /submit HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhello",
            )
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        let upstream_request = backend_thread.join().unwrap();
        proxy_thread.join().unwrap();

        assert!(upstream_request.contains("POST /submit HTTP/1.1"));
        assert!(upstream_request.ends_with("hello"));
        assert!(response.contains("HTTP/1.1 201 Created"));
    }

    #[test]
    fn forwards_put_method_and_preserves_upstream_status() {
        let backend = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let backend_thread = thread::spawn(move || {
            let (mut stream, _) = backend.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 512];
            loop {
                let read = stream.read(&mut buffer).unwrap();
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 7\r\nConnection: close\r\n\r\nmissing",
                )
                .unwrap();
            String::from_utf8_lossy(&request).to_string()
        });

        let client_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let proxy_thread = thread::spawn(move || {
            let (client, _) = client_listener.accept().unwrap();
            handle_http_proxy_connection(
                client,
                UpstreamTarget::parse(&format!("http://{backend_addr}")).unwrap(),
                HttpLimits::default(),
                "127.0.0.1".to_string(),
            )
            .unwrap();
        });

        let mut client = StdTcpStream::connect(client_addr).unwrap();
        client
            .write_all(b"PUT /missing HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        let upstream_request = backend_thread.join().unwrap();
        proxy_thread.join().unwrap();

        assert!(upstream_request.starts_with("PUT /missing HTTP/1.1"));
        assert!(response.contains("HTTP/1.1 404 Not Found"));
        assert!(response.ends_with("missing"));
    }

    #[test]
    fn forwards_upstream_500_response() {
        let backend = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let backend_thread = thread::spawn(move || {
            let (mut stream, _) = backend.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 512];
            loop {
                let read = stream.read(&mut buffer).unwrap();
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(
                    b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\nConnection: close\r\n\r\nerror",
                )
                .unwrap();
        });

        let client_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let proxy_thread = thread::spawn(move || {
            let (client, _) = client_listener.accept().unwrap();
            handle_http_proxy_connection(
                client,
                UpstreamTarget::parse(&format!("http://{backend_addr}")).unwrap(),
                HttpLimits::default(),
                "127.0.0.1".to_string(),
            )
            .unwrap();
        });

        let mut client = StdTcpStream::connect(client_addr).unwrap();
        client
            .write_all(b"GET /boom HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        backend_thread.join().unwrap();
        proxy_thread.join().unwrap();

        assert!(response.contains("HTTP/1.1 500 Internal Server Error"));
        assert!(response.ends_with("error"));
    }

    #[test]
    fn rejects_oversized_body_before_upstream_forwarding() {
        let backend = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let backend_addr = backend.local_addr().unwrap();
        drop(backend);

        let client_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let proxy_thread = thread::spawn(move || {
            let (client, _) = client_listener.accept().unwrap();
            let limits = HttpLimits {
                max_body_bytes: 4,
                ..HttpLimits::default()
            };
            handle_http_proxy_connection(
                client,
                UpstreamTarget::parse(&format!("http://{backend_addr}")).unwrap(),
                limits,
                "127.0.0.1".to_string(),
            )
            .unwrap();
        });

        let mut client = StdTcpStream::connect(client_addr).unwrap();
        client
            .write_all(
                b"POST /large HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhello",
            )
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        proxy_thread.join().unwrap();

        assert!(response.contains("HTTP/1.1 413 Payload Too Large"));
    }

    #[test]
    fn tunnels_websocket_upgrade_after_101_response() {
        let backend = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let backend_thread = thread::spawn(move || {
            let (mut stream, _) = backend.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 512];
            loop {
                let read = stream.read(&mut buffer).unwrap();
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                )
                .unwrap();
            let mut message = [0_u8; 4];
            stream.read_exact(&mut message).unwrap();
            stream.write_all(b"pong").unwrap();
            String::from_utf8_lossy(&request).to_string()
        });

        let client_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let proxy_thread = thread::spawn(move || {
            let (client, _) = client_listener.accept().unwrap();
            handle_http_proxy_connection(
                client,
                UpstreamTarget::parse(&format!("http://{backend_addr}")).unwrap(),
                HttpLimits::default(),
                "127.0.0.1".to_string(),
            )
            .unwrap();
        });

        let mut client = StdTcpStream::connect(client_addr).unwrap();
        client
            .write_all(
                b"GET /ws HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .unwrap();
        let mut response_headers = Vec::new();
        let mut buffer = [0_u8; 128];
        loop {
            let read = client.read(&mut buffer).unwrap();
            response_headers.extend_from_slice(&buffer[..read]);
            if response_headers
                .windows(4)
                .any(|window| window == b"\r\n\r\n")
            {
                break;
            }
        }
        client.write_all(b"ping").unwrap();
        let mut tunneled = [0_u8; 4];
        client.read_exact(&mut tunneled).unwrap();
        let _ = client.shutdown(std::net::Shutdown::Both);

        let upstream_request = backend_thread.join().unwrap();
        proxy_thread.join().unwrap();

        assert!(String::from_utf8_lossy(&response_headers).contains("101 Switching Protocols"));
        assert!(upstream_request.contains("Connection: Upgrade"));
        assert!(upstream_request.contains("Upgrade: websocket"));
        assert_eq!(&tunneled, b"pong");
    }

    #[test]
    fn selects_certificate_for_sni() {
        let selection =
            select_certificate_for_sni(&tls_snapshot(), "APP.example.com").expect("certificate");

        assert_eq!(selection.server_name, "app.example.com");
        assert_eq!(selection.certificate_ref.as_str(), "cert-app");
    }

    #[test]
    fn unknown_sni_has_no_certificate_selection() {
        assert!(select_certificate_for_sni(&tls_snapshot(), "missing.example.com").is_none());
    }

    #[test]
    fn tls_handshake_state_models_failure_without_panic() {
        let state = TlsHandshakeState::Failed(AppError::new(
            ErrorCode::CertificateNotFound,
            "certificate missing",
        ));

        assert!(matches!(state, TlsHandshakeState::Failed(_)));
    }

    #[test]
    fn tls_handshake_machine_selects_certificate_and_establishes() {
        let mut machine = TlsHandshakeMachine::new();

        let selection = machine
            .receive_client_hello(&tls_snapshot(), Some("APP.example.com"))
            .expect("certificate selection");
        machine.mark_established().expect("established");

        assert_eq!(selection.certificate_ref.as_str(), "cert-app");
        assert_eq!(machine.state(), &TlsHandshakeState::Established);
        assert_eq!(machine.server_name(), Some("app.example.com"));
        assert_eq!(machine.certificate_ref().unwrap().as_str(), "cert-app");
    }

    #[test]
    fn tls_handshake_events_drive_state_transitions() {
        let mut machine = TlsHandshakeMachine::new();

        let outcome = machine
            .handle_event(
                &tls_snapshot(),
                TlsHandshakeEvent::ClientHello {
                    server_name: Some("APP.example.com".to_string()),
                },
            )
            .expect("certificate selected");

        assert_eq!(
            outcome,
            TlsHandshakeOutcome::CertificateSelected(CertificateSelection {
                server_name: "app.example.com".to_string(),
                certificate_ref: CertificateRef::new("cert-app"),
            })
        );
        assert_eq!(machine.state(), &TlsHandshakeState::Handshaking);
        assert_eq!(machine.server_name(), Some("app.example.com"));
        assert_eq!(machine.certificate_ref().unwrap().as_str(), "cert-app");

        let outcome = machine
            .handle_event(&tls_snapshot(), TlsHandshakeEvent::HandshakeCompleted)
            .expect("handshake completed");

        assert_eq!(outcome, TlsHandshakeOutcome::StateChanged);
        assert_eq!(machine.state(), &TlsHandshakeState::Established);
    }

    #[test]
    fn tls_handshake_event_timeout_sets_failed_state() {
        let mut machine = TlsHandshakeMachine::new();

        let error = machine
            .handle_event(&tls_snapshot(), TlsHandshakeEvent::TimeoutExpired)
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::TlsHandshakeTimeout);
        assert!(matches!(
            machine.state(),
            TlsHandshakeState::Failed(failure) if failure.code == ErrorCode::TlsHandshakeTimeout
        ));
    }

    #[test]
    fn tls_handshake_machine_unknown_sni_fails_without_panic() {
        let mut machine = TlsHandshakeMachine::new();

        let error = machine
            .receive_client_hello(&tls_snapshot(), Some("missing.example.com"))
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::CertificateNotFound);
        assert!(matches!(
            machine.state(),
            TlsHandshakeState::Failed(failure) if failure.code == ErrorCode::CertificateNotFound
        ));
    }

    #[test]
    fn tls_handshake_machine_timeout_is_explicit_failure() {
        let mut machine = TlsHandshakeMachine::new();

        let error = machine.mark_timeout().unwrap_err();

        assert_eq!(error.code, ErrorCode::TlsHandshakeTimeout);
        assert!(matches!(
            machine.state(),
            TlsHandshakeState::Failed(failure) if failure.code == ErrorCode::TlsHandshakeTimeout
        ));
    }

    #[test]
    fn tls_handshake_interest_follows_current_state() {
        let waiting = TlsHandshakeState::WaitingForClientHello.io_interest();
        assert!(waiting.client_readable);
        assert!(!waiting.client_writable);
        assert!(!waiting.upstream_readable);
        assert!(!waiting.upstream_writable);

        let selecting = TlsHandshakeState::SelectingCertificate.io_interest();
        assert_eq!(selecting, ConnectionInterest::default());

        let handshaking = TlsHandshakeState::Handshaking.io_interest();
        assert!(handshaking.client_readable);
        assert!(handshaking.client_writable);
        assert!(!handshaking.upstream_readable);
        assert!(!handshaking.upstream_writable);

        let established = TlsHandshakeState::Established.io_interest();
        assert_eq!(
            established,
            ConnectionInterest::default(),
            "HTTP connection state takes over after TLS establishment"
        );

        let failed =
            TlsHandshakeState::Failed(AppError::new(ErrorCode::TlsHandshakeTimeout, "timed out"))
                .io_interest();
        assert_eq!(failed, ConnectionInterest::default());
    }

    #[test]
    fn tls_transport_drives_fragmented_fake_handshake_and_plaintext() {
        let mut transport = TlsTransport::new(Box::new(
            ScriptedTlsSession::new().with_sni("app.example.com"),
        ));

        assert_eq!(transport.state(), &TlsTransportState::Handshaking);
        assert_eq!(transport.receive_encrypted(b"client-"), Ok(7));
        assert_eq!(transport.state(), &TlsTransportState::Handshaking);
        assert_eq!(transport.receive_encrypted(b"hello"), Ok(5));
        assert_eq!(transport.state(), &TlsTransportState::Established);
        assert_eq!(transport.sni_hostname(), Some("app.example.com"));

        assert_eq!(
            transport.receive_encrypted(b"GET / HTTP/1.1\r\n\r\n"),
            Ok(18)
        );
        assert_eq!(transport.take_decrypted(1024), b"GET / HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn tls_transport_maps_session_interest_and_drains_ciphertext() {
        let mut transport = TlsTransport::new(Box::new(ScriptedTlsSession::established()));

        assert_eq!(
            transport.receive_plaintext(b"HTTP/1.1 200 OK\r\n\r\n"),
            Ok(19)
        );
        assert_eq!(
            transport.io_interest(),
            ConnectionInterest {
                client_readable: false,
                client_writable: true,
                ..ConnectionInterest::default()
            }
        );
        assert_eq!(transport.take_encrypted(8), b"HTTP/1.1");
        assert_eq!(transport.take_encrypted(1024), b" 200 OK\r\n\r\n");
        assert!(transport.io_interest().client_readable);
    }

    #[test]
    fn tls_transport_delegates_pending_owner_bytes_without_side_effects() {
        let mut transport = TlsTransport::new(Box::new(
            ScriptedTlsSession::new().with_handshake_response(b"reply"),
        ));

        transport.receive_encrypted(b"client-").unwrap();
        assert_eq!(
            transport.pending_tls_bytes(),
            edge_ports::TlsPendingBytes::new(7, 0, 0)
        );
        assert_eq!(transport.state(), &TlsTransportState::Handshaking);
        transport.receive_encrypted(b"helloGET").unwrap();
        assert_eq!(
            transport.pending_tls_bytes(),
            edge_ports::TlsPendingBytes::new(0, 3, 5)
        );
        assert_eq!(transport.state(), &TlsTransportState::Established);
    }

    #[test]
    fn tls_transport_timeout_is_terminal_and_removes_interest() {
        let mut transport = TlsTransport::new(Box::new(ScriptedTlsSession::new()));

        let error = transport.mark_handshake_timeout().unwrap_err();

        assert_eq!(error.code, ErrorCode::TlsHandshakeTimeout);
        assert!(matches!(
            transport.state(),
            TlsTransportState::Failed(failure)
                if failure.code == ErrorCode::TlsHandshakeTimeout
        ));
        assert_eq!(transport.io_interest(), ConnectionInterest::default());
        assert_eq!(transport.receive_encrypted(b"client-hello"), Ok(0));
    }

    #[test]
    fn phase009_prepared_client_tls_registry_is_keyed_and_requires_explicit_server_name() {
        use edge_domain::{ServiceId, TlsServerName, UpstreamId};
        use edge_ports::{ScriptedClientTlsSessionFactory, ScriptedTlsSession};

        let service_id = ServiceId::new("private-service");
        let upstream_id = UpstreamId::new("private-upstream");
        let server_name = TlsServerName::parse("backend.private.test").unwrap();
        let factory = ScriptedClientTlsSessionFactory::new(ScriptedTlsSession::established());
        let captured = factory.clone();
        let mut registry = PreparedClientTlsRegistry::new();

        registry
            .insert(service_id.clone(), upstream_id.clone(), factory)
            .unwrap();
        let duplicate = registry
            .insert(
                service_id.clone(),
                upstream_id.clone(),
                ScriptedClientTlsSessionFactory::new(ScriptedTlsSession::established()),
            )
            .unwrap_err();
        assert_eq!(duplicate.code, ErrorCode::UpstreamTlsProfileInvalid);

        let session = registry
            .create_session(&service_id, &upstream_id, &server_name)
            .unwrap();
        assert_eq!(session.progress(), TlsSessionProgress::Established);
        assert_eq!(captured.requested_server_names(), vec![server_name]);

        let missing = match registry.create_session(
            &service_id,
            &UpstreamId::new("missing"),
            &TlsServerName::parse("missing.private.test").unwrap(),
        ) {
            Ok(_) => panic!("missing prepared TLS profile must fail"),
            Err(error) => error,
        };
        assert_eq!(missing.code, ErrorCode::UpstreamTlsProfileInvalid);
    }

    #[test]
    fn phase009_prepared_server_tls_registry_rejects_duplicate_bind_and_missing_factory() {
        let bind: SocketAddr = "127.0.0.1:8443".parse().unwrap();
        let missing: SocketAddr = "127.0.0.1:9443".parse().unwrap();
        let mut registry = PreparedServerTlsRegistry::new();

        registry
            .insert(
                bind,
                ScriptedServerTlsSessionFactory::new(ScriptedTlsSession::new()),
            )
            .unwrap();
        let duplicate = registry
            .insert(
                bind,
                ScriptedServerTlsSessionFactory::new(ScriptedTlsSession::new()),
            )
            .unwrap_err();

        assert_eq!(duplicate.code, ErrorCode::RuntimeCommandRejected);
        assert!(registry.factory_for(&bind).is_some());
        assert!(registry.factory_for(&missing).is_none());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn phase009_upstream_tls_transport_gates_http_until_verified_and_maps_interest() {
        use edge_ports::ScriptedTlsSession;

        let session = ScriptedTlsSession::new()
            .with_handshake_marker(b"server-hello")
            .with_handshake_response(b"client-finished");
        let mut transport = UpstreamTransport::tls(Box::new(session));

        assert_eq!(transport.tls_state(), Some(&TlsTransportState::Handshaking));
        assert_eq!(
            transport
                .queue_http_bytes(b"GET / HTTP/1.1\r\n\r\n")
                .unwrap(),
            0
        );
        assert_eq!(transport.take_socket_bytes(1024), Vec::<u8>::new());
        assert_eq!(
            transport.merge_interest(ConnectionInterest::default()),
            ConnectionInterest {
                upstream_readable: true,
                upstream_writable: false,
                ..ConnectionInterest::default()
            }
        );

        assert!(transport
            .receive_socket_bytes(b"server-hello")
            .unwrap()
            .is_empty());
        assert_eq!(transport.tls_state(), Some(&TlsTransportState::Established));
        assert_eq!(
            transport.take_socket_bytes(1024),
            b"client-finished".to_vec()
        );
        assert_eq!(transport.queue_http_bytes(b"request").unwrap(), 7);
        assert_eq!(transport.take_socket_bytes(1024), b"request".to_vec());
    }

    #[test]
    fn phase009_upstream_tls_handshake_state_and_timeout_are_explicit() {
        let mut connection = Connection {
            token: ConnectionToken::new(900),
            state: ConnectionState::ConnectingUpstream,
        };

        connection
            .handle_event(ConnectionEvent::UpstreamTlsHandshakeStarted)
            .unwrap();
        assert_eq!(connection.state, ConnectionState::HandshakingUpstreamTls);
        assert_eq!(
            timeout_decision_for_state(&connection.state),
            Some(ConnectionTimeoutDecision {
                kind: ConnectionTimeoutKind::UpstreamTlsHandshake,
                status_code: Some(504),
                reason: "Gateway Timeout",
                next_state: ConnectionState::WritingClientResponse,
            })
        );
        connection
            .handle_event(ConnectionEvent::UpstreamTlsEstablished)
            .unwrap();
        assert_eq!(connection.state, ConnectionState::WritingUpstreamRequest);
    }

    #[test]
    fn phase009_runtime_preserves_https_endpoint_and_fails_closed_before_tls_wiring() {
        let backend = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let service_id = ServiceId::new("private-service");
        let mut snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "private-route",
                "private.example.test",
                "/",
                service_id.as_str(),
            )],
            vec![Service {
                id: service_id,
                policy: edge_domain::ServicePolicy::default(),
                upstreams: vec![Upstream {
                    id: UpstreamId::new("private-upstream"),
                    url: format!("https://{}:{}/base", backend_addr.ip(), backend_addr.port()),
                    administrative_state: edge_domain::UpstreamAdministrativeState::Active,
                    tls: edge_domain::UpstreamTlsPolicy::ServerAuthenticated {
                        server_name: edge_domain::TlsServerName::parse("backend.private.test")
                            .unwrap(),
                        http_host: edge_domain::UpstreamHttpHost::parse("backend.private.test")
                            .unwrap(),
                        trust_bundle_ref: edge_domain::TrustBundleRef::parse("private-root")
                            .unwrap(),
                    },
                }],
            }],
        );
        snapshot.schema_version = 2;
        let endpoint =
            edge_domain::UpstreamEndpoint::parse(&snapshot.services[0].upstreams[0].url).unwrap();
        assert_eq!(endpoint.scheme(), edge_domain::UpstreamScheme::Https);
        assert_eq!(endpoint.join_path("/status"), "/base/status");

        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default()),
                1,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let mut client = StdTcpStream::connect(listen).unwrap();
        client
            .write_all(b"GET /status HTTP/1.1\r\nHost: private.example.test\r\n\r\n")
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        runtime_thread.join().unwrap();

        assert!(response.starts_with("HTTP/1.1 502 Bad Gateway"));
        backend.set_nonblocking(true).unwrap();
        assert_eq!(
            backend.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn phase009_snapshot_mio_forwards_https_only_after_scripted_client_handshake() {
        use edge_ports::{ScriptedClientTlsSessionFactory, ScriptedTlsSession};

        let backend = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let backend_thread = thread::spawn(move || {
            let (mut stream, _) = backend.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut hello = [0_u8; 12];
            stream.read_exact(&mut hello).unwrap();
            assert_eq!(&hello, b"client-hello");
            stream.write_all(b"server-hello").unwrap();
            let mut request_bytes = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request_bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).unwrap();
                assert!(read > 0, "upstream request closed before headers");
                request_bytes.extend_from_slice(&buffer[..read]);
            }
            let request = String::from_utf8(request_bytes).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecure",
                )
                .unwrap();
            request
        });
        let service_id = ServiceId::new("private-service");
        let upstream_id = UpstreamId::new("private-upstream");
        let server_name = edge_domain::TlsServerName::parse("backend.private.test").unwrap();
        let mut snapshot = snapshot_for_runtime(
            vec![route_to_service(
                "private-route",
                "public.example.test",
                "/",
                service_id.as_str(),
            )],
            vec![Service {
                id: service_id.clone(),
                policy: edge_domain::ServicePolicy::default(),
                upstreams: vec![Upstream {
                    id: upstream_id.clone(),
                    url: format!("https://{}:{}", backend_addr.ip(), backend_addr.port()),
                    administrative_state: edge_domain::UpstreamAdministrativeState::Active,
                    tls: edge_domain::UpstreamTlsPolicy::ServerAuthenticated {
                        server_name: server_name.clone(),
                        http_host: edge_domain::UpstreamHttpHost::parse("backend.private.test")
                            .unwrap(),
                        trust_bundle_ref: edge_domain::TrustBundleRef::parse("private-root")
                            .unwrap(),
                    },
                }],
            }],
        );
        snapshot.schema_version = 2;
        let mut registry = PreparedClientTlsRegistry::new();
        registry
            .insert(
                service_id,
                upstream_id,
                ScriptedClientTlsSessionFactory::new(
                    ScriptedTlsSession::new()
                        .with_initial_encrypted(b"client-hello")
                        .with_handshake_marker(b"server-hello"),
                ),
            )
            .unwrap();
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_client_tls_registry(registry),
                1,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let mut client = StdTcpStream::connect(listen).unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: public.example.test\r\n\r\n")
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        let request = backend_thread.join().unwrap();
        runtime_thread.join().unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response:?}");
        assert!(response.ends_with("secure"));
        assert!(
            request.contains("Host: backend.private.test"),
            "{request:?}"
        );
        assert!(
            request.contains("X-Forwarded-Host: public.example.test"),
            "{request:?}"
        );
    }

    #[test]
    fn phase009_runtime_generation_replaces_and_rolls_back_outbound_tls_registry() {
        use edge_ports::{ScriptedClientTlsSessionFactory, ScriptedTlsSession};

        let backend = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let backend_thread = thread::spawn(move || {
            let (mut initially_rejected, _) = backend.accept().unwrap();
            initially_rejected
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut initially_rejected_bytes = Vec::new();
            initially_rejected
                .read_to_end(&mut initially_rejected_bytes)
                .unwrap();

            let (mut trusted, _) = backend.accept().unwrap();
            trusted
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut hello = [0_u8; 12];
            trusted.read_exact(&mut hello).unwrap();
            assert_eq!(&hello, b"client-hello");
            trusted.write_all(b"server-hello").unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = trusted.read(&mut buffer).unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buffer[..read]);
            }
            trusted
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\ntrusted",
                )
                .unwrap();

            let (mut rejected, _) = backend.accept().unwrap();
            rejected
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut bytes = Vec::new();
            rejected.read_to_end(&mut bytes).unwrap();
            (
                initially_rejected_bytes,
                String::from_utf8(request).unwrap(),
                bytes,
            )
        });
        let (current, service_id, upstream_id) = phase009_private_tls_snapshot(backend_addr);
        let mut next = current.clone();
        next.revision_id = ConfigRevisionId::new("trusted-generation");
        let mut rollback = current.clone();
        rollback.revision_id = ConfigRevisionId::new("rollback-generation");
        let mut failed_session = ScriptedTlsSession::new();
        failed_session.mark_failed(AppError::new(
            ErrorCode::UpstreamTlsUntrusted,
            "bounded fixture failure",
        ));
        let mut old_registry = PreparedClientTlsRegistry::new();
        old_registry
            .insert(
                service_id.clone(),
                upstream_id.clone(),
                ScriptedClientTlsSessionFactory::new(failed_session.clone()),
            )
            .unwrap();
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (mut command_client, command_receiver) = runtime_command_channel(4);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, current, HttpLimits::default())
                    .with_runtime_commands(command_receiver)
                    .with_client_tls_registry(old_registry),
                3,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();

        let rejected_ack = command_client.activate_runtime_generation(
            next.clone(),
            initial_availability_snapshot(&next),
            PreparedServerTlsRegistry::new(),
            PreparedClientTlsRegistry::new(),
        );
        assert!(matches!(
            rejected_ack,
            CommandAck::Rejected(error) if error.code == ErrorCode::UpstreamTlsProfileInvalid
        ));
        let initially_rejected = request_host(listen, "public.example.test");

        let mut trusted_registry = PreparedClientTlsRegistry::new();
        trusted_registry
            .insert(
                service_id.clone(),
                upstream_id.clone(),
                ScriptedClientTlsSessionFactory::new(
                    ScriptedTlsSession::new()
                        .with_initial_encrypted(b"client-hello")
                        .with_handshake_marker(b"server-hello"),
                ),
            )
            .unwrap();
        let availability = initial_availability_snapshot(&next);
        assert!(command_client
            .activate_runtime_generation(
                next,
                availability,
                PreparedServerTlsRegistry::new(),
                trusted_registry,
            )
            .is_success());
        let trusted = request_host(listen, "public.example.test");

        let mut rollback_registry = PreparedClientTlsRegistry::new();
        rollback_registry
            .insert(
                service_id,
                upstream_id,
                ScriptedClientTlsSessionFactory::new(failed_session),
            )
            .unwrap();
        let availability = initial_availability_snapshot(&rollback);
        assert!(command_client
            .activate_runtime_generation(
                rollback,
                availability,
                PreparedServerTlsRegistry::new(),
                rollback_registry,
            )
            .is_success());
        let rejected = request_host(listen, "public.example.test");

        let (initially_rejected_bytes, request, rejected_bytes) = backend_thread.join().unwrap();
        runtime_thread.join().unwrap();
        assert!(initially_rejected.starts_with("HTTP/1.1 502 Bad Gateway"));
        assert!(initially_rejected_bytes.is_empty());
        assert!(trusted.ends_with("trusted"));
        assert!(request.contains("Host: backend.private.test"));
        assert!(rejected.starts_with("HTTP/1.1 502 Bad Gateway"));
        assert!(rejected_bytes.is_empty());
    }

    #[test]
    fn phase009_snapshot_mio_maps_terminal_tls_session_to_502_without_plaintext() {
        use edge_ports::{ScriptedClientTlsSessionFactory, ScriptedTlsSession};

        let backend = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let backend_thread = thread::spawn(move || {
            let (mut stream, _) = backend.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).unwrap();
            bytes
        });
        let (snapshot, service_id, upstream_id) = phase009_private_tls_snapshot(backend_addr);
        let mut failed_session = ScriptedTlsSession::new();
        failed_session.mark_failed(AppError::new(
            ErrorCode::UpstreamTlsUntrusted,
            "fixture failure",
        ));
        let mut registry = PreparedClientTlsRegistry::new();
        registry
            .insert(
                service_id,
                upstream_id,
                ScriptedClientTlsSessionFactory::new(failed_session),
            )
            .unwrap();
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_client_tls_registry(registry),
                1,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();
        let mut client = StdTcpStream::connect(listen).unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: public.example.test\r\n\r\n")
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        assert!(response.starts_with("HTTP/1.1 502 Bad Gateway"));
        assert!(backend_thread.join().unwrap().is_empty());
        runtime_thread.join().unwrap();
    }

    #[test]
    fn phase009_snapshot_mio_maps_stalled_tls_handshake_to_504_without_request() {
        use edge_ports::{ScriptedClientTlsSessionFactory, ScriptedTlsSession};

        let backend = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let backend_thread = thread::spawn(move || {
            let (mut stream, _) = backend.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut hello = [0_u8; 12];
            stream.read_exact(&mut hello).unwrap();
            assert_eq!(&hello, b"client-hello");
            let mut remainder = Vec::new();
            stream.read_to_end(&mut remainder).unwrap();
            remainder
        });
        let (snapshot, service_id, upstream_id) = phase009_private_tls_snapshot(backend_addr);
        let mut registry = PreparedClientTlsRegistry::new();
        registry
            .insert(
                service_id,
                upstream_id,
                ScriptedClientTlsSessionFactory::new(
                    ScriptedTlsSession::new().with_initial_encrypted(b"client-hello"),
                ),
            )
            .unwrap();
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = listener.local_addr().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let runtime_thread = thread::spawn(move || {
            run_snapshot_http_proxy_mio_for_test(
                listener,
                SnapshotProxyConfig::new(listen, snapshot, HttpLimits::default())
                    .with_client_tls_registry(registry)
                    .with_resource_limits(ResourceLimits {
                        connect_timeout: Duration::from_millis(50),
                        ..ResourceLimits::default()
                    }),
                1,
                ready_tx,
            )
            .unwrap();
        });
        ready_rx.recv().unwrap();
        let mut client = StdTcpStream::connect(listen).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: public.example.test\r\n\r\n")
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();

        assert!(
            response.starts_with("HTTP/1.1 504 Gateway Timeout"),
            "{response:?}"
        );
        assert!(backend_thread.join().unwrap().is_empty());
        runtime_thread.join().unwrap();
    }

    #[test]
    fn tls_transport_peer_close_is_terminal_and_removes_interest() {
        let mut session = ScriptedTlsSession::established();
        session.mark_peer_closed();
        let transport = TlsTransport::new(Box::new(session));

        assert_eq!(transport.state(), &TlsTransportState::PeerClosed);
        assert_eq!(transport.io_interest(), ConnectionInterest::default());
    }

    #[test]
    fn tls_transport_close_notify_stays_writable_until_fully_drained() {
        let mut transport = TlsTransport::new(Box::new(ScriptedTlsSession::established()));

        transport.request_close_notify().unwrap();

        assert_eq!(transport.state(), &TlsTransportState::Closing);
        assert!(transport.io_interest().client_writable);
        assert_eq!(transport.take_encrypted(5), b"close");
        assert_eq!(transport.state(), &TlsTransportState::Closing);
        assert!(transport.io_interest().client_writable);
        assert_eq!(transport.take_encrypted(64), b"_notify");
        assert_eq!(transport.state(), &TlsTransportState::PeerClosed);
        assert_eq!(transport.io_interest(), ConnectionInterest::default());
    }

    #[test]
    fn client_transport_plaintext_passes_socket_and_http_bytes_unchanged() {
        let mut transport = ClientTransport::plaintext();

        assert!(transport.pending_tls_bytes().is_zero());

        assert_eq!(
            transport.receive_socket_bytes(b"GET / HTTP/1.1\r\n\r\n"),
            Ok(b"GET / HTTP/1.1\r\n\r\n".to_vec())
        );
        assert_eq!(
            transport.queue_http_bytes(b"HTTP/1.1 200 OK\r\n\r\n"),
            Ok(19)
        );
        assert_eq!(
            transport.take_socket_bytes(1024),
            b"HTTP/1.1 200 OK\r\n\r\n"
        );
    }

    #[test]
    fn client_transport_tls_hides_handshake_and_hands_off_plaintext() {
        let mut transport = ClientTransport::tls(Box::new(ScriptedTlsSession::new()));

        assert_eq!(transport.receive_socket_bytes(b"client-"), Ok(Vec::new()));
        assert_eq!(transport.receive_socket_bytes(b"hello"), Ok(Vec::new()));
        assert_eq!(
            transport.receive_socket_bytes(b"GET / HTTP/1.1\r\n\r\n"),
            Ok(b"GET / HTTP/1.1\r\n\r\n".to_vec())
        );
        assert_eq!(transport.queue_http_bytes(b"response"), Ok(8));
        assert_eq!(transport.pending_tls_bytes().encrypted_bytes, 8);
        assert_eq!(transport.take_socket_bytes(1024), b"response");
        assert!(transport.pending_tls_bytes().is_zero());
    }

    #[test]
    fn upstream_transport_reports_zero_for_plaintext_and_tls_session_bytes() {
        let plaintext = UpstreamTransport::plaintext();
        assert!(plaintext.pending_tls_bytes().is_zero());

        let mut tls = UpstreamTransport::tls(Box::new(ScriptedTlsSession::established()));
        tls.queue_http_bytes(b"request").unwrap();
        assert_eq!(tls.pending_tls_bytes().encrypted_bytes, 7);
        tls.take_socket_bytes(3);
        assert_eq!(tls.pending_tls_bytes().encrypted_bytes, 4);
    }

    #[test]
    fn client_transport_merges_tls_and_http_interest_without_losing_upstream() {
        let mut transport = ClientTransport::tls(Box::new(ScriptedTlsSession::new()));
        let base = ConnectionInterest {
            client_readable: true,
            client_writable: true,
            upstream_readable: true,
            ..ConnectionInterest::default()
        };

        let handshaking = transport.merge_interest(base);
        assert!(handshaking.client_readable);
        assert!(!handshaking.client_writable);
        assert!(handshaking.upstream_readable);

        transport.receive_socket_bytes(b"client-hello").unwrap();
        transport.queue_http_bytes(b"response").unwrap();
        let established = transport.merge_interest(base);
        assert!(established.client_readable);
        assert!(established.client_writable);
        assert!(established.upstream_readable);
    }

    #[test]
    fn pending_socket_output_preserves_plaintext_tail_until_acknowledged() {
        let mut transport = ClientTransport::plaintext();
        transport.queue_http_bytes(b"response-body").unwrap();
        let mut pending = PendingSocketOutput::new();

        assert_eq!(pending.pull_from(&mut transport, 1024), 13);
        assert_eq!(pending.remaining(), b"response-body");
        assert_eq!(pending.advance(5), 5);
        assert_eq!(pending.remaining(), b"nse-body");
        assert_eq!(pending.pull_from(&mut transport, 1024), 0);
        assert_eq!(pending.advance(1024), 8);
        assert!(pending.is_empty());
    }

    #[test]
    fn pending_socket_output_preserves_tls_ciphertext_until_acknowledged() {
        let mut transport = ClientTransport::tls(Box::new(ScriptedTlsSession::established()));
        transport.queue_http_bytes(b"encrypted-response").unwrap();
        let mut pending = PendingSocketOutput::new();

        assert_eq!(pending.pull_from(&mut transport, 7), 7);
        assert_eq!(pending.remaining(), b"encrypt");
        assert_eq!(pending.advance(3), 3);
        assert_eq!(pending.remaining(), b"rypt");
        assert_eq!(pending.pull_from(&mut transport, 7), 0);
        assert_eq!(pending.advance(4), 4);
        assert_eq!(pending.pull_from(&mut transport, 1024), 11);
        assert_eq!(pending.remaining(), b"ed-response");
    }
}
