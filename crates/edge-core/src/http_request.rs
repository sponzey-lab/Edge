//! Pure HTTP/1.1 request parsing and incremental request buffering.

use edge_domain::{
    AppError, ErrorCode, DEFAULT_MAX_REQUEST_BODY_BYTES, FIXED_REQUEST_HEADER_RESERVE_BYTES,
};

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

/// Parses a complete HTTP/1.1 request within supplied bounds.
///
/// Rejects malformed framing, missing/ambiguous HTTP/1.1 Host authority, and
/// field values containing prohibited ASCII controls so no unsafe request can
/// reach forwarding. Horizontal tab is permitted by HTTP field-value grammar.
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

    let (method, path, version) = validate_request_line(request_line)?;

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
        if !is_http_token(name) {
            return Err(AppError::new(
                ErrorCode::HttpMalformedRequest,
                "header name is invalid",
            ));
        }
        validate_header_value(value)?;
        headers.push(Header {
            name: name.trim().to_string(),
            value: value.trim().to_string(),
        });
    }

    validate_http11_host_authority(&headers)?;
    let expected_body_len = expected_request_body_len_from_headers(&headers)?;
    if expected_body_len > limits.max_body_bytes {
        return Err(AppError::new(
            ErrorCode::HttpRequestBodyTooLarge,
            "body exceeds limit",
        ));
    }
    if body.len() != expected_body_len {
        return Err(AppError::new(
            ErrorCode::HttpMalformedRequest,
            "content length does not match body",
        ));
    }

    Ok(HttpRequest {
        method: method.to_string(),
        path: path.to_string(),
        version: version.to_string(),
        headers,
        body,
    })
}

fn validate_header_value(value: &str) -> Result<(), AppError> {
    if contains_prohibited_http_field_value_control(value) {
        return Err(AppError::new(
            ErrorCode::HttpMalformedRequest,
            "header value contains prohibited control byte",
        ));
    }
    Ok(())
}

/// Returns whether a field value has an ASCII control byte forbidden by the
/// HTTP/1.1 field-value grammar. Horizontal tab remains permitted.
pub(crate) fn contains_prohibited_http_field_value_control(value: &str) -> bool {
    value
        .bytes()
        .any(|byte| matches!(byte, 0..=8 | 10..=31 | 127))
}

fn contains_prohibited_request_target_control(target: &str) -> bool {
    target.bytes().any(|byte| byte <= 31 || byte == 127)
}

fn validate_request_line(request_line: &str) -> Result<(&str, &str, &str), AppError> {
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| AppError::new(ErrorCode::HttpMalformedRequest, "missing method"))?;
    let path = request_parts
        .next()
        .ok_or_else(|| AppError::new(ErrorCode::HttpMalformedRequest, "missing path"))?;
    let version = request_parts
        .next()
        .ok_or_else(|| AppError::new(ErrorCode::HttpMalformedRequest, "missing version"))?;
    if request_parts.next().is_some() {
        return Err(AppError::new(
            ErrorCode::HttpMalformedRequest,
            "request line has unexpected trailing token",
        ));
    }
    if !is_http_token(method) {
        return Err(AppError::new(
            ErrorCode::HttpMalformedRequest,
            "request method is not an HTTP token",
        ));
    }
    if contains_prohibited_request_target_control(path) {
        return Err(AppError::new(
            ErrorCode::HttpMalformedRequest,
            "request target contains prohibited control byte",
        ));
    }
    if version != "HTTP/1.1" {
        return Err(AppError::new(
            ErrorCode::HttpMalformedRequest,
            "unsupported HTTP version",
        ));
    }
    if method.eq_ignore_ascii_case("CONNECT") {
        return Err(AppError::new(
            ErrorCode::HttpConnectMethodRejected,
            "CONNECT is not supported",
        ));
    }
    Ok((method, path, version))
}

fn validate_http11_host_authority(headers: &[Header]) -> Result<(), AppError> {
    let mut host_values = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("Host"))
        .map(|header| header.value.trim());
    let Some(host) = host_values.next() else {
        return Err(AppError::new(
            ErrorCode::HttpMalformedRequest,
            "HTTP/1.1 request requires one Host header",
        ));
    };
    if host.is_empty() || host_values.next().is_some() {
        return Err(AppError::new(
            ErrorCode::HttpMalformedRequest,
            "HTTP/1.1 request Host header is invalid or ambiguous",
        ));
    }
    Ok(())
}

pub(crate) fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
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
    let request_line = lines
        .next()
        .ok_or_else(|| AppError::new(ErrorCode::HttpMalformedRequest, "missing request line"))?;
    validate_request_line(request_line)?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| AppError::new(ErrorCode::HttpMalformedRequest, "malformed header"))?;
        validate_header_value(value)?;
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
