//! Pure incremental HTTP/1.1 upstream response framing.

use edge_domain::{AppError, ErrorCode};

use crate::http_request::{contains_prohibited_http_field_value_control, is_http_token};

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
    connection_close: bool,
    close_delimited: bool,
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
            connection_close: false,
            close_delimited: false,
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

    /// A completed response may keep its upstream socket only when HTTP framing
    /// is self-delimited and the upstream did not opt out with `Connection: close`.
    pub fn is_keep_alive_reusable(&self) -> bool {
        matches!(self.state, ResponseFramingState::Complete)
            && !self.connection_close
            && !self.close_delimited
    }

    /// Consumes upstream bytes while enforcing HTTP/1.1 framing safety.
    ///
    /// Malformed header or trailer control bytes transition the framer to its
    /// terminal failure state before those bytes can be forwarded.
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
                        let (status_code, body_framing, connection_close) =
                            parse_response_framing_headers(&headers, self.body_expectation)?;
                        self.status_code = Some(status_code);
                        if !matches!(body_framing, ResponseBodyFraming::Interim) {
                            self.connection_close = connection_close;
                            self.close_delimited =
                                matches!(body_framing, ResponseBodyFraming::CloseDelimited);
                        }
                        self.state = match body_framing {
                            ResponseBodyFraming::Interim => {
                                ResponseFramingState::Headers(Vec::new())
                            }
                            ResponseBodyFraming::None | ResponseBodyFraming::ContentLength(0) => {
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
                    if let Err(error) = try_push_bounded(line, input[cursor], self.max_line_bytes) {
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
                    if let Err(error) = try_push_bounded(line, input[cursor], self.max_line_bytes) {
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
                ResponseFramingState::CloseDelimited => cursor = input.len(),
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
) -> Result<(u16, ResponseBodyFraming, bool), AppError> {
    let header_text = std::str::from_utf8(headers)
        .map_err(|_| malformed_upstream_response("response headers are not UTF-8"))?;
    let header_text = header_text
        .strip_suffix("\r\n\r\n")
        .ok_or_else(|| malformed_upstream_response("response header terminator is missing"))?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| malformed_upstream_response("response status line is missing"))?;
    let (version, status_and_reason) = status_line
        .split_once(' ')
        .ok_or_else(|| malformed_upstream_response("response HTTP version is missing"))?;
    if version != "HTTP/1.1" {
        return Err(malformed_upstream_response(
            "response HTTP version is invalid",
        ));
    }
    let (status_code, _reason_phrase) = status_and_reason
        .split_once(' ')
        .ok_or_else(|| malformed_upstream_response("response reason separator is missing"))?;
    if status_code.len() != 3 || !status_code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(malformed_upstream_response(
            "response status code is invalid",
        ));
    }
    let status_code = status_code
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
    let mut connection_close = false;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| malformed_upstream_response("response header is malformed"))?;
        if !is_http_token(name) {
            return Err(malformed_upstream_response(
                "response header name is invalid",
            ));
        }
        validate_header_value(value, "response header")?;
        if name.eq_ignore_ascii_case("Content-Length") {
            if content_length.is_some() {
                return Err(malformed_upstream_response(
                    "duplicate response content length",
                ));
            }
            content_length =
                Some(value.trim().parse::<usize>().map_err(|_| {
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
        if name.eq_ignore_ascii_case("Connection") {
            connection_close |= value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("close"));
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
        return Ok((status_code, ResponseBodyFraming::Interim, connection_close));
    }
    if body_expectation == ResponseBodyExpectation::HeadResponse
        || matches!(status_code, 101 | 204 | 304)
    {
        return Ok((status_code, ResponseBodyFraming::None, connection_close));
    }
    let framing = if transfer_encoding_chunked {
        ResponseBodyFraming::Chunked
    } else if let Some(content_length) = content_length {
        ResponseBodyFraming::ContentLength(content_length)
    } else {
        ResponseBodyFraming::CloseDelimited
    };
    Ok((status_code, framing, connection_close))
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
    let (name, value) = line
        .split_once(':')
        .ok_or_else(|| malformed_upstream_response("chunk trailer is malformed"))?;
    if !is_http_token(name) {
        return Err(malformed_upstream_response("chunk trailer name is invalid"));
    }
    validate_header_value(value, "chunk trailer")?;
    Ok(())
}

fn validate_header_value(value: &str, field: &'static str) -> Result<(), AppError> {
    if contains_prohibited_http_field_value_control(value) {
        return Err(malformed_upstream_response(match field {
            "response header" => "response header value contains prohibited control byte",
            "chunk trailer" => "chunk trailer value contains prohibited control byte",
            _ => "response field value contains prohibited control byte",
        }));
    }
    Ok(())
}

fn malformed_upstream_response(message: &'static str) -> AppError {
    AppError::new(ErrorCode::RuntimeUpstreamBadGateway, message)
}

pub(crate) fn parse_response_status_code(bytes: &[u8]) -> Option<u16> {
    let line_end = bytes.windows(2).position(|window| window == b"\r\n")?;
    let status_line = std::str::from_utf8(&bytes[..line_end]).ok()?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse::<u16>().ok()
}
