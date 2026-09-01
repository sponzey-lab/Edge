//! Pure HTTP forwarding header, upgrade, and redirect policy.

use edge_domain::{AppError, ErrorCode};

use crate::{Header, HttpRequest};

/// Bounded incremental projection of non-upgrade upstream response headers.
///
/// The snapshot runtime validates response framing before passing bytes here.
/// This adapter removes response hop-by-hop fields without buffering the body.
/// `Transfer-Encoding` remains because the runtime forwards the already-framed
/// chunk stream rather than decoding and re-encoding it. The current runtime
/// closes every non-upgrade client connection after its final response, so the
/// projected final header explicitly advertises `Connection: close`; otherwise
/// an HTTP/1.1 client can reuse a connection the runtime has already closed.
#[derive(Debug)]
pub(crate) struct UpstreamResponseHeaderSanitizer {
    headers: Vec<u8>,
    max_header_bytes: usize,
    forwarding_body: bool,
}

impl UpstreamResponseHeaderSanitizer {
    pub(crate) fn new(max_header_bytes: usize) -> Self {
        Self {
            headers: Vec::new(),
            max_header_bytes,
            forwarding_body: false,
        }
    }

    pub(crate) fn sanitize(&mut self, input: &[u8]) -> Result<Vec<u8>, AppError> {
        if self.forwarding_body {
            return Ok(input.to_vec());
        }

        let mut output = Vec::new();
        let mut cursor = 0;
        while cursor < input.len() {
            if self.headers.len() >= self.max_header_bytes {
                return Err(response_header_error(
                    ErrorCode::ResourcePayloadCapacityReached,
                    "response header sanitizer limit reached",
                ));
            }
            if self.headers.len() == self.headers.capacity() {
                self.headers.try_reserve(1).map_err(|_| {
                    response_header_error(
                        ErrorCode::ResourceAllocationFailed,
                        "response header sanitizer allocation failed",
                    )
                })?;
            }
            self.headers.push(input[cursor]);
            cursor += 1;
            if !self.headers.ends_with(b"\r\n\r\n") {
                continue;
            }

            let (sanitized, interim) = sanitize_response_header_block(&self.headers)?;
            output.try_reserve(sanitized.len()).map_err(|_| {
                response_header_error(
                    ErrorCode::ResourceAllocationFailed,
                    "response header sanitizer allocation failed",
                )
            })?;
            output.extend_from_slice(&sanitized);
            self.headers.clear();
            if !interim {
                self.forwarding_body = true;
                output.try_reserve(input.len() - cursor).map_err(|_| {
                    response_header_error(
                        ErrorCode::ResourceAllocationFailed,
                        "response header sanitizer allocation failed",
                    )
                })?;
                output.extend_from_slice(&input[cursor..]);
                break;
            }
        }
        Ok(output)
    }
}

fn sanitize_response_header_block(headers: &[u8]) -> Result<(Vec<u8>, bool), AppError> {
    let header_text = std::str::from_utf8(headers).map_err(|_| {
        response_header_error(
            ErrorCode::RuntimeUpstreamBadGateway,
            "response headers are not UTF-8",
        )
    })?;
    let header_text = header_text.strip_suffix("\r\n\r\n").ok_or_else(|| {
        response_header_error(
            ErrorCode::RuntimeUpstreamBadGateway,
            "response header terminator is missing",
        )
    })?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().ok_or_else(|| {
        response_header_error(
            ErrorCode::RuntimeUpstreamBadGateway,
            "response status line is missing",
        )
    })?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| {
            response_header_error(
                ErrorCode::RuntimeUpstreamBadGateway,
                "response status code is invalid",
            )
        })?;
    let parsed_headers = lines
        .map(|line| {
            let (name, value) = line.split_once(':').ok_or_else(|| {
                response_header_error(
                    ErrorCode::RuntimeUpstreamBadGateway,
                    "response header is malformed",
                )
            })?;
            Ok(Header {
                name: name.to_string(),
                value: value.trim_start().to_string(),
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    let connection_tokens = connection_header_tokens(&parsed_headers);
    let retained = parsed_headers.into_iter().filter(|header| {
        let name = header.name.to_ascii_lowercase();
        name == "transfer-encoding"
            || (!is_hop_by_hop_header_name(&name)
                && !connection_tokens.iter().any(|token| token == &name))
    });

    let interim = (100..200).contains(&status_code) && status_code != 101;
    let mut sanitized = String::from(status_line);
    sanitized.push_str("\r\n");
    for header in retained {
        sanitized.push_str(&header.name);
        sanitized.push_str(": ");
        sanitized.push_str(&header.value);
        sanitized.push_str("\r\n");
    }
    if !interim {
        sanitized.push_str("Connection: close\r\n");
    }
    sanitized.push_str("\r\n");
    Ok((sanitized.into_bytes(), interim))
}

fn response_header_error(code: ErrorCode, message: &'static str) -> AppError {
    AppError::new(code, message)
}

pub fn remove_hop_by_hop_headers(headers: &[Header]) -> Vec<Header> {
    let connection_tokens = connection_header_tokens(headers);

    headers
        .iter()
        .filter(|header| {
            let name = header.name.to_ascii_lowercase();
            !is_hop_by_hop_header_name(&name)
                && !connection_tokens.iter().any(|token| token == &name)
        })
        .cloned()
        .collect()
}

/// Projects client headers for an upstream request. When the caller has
/// already validated a WebSocket upgrade, it preserves only the required
/// `Upgrade` field and emits a normalized `Connection: Upgrade` pair.
pub fn upstream_request_headers(headers: &[Header], preserve_upgrade: bool) -> Vec<Header> {
    if !preserve_upgrade {
        return remove_hop_by_hop_headers(headers);
    }

    let connection_tokens = connection_header_tokens(headers);
    let mut projected = headers
        .iter()
        .filter(|header| {
            let name = header.name.to_ascii_lowercase();
            (name == "upgrade" && header.value.trim().eq_ignore_ascii_case("websocket"))
                || (!is_hop_by_hop_header_name(&name)
                    && !connection_tokens.iter().any(|token| token == &name))
        })
        .cloned()
        .collect::<Vec<_>>();
    projected.push(Header {
        name: "Connection".to_string(),
        value: "Upgrade".to_string(),
    });
    projected
}

fn connection_header_tokens(headers: &[Header]) -> Vec<String> {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("Connection"))
        .flat_map(|header| {
            header
                .value
                .split(',')
                .map(|value| value.trim().to_ascii_lowercase())
        })
        .collect()
}

fn is_hop_by_hop_header_name(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
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

/// Reports a WebSocket upgrade request only for exact HTTP connection tokens.
///
/// Multiple `Connection` or `Upgrade` fields are allowed, but each relevant
/// value must contain an exact case-insensitive token rather than a substring.
pub fn is_websocket_upgrade(request: &HttpRequest) -> bool {
    request
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("Connection"))
        .any(|header| {
            header
                .value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
        && request
            .headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case("Upgrade"))
            .any(|header| header.value.trim().eq_ignore_ascii_case("websocket"))
}

pub fn https_redirect_location(host: &str, path: &str) -> String {
    format!("https://{host}{path}")
}

#[cfg(test)]
mod tests {
    use super::UpstreamResponseHeaderSanitizer;

    #[test]
    fn response_header_sanitizer_removes_hop_headers_across_fragments_and_interim() {
        let mut sanitizer = UpstreamResponseHeaderSanitizer::new(1024);

        assert_eq!(
            sanitizer
                .sanitize(b"HTTP/1.1 100 Continue\r\nConnection: X-Interim")
                .unwrap(),
            Vec::<u8>::new()
        );
        let projected = sanitizer
            .sanitize(
                b"\r\nX-Interim: drop\r\n\r\nHTTP/1.1 200 OK\r\nConnection: X-Hop\r\nX-Hop: drop\r\nProxy-Connection: close\r\nContent-Length: 2\r\nETag: stable\r\n\r\nok",
            )
            .unwrap();
        let projected = String::from_utf8(projected).unwrap();

        assert_eq!(
            projected,
            "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\nETag: stable\r\nConnection: close\r\n\r\nok"
        );
    }
}
