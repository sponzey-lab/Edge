//! Bounded, listener-free Admin HTTP request parsing and response rendering.

use edge_domain::{AppError, ErrorCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminHttpMethod {
    Get,
    Post,
    Patch,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminHttpRequest {
    pub method: AdminHttpMethod,
    pub path: String,
    pub request_id: String,
    pub session_id: Option<String>,
    pub csrf_token: Option<String>,
    pub body: String,
}

impl AdminHttpRequest {
    pub fn new(
        method: AdminHttpMethod,
        path: impl Into<String>,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            method,
            path: path.into(),
            request_id: request_id.into(),
            session_id: None,
            csrf_token: None,
            body: String::new(),
        }
    }

    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    pub fn with_csrf_token(mut self, csrf_token: impl Into<String>) -> Self {
        self.csrf_token = Some(csrf_token.into());
        self
    }

    pub fn with_body(mut self, body: impl Into<String>) -> Self {
        self.body = body.into();
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminHttpResponse {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub error_code: Option<String>,
}

impl AdminHttpResponse {
    pub fn from_error(status_code: u16, error: AppError, request_id: &str) -> Self {
        super::error_response(status_code, error, request_id)
    }

    pub(crate) fn json(status_code: u16, body: String) -> Self {
        Self {
            status_code,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body,
            error_code: None,
        }
    }

    pub(crate) fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub(crate) fn with_error_code(mut self, error_code: impl Into<String>) -> Self {
        self.error_code = Some(error_code.into());
        self
    }
}

/// Parses only the request envelope supplied by a listener; no socket or environment access.
pub fn parse_admin_http_request(
    raw: &str,
    fallback_request_id: impl Into<String>,
) -> Result<AdminHttpRequest, AppError> {
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw, ""));
    let mut lines = head.lines();
    let request_line = lines.next().ok_or_else(|| {
        AppError::new(ErrorCode::HttpMalformedRequest, "missing HTTP request line")
    })?;
    let mut request_parts = request_line.split_whitespace();
    let method = parse_http_method(request_parts.next())?;
    let path = request_parts
        .next()
        .ok_or_else(|| AppError::new(ErrorCode::HttpMalformedRequest, "missing HTTP path"))?;
    let version = request_parts
        .next()
        .ok_or_else(|| AppError::new(ErrorCode::HttpMalformedRequest, "missing HTTP version"))?;
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(AppError::new(
            ErrorCode::HttpMalformedRequest,
            "unsupported HTTP version",
        ));
    }

    let mut request_id = fallback_request_id.into();
    let mut session_id = None;
    let mut csrf_token = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(AppError::new(
                ErrorCode::HttpMalformedRequest,
                "malformed HTTP header",
            ));
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("x-request-id") && !value.is_empty() {
            request_id = value.to_string();
        } else if name.eq_ignore_ascii_case("x-csrf-token") && !value.is_empty() {
            csrf_token = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("cookie") {
            session_id = cookie_value(value, "sponzey_session").map(str::to_string);
        }
    }

    Ok(AdminHttpRequest {
        method,
        path: path.to_string(),
        request_id,
        session_id,
        csrf_token,
        body: body.to_string(),
    })
}

pub fn render_admin_http_response(response: &AdminHttpResponse) -> String {
    let mut rendered = format!(
        "HTTP/1.1 {} {}\r\ncontent-length: {}\r\n",
        response.status_code,
        status_reason(response.status_code),
        response.body.len()
    );
    for (name, value) in &response.headers {
        rendered.push_str(name);
        rendered.push_str(": ");
        rendered.push_str(value);
        rendered.push_str("\r\n");
    }
    rendered.push_str("\r\n");
    rendered.push_str(&response.body);
    rendered
}

fn parse_http_method(method: Option<&str>) -> Result<AdminHttpMethod, AppError> {
    match method {
        Some("GET") => Ok(AdminHttpMethod::Get),
        Some("POST") => Ok(AdminHttpMethod::Post),
        Some("PATCH") => Ok(AdminHttpMethod::Patch),
        Some("DELETE") => Ok(AdminHttpMethod::Delete),
        Some(_) => Err(AppError::new(
            ErrorCode::HttpMalformedRequest,
            "unsupported HTTP method",
        )),
        None => Err(AppError::new(
            ErrorCode::HttpMalformedRequest,
            "missing HTTP method",
        )),
    }
}

fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|part| {
        let (candidate, value) = part.trim().split_once('=')?;
        (candidate == name).then_some(value)
    })
}

fn status_reason(status_code: u16) -> &'static str {
    match status_code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        500 => "Internal Server Error",
        _ => "Error",
    }
}
