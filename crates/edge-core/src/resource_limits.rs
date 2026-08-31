//! Typed resource-limit defaults for the core runtime.

use std::time::Duration;

use edge_domain::{
    DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_REQUEST_BODY_BYTES, FIXED_REQUEST_HEADER_RESERVE_BYTES,
    FIXED_RESPONSE_BUFFER_RESERVE_BYTES,
};

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
