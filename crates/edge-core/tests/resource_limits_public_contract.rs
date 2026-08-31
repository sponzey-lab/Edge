use std::time::Duration;

use edge_core::ResourceLimits;
use edge_domain::{
    DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_REQUEST_BODY_BYTES, FIXED_REQUEST_HEADER_RESERVE_BYTES,
    FIXED_RESPONSE_BUFFER_RESERVE_BYTES,
};

#[test]
fn resource_limits_defaults_remain_available_from_the_crate_root() {
    let limits = ResourceLimits::default();

    assert_eq!(limits.max_connections, DEFAULT_MAX_CONNECTIONS);
    assert_eq!(
        limits.max_request_header_bytes,
        FIXED_REQUEST_HEADER_RESERVE_BYTES
    );
    assert_eq!(
        limits.max_request_body_bytes,
        DEFAULT_MAX_REQUEST_BODY_BYTES
    );
    assert_eq!(limits.idle_timeout, Duration::from_secs(30));
    assert_eq!(limits.connect_timeout, Duration::from_secs(5));
    assert_eq!(limits.upstream_read_timeout, Duration::from_secs(30));
    assert_eq!(limits.client_write_timeout, Duration::from_secs(30));
    assert_eq!(
        limits.max_response_buffer_bytes,
        FIXED_RESPONSE_BUFFER_RESERVE_BYTES
    );
}
