//! TLS and WebSocket pending-byte ownership calculations for payload accounting.

use edge_domain::AppError;

use crate::payload_budget_ledger::resource_accounting_error;
use crate::{ClientTransport, PendingSocketOutput, UpstreamTransport, WriteBuffer};

pub(crate) fn tls_pending_owner_bytes(
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

pub(crate) fn websocket_pending_owner_bytes(
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
