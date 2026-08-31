//! Client and upstream plaintext/TLS transport facades.

use edge_domain::AppError;
use edge_ports::{TlsPendingBytes, TlsSession};

use crate::{ConnectionInterest, TlsTransport, TlsTransportState, WriteBuffer};

#[derive(Debug, Default)]
pub struct PlaintextClientTransport {
    pub(crate) socket_output: Vec<u8>,
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

#[derive(Debug, Default)]
pub struct PlaintextUpstreamTransport {
    pub(crate) socket_output: Vec<u8>,
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
