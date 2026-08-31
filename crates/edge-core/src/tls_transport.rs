//! Byte-oriented TLS session transport without socket ownership.

use edge_domain::{AppError, ErrorCode};
use edge_ports::{TlsPendingBytes, TlsSession, TlsSessionProgress};

use crate::ConnectionInterest;

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
