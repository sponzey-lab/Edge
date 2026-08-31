//! Pure TLS handshake state and certificate-selection boundary.

use edge_domain::{AppError, CertificateRef, ConfigSnapshot, ErrorCode};

use crate::ConnectionInterest;

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
