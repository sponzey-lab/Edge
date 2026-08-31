use edge_core::{
    select_certificate_for_sni, CertificateSelection, PendingSocketOutput,
    PreparedClientTlsRegistry, PreparedServerTlsRegistry, TlsHandshakeEvent, TlsHandshakeMachine,
    TlsHandshakeOutcome, TlsHandshakeState, TlsTransport, TlsTransportState,
};
use edge_domain::{AppError, ConfigSnapshot};
use edge_ports::TlsSession;

#[test]
fn tls_contracts_remain_available_from_the_crate_root() {
    let _selector: fn(&ConfigSnapshot, &str) -> Option<CertificateSelection> =
        select_certificate_for_sni;
    let _event = TlsHandshakeEvent::TimeoutExpired;
    let _outcome = TlsHandshakeOutcome::StateChanged;
    let _transport_constructor: fn(Box<dyn TlsSession + Send>) -> TlsTransport = TlsTransport::new;
    let _transport_state = TlsTransportState::Established;
    let _failed = TlsHandshakeState::Failed(AppError::new(
        edge_domain::ErrorCode::TlsHandshakeTimeout,
        "fixture",
    ));

    assert_eq!(
        TlsHandshakeMachine::new().state(),
        &TlsHandshakeState::WaitingForClientHello
    );
    assert!(PreparedClientTlsRegistry::new().is_empty());
    assert!(PreparedServerTlsRegistry::new().is_empty());
    assert!(PendingSocketOutput::new().is_empty());
}
