use edge_core::{ClientTransport, ConnectionInterest, UpstreamTransport};
use edge_ports::ScriptedTlsSession;

#[test]
fn client_transport_contract_preserves_plaintext_and_tls_projections() {
    let mut plaintext = ClientTransport::plaintext();
    assert!(!plaintext.is_tls());
    assert_eq!(plaintext.forwarded_scheme(), "http");
    assert_eq!(plaintext.queue_http_bytes(b"response"), Ok(8));
    assert_eq!(plaintext.take_socket_bytes(3), b"res");
    assert_eq!(plaintext.take_socket_bytes(8), b"ponse");

    let mut tls = ClientTransport::tls(Box::new(ScriptedTlsSession::established()));
    assert!(tls.is_tls());
    assert_eq!(tls.forwarded_scheme(), "https");
    assert_eq!(tls.queue_http_bytes(b"response"), Ok(8));
    assert_eq!(tls.take_socket_bytes(8), b"response");
}

#[test]
fn upstream_transport_contract_preserves_plaintext_and_tls_readiness() {
    let mut plaintext = UpstreamTransport::plaintext();
    assert!(!plaintext.is_tls());
    assert_eq!(plaintext.queue_http_bytes(b"request"), Ok(7));
    assert_eq!(plaintext.take_socket_bytes(8), b"request");

    let tls = UpstreamTransport::tls(Box::new(ScriptedTlsSession::new()));
    assert!(tls.is_tls());
    assert_eq!(
        tls.merge_interest(ConnectionInterest {
            upstream_readable: true,
            upstream_writable: true,
            ..ConnectionInterest::default()
        }),
        ConnectionInterest {
            upstream_readable: true,
            ..ConnectionInterest::default()
        }
    );
}
