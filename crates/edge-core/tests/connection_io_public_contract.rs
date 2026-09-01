use edge_core::{
    Connection, ConnectionState, ConnectionToken, HttpConnectionIo, HttpLimits, RequestReadOutcome,
};
use edge_domain::ErrorCode;

#[test]
fn connection_io_contract_preserves_transition_rejection_and_buffer_lifecycle() {
    let mut connection = Connection {
        token: ConnectionToken::new(1),
        state: ConnectionState::Accepted,
    };
    assert_eq!(
        connection
            .transition_to(ConnectionState::Draining)
            .unwrap_err()
            .code,
        ErrorCode::RuntimeCommandRejected
    );

    let mut io = HttpConnectionIo::new(ConnectionToken::new(2));
    let limits = HttpLimits::default();
    assert_eq!(
        io.receive_client_bytes(b"GET /", &limits),
        Ok(RequestReadOutcome::Incomplete)
    );
    assert_eq!(io.connection.state, ConnectionState::ReadingClientRequest);
    assert!(matches!(
        io.receive_client_bytes(b" HTTP/1.1\r\nHost: example.test\r\n\r\n", &limits),
        Ok(RequestReadOutcome::Complete(_))
    ));
    assert_eq!(io.connection.state, ConnectionState::SelectingRoute);

    io.queue_client_response(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec())
        .unwrap();
    assert_eq!(io.connection.state, ConnectionState::WritingClientResponse);
    let buffered = io.client_write_buffer().remaining_len();
    assert_eq!(io.advance_client_write(buffered), Ok(buffered));
    assert_eq!(io.connection.state, ConnectionState::WritingClientResponse);
    io.finish_client_response(false).unwrap();
    assert_eq!(io.connection.state, ConnectionState::Draining);
    assert!(io.client_write_buffer().is_complete());
}
