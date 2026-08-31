use edge_core::{parse_http_request, ClientRequestBuffer, HttpLimits, RequestReadOutcome};

#[test]
fn http_request_contract_remains_available_from_the_crate_root() {
    let limits = HttpLimits::default();
    let request =
        parse_http_request(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n", &limits).unwrap();
    assert_eq!(request.header_value("Host"), Some("example.test"));

    let mut buffer = ClientRequestBuffer::default();
    assert_eq!(
        buffer.push(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n", &limits),
        Ok(RequestReadOutcome::Complete(
            b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec()
        ))
    );
}
