use edge_core::{
    forwarded_headers, https_redirect_location, is_websocket_upgrade, parse_http_request,
    remove_hop_by_hop_headers, Header, HttpLimits,
};

#[test]
fn http_forwarding_policy_contract_remains_available_from_the_crate_root() {
    let headers = vec![
        Header {
            name: "Connection".to_string(),
            value: "X-Hop".to_string(),
        },
        Header {
            name: "X-Hop".to_string(),
            value: "remove".to_string(),
        },
    ];
    assert!(remove_hop_by_hop_headers(&headers).is_empty());
    assert_eq!(
        forwarded_headers("127.0.0.1", "https", "example.test")[1].value,
        "https"
    );

    let request = parse_http_request(
        b"GET /socket HTTP/1.1\r\nHost: example.test\r\nConnection: upgrade\r\nUpgrade: WebSocket\r\n\r\n",
        &HttpLimits::default(),
    )
    .unwrap();
    assert!(is_websocket_upgrade(&request));
    assert_eq!(
        https_redirect_location("example.test", "/"),
        "https://example.test/"
    );
}
