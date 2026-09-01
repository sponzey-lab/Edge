use edge_memory_harness::websocket_driver::{
    decode_server_frame, encode_masked_client_frame, encode_masked_text_frame,
    parse_websocket_options, websocket_upgrade_request, WebSocketLifecycle, WebSocketState,
};

#[test]
fn lifecycle_progresses_to_128_and_releases_exactly() {
    let mut lifecycle = WebSocketLifecycle::new(128).unwrap();
    for target in [32, 64, 128] {
        lifecycle.ramp_verified(target, target).unwrap();
    }
    assert_eq!(lifecycle.state(), WebSocketState::Holding);
    assert_eq!(lifecycle.held_count(), 128);
    assert_eq!(lifecycle.release().unwrap(), 128);
    assert_eq!(lifecycle.state(), WebSocketState::Completed);
}

#[test]
fn bounded_frame_codec_masks_clients_and_accepts_only_complete_server_frames() {
    let encoded = encode_masked_client_frame(b"ping").unwrap();
    assert_eq!(&encoded[..6], &[0x82, 0x84, 0x11, 0x22, 0x33, 0x44]);
    let text = encode_masked_text_frame(b"ping").unwrap();
    assert_eq!(&text[..6], &[0x81, 0x84, 0x11, 0x22, 0x33, 0x44]);
    assert_eq!(decode_server_frame(b"\x82\x04pong", 16).unwrap(), b"pong");

    assert!(decode_server_frame(b"\x82\x84\0\0\0\0pong", 16).is_err());
    assert!(decode_server_frame(b"\x82\x04po", 16).is_err());
    assert!(decode_server_frame(b"\x89\x04pong", 16).is_err());
    assert!(decode_server_frame(b"\x82\x7e\0\x7e", 125).is_err());
    assert!(encode_masked_client_frame(&[0; 126]).is_err());
}

#[test]
fn upgrade_request_uses_the_explicit_route_host_and_rejects_injection() {
    let request = websocket_upgrade_request("edge.test").unwrap();
    assert!(request.starts_with(b"GET /ws/echo HTTP/1.1\r\n"));
    assert!(request
        .windows(b"Host: edge.test\r\n".len())
        .any(|line| line == b"Host: edge.test\r\n"));
    assert!(websocket_upgrade_request("").is_err());
    assert!(websocket_upgrade_request("edge.test\r\nX-Injected: yes").is_err());
}

#[test]
fn invalid_ramp_release_and_cli_fail_closed() {
    let mut partial = WebSocketLifecycle::new(128).unwrap();
    assert!(partial.ramp_verified(32, 31).is_err());

    let mut duplicate = WebSocketLifecycle::new(32).unwrap();
    duplicate.ramp_verified(32, 32).unwrap();
    duplicate.release().unwrap();
    assert!(duplicate.release().is_err());

    assert_eq!(
        parse_websocket_options(&valid_args()).unwrap().connections,
        128
    );
    let mut missing = valid_args();
    missing.truncate(missing.len() - 2);
    assert!(parse_websocket_options(&missing).is_err());
    let mut duplicate_arg = valid_args();
    duplicate_arg.extend(["--connections".to_string(), "1".to_string()]);
    assert!(parse_websocket_options(&duplicate_arg).is_err());
    let mut zero = valid_args();
    zero[3] = "0".to_string();
    assert!(parse_websocket_options(&zero).is_err());
}

fn valid_args() -> Vec<String> {
    [
        "--address",
        "127.0.0.1:8080",
        "--connections",
        "128",
        "--timeout-ms",
        "5000",
        "--hold-timeout-ms",
        "60000",
        "--max-header-bytes",
        "4096",
        "--ready-output",
        "ready.txt",
        "--stop-file",
        "stop.txt",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}
