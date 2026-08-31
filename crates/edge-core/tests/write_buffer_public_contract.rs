use edge_core::WriteBuffer;

#[test]
fn write_buffer_contract_remains_available_from_the_crate_root() {
    let mut buffer = WriteBuffer::new(b"abc".to_vec());

    assert_eq!(buffer.advance(1), 1);
    buffer.try_append(b"d").unwrap();
    assert_eq!(buffer.remaining(), b"bcd");

    assert_eq!(buffer.advance_and_clear_if_complete(3), 3);
    assert!(buffer.is_complete());
    assert!(buffer.bytes().is_empty());
}
