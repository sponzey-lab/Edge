use edge_core::{ConnectionToken, TokenAllocator};

#[test]
fn token_allocator_contract_remains_available_from_the_crate_root() {
    let mut allocator = TokenAllocator::default();
    let first = allocator.allocate();
    let second = allocator.allocate();
    assert_ne!(first, second);
    assert_eq!(first.as_usize(), 0);

    allocator.release(second);
    allocator.release(first);
    assert_eq!(allocator.allocate(), first);
    assert_eq!(ConnectionToken::new(7).as_usize(), 7);
}
