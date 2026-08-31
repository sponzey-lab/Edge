use edge_core::{Connection, ConnectionState, ConnectionTable, ConnectionToken};

#[test]
fn connection_table_contract_remains_available_from_the_crate_root() {
    let token = ConnectionToken::new(4);
    let mut table = ConnectionTable::default();
    table.insert(Connection {
        token,
        state: ConnectionState::Closed,
    });

    assert_eq!(table.cleanup_closed(), vec![token]);
    assert!(table.is_empty());
}
