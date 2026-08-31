//! Identity-indexed connection state storage and terminal-entry cleanup.

use std::collections::BTreeMap;

use crate::{Connection, ConnectionState, ConnectionToken};

#[derive(Debug, Default)]
pub struct ConnectionTable {
    entries: BTreeMap<usize, Connection>,
}

impl ConnectionTable {
    pub fn insert(&mut self, connection: Connection) -> Option<Connection> {
        self.entries.insert(connection.token.as_usize(), connection)
    }

    pub fn get(&self, token: ConnectionToken) -> Option<&Connection> {
        self.entries.get(&token.as_usize())
    }

    pub fn remove(&mut self, token: ConnectionToken) -> Option<Connection> {
        self.entries.remove(&token.as_usize())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn cleanup_closed(&mut self) -> Vec<ConnectionToken> {
        let removable: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, connection)| {
                matches!(
                    connection.state,
                    ConnectionState::Closed | ConnectionState::Failed
                )
            })
            .map(|(token, _)| ConnectionToken::new(*token))
            .collect();

        for token in &removable {
            self.entries.remove(&token.as_usize());
        }

        removable
    }
}
