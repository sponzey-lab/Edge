//! mio token identity and recycled-token allocation without socket registration.

use mio::Token;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionToken(Token);

impl ConnectionToken {
    pub fn new(value: usize) -> Self {
        Self(Token(value))
    }

    pub fn as_usize(&self) -> usize {
        self.0 .0
    }
}

#[derive(Debug, Default)]
pub struct TokenAllocator {
    next: usize,
    recycled: Vec<usize>,
}

impl TokenAllocator {
    pub fn allocate(&mut self) -> ConnectionToken {
        if let Some(value) = self.recycled.pop() {
            ConnectionToken::new(value)
        } else {
            let token = ConnectionToken::new(self.next);
            self.next += 1;
            token
        }
    }

    pub fn release(&mut self, token: ConnectionToken) {
        self.recycled.push(token.as_usize());
    }
}
