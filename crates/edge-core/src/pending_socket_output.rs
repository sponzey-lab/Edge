//! Buffered client socket output awaiting nonblocking write acknowledgement.

use edge_domain::AppError;

use crate::{ClientTransport, WriteBuffer};

#[derive(Debug, Default)]
pub struct PendingSocketOutput {
    pub(crate) buffer: WriteBuffer,
}

impl PendingSocketOutput {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pull_from(&mut self, transport: &mut ClientTransport, max_bytes: usize) -> usize {
        if !self.is_empty() {
            return 0;
        }
        let bytes = transport.take_socket_bytes(max_bytes);
        let pulled = bytes.len();
        self.buffer = WriteBuffer::new(bytes);
        pulled
    }

    pub fn pull_tunnel_plaintext(
        &mut self,
        transport: &mut ClientTransport,
        plaintext: &[u8],
    ) -> Result<usize, AppError> {
        if !self.is_empty() {
            return Ok(0);
        }
        match transport {
            ClientTransport::Plaintext(_) => {
                self.buffer.try_replace_if_complete(plaintext)?;
                Ok(plaintext.len())
            }
            ClientTransport::Tls(transport) => {
                let consumed = transport.receive_plaintext(plaintext)?;
                let socket_bytes = transport.take_encrypted(usize::MAX);
                self.buffer.try_replace_if_complete(&socket_bytes)?;
                Ok(consumed)
            }
        }
    }

    pub fn remaining(&self) -> &[u8] {
        self.buffer.remaining()
    }

    pub fn remaining_len(&self) -> usize {
        self.buffer.remaining_len()
    }

    pub fn advance(&mut self, byte_count: usize) -> usize {
        let advanced = self.buffer.advance(byte_count);
        self.buffer.clear_if_complete();
        advanced
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_complete()
    }
}
