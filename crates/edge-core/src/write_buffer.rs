//! Capacity-safe owned bytes awaiting nonblocking write acknowledgement.

use edge_domain::{AppError, ErrorCode};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WriteBuffer {
    pub(crate) bytes: Vec<u8>,
    written: usize,
}

impl WriteBuffer {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, written: 0 }
    }

    pub fn try_append(&mut self, chunk: &[u8]) -> Result<(), AppError> {
        self.try_reserve_append(chunk.len())?;
        self.bytes.extend_from_slice(chunk);
        Ok(())
    }

    pub(crate) fn try_reserve_append(&mut self, additional_bytes: usize) -> Result<(), AppError> {
        self.bytes
            .len()
            .checked_add(additional_bytes)
            .ok_or_else(resource_allocation_error)?;
        self.bytes
            .try_reserve_exact(additional_bytes)
            .map_err(|_| resource_allocation_error())
    }

    pub fn remaining(&self) -> &[u8] {
        &self.bytes[self.written..]
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn remaining_len(&self) -> usize {
        self.remaining().len()
    }

    pub fn is_complete(&self) -> bool {
        self.written >= self.bytes.len()
    }

    pub fn advance(&mut self, byte_count: usize) -> usize {
        let advanced = byte_count.min(self.remaining_len());
        self.written += advanced;
        advanced
    }

    pub fn advance_and_clear_if_complete(&mut self, byte_count: usize) -> usize {
        let advanced = self.advance(byte_count);
        self.clear_if_complete();
        advanced
    }

    pub fn clear_if_complete(&mut self) -> bool {
        if !self.is_complete() || self.bytes.is_empty() {
            return false;
        }
        self.bytes.clear();
        self.written = 0;
        true
    }

    pub fn try_replace_if_complete(&mut self, bytes: &[u8]) -> Result<bool, AppError> {
        if !self.is_complete() {
            return Ok(false);
        }
        let additional = bytes.len().saturating_sub(self.bytes.len());
        self.bytes
            .try_reserve_exact(additional)
            .map_err(|_| resource_allocation_error())?;
        self.bytes.clear();
        self.bytes.extend_from_slice(bytes);
        self.written = 0;
        Ok(true)
    }
}

fn resource_allocation_error() -> AppError {
    AppError::new(
        ErrorCode::ResourceAllocationFailed,
        "managed buffer allocation failed",
    )
}
