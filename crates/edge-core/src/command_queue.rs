//! Bounded FIFO storage for validated Core commands.

use std::collections::VecDeque;

use edge_domain::CoreCommand;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueError {
    Full,
}

#[derive(Debug)]
pub struct BoundedCommandQueue {
    capacity: usize,
    queue: VecDeque<CoreCommand>,
}

impl BoundedCommandQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            queue: VecDeque::new(),
        }
    }

    pub fn push(&mut self, command: CoreCommand) -> Result<(), QueueError> {
        if self.queue.len() >= self.capacity {
            return Err(QueueError::Full);
        }
        self.queue.push_back(command);
        Ok(())
    }

    pub fn pop(&mut self) -> Option<CoreCommand> {
        self.queue.pop_front()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

impl Default for BoundedCommandQueue {
    fn default() -> Self {
        Self::new(128)
    }
}
