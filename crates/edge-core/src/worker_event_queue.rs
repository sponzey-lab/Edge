//! Worker completion-event vocabulary and FIFO handoff storage.

use std::collections::VecDeque;

use edge_domain::{AppError, ConfigSnapshot};

#[derive(Debug, Clone)]
pub enum WorkerEvent {
    ConfigSnapshotReady(ConfigSnapshot),
    Failed(AppError),
}

#[derive(Debug, Default)]
pub struct WorkerEventQueue {
    events: VecDeque<WorkerEvent>,
}

impl WorkerEventQueue {
    pub fn push(&mut self, event: WorkerEvent) {
        self.events.push_back(event);
    }

    pub fn pop(&mut self) -> Option<WorkerEvent> {
        self.events.pop_front()
    }
}
