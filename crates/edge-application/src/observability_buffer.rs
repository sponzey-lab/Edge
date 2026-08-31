//! Bounded in-memory state for operator-facing observability.
//!
//! These containers retain recent redacted events without recording, emitting,
//! or otherwise performing I/O.

use std::collections::VecDeque;

use edge_ports::StructuredLogEvent;

use crate::AccessLogEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestIdGenerator {
    prefix: String,
    next: u64,
}

impl RequestIdGenerator {
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
            next: 1,
        }
    }

    pub fn next_id(&mut self) -> String {
        let id = format!("{}-{:016x}", self.prefix, self.next);
        self.next += 1;
        id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedLogQueue {
    capacity: usize,
    events: VecDeque<StructuredLogEvent>,
    dropped_oldest: u64,
}

impl BoundedLogQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            events: VecDeque::new(),
            dropped_oldest: 0,
        }
    }

    pub fn push(&mut self, event: StructuredLogEvent) {
        if self.capacity == 0 {
            self.dropped_oldest += 1;
            return;
        }
        if self.events.len() >= self.capacity {
            self.events.pop_front();
            self.dropped_oldest += 1;
        }
        self.events.push_back(event);
    }

    pub fn events(&self) -> Vec<StructuredLogEvent> {
        self.events.iter().cloned().collect()
    }

    pub fn dropped_oldest(&self) -> u64 {
        self.dropped_oldest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecentAccessLogBuffer {
    capacity: usize,
    events: VecDeque<AccessLogEvent>,
}

impl RecentAccessLogBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            events: VecDeque::new(),
        }
    }

    pub fn push(&mut self, event: AccessLogEvent) {
        if self.capacity == 0 {
            return;
        }
        if self.events.len() >= self.capacity {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    pub fn recent(&self) -> Vec<AccessLogEvent> {
        self.events.iter().cloned().collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecentErrorEvent {
    pub request_id: Option<String>,
    pub error_code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecentErrorBuffer {
    capacity: usize,
    events: VecDeque<RecentErrorEvent>,
}

impl RecentErrorBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            events: VecDeque::new(),
        }
    }

    pub fn push(&mut self, event: RecentErrorEvent) {
        if self.capacity == 0 {
            return;
        }
        if self.events.len() >= self.capacity {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    pub fn recent(&self) -> Vec<RecentErrorEvent> {
        self.events.iter().cloned().collect()
    }
}
