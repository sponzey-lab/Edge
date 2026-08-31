//! Token-keyed deadline ordering and expiry collection.

use std::time::Instant;

use crate::ConnectionToken;

#[derive(Debug, Default)]
pub struct TimerQueue {
    timers: Vec<(Instant, ConnectionToken)>,
}

impl TimerQueue {
    pub fn schedule(&mut self, token: ConnectionToken, deadline: Instant) {
        self.timers.push((deadline, token));
        self.timers.sort_by_key(|(deadline, _)| *deadline);
    }

    pub fn pop_expired(&mut self, now: Instant) -> Vec<ConnectionToken> {
        let split = self
            .timers
            .iter()
            .position(|(deadline, _)| *deadline > now)
            .unwrap_or(self.timers.len());
        self.timers.drain(..split).map(|(_, token)| token).collect()
    }
}
