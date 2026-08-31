use std::time::{Duration, Instant};

use edge_core::{ConnectionToken, TimerQueue};

#[test]
fn timer_queue_contract_keeps_deadline_order_and_includes_exact_expiry() {
    let now = Instant::now();
    let mut timers = TimerQueue::default();

    timers.schedule(ConnectionToken::new(3), now + Duration::from_secs(2));
    timers.schedule(ConnectionToken::new(1), now + Duration::from_secs(1));
    timers.schedule(ConnectionToken::new(2), now + Duration::from_secs(1));

    assert_eq!(
        timers.pop_expired(now + Duration::from_secs(1)),
        vec![ConnectionToken::new(1), ConnectionToken::new(2)]
    );
    assert_eq!(
        timers.pop_expired(now + Duration::from_secs(2)),
        vec![ConnectionToken::new(3)]
    );
}
