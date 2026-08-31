//! Admin runtime-log receiver and bounded-buffer collector adapter.
//!
//! The collector owns no HTTP request handling or logging policy. It stops when
//! its input channel closes or a bounded buffer lock becomes unavailable.

use std::sync::{atomic::AtomicU64, mpsc, Arc, Mutex};
use std::thread;

use edge_application::{
    AccessLogEvent, RecentAccessLogBuffer, RecentErrorBuffer, RecentErrorEvent,
};

pub struct AdminLogReceivers {
    pub access: mpsc::Receiver<AccessLogEvent>,
    pub error: mpsc::Receiver<RecentErrorEvent>,
    pub dropped: Arc<AtomicU64>,
}

pub(crate) fn spawn_access_log_collector(
    access_logs: Arc<Mutex<RecentAccessLogBuffer>>,
    receiver: mpsc::Receiver<AccessLogEvent>,
) {
    thread::spawn(move || {
        while let Ok(event) = receiver.recv() {
            let Ok(mut access_logs) = access_logs.lock() else {
                break;
            };
            access_logs.push(event);
        }
    });
}

pub(crate) fn spawn_error_log_collector(
    error_logs: Arc<Mutex<RecentErrorBuffer>>,
    receiver: mpsc::Receiver<RecentErrorEvent>,
) {
    thread::spawn(move || {
        while let Ok(event) = receiver.recv() {
            let Ok(mut error_logs) = error_logs.lock() else {
                break;
            };
            error_logs.push(event);
        }
    });
}
