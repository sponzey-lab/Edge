use edge_core::{WorkerEvent, WorkerEventQueue};
use edge_domain::{AppError, ErrorCode};

#[test]
fn worker_event_queue_contract_preserves_failure_fifo_order() {
    let mut queue = WorkerEventQueue::default();
    queue.push(WorkerEvent::Failed(AppError::new(
        ErrorCode::RuntimeCommandRejected,
        "first",
    )));
    queue.push(WorkerEvent::Failed(AppError::new(
        ErrorCode::RuntimeHealthUnavailable,
        "second",
    )));

    assert!(matches!(
        queue.pop(),
        Some(WorkerEvent::Failed(error)) if error.code == ErrorCode::RuntimeCommandRejected
    ));
    assert!(matches!(
        queue.pop(),
        Some(WorkerEvent::Failed(error)) if error.code == ErrorCode::RuntimeHealthUnavailable
    ));
    assert!(queue.pop().is_none());
}
