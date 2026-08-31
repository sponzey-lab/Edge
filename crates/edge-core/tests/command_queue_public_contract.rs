use edge_core::{BoundedCommandQueue, QueueError};
use edge_domain::CoreCommand;

#[test]
fn bounded_command_queue_contract_remains_available_from_the_crate_root() {
    let mut queue = BoundedCommandQueue::new(1);
    queue.push(CoreCommand::RefreshRouteTable).unwrap();

    assert_eq!(queue.push(CoreCommand::Shutdown), Err(QueueError::Full));
    assert_eq!(queue.pop(), Some(CoreCommand::RefreshRouteTable));
    assert!(queue.is_empty());
}
