//! Process SIGTERM observation and bounded Core-drain delivery.
//!
//! The Unix signal handler only sets an atomic flag. A watcher consumes it
//! outside signal context and reports any rejected drain command without
//! mutating Core state directly.

use std::sync::{mpsc::SyncSender, Arc, Mutex};

use edge_core::snapshot_http::SnapshotRuntimeCommandClient;
use edge_domain::{CoreCommand, OperationalLifecycle};
use edge_ports::{CoreCommandClient, StructuredLogEvent};

const SIGTERM_DRAIN_DEADLINE_MS: u64 = 30_000;

#[cfg(unix)]
pub(crate) static SIGTERM_REQUESTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(unix)]
pub(crate) extern "C" fn handle_sigterm(_signal: libc::c_int) {
    // SAFETY: AtomicBool::store is lock-free on supported Unix targets and the
    // handler performs no allocation, I/O, locking, or command delivery.
    SIGTERM_REQUESTED.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(unix)]
pub(crate) fn install_sigterm_drain_watcher(
    mut command_client: SnapshotRuntimeCommandClient,
    lifecycle: Arc<Mutex<OperationalLifecycle>>,
    product_log: SyncSender<StructuredLogEvent>,
) -> std::io::Result<()> {
    SIGTERM_REQUESTED.store(false, std::sync::atomic::Ordering::Relaxed);
    // SAFETY: the handler is an extern C function with the required signature;
    // it only stores to SIGTERM_REQUESTED, which the watcher consumes outside
    // signal context.
    unsafe {
        libc::signal(
            libc::SIGTERM,
            handle_sigterm as *const () as libc::sighandler_t,
        );
    }
    std::thread::spawn(move || loop {
        if SIGTERM_REQUESTED.swap(false, std::sync::atomic::Ordering::Relaxed) {
            begin_sigterm_drain(&mut command_client, &lifecycle, &product_log);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    });
    Ok(())
}

pub(crate) fn begin_sigterm_drain<C>(
    command_client: &mut C,
    lifecycle: &Arc<Mutex<OperationalLifecycle>>,
    product_log: &SyncSender<StructuredLogEvent>,
) where
    C: CoreCommandClient,
{
    if let Ok(mut current) = lifecycle.lock() {
        *current = current.transition(edge_domain::OperationalLifecycleEvent::TerminationRequested);
    }
    let acknowledgement = command_client.send(CoreCommand::BeginDrain {
        deadline_ms: SIGTERM_DRAIN_DEADLINE_MS,
    });
    if !acknowledgement.is_success() {
        if let Ok(mut current) = lifecycle.lock() {
            *current = current.transition(edge_domain::OperationalLifecycleEvent::Failed);
        }
        let _ = product_log.try_send(StructuredLogEvent {
            component: "edge-proxy".to_string(),
            event: "process.drain.command_rejected".to_string(),
            fields: vec![(
                "error_code".to_string(),
                "RUNTIME_COMMAND_REJECTED".to_string(),
            )],
        });
    }
}

#[cfg(not(unix))]
pub(crate) fn install_sigterm_drain_watcher(
    _command_client: SnapshotRuntimeCommandClient,
    _lifecycle: Arc<Mutex<OperationalLifecycle>>,
    _product_log: SyncSender<StructuredLogEvent>,
) -> std::io::Result<()> {
    Ok(())
}
