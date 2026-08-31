use std::collections::VecDeque;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use edge_ports::{
    HealthProbeCompletion, HealthProbeDispatcher, HealthProbeRequest, HealthProbeSubmit,
    HealthProbeTransport,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthProbeWorkerBuildError {
    NoWorkers,
    ZeroCapacity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthProbeShutdownReport {
    pub cancelled_queued: usize,
    pub joined_workers: usize,
    pub already_stopped: bool,
}

#[derive(Debug)]
struct HealthProbeWorkerState {
    queue: VecDeque<HealthProbeRequest>,
    accepting: bool,
    outstanding: usize,
}

#[derive(Debug)]
struct SharedHealthProbeWorkerState {
    state: Mutex<HealthProbeWorkerState>,
    work_available: Condvar,
    capacity: usize,
}

#[derive(Debug)]
pub struct HealthProbeCompletionReceiver {
    receiver: Receiver<HealthProbeCompletion>,
    shared: Arc<SharedHealthProbeWorkerState>,
}

impl HealthProbeCompletionReceiver {
    pub fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<HealthProbeCompletion, RecvTimeoutError> {
        let completion = self.receiver.recv_timeout(timeout)?;
        self.release_outstanding_slot();
        Ok(completion)
    }

    pub fn try_recv(&self) -> Result<HealthProbeCompletion, TryRecvError> {
        let completion = self.receiver.try_recv()?;
        self.release_outstanding_slot();
        Ok(completion)
    }

    fn release_outstanding_slot(&self) {
        let mut state = lock_worker_state(&self.shared);
        state.outstanding = state.outstanding.saturating_sub(1);
    }
}

impl Drop for HealthProbeCompletionReceiver {
    fn drop(&mut self) {
        let mut state = lock_worker_state(&self.shared);
        state.accepting = false;
        let cancelled = state.queue.len();
        state.queue.clear();
        state.outstanding = state.outstanding.saturating_sub(cancelled);
        drop(state);
        self.shared.work_available.notify_all();
    }
}

#[derive(Debug)]
pub struct HealthProbeWorkerPool {
    shared: Arc<SharedHealthProbeWorkerState>,
    workers: Vec<JoinHandle<()>>,
}

impl HealthProbeWorkerPool {
    pub fn new<T>(
        transports: Vec<T>,
        capacity: usize,
    ) -> Result<(Self, HealthProbeCompletionReceiver), HealthProbeWorkerBuildError>
    where
        T: HealthProbeTransport + Send + 'static,
    {
        if transports.is_empty() {
            return Err(HealthProbeWorkerBuildError::NoWorkers);
        }
        if capacity == 0 {
            return Err(HealthProbeWorkerBuildError::ZeroCapacity);
        }

        let shared = Arc::new(SharedHealthProbeWorkerState {
            state: Mutex::new(HealthProbeWorkerState {
                queue: VecDeque::new(),
                accepting: true,
                outstanding: 0,
            }),
            work_available: Condvar::new(),
            capacity,
        });
        let (completion_sender, completion_receiver) = mpsc::sync_channel(capacity);
        let workers = transports
            .into_iter()
            .map(|mut transport| {
                let shared = Arc::clone(&shared);
                let completion_sender = completion_sender.clone();
                thread::spawn(move || {
                    while let Some(request) = take_probe_work(&shared) {
                        let result = transport.probe(request.clone());
                        if completion_sender
                            .send(HealthProbeCompletion { request, result })
                            .is_err()
                        {
                            let mut state = lock_worker_state(&shared);
                            state.outstanding = state.outstanding.saturating_sub(1);
                        }
                    }
                })
            })
            .collect();
        drop(completion_sender);

        Ok((
            Self {
                shared: Arc::clone(&shared),
                workers,
            },
            HealthProbeCompletionReceiver {
                receiver: completion_receiver,
                shared,
            },
        ))
    }

    pub fn submit(&self, request: HealthProbeRequest) -> HealthProbeSubmit {
        let mut state = lock_worker_state(&self.shared);
        if !state.accepting {
            return HealthProbeSubmit::Stopped;
        }
        if state.outstanding >= self.shared.capacity {
            return HealthProbeSubmit::Full;
        }
        state.outstanding += 1;
        state.queue.push_back(request);
        drop(state);
        self.shared.work_available.notify_one();
        HealthProbeSubmit::Accepted
    }

    pub fn shutdown(&mut self) -> HealthProbeShutdownReport {
        if self.workers.is_empty() {
            return HealthProbeShutdownReport {
                cancelled_queued: 0,
                joined_workers: 0,
                already_stopped: true,
            };
        }
        let cancelled_queued = {
            let mut state = lock_worker_state(&self.shared);
            state.accepting = false;
            let cancelled = state.queue.len();
            state.queue.clear();
            state.outstanding = state.outstanding.saturating_sub(cancelled);
            cancelled
        };
        self.shared.work_available.notify_all();
        let joined_workers = self.workers.len();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
        HealthProbeShutdownReport {
            cancelled_queued,
            joined_workers,
            already_stopped: false,
        }
    }
}

impl HealthProbeDispatcher for HealthProbeWorkerPool {
    fn submit(&self, request: HealthProbeRequest) -> HealthProbeSubmit {
        HealthProbeWorkerPool::submit(self, request)
    }
}

impl Drop for HealthProbeWorkerPool {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn lock_worker_state(
    shared: &SharedHealthProbeWorkerState,
) -> std::sync::MutexGuard<'_, HealthProbeWorkerState> {
    shared
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn take_probe_work(shared: &SharedHealthProbeWorkerState) -> Option<HealthProbeRequest> {
    let mut state = lock_worker_state(shared);
    loop {
        if let Some(request) = state.queue.pop_front() {
            return Some(request);
        }
        if !state.accepting {
            return None;
        }
        state = shared
            .work_available
            .wait(state)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
    }
}
