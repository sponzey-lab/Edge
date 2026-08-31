//! Shared runtime-status adapters for the Admin HTTP boundary.
//!
//! These adapters retain only Core-published runtime facts. They expose bounded
//! lock outcomes and emit drain-transition observability; they do not parse or
//! handle Admin HTTP requests.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    mpsc, Arc, Mutex,
};

use edge_application::{
    failure_aware_metric, structured_failure_aware_log, FailureAwareEvent, FailureAwareTransition,
};
use edge_domain::{AppError, ErrorCode, HealthGeneration, OperationalRuntimeFacts};
use edge_ports::{
    MetricPublishOutcome, MetricPublisher, OperationalRuntimeStatusPublisher,
    OperationalRuntimeStatusReader, RuntimeResourceStatusPublishOutcome,
    RuntimeResourceStatusPublisher, RuntimeResourceStatusReader, RuntimeResourceStatusSnapshot,
    RuntimeUpstreamStatusPublisher, RuntimeUpstreamStatusReader, RuntimeUpstreamStatusSnapshot,
    StructuredLogEvent,
};

#[derive(Clone, Default)]
pub struct SharedOperationalRuntimeStatus(Arc<Mutex<Option<OperationalRuntimeFacts>>>);

impl OperationalRuntimeStatusPublisher for SharedOperationalRuntimeStatus {
    fn publish_operational_runtime_facts(&self, facts: OperationalRuntimeFacts) {
        if let Ok(mut current) = self.0.lock() {
            *current = Some(facts);
        }
    }
}

impl OperationalRuntimeStatusReader for SharedOperationalRuntimeStatus {
    fn read_operational_runtime_facts(&self) -> Result<OperationalRuntimeFacts, AppError> {
        self.0
            .lock()
            .map_err(|_| {
                AppError::new(
                    ErrorCode::InternalBug,
                    "operational runtime status lock poisoned",
                )
            })?
            .ok_or_else(|| {
                AppError::new(
                    ErrorCode::RuntimeHealthUnavailable,
                    "operational runtime status unavailable",
                )
            })
    }
}

#[derive(Clone, Default)]
pub struct SharedRuntimeUpstreamStatus {
    snapshot: Arc<Mutex<Option<RuntimeUpstreamStatusSnapshot>>>,
    product_log: Option<mpsc::SyncSender<StructuredLogEvent>>,
    metrics: Option<Arc<dyn MetricPublisher>>,
    dropped: Option<Arc<AtomicU64>>,
}

impl SharedRuntimeUpstreamStatus {
    pub fn with_observability(
        product_log: mpsc::SyncSender<StructuredLogEvent>,
        metrics: Arc<dyn MetricPublisher>,
        dropped: Arc<AtomicU64>,
    ) -> Self {
        Self {
            snapshot: Arc::new(Mutex::new(None)),
            product_log: Some(product_log),
            metrics: Some(metrics),
            dropped: Some(dropped),
        }
    }
}

impl RuntimeUpstreamStatusPublisher for SharedRuntimeUpstreamStatus {
    fn publish_runtime_status(&self, snapshot: RuntimeUpstreamStatusSnapshot) {
        if let Ok(mut current) = self.snapshot.try_lock() {
            if let Some(previous) = current.as_ref() {
                for item in &snapshot.upstreams {
                    let old = previous.upstreams.iter().find(|old| old.key == item.key);
                    let transition = match (old.map(|old| old.state), item.state) {
                        (
                            Some(edge_ports::RuntimeDrainState::Active),
                            edge_ports::RuntimeDrainState::Draining
                            | edge_ports::RuntimeDrainState::Drained,
                        ) => Some(FailureAwareTransition::DrainStarted),
                        (
                            Some(edge_ports::RuntimeDrainState::Draining),
                            edge_ports::RuntimeDrainState::Drained,
                        ) => Some(FailureAwareTransition::DrainCompleted),
                        _ => None,
                    };
                    if let Some(transition) = transition {
                        let event = FailureAwareEvent {
                            transition,
                            revision_id: snapshot.revision_id.clone(),
                            generation: HealthGeneration(snapshot.generation),
                            key: Some(item.key.clone()),
                            reason: Some("config_revision"),
                            connection_count: Some(item.connection_count),
                        };
                        let dropped = self.product_log.as_ref().is_some_and(|sender| {
                            sender
                                .try_send(structured_failure_aware_log(&event))
                                .is_err()
                        }) | self.metrics.as_ref().is_some_and(|publisher| {
                            publisher.try_publish(failure_aware_metric(&event))
                                != MetricPublishOutcome::Accepted
                        });
                        if dropped {
                            if let Some(counter) = &self.dropped {
                                counter.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
            *current = Some(snapshot);
        }
    }
}

impl RuntimeUpstreamStatusReader for SharedRuntimeUpstreamStatus {
    fn read_runtime_status(&self) -> Result<RuntimeUpstreamStatusSnapshot, AppError> {
        self.snapshot
            .lock()
            .map_err(|_| AppError::new(ErrorCode::InternalBug, "runtime status lock poisoned"))?
            .clone()
            .ok_or_else(|| {
                AppError::new(
                    ErrorCode::RuntimeHealthUnavailable,
                    "runtime status unavailable",
                )
            })
    }
}

#[derive(Clone, Default)]
pub struct SharedRuntimeResourceStatus {
    snapshot: Arc<Mutex<Option<RuntimeResourceStatusSnapshot>>>,
}

impl RuntimeResourceStatusPublisher for SharedRuntimeResourceStatus {
    fn try_publish_resource_status(
        &self,
        snapshot: RuntimeResourceStatusSnapshot,
    ) -> RuntimeResourceStatusPublishOutcome {
        match self.snapshot.try_lock() {
            Ok(mut current) => {
                *current = Some(snapshot);
                RuntimeResourceStatusPublishOutcome::Accepted
            }
            Err(std::sync::TryLockError::WouldBlock) => RuntimeResourceStatusPublishOutcome::Full,
            Err(std::sync::TryLockError::Poisoned(_)) => {
                RuntimeResourceStatusPublishOutcome::Stopped
            }
        }
    }
}

impl RuntimeResourceStatusReader for SharedRuntimeResourceStatus {
    fn read_resource_status(&self) -> Result<RuntimeResourceStatusSnapshot, AppError> {
        self.snapshot
            .lock()
            .map_err(|_| {
                AppError::new(
                    ErrorCode::InternalBug,
                    "runtime resource status lock poisoned",
                )
            })?
            .clone()
            .ok_or_else(|| {
                AppError::new(
                    ErrorCode::RuntimeHealthUnavailable,
                    "runtime resource status unavailable",
                )
            })
    }
}
