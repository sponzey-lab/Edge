use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(test)]
use edge_adapters::MetricChannelPublisher;
use edge_adapters::{HealthProbeWorkerPool, HttpHealthProbeTransport, PreparedHealthTlsRegistry};
use edge_application::{
    failure_aware_metric, health_transition_metric, ignored_health_result_metric,
    structured_failure_aware_log, structured_health_probe_debug_log,
    structured_health_transition_log, upstream_availability_metric, FailureAwareEvent,
    FailureAwareTransition, FieldDebugHealthSampler, HandleProbeResult, HealthGenerationAllocator,
    HealthProbeDebugEvent, HealthReconciliationSnapshot, HealthRuntimeCoordinator,
    HealthRuntimeCoordinatorState, HealthTransitionEvent, PassiveHealthSupervisor,
};
use edge_domain::{
    AppError, ConfigSnapshot, CoreCommand, ErrorCode, HealthAvailabilitySnapshot, HealthGeneration,
    LogMode, PassiveHealthMode, PassiveHealthPolicy,
};
use edge_ports::{
    CoreCommandClient, HealthProbeOutcome, HealthProbeTransport, HealthStatusReader, MetricEvent,
    MetricPublishOutcome, MetricPublisher, PassiveObservation, PassiveObservationDispatcher,
    PassiveObservationSubmit, StructuredLogEvent,
};

const HEALTH_WORKERS: usize = 8;
const HEALTH_OUTSTANDING_CAPACITY: usize = 1_024;
const MAX_TICK_WORK: usize = 8;
const MAX_COMPLETION_DRAIN: usize = 32;
const PASSIVE_OBSERVATION_CAPACITY: usize = 1_024;
const LOOP_PAUSE: Duration = Duration::from_millis(25);

#[derive(Clone, Default)]
pub(crate) struct HealthRuntimeObservability {
    product_log: Option<SyncSender<StructuredLogEvent>>,
    metrics: Option<Arc<dyn MetricPublisher>>,
    dropped: Option<Arc<AtomicU64>>,
}

impl HealthRuntimeObservability {
    pub(crate) fn new(
        product_log: SyncSender<StructuredLogEvent>,
        metrics: Arc<dyn MetricPublisher>,
        dropped: Arc<AtomicU64>,
    ) -> Self {
        Self {
            product_log: Some(product_log),
            metrics: Some(metrics),
            dropped: Some(dropped),
        }
    }

    fn emit_log(&self, event: StructuredLogEvent) {
        if self
            .product_log
            .as_ref()
            .is_some_and(|sender| sender.try_send(event).is_err())
        {
            self.record_drop();
        }
    }

    fn emit_metric(&self, metric: MetricEvent) {
        if self.metrics.as_ref().is_some_and(|publisher| {
            publisher.try_publish(metric) != MetricPublishOutcome::Accepted
        }) {
            self.record_drop();
        }
    }

    fn record_drop(&self) {
        if let Some(counter) = &self.dropped {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HealthServiceState {
    Starting,
    Running,
    Stopping,
    Stopped,
}

pub(crate) struct StartupHealthRuntime {
    stop: Arc<AtomicBool>,
    state: Arc<Mutex<HealthServiceState>>,
    thread: Option<JoinHandle<()>>,
    start: Option<SyncSender<HealthStartSignal>>,
    #[cfg(test)]
    generation: HealthGeneration,
    reconciliation: Arc<Mutex<HealthReconciliationSnapshot>>,
    passive_dispatcher: PassiveObservationChannelDispatcher,
}

#[derive(Clone)]
pub(crate) struct PassiveObservationChannelDispatcher(SyncSender<PassiveObservation>);

impl PassiveObservationDispatcher for PassiveObservationChannelDispatcher {
    fn submit(&mut self, observation: PassiveObservation) -> PassiveObservationSubmit {
        match self.0.try_send(observation) {
            Ok(()) => PassiveObservationSubmit::Accepted,
            Err(mpsc::TrySendError::Full(_)) => PassiveObservationSubmit::Full,
            Err(mpsc::TrySendError::Disconnected(_)) => PassiveObservationSubmit::Stopped,
        }
    }
}

enum HealthStartSignal {
    Activate,
    Cancel,
}

pub(crate) struct PreparedHealthRuntime {
    runtime: StartupHealthRuntime,
    availability: HealthAvailabilitySnapshot,
}

pub(crate) struct HealthRuntimeController<C> {
    inner: Arc<Mutex<HealthRuntimeControllerState<C>>>,
}

struct HealthRuntimeControllerState<C> {
    publisher: C,
    generations: HealthGenerationAllocator,
    active: Option<StartupHealthRuntime>,
    observability: HealthRuntimeObservability,
    tls_registry: PreparedHealthTlsRegistry,
    #[cfg(test)]
    fail_next_commit: bool,
}

impl<C> Clone for HealthRuntimeController<C> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<C> HealthRuntimeController<C>
where
    C: CoreCommandClient + Clone + Send + 'static,
{
    pub(crate) fn new(publisher: C) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HealthRuntimeControllerState {
                publisher,
                generations: HealthGenerationAllocator::new(),
                active: None,
                observability: HealthRuntimeObservability::default(),
                tls_registry: PreparedHealthTlsRegistry::new(),
                #[cfg(test)]
                fail_next_commit: false,
            })),
        }
    }

    pub(crate) fn new_with_observability(
        publisher: C,
        observability: HealthRuntimeObservability,
    ) -> Self {
        let controller = Self::new(publisher);
        lock_controller(&controller.inner).observability = observability;
        controller
    }

    pub(crate) fn new_with_observability_and_tls(
        publisher: C,
        observability: HealthRuntimeObservability,
        tls_registry: PreparedHealthTlsRegistry,
    ) -> Self {
        let controller = Self::new_with_observability(publisher, observability);
        lock_controller(&controller.inner).tls_registry = tls_registry;
        controller
    }

    pub(crate) fn prepare(
        &self,
        snapshot: ConfigSnapshot,
    ) -> Result<PreparedHealthRuntime, AppError> {
        let tls_registry = lock_controller(&self.inner).tls_registry.clone();
        self.prepare_with_tls_registry(snapshot, tls_registry)
    }

    pub(crate) fn prepare_with_tls_registry(
        &self,
        snapshot: ConfigSnapshot,
        tls_registry: PreparedHealthTlsRegistry,
    ) -> Result<PreparedHealthRuntime, AppError> {
        let (publisher, generation, previous, observability, tls_registry) = {
            let mut inner = lock_controller(&self.inner);
            let publisher = inner.publisher.clone();
            let generation = inner.generations.allocate()?;
            let previous = inner
                .active
                .as_ref()
                .map(StartupHealthRuntime::reconciliation_snapshot);
            (
                publisher,
                generation,
                previous,
                inner.observability.clone(),
                tls_registry,
            )
        };
        StartupHealthRuntime::prepare_reconciled(
            snapshot,
            publisher,
            generation,
            previous.as_ref(),
            observability,
            tls_registry,
        )
    }

    pub(crate) fn commit(&self, prepared: PreparedHealthRuntime) -> Result<(), AppError> {
        let tls_registry = lock_controller(&self.inner).tls_registry.clone();
        self.commit_with_tls_registry(prepared, tls_registry)
    }

    pub(crate) fn commit_with_tls_registry(
        &self,
        prepared: PreparedHealthRuntime,
        tls_registry: PreparedHealthTlsRegistry,
    ) -> Result<(), AppError> {
        #[cfg(test)]
        {
            let mut inner = lock_controller(&self.inner);
            if inner.fail_next_commit {
                inner.fail_next_commit = false;
                return Err(AppError::new(
                    ErrorCode::RuntimeCommandRejected,
                    "injected health commit failure",
                ));
            }
        }
        let candidate = prepared.activate()?;
        let previous = {
            let mut inner = lock_controller(&self.inner);
            inner.tls_registry = tls_registry;
            inner.active.replace(candidate)
        };
        if let Some(mut previous) = previous {
            previous.shutdown();
        }
        Ok(())
    }

    pub(crate) fn shutdown(&self) {
        let active = lock_controller(&self.inner).active.take();
        if let Some(mut active) = active {
            active.shutdown();
        }
    }

    #[cfg(test)]
    pub(crate) fn active_generation(&self) -> Option<HealthGeneration> {
        lock_controller(&self.inner)
            .active
            .as_ref()
            .map(|runtime| runtime.generation)
    }

    #[cfg(test)]
    pub(crate) fn fail_next_commit(&self) {
        lock_controller(&self.inner).fail_next_commit = true;
    }
}

impl<C> HealthStatusReader for HealthRuntimeController<C>
where
    C: CoreCommandClient + Clone + Send + 'static,
{
    fn read_health_status(&self) -> Result<HealthAvailabilitySnapshot, AppError> {
        let inner = lock_controller(&self.inner);
        let active = inner.active.as_ref().ok_or_else(|| {
            AppError::new(
                ErrorCode::RuntimeHealthUnavailable,
                "health runtime is not active",
            )
        })?;
        Ok(active.availability_snapshot())
    }
}

impl<C> PassiveObservationDispatcher for HealthRuntimeController<C>
where
    C: CoreCommandClient + Clone + Send + 'static,
{
    fn submit(&mut self, observation: PassiveObservation) -> PassiveObservationSubmit {
        let dispatcher = lock_controller(&self.inner)
            .active
            .as_ref()
            .map(|runtime| runtime.passive_dispatcher.clone());
        dispatcher.map_or(PassiveObservationSubmit::Stopped, |mut dispatcher| {
            dispatcher.submit(observation)
        })
    }
}

impl PreparedHealthRuntime {
    pub(crate) fn availability(&self) -> &HealthAvailabilitySnapshot {
        &self.availability
    }

    pub(crate) fn activate(mut self) -> Result<StartupHealthRuntime, AppError> {
        let start = self.runtime.start.take().ok_or_else(|| {
            AppError::new(
                ErrorCode::InternalBug,
                "prepared health runtime has already been resolved",
            )
        })?;
        start.send(HealthStartSignal::Activate).map_err(|_| {
            AppError::new(
                ErrorCode::RuntimeCommandRejected,
                "prepared health runtime stopped before activation",
            )
        })?;
        Ok(self.runtime)
    }
}

impl StartupHealthRuntime {
    fn prepare_reconciled<C>(
        snapshot: ConfigSnapshot,
        command_client: C,
        generation: HealthGeneration,
        previous: Option<&HealthReconciliationSnapshot>,
        observability: HealthRuntimeObservability,
        tls_registry: PreparedHealthTlsRegistry,
    ) -> Result<PreparedHealthRuntime, AppError>
    where
        C: CoreCommandClient + Send + 'static,
    {
        let transports = (0..HEALTH_WORKERS)
            .map(|_| HttpHealthProbeTransport::with_tls_registry(tls_registry.clone()))
            .collect();
        Self::prepare_with_transports_and_observability(
            snapshot,
            command_client,
            generation,
            transports,
            HEALTH_OUTSTANDING_CAPACITY,
            MAX_TICK_WORK,
            previous,
            observability,
        )
    }

    #[cfg(test)]
    fn prepare_with_transports<C, T>(
        snapshot: ConfigSnapshot,
        command_client: C,
        generation: HealthGeneration,
        transports: Vec<T>,
        capacity: usize,
        max_tick_work: usize,
        previous: Option<&HealthReconciliationSnapshot>,
    ) -> Result<PreparedHealthRuntime, AppError>
    where
        C: CoreCommandClient + Send + 'static,
        T: HealthProbeTransport + Send + 'static,
    {
        Self::prepare_with_transports_and_observability(
            snapshot,
            command_client,
            generation,
            transports,
            capacity,
            max_tick_work,
            previous,
            HealthRuntimeObservability::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_with_transports_and_observability<C, T>(
        snapshot: ConfigSnapshot,
        mut command_client: C,
        generation: HealthGeneration,
        transports: Vec<T>,
        capacity: usize,
        max_tick_work: usize,
        previous: Option<&HealthReconciliationSnapshot>,
        observability: HealthRuntimeObservability,
    ) -> Result<PreparedHealthRuntime, AppError>
    where
        C: CoreCommandClient + Send + 'static,
        T: HealthProbeTransport + Send + 'static,
    {
        let field_debug_enabled = matches!(snapshot.log_mode, LogMode::FieldDebug | LogMode::Dev);
        let mut coordinator =
            HealthRuntimeCoordinator::activate_reconciled(&snapshot, generation, 0, previous)?;
        let availability = coordinator.availability_snapshot();
        let passive_config = snapshot.clone();
        let mut passive_supervisor =
            PassiveHealthSupervisor::new(snapshot.revision_id.clone(), generation);
        for service in &snapshot.services {
            for upstream in &service.upstreams {
                let (policy, enabled) = match service.policy.passive_health {
                    PassiveHealthMode::Disabled => (
                        PassiveHealthPolicy::new(3, 30_000)
                            .map_err(|error| AppError::new(error.code, error.message))?,
                        false,
                    ),
                    PassiveHealthMode::Enabled(policy) => (policy, true),
                };
                passive_supervisor.register(
                    edge_domain::UpstreamHealthKey {
                        service_id: service.id.clone(),
                        upstream_id: upstream.id.clone(),
                    },
                    policy,
                    enabled,
                );
            }
        }
        let (passive_sender, passive_receiver) = mpsc::sync_channel(PASSIVE_OBSERVATION_CAPACITY);
        let passive_dispatcher = PassiveObservationChannelDispatcher(passive_sender);
        let reconciliation = Arc::new(Mutex::new(coordinator.reconciliation_snapshot()));
        let thread_reconciliation = Arc::clone(&reconciliation);
        let (mut workers, completions) =
            HealthProbeWorkerPool::new(transports, capacity).map_err(|error| {
                AppError::new(
                    ErrorCode::InternalBug,
                    format!("invalid health worker configuration: {error:?}"),
                )
            })?;
        let stop = Arc::new(AtomicBool::new(false));
        let state = Arc::new(Mutex::new(HealthServiceState::Starting));
        let (start_sender, start_receiver) = mpsc::sync_channel(1);
        let thread_stop = Arc::clone(&stop);
        let thread_state = Arc::clone(&state);
        let handle = thread::Builder::new()
            .name("sponzey-health-runtime".to_string())
            .spawn(move || {
                let mut field_debug_sampler = FieldDebugHealthSampler::new(8_192);
                if !matches!(start_receiver.recv(), Ok(HealthStartSignal::Activate)) {
                    set_state(&thread_state, HealthServiceState::Stopping);
                    coordinator.shutdown();
                    workers.shutdown();
                    set_state(&thread_state, HealthServiceState::Stopped);
                    return;
                }
                set_state(&thread_state, HealthServiceState::Running);
                let started_at = Instant::now();

                'runtime: while !thread_stop.load(Ordering::Acquire) {
                    let now_ms = elapsed_millis(started_at);
                    let tick = coordinator.handle_tick(now_ms, max_tick_work, &workers);
                    if tick.full > 0 {
                        let metric = edge_ports::MetricEvent::counter_add(
                            edge_ports::MetricDescriptor::MetricEventsDroppedTotal,
                            u64::try_from(tick.full).unwrap_or(u64::MAX),
                            vec![("reason".into(), "queue_full".into())],
                        )
                        .expect("health dispatch metric contract");
                        observability.emit_metric(metric);
                    }
                    if tick.stopped > 0 {
                        let metric = edge_ports::MetricEvent::counter_add(
                            edge_ports::MetricDescriptor::MetricEventsDroppedTotal,
                            u64::try_from(tick.stopped).unwrap_or(u64::MAX),
                            vec![("reason".into(), "worker_stopped".into())],
                        )
                        .expect("health dispatch metric contract");
                        observability.emit_metric(metric);
                    }
                    if tick.stopped > 0
                        || coordinator.state() == HealthRuntimeCoordinatorState::Stopped
                    {
                        break;
                    }

                    let mut passive_changed = passive_supervisor.expire_cooldowns(now_ms);
                    for _ in 0..MAX_COMPLETION_DRAIN {
                        match passive_receiver.try_recv() {
                            Ok(observation) => {
                                let key = observation.key.clone();
                                let previous = passive_supervisor.state(&key);
                                let applied = passive_supervisor.handle(observation);
                                passive_changed |= matches!(
                                    applied,
                                    edge_application::HandlePassiveObservation::Applied { .. }
                                );
                                let next = passive_supervisor.state(&key);
                                let transition = match (previous, next) {
                                    (
                                        Some(edge_domain::PassiveHealthState::Observing { .. }),
                                        Some(edge_domain::PassiveHealthState::Ejected { .. }),
                                    ) => Some(FailureAwareTransition::PassiveEjected),
                                    (
                                        Some(edge_domain::PassiveHealthState::Ejected { .. }),
                                        Some(edge_domain::PassiveHealthState::Observing { .. }),
                                    ) => Some(FailureAwareTransition::PassiveRecovered),
                                    _ => None,
                                };
                                if let Some(transition) = transition {
                                    let event = FailureAwareEvent {
                                        transition,
                                        revision_id: passive_config.revision_id.clone(),
                                        generation: coordinator.availability_snapshot().generation,
                                        key: Some(key),
                                        reason: Some("transport_observation"),
                                        connection_count: None,
                                    };
                                    observability.emit_log(structured_failure_aware_log(&event));
                                    observability.emit_metric(failure_aware_metric(&event));
                                }
                            }
                            Err(mpsc::TryRecvError::Empty) => break,
                            Err(mpsc::TryRecvError::Disconnected) => break,
                        }
                    }
                    if passive_changed {
                        let effective = passive_supervisor.effective_availability(
                            &passive_config,
                            &coordinator.availability_snapshot(),
                        );
                        if !command_client
                            .send(CoreCommand::PublishUpstreamAvailability {
                                snapshot: effective,
                            })
                            .is_success()
                        {
                            break 'runtime;
                        }
                    }

                    for _ in 0..MAX_COMPLETION_DRAIN {
                        let completion = match completions.try_recv() {
                            Ok(completion) => completion,
                            Err(std::sync::mpsc::TryRecvError::Empty) => break,
                            Err(std::sync::mpsc::TryRecvError::Disconnected) => break 'runtime,
                        };
                        let request = completion.request.clone();
                        let probe_result = completion.result;
                        let completed_at_ms = elapsed_millis(started_at);
                        let result = coordinator.handle_completion(completion, completed_at_ms);
                        *lock_reconciliation(&thread_reconciliation) =
                            coordinator.reconciliation_snapshot();
                        if matches!(
                            &result,
                            HandleProbeResult::Applied {
                                change: Some(_),
                                ..
                            }
                        ) {
                            let ack =
                                command_client.send(CoreCommand::PublishUpstreamAvailability {
                                    snapshot: passive_supervisor.effective_availability(
                                        &passive_config,
                                        &coordinator.availability_snapshot(),
                                    ),
                                });
                            if !ack.is_success() {
                                break 'runtime;
                            }
                        }
                        match &result {
                            HandleProbeResult::Applied {
                                change: Some(change),
                                ..
                            } => {
                                if let Some(event) = HealthTransitionEvent::new(
                                    request.revision_id.clone(),
                                    request.generation,
                                    request.key.clone(),
                                    *change,
                                ) {
                                    observability
                                        .emit_log(structured_health_transition_log(&event));
                                    observability.emit_metric(health_transition_metric(&event));
                                    observability.emit_metric(upstream_availability_metric(
                                        &request.key,
                                        change.to,
                                    ));
                                }
                            }
                            HandleProbeResult::Ignored(reason) => {
                                observability.emit_metric(ignored_health_result_metric(
                                    &request.key,
                                    *reason,
                                ));
                            }
                            HandleProbeResult::Applied { change: None, .. } => {}
                        }
                        if field_debug_enabled {
                            let debug_event = match probe_result.outcome {
                                HealthProbeOutcome::Succeeded { status_code } => {
                                    HealthProbeDebugEvent::succeeded(
                                        request.revision_id,
                                        request.generation,
                                        request.key,
                                        status_code,
                                        probe_result.duration_ms,
                                    )
                                }
                                HealthProbeOutcome::Failed(failure) => {
                                    HealthProbeDebugEvent::failed(
                                        request.revision_id,
                                        request.generation,
                                        request.key,
                                        failure,
                                        probe_result.duration_ms,
                                    )
                                }
                            };
                            if field_debug_sampler.should_emit(&debug_event, completed_at_ms) {
                                observability
                                    .emit_log(structured_health_probe_debug_log(&debug_event));
                            }
                        }
                    }

                    thread::sleep(LOOP_PAUSE);
                }

                set_state(&thread_state, HealthServiceState::Stopping);
                coordinator.shutdown();
                workers.shutdown();
                set_state(&thread_state, HealthServiceState::Stopped);
            })
            .map_err(|error| {
                AppError::new(
                    ErrorCode::RuntimeCommandRejected,
                    format!("health runtime thread could not start: {error}"),
                )
            })?;

        Ok(PreparedHealthRuntime {
            runtime: Self {
                stop,
                state,
                thread: Some(handle),
                start: Some(start_sender),
                #[cfg(test)]
                generation,
                reconciliation,
                passive_dispatcher: passive_dispatcher.clone(),
            },
            availability,
        })
    }

    #[cfg(test)]
    pub(crate) fn state(&self) -> HealthServiceState {
        *lock_state(&self.state)
    }

    pub(crate) fn shutdown(&mut self) {
        if self.thread.is_none() {
            return;
        }
        set_state(&self.state, HealthServiceState::Stopping);
        self.stop.store(true, Ordering::Release);
        if let Some(start) = self.start.take() {
            let _ = start.send(HealthStartSignal::Cancel);
        }
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
        set_state(&self.state, HealthServiceState::Stopped);
    }

    fn reconciliation_snapshot(&self) -> HealthReconciliationSnapshot {
        lock_reconciliation(&self.reconciliation).clone()
    }

    fn availability_snapshot(&self) -> HealthAvailabilitySnapshot {
        lock_reconciliation(&self.reconciliation).availability_snapshot()
    }
}

impl Drop for StartupHealthRuntime {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn elapsed_millis(started_at: Instant) -> u64 {
    u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn set_state(state: &Mutex<HealthServiceState>, next: HealthServiceState) {
    *lock_state(state) = next;
}

fn lock_state(state: &Mutex<HealthServiceState>) -> std::sync::MutexGuard<'_, HealthServiceState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn lock_controller<C>(
    state: &Mutex<HealthRuntimeControllerState<C>>,
) -> std::sync::MutexGuard<'_, HealthRuntimeControllerState<C>> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn lock_reconciliation(
    state: &Mutex<HealthReconciliationSnapshot>,
) -> std::sync::MutexGuard<'_, HealthReconciliationSnapshot> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_domain::{
        AdminConfig, CommandAck, ConfigRevisionId, HealthCheckPolicy, HttpHealthCheckPolicy,
        LoadBalancingPolicy, LogMode, RuntimeOptions, Service, ServiceId, ServicePolicy, Upstream,
        UpstreamAvailability, UpstreamId,
    };
    use edge_ports::{
        HealthProbeFailure, HealthProbeResult, PassiveFailureReason, PassiveObservation,
        PassiveObservationDispatcher, PassiveObservationOutcome, PassiveObservationSubmit,
        ScriptedHealthProbeTransport,
    };

    #[derive(Clone)]
    struct RecordingCommandClient {
        commands: Arc<Mutex<Vec<CoreCommand>>>,
        ack: CommandAck,
    }

    impl CoreCommandClient for RecordingCommandClient {
        fn send(&mut self, command: CoreCommand) -> CommandAck {
            lock_commands(&self.commands).push(command);
            self.ack.clone()
        }
    }

    #[test]
    fn prepared_runtime_does_not_probe_or_publish_until_activated() {
        let commands = Arc::new(Mutex::new(Vec::new()));
        let client = RecordingCommandClient {
            commands: Arc::clone(&commands),
            ack: CommandAck::accepted(),
        };
        let transport =
            ScriptedHealthProbeTransport::new(vec![HealthProbeResult::succeeded(200, 1)]);
        let prepared = StartupHealthRuntime::prepare_with_transports(
            snapshot(),
            client,
            HealthGeneration(9),
            vec![transport],
            1,
            1,
            None,
        )
        .unwrap();

        thread::sleep(Duration::from_millis(50));
        assert!(lock_commands(&commands).is_empty());
        assert_eq!(prepared.runtime.state(), HealthServiceState::Starting);

        let mut runtime = prepared.activate().unwrap();
        wait_until(Duration::from_secs(1), || {
            !lock_commands(&commands).is_empty()
        });
        runtime.shutdown();
    }

    #[test]
    fn controller_health_status_reader_requires_active_runtime_and_returns_current_snapshot() {
        let client = RecordingCommandClient {
            commands: Arc::new(Mutex::new(Vec::new())),
            ack: CommandAck::accepted(),
        };
        let controller = HealthRuntimeController::new(client);

        let inactive = edge_ports::HealthStatusReader::read_health_status(&controller).unwrap_err();
        assert_eq!(inactive.code, ErrorCode::RuntimeHealthUnavailable);

        let prepared = controller.prepare(snapshot()).unwrap();
        controller.commit(prepared).unwrap();
        let active = edge_ports::HealthStatusReader::read_health_status(&controller).unwrap();
        assert_eq!(active.revision_id.as_str(), "rev-health-runtime");
        assert_eq!(active.generation, HealthGeneration(1));
        assert_eq!(active.entries.len(), 1);

        controller.shutdown();
        let stopped = edge_ports::HealthStatusReader::read_health_status(&controller).unwrap_err();
        assert_eq!(stopped.code, ErrorCode::RuntimeHealthUnavailable);
    }

    #[test]
    fn controller_composes_current_passive_failure_into_effective_unhealthy_publish() {
        let commands = Arc::new(Mutex::new(Vec::new()));
        let client = RecordingCommandClient {
            commands: Arc::clone(&commands),
            ack: CommandAck::accepted(),
        };
        let mut config = snapshot();
        config.services[0].policy.health_check = HealthCheckPolicy::Disabled;
        config.services[0].policy.passive_health = edge_domain::PassiveHealthMode::Enabled(
            edge_domain::PassiveHealthPolicy::new(1, 1_000).unwrap(),
        );
        let revision_id = config.revision_id.clone();
        let key = edge_domain::UpstreamHealthKey {
            service_id: config.services[0].id.clone(),
            upstream_id: config.services[0].upstreams[0].id.clone(),
        };
        let controller = HealthRuntimeController::new(client);
        let prepared = controller.prepare(config).unwrap();
        controller.commit(prepared).unwrap();
        let mut dispatcher = controller.clone();

        assert_eq!(
            dispatcher.submit(PassiveObservation {
                revision_id,
                generation: HealthGeneration(1),
                key: key.clone(),
                outcome: PassiveObservationOutcome::Failed(PassiveFailureReason::Connect),
                observed_at_ms: 0,
            }),
            PassiveObservationSubmit::Accepted
        );
        wait_until(Duration::from_secs(1), || {
            !lock_commands(&commands).is_empty()
        });
        let published = lock_commands(&commands).last().cloned().unwrap();
        let CoreCommand::PublishUpstreamAvailability { snapshot } = published else {
            panic!("passive transition must publish effective availability");
        };
        assert_eq!(
            snapshot.entries.get(&key),
            Some(&UpstreamAvailability::Unhealthy)
        );
        controller.shutdown();
    }

    #[test]
    fn startup_runtime_publishes_health_transition_and_stops_cleanly() {
        let commands = Arc::new(Mutex::new(Vec::new()));
        let client = RecordingCommandClient {
            commands: Arc::clone(&commands),
            ack: CommandAck::accepted(),
        };
        let transport =
            ScriptedHealthProbeTransport::new(vec![HealthProbeResult::succeeded(204, 1)]);
        let mut runtime = StartupHealthRuntime::prepare_with_transports(
            snapshot(),
            client,
            HealthGeneration(1),
            vec![transport],
            1,
            1,
            None,
        )
        .unwrap()
        .activate()
        .unwrap();

        wait_until(Duration::from_secs(1), || {
            !lock_commands(&commands).is_empty()
        });
        let published = lock_commands(&commands).first().cloned().unwrap();
        let CoreCommand::PublishUpstreamAvailability { snapshot } = published else {
            panic!("health runtime must publish an availability snapshot");
        };
        assert_eq!(snapshot.generation, HealthGeneration(1));
        assert_eq!(
            snapshot.entries.values().copied().collect::<Vec<_>>(),
            vec![UpstreamAvailability::Healthy]
        );

        runtime.shutdown();
        assert_eq!(runtime.state(), HealthServiceState::Stopped);
    }

    #[test]
    fn phase009_runtime_health_uses_prepared_private_root_and_publishes_healthy() {
        use edge_adapters::{
            load_rustls_server_config, RustlsClientTlsSessionFactory,
            RustlsTrustBundleMaterialValidator,
        };
        use edge_ports::{StoredCertificate, TrustBundleMaterialValidator};
        use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root = CertifiedIssuer::self_signed(root_params, KeyPair::generate().unwrap()).unwrap();
        let server_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["backend.private.test".to_string()])
            .unwrap()
            .signed_by(&server_key, &root)
            .unwrap();
        let stored = StoredCertificate {
            certificate_ref: edge_domain::CertificateRef::new("health-backend"),
            domains: vec!["backend.private.test".to_string()],
            not_after_epoch_seconds: 4_000_000_000,
            source: "test".to_string(),
            certificate_pem: format!("{}{}", leaf.pem(), root.pem()),
            private_key_pem: server_key.serialize_pem(),
        };
        let server_config = load_rustls_server_config(&stored).unwrap().server_config;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let backend = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let connection = rustls::ServerConnection::new(server_config).unwrap();
            let mut stream = rustls::StreamOwned::new(connection, stream);
            let mut request = Vec::new();
            let mut buffer = [0_u8; 512];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).unwrap();
                request.extend_from_slice(&buffer[..read]);
            }
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            request
        });
        let trust_ref = edge_domain::TrustBundleRef::parse("private-root").unwrap();
        let trust = RustlsTrustBundleMaterialValidator
            .validate_trust_bundle(&trust_ref, root.pem().as_bytes(), 1)
            .unwrap();
        let mut tls_registry = PreparedHealthTlsRegistry::new();
        let key = edge_domain::UpstreamHealthKey {
            service_id: ServiceId::new("app"),
            upstream_id: UpstreamId::new("app-a"),
        };
        tls_registry
            .insert(
                key.clone(),
                RustlsClientTlsSessionFactory::from_trust_bundle(&trust).unwrap(),
            )
            .unwrap();
        let mut config = snapshot();
        config.schema_version = 2;
        config.services[0].policy.health_check = HealthCheckPolicy::Http(
            HttpHealthCheckPolicy::new("/health", 10_000, 5_000, 1, 1, 200, 399).unwrap(),
        );
        config.services[0].upstreams[0].url = format!("https://{address}");
        config.services[0].upstreams[0].tls = edge_domain::UpstreamTlsPolicy::ServerAuthenticated {
            server_name: edge_domain::TlsServerName::parse("backend.private.test").unwrap(),
            http_host: edge_domain::UpstreamHttpHost::parse("health.private.test").unwrap(),
            trust_bundle_ref: trust_ref,
        };
        let commands = Arc::new(Mutex::new(Vec::new()));
        let client = RecordingCommandClient {
            commands: Arc::clone(&commands),
            ack: CommandAck::accepted(),
        };
        let controller = HealthRuntimeController::new_with_observability_and_tls(
            client,
            HealthRuntimeObservability::default(),
            tls_registry,
        );

        let prepared = controller.prepare(config).unwrap();
        controller.commit(prepared).unwrap();
        wait_until(Duration::from_secs(10), || {
            lock_commands(&commands).iter().any(|command| {
                matches!(command, CoreCommand::PublishUpstreamAvailability { snapshot }
                    if snapshot.entries.get(&key) == Some(&UpstreamAvailability::Healthy))
            })
        });
        controller.shutdown();

        let request = String::from_utf8(backend.join().unwrap()).unwrap();
        assert!(request.contains("\r\nHost: health.private.test\r\n"));
    }

    #[test]
    fn health_runtime_emits_transition_observability_without_sensitive_fields() {
        let commands = Arc::new(Mutex::new(Vec::new()));
        let client = RecordingCommandClient {
            commands: Arc::clone(&commands),
            ack: CommandAck::accepted(),
        };
        let (log_tx, log_rx) = mpsc::sync_channel(4);
        let (metric_tx, metric_rx) = mpsc::sync_channel(4);
        let dropped = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let observability = HealthRuntimeObservability::new(
            log_tx,
            Arc::new(MetricChannelPublisher::new(metric_tx)),
            Arc::clone(&dropped),
        );
        let transport =
            ScriptedHealthProbeTransport::new(vec![HealthProbeResult::succeeded(204, 1)]);
        let mut runtime = StartupHealthRuntime::prepare_with_transports_and_observability(
            snapshot(),
            client,
            HealthGeneration(41),
            vec![transport],
            1,
            1,
            None,
            observability,
        )
        .unwrap()
        .activate()
        .unwrap();

        wait_until(Duration::from_secs(1), || {
            !lock_commands(&commands).is_empty()
        });
        let log = log_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("health transition product log");
        let metric = metric_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("health transition metric");
        runtime.shutdown();

        assert_eq!(log.event, "upstream_health_changed");
        assert!(log
            .fields
            .contains(&("generation".to_string(), "41".to_string())));
        assert!(!format!("{log:?}").contains("127.0.0.1"));
        assert_eq!(
            metric.descriptor,
            edge_ports::MetricDescriptor::UpstreamHealthTransitionsTotal
        );
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        assert!(log_rx.try_recv().is_err());
    }

    #[test]
    fn field_debug_health_runtime_emits_sampled_probe_detail() {
        let commands = Arc::new(Mutex::new(Vec::new()));
        let client = RecordingCommandClient {
            commands: Arc::clone(&commands),
            ack: CommandAck::accepted(),
        };
        let (log_tx, log_rx) = mpsc::sync_channel(4);
        let (metric_tx, _metric_rx) = mpsc::sync_channel(4);
        let observability = HealthRuntimeObservability::new(
            log_tx,
            Arc::new(MetricChannelPublisher::new(metric_tx)),
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        );
        let transport =
            ScriptedHealthProbeTransport::new(vec![HealthProbeResult::succeeded(204, 7)]);
        let mut config = snapshot();
        config.log_mode = LogMode::FieldDebug;
        let mut runtime = StartupHealthRuntime::prepare_with_transports_and_observability(
            config,
            client,
            HealthGeneration(43),
            vec![transport],
            1,
            1,
            None,
            observability,
        )
        .unwrap()
        .activate()
        .unwrap();

        wait_until(Duration::from_secs(1), || {
            !lock_commands(&commands).is_empty()
        });
        thread::sleep(Duration::from_millis(20));
        let logs = log_rx.try_iter().collect::<Vec<_>>();
        runtime.shutdown();

        assert!(logs
            .iter()
            .any(|event| event.event == "upstream_health_changed"));
        assert!(logs.iter().any(|event| {
            event.event == "upstream_health_probe_debug"
                && event
                    .fields
                    .contains(&("status_code".to_string(), "204".to_string()))
        }));
    }

    #[test]
    fn saturated_health_observability_queues_do_not_stop_state_progression() {
        let commands = Arc::new(Mutex::new(Vec::new()));
        let client = RecordingCommandClient {
            commands: Arc::clone(&commands),
            ack: CommandAck::accepted(),
        };
        let (log_tx, _log_rx) = mpsc::sync_channel(0);
        let (metric_tx, _metric_rx) = mpsc::sync_channel(0);
        let dropped = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let observability = HealthRuntimeObservability::new(
            log_tx,
            Arc::new(MetricChannelPublisher::new(metric_tx)),
            Arc::clone(&dropped),
        );
        let transport = ScriptedHealthProbeTransport::new(vec![HealthProbeResult::failed(
            HealthProbeFailure::ReadTimeout,
            1,
        )]);
        let mut runtime = StartupHealthRuntime::prepare_with_transports_and_observability(
            snapshot(),
            client,
            HealthGeneration(42),
            vec![transport],
            1,
            1,
            None,
            observability,
        )
        .unwrap()
        .activate()
        .unwrap();

        wait_until(Duration::from_secs(1), || {
            !lock_commands(&commands).is_empty() && dropped.load(Ordering::Relaxed) >= 2
        });
        assert_eq!(runtime.state(), HealthServiceState::Running);
        assert!(dropped.load(Ordering::Relaxed) >= 2);
        runtime.shutdown();
    }

    #[test]
    fn rejected_publish_is_a_terminal_runtime_event() {
        let commands = Arc::new(Mutex::new(Vec::new()));
        let client = RecordingCommandClient {
            commands: Arc::clone(&commands),
            ack: CommandAck::rejected(AppError::new(
                ErrorCode::RuntimeCommandRejected,
                "test rejection",
            )),
        };
        let transport = ScriptedHealthProbeTransport::new(vec![HealthProbeResult::failed(
            HealthProbeFailure::ReadTimeout,
            100,
        )]);
        let mut runtime = StartupHealthRuntime::prepare_with_transports(
            snapshot(),
            client,
            HealthGeneration(2),
            vec![transport],
            1,
            1,
            None,
        )
        .unwrap()
        .activate()
        .unwrap();

        wait_until(Duration::from_secs(1), || {
            runtime.state() == HealthServiceState::Stopped
        });
        let published = lock_commands(&commands).first().cloned().unwrap();
        let CoreCommand::PublishUpstreamAvailability { snapshot } = published else {
            panic!("failed probe must publish an availability snapshot");
        };
        assert_eq!(
            snapshot.entries.values().copied().collect::<Vec<_>>(),
            vec![UpstreamAvailability::Unhealthy]
        );
        runtime.shutdown();
    }

    #[test]
    fn controller_reconciles_latest_worker_state_into_next_candidate() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });
        let commands = Arc::new(Mutex::new(Vec::new()));
        let client = RecordingCommandClient {
            commands: Arc::clone(&commands),
            ack: CommandAck::accepted(),
        };
        let controller = HealthRuntimeController::new(client);
        let mut config = snapshot();
        config.services[0].upstreams[0].url = format!("http://{address}");
        let initial = controller.prepare(config.clone()).unwrap();
        controller.commit(initial).unwrap();

        wait_until(Duration::from_secs(2), || {
            !lock_commands(&commands).is_empty()
        });
        server.join().unwrap();
        let candidate = controller.prepare(config).unwrap();

        assert_eq!(candidate.availability().generation, HealthGeneration(2));
        assert_eq!(
            candidate
                .availability()
                .entries
                .values()
                .copied()
                .collect::<Vec<_>>(),
            vec![UpstreamAvailability::Unhealthy]
        );
        drop(candidate);
        controller.shutdown();
    }

    fn snapshot() -> ConfigSnapshot {
        ConfigSnapshot {
            schema_version: 1,
            revision_id: ConfigRevisionId::new("rev-health-runtime"),
            admin: AdminConfig {
                bind: "127.0.0.1:9443".to_string(),
                auth_required: true,
            },
            listeners: vec![],
            routes: vec![],
            services: vec![Service {
                id: ServiceId::new("app"),
                upstreams: vec![Upstream {
                    id: UpstreamId::new("app-a"),
                    url: "http://127.0.0.1:3001".to_string(),
                    administrative_state: edge_domain::UpstreamAdministrativeState::Active,
                    tls: edge_domain::UpstreamTlsPolicy::Disabled,
                }],
                policy: ServicePolicy {
                    load_balancing: LoadBalancingPolicy::RoundRobin,
                    health_check: HealthCheckPolicy::Http(
                        HttpHealthCheckPolicy::new("/health", 1_000, 100, 1, 1, 200, 399).unwrap(),
                    ),
                    ..ServicePolicy::default()
                },
            }],
            certificate_resolvers: vec![],
            log_mode: LogMode::Product,
            runtime: RuntimeOptions {
                max_connections: 100,
                max_inflight_payload_bytes: 128 * 1024 * 1024,
                max_request_header_bytes: 16 * 1024,
                max_request_body_bytes: 1024 * 1024,
                upstream_read_timeout_ms: edge_domain::DEFAULT_UPSTREAM_READ_TIMEOUT_MS,
                metrics: edge_domain::MetricsConfig::default(),
            },
        }
    }

    fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + timeout;
        while !condition() {
            assert!(Instant::now() < deadline, "condition timed out");
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn lock_commands(
        commands: &Mutex<Vec<CoreCommand>>,
    ) -> std::sync::MutexGuard<'_, Vec<CoreCommand>> {
        commands
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
