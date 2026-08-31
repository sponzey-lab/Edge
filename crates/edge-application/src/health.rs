use std::collections::BTreeMap;

use edge_domain::{
    transition_upstream_health, AppError, ConfigRevisionId, ConfigSnapshot, ErrorCode,
    HealthCheckPolicy, HealthObservation, HealthStateChange, HttpHealthCheckPolicy,
    UpstreamAvailability, UpstreamEndpoint, UpstreamHealthState, UpstreamTlsPolicy,
};
use edge_ports::HealthAvailabilitySnapshot;
pub use edge_ports::{HealthGeneration, HealthProbeId, HealthProbeRequest, UpstreamHealthKey};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthGenerationAllocator {
    next: Option<u64>,
}

impl Default for HealthGenerationAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthGenerationAllocator {
    pub fn new() -> Self {
        Self { next: Some(1) }
    }

    pub fn allocate(&mut self) -> Result<HealthGeneration, AppError> {
        let value = self.next.ok_or_else(|| {
            AppError::new(
                ErrorCode::InternalBug,
                "health generation space is exhausted",
            )
        })?;
        self.next = value.checked_add(1);
        Ok(HealthGeneration(value))
    }

    #[cfg(test)]
    fn from_next_for_test(next: u64) -> Self {
        Self { next: Some(next) }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthSupervisorState {
    Running,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeScheduleState {
    Disabled,
    Scheduled { next_due_ms: u64 },
    InFlight { probe_id: HealthProbeId },
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResultIgnored {
    StaleGeneration,
    UnknownUpstream,
    NotInFlight,
    RequestMismatch,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandleProbeResult {
    Applied {
        availability: UpstreamAvailability,
        change: Option<HealthStateChange>,
    },
    Ignored(ProbeResultIgnored),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandleProbeDispatchRejection {
    Rescheduled { next_due_ms: u64 },
    Ignored(ProbeResultIgnored),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthDispatchDropReason {
    QueueFull,
    WorkerStopped,
}

#[derive(Debug, Clone)]
struct HealthEntry {
    endpoint: UpstreamEndpoint,
    tls: UpstreamTlsPolicy,
    policy: Option<HttpHealthCheckPolicy>,
    health: UpstreamHealthState,
    schedule: ProbeScheduleState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthReconciliationSnapshot {
    revision_id: ConfigRevisionId,
    generation: HealthGeneration,
    entries: BTreeMap<UpstreamHealthKey, HealthReconciliationEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HealthReconciliationEntry {
    endpoint: UpstreamEndpoint,
    tls: UpstreamTlsPolicy,
    policy: Option<HttpHealthCheckPolicy>,
    health: UpstreamHealthState,
}

impl HealthReconciliationSnapshot {
    pub fn availability_snapshot(&self) -> HealthAvailabilitySnapshot {
        HealthAvailabilitySnapshot {
            revision_id: self.revision_id.clone(),
            generation: self.generation,
            entries: self
                .entries
                .iter()
                .map(|(key, entry)| (key.clone(), entry.health.availability()))
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HealthSupervisor {
    revision_id: ConfigRevisionId,
    generation: HealthGeneration,
    state: HealthSupervisorState,
    entries: BTreeMap<UpstreamHealthKey, HealthEntry>,
    next_probe_id: u64,
}

impl HealthSupervisor {
    pub(crate) fn activate_reconciled(
        snapshot: &ConfigSnapshot,
        generation: HealthGeneration,
        now_ms: u64,
        previous: Option<&HealthReconciliationSnapshot>,
    ) -> Result<Self, AppError> {
        let mut supervisor = Self::activate(snapshot, generation, now_ms)?;
        if let Some(previous) = previous {
            for (key, entry) in &mut supervisor.entries {
                let Some(prior) = previous.entries.get(key) else {
                    continue;
                };
                if entry.endpoint == prior.endpoint
                    && entry.tls == prior.tls
                    && entry.policy == prior.policy
                {
                    entry.health = prior.health.clone();
                }
            }
        }
        Ok(supervisor)
    }

    pub(crate) fn availability_snapshot(&self) -> HealthAvailabilitySnapshot {
        HealthAvailabilitySnapshot {
            revision_id: self.revision_id.clone(),
            generation: self.generation,
            entries: self
                .entries
                .iter()
                .map(|(key, entry)| (key.clone(), entry.health.availability()))
                .collect(),
        }
    }

    pub(crate) fn reconciliation_snapshot(&self) -> HealthReconciliationSnapshot {
        HealthReconciliationSnapshot {
            revision_id: self.revision_id.clone(),
            generation: self.generation,
            entries: self
                .entries
                .iter()
                .map(|(key, entry)| {
                    (
                        key.clone(),
                        HealthReconciliationEntry {
                            endpoint: entry.endpoint.clone(),
                            tls: entry.tls.clone(),
                            policy: entry.policy.clone(),
                            health: entry.health.clone(),
                        },
                    )
                })
                .collect(),
        }
    }

    pub fn activate(
        snapshot: &ConfigSnapshot,
        generation: HealthGeneration,
        now_ms: u64,
    ) -> Result<Self, AppError> {
        let mut entries = BTreeMap::new();
        for service in &snapshot.services {
            for upstream in &service.upstreams {
                let key = UpstreamHealthKey {
                    service_id: service.id.clone(),
                    upstream_id: upstream.id.clone(),
                };
                let (policy, health, schedule) = match &service.policy.health_check {
                    HealthCheckPolicy::Disabled => (
                        None,
                        UpstreamHealthState::Disabled,
                        ProbeScheduleState::Disabled,
                    ),
                    HealthCheckPolicy::Http(policy) => (
                        Some(policy.clone()),
                        UpstreamHealthState::for_policy(&service.policy.health_check),
                        ProbeScheduleState::Scheduled {
                            next_due_ms: now_ms,
                        },
                    ),
                };
                let endpoint = UpstreamEndpoint::parse(&upstream.url)
                    .map_err(|error| AppError::new(error.code, error.message))?;
                if !matches!(
                    (endpoint.scheme(), &upstream.tls),
                    (
                        edge_domain::UpstreamScheme::Http,
                        UpstreamTlsPolicy::Disabled
                    ) | (
                        edge_domain::UpstreamScheme::Https,
                        UpstreamTlsPolicy::ServerAuthenticated { .. }
                    )
                ) {
                    return Err(AppError::new(
                        ErrorCode::UpstreamTlsProfileInvalid,
                        "upstream TLS profile is invalid",
                    ));
                }
                entries.insert(
                    key,
                    HealthEntry {
                        endpoint,
                        tls: upstream.tls.clone(),
                        policy,
                        health,
                        schedule,
                    },
                );
            }
        }

        Ok(Self {
            revision_id: snapshot.revision_id.clone(),
            generation,
            state: HealthSupervisorState::Running,
            entries,
            next_probe_id: 0,
        })
    }

    pub fn state(&self) -> HealthSupervisorState {
        self.state
    }

    pub fn availability(&self, key: &UpstreamHealthKey) -> Option<UpstreamAvailability> {
        self.entries
            .get(key)
            .map(|entry| entry.health.availability())
    }

    pub fn handle_tick(&mut self, now_ms: u64, max_work: usize) -> Vec<HealthProbeRequest> {
        if self.state == HealthSupervisorState::Stopped || max_work == 0 {
            return Vec::new();
        }

        let mut work = Vec::new();
        for (key, entry) in &mut self.entries {
            if work.len() >= max_work {
                break;
            }
            let ProbeScheduleState::Scheduled { next_due_ms } = entry.schedule else {
                continue;
            };
            if next_due_ms > now_ms {
                continue;
            }
            let Some(policy) = entry.policy.as_ref() else {
                continue;
            };
            let probe_id = HealthProbeId(self.next_probe_id);
            self.next_probe_id = self.next_probe_id.wrapping_add(1);
            entry.schedule = ProbeScheduleState::InFlight { probe_id };
            work.push(HealthProbeRequest {
                probe_id,
                revision_id: self.revision_id.clone(),
                generation: self.generation,
                key: key.clone(),
                endpoint: entry.endpoint.clone(),
                tls: entry.tls.clone(),
                path: policy.path.clone(),
                timeout_ms: policy.timeout_ms,
                status_min: policy.status_min,
                status_max: policy.status_max,
            });
        }
        work
    }

    pub fn handle_probe_result(
        &mut self,
        request: &HealthProbeRequest,
        observation: HealthObservation,
        completed_at_ms: u64,
    ) -> HandleProbeResult {
        if let Err(reason) = self.validate_probe_request(request) {
            return HandleProbeResult::Ignored(reason);
        }
        let Some(entry) = self.entries.get_mut(&request.key) else {
            return HandleProbeResult::Ignored(ProbeResultIgnored::UnknownUpstream);
        };
        let Some(policy) = entry.policy.as_ref() else {
            return HandleProbeResult::Ignored(ProbeResultIgnored::NotInFlight);
        };
        let transition = transition_upstream_health(entry.health.clone(), observation, policy);
        entry.health = transition.state;
        entry.schedule = ProbeScheduleState::Scheduled {
            next_due_ms: next_probe_due_ms(
                &request.key,
                request.generation,
                policy.interval_ms,
                completed_at_ms,
            ),
        };

        HandleProbeResult::Applied {
            availability: entry.health.availability(),
            change: transition.change,
        }
    }

    pub fn handle_probe_dispatch_rejected(
        &mut self,
        request: &HealthProbeRequest,
        rejected_at_ms: u64,
    ) -> HandleProbeDispatchRejection {
        if let Err(reason) = self.validate_probe_request(request) {
            return HandleProbeDispatchRejection::Ignored(reason);
        }
        let Some(entry) = self.entries.get_mut(&request.key) else {
            return HandleProbeDispatchRejection::Ignored(ProbeResultIgnored::UnknownUpstream);
        };
        let Some(policy) = entry.policy.as_ref() else {
            return HandleProbeDispatchRejection::Ignored(ProbeResultIgnored::NotInFlight);
        };
        let next_due_ms = next_probe_due_ms(
            &request.key,
            request.generation,
            policy.interval_ms,
            rejected_at_ms,
        );
        entry.schedule = ProbeScheduleState::Scheduled { next_due_ms };
        HandleProbeDispatchRejection::Rescheduled { next_due_ms }
    }

    fn validate_probe_request(
        &self,
        request: &HealthProbeRequest,
    ) -> Result<(), ProbeResultIgnored> {
        if self.state == HealthSupervisorState::Stopped {
            return Err(ProbeResultIgnored::Stopped);
        }
        if request.generation != self.generation || request.revision_id != self.revision_id {
            return Err(ProbeResultIgnored::StaleGeneration);
        }
        let Some(entry) = self.entries.get(&request.key) else {
            return Err(ProbeResultIgnored::UnknownUpstream);
        };
        match entry.schedule {
            ProbeScheduleState::InFlight { probe_id } if probe_id == request.probe_id => Ok(()),
            ProbeScheduleState::InFlight { .. } => Err(ProbeResultIgnored::RequestMismatch),
            _ => Err(ProbeResultIgnored::NotInFlight),
        }
    }

    pub fn shutdown(&mut self) {
        self.state = HealthSupervisorState::Stopped;
        for entry in self.entries.values_mut() {
            entry.schedule = ProbeScheduleState::Stopped;
        }
    }
}

fn next_probe_due_ms(
    key: &UpstreamHealthKey,
    generation: HealthGeneration,
    interval_ms: u64,
    event_at_ms: u64,
) -> u64 {
    event_at_ms
        .saturating_add(interval_ms)
        .saturating_add(health_jitter_ms(key, generation, interval_ms))
}

fn health_jitter_ms(
    key: &UpstreamHealthKey,
    generation: HealthGeneration,
    interval_ms: u64,
) -> u64 {
    let maximum = interval_ms / 10;
    if maximum == 0 {
        return 0;
    }
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in key
        .service_id
        .as_str()
        .bytes()
        .chain([0xff])
        .chain(key.upstream_id.as_str().bytes())
        .chain(generation.0.to_le_bytes())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash % maximum.saturating_add(1)
}

#[cfg(test)]
mod tests {
    use crate::health_probe_observability::{
        structured_health_probe_debug_log, FieldDebugHealthSampler, HealthProbeDebugEvent,
    };
    use crate::health_runtime_metrics::{
        health_dispatch_drop_metric, health_key_labels, ignored_health_result_metric,
        no_eligible_upstream_metric, upstream_availability_metric, upstream_selection_metric,
    };
    use crate::health_transition_observability::{
        availability_name, health_transition_metric, record_health_transition_log,
        record_health_transition_metric, structured_health_transition_log, HealthTransitionEvent,
    };
    use crate::{HealthRuntimeCoordinator, HealthRuntimeCoordinatorState, HealthTickSummary};
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use edge_domain::{
        AdminConfig, ConfigRevisionId, ConfigSnapshot, HealthCheckPolicy, HealthObservation,
        HttpHealthCheckPolicy, LogMode, RuntimeOptions, Service, ServiceId, ServicePolicy,
        Upstream, UpstreamAvailability, UpstreamId,
    };
    use edge_ports::{
        HealthProbeCompletion, HealthProbeDispatcher, HealthProbeFailure, HealthProbeResult,
        HealthProbeSubmit, MetricDescriptor,
    };

    use super::*;

    fn snapshot() -> ConfigSnapshot {
        ConfigSnapshot {
            schema_version: 1,
            revision_id: ConfigRevisionId::new("rev-health"),
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
                    load_balancing: edge_domain::LoadBalancingPolicy::RoundRobin,
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

    #[test]
    fn tick_emits_one_in_flight_probe_and_completion_schedules_next_interval() {
        let mut supervisor =
            HealthSupervisor::activate(&snapshot(), HealthGeneration(7), 100).unwrap();

        assert!(supervisor.handle_tick(99, 8).is_empty());
        let work = supervisor.handle_tick(100, 8);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].generation, HealthGeneration(7));
        assert_eq!(work[0].revision_id.as_str(), "rev-health");
        assert_eq!(work[0].key.service_id.as_str(), "app");
        assert_eq!(work[0].key.upstream_id.as_str(), "app-a");
        assert_eq!(work[0].path, "/health");
        assert_eq!(work[0].timeout_ms, 100);
        assert!(supervisor.handle_tick(100, 8).is_empty());

        let completion =
            supervisor.handle_probe_result(&work[0], HealthObservation::Succeeded, 150);
        assert_eq!(
            completion,
            HandleProbeResult::Applied {
                availability: UpstreamAvailability::Healthy,
                change: Some(edge_domain::HealthStateChange {
                    from: UpstreamAvailability::Unknown,
                    to: UpstreamAvailability::Healthy,
                }),
            }
        );
        let next_due = 150_u64
            .saturating_add(1_000)
            .saturating_add(health_jitter_ms(&work[0].key, HealthGeneration(7), 1_000));
        assert!(supervisor
            .handle_tick(next_due.saturating_sub(1), 8)
            .is_empty());
        assert_eq!(supervisor.handle_tick(next_due, 8).len(), 1);
    }

    #[test]
    fn phase009_https_health_request_preserves_endpoint_and_strict_tls_policy() {
        let mut input = snapshot();
        input.schema_version = 2;
        input.services[0].upstreams[0].url = "https://127.0.0.1:3443/base".to_string();
        input.services[0].upstreams[0].tls = edge_domain::UpstreamTlsPolicy::ServerAuthenticated {
            server_name: edge_domain::TlsServerName::parse("backend.private.test").unwrap(),
            http_host: edge_domain::UpstreamHttpHost::parse("health.private.test").unwrap(),
            trust_bundle_ref: edge_domain::TrustBundleRef::parse("private-root").unwrap(),
        };

        let mut supervisor = HealthSupervisor::activate(&input, HealthGeneration(40), 0).unwrap();
        let request = supervisor.handle_tick(0, 1).remove(0);

        assert_eq!(
            request.endpoint.scheme(),
            edge_domain::UpstreamScheme::Https
        );
        assert!(matches!(
            request.tls,
            edge_domain::UpstreamTlsPolicy::ServerAuthenticated {
                ref server_name,
                ref http_host,
                ref trust_bundle_ref,
            } if server_name.as_str() == "backend.private.test"
                && http_host.as_str() == "health.private.test"
                && trust_bundle_ref.as_str() == "private-root"
        ));
    }

    #[test]
    fn rejected_dispatch_reschedules_without_changing_health() {
        let mut supervisor =
            HealthSupervisor::activate(&snapshot(), HealthGeneration(8), 0).unwrap();
        let request = supervisor.handle_tick(0, 1).remove(0);

        let result = supervisor.handle_probe_dispatch_rejected(&request, 10);

        let HandleProbeDispatchRejection::Rescheduled { next_due_ms } = result else {
            panic!("valid dispatch rejection must reschedule");
        };
        assert!((1_010..=1_110).contains(&next_due_ms));
        assert_eq!(
            supervisor.availability(&request.key),
            Some(UpstreamAvailability::Unknown)
        );
        assert!(supervisor
            .handle_tick(next_due_ms.saturating_sub(1), 1)
            .is_empty());
        assert_eq!(supervisor.handle_tick(next_due_ms, 1).len(), 1);
    }

    #[test]
    fn rejected_dispatch_ignores_stale_mismatched_and_stopped_requests() {
        let mut supervisor =
            HealthSupervisor::activate(&snapshot(), HealthGeneration(9), 0).unwrap();
        let request = supervisor.handle_tick(0, 1).remove(0);
        let mut stale = request.clone();
        stale.generation = HealthGeneration(8);
        assert_eq!(
            supervisor.handle_probe_dispatch_rejected(&stale, 10),
            HandleProbeDispatchRejection::Ignored(ProbeResultIgnored::StaleGeneration)
        );
        let mut mismatch = request.clone();
        mismatch.probe_id = HealthProbeId(request.probe_id.0.wrapping_add(1));
        assert_eq!(
            supervisor.handle_probe_dispatch_rejected(&mismatch, 10),
            HandleProbeDispatchRejection::Ignored(ProbeResultIgnored::RequestMismatch)
        );

        supervisor.shutdown();
        assert_eq!(
            supervisor.handle_probe_dispatch_rejected(&request, 10),
            HandleProbeDispatchRejection::Ignored(ProbeResultIgnored::Stopped)
        );
    }

    #[test]
    fn health_jitter_is_stable_bounded_and_due_time_saturates() {
        let key = UpstreamHealthKey {
            service_id: ServiceId::new("app"),
            upstream_id: UpstreamId::new("app-a"),
        };
        let jitter = health_jitter_ms(&key, HealthGeneration(10), 1_000);
        assert_eq!(jitter, health_jitter_ms(&key, HealthGeneration(10), 1_000));
        assert!(jitter <= 100);
        assert_eq!(health_jitter_ms(&key, HealthGeneration(10), 0), 0);

        let mut supervisor =
            HealthSupervisor::activate(&snapshot(), HealthGeneration(10), 0).unwrap();
        let request = supervisor.handle_tick(0, 1).remove(0);
        assert_eq!(
            supervisor.handle_probe_dispatch_rejected(&request, u64::MAX),
            HandleProbeDispatchRejection::Rescheduled {
                next_due_ms: u64::MAX,
            }
        );
    }

    struct RecordingDispatcher {
        outcomes: RefCell<VecDeque<HealthProbeSubmit>>,
        requests: RefCell<Vec<HealthProbeRequest>>,
    }

    impl RecordingDispatcher {
        fn new(outcomes: Vec<HealthProbeSubmit>) -> Self {
            Self {
                outcomes: RefCell::new(outcomes.into()),
                requests: RefCell::new(Vec::new()),
            }
        }
    }

    impl HealthProbeDispatcher for RecordingDispatcher {
        fn submit(&self, request: HealthProbeRequest) -> HealthProbeSubmit {
            self.requests.borrow_mut().push(request);
            self.outcomes
                .borrow_mut()
                .pop_front()
                .unwrap_or(HealthProbeSubmit::Stopped)
        }
    }

    #[test]
    fn coordinator_dispatches_tick_and_applies_success_completion() {
        let dispatcher = RecordingDispatcher::new(vec![HealthProbeSubmit::Accepted]);
        let mut coordinator =
            HealthRuntimeCoordinator::activate(&snapshot(), HealthGeneration(11), 0).unwrap();

        assert_eq!(
            coordinator.handle_tick(0, 8, &dispatcher),
            HealthTickSummary {
                requested: 1,
                accepted: 1,
                full: 0,
                stopped: 0,
            }
        );
        let request = dispatcher.requests.borrow()[0].clone();
        assert_eq!(
            coordinator.handle_completion(
                HealthProbeCompletion {
                    request,
                    result: HealthProbeResult::succeeded(204, 5),
                },
                5,
            ),
            HandleProbeResult::Applied {
                availability: UpstreamAvailability::Healthy,
                change: Some(edge_domain::HealthStateChange {
                    from: UpstreamAvailability::Unknown,
                    to: UpstreamAvailability::Healthy,
                }),
            }
        );
        let availability = coordinator.availability_snapshot();
        assert_eq!(availability.revision_id.as_str(), "rev-health");
        assert_eq!(availability.generation, HealthGeneration(11));
        assert_eq!(
            availability.entries.get(&UpstreamHealthKey {
                service_id: ServiceId::new("app"),
                upstream_id: UpstreamId::new("app-a"),
            }),
            Some(&UpstreamAvailability::Healthy)
        );
    }

    #[test]
    fn coordinator_reschedules_full_and_stops_on_dispatcher_shutdown() {
        let full_dispatcher = RecordingDispatcher::new(vec![HealthProbeSubmit::Full]);
        let mut coordinator =
            HealthRuntimeCoordinator::activate(&snapshot(), HealthGeneration(12), 0).unwrap();
        assert_eq!(coordinator.handle_tick(0, 1, &full_dispatcher).full, 1);
        assert_eq!(coordinator.handle_tick(0, 1, &full_dispatcher).requested, 0);
        assert_eq!(coordinator.state(), HealthRuntimeCoordinatorState::Running);

        let stopped_dispatcher = RecordingDispatcher::new(vec![HealthProbeSubmit::Stopped]);
        let mut stopped =
            HealthRuntimeCoordinator::activate(&snapshot(), HealthGeneration(13), 0).unwrap();
        assert_eq!(stopped.handle_tick(0, 1, &stopped_dispatcher).stopped, 1);
        assert_eq!(stopped.state(), HealthRuntimeCoordinatorState::Stopped);
        assert_eq!(
            stopped.handle_tick(u64::MAX, 1, &stopped_dispatcher),
            HealthTickSummary::default()
        );
    }

    #[test]
    fn coordinator_maps_probe_failure_and_preserves_stale_fencing() {
        let dispatcher = RecordingDispatcher::new(vec![HealthProbeSubmit::Accepted]);
        let mut coordinator =
            HealthRuntimeCoordinator::activate(&snapshot(), HealthGeneration(14), 0).unwrap();
        coordinator.handle_tick(0, 1, &dispatcher);
        let mut stale = dispatcher.requests.borrow()[0].clone();
        stale.generation = HealthGeneration(13);

        assert_eq!(
            coordinator.handle_completion(
                HealthProbeCompletion {
                    request: stale,
                    result: HealthProbeResult::failed(HealthProbeFailure::ReadTimeout, 100),
                },
                100,
            ),
            HandleProbeResult::Ignored(ProbeResultIgnored::StaleGeneration)
        );
        let request = dispatcher.requests.borrow()[0].clone();
        assert_eq!(
            coordinator.handle_completion(
                HealthProbeCompletion {
                    request,
                    result: HealthProbeResult::failed(HealthProbeFailure::ConnectError, 2),
                },
                2,
            ),
            HandleProbeResult::Applied {
                availability: UpstreamAvailability::Unhealthy,
                change: Some(edge_domain::HealthStateChange {
                    from: UpstreamAvailability::Unknown,
                    to: UpstreamAvailability::Unhealthy,
                }),
            }
        );
    }

    #[test]
    fn stale_duplicate_and_unknown_probe_results_are_ignored_without_state_change() {
        let mut supervisor =
            HealthSupervisor::activate(&snapshot(), HealthGeneration(2), 0).unwrap();
        let request = supervisor.handle_tick(0, 1).remove(0);
        let mut stale = request.clone();
        stale.generation = HealthGeneration(1);

        assert_eq!(
            supervisor.handle_probe_result(&stale, HealthObservation::Failed, 10),
            HandleProbeResult::Ignored(ProbeResultIgnored::StaleGeneration)
        );
        assert_eq!(
            supervisor.handle_probe_result(&request, HealthObservation::Succeeded, 20),
            HandleProbeResult::Applied {
                availability: UpstreamAvailability::Healthy,
                change: Some(edge_domain::HealthStateChange {
                    from: UpstreamAvailability::Unknown,
                    to: UpstreamAvailability::Healthy,
                }),
            }
        );
        assert_eq!(
            supervisor.handle_probe_result(&request, HealthObservation::Failed, 30),
            HandleProbeResult::Ignored(ProbeResultIgnored::NotInFlight)
        );

        let mut unknown = request;
        unknown.key.upstream_id = UpstreamId::new("missing");
        assert_eq!(
            supervisor.handle_probe_result(&unknown, HealthObservation::Failed, 30),
            HandleProbeResult::Ignored(ProbeResultIgnored::UnknownUpstream)
        );
        assert_eq!(
            supervisor.availability(&UpstreamHealthKey {
                service_id: ServiceId::new("app"),
                upstream_id: UpstreamId::new("app-a"),
            }),
            Some(UpstreamAvailability::Healthy)
        );
    }

    #[test]
    fn shutdown_is_terminal_for_ticks_and_probe_results() {
        let mut supervisor =
            HealthSupervisor::activate(&snapshot(), HealthGeneration(3), 0).unwrap();
        let request = supervisor.handle_tick(0, 1).remove(0);

        supervisor.shutdown();

        assert!(supervisor.handle_tick(1_000, 1).is_empty());
        assert_eq!(
            supervisor.handle_probe_result(&request, HealthObservation::Succeeded, 10),
            HandleProbeResult::Ignored(ProbeResultIgnored::Stopped)
        );
        assert_eq!(supervisor.state(), HealthSupervisorState::Stopped);
    }

    #[test]
    fn tick_respects_work_bound_disabled_policy_and_probe_id_wrapping() {
        let mut enabled = snapshot();
        enabled.services[0].upstreams.push(Upstream {
            id: UpstreamId::new("app-b"),
            url: "http://127.0.0.1:3002".to_string(),
            administrative_state: edge_domain::UpstreamAdministrativeState::Active,
            tls: edge_domain::UpstreamTlsPolicy::Disabled,
        });
        let mut supervisor = HealthSupervisor::activate(&enabled, HealthGeneration(4), 0).unwrap();
        supervisor.next_probe_id = u64::MAX;

        let first = supervisor.handle_tick(0, 1);
        let second = supervisor.handle_tick(0, 1);
        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_eq!(first[0].probe_id, HealthProbeId(u64::MAX));
        assert_eq!(second[0].probe_id, HealthProbeId(0));
        assert!(supervisor.handle_tick(0, 1).is_empty());

        let mut disabled = snapshot();
        disabled.services[0].policy.health_check = HealthCheckPolicy::Disabled;
        let mut disabled_supervisor =
            HealthSupervisor::activate(&disabled, HealthGeneration(5), 0).unwrap();
        let key = UpstreamHealthKey {
            service_id: ServiceId::new("app"),
            upstream_id: UpstreamId::new("app-a"),
        };
        assert!(disabled_supervisor.handle_tick(u64::MAX, 8).is_empty());
        assert_eq!(
            disabled_supervisor.availability(&key),
            Some(UpstreamAvailability::Disabled)
        );
    }

    #[test]
    fn activation_rejects_invalid_endpoint_without_panic() {
        let mut invalid = snapshot();
        invalid.services[0].upstreams[0].url = "http://upstream.internal:3000".to_string();

        let error = HealthSupervisor::activate(&invalid, HealthGeneration(6), 0).unwrap_err();

        assert_eq!(error.code, edge_domain::ErrorCode::ConfigInvalidUpstreamUrl);
    }

    #[test]
    fn phase009_health_activation_rejects_scheme_tls_contradiction() {
        let mut invalid = snapshot();
        invalid.services[0].upstreams[0].url = "https://127.0.0.1:3443".to_string();

        let error = HealthSupervisor::activate(&invalid, HealthGeneration(41), 0).unwrap_err();

        assert_eq!(
            error.code,
            edge_domain::ErrorCode::UpstreamTlsProfileInvalid
        );
    }

    #[test]
    fn health_generation_allocator_is_monotonic_and_reports_exhaustion() {
        let mut allocator = HealthGenerationAllocator::new();
        assert_eq!(allocator.allocate().unwrap(), HealthGeneration(1));
        assert_eq!(allocator.allocate().unwrap(), HealthGeneration(2));

        let mut boundary = HealthGenerationAllocator::from_next_for_test(u64::MAX);
        assert_eq!(boundary.allocate().unwrap(), HealthGeneration(u64::MAX));
        assert_eq!(
            boundary.allocate().unwrap_err().code,
            edge_domain::ErrorCode::InternalBug
        );
    }

    #[test]
    fn reconciliation_preserves_matching_health_counter_and_resets_changed_endpoint() {
        let mut previous = snapshot();
        let HealthCheckPolicy::Http(policy) = &mut previous.services[0].policy.health_check else {
            panic!("expected HTTP health policy");
        };
        policy.unhealthy_threshold = 2;
        let mut old =
            HealthRuntimeCoordinator::activate(&previous, HealthGeneration(20), 0).unwrap();
        let request = old.supervisor_for_test().handle_tick(0, 1).remove(0);
        let completion = HealthProbeCompletion {
            request,
            result: edge_ports::HealthProbeResult::failed(
                edge_ports::HealthProbeFailure::ReadTimeout,
                100,
            ),
        };
        assert!(matches!(
            old.handle_completion(completion, 10),
            HandleProbeResult::Applied { change: None, .. }
        ));
        let state = old.reconciliation_snapshot();

        let mut same = HealthRuntimeCoordinator::activate_reconciled(
            &previous,
            HealthGeneration(21),
            0,
            Some(&state),
        )
        .unwrap();
        let request = same.supervisor_for_test().handle_tick(0, 1).remove(0);
        assert!(matches!(
            same.supervisor_for_test()
                .handle_probe_result(&request, HealthObservation::Failed, 10),
            HandleProbeResult::Applied {
                availability: UpstreamAvailability::Unhealthy,
                ..
            }
        ));

        let mut changed = previous;
        changed.services[0].upstreams[0].url = "http://127.0.0.1:3002".to_string();
        let mut reset = HealthRuntimeCoordinator::activate_reconciled(
            &changed,
            HealthGeneration(22),
            0,
            Some(&state),
        )
        .unwrap();
        let request = reset.supervisor_for_test().handle_tick(0, 1).remove(0);
        assert!(matches!(
            reset.supervisor_for_test().handle_probe_result(
                &request,
                HealthObservation::Failed,
                10
            ),
            HandleProbeResult::Applied {
                availability: UpstreamAvailability::Unknown,
                change: None
            }
        ));
    }

    #[test]
    fn phase009_reconciliation_resets_counter_when_tls_identity_changes() {
        let mut previous = snapshot();
        previous.schema_version = 2;
        previous.services[0].upstreams[0].url = "https://127.0.0.1:3443".to_string();
        previous.services[0].upstreams[0].tls =
            edge_domain::UpstreamTlsPolicy::ServerAuthenticated {
                server_name: edge_domain::TlsServerName::parse("old.private.test").unwrap(),
                http_host: edge_domain::UpstreamHttpHost::parse("health.private.test").unwrap(),
                trust_bundle_ref: edge_domain::TrustBundleRef::parse("private-root").unwrap(),
            };
        let HealthCheckPolicy::Http(policy) = &mut previous.services[0].policy.health_check else {
            panic!("expected HTTP health policy");
        };
        policy.unhealthy_threshold = 2;
        let mut old =
            HealthRuntimeCoordinator::activate(&previous, HealthGeneration(42), 0).unwrap();
        let request = old.supervisor_for_test().handle_tick(0, 1).remove(0);
        old.supervisor_for_test()
            .handle_probe_result(&request, HealthObservation::Failed, 10);
        let state = old.reconciliation_snapshot();

        let mut changed = previous;
        let edge_domain::UpstreamTlsPolicy::ServerAuthenticated { server_name, .. } =
            &mut changed.services[0].upstreams[0].tls
        else {
            panic!("expected strict TLS policy");
        };
        *server_name = edge_domain::TlsServerName::parse("new.private.test").unwrap();
        let mut next = HealthRuntimeCoordinator::activate_reconciled(
            &changed,
            HealthGeneration(43),
            0,
            Some(&state),
        )
        .unwrap();
        let request = next.supervisor_for_test().handle_tick(0, 1).remove(0);

        assert!(matches!(
            next.supervisor_for_test()
                .handle_probe_result(&request, HealthObservation::Failed, 10),
            HandleProbeResult::Applied {
                availability: UpstreamAvailability::Unknown,
                change: None,
            }
        ));
    }

    #[test]
    fn reconciliation_resets_policy_changes_and_handles_disabled_added_and_removed_entries() {
        let previous = snapshot();
        let mut old =
            HealthRuntimeCoordinator::activate(&previous, HealthGeneration(30), 0).unwrap();
        let request = old.supervisor_for_test().handle_tick(0, 1).remove(0);
        old.supervisor_for_test()
            .handle_probe_result(&request, HealthObservation::Failed, 10);
        let state = old.reconciliation_snapshot();
        assert_eq!(state.revision_id.as_str(), "rev-health");
        assert_eq!(state.generation, HealthGeneration(30));

        let mut changed = previous.clone();
        changed.services[0].policy.health_check = HealthCheckPolicy::Http(
            HttpHealthCheckPolicy::new("/ready", 1_000, 100, 1, 1, 200, 399).unwrap(),
        );
        changed.services[0].upstreams.push(Upstream {
            id: UpstreamId::new("app-b"),
            url: "http://127.0.0.1:3002".to_string(),
            administrative_state: edge_domain::UpstreamAdministrativeState::Active,
            tls: edge_domain::UpstreamTlsPolicy::Disabled,
        });
        let changed_runtime = HealthRuntimeCoordinator::activate_reconciled(
            &changed,
            HealthGeneration(31),
            0,
            Some(&state),
        )
        .unwrap();
        let changed_availability = changed_runtime.availability_snapshot();
        assert!(changed_availability
            .entries
            .values()
            .all(|value| *value == UpstreamAvailability::Unknown));

        let mut disabled = changed;
        disabled.services[0].policy.health_check = HealthCheckPolicy::Disabled;
        disabled.services[0].upstreams.remove(0);
        let disabled_runtime = HealthRuntimeCoordinator::activate_reconciled(
            &disabled,
            HealthGeneration(32),
            0,
            Some(&state),
        )
        .unwrap();
        let disabled_availability = disabled_runtime.availability_snapshot();
        assert_eq!(disabled_availability.entries.len(), 1);
        assert_eq!(
            disabled_availability.entries.values().next(),
            Some(&UpstreamAvailability::Disabled)
        );
        assert!(!disabled_availability
            .entries
            .contains_key(&UpstreamHealthKey {
                service_id: ServiceId::new("app"),
                upstream_id: UpstreamId::new("app-a"),
            }));
    }

    #[test]
    fn health_transition_observability_has_exact_safe_product_fields_and_bounded_labels() {
        let event = HealthTransitionEvent::new(
            ConfigRevisionId::new("rev-observe"),
            HealthGeneration(17),
            UpstreamHealthKey {
                service_id: ServiceId::new("app"),
                upstream_id: UpstreamId::new("app-a"),
            },
            edge_domain::HealthStateChange {
                from: UpstreamAvailability::Unknown,
                to: UpstreamAvailability::Healthy,
            },
        )
        .unwrap();

        let log = structured_health_transition_log(&event);
        assert_eq!(log.component, "edge-application");
        assert_eq!(log.event, "upstream_health_changed");
        assert_eq!(
            log.fields,
            vec![
                ("revision_id".to_string(), "rev-observe".to_string()),
                ("generation".to_string(), "17".to_string()),
                ("service_id".to_string(), "app".to_string()),
                ("upstream_id".to_string(), "app-a".to_string()),
                ("previous_state".to_string(), "unknown".to_string()),
                ("next_state".to_string(), "healthy".to_string()),
            ]
        );
        assert!(!format!("{log:?}").contains("127.0.0.1"));
        assert!(!format!("{log:?}").contains("secret"));

        let metric = health_transition_metric(&event);
        assert_eq!(
            metric.descriptor,
            MetricDescriptor::UpstreamHealthTransitionsTotal
        );
        assert_eq!(
            metric
                .labels
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>(),
            vec!["from", "service_id", "to", "upstream_id"]
        );
    }

    #[test]
    fn health_operational_metrics_use_fixed_names_and_bounded_reason_values() {
        let key = UpstreamHealthKey {
            service_id: ServiceId::new("app"),
            upstream_id: UpstreamId::new("app-a"),
        };

        assert_eq!(
            upstream_selection_metric(&key).descriptor,
            MetricDescriptor::UpstreamSelectionsTotal
        );
        assert_eq!(
            no_eligible_upstream_metric(&key.service_id).descriptor,
            MetricDescriptor::UpstreamNoEligibleTotal
        );
        let stale = ignored_health_result_metric(&key, ProbeResultIgnored::StaleGeneration);
        assert_eq!(stale.descriptor, MetricDescriptor::MetricEventsDroppedTotal);
        assert!(stale
            .labels
            .contains(&("reason".to_string(), "stale_generation".to_string())));
        let dropped = health_dispatch_drop_metric(HealthDispatchDropReason::QueueFull);
        assert_eq!(
            dropped.descriptor,
            MetricDescriptor::MetricEventsDroppedTotal
        );
        assert_eq!(
            dropped.labels,
            vec![("reason".to_string(), "queue_full".to_string())]
        );
    }

    #[test]
    fn upstream_availability_metric_maps_current_state_to_binary_gauge() {
        let key = UpstreamHealthKey {
            service_id: ServiceId::new("service-a"),
            upstream_id: edge_domain::UpstreamId::new("upstream-a"),
        };

        let healthy = upstream_availability_metric(&key, UpstreamAvailability::Healthy);
        let unhealthy = upstream_availability_metric(&key, UpstreamAvailability::Unhealthy);

        assert_eq!(healthy.descriptor, MetricDescriptor::UpstreamAvailable);
        assert_eq!(healthy.operation, edge_ports::MetricOperation::GaugeSet(1));
        assert_eq!(
            unhealthy.operation,
            edge_ports::MetricOperation::GaugeSet(0)
        );
        assert_eq!(healthy.labels, health_key_labels(&key));
    }

    #[test]
    fn health_observability_uses_fixed_names_for_all_availability_states() {
        let states = [
            (UpstreamAvailability::Disabled, "disabled"),
            (UpstreamAvailability::Unknown, "unknown"),
            (UpstreamAvailability::Healthy, "healthy"),
            (UpstreamAvailability::Unhealthy, "unhealthy"),
        ];
        for (state, expected) in states {
            assert_eq!(availability_name(state), expected);
        }
        assert!(HealthTransitionEvent::new(
            ConfigRevisionId::new("rev-observe"),
            HealthGeneration(1),
            UpstreamHealthKey {
                service_id: ServiceId::new("app"),
                upstream_id: UpstreamId::new("app-a"),
            },
            edge_domain::HealthStateChange {
                from: UpstreamAvailability::Healthy,
                to: UpstreamAvailability::Healthy,
            },
        )
        .is_none());
    }

    #[test]
    fn health_observability_sink_failure_is_typed_and_does_not_mutate_input() {
        struct FailingLogSink;
        impl edge_ports::LogSink for FailingLogSink {
            fn record_log(
                &mut self,
                _event: edge_ports::StructuredLogEvent,
            ) -> Result<(), AppError> {
                Err(AppError::new(
                    ErrorCode::InternalBug,
                    "test log sink failure",
                ))
            }
        }
        struct FailingMetricsSink;
        impl edge_ports::MetricsSink for FailingMetricsSink {
            fn record_metric(&mut self, _metric: edge_ports::MetricEvent) -> Result<(), AppError> {
                Err(AppError::new(
                    ErrorCode::InternalBug,
                    "test metric sink failure",
                ))
            }
        }

        let event = HealthTransitionEvent::new(
            ConfigRevisionId::new("rev-observe"),
            HealthGeneration(18),
            UpstreamHealthKey {
                service_id: ServiceId::new("app"),
                upstream_id: UpstreamId::new("app-a"),
            },
            edge_domain::HealthStateChange {
                from: UpstreamAvailability::Healthy,
                to: UpstreamAvailability::Unhealthy,
            },
        )
        .unwrap();
        let before = event.clone();
        let error = record_health_transition_log(&mut FailingLogSink, &event).unwrap_err();
        let metric_error =
            record_health_transition_metric(&mut FailingMetricsSink, &event).unwrap_err();

        assert_eq!(error.code, ErrorCode::InternalBug);
        assert_eq!(metric_error.code, ErrorCode::InternalBug);
        assert_eq!(event, before);
    }

    #[test]
    fn field_debug_health_sampler_enforces_sixty_second_boundary_and_capacity() {
        let event = HealthProbeDebugEvent::failed(
            ConfigRevisionId::new("rev-debug"),
            HealthGeneration(3),
            UpstreamHealthKey {
                service_id: ServiceId::new("app"),
                upstream_id: UpstreamId::new("app-a"),
            },
            edge_ports::HealthProbeFailure::ReadTimeout,
            150,
        );
        let mut sampler = FieldDebugHealthSampler::new(1);

        assert!(sampler.should_emit(&event, 0));
        assert!(!sampler.should_emit(&event, 59_999));
        assert!(sampler.should_emit(&event, 60_000));

        let other = HealthProbeDebugEvent::failed(
            ConfigRevisionId::new("rev-debug"),
            HealthGeneration(3),
            UpstreamHealthKey {
                service_id: ServiceId::new("app"),
                upstream_id: UpstreamId::new("app-b"),
            },
            edge_ports::HealthProbeFailure::ConnectError,
            2,
        );
        assert!(sampler.should_emit(&other, 60_001));
        assert_eq!(sampler.len(), 1);
    }

    #[test]
    fn field_debug_health_event_has_exact_safe_bounded_fields() {
        let event = HealthProbeDebugEvent::succeeded(
            ConfigRevisionId::new("rev-debug"),
            HealthGeneration(4),
            UpstreamHealthKey {
                service_id: ServiceId::new("app"),
                upstream_id: UpstreamId::new("app-a"),
            },
            204,
            7,
        );
        let log = structured_health_probe_debug_log(&event);

        assert_eq!(log.event, "upstream_health_probe_debug");
        assert_eq!(
            log.fields
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>(),
            vec![
                "revision_id",
                "generation",
                "service_id",
                "upstream_id",
                "outcome",
                "status_code",
                "duration_ms",
            ]
        );
        assert!(log
            .fields
            .contains(&("outcome".to_string(), "succeeded".to_string())));
        assert!(!format!("{log:?}").contains("127.0.0.1"));
        assert!(!format!("{log:?}").contains("/health"));
    }
}
