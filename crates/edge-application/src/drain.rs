use std::collections::{BTreeMap, BTreeSet};

use edge_domain::{ConfigSnapshot, UpstreamAdministrativeState, UpstreamHealthKey};
use edge_ports::{RuntimeDrainState, RuntimeUpstreamStatus, RuntimeUpstreamStatusSnapshot};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct DrainGeneration(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainReference {
    generation: DrainGeneration,
    key: UpstreamHealthKey,
    lease_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamDrainState {
    Active,
    Draining,
    Drained,
    Removed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamDrainStatus {
    pub state: UpstreamDrainState,
    pub connection_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainAcquireResult {
    Acquired,
    NotSelectable(UpstreamDrainState),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainReleaseResult {
    Released,
    DrainCompleted,
    RemovedCompleted,
    Unknown,
    Underflow,
}

#[derive(Debug, Clone, Default)]
pub struct UpstreamDrainTracker {
    current_generation: Option<DrainGeneration>,
    entries: BTreeMap<(DrainGeneration, UpstreamHealthKey), DrainEntry>,
    next_lease_id: u64,
}

#[derive(Debug, Clone)]
struct DrainEntry {
    state: UpstreamDrainState,
    leases: BTreeSet<u64>,
}

impl UpstreamDrainTracker {
    pub fn from_snapshot(snapshot: &ConfigSnapshot, generation: DrainGeneration) -> Self {
        let mut tracker = Self::default();
        tracker.reconcile(snapshot, generation);
        tracker
    }

    pub fn reconcile(&mut self, snapshot: &ConfigSnapshot, generation: DrainGeneration) {
        let desired: BTreeMap<_, _> = snapshot
            .services
            .iter()
            .flat_map(|service| {
                service.upstreams.iter().map(|upstream| {
                    (
                        UpstreamHealthKey {
                            service_id: service.id.clone(),
                            upstream_id: upstream.id.clone(),
                        },
                        upstream.administrative_state,
                    )
                })
            })
            .collect();

        if let Some(current) = self.current_generation {
            for ((entry_generation, key), entry) in &mut self.entries {
                if *entry_generation != current {
                    continue;
                }
                entry.state = if desired.get(key) == Some(&UpstreamAdministrativeState::Draining) {
                    if entry.leases.is_empty() {
                        UpstreamDrainState::Drained
                    } else {
                        UpstreamDrainState::Draining
                    }
                } else {
                    UpstreamDrainState::Removed
                };
            }
        }

        for (key, administrative_state) in desired {
            let state = match administrative_state {
                UpstreamAdministrativeState::Active => UpstreamDrainState::Active,
                UpstreamAdministrativeState::Draining => UpstreamDrainState::Drained,
            };
            self.entries.insert(
                (generation, key),
                DrainEntry {
                    state,
                    leases: BTreeSet::new(),
                },
            );
        }
        self.current_generation = Some(generation);
    }

    pub fn acquire(
        &mut self,
        generation: DrainGeneration,
        key: &UpstreamHealthKey,
    ) -> (DrainAcquireResult, Option<DrainReference>) {
        if self.current_generation != Some(generation) {
            return (DrainAcquireResult::Unknown, None);
        }
        let Some(entry) = self.entries.get_mut(&(generation, key.clone())) else {
            return (DrainAcquireResult::Unknown, None);
        };
        if entry.state != UpstreamDrainState::Active {
            return (DrainAcquireResult::NotSelectable(entry.state), None);
        }
        let lease_id = self.next_lease_id;
        self.next_lease_id = self.next_lease_id.wrapping_add(1);
        entry.leases.insert(lease_id);
        (
            DrainAcquireResult::Acquired,
            Some(DrainReference {
                generation,
                key: key.clone(),
                lease_id,
            }),
        )
    }

    pub fn release(&mut self, reference: &DrainReference) -> DrainReleaseResult {
        let Some(entry) = self
            .entries
            .get_mut(&(reference.generation, reference.key.clone()))
        else {
            return DrainReleaseResult::Unknown;
        };
        if !entry.leases.remove(&reference.lease_id) {
            return DrainReleaseResult::Underflow;
        }
        if !entry.leases.is_empty() {
            return DrainReleaseResult::Released;
        }
        match entry.state {
            UpstreamDrainState::Draining => {
                entry.state = UpstreamDrainState::Drained;
                DrainReleaseResult::DrainCompleted
            }
            UpstreamDrainState::Removed => DrainReleaseResult::RemovedCompleted,
            UpstreamDrainState::Active | UpstreamDrainState::Drained => {
                DrainReleaseResult::Released
            }
        }
    }

    pub fn status(
        &self,
        generation: DrainGeneration,
        key: &UpstreamHealthKey,
    ) -> Option<UpstreamDrainStatus> {
        self.entries
            .get(&(generation, key.clone()))
            .map(|entry| UpstreamDrainStatus {
                state: entry.state,
                connection_count: entry.leases.len() as u64,
            })
    }

    pub fn current_generation(&self) -> Option<DrainGeneration> {
        self.current_generation
    }

    pub fn operational_snapshot(&self, snapshot: &ConfigSnapshot) -> RuntimeUpstreamStatusSnapshot {
        let generation = self.current_generation.unwrap_or_default();
        let mut upstreams = Vec::new();
        for service in &snapshot.services {
            for upstream in &service.upstreams {
                let key = UpstreamHealthKey {
                    service_id: service.id.clone(),
                    upstream_id: upstream.id.clone(),
                };
                let current = self
                    .status(generation, &key)
                    .unwrap_or(UpstreamDrainStatus {
                        state: UpstreamDrainState::Removed,
                        connection_count: 0,
                    });
                let old_count = self
                    .entries
                    .iter()
                    .filter(|((entry_generation, entry_key), entry)| {
                        *entry_generation != generation
                            && entry_key == &key
                            && matches!(
                                entry.state,
                                UpstreamDrainState::Draining | UpstreamDrainState::Removed
                            )
                    })
                    .map(|(_, entry)| entry.leases.len() as u64)
                    .sum::<u64>();
                let connection_count = current.connection_count.saturating_add(old_count);
                let state =
                    if upstream.administrative_state == UpstreamAdministrativeState::Draining {
                        if connection_count == 0 {
                            RuntimeDrainState::Drained
                        } else {
                            RuntimeDrainState::Draining
                        }
                    } else {
                        RuntimeDrainState::Active
                    };
                upstreams.push(RuntimeUpstreamStatus {
                    key,
                    state,
                    connection_count,
                });
            }
        }
        RuntimeUpstreamStatusSnapshot {
            revision_id: snapshot.revision_id.clone(),
            generation: generation.0,
            upstreams,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_domain::{
        AdminConfig, ConfigRevisionId, LogMode, RuntimeOptions, Service, ServiceId, Upstream,
        UpstreamId,
    };

    fn snapshot(
        revision: &str,
        upstreams: &[(&str, UpstreamAdministrativeState)],
    ) -> ConfigSnapshot {
        ConfigSnapshot {
            schema_version: 1,
            revision_id: ConfigRevisionId::new(revision),
            admin: AdminConfig {
                bind: "127.0.0.1:9443".into(),
                auth_required: true,
            },
            listeners: vec![],
            services: vec![Service {
                id: ServiceId::new("service"),
                upstreams: upstreams
                    .iter()
                    .map(|(id, administrative_state)| Upstream {
                        id: UpstreamId::new(*id),
                        url: "http://127.0.0.1:8080".into(),
                        administrative_state: *administrative_state,
                        tls: edge_domain::UpstreamTlsPolicy::Disabled,
                    })
                    .collect(),
                policy: Default::default(),
            }],
            routes: Vec::new(),
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

    fn key(id: &str) -> UpstreamHealthKey {
        UpstreamHealthKey {
            service_id: ServiceId::new("service"),
            upstream_id: UpstreamId::new(id),
        }
    }

    #[test]
    fn zero_reference_drain_is_immediately_drained() {
        let generation = DrainGeneration(1);
        let mut tracker = UpstreamDrainTracker::from_snapshot(
            &snapshot("rev-1", &[("a", UpstreamAdministrativeState::Active)]),
            generation,
        );

        tracker.reconcile(
            &snapshot("rev-2", &[("a", UpstreamAdministrativeState::Draining)]),
            DrainGeneration(2),
        );

        assert_eq!(
            tracker.status(DrainGeneration(2), &key("a")),
            Some(UpstreamDrainStatus {
                state: UpstreamDrainState::Drained,
                connection_count: 0,
            })
        );
    }

    #[test]
    fn in_flight_reference_completes_drain_only_after_release() {
        let generation = DrainGeneration(1);
        let mut tracker = UpstreamDrainTracker::from_snapshot(
            &snapshot("rev-1", &[("a", UpstreamAdministrativeState::Active)]),
            generation,
        );
        let (result, reference) = tracker.acquire(generation, &key("a"));
        assert_eq!(result, DrainAcquireResult::Acquired);

        tracker.reconcile(
            &snapshot("rev-2", &[("a", UpstreamAdministrativeState::Draining)]),
            DrainGeneration(2),
        );
        assert_eq!(
            tracker.status(generation, &key("a")).unwrap().state,
            UpstreamDrainState::Draining
        );
        assert_eq!(
            tracker.release(&reference.unwrap()),
            DrainReleaseResult::DrainCompleted
        );
    }

    #[test]
    fn remove_and_readd_fences_old_release_from_new_generation() {
        let mut tracker = UpstreamDrainTracker::from_snapshot(
            &snapshot("rev-1", &[("a", UpstreamAdministrativeState::Active)]),
            DrainGeneration(1),
        );
        let (_, old_reference) = tracker.acquire(DrainGeneration(1), &key("a"));
        tracker.reconcile(&snapshot("rev-2", &[]), DrainGeneration(2));
        tracker.reconcile(
            &snapshot("rev-3", &[("a", UpstreamAdministrativeState::Active)]),
            DrainGeneration(3),
        );
        let (_, new_reference) = tracker.acquire(DrainGeneration(3), &key("a"));

        assert_eq!(
            tracker.release(&old_reference.unwrap()),
            DrainReleaseResult::RemovedCompleted
        );
        assert_eq!(
            tracker
                .status(DrainGeneration(3), &key("a"))
                .unwrap()
                .connection_count,
            1
        );
        assert_eq!(
            tracker.release(&new_reference.unwrap()),
            DrainReleaseResult::Released
        );
    }

    #[test]
    fn unknown_and_duplicate_release_do_not_mutate_counts() {
        let generation = DrainGeneration(1);
        let mut tracker = UpstreamDrainTracker::from_snapshot(
            &snapshot("rev-1", &[("a", UpstreamAdministrativeState::Active)]),
            generation,
        );
        let (_, reference) = tracker.acquire(generation, &key("a"));
        let reference = reference.unwrap();
        assert_eq!(tracker.release(&reference), DrainReleaseResult::Released);
        assert_eq!(tracker.release(&reference), DrainReleaseResult::Underflow);
        assert_eq!(
            tracker.acquire(generation, &key("missing")).0,
            DrainAcquireResult::Unknown
        );
        assert_eq!(
            tracker
                .status(generation, &key("a"))
                .unwrap()
                .connection_count,
            0
        );
    }

    #[test]
    fn operational_snapshot_aggregates_old_in_flight_drain_reference() {
        let mut tracker = UpstreamDrainTracker::from_snapshot(
            &snapshot("rev-1", &[("a", UpstreamAdministrativeState::Active)]),
            DrainGeneration(1),
        );
        let _ = tracker.acquire(DrainGeneration(1), &key("a"));
        let draining = snapshot("rev-2", &[("a", UpstreamAdministrativeState::Draining)]);
        tracker.reconcile(&draining, DrainGeneration(2));

        let status = tracker.operational_snapshot(&draining);

        assert_eq!(status.revision_id.as_str(), "rev-2");
        assert_eq!(status.generation, 2);
        assert_eq!(
            status.upstreams[0].state,
            edge_ports::RuntimeDrainState::Draining
        );
        assert_eq!(status.upstreams[0].connection_count, 1);
    }
}
