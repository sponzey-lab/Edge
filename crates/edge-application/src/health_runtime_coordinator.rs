use edge_domain::{AppError, ConfigSnapshot, HealthObservation, UpstreamAvailability};
use edge_ports::{
    HealthAvailabilitySnapshot, HealthProbeCompletion, HealthProbeDispatcher, HealthProbeOutcome,
    HealthProbeSubmit,
};

use crate::{
    HandleProbeResult, HealthGeneration, HealthReconciliationSnapshot, HealthSupervisor,
    UpstreamHealthKey,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthRuntimeCoordinatorState {
    Running,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HealthTickSummary {
    pub requested: usize,
    pub accepted: usize,
    pub full: usize,
    pub stopped: usize,
}

#[derive(Debug, Clone)]
pub struct HealthRuntimeCoordinator {
    supervisor: HealthSupervisor,
    state: HealthRuntimeCoordinatorState,
}

impl HealthRuntimeCoordinator {
    pub fn activate(
        snapshot: &ConfigSnapshot,
        generation: HealthGeneration,
        now_ms: u64,
    ) -> Result<Self, AppError> {
        Self::activate_reconciled(snapshot, generation, now_ms, None)
    }

    pub fn activate_reconciled(
        snapshot: &ConfigSnapshot,
        generation: HealthGeneration,
        now_ms: u64,
        previous: Option<&HealthReconciliationSnapshot>,
    ) -> Result<Self, AppError> {
        Ok(Self {
            supervisor: HealthSupervisor::activate_reconciled(
                snapshot, generation, now_ms, previous,
            )?,
            state: HealthRuntimeCoordinatorState::Running,
        })
    }

    pub fn state(&self) -> HealthRuntimeCoordinatorState {
        self.state
    }

    pub fn availability(&self, key: &UpstreamHealthKey) -> Option<UpstreamAvailability> {
        self.supervisor.availability(key)
    }

    pub fn availability_snapshot(&self) -> HealthAvailabilitySnapshot {
        self.supervisor.availability_snapshot()
    }

    pub fn reconciliation_snapshot(&self) -> HealthReconciliationSnapshot {
        self.supervisor.reconciliation_snapshot()
    }

    pub fn handle_tick(
        &mut self,
        now_ms: u64,
        max_work: usize,
        dispatcher: &dyn HealthProbeDispatcher,
    ) -> HealthTickSummary {
        if self.state == HealthRuntimeCoordinatorState::Stopped {
            return HealthTickSummary::default();
        }
        let work = self.supervisor.handle_tick(now_ms, max_work);
        let mut summary = HealthTickSummary {
            requested: work.len(),
            ..HealthTickSummary::default()
        };
        for request in work {
            match dispatcher.submit(request.clone()) {
                HealthProbeSubmit::Accepted => summary.accepted += 1,
                HealthProbeSubmit::Full => {
                    summary.full += 1;
                    self.supervisor
                        .handle_probe_dispatch_rejected(&request, now_ms);
                }
                HealthProbeSubmit::Stopped => {
                    summary.stopped += 1;
                    self.state = HealthRuntimeCoordinatorState::Stopped;
                    self.supervisor.shutdown();
                    break;
                }
            }
        }
        summary
    }

    pub fn handle_completion(
        &mut self,
        completion: HealthProbeCompletion,
        completed_at_ms: u64,
    ) -> HandleProbeResult {
        let observation = match completion.result.outcome {
            HealthProbeOutcome::Succeeded { .. } => HealthObservation::Succeeded,
            HealthProbeOutcome::Failed(_) => HealthObservation::Failed,
        };
        self.supervisor
            .handle_probe_result(&completion.request, observation, completed_at_ms)
    }

    pub fn shutdown(&mut self) {
        self.state = HealthRuntimeCoordinatorState::Stopped;
        self.supervisor.shutdown();
    }

    #[cfg(test)]
    pub(crate) fn supervisor_for_test(&mut self) -> &mut HealthSupervisor {
        &mut self.supervisor
    }
}
