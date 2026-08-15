//! Process lifecycle facts used by unauthenticated operational probes.
//!
//! This model deliberately contains no listener, signal, clock, or I/O handle.
//! Adapters publish observed facts; the model decides only safe liveness and
//! readiness responses.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationalLifecycle {
    Starting,
    Ready,
    Draining,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStatus {
    Live,
    NotLive,
    Ready,
    NotReady,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OperationalRuntimeFacts {
    pub has_active_snapshot: bool,
    pub has_listener: bool,
    pub has_command_path: bool,
}

impl OperationalLifecycle {
    /// Returns the limited unauthenticated liveness fact: event-loop ownership
    /// remains available until it has stopped or entered an unrecoverable state.
    pub fn liveness(self) -> ProbeStatus {
        match self {
            Self::Starting | Self::Ready | Self::Draining => ProbeStatus::Live,
            Self::Stopped | Self::Failed => ProbeStatus::NotLive,
        }
    }

    /// Readiness requires an active configuration, listener, and command path;
    /// upstream availability is intentionally not a global readiness condition.
    pub fn readiness(
        self,
        has_active_snapshot: bool,
        has_listener: bool,
        has_command_path: bool,
    ) -> ProbeStatus {
        if self == Self::Ready && has_active_snapshot && has_listener && has_command_path {
            ProbeStatus::Ready
        } else {
            ProbeStatus::NotReady
        }
    }

    /// Applies the only legal process-state transitions used by the bootstrap
    /// adapter. Repeated termination remains idempotently draining/stopped.
    pub fn transition(self, event: OperationalLifecycleEvent) -> Self {
        match (self, event) {
            (Self::Starting, OperationalLifecycleEvent::StartupSucceeded) => Self::Ready,
            (Self::Starting | Self::Ready, OperationalLifecycleEvent::TerminationRequested) => {
                Self::Draining
            }
            (Self::Draining, OperationalLifecycleEvent::DrainCompleted)
            | (Self::Draining, OperationalLifecycleEvent::DeadlineExpired) => Self::Stopped,
            (Self::Starting | Self::Ready | Self::Draining, OperationalLifecycleEvent::Failed) => {
                Self::Failed
            }
            (state, _) => state,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationalLifecycleEvent {
    StartupSucceeded,
    TerminationRequested,
    DrainCompleted,
    DeadlineExpired,
    Failed,
}

#[cfg(test)]
mod tests {
    use super::{OperationalLifecycle, OperationalLifecycleEvent, ProbeStatus};

    #[test]
    fn readiness_requires_runtime_facts_but_not_each_upstream_health() {
        assert_eq!(
            OperationalLifecycle::Ready.readiness(true, true, true),
            ProbeStatus::Ready
        );
        assert_eq!(
            OperationalLifecycle::Ready.readiness(true, false, true),
            ProbeStatus::NotReady
        );
        assert_eq!(
            OperationalLifecycle::Draining.readiness(true, true, true),
            ProbeStatus::NotReady
        );
    }

    #[test]
    fn termination_is_idempotent_and_deadline_ends_drain() {
        let draining =
            OperationalLifecycle::Ready.transition(OperationalLifecycleEvent::TerminationRequested);
        assert_eq!(draining, OperationalLifecycle::Draining);
        assert_eq!(
            draining.transition(OperationalLifecycleEvent::TerminationRequested),
            OperationalLifecycle::Draining
        );
        assert_eq!(
            draining.transition(OperationalLifecycleEvent::DeadlineExpired),
            OperationalLifecycle::Stopped
        );
    }
}
