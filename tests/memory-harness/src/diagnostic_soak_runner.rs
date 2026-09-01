use crate::diagnostic_soak::{
    evaluate_diagnostic_soak, DiagnosticSoakObservation, DiagnosticSoakReport,
    SOAK_INTERVAL_SECONDS, SOAK_OBSERVATION_COUNT,
};
use crate::soak_window::{
    SoakWindowIdentity, SoakWindowLoadPort, SoakWindowProcessPort, SoakWindowRequest,
    SoakWindowRunner, SoakWindowRuntimePort,
};
use crate::HarnessError;

pub const SOAK_MAX_SCHEDULE_LATENESS_SECONDS: u64 = 5;

pub trait SoakSchedulePort {
    fn wait_until_seconds(&mut self, target: u64) -> Result<(), HarnessError>;
    fn elapsed_seconds(&mut self) -> Result<u64, HarnessError>;
}

pub trait SoakWindowExecutionPort {
    fn execute(
        &mut self,
        request: SoakWindowRequest,
    ) -> Result<DiagnosticSoakObservation, HarnessError>;
}

pub struct PortSoakWindowExecutor<L, R, P> {
    load: L,
    runtime: R,
    process: P,
}

impl<L, R, P> PortSoakWindowExecutor<L, R, P>
where
    L: SoakWindowLoadPort,
    R: SoakWindowRuntimePort,
    P: SoakWindowProcessPort,
{
    pub fn new(load: L, runtime: R, process: P) -> Self {
        Self {
            load,
            runtime,
            process,
        }
    }
}

impl<L, R, P> SoakWindowExecutionPort for PortSoakWindowExecutor<L, R, P>
where
    L: SoakWindowLoadPort,
    R: SoakWindowRuntimePort,
    P: SoakWindowProcessPort,
{
    fn execute(
        &mut self,
        request: SoakWindowRequest,
    ) -> Result<DiagnosticSoakObservation, HarnessError> {
        SoakWindowRunner::new(&mut self.load, &mut self.runtime, &mut self.process).run(request)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticSoakRunnerState {
    Created,
    Baseline,
    Running { completed_windows: u32 },
    Analyzing,
    Published,
    Failed,
}

pub struct DiagnosticSoakOrchestrator<S, E> {
    schedule: S,
    executor: E,
    identity: SoakWindowIdentity,
    state: DiagnosticSoakRunnerState,
}

impl<S, E> DiagnosticSoakOrchestrator<S, E>
where
    S: SoakSchedulePort,
    E: SoakWindowExecutionPort,
{
    pub fn new(schedule: S, executor: E, identity: SoakWindowIdentity) -> Self {
        Self {
            schedule,
            executor,
            identity,
            state: DiagnosticSoakRunnerState::Created,
        }
    }

    pub fn state(&self) -> DiagnosticSoakRunnerState {
        self.state
    }

    pub fn schedule(&self) -> &S {
        &self.schedule
    }

    pub fn run(&mut self) -> Result<DiagnosticSoakReport, HarnessError> {
        if self.state != DiagnosticSoakRunnerState::Created {
            return self.fail("diagnostic soak orchestrator is not reusable");
        }
        let mut observations = Vec::with_capacity(SOAK_OBSERVATION_COUNT as usize);
        for index in 0..SOAK_OBSERVATION_COUNT {
            self.state = if index == 0 {
                DiagnosticSoakRunnerState::Baseline
            } else {
                DiagnosticSoakRunnerState::Running {
                    completed_windows: index - 1,
                }
            };
            let target = u64::from(index) * SOAK_INTERVAL_SECONDS;
            if self.schedule.wait_until_seconds(target).is_err() {
                return self.fail("diagnostic soak schedule wait failed");
            }
            let actual = match self.schedule.elapsed_seconds() {
                Ok(value) => value,
                Err(_) => return self.fail("diagnostic soak schedule observation failed"),
            };
            if actual < target || actual > target + SOAK_MAX_SCHEDULE_LATENESS_SECONDS {
                return self.fail("diagnostic soak schedule deadline was missed");
            }
            let request = SoakWindowRequest::new(index, target, self.identity.clone())?;
            let observation = match self.executor.execute(request) {
                Ok(value) => value,
                Err(error) => {
                    return self.fail(&format!(
                        "diagnostic soak window execution failed at index {index}: {error}"
                    ));
                }
            };
            observations.push(observation);
        }
        self.state = DiagnosticSoakRunnerState::Analyzing;
        let report = match evaluate_diagnostic_soak(observations) {
            Ok(value) => value,
            Err(_) => return self.fail("diagnostic soak final evaluation failed"),
        };
        self.state = DiagnosticSoakRunnerState::Published;
        Ok(report)
    }

    fn fail<T>(&mut self, message: &str) -> Result<T, HarnessError> {
        self.state = DiagnosticSoakRunnerState::Failed;
        Err(HarnessError::new(message))
    }
}
