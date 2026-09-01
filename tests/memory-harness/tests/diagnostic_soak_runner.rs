use edge_memory_harness::diagnostic_soak::{
    DiagnosticSoakObservation, SoakWorkload, SOAK_OBSERVATION_COUNT,
};
use edge_memory_harness::diagnostic_soak_runner::{
    DiagnosticSoakOrchestrator, DiagnosticSoakRunnerState, SoakSchedulePort,
    SoakWindowExecutionPort,
};
use edge_memory_harness::soak_window::{SoakWindowIdentity, SoakWindowRequest};
use edge_memory_harness::HarnessError;

const BUILD: &str =
    "source-tree-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CONFIG: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PROCESS: &str = "macos-lstart:orchestrator-process";

#[test]
fn exact_121_deadlines_and_alternating_windows_publish() {
    let mut orchestrator =
        DiagnosticSoakOrchestrator::new(FakeSchedule::exact(), FakeExecutor::clean(), identity());
    let report = orchestrator.run().unwrap();
    assert_eq!(report.observation_count, SOAK_OBSERVATION_COUNT);
    assert_eq!(report.duration_seconds, 7_200);
    assert_eq!(report.churn_windows, 60);
    assert_eq!(report.websocket_windows, 60);
    assert_eq!(orchestrator.state(), DiagnosticSoakRunnerState::Published);
    assert_eq!(
        orchestrator.schedule().targets,
        (0..SOAK_OBSERVATION_COUNT)
            .map(|index| u64::from(index) * 60)
            .collect::<Vec<_>>()
    );
}

#[test]
fn early_or_late_scheduler_fails_closed() {
    for schedule in [FakeSchedule::early_at(1), FakeSchedule::late_at(40)] {
        let mut orchestrator =
            DiagnosticSoakOrchestrator::new(schedule, FakeExecutor::clean(), identity());
        assert!(orchestrator.run().is_err());
        assert_eq!(orchestrator.state(), DiagnosticSoakRunnerState::Failed);
    }
}

#[test]
fn window_failure_and_reuse_are_terminal() {
    let mut failed = DiagnosticSoakOrchestrator::new(
        FakeSchedule::exact(),
        FakeExecutor::fail_at(20),
        identity(),
    );
    let error = failed.run().unwrap_err();
    assert!(error.to_string().contains("fake window failure"));
    assert_eq!(failed.state(), DiagnosticSoakRunnerState::Failed);

    let mut completed =
        DiagnosticSoakOrchestrator::new(FakeSchedule::exact(), FakeExecutor::clean(), identity());
    completed.run().unwrap();
    assert!(completed.run().is_err());
    assert_eq!(completed.state(), DiagnosticSoakRunnerState::Failed);
}

fn identity() -> SoakWindowIdentity {
    SoakWindowIdentity::new(BUILD, CONFIG, PROCESS).unwrap()
}

struct FakeSchedule {
    targets: Vec<u64>,
    current: u64,
    early_at: Option<u32>,
    late_at: Option<u32>,
}

impl FakeSchedule {
    fn exact() -> Self {
        Self {
            targets: Vec::new(),
            current: 0,
            early_at: None,
            late_at: None,
        }
    }

    fn early_at(index: u32) -> Self {
        Self {
            early_at: Some(index),
            ..Self::exact()
        }
    }

    fn late_at(index: u32) -> Self {
        Self {
            late_at: Some(index),
            ..Self::exact()
        }
    }
}

impl SoakSchedulePort for FakeSchedule {
    fn wait_until_seconds(&mut self, target: u64) -> Result<(), HarnessError> {
        self.targets.push(target);
        let index = u32::try_from(target / 60).unwrap();
        self.current = if self.early_at == Some(index) {
            target.saturating_sub(1)
        } else if self.late_at == Some(index) {
            target + 6
        } else {
            target
        };
        Ok(())
    }

    fn elapsed_seconds(&mut self) -> Result<u64, HarnessError> {
        Ok(self.current)
    }
}

struct FakeExecutor {
    fail_at: Option<u32>,
}

impl FakeExecutor {
    fn clean() -> Self {
        Self { fail_at: None }
    }

    fn fail_at(index: u32) -> Self {
        Self {
            fail_at: Some(index),
        }
    }
}

impl SoakWindowExecutionPort for FakeExecutor {
    fn execute(
        &mut self,
        request: SoakWindowRequest,
    ) -> Result<DiagnosticSoakObservation, HarnessError> {
        if self.fail_at == Some(request.index()) {
            return Err(HarnessError::new("fake window failure"));
        }
        Ok(DiagnosticSoakObservation {
            index: request.index(),
            elapsed_seconds: request.elapsed_seconds(),
            workload: request.workload(),
            build_identity: BUILD.to_string(),
            config_sha256: CONFIG.to_string(),
            process_start_identity: PROCESS.to_string(),
            expected: request.expected(),
            succeeded: request.expected(),
            failed: 0,
            process_alive: true,
            rss_bytes: 12_000_000,
            cleanup_connections: 0,
            cleanup_payload_bytes: 0,
            cleanup_pressure: "normal".to_string(),
            recovery_status: 200,
        })
    }
}

#[test]
fn workload_mapping_is_fixed_by_request() {
    let baseline = SoakWindowRequest::new(0, 0, identity()).unwrap();
    let churn = SoakWindowRequest::new(1, 60, identity()).unwrap();
    let websocket = SoakWindowRequest::new(2, 120, identity()).unwrap();
    assert_eq!(baseline.workload(), SoakWorkload::Baseline);
    assert_eq!(churn.workload(), SoakWorkload::Churn);
    assert_eq!(websocket.workload(), SoakWorkload::Websocket);
}
