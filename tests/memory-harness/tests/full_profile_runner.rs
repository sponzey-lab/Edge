use edge_memory_harness::full_profile_readiness::{evaluate_full_profile, FULL_PROFILE_SCENARIOS};
use std::fs;
use std::path::Path;

use edge_memory_harness::full_profile_runner::{
    build_verified_input, validate_runner_entrypoints, validate_runner_registry,
    FullProfileRunnerEvent, FullProfileRunnerState, RunnerJobOutcome, RunnerLifecycle,
    FULL_PROFILE_JOBS,
};

const BUILD: &str =
    "source-tree-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[test]
fn fixed_ten_jobs_cover_exact_twelve_scenarios() {
    validate_runner_registry().unwrap();
    assert_eq!(FULL_PROFILE_JOBS.len(), 10);
    let mut covered = FULL_PROFILE_JOBS
        .iter()
        .flat_map(|job| job.scenarios.iter().copied())
        .collect::<Vec<_>>();
    covered.sort_unstable();
    let mut expected = FULL_PROFILE_SCENARIOS
        .iter()
        .map(|scenario| scenario.scenario_id)
        .collect::<Vec<_>>();
    expected.sort_unstable();
    assert_eq!(covered, expected);
}

#[test]
fn physical_executable_entrypoints_are_required_before_a_profile_is_planned() {
    let root = temporary_root("entrypoint-preflight");
    assert!(validate_runner_entrypoints(&root).is_err());

    for job in FULL_PROFILE_JOBS {
        let path = root.join(job.script_path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        set_executable(&path);
    }

    assert!(validate_runner_entrypoints(&root).is_ok());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn all_fixed_job_successes_build_ready_ordered_input() {
    let input = build_verified_input(BUILD, "macos", "aarch64", outcomes()).unwrap();
    assert_eq!(input.entries.len(), 12);
    assert_eq!(
        input
            .entries
            .iter()
            .map(|entry| entry.scenario_id.as_str())
            .collect::<Vec<_>>(),
        FULL_PROFILE_SCENARIOS
            .iter()
            .map(|scenario| scenario.scenario_id)
            .collect::<Vec<_>>()
    );
    assert!(input.entries.iter().all(|entry| entry.validation_passed));
    assert!(evaluate_full_profile(input).unwrap().ready);
}

#[test]
fn failure_duplicate_missing_stale_and_bad_digest_fail_closed() {
    let mut failed = outcomes();
    failed[2].script_passed = false;
    assert!(build_verified_input(BUILD, "macos", "aarch64", failed).is_err());

    let mut duplicate = outcomes();
    duplicate[1].job_id = duplicate[0].job_id.clone();
    assert!(build_verified_input(BUILD, "macos", "aarch64", duplicate).is_err());

    let mut missing = outcomes();
    missing.pop();
    assert!(build_verified_input(BUILD, "macos", "aarch64", missing).is_err());

    let mut stale = outcomes();
    stale[4].build_identity = format!("source-tree-sha256:{}", "c".repeat(64));
    assert!(build_verified_input(BUILD, "macos", "aarch64", stale).is_err());

    let mut tampered = outcomes();
    tampered[5].report_sha256 = "not-a-digest".to_string();
    assert!(build_verified_input(BUILD, "macos", "aarch64", tampered).is_err());
}

#[test]
fn runner_lifecycle_rejects_out_of_order_and_failure_is_terminal() {
    let mut lifecycle = RunnerLifecycle::new();
    assert!(lifecycle
        .transition(FullProfileRunnerEvent::JobStarted)
        .is_err());
    assert_eq!(lifecycle.state(), FullProfileRunnerState::Failed);
    assert!(lifecycle
        .transition(FullProfileRunnerEvent::PlanValidated)
        .is_err());

    let mut lifecycle = RunnerLifecycle::new();
    lifecycle
        .transition(FullProfileRunnerEvent::PlanValidated)
        .unwrap();
    lifecycle
        .transition(FullProfileRunnerEvent::JobStarted)
        .unwrap();
    lifecycle
        .transition(FullProfileRunnerEvent::JobVerified)
        .unwrap();
    lifecycle
        .transition(FullProfileRunnerEvent::InventoryBuilt)
        .unwrap();
    lifecycle
        .transition(FullProfileRunnerEvent::Published)
        .unwrap();
    assert_eq!(lifecycle.state(), FullProfileRunnerState::Published);
}

fn outcomes() -> Vec<RunnerJobOutcome> {
    FULL_PROFILE_JOBS
        .iter()
        .map(|job| RunnerJobOutcome {
            job_id: job.job_id.to_string(),
            build_identity: BUILD.to_string(),
            report_sha256: DIGEST.to_string(),
            script_passed: true,
        })
        .collect()
}

fn temporary_root(name: &str) -> std::path::PathBuf {
    let root =
        std::env::temp_dir().join(format!("edge-memory-harness-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    root
}

#[cfg(unix)]
fn set_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

#[cfg(not(unix))]
fn set_executable(_: &Path) {}
