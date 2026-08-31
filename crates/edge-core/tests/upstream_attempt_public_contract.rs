use edge_core::{
    UpstreamAttemptFailure, UpstreamAttemptPhase, UpstreamAttemptProgress, UpstreamAttemptTerminal,
};

#[test]
fn upstream_attempt_contract_remains_available_from_the_crate_root() {
    let mut attempt = UpstreamAttemptProgress::default();
    attempt.begin().unwrap();
    attempt.record_request_write(3).unwrap();
    attempt.request_write_completed().unwrap();
    attempt.fail(UpstreamAttemptFailure::Connect).unwrap();

    assert_eq!(attempt.phase(), UpstreamAttemptPhase::Terminal);
    assert_eq!(
        attempt.terminal(),
        Some(UpstreamAttemptTerminal::Failed(
            UpstreamAttemptFailure::Connect
        ))
    );
}
