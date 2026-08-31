use edge_core::{
    connection_admission_decision, response_read_interest_action, ConnectionAdmissionDecision,
    ConnectionState, ResourcePressureState, ResponseReadInterestAction,
};

#[test]
fn resource_admission_policy_contract_remains_available_from_the_crate_root() {
    assert_eq!(
        connection_admission_decision(ResourcePressureState::FailedClosed, 0, 1),
        ConnectionAdmissionDecision::RejectedFailedClosed
    );
    assert_eq!(
        response_read_interest_action(
            ResourcePressureState::Normal,
            &ConnectionState::ReadingUpstreamResponse,
            false,
            0,
            1,
        ),
        ResponseReadInterestAction::Resume
    );
}
