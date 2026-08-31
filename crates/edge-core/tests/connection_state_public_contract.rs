use edge_core::{
    timeout_decision_for_state, ConnectionInterest, ConnectionState, ConnectionTimeoutKind,
};

#[test]
fn connection_state_policy_remains_available_from_the_crate_root() {
    assert!(ConnectionState::Accepted.can_transition_to(&ConnectionState::ReadingClientRequest));
    assert_eq!(
        ConnectionState::SelectingRoute.io_interest(),
        ConnectionInterest::default()
    );
    assert_eq!(
        timeout_decision_for_state(&ConnectionState::ConnectingUpstream)
            .unwrap()
            .kind,
        ConnectionTimeoutKind::UpstreamConnect
    );
}
