//! Pure overload admission and upstream response-read interest policy.

use crate::ConnectionState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourcePressureState {
    Normal,
    Pressured,
    Exhausted,
    FailedClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionAdmissionDecision {
    Accepted,
    RejectedConnectionLimit,
    RejectedPayloadPressure,
    RejectedFailedClosed,
}

pub fn connection_admission_decision(
    pressure_state: ResourcePressureState,
    active_connections: usize,
    max_connections: usize,
) -> ConnectionAdmissionDecision {
    match pressure_state {
        ResourcePressureState::FailedClosed => ConnectionAdmissionDecision::RejectedFailedClosed,
        ResourcePressureState::Pressured | ResourcePressureState::Exhausted => {
            ConnectionAdmissionDecision::RejectedPayloadPressure
        }
        ResourcePressureState::Normal if active_connections >= max_connections => {
            ConnectionAdmissionDecision::RejectedConnectionLimit
        }
        ResourcePressureState::Normal => ConnectionAdmissionDecision::Accepted,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseReadInterestAction {
    Keep,
    Pause,
    Resume,
}

pub fn response_read_interest_action(
    pressure_state: ResourcePressureState,
    connection_state: &ConnectionState,
    upstream_registered: bool,
    buffered_client_output_bytes: usize,
    max_response_buffer_bytes: usize,
) -> ResponseReadInterestAction {
    if connection_state != &ConnectionState::ReadingUpstreamResponse {
        return ResponseReadInterestAction::Keep;
    }

    let read_must_pause = pressure_state != ResourcePressureState::Normal
        || buffered_client_output_bytes >= max_response_buffer_bytes;
    match (upstream_registered, read_must_pause) {
        (true, true) => ResponseReadInterestAction::Pause,
        (false, false) => ResponseReadInterestAction::Resume,
        (true, false) | (false, true) => ResponseReadInterestAction::Keep,
    }
}
