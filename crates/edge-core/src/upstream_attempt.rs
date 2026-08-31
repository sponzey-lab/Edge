//! Pure state tracking for one upstream request attempt.

use edge_domain::{AppError, ErrorCode};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum UpstreamAttemptPhase {
    #[default]
    NotStarted,
    Writing,
    AwaitingResponse,
    ResponseStarted,
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamAttemptFailure {
    Connect,
    ConnectTimeout,
    TlsHandshake,
    TlsHandshakeTimeout,
    Write,
    Read,
    ReadTimeout,
    ResetBeforeResponse,
    ResetAfterResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpstreamResponseFailureDisposition {
    QueueSyntheticResponse,
    FailClose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamAttemptTerminal {
    Succeeded,
    Failed(UpstreamAttemptFailure),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UpstreamAttemptProgress {
    phase: UpstreamAttemptPhase,
    request_bytes_written: u64,
    response_started: bool,
    terminal: Option<UpstreamAttemptTerminal>,
}

impl UpstreamAttemptProgress {
    pub fn begin(&mut self) -> Result<(), AppError> {
        self.require_phase(UpstreamAttemptPhase::NotStarted)?;
        self.phase = UpstreamAttemptPhase::Writing;
        Ok(())
    }

    pub fn record_request_write(&mut self, byte_count: u64) -> Result<(), AppError> {
        self.require_phase(UpstreamAttemptPhase::Writing)?;
        self.request_bytes_written = self.request_bytes_written.saturating_add(byte_count);
        Ok(())
    }

    pub fn request_write_completed(&mut self) -> Result<(), AppError> {
        self.require_phase(UpstreamAttemptPhase::Writing)?;
        self.phase = UpstreamAttemptPhase::AwaitingResponse;
        Ok(())
    }

    pub fn record_response_bytes(&mut self, byte_count: usize) -> Result<(), AppError> {
        if !matches!(
            self.phase,
            UpstreamAttemptPhase::AwaitingResponse | UpstreamAttemptPhase::ResponseStarted
        ) {
            return Err(invalid_upstream_attempt_transition());
        }
        if byte_count > 0 {
            self.response_started = true;
            self.phase = UpstreamAttemptPhase::ResponseStarted;
        }
        Ok(())
    }

    pub fn succeed(&mut self) -> Result<(), AppError> {
        if !matches!(
            self.phase,
            UpstreamAttemptPhase::AwaitingResponse | UpstreamAttemptPhase::ResponseStarted
        ) {
            return Err(invalid_upstream_attempt_transition());
        }
        self.complete(UpstreamAttemptTerminal::Succeeded)
    }

    pub fn fail(&mut self, failure: UpstreamAttemptFailure) -> Result<(), AppError> {
        if self.phase == UpstreamAttemptPhase::Terminal {
            return Err(invalid_upstream_attempt_transition());
        }
        self.complete(UpstreamAttemptTerminal::Failed(failure))
    }

    pub fn phase(&self) -> UpstreamAttemptPhase {
        self.phase
    }

    pub fn request_bytes_written(&self) -> u64 {
        self.request_bytes_written
    }

    pub fn response_started(&self) -> bool {
        self.response_started
    }

    pub fn terminal(&self) -> Option<UpstreamAttemptTerminal> {
        self.terminal
    }

    fn require_phase(&self, expected: UpstreamAttemptPhase) -> Result<(), AppError> {
        if self.phase != expected {
            return Err(invalid_upstream_attempt_transition());
        }
        Ok(())
    }

    fn complete(&mut self, terminal: UpstreamAttemptTerminal) -> Result<(), AppError> {
        if self.terminal.is_some() {
            return Err(invalid_upstream_attempt_transition());
        }
        self.terminal = Some(terminal);
        self.phase = UpstreamAttemptPhase::Terminal;
        Ok(())
    }
}

pub(crate) fn invalid_upstream_attempt_transition() -> AppError {
    AppError::new(
        ErrorCode::RuntimeCommandRejected,
        "invalid upstream attempt transition",
    )
}

pub(crate) fn upstream_failure_response_spec(
    failure: UpstreamAttemptFailure,
) -> (u16, &'static str) {
    match failure {
        UpstreamAttemptFailure::Connect
        | UpstreamAttemptFailure::TlsHandshake
        | UpstreamAttemptFailure::Write
        | UpstreamAttemptFailure::Read
        | UpstreamAttemptFailure::ResetBeforeResponse
        | UpstreamAttemptFailure::ResetAfterResponse => (502, "Bad Gateway"),
        UpstreamAttemptFailure::ConnectTimeout
        | UpstreamAttemptFailure::TlsHandshakeTimeout
        | UpstreamAttemptFailure::ReadTimeout => (504, "Gateway Timeout"),
    }
}

pub(crate) fn upstream_response_failure_disposition(
    response_started: bool,
) -> UpstreamResponseFailureDisposition {
    if response_started {
        UpstreamResponseFailureDisposition::FailClose
    } else {
        UpstreamResponseFailureDisposition::QueueSyntheticResponse
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_failure_disposition_never_appends_a_synthetic_response_after_start() {
        assert_eq!(
            upstream_response_failure_disposition(false),
            UpstreamResponseFailureDisposition::QueueSyntheticResponse
        );
        assert_eq!(
            upstream_response_failure_disposition(true),
            UpstreamResponseFailureDisposition::FailClose
        );
    }
}
