//! Per-connection transition wrapper and buffered HTTP I/O state.

use edge_domain::{AppError, ErrorCode};

use crate::upstream_attempt::invalid_upstream_attempt_transition;
use crate::{
    parse_http_request, timeout_decision_for_state, ClientRequestBuffer, ConnectionEvent,
    ConnectionState, ConnectionTimeoutDecision, ConnectionToken, HttpLimits, RequestReadOutcome,
    RouteSelectionTarget, UpstreamAttemptFailure, UpstreamAttemptProgress, WriteBuffer,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    pub token: ConnectionToken,
    pub state: ConnectionState,
}

impl Connection {
    pub fn transition_to(&mut self, next: ConnectionState) -> Result<(), AppError> {
        if !self.state.can_transition_to(&next) {
            return Err(AppError::new(
                ErrorCode::RuntimeCommandRejected,
                "invalid connection state transition",
            ));
        }
        self.state = next;
        Ok(())
    }

    pub fn handle_event(&mut self, event: ConnectionEvent) -> Result<(), AppError> {
        use ConnectionEvent::*;
        use ConnectionState::*;
        use RouteSelectionTarget::*;

        if event == TimeoutExpired {
            return self.handle_timeout().map(|_| ()).ok_or_else(|| {
                AppError::new(
                    ErrorCode::RuntimeCommandRejected,
                    "no timeout policy for current connection state",
                )
            });
        }

        let next = match (&self.state, event) {
            (_, IoError) => Failed,
            (_, ClientClosed | CommandShutdown) => Closed,
            (Accepted, ClientReadable) => ReadingClientRequest,
            (ReadingClientRequest, RequestParsed) => SelectingRoute,
            (SelectingRoute, RouteSelected(Proxy)) => ConnectingUpstream,
            (SelectingRoute, RouteSelected(ImmediateResponse)) => WritingClientResponse,
            (ConnectingUpstream, UpstreamConnectReady) => WritingUpstreamRequest,
            (ConnectingUpstream, UpstreamTlsHandshakeStarted) => HandshakingUpstreamTls,
            (HandshakingUpstreamTls, UpstreamTlsEstablished) => WritingUpstreamRequest,
            (WritingUpstreamRequest, UpstreamWritable) => ReadingUpstreamResponse,
            (ReadingUpstreamResponse, UpstreamReadable) => WritingClientResponse,
            (ReadingUpstreamResponse, RouteSelected(WebSocketTunnel)) => TunnelingWebSocket,
            (WritingClientResponse, ClientWritable) => Draining,
            (Draining, UpstreamClosed) => Closed,
            _ => {
                return Err(AppError::new(
                    ErrorCode::RuntimeCommandRejected,
                    "event is not valid for current connection state",
                ));
            }
        };

        self.transition_to(next)
    }

    pub fn handle_timeout(&mut self) -> Option<ConnectionTimeoutDecision> {
        let decision = timeout_decision_for_state(&self.state)?;
        self.state = decision.next_state.clone();
        Some(decision)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpConnectionIo {
    pub connection: Connection,
    upstream_attempt: UpstreamAttemptProgress,
    client_request: ClientRequestBuffer,
    upstream_write: WriteBuffer,
    client_write: WriteBuffer,
}

impl HttpConnectionIo {
    pub fn new(token: ConnectionToken) -> Self {
        Self {
            connection: Connection {
                token,
                state: ConnectionState::Accepted,
            },
            upstream_attempt: UpstreamAttemptProgress::default(),
            client_request: ClientRequestBuffer::default(),
            upstream_write: WriteBuffer::default(),
            client_write: WriteBuffer::default(),
        }
    }

    pub fn receive_client_bytes(
        &mut self,
        chunk: &[u8],
        limits: &HttpLimits,
    ) -> Result<RequestReadOutcome, AppError> {
        if self.connection.state == ConnectionState::Accepted {
            self.connection
                .handle_event(ConnectionEvent::ClientReadable)?;
        }
        if self.connection.state != ConnectionState::ReadingClientRequest {
            return Err(invalid_connection_io_state());
        }

        let outcome = self.client_request.push(chunk, limits)?;
        if let RequestReadOutcome::Complete(bytes) = &outcome {
            parse_http_request(bytes, limits)?;
            self.connection
                .handle_event(ConnectionEvent::RequestParsed)?;
        }
        Ok(outcome)
    }

    pub fn begin_upstream_connect(&mut self) -> Result<(), AppError> {
        self.connection
            .handle_event(ConnectionEvent::RouteSelected(RouteSelectionTarget::Proxy))?;
        self.upstream_attempt.begin()
    }

    pub fn upstream_connected(&mut self, upstream_request: Vec<u8>) -> Result<(), AppError> {
        let event = match self.connection.state {
            ConnectionState::ConnectingUpstream => ConnectionEvent::UpstreamConnectReady,
            ConnectionState::HandshakingUpstreamTls => ConnectionEvent::UpstreamTlsEstablished,
            _ => return Err(invalid_connection_io_state()),
        };
        self.upstream_write = WriteBuffer::new(upstream_request);
        self.connection.handle_event(event)
    }

    pub fn advance_upstream_write(&mut self, byte_count: usize) -> Result<usize, AppError> {
        if self.connection.state != ConnectionState::WritingUpstreamRequest {
            return Err(invalid_connection_io_state());
        }
        let advanced = self.upstream_write.advance(byte_count);
        self.upstream_attempt
            .record_request_write(advanced as u64)?;
        if self.upstream_write.is_complete() {
            self.upstream_attempt.request_write_completed()?;
            self.connection
                .handle_event(ConnectionEvent::UpstreamWritable)?;
            self.upstream_write.clear_if_complete();
        }
        Ok(advanced)
    }

    pub fn receive_upstream_bytes(&mut self, chunk: &[u8]) -> Result<usize, AppError> {
        if self.connection.state != ConnectionState::ReadingUpstreamResponse {
            return Err(invalid_connection_io_state());
        }
        self.client_write.try_append(chunk)?;
        self.upstream_attempt.record_response_bytes(chunk.len())?;
        Ok(chunk.len())
    }

    pub fn finish_upstream_response(&mut self) -> Result<(), AppError> {
        self.connection
            .handle_event(ConnectionEvent::UpstreamReadable)?;
        self.upstream_attempt.succeed()
    }

    pub fn fail_upstream_attempt(
        &mut self,
        failure: UpstreamAttemptFailure,
    ) -> Result<(), AppError> {
        self.upstream_attempt.fail(failure)
    }

    pub fn upstream_attempt(&self) -> &UpstreamAttemptProgress {
        &self.upstream_attempt
    }

    pub fn prepare_upstream_retry(&mut self) -> Result<(), AppError> {
        if !matches!(
            self.connection.state,
            ConnectionState::ConnectingUpstream | ConnectionState::WritingUpstreamRequest
        ) || self.upstream_attempt.terminal().is_none()
        {
            return Err(invalid_upstream_attempt_transition());
        }
        self.connection.state = ConnectionState::SelectingRoute;
        self.upstream_attempt = UpstreamAttemptProgress::default();
        self.upstream_write = WriteBuffer::default();
        Ok(())
    }

    pub fn queue_client_response(&mut self, response: Vec<u8>) -> Result<(), AppError> {
        if !self
            .connection
            .state
            .can_transition_to(&ConnectionState::WritingClientResponse)
        {
            return Err(invalid_connection_io_state());
        }
        self.client_write = WriteBuffer::new(response);
        self.connection
            .transition_to(ConnectionState::WritingClientResponse)
    }

    pub fn advance_client_write(&mut self, byte_count: usize) -> Result<usize, AppError> {
        if !matches!(
            self.connection.state,
            ConnectionState::ReadingUpstreamResponse | ConnectionState::WritingClientResponse
        ) {
            return Err(invalid_connection_io_state());
        }
        let advanced = self.client_write.advance(byte_count);
        if self.connection.state == ConnectionState::WritingClientResponse
            && self.client_write.is_complete()
        {
            self.connection
                .handle_event(ConnectionEvent::ClientWritable)?;
        }
        if self.client_write.is_complete() {
            self.client_write.clear_if_complete();
        }
        Ok(advanced)
    }

    pub fn upstream_write_buffer(&self) -> &WriteBuffer {
        &self.upstream_write
    }

    pub fn client_write_buffer(&self) -> &WriteBuffer {
        &self.client_write
    }
}

fn invalid_connection_io_state() -> AppError {
    AppError::new(
        ErrorCode::RuntimeCommandRejected,
        "operation is not valid for current connection state",
    )
}
