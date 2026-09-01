//! Pure connection lifecycle transition, readiness, and timeout policy.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Accepted,
    ReadingClientRequest,
    SelectingRoute,
    ConnectingUpstream,
    HandshakingUpstreamTls,
    WritingUpstreamRequest,
    ReadingUpstreamResponse,
    WritingClientResponse,
    TunnelingWebSocket,
    Draining,
    Closed,
    Failed,
}

impl ConnectionState {
    pub fn can_transition_to(&self, next: &Self) -> bool {
        use ConnectionState::*;
        matches!(
            (self, next),
            (Accepted, ReadingClientRequest)
                | (Accepted, WritingClientResponse)
                | (ReadingClientRequest, SelectingRoute)
                | (ReadingClientRequest, WritingClientResponse)
                | (SelectingRoute, ConnectingUpstream)
                | (SelectingRoute, WritingClientResponse)
                | (ConnectingUpstream, WritingUpstreamRequest)
                | (ConnectingUpstream, HandshakingUpstreamTls)
                | (HandshakingUpstreamTls, WritingUpstreamRequest)
                | (HandshakingUpstreamTls, WritingClientResponse)
                | (ConnectingUpstream, WritingClientResponse)
                | (WritingUpstreamRequest, ReadingUpstreamResponse)
                | (WritingUpstreamRequest, WritingClientResponse)
                | (ReadingUpstreamResponse, WritingClientResponse)
                | (ReadingUpstreamResponse, TunnelingWebSocket)
                | (WritingClientResponse, ReadingClientRequest)
                | (WritingClientResponse, Draining)
                | (TunnelingWebSocket, Draining)
                | (_, Closed)
                | (_, Failed)
        )
    }

    pub fn io_interest(&self) -> ConnectionInterest {
        match self {
            Self::Accepted | Self::ReadingClientRequest => ConnectionInterest {
                client_readable: true,
                ..ConnectionInterest::default()
            },
            Self::SelectingRoute | Self::Draining | Self::Closed | Self::Failed => {
                ConnectionInterest::default()
            }
            Self::ConnectingUpstream | Self::WritingUpstreamRequest => ConnectionInterest {
                upstream_writable: true,
                ..ConnectionInterest::default()
            },
            Self::HandshakingUpstreamTls => ConnectionInterest {
                upstream_readable: true,
                upstream_writable: true,
                ..ConnectionInterest::default()
            },
            Self::ReadingUpstreamResponse => ConnectionInterest {
                upstream_readable: true,
                ..ConnectionInterest::default()
            },
            Self::WritingClientResponse => ConnectionInterest {
                client_writable: true,
                ..ConnectionInterest::default()
            },
            Self::TunnelingWebSocket => ConnectionInterest {
                client_readable: true,
                upstream_readable: true,
                ..ConnectionInterest::default()
            },
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConnectionInterest {
    pub client_readable: bool,
    pub client_writable: bool,
    pub upstream_readable: bool,
    pub upstream_writable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteSelectionTarget {
    Proxy,
    ImmediateResponse,
    WebSocketTunnel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionEvent {
    ClientReadable,
    ClientWritable,
    ClientResponseCompleted,
    UpstreamConnectReady,
    UpstreamTlsHandshakeStarted,
    UpstreamTlsEstablished,
    UpstreamReadable,
    UpstreamWritable,
    RequestParsed,
    RouteSelected(RouteSelectionTarget),
    TimeoutExpired,
    ClientClosed,
    UpstreamClosed,
    CommandShutdown,
    IoError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionTimeoutKind {
    ClientIdle,
    UpstreamConnect,
    UpstreamTlsHandshake,
    UpstreamRead,
    ClientWrite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionTimeoutDecision {
    pub kind: ConnectionTimeoutKind,
    pub status_code: Option<u16>,
    pub reason: &'static str,
    pub next_state: ConnectionState,
}

pub fn timeout_decision_for_state(state: &ConnectionState) -> Option<ConnectionTimeoutDecision> {
    match state {
        ConnectionState::Accepted | ConnectionState::ReadingClientRequest => {
            Some(ConnectionTimeoutDecision {
                kind: ConnectionTimeoutKind::ClientIdle,
                status_code: Some(408),
                reason: "Request Timeout",
                next_state: ConnectionState::WritingClientResponse,
            })
        }
        ConnectionState::ConnectingUpstream => Some(ConnectionTimeoutDecision {
            kind: ConnectionTimeoutKind::UpstreamConnect,
            status_code: Some(504),
            reason: "Gateway Timeout",
            next_state: ConnectionState::WritingClientResponse,
        }),
        ConnectionState::HandshakingUpstreamTls => Some(ConnectionTimeoutDecision {
            kind: ConnectionTimeoutKind::UpstreamTlsHandshake,
            status_code: Some(504),
            reason: "Gateway Timeout",
            next_state: ConnectionState::WritingClientResponse,
        }),
        ConnectionState::WritingUpstreamRequest | ConnectionState::ReadingUpstreamResponse => {
            Some(ConnectionTimeoutDecision {
                kind: ConnectionTimeoutKind::UpstreamRead,
                status_code: Some(504),
                reason: "Gateway Timeout",
                next_state: ConnectionState::WritingClientResponse,
            })
        }
        ConnectionState::WritingClientResponse => Some(ConnectionTimeoutDecision {
            kind: ConnectionTimeoutKind::ClientWrite,
            status_code: None,
            reason: "Client Write Timeout",
            next_state: ConnectionState::Failed,
        }),
        _ => None,
    }
}
