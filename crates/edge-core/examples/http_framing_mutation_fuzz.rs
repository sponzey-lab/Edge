//! Manual-only bounded mutation runner for HTTP framing and connection states.
//!
//! This test tool has no production runtime path, network activity, corpus
//! persistence, or release-evidence role.

use std::env;
use std::process::ExitCode;

use edge_core::{
    parse_http_request, Connection, ConnectionEvent, ConnectionState, ConnectionToken, HttpLimits,
    HttpResponseFraming, ResponseFramingPhase, RouteSelectionTarget,
};

const DEFAULT_CASES: u32 = 100_000;
const MAX_CASES: u32 = 1_000_000;
const REQUEST: &[u8] =
    b"POST /items/a?mode=fast HTTP/1.1\r\nHost: example.test\r\nContent-Length: 3\r\n\r\nabc";
const RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Trace: done\r\n\r\n";

fn main() -> ExitCode {
    match run() {
        Ok(case_count) => {
            println!("http_framing_mutation_fuzz completed {case_count} deterministic cases");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("http_framing_mutation_fuzz: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<u32, String> {
    let case_count = parse_case_count(env::args().skip(1))?;
    for seed in 0..case_count {
        let request = mutate(REQUEST, seed.wrapping_add(0x243f_6a88));
        let _ = parse_http_request(&request, &HttpLimits::default());

        let response = mutate(RESPONSE, seed.wrapping_add(0x85a3_08d3));
        let mut framing = HttpResponseFraming::new(8 * 1024, 1024);
        push_fragmented_response(&mut framing, &response, seed);
        let _ = framing.finish_on_eof();
        if !matches!(
            framing.phase(),
            ResponseFramingPhase::Complete | ResponseFramingPhase::Failed
        ) {
            return Err(format!(
                "response framer was non-terminal after case {seed}"
            ));
        }

        fuzz_connection_state_machine(seed)?;
    }
    Ok(case_count)
}

fn fuzz_connection_state_machine(seed: u32) -> Result<(), String> {
    let mut connection = Connection {
        token: ConnectionToken::new(seed as usize),
        state: ConnectionState::Accepted,
    };
    let mut state = seed.wrapping_add(0xa409_3822);

    for _ in 0..16 {
        state = next_state(state);
        let _ = connection.handle_event(connection_event(state));
    }

    connection
        .handle_event(ConnectionEvent::ClientClosed)
        .map_err(|error| format!("connection close was rejected after case {seed}: {error:?}"))?;
    if connection.state != ConnectionState::Closed {
        return Err(format!(
            "connection state machine did not close after case {seed}: {:?}",
            connection.state
        ));
    }
    Ok(())
}

fn connection_event(state: u32) -> ConnectionEvent {
    match state % 13 {
        0 => ConnectionEvent::ClientReadable,
        1 => ConnectionEvent::ClientWritable,
        2 => ConnectionEvent::UpstreamConnectReady,
        3 => ConnectionEvent::UpstreamTlsHandshakeStarted,
        4 => ConnectionEvent::UpstreamTlsEstablished,
        5 => ConnectionEvent::UpstreamReadable,
        6 => ConnectionEvent::UpstreamWritable,
        7 => ConnectionEvent::RequestParsed,
        8 => ConnectionEvent::RouteSelected(RouteSelectionTarget::Proxy),
        9 => ConnectionEvent::RouteSelected(RouteSelectionTarget::ImmediateResponse),
        10 => ConnectionEvent::RouteSelected(RouteSelectionTarget::WebSocketTunnel),
        11 => ConnectionEvent::TimeoutExpired,
        _ => ConnectionEvent::IoError,
    }
}

fn parse_case_count(mut args: impl Iterator<Item = String>) -> Result<u32, String> {
    let Some(value) = args.next() else {
        return Ok(DEFAULT_CASES);
    };
    if args.next().is_some() {
        return Err("usage: http_framing_mutation_fuzz [case-count]".to_string());
    }
    let count = value
        .parse::<u32>()
        .map_err(|_| "case count must be an unsigned integer".to_string())?;
    if !(1..=MAX_CASES).contains(&count) {
        return Err(format!(
            "case count must be between 1 and {MAX_CASES} (inclusive)"
        ));
    }
    Ok(count)
}

fn push_fragmented_response(framing: &mut HttpResponseFraming, bytes: &[u8], seed: u32) {
    let mut state = seed.wrapping_add(0x1319_8a2e);
    let mut offset = 0;
    while offset < bytes.len()
        && !matches!(
            framing.phase(),
            ResponseFramingPhase::Complete | ResponseFramingPhase::Failed
        )
    {
        state = next_state(state);
        let length = 1 + (state as usize % 32);
        let end = (offset + length).min(bytes.len());
        let _ = framing.push(&bytes[offset..end]);
        offset = end;
    }
}

fn mutate(base: &[u8], seed: u32) -> Vec<u8> {
    let mut state = seed;
    let mut bytes = base.to_vec();
    for _ in 0..8 {
        state = next_state(state);
        let index = state as usize % bytes.len();
        bytes[index] ^= (state >> 24) as u8;
    }
    state = next_state(state);
    bytes.truncate(state as usize % (base.len() + 1));
    bytes
}

fn next_state(mut state: u32) -> u32 {
    state ^= state << 13;
    state ^= state >> 17;
    state ^ (state << 5)
}
