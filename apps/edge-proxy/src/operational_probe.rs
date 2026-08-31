//! Local operational liveness and readiness probe CLI adapter.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::Duration;

use crate::process_mode::{ProbeOptions, ProbeTarget};

pub(crate) fn run_probe(options: ProbeOptions) -> i32 {
    let address = match options.admin_bind.parse::<SocketAddr>() {
        Ok(address) if address.ip().is_loopback() => address,
        _ => return 2,
    };
    let path = match options.target {
        ProbeTarget::Live => "/api/v1/health/live",
        ProbeTarget::Ready => "/api/v1/health/ready",
    };
    let expected = match options.target {
        ProbeTarget::Live => "live",
        ProbeTarget::Ready => "ready",
    };
    let result = (|| -> std::io::Result<String> {
        let mut stream = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response)
    })();
    match result {
        Ok(response)
            if response.starts_with("HTTP/1.1 200 ")
                && response.contains(&format!("\"status\":\"{expected}\"")) =>
        {
            0
        }
        Ok(response) if response.starts_with("HTTP/1.1 503 ") => 1,
        _ => 2,
    }
}
