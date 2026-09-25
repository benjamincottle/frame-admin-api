//! `admin_api --healthcheck`: probe a running instance and exit 0/1. Meant for
//! a container HEALTHCHECK; needs only BIND_ADDR from the environment.
//!
//! The probe is an unauthenticated OPTIONS request, answered with a 204 by the
//! worker threads (`serve_options`). That exercises the accept thread, a worker
//! and the response path, but deliberately not the database or Google.

use std::{
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpStream},
    process::exit,
    time::Duration,
};
use tiny_http::Request;

pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:5000";
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_USER_AGENT: &str = "admin_api-probe";

pub fn run() -> ! {
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string());
    let Ok(addr) = bind_addr.parse::<SocketAddr>() else {
        eprintln!("healthcheck: BIND_ADDR {bind_addr:?} is not an ip:port address");
        exit(1);
    };
    match probe(probe_target(addr)) {
        Ok(()) => exit(0),
        Err(e) => {
            eprintln!("healthcheck failed: {e}");
            exit(1);
        }
    }
}

/// The healthcheck's own requests are not worth an access-log line.
pub fn is_self_probe(request: &Request) -> bool {
    request.method().as_str() == "OPTIONS"
        && request
            .headers()
            .iter()
            .any(|h| h.field.equiv("User-Agent") && h.value.as_str() == PROBE_USER_AGENT)
        && request.remote_addr().is_some_and(|a| a.ip().is_loopback())
}

/// Where to connect to reach a listener bound at `addr`: an unspecified bind
/// address (0.0.0.0 or ::) is reached through loopback.
fn probe_target(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V4([127, 0, 0, 1].into()), addr.port())
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V6([0, 0, 0, 0, 0, 0, 0, 1].into()), addr.port())
        }
        _ => addr,
    }
}

/// Send an OPTIONS request to the listener and expect a 204.
fn probe(addr: SocketAddr) -> Result<(), String> {
    let mut stream = TcpStream::connect_timeout(&addr, PROBE_TIMEOUT)
        .map_err(|e| format!("connect to {addr}: {e}"))?;
    let _ = stream.set_read_timeout(Some(PROBE_TIMEOUT));
    let _ = stream.set_write_timeout(Some(PROBE_TIMEOUT));
    stream
        .write_all(
            format!(
                "OPTIONS /frame_admin HTTP/1.1\r\nHost: localhost\r\nUser-Agent: {PROBE_USER_AGENT}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .map_err(|e| format!("write to {addr}: {e}"))?;
    let mut buf = [0u8; 64];
    let mut filled = 0;
    while filled < buf.len() && !buf[..filled].contains(&b'\n') {
        match stream.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) => return Err(format!("read from {addr}: {e}")),
        }
    }
    let status_line = String::from_utf8_lossy(&buf[..filled]);
    let status_line = status_line.lines().next().unwrap_or("");
    if status_line.starts_with("HTTP/1.1 204") || status_line.starts_with("HTTP/1.0 204") {
        Ok(())
    } else {
        let shown: String = status_line
            .chars()
            .take(64)
            .map(|c| {
                if c.is_ascii_graphic() || c == ' ' {
                    c
                } else {
                    '?'
                }
            })
            .collect();
        Err(format!("unexpected status line: {shown}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unspecified_bind_is_probed_on_loopback() {
        let v4: SocketAddr = "0.0.0.0:5000".parse().unwrap();
        assert_eq!(probe_target(v4), "127.0.0.1:5000".parse().unwrap());
        let v6: SocketAddr = "[::]:5000".parse().unwrap();
        assert_eq!(probe_target(v6), "[::1]:5000".parse().unwrap());
        let pinned: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(probe_target(pinned), pinned);
    }

    #[test]
    fn probe_accepts_serve_options_and_rejects_anything_else() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let addr = server.server_addr().to_ip().unwrap();
        let worker = std::thread::spawn(move || {
            let request = server.recv().unwrap();
            assert!(is_self_probe(&request));
            crate::route_handler::serve_options(request);
            let request = server.recv().unwrap();
            crate::route_handler::serve_error(request, tiny_http::StatusCode(405), "no");
        });
        assert_eq!(probe(addr), Ok(()));
        assert!(probe(addr).unwrap_err().contains("405"));
        worker.join().unwrap();
    }
}
