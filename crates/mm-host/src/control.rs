//! Client for the worker control channel (the parent/CLI/agent → jailed-worker side).
//!
//! One request line, one response line over the worker's `control.sock` (see
//! [`control_proto`](crate::control_proto)). Shared by the single-host `mm snapshot`
//! CLI and the cluster agent so both speak the protocol identically.
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use crate::control_proto::{ControlRequest, ControlResponse};

/// Connect to a worker control UDS at `path`, send `req`, and return the parsed
/// response. `read_timeout` bounds the wait for the reply (a live branch copies all of
/// guest RAM before replying, so callers pass a generous value).
pub fn request(
    path: &Path,
    req: &ControlRequest,
    read_timeout: Duration,
) -> io::Result<ControlResponse> {
    let mut conn = UnixStream::connect(path)?;
    conn.set_read_timeout(Some(read_timeout))?;
    conn.write_all(req.encode().as_bytes())?;
    conn.flush()?;
    let mut line = String::new();
    BufReader::new(&conn).read_line(&mut line)?;
    ControlResponse::parse(line.trim_end())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
