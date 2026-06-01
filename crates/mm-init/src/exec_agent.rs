//! In-guest exec agent for Sandbox Mode (SPEC-1 FR-13).
//!
//! When the guest boots in Sandbox mode, `mm-init` runs this agent: it listens on a
//! vsock port, and for each [`Frame::Exec`] it receives, spawns the command, streams
//! its stdout/stderr back as [`Frame::Output`] frames, enforces the request timeout,
//! and finishes with a single [`Frame::Exit`]. The host side (`mm ssh`-style exec,
//! routed via the agent) speaks the same length-prefixed protocol.
//!
//! The command-building + exit-code conventions are pure and cross-platform (so they
//! are unit-tested anywhere); the vsock listener is Linux-only.
use std::process::{Command, Stdio};

/// The vsock port the guest exec agent listens on (the host connects to it).
pub const EXEC_VSOCK_PORT: u32 = 1025;

/// Exit code reported when a command is killed for exceeding its timeout (matches
/// coreutils `timeout`).
pub const TIMEOUT_EXIT_CODE: i32 = 124;

/// Exit code reported when the command could not be started (empty argv or spawn
/// failure), matching the shell "command not found / not executable" convention.
pub const SPAWN_FAILED_EXIT_CODE: i32 = 127;

/// Build the process to run from an exec request's argv. Returns `None` for an empty
/// argv. stdout/stderr are piped (so the agent can stream them) and stdin is null.
pub fn build_command(cmd: &[String]) -> Option<Command> {
    let (program, args) = cmd.split_first()?;
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    Some(command)
}

#[cfg(target_os = "linux")]
pub use linux::serve;

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::unix::io::{FromRawFd, RawFd};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use mm_sandbox::exec::{decode, encode, Frame, Stream};

    use super::{build_command, SPAWN_FAILED_EXIT_CODE, TIMEOUT_EXIT_CODE};

    /// Listen on `port` (vsock) and serve exec requests, one connection per client.
    /// Diverges: runs for the lifetime of the sandbox. Best-effort: a failure to set
    /// up the listener logs and returns (the sandbox still runs, just without exec).
    pub fn serve(port: u32) {
        // SAFETY: each libc call is checked; the listen fd is owned for the loop.
        let listen_fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
        if listen_fd < 0 {
            eprintln!("mm-init: exec agent: vsock socket failed");
            return;
        }
        // SAFETY: sockaddr_vm is a C POD; zeroing is a valid initial state.
        let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        addr.svm_cid = libc::VMADDR_CID_ANY;
        addr.svm_port = port;
        let bind = unsafe {
            libc::bind(
                listen_fd,
                (&addr as *const libc::sockaddr_vm).cast(),
                std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        };
        if bind < 0 || unsafe { libc::listen(listen_fd, 8) } < 0 {
            eprintln!("mm-init: exec agent: vsock bind/listen failed");
            unsafe { libc::close(listen_fd) };
            return;
        }
        eprintln!("mm-init: exec agent listening on vsock port {port}");

        loop {
            let conn =
                unsafe { libc::accept(listen_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
            if conn < 0 {
                continue;
            }
            // One thread per connection so concurrent execs don't block each other.
            std::thread::spawn(move || handle_connection(conn));
        }
    }

    /// Read framed exec requests from one connection until it closes.
    fn handle_connection(fd: RawFd) {
        // SAFETY: `fd` is a freshly-accepted socket fd we take exclusive ownership of.
        let mut stream = unsafe { File::from_raw_fd(fd) };
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            // Process every complete frame currently buffered.
            while let Some((frame, consumed)) = decode(&buf) {
                buf.drain(..consumed);
                if let Frame::Exec {
                    id,
                    cmd,
                    timeout_ms,
                } = frame
                {
                    handle_exec(&mut stream, id, &cmd, timeout_ms);
                }
            }
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break, // peer closed or error
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    }

    /// Run one command, streaming its output and a final exit frame to `stream`.
    fn handle_exec(stream: &mut File, id: u64, cmd: &[String], timeout_ms: u64) {
        let Some(mut command) = build_command(cmd) else {
            send(
                stream,
                &Frame::Exit {
                    id,
                    code: SPAWN_FAILED_EXIT_CODE,
                },
            );
            return;
        };
        let mut child = match command.spawn() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("mm-init: exec agent: spawn failed: {e}");
                send(
                    stream,
                    &Frame::Exit {
                        id,
                        code: SPAWN_FAILED_EXIT_CODE,
                    },
                );
                return;
            }
        };

        // Shared writer so the stdout + stderr streamers can interleave Output frames.
        let writer = match stream.try_clone() {
            Ok(w) => Arc::new(Mutex::new(w)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return;
            }
        };
        let out = stream_reader(writer.clone(), id, Stream::Stdout, child.stdout.take());
        let err = stream_reader(writer.clone(), id, Stream::Stderr, child.stderr.take());

        // Poll for completion, killing the child if it exceeds its timeout.
        let deadline = Instant::now() + Duration::from_millis(timeout_ms.max(1));
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break Some(s),
                Ok(None) => {}
                Err(_) => break None,
            }
            if timeout_ms > 0 && Instant::now() >= deadline {
                let _ = child.kill();
                timed_out = true;
                break child.wait().ok();
            }
            std::thread::sleep(Duration::from_millis(5));
        };

        let _ = out.join();
        let _ = err.join();

        let code = if timed_out {
            TIMEOUT_EXIT_CODE
        } else {
            status.and_then(|s| s.code()).unwrap_or(-1)
        };
        let mut w = writer.lock().expect("writer mutex");
        let _ = w.write_all(&encode(&Frame::Exit { id, code }));
        let _ = w.flush();
    }

    /// Spawn a thread that reads `source` to EOF, forwarding each chunk as an
    /// `Output` frame on `writer`. Returns the join handle.
    fn stream_reader<R: Read + Send + 'static>(
        writer: Arc<Mutex<File>>,
        id: u64,
        stream: Stream,
        source: Option<R>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let Some(mut src) = source else { return };
            let mut buf = [0u8; 8192];
            loop {
                match src.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let frame = Frame::Output {
                            id,
                            stream,
                            data: buf[..n].to_vec(),
                        };
                        let bytes = encode(&frame);
                        match writer.lock() {
                            Ok(mut w) => {
                                if w.write_all(&bytes).is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        })
    }

    fn send(stream: &mut File, frame: &Frame) {
        let _ = stream.write_all(&encode(frame));
        let _ = stream.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_argv_has_no_command() {
        assert!(build_command(&[]).is_none());
    }

    #[test]
    fn builds_program_and_args() {
        let cmd = build_command(&["echo".to_string(), "hi".to_string(), "there".to_string()])
            .expect("command");
        assert_eq!(cmd.get_program(), "echo");
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args, vec!["hi", "there"]);
    }

    #[test]
    fn exit_code_conventions() {
        assert_eq!(TIMEOUT_EXIT_CODE, 124);
        assert_eq!(SPAWN_FAILED_EXIT_CODE, 127);
    }
}
