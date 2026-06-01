//! Host-side exec client (SPEC-1 FR-13).
//!
//! Speaks the [`crate::exec::protocol`] over a connected byte stream — in production
//! the stream is the vsock-bridged connection to the guest's exec agent. Generic over
//! the stream so it is unit-testable against a mock guest. Sends one [`Frame::Exec`],
//! collects [`Frame::Output`] chunks, and returns the [`Frame::Exit`] result.
use std::io::{Read, Write};

use super::protocol::{decode, encode, Frame, Stream};

/// The outcome of a remote command: its exit code and the captured streams.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Perform the firecracker-style hybrid vsock handshake on a freshly-connected host
/// Unix-domain stream: request a connection to guest vsock `port`, then await the
/// `OK <port>\n` acknowledgement. Reads one byte at a time so it stops exactly at the
/// newline and never consumes any following exec-protocol bytes.
pub fn vsock_connect<S: Read + Write>(stream: &mut S, port: u32) -> std::io::Result<()> {
    stream.write_all(format!("CONNECT {port}\n").as_bytes())?;
    stream.flush()?;

    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "vsock handshake: stream closed before OK",
            ));
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() > 64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "vsock handshake: response line too long",
            ));
        }
    }
    // Tolerate a trailing CR.
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    if line.starts_with(b"OK") {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!(
                "vsock handshake: guest refused (got {:?})",
                String::from_utf8_lossy(&line)
            ),
        ))
    }
}

/// Connect to the host vsock bridge at `uds_path`, handshake to guest `port`, and run
/// `cmd` there — the end-to-end host entry point used by the agent (SPEC-1 FR-13).
pub fn run_exec_over_uds(
    uds_path: &std::path::Path,
    port: u32,
    id: u64,
    cmd: &[String],
    timeout_ms: u64,
) -> std::io::Result<ExecResult> {
    let mut stream = std::os::unix::net::UnixStream::connect(uds_path)?;
    vsock_connect(&mut stream, port)?;
    run_exec(&mut stream, id, cmd, timeout_ms)
}

/// Run `cmd` over an already-connected `stream`, collecting output until the guest
/// agent sends the terminal `Exit` frame. Frames for other request ids are ignored
/// (so the channel may be shared). If the stream closes before an `Exit`, returns the
/// output collected so far with exit code -1.
pub fn run_exec<S: Read + Write>(
    stream: &mut S,
    id: u64,
    cmd: &[String],
    timeout_ms: u64,
) -> std::io::Result<ExecResult> {
    stream.write_all(&encode(&Frame::Exec {
        id,
        cmd: cmd.to_vec(),
        timeout_ms,
    }))?;
    stream.flush()?;

    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    loop {
        while let Some((frame, consumed)) = decode(&buf) {
            buf.drain(..consumed);
            match frame {
                Frame::Output {
                    id: fid,
                    stream: which,
                    data,
                } if fid == id => match which {
                    Stream::Stdout => stdout.extend_from_slice(&data),
                    Stream::Stderr => stderr.extend_from_slice(&data),
                },
                Frame::Exit { id: fid, code } if fid == id => {
                    return Ok(ExecResult {
                        exit_code: code,
                        stdout,
                        stderr,
                    });
                }
                _ => {} // a frame for another request id, or an unexpected Exec — skip
            }
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            // Peer closed before sending Exit — surface what we have.
            return Ok(ExecResult {
                exit_code: -1,
                stdout,
                stderr,
            });
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A mock guest agent: it captures what the host writes, and on read serves a
    /// canned sequence of response frames (as if the guest ran the command).
    struct MockGuest {
        responses: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl MockGuest {
        fn new(frames: &[Frame]) -> Self {
            let mut bytes = Vec::new();
            for f in frames {
                bytes.extend_from_slice(&encode(f));
            }
            Self {
                responses: Cursor::new(bytes),
                written: Vec::new(),
            }
        }
    }

    impl Write for MockGuest {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Read for MockGuest {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.responses.read(buf)
        }
    }

    #[test]
    fn collects_output_and_exit_code() {
        let mut guest = MockGuest::new(&[
            Frame::Output {
                id: 1,
                stream: Stream::Stdout,
                data: b"hello ".to_vec(),
            },
            Frame::Output {
                id: 1,
                stream: Stream::Stdout,
                data: b"world\n".to_vec(),
            },
            Frame::Output {
                id: 1,
                stream: Stream::Stderr,
                data: b"warn\n".to_vec(),
            },
            Frame::Exit { id: 1, code: 0 },
        ]);
        let result = run_exec(&mut guest, 1, &["echo".into(), "hello world".into()], 5000).unwrap();
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, b"hello world\n");
        assert_eq!(result.stderr, b"warn\n");
        // The host actually sent the Exec frame.
        let (sent, _) = decode(&guest.written).unwrap();
        assert_eq!(
            sent,
            Frame::Exec {
                id: 1,
                cmd: vec!["echo".into(), "hello world".into()],
                timeout_ms: 5000,
            }
        );
    }

    #[test]
    fn ignores_frames_for_other_ids() {
        let mut guest = MockGuest::new(&[
            Frame::Output {
                id: 99,
                stream: Stream::Stdout,
                data: b"not mine".to_vec(),
            },
            Frame::Output {
                id: 7,
                stream: Stream::Stdout,
                data: b"mine".to_vec(),
            },
            Frame::Exit { id: 7, code: 3 },
        ]);
        let result = run_exec(&mut guest, 7, &["x".into()], 1000).unwrap();
        assert_eq!(result.exit_code, 3);
        assert_eq!(result.stdout, b"mine");
    }

    #[test]
    fn handshake_accepts_ok_then_leaves_exec_stream_intact() {
        // Guest serves the handshake ack followed by exec frames on the same stream.
        let mut bytes = b"OK 1025\n".to_vec();
        for f in [
            Frame::Output {
                id: 1,
                stream: Stream::Stdout,
                data: b"hi\n".to_vec(),
            },
            Frame::Exit { id: 1, code: 0 },
        ] {
            bytes.extend_from_slice(&encode(&f));
        }
        let mut guest = MockGuest {
            responses: Cursor::new(bytes),
            written: Vec::new(),
        };
        vsock_connect(&mut guest, 1025).unwrap();
        // The CONNECT request was sent verbatim.
        assert_eq!(guest.written, b"CONNECT 1025\n");
        // Byte-at-a-time handshake stopped at the newline, so run_exec still sees
        // every exec frame.
        let r = run_exec(&mut guest, 1, &["echo".into(), "hi".into()], 1000).unwrap();
        assert_eq!(r.exit_code, 0);
        assert_eq!(r.stdout, b"hi\n");
    }

    #[test]
    fn handshake_rejects_non_ok_response() {
        let mut guest = MockGuest {
            responses: Cursor::new(b"RST\n".to_vec()),
            written: Vec::new(),
        };
        let err = vsock_connect(&mut guest, 1025).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
    }

    #[test]
    fn closed_stream_before_exit_yields_minus_one() {
        let mut guest = MockGuest::new(&[Frame::Output {
            id: 1,
            stream: Stream::Stdout,
            data: b"partial".to_vec(),
        }]);
        let result = run_exec(&mut guest, 1, &["x".into()], 1000).unwrap();
        assert_eq!(result.exit_code, -1);
        assert_eq!(result.stdout, b"partial");
    }
}
