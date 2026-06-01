//! Host<->guest exec wire protocol over vsock (SPEC-1 FR-13 / Appendix B.2).
//!
//! Length-prefixed JSON frames: a 4-byte big-endian length prefix followed by a JSON
//! body. The host sends [`Frame::Exec`] to run a command; the guest agent (the
//! `mm-init` Sandbox-mode exec agent) streams [`Frame::Output`] chunks and ends with
//! a single [`Frame::Exit`]. Both ends speak this exact framing, so a partial read
//! over the stream never mis-parses — [`decode`] returns `None` until a whole frame
//! is buffered.
use serde::{Deserialize, Serialize};

/// One message on the exec channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Frame {
    /// host -> guest: run a command, with a wall-clock timeout.
    Exec {
        id: u64,
        cmd: Vec<String>,
        timeout_ms: u64,
    },
    /// guest -> host: a chunk of output on stdout or stderr.
    Output {
        id: u64,
        stream: Stream,
        data: Vec<u8>,
    },
    /// guest -> host: the command finished with this exit code (terminal frame).
    Exit { id: u64, code: i32 },
}

/// Which output stream an [`Frame::Output`] chunk came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stream {
    Stdout,
    Stderr,
}

/// Encode a frame as a 4-byte big-endian length prefix + JSON body.
pub fn encode(frame: &Frame) -> Vec<u8> {
    let body = serde_json::to_vec(frame).expect("frame serializes");
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

/// Decode one frame from the front of `buf`; returns `(frame, bytes_consumed)`, or
/// `None` if `buf` does not yet hold a complete frame (the caller should read more).
pub fn decode(buf: &[u8]) -> Option<(Frame, usize)> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + len {
        return None;
    }
    let frame = serde_json::from_slice(&buf[4..4 + len]).ok()?;
    Some((frame, 4 + len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_exec_frame() {
        let f = Frame::Exec {
            id: 7,
            cmd: vec!["python3".into(), "-c".into(), "print(2+2)".into()],
            timeout_ms: 5000,
        };
        let bytes = encode(&f);
        let (got, n) = decode(&bytes).unwrap();
        assert_eq!(got, f);
        assert_eq!(n, bytes.len());
    }

    #[test]
    fn round_trips_output_and_exit_frames() {
        let out = Frame::Output {
            id: 3,
            stream: Stream::Stderr,
            data: b"oops\n".to_vec(),
        };
        let (got, _) = decode(&encode(&out)).unwrap();
        assert_eq!(got, out);

        let exit = Frame::Exit { id: 3, code: 42 };
        let (got, _) = decode(&encode(&exit)).unwrap();
        assert_eq!(got, exit);
    }

    #[test]
    fn decode_waits_for_complete_frame() {
        let f = Frame::Exit { id: 1, code: 0 };
        let bytes = encode(&f);
        assert!(decode(&bytes[..3]).is_none(), "incomplete length prefix");
        assert!(
            decode(&bytes[..bytes.len() - 1]).is_none(),
            "incomplete body"
        );
        assert!(decode(&bytes).is_some());
    }

    #[test]
    fn handles_two_frames_in_one_buffer() {
        let mut buf = encode(&Frame::Exit { id: 1, code: 0 });
        buf.extend(encode(&Frame::Exit { id: 2, code: 1 }));
        let (f1, n1) = decode(&buf).unwrap();
        let (f2, _) = decode(&buf[n1..]).unwrap();
        assert_eq!(f1, Frame::Exit { id: 1, code: 0 });
        assert_eq!(f2, Frame::Exit { id: 2, code: 1 });
    }
}
