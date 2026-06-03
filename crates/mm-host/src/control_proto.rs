//! The line protocol the privileged parent speaks to the jailed `__vmm-worker` over
//! its control UDS (`control.sock`) to act on a *live* guest (SPEC-1 FR-14/FR-16).
//!
//! One request line, one response line, newline-terminated:
//!   `SNAPSHOT\n` | `BRANCH\n`  →  `OK <id>\n` | `ERR <message>\n`
//!
//! The worker — not the parent — allocates the snapshot id (it owns the in-chroot
//! snapshot dir it writes, so there is no cross-uid permission dance and no
//! parent-supplied path to sanitize); it returns the new id in the `OK` reply. Pure
//! parse/encode, unit-tested on the dev host with no KVM.

/// A control request from the parent to the worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlRequest {
    /// Freeze-snapshot the live guest (pause → capture → resume).
    Snapshot,
    /// Branch the *running* guest (no freeze-for-dump).
    Branch,
}

/// The worker's reply: `Ok` carries the worker-allocated snapshot id; `Err` a reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlResponse {
    Ok { id: String },
    Err { msg: String },
}

impl ControlRequest {
    /// Encode to the wire line (newline-terminated).
    pub fn encode(&self) -> String {
        match self {
            ControlRequest::Snapshot => "SNAPSHOT\n".to_string(),
            ControlRequest::Branch => "BRANCH\n".to_string(),
        }
    }

    /// Parse one request line (without the trailing newline).
    pub fn parse(line: &str) -> Result<Self, String> {
        match line {
            "SNAPSHOT" => Ok(ControlRequest::Snapshot),
            "BRANCH" => Ok(ControlRequest::Branch),
            other => Err(format!("unknown control request: {other:?}")),
        }
    }
}

impl ControlResponse {
    /// Encode to the wire line (newline-terminated).
    pub fn encode(&self) -> String {
        match self {
            ControlResponse::Ok { id } => format!("OK {id}\n"),
            ControlResponse::Err { msg } => format!("ERR {msg}\n"),
        }
    }

    /// Parse one response line (without the trailing newline).
    pub fn parse(line: &str) -> Result<Self, String> {
        match line.split_once(' ') {
            Some(("OK", id)) => Ok(ControlResponse::Ok { id: id.to_string() }),
            Some(("ERR", msg)) => Ok(ControlResponse::Err {
                msg: msg.to_string(),
            }),
            _ => Err(format!("malformed control response: {line:?}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip() {
        assert_eq!(ControlRequest::Snapshot.encode(), "SNAPSHOT\n");
        assert_eq!(ControlRequest::Branch.encode(), "BRANCH\n");
        assert_eq!(
            ControlRequest::parse("SNAPSHOT").unwrap(),
            ControlRequest::Snapshot
        );
        assert_eq!(
            ControlRequest::parse("BRANCH").unwrap(),
            ControlRequest::Branch
        );
    }

    #[test]
    fn rejects_unknown_request() {
        assert!(ControlRequest::parse("BOGUS").is_err());
        assert!(ControlRequest::parse("SNAPSHOT x").is_err());
        assert!(ControlRequest::parse("").is_err());
    }

    #[test]
    fn responses_round_trip() {
        assert_eq!(
            ControlResponse::Ok {
                id: "00000000000000000042".into()
            }
            .encode(),
            "OK 00000000000000000042\n"
        );
        assert_eq!(
            ControlResponse::Err { msg: "boom".into() }.encode(),
            "ERR boom\n"
        );
        assert_eq!(
            ControlResponse::parse("OK 00000000000000000042").unwrap(),
            ControlResponse::Ok {
                id: "00000000000000000042".into()
            }
        );
        assert_eq!(
            ControlResponse::parse("ERR boom").unwrap(),
            ControlResponse::Err { msg: "boom".into() }
        );
    }
}
