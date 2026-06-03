//! The line protocol the privileged parent speaks to the jailed `__vmm-worker` over
//! its control UDS (`control.sock`) to act on a *live* guest (SPEC-1 FR-14/FR-16).
//!
//! One request line, one response line, newline-terminated:
//!   `SNAPSHOT <dir>\n` | `BRANCH <dir>\n`  →  `OK <id>\n` | `ERR <message>\n`
//!
//! `<dir>` is a single path segment (a store-allocated id) the worker joins under the
//! snapshot dir the parent created; it must not contain `/` or NUL (path safety). Pure
//! parse/encode so it is unit-tested on the dev host with no KVM.

/// A control request from the parent to the worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlRequest {
    /// Freeze-snapshot the live guest into `<snapshot-root>/<dir>`.
    Snapshot { dir: String },
    /// Branch the *running* guest into `<snapshot-root>/<dir>` (no freeze-for-dump).
    Branch { dir: String },
}

/// The worker's reply: `Ok` carries the new snapshot id; `Err` a human-readable reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlResponse {
    Ok { id: String },
    Err { msg: String },
}

/// A path segment is safe iff non-empty and free of `/`, NUL, and `.`-only traversal,
/// so the worker cannot be tricked into writing outside the per-VM snapshot dir.
fn is_safe_segment(s: &str) -> bool {
    !s.is_empty() && s != "." && s != ".." && !s.contains('/') && !s.contains('\0')
}

impl ControlRequest {
    /// Encode to the wire line (newline-terminated).
    pub fn encode(&self) -> String {
        match self {
            ControlRequest::Snapshot { dir } => format!("SNAPSHOT {dir}\n"),
            ControlRequest::Branch { dir } => format!("BRANCH {dir}\n"),
        }
    }

    /// Parse one request line (without the trailing newline). Rejects unknown verbs
    /// and unsafe dir segments.
    pub fn parse(line: &str) -> Result<Self, String> {
        let (verb, arg) = line
            .split_once(' ')
            .ok_or_else(|| format!("malformed control request: {line:?}"))?;
        if !is_safe_segment(arg) {
            return Err(format!("unsafe dir segment: {arg:?}"));
        }
        match verb {
            "SNAPSHOT" => Ok(ControlRequest::Snapshot {
                dir: arg.to_string(),
            }),
            "BRANCH" => Ok(ControlRequest::Branch {
                dir: arg.to_string(),
            }),
            other => Err(format!("unknown control verb: {other}")),
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
    fn snapshot_request_round_trips() {
        let req = ControlRequest::Snapshot {
            dir: "snap-1".into(),
        };
        let line = req.encode();
        assert_eq!(line, "SNAPSHOT snap-1\n");
        assert_eq!(ControlRequest::parse(line.trim_end()).unwrap(), req);
    }

    #[test]
    fn branch_request_round_trips() {
        let req = ControlRequest::Branch {
            dir: "branch-1".into(),
        };
        assert_eq!(req.encode(), "BRANCH branch-1\n");
        assert_eq!(ControlRequest::parse("BRANCH branch-1").unwrap(), req);
    }

    #[test]
    fn rejects_unknown_verb_and_pathsep() {
        assert!(ControlRequest::parse("BOGUS x").is_err());
        // A dir token must be a single path segment (no '/', '..', or NUL) — defense in
        // depth so the worker can't be steered outside the per-VM snapshot dir.
        assert!(ControlRequest::parse("SNAPSHOT ../etc").is_err());
        assert!(ControlRequest::parse("SNAPSHOT a/b").is_err());
        assert!(ControlRequest::parse("SNAPSHOT").is_err());
    }

    #[test]
    fn responses_round_trip() {
        assert_eq!(
            ControlResponse::Ok {
                id: "snap-1".into()
            }
            .encode(),
            "OK snap-1\n"
        );
        assert_eq!(
            ControlResponse::Err { msg: "boom".into() }.encode(),
            "ERR boom\n"
        );
        assert_eq!(
            ControlResponse::parse("OK snap-1").unwrap(),
            ControlResponse::Ok {
                id: "snap-1".into()
            }
        );
        assert_eq!(
            ControlResponse::parse("ERR boom").unwrap(),
            ControlResponse::Err { msg: "boom".into() }
        );
    }
}
