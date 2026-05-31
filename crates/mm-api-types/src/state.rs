//! Machine lifecycle state — SPEC-1 §3.3.
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::Error;

/// The lifecycle state of a Machine (microVM). SPEC-1 §3.3 / Appendix B.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Created,
    Preparing,
    Starting,
    Running,
    Paused,
    Stopping,
    Stopped,
    Failed,
    Destroying,
    Destroyed,
}

impl State {
    /// Every variant, in lifecycle order. Lets callers iterate states without
    /// hard-coding the set (used by parsing and exhaustiveness checks).
    pub const ALL: [State; 10] = [
        State::Created,
        State::Preparing,
        State::Starting,
        State::Running,
        State::Paused,
        State::Stopping,
        State::Stopped,
        State::Failed,
        State::Destroying,
        State::Destroyed,
    ];

    /// The canonical `snake_case` wire name — identical to the serde
    /// representation, so the string form is consistent everywhere (CLI,
    /// logs, database columns) without going through JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            State::Created => "created",
            State::Preparing => "preparing",
            State::Starting => "starting",
            State::Running => "running",
            State::Paused => "paused",
            State::Stopping => "stopping",
            State::Stopped => "stopped",
            State::Failed => "failed",
            State::Destroying => "destroying",
            State::Destroyed => "destroyed",
        }
    }

    /// A state is terminal if no further transition is expected without a new spec.
    pub fn is_terminal(self) -> bool {
        matches!(self, State::Stopped | State::Failed | State::Destroyed)
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for State {
    type Err = Error;

    /// Parse a `snake_case` state name, rejecting anything unknown with
    /// [`Error::UnknownState`]. Inverse of [`State::as_str`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        State::ALL
            .into_iter()
            .find(|state| state.as_str() == s)
            .ok_or_else(|| Error::UnknownState(s.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_serializes_snake_case() {
        let json = serde_json::to_string(&State::Running).unwrap();
        assert_eq!(json, "\"running\"");
    }

    #[test]
    fn terminal_states_are_classified() {
        assert!(State::Stopped.is_terminal());
        assert!(State::Failed.is_terminal());
        assert!(!State::Running.is_terminal());
    }

    #[test]
    fn state_roundtrips_through_str() {
        for state in State::ALL {
            let parsed: State = state.as_str().parse().unwrap();
            assert_eq!(parsed, state);
        }
    }

    #[test]
    fn as_str_matches_serde_representation() {
        for state in State::ALL {
            let json = serde_json::to_string(&state).unwrap();
            assert_eq!(json, format!("\"{}\"", state.as_str()));
        }
    }

    #[test]
    fn unknown_state_string_is_rejected() {
        let err = "zombie".parse::<State>().unwrap_err();
        assert_eq!(err, Error::UnknownState("zombie".to_string()));
    }

    #[test]
    fn display_uses_snake_case() {
        assert_eq!(State::Running.to_string(), "running");
    }
}
