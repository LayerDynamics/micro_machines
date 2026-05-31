//! Machine lifecycle state — SPEC-1 §3.3.
use serde::{Deserialize, Serialize};

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
    /// A state is terminal if no further transition is expected without a new spec.
    pub fn is_terminal(self) -> bool {
        matches!(self, State::Stopped | State::Failed | State::Destroyed)
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
}
