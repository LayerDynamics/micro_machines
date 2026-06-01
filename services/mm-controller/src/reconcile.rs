//! Reconciliation: the pure desired-vs-observed decision (SPEC-1 FR-9, NFR-R4).
//!
//! The control plane stores a machine's desired state (`spec`) and last observed
//! state (`status`). On every reconcile tick the loop (Task 8) loads both and asks
//! [`decide`] what to do next. Keeping that decision pure — no database, no gRPC —
//! makes the convergence rules exhaustively unit-testable and keeps the loop a thin
//! actuator around it.
use mm_api_types::State;

/// The action the reconcile loop should take for one machine this tick.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Already converged — nothing to do.
    None,
    /// Desired running, but not yet placed on a host or not yet running: schedule
    /// it onto a host and start it.
    AssignAndStart,
    /// Desired stopped, but currently running: stop it.
    Stop,
    /// The spec was deleted: tear the machine down.
    Destroy,
    /// Failed and still under the retry budget: try again.
    Retry,
}

/// A machine's observed state, as last reported by the owning agent.
#[derive(Debug)]
pub struct Observed {
    pub state: State,
    pub host_assigned: bool,
    pub retry_count: u32,
}

/// Decide the next action for a machine from its desired flags and observed state.
///
/// Pure and total: every `(desired_running, spec_deleted, state)` combination maps
/// to exactly one [`Action`], with no IO, so the loop never embeds policy.
///
/// - `spec_deleted` wins over everything: destroy unless already destroyed.
/// - A `Failed` machine retries while under `max_retries`, then rests in `None`
///   (it stays failed rather than thrashing).
/// - "Not yet converged toward running" (unplaced / stopped / freshly created)
///   means assign-and-start; an in-flight state (preparing/starting) is left alone.
pub fn decide(
    desired_running: bool,
    spec_deleted: bool,
    obs: &Observed,
    max_retries: u32,
) -> Action {
    if spec_deleted {
        return if obs.state == State::Destroyed {
            Action::None
        } else {
            Action::Destroy
        };
    }
    match (desired_running, obs.state) {
        (true, State::Running) => Action::None,
        (true, State::Failed) if obs.retry_count < max_retries => Action::Retry,
        (true, State::Failed) => Action::None, // budget exhausted; stays failed
        (true, _)
            if !obs.host_assigned || obs.state == State::Stopped || obs.state == State::Created =>
        {
            Action::AssignAndStart
        }
        (true, _) => Action::None, // in-flight (Preparing/Starting/Stopping/...)
        (false, State::Running) => Action::Stop,
        (false, _) => Action::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(state: State, host: bool) -> Observed {
        Observed {
            state,
            host_assigned: host,
            retry_count: 0,
        }
    }

    #[test]
    fn starts_when_desired_running_and_unplaced() {
        assert_eq!(
            decide(true, false, &obs(State::Created, false), 3),
            Action::AssignAndStart
        );
    }

    #[test]
    fn noop_when_already_running() {
        assert_eq!(
            decide(true, false, &obs(State::Running, true), 3),
            Action::None
        );
    }

    #[test]
    fn stops_when_desired_off() {
        assert_eq!(
            decide(false, false, &obs(State::Running, true), 3),
            Action::Stop
        );
    }

    #[test]
    fn destroys_on_spec_delete() {
        assert_eq!(
            decide(true, true, &obs(State::Running, true), 3),
            Action::Destroy
        );
    }

    #[test]
    fn destroy_is_noop_once_destroyed() {
        assert_eq!(
            decide(true, true, &obs(State::Destroyed, false), 3),
            Action::None
        );
    }

    #[test]
    fn retries_failed_within_budget_then_rests() {
        assert_eq!(
            decide(
                true,
                false,
                &Observed {
                    state: State::Failed,
                    host_assigned: true,
                    retry_count: 1
                },
                3
            ),
            Action::Retry
        );
        assert_eq!(
            decide(
                true,
                false,
                &Observed {
                    state: State::Failed,
                    host_assigned: true,
                    retry_count: 3
                },
                3
            ),
            Action::None
        );
    }

    #[test]
    fn in_flight_states_are_left_alone() {
        // Placed and already progressing toward Running — don't re-issue an assign.
        assert_eq!(
            decide(true, false, &obs(State::Starting, true), 3),
            Action::None
        );
        assert_eq!(
            decide(true, false, &obs(State::Preparing, true), 3),
            Action::None
        );
    }

    #[test]
    fn restarts_a_stopped_machine_that_should_run() {
        assert_eq!(
            decide(true, false, &obs(State::Stopped, true), 3),
            Action::AssignAndStart
        );
    }
}
