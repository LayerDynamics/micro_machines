//! Capture-and-continue barrier for **resume-in-place** (SPEC-1 FR-16 running BRANCH).
//!
//! The freeze-only snapshot pause (`Machine::pause_and_capture_vcpus`) makes each vCPU
//! thread capture its state and **exit** — restore then rebuilds a fresh VM. The
//! running BRANCH needs the opposite: pause the parent's threads at a quiescent
//! barrier, capture their state, do some work (arm write-protection over guest RAM),
//! then **resume the same threads** so the parent keeps executing on the same guest
//! memory. This type is that barrier.
//!
//! Protocol — the orchestrator is the thread driving the checkpoint (the one calling
//! `Machine::checkpoint_in_place`); the participants are the vCPU threads (and, later,
//! the device workers):
//!
//! 1. orchestrator [`request`](Checkpoint::request) — ask participants to capture and park.
//! 2. each participant, observing [`is_requested`](Checkpoint::is_requested), captures
//!    its own state (KVM ioctls are thread-bound, so each thread must capture itself)
//!    and calls [`park`](Checkpoint::park), which blocks until release.
//! 3. orchestrator [`wait_until_parked`](Checkpoint::wait_until_parked) — once all
//!    participants are parked the guest is quiescent; read the captured state / arm WP.
//! 4. orchestrator [`release`](Checkpoint::release) then
//!    [`wait_until_resumed`](Checkpoint::wait_until_resumed) — participants leave the
//!    barrier and resume their loops; the next checkpoint starts from a clean slate.
//!
//! The state machine is pure (atomics + a parked counter), so it is unit-tested with
//! plain threads and no KVM — the part the host can actually validate locally.
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Barrier coordinating a capture-and-continue checkpoint across the vCPU threads (and
/// device workers). See the module docs for the protocol.
#[derive(Default)]
pub(crate) struct Checkpoint {
    /// Orchestrator → participants: capture your state and park now.
    requested: AtomicBool,
    /// Orchestrator → participants: leave the barrier and resume.
    released: AtomicBool,
    /// Participants → orchestrator: how many are currently parked at the barrier.
    parked: AtomicUsize,
}

impl Checkpoint {
    /// Orchestrator: request a checkpoint. Clears any prior release **first** so a
    /// participant cannot observe a stale "released" from the previous cycle and skip
    /// parking.
    pub(crate) fn request(&self) {
        self.released.store(false, Ordering::Release);
        self.requested.store(true, Ordering::Release);
    }

    /// Participant: is a checkpoint being requested right now?
    pub(crate) fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }

    /// Participant: park at the barrier until the orchestrator releases. Counts this
    /// thread as parked for the duration so [`wait_until_parked`](Self::wait_until_parked)
    /// can observe it. Must be called *after* the participant has stored its captured
    /// state, so that "all parked" implies "all state captured".
    pub(crate) fn park(&self) {
        self.parked.fetch_add(1, Ordering::AcqRel);
        while !self.released.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_micros(50));
        }
        self.parked.fetch_sub(1, Ordering::AcqRel);
    }

    /// Orchestrator: block until at least `n` participants are parked, or `timeout`
    /// elapses. Returns `true` if all `n` parked in time.
    pub(crate) fn wait_until_parked(&self, n: usize, timeout: Duration) -> bool {
        self.wait_for(|| self.parked.load(Ordering::Acquire) >= n, timeout)
    }

    /// Orchestrator: release the parked participants and clear the request, so the next
    /// loop iteration of each participant does not immediately re-checkpoint.
    pub(crate) fn release(&self) {
        self.requested.store(false, Ordering::Release);
        self.released.store(true, Ordering::Release);
    }

    /// Orchestrator: block until every parked participant has left the barrier (the
    /// parked count returns to zero), so a subsequent checkpoint starts clean. Returns
    /// `true` if all resumed in time.
    pub(crate) fn wait_until_resumed(&self, timeout: Duration) -> bool {
        self.wait_for(|| self.parked.load(Ordering::Acquire) == 0, timeout)
    }

    /// Poll `cond` until true or `timeout` elapses.
    fn wait_for(&self, cond: impl Fn() -> bool, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if cond() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_micros(100));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// One participant captures and parks; the orchestrator sees it parked, releases,
    /// and the participant resumes — the full single-thread cycle.
    #[test]
    fn single_participant_parks_then_resumes() {
        let cp = Arc::new(Checkpoint::default());
        let captured = Arc::new(AtomicUsize::new(0));
        let resumed = Arc::new(AtomicBool::new(false));

        let participant = {
            let cp = cp.clone();
            let captured = captured.clone();
            let resumed = resumed.clone();
            std::thread::spawn(move || {
                // Simulate a run loop that gets one checkpoint request.
                while !cp.is_requested() {
                    std::thread::sleep(Duration::from_micros(50));
                }
                captured.fetch_add(1, Ordering::AcqRel); // "capture state"
                cp.park();
                resumed.store(true, Ordering::Release); // resumed past the barrier
            })
        };

        cp.request();
        assert!(
            cp.wait_until_parked(1, Duration::from_secs(2)),
            "participant should park at the barrier"
        );
        // State was captured before parking; the participant has not resumed yet.
        assert_eq!(captured.load(Ordering::Acquire), 1);
        assert!(!resumed.load(Ordering::Acquire), "must wait for release");

        cp.release();
        assert!(
            cp.wait_until_resumed(Duration::from_secs(2)),
            "participant should leave the barrier"
        );
        participant.join().unwrap();
        assert!(resumed.load(Ordering::Acquire));
    }

    /// All N participants must park before the orchestrator proceeds, and all must
    /// capture exactly once — the "all parked ⇒ all captured" invariant.
    #[test]
    fn all_participants_barrier_before_release() {
        const N: usize = 4;
        let cp = Arc::new(Checkpoint::default());
        let captured = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = (0..N)
            .map(|_| {
                let cp = cp.clone();
                let captured = captured.clone();
                std::thread::spawn(move || {
                    while !cp.is_requested() {
                        std::thread::sleep(Duration::from_micros(50));
                    }
                    captured.fetch_add(1, Ordering::AcqRel);
                    cp.park();
                })
            })
            .collect();

        cp.request();
        assert!(cp.wait_until_parked(N, Duration::from_secs(2)));
        assert_eq!(
            captured.load(Ordering::Acquire),
            N,
            "every participant captured before the barrier opened"
        );
        cp.release();
        assert!(cp.wait_until_resumed(Duration::from_secs(2)));
        for h in handles {
            h.join().unwrap();
        }
    }

    /// Two back-to-back checkpoints on the same barrier: the participant re-checkpoints
    /// on the second request and not before (no stale-release skip).
    #[test]
    fn two_sequential_checkpoints() {
        let cp = Arc::new(Checkpoint::default());
        let captures = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        let participant = {
            let cp = cp.clone();
            let captures = captures.clone();
            let stop = stop.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    if cp.is_requested() {
                        captures.fetch_add(1, Ordering::AcqRel);
                        cp.park();
                    }
                    std::thread::sleep(Duration::from_micros(50));
                }
            })
        };

        for expected in 1..=2 {
            cp.request();
            assert!(cp.wait_until_parked(1, Duration::from_secs(2)));
            assert_eq!(captures.load(Ordering::Acquire), expected);
            cp.release();
            assert!(cp.wait_until_resumed(Duration::from_secs(2)));
        }

        stop.store(true, Ordering::Release);
        participant.join().unwrap();
        // Exactly two checkpoints, not more — no spurious re-checkpoint after release.
        assert_eq!(captures.load(Ordering::Acquire), 2);
    }
}
