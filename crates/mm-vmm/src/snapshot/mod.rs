//! Snapshot / restore / fork for paused microVMs (SPEC-1 FR-14, FR-15).
//!
//! Cross-platform pieces — the [`manifest`] contract and the [`fork`] accounting —
//! build everywhere and are unit-tested. The actual snapshot/restore engine and the
//! userfaultfd copy-on-write fork engine are Linux/KVM-only and added behind
//! `cfg(target_os = "linux")`.
pub mod fork;
pub mod manifest;
pub mod store;

pub use fork::{plan_fork, ForkError, ForkPlan};
pub use manifest::{HostFingerprint, SnapshotKind, SnapshotManifest};
pub use store::{SnapshotRef, SnapshotStore};

/// Serializable vCPU + device state (the snapshot `state_file`). Linux-only: it
/// embeds `kvm_bindings`. The (de)serialization is pure and unit-tested on any Linux
/// host without KVM.
#[cfg(target_os = "linux")]
pub mod state;
#[cfg(target_os = "linux")]
pub use state::{DeviceState, MsrEntry, QueueCursor, StateError, VcpuState, VmState};

/// Snapshot/restore engine (Linux/KVM-only): drives the live VM's pause/capture and
/// the KVM state ioctls to write/read a snapshot directory.
#[cfg(target_os = "linux")]
pub mod engine;
#[cfg(target_os = "linux")]
pub use engine::{load_manifest, load_state, restore, snapshot};

/// Copy-on-write fork engine (Linux/KVM-only): fan children off a parent snapshot via
/// MAP_PRIVATE guest memory (SPEC-1 FR-15, NFR-P2).
#[cfg(target_os = "linux")]
pub mod fork_engine;
#[cfg(target_os = "linux")]
pub use fork_engine::fork_children;

/// Running-BRANCH write-protect engine (SPEC-1 FR-16): materialize a point-in-time copy
/// of a *running* parent's RAM via userfaultfd write-protect, without freezing it for a
/// dump. Feature-gated (`branch`) so the lib still cross-compiles where `userfaultfd-sys`
/// cannot (no Linux kernel headers).
#[cfg(all(target_os = "linux", feature = "branch"))]
pub mod branch;

/// Lazy post-copy branching (SPEC-1 FR-16 Phase 2): serve a child's RAM on demand from the
/// parent (still-T pages) + the sparse branch file (diverged pages), avoiding the eager
/// full-RAM copy. The engine is complete + compile-checked here; the Machine wiring
/// (`branch_lazy`/`fork_lazy`) + KVM e2e are the remaining step (see
/// `docs/plans/2026-06-03-lazy-post-copy.md`) — `allow(dead_code)` marks the not-yet-wired
/// gap honestly until then.
#[cfg(all(target_os = "linux", feature = "branch"))]
#[allow(dead_code)]
pub(crate) mod lazy;
