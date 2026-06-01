//! Snapshot / restore / fork for paused microVMs (SPEC-1 FR-14, FR-15).
//!
//! Cross-platform pieces — the [`manifest`] contract and the [`fork`] accounting —
//! build everywhere and are unit-tested. The actual snapshot/restore engine and the
//! userfaultfd copy-on-write fork engine are Linux/KVM-only and added behind
//! `cfg(target_os = "linux")`.
pub mod fork;
pub mod manifest;

pub use fork::{plan_fork, ForkError, ForkPlan};
pub use manifest::{SnapshotKind, SnapshotManifest};

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
pub use engine::{load_manifest, load_state, snapshot};
