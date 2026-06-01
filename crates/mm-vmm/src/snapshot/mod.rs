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
