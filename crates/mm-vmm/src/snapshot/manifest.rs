//! Snapshot manifest — describes a saved microVM (SPEC-1 FR-14).
//!
//! A snapshot is the guest RAM plus the serialized vCPU + device state needed to
//! restore (or fork) a paused microVM. The manifest is the cross-platform contract
//! that ties those files together; the engine that writes/reads them is Linux-only.
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Everything needed to restore (or fork) a paused microVM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub version: u32,
    pub vcpu_count: u8,
    pub memory_mib: u64,
    /// Backing file holding guest RAM (mmap'd `MAP_PRIVATE` by children on fork).
    pub memory_file: PathBuf,
    /// Serialized vCPU register/sregs/CPUID + device state.
    pub state_file: PathBuf,
    pub kind: SnapshotKind,
    /// Set for diff snapshots: the parent this diff layers on.
    pub parent_uid: Option<String>,
}

/// Whether a snapshot stands alone (`Full`) or layers on a parent (`Diff`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotKind {
    Full,
    Diff,
}

impl SnapshotManifest {
    pub const CURRENT_VERSION: u32 = 1;

    /// A manifest is forkable if it is a complete, current-version full snapshot.
    /// (Diff snapshots and future-version snapshots are restore-only.)
    pub fn is_forkable(&self) -> bool {
        self.version == Self::CURRENT_VERSION && self.kind == SnapshotKind::Full
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> SnapshotManifest {
        SnapshotManifest {
            version: 1,
            vcpu_count: 1,
            memory_mib: 128,
            memory_file: "mem.bin".into(),
            state_file: "state.bin".into(),
            kind: SnapshotKind::Full,
            parent_uid: None,
        }
    }

    #[test]
    fn round_trips_json() {
        let m = full();
        let s = serde_json::to_string(&m).unwrap();
        assert_eq!(serde_json::from_str::<SnapshotManifest>(&s).unwrap(), m);
    }

    #[test]
    fn full_current_is_forkable_diff_is_not() {
        assert!(full().is_forkable());
        let mut d = full();
        d.kind = SnapshotKind::Diff;
        d.parent_uid = Some("p".into());
        assert!(!d.is_forkable());
    }

    #[test]
    fn future_version_is_not_forkable() {
        let mut m = full();
        m.version = SnapshotManifest::CURRENT_VERSION + 1;
        assert!(!m.is_forkable());
    }
}
