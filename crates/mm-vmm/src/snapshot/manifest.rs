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
    /// Identity of the host the snapshot was taken on, so a restore can refuse a
    /// host whose CPU feature set differs (which would crash the guest). Defaulted
    /// (empty) for snapshots taken before this field existed — those skip the check.
    #[serde(default)]
    pub host: HostFingerprint,
}

/// The host properties a snapshot is sensitive to. A microVM is restored by replaying
/// guest state captured against a specific CPU: if the restore host exposes a
/// different CPU feature set, the guest (which probed those features at boot) may
/// execute an instruction the new host lacks and trap (#UD), so restore refuses on a
/// CPUID mismatch. TSC frequency is recorded for diagnostics but not gated — restore
/// re-applies it via TSC scaling.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostFingerprint {
    /// Order-independent hash of the host's KVM-supported CPUID leaves (the guest's
    /// visible CPU feature set). 0 means "unset" (a pre-fingerprint snapshot).
    pub cpuid_hash: u64,
    /// Host TSC frequency in kHz at snapshot time (diagnostics).
    pub tsc_khz: u32,
}

impl HostFingerprint {
    /// True if unset — a snapshot taken before fingerprinting existed, which carries
    /// no host identity to check against.
    pub fn is_unset(&self) -> bool {
        self.cpuid_hash == 0
    }

    /// Validate that a snapshot taken on `self` can be safely restored on the `live`
    /// host. Ok when `self` is unset (nothing to check) or the CPU feature sets match;
    /// Err with an operator-facing reason on a CPUID mismatch (refuse — restoring onto
    /// a different CPU feature set would crash the guest). Pure, so the policy is
    /// unit-tested without KVM.
    pub fn check_restore_onto(&self, live: &HostFingerprint) -> Result<(), String> {
        if self.is_unset() {
            return Ok(());
        }
        if self.cpuid_hash != live.cpuid_hash {
            return Err(format!(
                "snapshot host CPU feature set (CPUID fingerprint {:#018x}) differs from \
                 this host ({:#018x}); restoring here would crash the guest — restore on a \
                 host with a matching CPU.",
                self.cpuid_hash, live.cpuid_hash
            ));
        }
        Ok(())
    }
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
            host: HostFingerprint {
                cpuid_hash: 0xABCD_1234_5678_9012,
                tsc_khz: 2_500_000,
            },
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

    #[test]
    fn manifest_without_host_field_loads_with_unset_fingerprint() {
        // A pre-fingerprint manifest (no `host` key) must still parse — and its
        // fingerprint is unset, so a restore skips the host check rather than failing.
        let json = r#"{"version":1,"vcpu_count":1,"memory_mib":128,
            "memory_file":"mem.bin","state_file":"state.bin","kind":"full","parent_uid":null}"#;
        let m: SnapshotManifest = serde_json::from_str(json).unwrap();
        assert!(m.host.is_unset());
        assert!(m
            .host
            .check_restore_onto(&HostFingerprint::default())
            .is_ok());
    }

    #[test]
    fn restore_refuses_a_cpuid_mismatch_but_allows_a_match() {
        let snap = HostFingerprint {
            cpuid_hash: 0x1111,
            tsc_khz: 2_000_000,
        };
        // Same CPU feature set (different TSC freq is fine — scaled at restore).
        let same_cpu = HostFingerprint {
            cpuid_hash: 0x1111,
            tsc_khz: 3_000_000,
        };
        assert!(snap.check_restore_onto(&same_cpu).is_ok());
        // Different CPU feature set -> refused.
        let other_cpu = HostFingerprint {
            cpuid_hash: 0x2222,
            tsc_khz: 2_000_000,
        };
        assert!(snap.check_restore_onto(&other_cpu).is_err());
        // An unset snapshot fingerprint never refuses.
        assert!(HostFingerprint::default()
            .check_restore_onto(&other_cpu)
            .is_ok());
    }
}
