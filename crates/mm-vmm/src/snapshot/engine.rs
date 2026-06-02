//! Snapshot/restore engine (SPEC-1 FR-14). Linux/KVM-only — it drives the live VM's
//! pause/capture and the KVM state ioctls. The file layout it produces:
//!
//! ```text
//! <dir>/manifest.json   # SnapshotManifest (cross-platform contract)
//! <dir>/state.bin       # VmState (vCPU + device + clock), bincode
//! <dir>/memory.bin      # raw guest RAM, region order
//! ```
//!
//! Snapshot is freeze-only: it pauses the vCPUs (which then exit) and quiesces the
//! devices, so the VM is frozen afterwards; restore rebuilds a fresh [`Machine`].
use std::os::unix::io::RawFd;
use std::path::Path;

use crate::config::VmConfig;
use crate::machine::{Machine, Result, VcpuHook, VmmError};
use crate::snapshot::manifest::{SnapshotKind, SnapshotManifest};
use crate::snapshot::state::VmState;

const MEMORY_FILE: &str = "memory.bin";
const STATE_FILE: &str = "state.bin";
const MANIFEST_FILE: &str = "manifest.json";

/// Snapshot a running microVM into `out_dir` (SPEC-1 FR-14): pause the vCPUs (which
/// freezes the guest), quiesce the devices, capture the VM clock, dump guest RAM, and
/// serialize the non-RAM state. The VM is frozen afterwards. Returns the manifest.
pub fn snapshot(machine: &mut Machine, out_dir: &Path) -> Result<SnapshotManifest> {
    std::fs::create_dir_all(out_dir).map_err(VmmError::Io)?;

    // Order matters: pause the vCPUs first so the guest is frozen, then quiesce the
    // devices and capture the clock while nothing can mutate guest state.
    let vcpus = machine.pause_and_capture_vcpus()?;
    let devices = machine.pause_devices()?;
    let clock = machine.capture_clock()?;
    let irqchip = machine.capture_irqchip()?;

    machine.dump_guest_memory(&out_dir.join(MEMORY_FILE))?;

    let vm_state = VmState {
        vcpus,
        devices,
        clock,
        irqchip,
    };
    let manifest = SnapshotManifest {
        version: SnapshotManifest::CURRENT_VERSION,
        vcpu_count: machine.config().vcpus,
        memory_mib: machine.config().memory_mib,
        memory_file: MEMORY_FILE.into(),
        state_file: STATE_FILE.into(),
        kind: SnapshotKind::Full,
        parent_uid: None,
    };
    write_snapshot_metadata(out_dir, &vm_state, &manifest)?;
    Ok(manifest)
}

/// Write the `state.bin` + `manifest.json` of a snapshot. Split out from
/// [`snapshot`] (which also needs a live VM for the pause + RAM dump) so the
/// serialization/layout is unit-testable without KVM.
fn write_snapshot_metadata(
    out_dir: &Path,
    vm_state: &VmState,
    manifest: &SnapshotManifest,
) -> Result<()> {
    let state_bytes = vm_state
        .to_bytes()
        .map_err(|e| VmmError::Device(format!("serializing snapshot state: {e}")))?;
    std::fs::write(out_dir.join(STATE_FILE), state_bytes).map_err(VmmError::Io)?;

    let manifest_bytes = serde_json::to_vec_pretty(manifest)
        .map_err(|e| VmmError::Device(format!("serializing manifest: {e}")))?;
    std::fs::write(out_dir.join(MANIFEST_FILE), manifest_bytes).map_err(VmmError::Io)?;
    Ok(())
}

/// Restore a snapshot directory into a fresh, running microVM (SPEC-1 FR-14). Takes
/// the same inherited fds as a jailed boot plus the snapshot `dir`; `config` must
/// match the snapshot's device set (same rootfs/net/vsock), and is used to rebuild
/// the VM before its saved state is loaded back in.
#[allow(clippy::too_many_arguments)]
pub fn restore(
    config: &VmConfig,
    kvm_fd: RawFd,
    tap_fds: Vec<RawFd>,
    vsock_listener_fd: Option<RawFd>,
    vcpu_hook: Option<VcpuHook>,
    dir: &Path,
) -> Result<Machine> {
    let manifest = load_manifest(dir)?;
    let state = load_state(dir, &manifest)?;
    let mem_path = dir.join(&manifest.memory_file);
    Machine::restore_jailed(
        config,
        kvm_fd,
        tap_fds,
        vsock_listener_fd,
        vcpu_hook,
        state,
        &mem_path,
    )
}

/// Load a snapshot's manifest from `dir`.
pub fn load_manifest(dir: &Path) -> Result<SnapshotManifest> {
    let bytes = std::fs::read(dir.join(MANIFEST_FILE)).map_err(VmmError::Io)?;
    serde_json::from_slice(&bytes).map_err(|e| VmmError::Device(format!("parsing manifest: {e}")))
}

/// Load a snapshot's `VmState` from `dir`, given its manifest.
pub fn load_state(dir: &Path, manifest: &SnapshotManifest) -> Result<VmState> {
    let bytes = std::fs::read(dir.join(&manifest.state_file)).map_err(VmmError::Io)?;
    VmState::from_bytes(&bytes)
        .map_err(|e| VmmError::Device(format!("parsing snapshot state: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::state::{DeviceState, QueueCursor, VcpuState};
    use kvm_bindings::{kvm_clock_data, kvm_lapic_state, kvm_mp_state, kvm_regs, kvm_sregs};

    fn sample_state() -> VmState {
        VmState {
            clock: kvm_clock_data {
                clock: 0xfeed,
                ..Default::default()
            },
            vcpus: vec![VcpuState {
                regs: kvm_regs {
                    rip: 0x1000,
                    ..Default::default()
                },
                sregs: kvm_sregs::default(),
                fpu: vec![7u8; 32],
                lapic: kvm_lapic_state::default(),
                mp_state: kvm_mp_state::default(),
                msrs: Vec::new(),
                tsc_khz: 3_000_000,
            }],
            devices: vec![DeviceState {
                device_type: 2,
                queues: vec![QueueCursor {
                    next_avail: 11,
                    next_used: 11,
                    ..Default::default()
                }],
            }],
            irqchip: Default::default(),
        }
    }

    #[test]
    fn snapshot_metadata_round_trips_on_disk() {
        let dir = std::env::temp_dir().join(format!("mm-snap-meta-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let manifest = SnapshotManifest {
            version: SnapshotManifest::CURRENT_VERSION,
            vcpu_count: 1,
            memory_mib: 128,
            memory_file: MEMORY_FILE.into(),
            state_file: STATE_FILE.into(),
            kind: SnapshotKind::Full,
            parent_uid: None,
        };
        write_snapshot_metadata(&dir, &sample_state(), &manifest).unwrap();

        // The manifest reloads identically, and the state file round-trips.
        let loaded_manifest = load_manifest(&dir).unwrap();
        assert_eq!(loaded_manifest, manifest);
        let state = load_state(&dir, &loaded_manifest).unwrap();
        assert_eq!(state.vcpus.len(), 1);
        assert_eq!(state.vcpus[0].regs.rip, 0x1000);
        assert_eq!(state.vcpus[0].tsc_khz, 3_000_000);
        assert_eq!(state.clock.clock, 0xfeed);
        assert_eq!(state.devices[0].queues[0].next_avail, 11);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
