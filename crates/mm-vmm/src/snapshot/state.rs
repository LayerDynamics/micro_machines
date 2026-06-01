//! Serializable microVM state — the contents of a snapshot's `state_file`
//! (SPEC-1 FR-14). The companion `memory_file` holds raw guest RAM; this module is
//! the per-vCPU and per-device state captured under pause.
//!
//! vCPU register state is serialized straight from the `kvm_bindings` structs (which
//! gain `serde` impls from the crate's `serde` feature — the same approach
//! Firecracker uses for migration), so the format tracks KVM's own layout rather
//! than a hand-mirrored copy that could silently drift. Device state is the virtio
//! queue cursors, mirrored from [`virtio_queue::QueueState`] (which is not itself
//! `serde`) into [`QueueCursor`] so it round-trips and rebuilds a [`virtio_queue::Queue`].
//!
//! Linux-only: the types embed `kvm_bindings`, which is a Linux-only dependency. The
//! (de)serialization is pure (no KVM calls), so its round-trip is unit-tested on any
//! Linux host without `/dev/kvm`.
use kvm_bindings::{kvm_clock_data, kvm_lapic_state, kvm_mp_state, kvm_regs, kvm_sregs};
use serde::{Deserialize, Serialize};
use virtio_queue::QueueState;

/// Errors (de)serializing snapshot state.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("serializing VM state: {0}")]
    Serialize(bincode::Error),
    #[error("deserializing VM state: {0}")]
    Deserialize(bincode::Error),
}

/// One `(index, value)` model-specific register, captured/restored via KVM's MSR
/// ioctls. Stored as plain pairs (rather than the FAM `Msrs` wrapper) so the list
/// serializes cleanly and is rebuilt at restore.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsrEntry {
    pub index: u32,
    pub data: u64,
}

/// Everything KVM needs to recreate one vCPU's execution context.
#[derive(Clone, Serialize, Deserialize)]
pub struct VcpuState {
    /// General-purpose + instruction-pointer registers (`KVM_GET_REGS`).
    pub regs: kvm_regs,
    /// Segment/control registers (`KVM_GET_SREGS`).
    pub sregs: kvm_sregs,
    /// FPU/SSE state as the raw bytes of a `kvm_fpu` (`KVM_GET_FPU` /
    /// `KVM_SET_FPU`). Stored as bytes because `kvm_fpu` has no serde impl and
    /// kvm-ioctls 0.24 exposes no `set_xsave` to restore the richer `kvm_xsave`;
    /// `kvm_fpu` is a fixed-size POD, so its bytes round-trip exactly. Length is
    /// `size_of::<kvm_fpu>()`; the capture/restore boundary (vcpu.rs) validates it.
    pub fpu: Vec<u8>,
    /// Local APIC state (`KVM_GET_LAPIC`).
    pub lapic: kvm_lapic_state,
    /// Run state, e.g. runnable vs halted (`KVM_GET_MP_STATE`).
    pub mp_state: kvm_mp_state,
    /// Model-specific registers we save/restore (`KVM_GET_MSRS`).
    pub msrs: Vec<MsrEntry>,
    /// TSC frequency in kHz (`KVM_GET_TSC_KHZ`), re-applied at restore so the guest's
    /// time base matches; 0 means the host does not support querying/scaling it.
    pub tsc_khz: u32,
}

/// A virtio queue's restorable cursor state — a `serde` mirror of
/// [`virtio_queue::QueueState`] (which derives no serde impls). Converts both ways so
/// the engine can capture `queue.state()` and rebuild via `Queue::try_from(..)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueCursor {
    pub max_size: u16,
    pub next_avail: u16,
    pub next_used: u16,
    pub event_idx_enabled: bool,
    pub size: u16,
    pub ready: bool,
    pub desc_table: u64,
    pub avail_ring: u64,
    pub used_ring: u64,
}

impl From<QueueState> for QueueCursor {
    fn from(q: QueueState) -> Self {
        Self {
            max_size: q.max_size,
            next_avail: q.next_avail,
            next_used: q.next_used,
            event_idx_enabled: q.event_idx_enabled,
            size: q.size,
            ready: q.ready,
            desc_table: q.desc_table,
            avail_ring: q.avail_ring,
            used_ring: q.used_ring,
        }
    }
}

impl From<QueueCursor> for QueueState {
    fn from(c: QueueCursor) -> Self {
        QueueState {
            max_size: c.max_size,
            next_avail: c.next_avail,
            next_used: c.next_used,
            event_idx_enabled: c.event_idx_enabled,
            size: c.size,
            ready: c.ready,
            desc_table: c.desc_table,
            avail_ring: c.avail_ring,
            used_ring: c.used_ring,
        }
    }
}

/// One virtio device's captured state: its type id plus the cursor of each queue.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceState {
    /// virtio device type id (`devices::TYPE_*`), so restore reattaches the cursors
    /// to the right rebuilt device.
    pub device_type: u32,
    /// One cursor per virtqueue, in queue-index order.
    pub queues: Vec<QueueCursor>,
}

/// The full non-RAM state of a paused microVM — the serialized `state_file`.
#[derive(Clone, Serialize, Deserialize)]
pub struct VmState {
    /// Per-vCPU state, in vCPU-index order.
    pub vcpus: Vec<VcpuState>,
    /// Per-device state, in device-attach order.
    pub devices: Vec<DeviceState>,
    /// VM-wide kvm-clock master clock (`KVM_GET_CLOCK`). Restored so the guest's
    /// paravirt clock does not jump forward by the snapshot's wall-clock age — the
    /// classic restore hang (RCU stalls) if omitted.
    pub clock: kvm_clock_data,
}

impl VmState {
    /// Serialize to the compact binary `state_file` form.
    pub fn to_bytes(&self) -> Result<Vec<u8>, StateError> {
        bincode::serialize(self).map_err(StateError::Serialize)
    }

    /// Parse a `state_file` produced by [`to_bytes`](Self::to_bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StateError> {
        bincode::deserialize(bytes).map_err(StateError::Deserialize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_vcpu() -> VcpuState {
        let regs = kvm_regs {
            rip: 0xdead_beef,
            rsp: 0x8ff0,
            ..Default::default()
        };
        VcpuState {
            regs,
            sregs: kvm_sregs::default(),
            // Arbitrary stand-in bytes; the real length is size_of::<kvm_fpu>() and
            // is validated at the vcpu.rs capture/restore boundary.
            fpu: vec![0xab; 16],
            lapic: kvm_lapic_state::default(),
            mp_state: kvm_mp_state::default(),
            msrs: vec![
                MsrEntry {
                    index: 0x10,
                    data: 0x1234,
                },
                MsrEntry {
                    index: 0xc000_0080,
                    data: 0x5678,
                },
            ],
            tsc_khz: 2_500_000,
        }
    }

    #[test]
    fn vm_state_round_trips_through_bincode() {
        let vm = VmState {
            clock: kvm_clock_data {
                clock: 0x1234_5678,
                ..Default::default()
            },
            vcpus: vec![sample_vcpu(), sample_vcpu()],
            devices: vec![DeviceState {
                device_type: 2, // TYPE_BLOCK
                queues: vec![QueueCursor {
                    max_size: 256,
                    next_avail: 5,
                    next_used: 5,
                    size: 256,
                    ready: true,
                    desc_table: 0x1000,
                    avail_ring: 0x2000,
                    used_ring: 0x3000,
                    event_idx_enabled: false,
                }],
            }],
        };

        let bytes = vm.to_bytes().expect("serialize");
        let back = VmState::from_bytes(&bytes).expect("deserialize");

        // Re-serialization is stable (a faithful round-trip), avoiding the need for
        // PartialEq on the kvm_bindings structs.
        assert_eq!(bytes, back.to_bytes().unwrap());
        // Spot-check fields survived across the round-trip.
        assert_eq!(back.vcpus.len(), 2);
        assert_eq!(back.vcpus[0].regs.rip, 0xdead_beef);
        assert_eq!(back.vcpus[0].msrs[1].index, 0xc000_0080);
        assert_eq!(back.vcpus[0].tsc_khz, 2_500_000);
        assert_eq!(back.clock.clock, 0x1234_5678);
        assert_eq!(back.devices[0].device_type, 2);
        assert_eq!(back.devices[0].queues[0].next_avail, 5);
        assert!(back.devices[0].queues[0].ready);
    }

    #[test]
    fn queue_cursor_round_trips_through_queue_state() {
        let original = QueueCursor {
            max_size: 128,
            next_avail: 9,
            next_used: 7,
            event_idx_enabled: true,
            size: 128,
            ready: true,
            desc_table: 0xa000,
            avail_ring: 0xb000,
            used_ring: 0xc000,
        };
        let as_state: QueueState = original.into();
        let back: QueueCursor = as_state.into();
        assert_eq!(original, back);
    }
}
