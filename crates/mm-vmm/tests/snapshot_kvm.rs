//! End-to-end: snapshot a running microVM and restore it on KVM (SPEC-1 FR-14).
//!
//! Layer 1 (this test) is the **state-fidelity** check the design calls for: boot a
//! sandbox guest (so PID 1 stays alive), snapshot it, restore into a *fresh* Machine,
//! and re-snapshot the restored VM. A successful re-snapshot proves the restored VM
//! is live and pausable, and the two snapshots must have the same shape (RAM size,
//! vCPU count, device set) — which exercises the whole pipeline: vCPU + clock + device
//! capture/restore, the RAM dump/load, and the restore-activate transport seam, with a
//! hang surfaced as the CI job timeout. (Full execution-continuity — the guest
//! provably continuing a counter — is a follow-up layer.)
//!
//! Requires /dev/kvm and the kernel + rootfs fixtures. `#[ignore]`d otherwise.
#![cfg(all(target_os = "linux", feature = "kvm-integration"))]

use std::path::PathBuf;
use std::time::Duration;

use mm_vmm::snapshot::{load_manifest, load_state, snapshot};
use mm_vmm::{BlockDevice, Machine, VmConfig};

#[cfg(target_arch = "aarch64")]
const GUEST_CONSOLE: &str = "console=ttyAMA0";
#[cfg(not(target_arch = "aarch64"))]
const GUEST_CONSOLE: &str = "console=ttyS0";

/// A sandbox-mode fixture config: `mm.mode=sandbox` keeps PID 1 alive (the exec agent
/// + reaper), so the guest is still running when we snapshot it.
fn fixture_config() -> VmConfig {
    VmConfig {
        vcpus: 1,
        memory_mib: 128,
        kernel: "tests/fixtures/vmlinux".into(),
        kernel_cmdline: format!(
            "{GUEST_CONSOLE} root=/dev/vda ro init=/init reboot=t panic=1 {} mm.mode=sandbox",
            mm_vmm::FAST_BOOT_ARGS,
        ),
        rootfs: BlockDevice {
            path: "tests/fixtures/rootfs.ext4".into(),
            read_only: true,
            rate_limit: None,
        },
        devices: vec![],
    }
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mm-snap-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

#[test]
#[ignore = "requires /dev/kvm and fixtures"]
fn snapshot_restore_round_trip_preserves_state() {
    let cfg = fixture_config();
    cfg.validate().unwrap();

    // 1. Boot a live sandbox guest.
    let mut m1 = Machine::boot(&cfg).expect("guest boots");
    assert!(
        m1.wait_for_ready(Duration::from_secs(10))
            .expect("readiness poll"),
        "guest reached userspace"
    );

    // 2. Snapshot it (freezes m1).
    let dir1 = scratch_dir("a");
    let manifest1 = snapshot(&mut m1, &dir1).expect("snapshot the running VM");
    let mem_bytes = cfg.memory_mib * 1024 * 1024;
    let mem_len1 = std::fs::metadata(dir1.join(&manifest1.memory_file))
        .expect("memory.bin exists")
        .len();
    assert_eq!(mem_len1, mem_bytes, "memory.bin holds the full guest RAM");

    // 3. Restore into a fresh Machine.
    let manifest = load_manifest(&dir1).expect("load manifest");
    let state = load_state(&dir1, &manifest).expect("load state");
    let mut m2 = Machine::restore(&cfg, state, &dir1.join(&manifest.memory_file))
        .expect("restore the snapshot into a fresh VM");

    // 4. Fidelity: the restored VM is alive + pausable, and re-snapshots to the same
    //    shape. A successful re-snapshot is the proof the restore produced a working,
    //    pausable VM (a broken restore would error here or hang -> job timeout).
    let dir2 = scratch_dir("b");
    let manifest2 = snapshot(&mut m2, &dir2).expect("re-snapshot the restored VM");

    assert_eq!(manifest2.vcpu_count, manifest1.vcpu_count, "vcpu count");
    assert_eq!(manifest2.memory_mib, manifest1.memory_mib, "memory size");
    let mem_len2 = std::fs::metadata(dir2.join(&manifest2.memory_file))
        .unwrap()
        .len();
    assert_eq!(mem_len2, mem_len1, "re-snapshot RAM size matches");

    let s1 = load_state(&dir1, &manifest1).unwrap();
    let s2 = load_state(&dir2, &manifest2).unwrap();
    assert_eq!(s1.vcpus.len(), s2.vcpus.len(), "same vcpu count in state");
    assert_eq!(
        s1.devices.len(),
        s2.devices.len(),
        "same device set survived the round-trip"
    );
    // Each device kept its queue count across capture -> restore -> recapture.
    for (a, b) in s1.devices.iter().zip(s2.devices.iter()) {
        assert_eq!(
            a.queues.len(),
            b.queues.len(),
            "device {} queue count preserved",
            a.device_type
        );
    }

    let _ = std::fs::remove_dir_all(&dir1);
    let _ = std::fs::remove_dir_all(&dir2);
}
