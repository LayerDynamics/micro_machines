//! End-to-end: fork child microVMs from a snapshot via copy-on-write memory on KVM
//! (SPEC-1 FR-15, NFR-P2). Boots a sandbox parent, snapshots it, fans out N children
//! with `MAP_PRIVATE` CoW guest RAM, and proves the children are **independent**:
//! writing a distinct value into each child's guest memory and reading it back must
//! return that child's own value (a `MAP_SHARED` mapping — the bug this guards
//! against — would make every child read the last write). Also reports the fan-out
//! latency tracked by NFR-P2 (p50 < 150 ms; the hard gate is liveness + isolation,
//! since the nested-KVM CI runner is slower than a bare-metal host).
//!
//! The full N=100 latency benchmark + in-guest exec independence is a follow-up layer.
//!
//! Requires /dev/kvm and the kernel + rootfs fixtures. `#[ignore]`d otherwise.
#![cfg(all(target_os = "linux", feature = "kvm-integration"))]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use mm_vmm::snapshot::{fork_children, snapshot, ForkPlan};
use mm_vmm::{BlockDevice, Machine, VmConfig};
use vm_memory::{Bytes, GuestAddress};

#[cfg(target_arch = "aarch64")]
const GUEST_CONSOLE: &str = "console=ttyAMA0";
#[cfg(not(target_arch = "aarch64"))]
const GUEST_CONSOLE: &str = "console=ttyS0";

/// How many children to fan out. Enough to prove independence + fan-out without
/// overloading the shared CI runner; the full NFR-P2 N=100 sweep is a follow-up.
const CHILDREN: usize = 4;
/// A scratch guest-physical address inside the 128 MiB of RAM but well above what an
/// idle sandbox guest touches, used to prove per-child CoW isolation.
const SCRATCH_GPA: u64 = 0x0400_0000; // 64 MiB

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

fn scratch_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mm-fork-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

#[test]
#[ignore = "requires /dev/kvm and fixtures"]
fn fork_fans_out_independent_cow_children() {
    let cfg = fixture_config();
    cfg.validate().unwrap();

    // Warm parent: boot a sandbox guest to userspace, then snapshot it.
    let mut parent = Machine::boot(&cfg).expect("parent boots");
    assert!(
        parent
            .wait_for_ready(Duration::from_secs(10))
            .expect("readiness poll"),
        "parent reached userspace"
    );
    let dir = scratch_dir();
    let manifest = snapshot(&mut parent, &dir).expect("snapshot the warm parent");

    // Fan out CHILDREN children over CoW memory, timing the fan-out (NFR-P2).
    let plan = ForkPlan {
        child_ids: (1..=CHILDREN as u64).collect(),
        shared_mib: manifest.memory_mib,
        per_child_overhead_mib: 0,
    };
    let t0 = Instant::now();
    let children = fork_children(&cfg, &dir, &plan).expect("fork children");
    let elapsed = t0.elapsed();
    assert_eq!(children.len(), CHILDREN, "all children forked");
    println!(
        "fork fan-out: {CHILDREN} children in {} ms ({} ms/child) — NFR-P2 p50<150ms target",
        elapsed.as_millis(),
        elapsed.as_millis() / CHILDREN as u128
    );

    // CoW isolation: each child gets a distinct value written into its guest RAM;
    // reading it back must yield that child's own value. A MAP_SHARED mapping would
    // make all children (and the backing file) see the last write — this catches it.
    let addr = GuestAddress(SCRATCH_GPA);
    for (i, child) in children.iter().enumerate() {
        let sentinel = 0xC0DE_0000_u64 + i as u64;
        child
            .guest_memory()
            .write_obj(sentinel, addr)
            .expect("write child guest RAM");
    }
    for (i, child) in children.iter().enumerate() {
        let want = 0xC0DE_0000_u64 + i as u64;
        let got: u64 = child
            .guest_memory()
            .read_obj(addr)
            .expect("read child guest RAM");
        assert_eq!(
            got, want,
            "child {i} guest RAM is CoW-isolated (got {got:#x}, want {want:#x})"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}
