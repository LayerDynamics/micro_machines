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

use mm_vmm::snapshot::{fork_children, load_state, snapshot, ForkPlan};
use mm_vmm::{BlockDevice, Machine, VmConfig};
use vm_memory::{Bytes, GuestAddress};

#[cfg(target_arch = "aarch64")]
const GUEST_CONSOLE: &str = "console=ttyAMA0";
#[cfg(not(target_arch = "aarch64"))]
const GUEST_CONSOLE: &str = "console=ttyS0";

/// How many children to fan out concurrently for the CoW-isolation proof. Kept small
/// so all stay resident at once; the latency sweep below uses a much larger N.
const CHILDREN: usize = 4;
/// Children for the NFR-P2 latency sweep. Forked one at a time (only one resident at
/// once) so the shared nested-KVM CI runner is not overloaded by 100 live VMs.
const FANOUT: usize = 100;
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

#[test]
#[ignore = "requires /dev/kvm and fixtures; long-running benchmark"]
fn fork_fanout_p50_tracks_nfr_p2() {
    let cfg = fixture_config();
    cfg.validate().unwrap();

    // Warm a parent and snapshot it (the source for every fork).
    let mut parent = Machine::boot(&cfg).expect("parent boots");
    assert!(
        parent
            .wait_for_ready(Duration::from_secs(10))
            .expect("readiness poll"),
        "parent reached userspace"
    );
    let dir = scratch_dir();
    let manifest = snapshot(&mut parent, &dir).expect("snapshot the warm parent");
    drop(parent); // frozen parent is no longer needed

    // Load the captured state once; each fork gets its own CoW mapping + a clone of it.
    let state = load_state(&dir, &manifest).expect("load snapshot state");
    let mem_path = dir.join(&manifest.memory_file);

    // Fork children one at a time, timing each fork's time-to-running. Only one child
    // is resident at a time (shut down before the next), so 100 forks don't overload
    // the runner — and the per-child fork latency is exactly the NFR-P2 metric.
    let mut samples: Vec<Duration> = Vec::with_capacity(FANOUT);
    for _ in 0..FANOUT {
        let t0 = Instant::now();
        let mut child = Machine::fork(&cfg, state.clone(), &mem_path).expect("fork child");
        samples.push(t0.elapsed());
        child.shutdown().expect("stop forked child");
    }

    samples.sort_unstable();
    let quantile = |q: f64| samples[((samples.len() as f64 * q) as usize).min(samples.len() - 1)];
    let p50 = quantile(0.50);
    let p90 = quantile(0.90);
    println!(
        "fork fan-out N={FANOUT}: p50={} ms, p90={} ms, min={} ms, max={} ms — NFR-P2 p50<150ms target",
        p50.as_millis(),
        p90.as_millis(),
        samples.first().unwrap().as_millis(),
        samples.last().unwrap().as_millis(),
    );

    // The 150 ms p50 target is reported + tracked (like the boot NFR-P1 bench); the
    // hard gate is a generous bound that only catches a genuine regression, since the
    // nested-KVM CI runner is materially slower than a bare-metal host.
    assert!(
        p50.as_millis() < 2_000,
        "per-child fork p50 must be < 2s (got {} ms); NFR-P2 150ms tracked in the number above",
        p50.as_millis(),
    );

    let _ = std::fs::remove_dir_all(&dir);
}
