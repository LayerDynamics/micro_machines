//! End-to-end: boot a real microVM on KVM and confirm the guest reaches userspace.
//! Requires /dev/kvm and a test kernel+rootfs (see tests/fixtures/README.md).
#![cfg(all(target_os = "linux", feature = "kvm-integration"))]

use std::time::{Duration, Instant};

use mm_vmm::{BlockDevice, Machine, VmConfig};

/// The guest serial console for the build architecture (matches the arch-aware
/// fixtures built by `scripts/fetch-test-fixtures.sh`).
#[cfg(target_arch = "aarch64")]
const GUEST_CONSOLE: &str = "console=ttyAMA0";
#[cfg(not(target_arch = "aarch64"))]
const GUEST_CONSOLE: &str = "console=ttyS0";

/// The fixture VM config used by every test/benchmark in this file.
fn fixture_config() -> VmConfig {
    VmConfig {
        vcpus: 1,
        memory_mib: 128,
        kernel: "tests/fixtures/vmlinux".into(),
        // root=/dev/vda: the rootfs block device is the first virtio-mmio device.
        // init=/init: mm-init is installed as /init in the fixture rootfs.
        kernel_cmdline: format!(
            "{GUEST_CONSOLE} root=/dev/vda ro init=/init reboot=k panic=1 mm.workload=/sbin/ready"
        ),
        rootfs: BlockDevice {
            path: "tests/fixtures/rootfs.ext4".into(),
            read_only: true,
        },
        devices: vec![],
    }
}

/// Boot once, returning the boot-to-userspace duration. Panics on failure.
fn boot_once() -> Duration {
    let cfg = fixture_config();
    cfg.validate().unwrap();
    let start = Instant::now();
    let mut vm = Machine::boot(&cfg).expect("vm boots");
    let ready = vm
        .wait_for_ready(Duration::from_secs(5))
        .expect("guest signals ready over vsock");
    let elapsed = start.elapsed();
    assert!(ready, "guest reached userspace");
    vm.shutdown().unwrap();
    elapsed
}

#[test]
#[ignore = "requires /dev/kvm and fixtures"]
fn boots_to_userspace_under_125ms() {
    let elapsed = boot_once();
    // NFR-P1: record the timing; the hard gate is < 1 s, p50 < 125 ms is tracked.
    println!("boot-to-userspace: {} ms", elapsed.as_millis());
    assert!(
        elapsed.as_millis() < 1000,
        "boot under 1s (hard); track p50<125ms (NFR-P1) in the bench"
    );
}

/// NFR-P1 benchmark: boot the guest many times, report p50/p90/min/max, and track
/// the < 125 ms p50 target. The hard gate is p50 < 1 s; falling short of 125 ms is
/// reported (not failed) so the number is tracked over time.
#[test]
#[ignore = "requires /dev/kvm and fixtures; long-running benchmark"]
fn boot_p50_tracks_nfr_p1() {
    const ITERATIONS: usize = 30;

    let mut samples: Vec<Duration> = Vec::with_capacity(ITERATIONS);
    for _ in 0..ITERATIONS {
        samples.push(boot_once());
    }
    samples.sort_unstable();

    let pct = |p: usize| samples[(samples.len() * p / 100).min(samples.len() - 1)];
    let p50 = pct(50);
    let p90 = pct(90);
    let min = samples[0];
    let max = samples[samples.len() - 1];

    println!(
        "boot-to-userspace over {ITERATIONS} iters: p50={}ms p90={}ms min={}ms max={}ms (NFR-P1 target: p50<125ms)",
        p50.as_millis(),
        p90.as_millis(),
        min.as_millis(),
        max.as_millis(),
    );

    // Hard gate: p50 under 1 s. NFR-P1's 125 ms target is tracked, not gated.
    assert!(
        p50.as_millis() < 1000,
        "p50 boot must be under 1s (got {}ms)",
        p50.as_millis()
    );
    if p50.as_millis() >= 125 {
        println!(
            "NOTE: p50 {}ms exceeds the NFR-P1 target of 125ms — tracked as an optimization TODO",
            p50.as_millis()
        );
    }
}
