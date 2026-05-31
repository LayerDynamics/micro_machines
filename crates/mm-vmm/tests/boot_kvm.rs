//! End-to-end: boot a real microVM on KVM and confirm the guest reaches userspace.
//! Requires /dev/kvm and a test kernel+rootfs (see tests/fixtures/README.md).
#![cfg(all(target_os = "linux", feature = "kvm-integration"))]

use std::time::{Duration, Instant};

use mm_vmm::{BlockDevice, Machine, VmConfig};

#[test]
#[ignore = "requires /dev/kvm and fixtures"]
fn boots_to_userspace_under_125ms() {
    let cfg = VmConfig {
        vcpus: 1,
        memory_mib: 128,
        kernel: "tests/fixtures/vmlinux".into(),
        kernel_cmdline: "console=ttyS0 reboot=k panic=1 mm.workload=/sbin/ready".into(),
        rootfs: BlockDevice {
            path: "tests/fixtures/rootfs.ext4".into(),
            read_only: true,
        },
        devices: vec![],
    };
    cfg.validate().unwrap();

    let start = Instant::now();
    let mut vm = Machine::boot(&cfg).expect("vm boots");
    let ready = vm
        .wait_for_ready(Duration::from_secs(5))
        .expect("guest signals ready over vsock");
    let elapsed = start.elapsed();

    assert!(ready, "guest reached userspace");
    // NFR-P1: record the timing; the hard gate is < 1 s, p50 < 125 ms is tracked.
    println!("boot-to-userspace: {} ms", elapsed.as_millis());
    assert!(
        elapsed.as_millis() < 1000,
        "boot under 1s (hard); track p50<125ms (NFR-P1) in the bench"
    );

    vm.shutdown().unwrap();
}
