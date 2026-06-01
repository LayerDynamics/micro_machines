//! End-to-end: boot a real microVM with a virtio-net device on a host bridge and
//! confirm the guest's NIC actually carries traffic (SPEC-1 FR-10/11).
//!
//! Proves three things the plain boot test does not:
//!   * virtio-net TX works — a guest-originated Ethernet frame traverses the TAP,
//!     the host bridge, and arrives at a host socket;
//!   * the kernel's static `ip=` config brings `eth0` up with the address we set;
//!   * the MMIO net transport is discovered and activated (its epoll worker runs).
//!
//! Requires /dev/kvm, the fixtures (see tests/fixtures/README.md), AND root, since
//! it creates a bridge + TAP and opens the TAP via TUNSETIFF (CAP_NET_ADMIN). The
//! CI `net-integration` job runs it under `sudo`. It is `#[ignore]`d so a normal
//! `cargo test` never touches host networking.
#![cfg(all(target_os = "linux", feature = "kvm-integration"))]

use std::net::UdpSocket;
use std::process::Command;
use std::time::Duration;

use mm_vmm::{BlockDevice, Machine, VirtioDevice, VmConfig};

#[cfg(target_arch = "aarch64")]
const GUEST_CONSOLE: &str = "console=ttyAMA0";
#[cfg(not(target_arch = "aarch64"))]
const GUEST_CONSOLE: &str = "console=ttyS0";

// The host bridge owns the gateway address; the guest is one address over. These
// match the destination hardcoded in the fixture `ready` helper (10.0.0.1:1234).
const BRIDGE: &str = "mmnet0";
const TAP: &str = "mmtap0";
const GATEWAY_IP: &str = "10.0.0.1";
const GUEST_IP: &str = "10.0.0.2";
const NETMASK: &str = "255.255.255.0";
const UDP_PORT: u16 = 1234;
const GUEST_MAC: &str = "02:00:00:00:00:02";

/// Run `ip <args>`, panicking with the captured stderr on failure.
fn ip(args: &[&str]) {
    let out = Command::new("ip")
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn `ip {}`: {e}", args.join(" ")));
    assert!(
        out.status.success(),
        "`ip {}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Best-effort `ip <args>` for teardown — ignores failures (link may be gone).
fn ip_ok(args: &[&str]) {
    let _ = Command::new("ip").args(args).output();
}

/// Owns the host bridge + TAP for the test and tears them down on drop, so a
/// panic mid-test never leaks interfaces into the runner.
struct NetFixture;

impl NetFixture {
    fn up() -> Self {
        // Idempotent: clear any leftovers from a previous aborted run first.
        ip_ok(&["link", "del", TAP]);
        ip_ok(&["link", "del", BRIDGE]);

        ip(&["link", "add", BRIDGE, "type", "bridge"]);
        ip(&["addr", "add", &format!("{GATEWAY_IP}/24"), "dev", BRIDGE]);
        ip(&["link", "set", BRIDGE, "up"]);
        ip(&["tuntap", "add", TAP, "mode", "tap"]);
        ip(&["link", "set", TAP, "master", BRIDGE]);
        ip(&["link", "set", TAP, "up"]);
        NetFixture
    }
}

impl Drop for NetFixture {
    fn drop(&mut self) {
        ip_ok(&["link", "del", TAP]);
        ip_ok(&["link", "del", BRIDGE]);
    }
}

/// VM config with a virtio-net device on the test TAP and a static `ip=` so the
/// guest kernel brings `eth0` up before `/init` execs the workload.
fn net_config() -> VmConfig {
    // ip=<client>:<server>:<gw>:<netmask>:<host>:<dev>:<autoconf>
    let ip_param = format!("ip={GUEST_IP}::{GATEWAY_IP}:{NETMASK}::eth0:off");
    VmConfig {
        vcpus: 1,
        memory_mib: 128,
        kernel: "tests/fixtures/vmlinux".into(),
        // net.ifnames=0 forces the legacy `eth0` name the `ip=` param targets,
        // rather than a predictable name (enp0s…) that would leave eth0 unconfigured.
        kernel_cmdline: format!(
            "{GUEST_CONSOLE} root=/dev/vda ro init=/init reboot=t panic=1 \
             {} net.ifnames=0 {ip_param} mm.workload=/sbin/ready",
            mm_vmm::FAST_BOOT_ARGS,
        ),
        rootfs: BlockDevice {
            path: "tests/fixtures/rootfs.ext4".into(),
            read_only: true,
            rate_limit: None,
        },
        devices: vec![VirtioDevice::Net {
            tap_name: TAP.into(),
            mac: GUEST_MAC.into(),
            rate_limit: None,
        }],
    }
}

#[test]
#[ignore = "requires /dev/kvm, fixtures, and root (creates a bridge + TAP)"]
fn guest_nic_carries_traffic() {
    let _net = NetFixture::up();

    // Listen on the gateway address for the guest's readiness datagram. Binding
    // before boot guarantees we never miss the packet.
    let sock = UdpSocket::bind(("0.0.0.0", UDP_PORT)).expect("bind udp listener");
    sock.set_read_timeout(Some(Duration::from_secs(15)))
        .expect("set recv timeout");

    let cfg = net_config();
    cfg.validate().unwrap();
    let mut vm = Machine::boot(&cfg).expect("vm boots with net device");

    let mut buf = [0u8; 64];
    let (n, from) = sock
        .recv_from(&mut buf)
        .expect("guest UDP datagram reaches the host over the bridge");

    assert_eq!(&buf[..n], b"mm-ready", "unexpected datagram payload");
    assert_eq!(
        from.ip().to_string(),
        GUEST_IP,
        "datagram must originate from the guest's configured address"
    );
    println!("net: received {n} bytes from {from} over the bridge");

    vm.shutdown().unwrap();
}
