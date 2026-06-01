//! Pure VM-config construction + naming helpers (no I/O), shared by every actuator.
use std::net::Ipv4Addr;
use std::path::PathBuf;

use mm_vmm::{BlockDevice, VirtioDevice, VmConfig};

/// The guest netmask for the MicroMachines `/24`.
pub const NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

/// Build the VM configuration from resolved inputs. Pure (no I/O) so it is unit
/// tested directly; the kernel cmdline carries the static `ip=` (no in-guest DHCP)
/// and the `mm.*` guest-init directives.
#[allow(clippy::too_many_arguments)]
pub fn build_vm_config(
    vcpus: u8,
    memory_mib: u64,
    kernel: PathBuf,
    rootfs: PathBuf,
    ip: Ipv4Addr,
    gateway: Ipv4Addr,
    mask: Ipv4Addr,
    hostname: &str,
    tap_name: String,
    mac: String,
    workload_argv_hex: Option<&str>,
    authorized_key_hex: Option<&str>,
    random_seed_hex: Option<&str>,
) -> VmConfig {
    let ip_param = mm_net::ip_cmdline(ip, gateway, mask, hostname, "eth0");
    // Some(hex) → run the image's command (argv hex-encoded as mm.workload_argv);
    // None → sandbox mode (an interactive shell, for `mm run --ssh`).
    let mode = match workload_argv_hex {
        Some(hex) => format!("mm.workload_argv={hex}"),
        None => "mm.mode=sandbox".to_string(),
    };
    // root=/dev/vda: the rootfs is the first virtio-mmio block device. init=/init:
    // mm-init is PID 1 in the guest image. FAST_BOOT_ARGS skips the PS/2 + PCI probes
    // a microVM never needs (NFR-P1). The rootfs is read-only; mm-init turns it into
    // a writable overlay root at boot.
    let mut kernel_cmdline = format!(
        "console=ttyS0 root=/dev/vda ro init=/init reboot=t panic=1 {} {ip_param} {mode}",
        mm_vmm::FAST_BOOT_ARGS,
    );
    if let Some(hex) = authorized_key_hex {
        // Hex-encoded (no spaces) so it survives the whitespace-split cmdline.
        kernel_cmdline.push_str(&format!(" mm.authorized_key={hex}"));
    }
    if let Some(hex) = random_seed_hex {
        // Real host entropy for the guest CRNG — mm-init credits it via RNDADDENTROPY
        // so getrandom(2) doesn't block (this kernel has no virtio-rng). Hex-encoded.
        kernel_cmdline.push_str(&format!(" mm.random_seed={hex}"));
    }
    VmConfig {
        vcpus,
        memory_mib,
        kernel,
        kernel_cmdline,
        rootfs: BlockDevice {
            path: rootfs,
            read_only: true,
        },
        devices: vec![VirtioDevice::Net { tap_name, mac }],
    }
}

/// Derive a default machine name from an image reference: last path component,
/// tag stripped, plus a short unique suffix.
pub fn default_name(image: &str) -> String {
    let base = image
        .rsplit('/')
        .next()
        .unwrap_or(image)
        .split(':')
        .next()
        .unwrap_or("vm");
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    format!("{base}-{}", &suffix[..6])
}

/// A locally-administered MAC derived from the guest IP (stable per IP).
pub fn mac_from_ip(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("02:00:00:{:02x}:{:02x}:{:02x}", o[1], o[2], o[3])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_config_carries_static_ip_and_workload_mode() {
        let cfg = build_vm_config(
            2,
            512,
            PathBuf::from("/k/vmlinux"),
            PathBuf::from("/r/root.ext4"),
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            NETMASK,
            "web-1",
            "mm-web-1".to_string(),
            "02:00:00:0a:00:02".to_string(),
            Some("2f62696e2f7368"), // hex("/bin/sh")
            None,
            None,
        );
        assert_eq!(cfg.vcpus, 2);
        assert!(cfg
            .kernel_cmdline
            .contains("ip=10.0.0.2::10.0.0.1:255.255.255.0:web-1:eth0:off"));
        assert!(cfg
            .kernel_cmdline
            .contains("mm.workload_argv=2f62696e2f7368"));
        assert!(cfg.rootfs.read_only);
        assert_eq!(
            cfg.devices,
            vec![VirtioDevice::Net {
                tap_name: "mm-web-1".to_string(),
                mac: "02:00:00:0a:00:02".to_string()
            }]
        );
    }

    #[test]
    fn sandbox_flag_selects_sandbox_mode() {
        let cfg = build_vm_config(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(10, 0, 0, 1),
            NETMASK,
            "s",
            "tap".to_string(),
            "02:00:00:0a:00:05".to_string(),
            None, // no workload argv → sandbox mode
            None,
            None,
        );
        assert!(cfg.kernel_cmdline.contains("mm.mode=sandbox"));
        assert!(!cfg.kernel_cmdline.contains("mm.workload"));
    }

    #[test]
    fn authorized_key_and_seed_are_injected_on_cmdline() {
        let cfg = build_vm_config(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            Ipv4Addr::new(10, 0, 0, 7),
            Ipv4Addr::new(10, 0, 0, 1),
            NETMASK,
            "k",
            "tap".to_string(),
            "02:00:00:0a:00:07".to_string(),
            Some("2f62696e2f7368"), // hex("/bin/sh")
            Some("deadbeef"),
            Some("00ff10ab"),
        );
        assert!(cfg.kernel_cmdline.contains("mm.authorized_key=deadbeef"));
        assert!(cfg.kernel_cmdline.contains("mm.random_seed=00ff10ab"));
    }

    #[test]
    fn default_name_strips_registry_and_tag() {
        let n = default_name("docker.io/library/alpine:latest");
        assert!(n.starts_with("alpine-"), "got {n}");
        assert_eq!(n.len(), "alpine-".len() + 6);
    }

    #[test]
    fn mac_is_locally_administered_and_ip_derived() {
        assert_eq!(mac_from_ip(Ipv4Addr::new(10, 0, 0, 2)), "02:00:00:00:00:02");
        assert_eq!(mac_from_ip(Ipv4Addr::new(10, 1, 2, 3)), "02:00:00:01:02:03");
    }
}
