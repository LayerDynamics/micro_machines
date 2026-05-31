//! VMM configuration contract — SPEC-1 FR-4, §3.2 (VMM Core).
//!
//! This is the typed, validated description of a microVM the rest of the VMM
//! builds from. It is deliberately platform-independent: it names what the guest
//! should look like (vCPUs, memory, kernel, rootfs, devices) without referencing
//! any KVM handle, so it can be constructed and validated on any host before a
//! single `/dev/kvm` resource is touched.
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Kernel command-line arguments that skip device probes a microVM never needs, so
/// the guest reaches userspace fast (SPEC-1 NFR-P1). On a virtio-mmio microVM there
/// is no PS/2 controller and no PCI bus; the default i8042 probe alone blocks the
/// boot for ~0.6 s on a timeout. These disable that probe (`i8042.*`), the PCI scan
/// (`pci=off`), and extra 8250 UART ports (`8250.nr_uarts=1`, keeping COM1 for the
/// console). Callers append this to the guest cmdline.
pub const FAST_BOOT_ARGS: &str =
    "i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd pci=off 8250.nr_uarts=1";

/// Fully-resolved configuration for a single microVM (SPEC-1 FR-4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmConfig {
    pub vcpus: u8,
    pub memory_mib: u64,
    pub kernel: PathBuf,
    pub kernel_cmdline: String,
    pub rootfs: BlockDevice,
    pub devices: Vec<VirtioDevice>,
}

/// A backing block device exposed to the guest as virtio-blk (SPEC-1 FR-3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockDevice {
    pub path: PathBuf,
    pub read_only: bool,
}

/// The virtio device set M1 supports (SPEC-1 FR-3). Serialized with an internal
/// `kind` tag so configs round-trip through JSON/TOML unambiguously.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VirtioDevice {
    /// Networking via a host TAP device (FR-3, FR-10).
    Net { tap_name: String, mac: String },
    /// Host<->guest control/exec channel (FR-3; used by Sandbox Mode in M3).
    Vsock { cid: u32 },
    /// Memory reclamation (FR-3).
    Balloon { target_mib: u64 },
}

/// Validation failures surfaced before any KVM resource is allocated (FR-4).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("vcpus must be between 1 and 32, got {0}")]
    VcpuRange(u8),
    #[error("memory must be at least 16 MiB, got {0}")]
    MemoryTooSmall(u64),
}

impl VmConfig {
    /// Validate the config before any KVM resources are allocated (FR-4).
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !(1..=32).contains(&self.vcpus) {
            return Err(ConfigError::VcpuRange(self.vcpus));
        }
        if self.memory_mib < 16 {
            return Err(ConfigError::MemoryTooSmall(self.memory_mib));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn base() -> VmConfig {
        VmConfig {
            vcpus: 2,
            memory_mib: 512,
            kernel: "/k/vmlinux".into(),
            kernel_cmdline: "console=ttyS0".into(),
            rootfs: BlockDevice {
                path: "/r/root.img".into(),
                read_only: true,
            },
            devices: vec![],
        }
    }
    #[test]
    fn rejects_zero_vcpus() {
        let mut c = base();
        c.vcpus = 0;
        assert_eq!(c.validate(), Err(ConfigError::VcpuRange(0)));
    }
    #[test]
    fn rejects_tiny_memory() {
        let mut c = base();
        c.memory_mib = 8;
        assert_eq!(c.validate(), Err(ConfigError::MemoryTooSmall(8)));
    }
    #[test]
    fn accepts_valid_config() {
        assert!(base().validate().is_ok());
    }
}
