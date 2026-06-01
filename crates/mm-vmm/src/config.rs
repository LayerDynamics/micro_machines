//! VMM configuration contract — SPEC-1 FR-4, §3.2 (VMM Core).
//!
//! This is the typed, validated description of a microVM the rest of the VMM
//! builds from. It is deliberately platform-independent: it names what the guest
//! should look like (vCPUs, memory, kernel, rootfs, devices) without referencing
//! any KVM handle, so it can be constructed and validated on any host before a
//! single `/dev/kvm` resource is touched.
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Kernel command-line hygiene for a virtio-mmio microVM, which has no PCI bus and
/// only the COM1 UART: `pci=off` skips the PCI scan and `8250.nr_uarts=1` avoids
/// probing extra serial ports. Callers append this to the guest cmdline.
///
/// NOTE on NFR-P1 (125 ms boot): the dominant cost on the current fixture kernel is
/// the i8042 PS/2 controller probe (~0.6 s timeout). It is *not* removable from
/// userspace — the `i8042.*` cmdline flags do not stop the controller probe, and
/// emulating the i8042 ports as an open bus so the probe fails fast measured *worse*
/// (a deferred re-probe). Reaching 125 ms needs a guest kernel built without the
/// legacy i8042 probe (the Firecracker-style minimal config); these args alone do
/// not get there.
pub const FAST_BOOT_ARGS: &str = "pci=off 8250.nr_uarts=1";

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
    /// Optional token-bucket throughput limit (SPEC-1 FR-28); `None` = unlimited.
    #[serde(default)]
    pub rate_limit: Option<RateLimit>,
}

/// Token-bucket throughput limits for a virtio device (SPEC-1 FR-28): a bucket for
/// operations (one per request) and a bucket for bytes. A device is throttled when
/// either bucket is dry, until time refills it. Zero capacity in a bucket disables
/// that dimension's limit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimit {
    pub ops_capacity: u64,
    pub ops_refill_per_ms: u64,
    pub bytes_capacity: u64,
    pub bytes_refill_per_ms: u64,
}

/// The virtio device set M1 supports (SPEC-1 FR-3). Serialized with an internal
/// `kind` tag so configs round-trip through JSON/TOML unambiguously.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VirtioDevice {
    /// Networking via a host TAP device (FR-3, FR-10).
    Net {
        tap_name: String,
        mac: String,
        /// Optional token-bucket throughput limit (FR-28); `None` = unlimited.
        #[serde(default)]
        rate_limit: Option<RateLimit>,
    },
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
                rate_limit: None,
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
