//! MicroMachines native VMM core (SPEC-1 §3.2). Built on the rust-vmm crates.
//!
//! The configuration contract ([`config`]) is platform-independent and always
//! compiled. The KVM machinery (machine/vcpu/boot/devices) is Linux-only and is
//! added in Tasks 5–8 behind `cfg(target_os = "linux")`; on other hosts only the
//! contract and its tests build.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

pub mod config;
pub use config::{BlockDevice, ConfigError, VirtioDevice, VmConfig, FAST_BOOT_ARGS};

// Linux-only KVM machinery (Tasks 5–8), behind `cfg(target_os = "linux")`.
#[cfg(target_os = "linux")]
pub mod boot;
#[cfg(target_os = "linux")]
pub mod devices;
#[cfg(target_os = "linux")]
mod machine;
#[cfg(target_os = "linux")]
mod vcpu;

#[cfg(target_os = "linux")]
pub use boot::KernelBoot;
#[cfg(target_os = "linux")]
pub use machine::{IoDispatch, Machine, VcpuHook, VmmError};
#[cfg(target_os = "linux")]
pub use vcpu::{Vcpu, VcpuRunExit};
