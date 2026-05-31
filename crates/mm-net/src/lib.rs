//! Host networking for MicroMachines microVMs (SPEC-1 FR-10/FR-11).
//!
//! The IPAM and boot-param logic is pure and unsafe-free on every host. The
//! privileged bridge/TAP plumbing (Task 9) is Linux-only and needs raw `ioctl`s
//! for `/dev/net/tun`, so `unsafe` is forbidden everywhere *except* the Linux
//! host module.
#![cfg_attr(not(target_os = "linux"), forbid(unsafe_code))]

pub mod bootparam;
pub mod ipam;
pub use bootparam::ip_cmdline;
pub use ipam::{Ipam, IpamError};

// The bridge/TAP host plumbing (privileged, linux-only).
#[cfg(target_os = "linux")]
pub mod host;
#[cfg(target_os = "linux")]
pub use host::{create_tap, enable_nat, ensure_bridge, teardown_tap, HostNetError, Tap};
