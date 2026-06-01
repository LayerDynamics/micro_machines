//! Host-side sandbox for MicroMachines microVMs (SPEC-1 FR-27).
//!
//! Two layers of defense are applied before any guest code runs:
//! * the **jailer** ([`jailer`], linux-only) confines the VMM process with mount/
//!   pid/net namespaces, a chroot into a per-VM root, cgroup v2 cpu/memory limits,
//!   and a drop to an unprivileged uid/gid;
//! * a per-thread **seccomp-BPF** allowlist ([`seccomp`]) restricts each VMM/vCPU
//!   thread to the syscalls it actually needs before the first `vcpu.run()`.
//!
//! The seccomp allowlist is cross-platform data (testable anywhere); compiling and
//! installing it, and the jailer, are Linux-only.
pub mod seccomp;
pub use seccomp::{vmm_thread_rules, SeccompAllowlist, SeccompError};

/// Host<->guest exec wire protocol for Sandbox Mode (cross-platform).
pub mod exec;

#[cfg(target_os = "linux")]
pub mod jailer;
#[cfg(target_os = "linux")]
pub use jailer::{apply_cgroup_limits, confine, CgroupLimits, JailSpec, JailerError};
