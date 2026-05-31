//! Guest init library: cmdline parsing + (linux) mount/exec helpers (SPEC-1 FR-5).
pub mod cmdline;
pub use cmdline::{InitConfig, Mode};

// The PID-1 runtime (mount, net, exec, fail-fast) is linux-only and added in
// Task 4 behind `cfg(target_os = "linux")`.
