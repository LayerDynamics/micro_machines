//! `mm-host` — shared host actuation for MicroMachines.
//!
//! Turns an OCI image into a booted, jailed, network-reachable microVM by composing
//! the M1 crates ([`mm_image`], [`mm_net`], [`mm_sandbox`], [`mm_vmm`]). This is the
//! exact boot path `mm run` used in M1, lifted out of the CLI binary so the cluster
//! agent (M2) reuses it verbatim rather than re-deriving the privileged
//! parent/jailed-worker/fd-passing machinery.
//!
//! Two entry points, decoupled from any registry:
//! - [`launch`] — the privileged parent: build + wire + spawn the jailed worker,
//!   returning a [`LaunchOutcome`] the caller persists however it likes.
//! - [`run_worker`] — the body of the internal `__vmm-worker` re-exec target; the
//!   binary that calls [`launch`] must also expose this subcommand, since `launch`
//!   re-execs `current_exe() __vmm-worker`.
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Child;

mod config;
/// Parent↔worker control-channel wire protocol (live snapshot/branch). Pure; the `mm`
/// CLI uses it as the client and the worker as the server.
pub mod control_proto;
#[cfg(target_os = "linux")]
mod launch;
mod worker;

pub use config::{build_vm_config, default_name, mac_from_ip, NETMASK};
pub use worker::{run as run_worker, WorkerArgs};

/// The `SnapshotStore` machine-bucket used for a single host's per-VM snapshots. The
/// per-VM jail already scopes snapshots to one machine, so a fixed bucket name is used
/// on both sides: the worker writes `<chroot>/snapshots/<bucket>/<id>` and the CLI reads
/// `<jail_root>/snapshots/<bucket>/<id>` — the same directory.
pub const SNAPSHOT_BUCKET: &str = "local";

/// Everything needed to boot one microVM, decoupled from any registry. The caller
/// resolves the machine name + the IPs already in use (so launch never reads a
/// store) and the on-disk locations of the kernel, mm-init, and optional sshd.
pub struct LaunchSpec {
    /// OCI image reference to boot.
    pub image: String,
    /// Machine name (already resolved + collision-checked by the caller).
    pub name: String,
    pub cpus: u8,
    pub memory_mib: u64,
    /// Boot an SSH-reachable sandbox shell rather than the image's workload.
    pub ssh: bool,
    /// Run the worker in its own session (background) and return immediately.
    pub detach: bool,
    /// Root directory for host state (images cache + per-VM jails + managed SSH key).
    pub state_root: PathBuf,
    /// Guest kernel image (hardlinked/copied into the jail as `/vmlinux`).
    pub kernel_path: PathBuf,
    /// Guest `mm-init` binary, injected into the rootfs as `/init`.
    pub mm_init_path: PathBuf,
    /// Optional static sshd injected as `/sbin/dropbear`; `None` boots without SSH.
    pub sshd_path: Option<PathBuf>,
    /// IPs already allocated to other machines, used to seed the IPAM pool so the new
    /// machine gets a free address.
    pub reserved_ips: Vec<Ipv4Addr>,
}

/// Everything needed to restore a microVM from a snapshot directory into a fresh jail.
/// Unlike [`LaunchSpec`] there is no OCI image — the guest comes from the snapshot's
/// memory + state; the caller supplies the source machine's rootfs + kernel (the device
/// set must match the snapshot) and the snapshot directory.
pub struct RestoreSpec {
    /// New machine name (already resolved + collision-checked by the caller).
    pub name: String,
    /// Snapshot directory holding `manifest.json` + `state.bin` + `memory.bin`.
    pub snapshot_dir: PathBuf,
    /// The source machine's rootfs image (linked into the new jail as `/rootfs.ext4`).
    pub rootfs_path: PathBuf,
    /// Guest kernel (linked into the new jail as `/vmlinux`).
    pub kernel_path: PathBuf,
    pub cpus: u8,
    pub memory_mib: u64,
    /// Run the worker detached (its own session) and return immediately.
    pub detach: bool,
    /// Root directory for host state (per-VM jails + managed SSH key).
    pub state_root: PathBuf,
    /// IPs already allocated to other machines, to seed the IPAM pool.
    pub reserved_ips: Vec<Ipv4Addr>,
}

/// The result of a successful [`launch`] — what the caller persists.
pub struct LaunchOutcome {
    pub name: String,
    pub ip: Ipv4Addr,
    pub tap_name: String,
    /// PID of the spawned jailed worker (the handle a caller's `stop` signals).
    pub pid: u32,
    /// File the detached guest console is written to.
    pub console_log: PathBuf,
    /// Host Unix-domain socket the vsock exec bridge listens on; connect here and
    /// speak the `CONNECT <port>\n` handshake to reach a guest vsock port (FR-13).
    pub vsock_path: PathBuf,
    /// Host Unix-domain socket the worker's control channel listens on; connect here and
    /// speak the control protocol (`SNAPSHOT`/`BRANCH`) to act on the live guest
    /// (FR-14/FR-16). See [`control_proto`](crate::control_proto).
    pub control_path: PathBuf,
    /// Handle to the spawned jailed worker. Wait on it to serve the guest in the
    /// foreground; drop it to leave the detached worker running in its own session.
    pub child: Child,
}

/// Boot a microVM per `spec`, returning the running outcome. Linux/KVM only; on
/// other platforms this returns an error (the rest of the library still compiles so
/// logic/unit tests run anywhere).
pub fn launch(spec: &LaunchSpec) -> anyhow::Result<LaunchOutcome> {
    #[cfg(target_os = "linux")]
    {
        launch::launch(spec)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = spec;
        anyhow::bail!("booting a microVM requires a Linux/KVM host")
    }
}

/// Restore a microVM from a snapshot directory into a fresh jail (SPEC-1 FR-14), the
/// counterpart of [`launch`] for `mm restore`/`mm branch`. Linux/KVM only.
pub fn restore_launch(spec: &RestoreSpec) -> anyhow::Result<LaunchOutcome> {
    #[cfg(target_os = "linux")]
    {
        launch::restore_launch(spec)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = spec;
        anyhow::bail!("restoring a microVM requires a Linux/KVM host")
    }
}
