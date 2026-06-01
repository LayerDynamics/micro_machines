//! Actuation: turn a controller assignment into a real microVM (SPEC-1 FR-17/FR-19).
//!
//! This is the agent's bridge to the host. It reuses the exact M1 boot path via
//! [`mm_host::launch`] (build rootfs → IPAM → bridge/TAP/NAT → jail → boot the
//! `__vmm-worker`), so a machine the controller schedules here boots identically to
//! a local `mm run`. Booting is Linux/KVM only; the mapping + record types are
//! cross-platform so the logic is testable anywhere.
use std::path::PathBuf;

use anyhow::Result;

use crate::local_store::LocalMachine;

/// Host-specific paths the actuator needs, resolved once at agent startup.
#[derive(Debug, Clone)]
pub struct HostConfig {
    /// Root for host state (image cache + per-VM jails + managed SSH key).
    pub state_root: PathBuf,
    /// Guest kernel image.
    pub kernel_path: PathBuf,
    /// Guest `mm-init` binary (injected as `/init`).
    pub mm_init_path: PathBuf,
    /// Optional static sshd injected as `/sbin/dropbear`.
    pub sshd_path: Option<PathBuf>,
}

/// A request to boot one machine, distilled from a controller `Assignment`.
#[derive(Debug, Clone)]
pub struct BootRequest {
    pub uid: String,
    pub namespace: String,
    pub name: String,
    pub image: String,
    pub cpus: u8,
    pub memory_mib: u64,
    pub ssh: bool,
}

/// Boot the requested machine, returning the local record to persist + report. The
/// worker runs detached (its own session) so the agent keeps serving other RPCs.
/// `reserved_ips` are the addresses other machines on this host already hold.
pub fn boot(
    host: &HostConfig,
    req: &BootRequest,
    reserved_ips: Vec<std::net::Ipv4Addr>,
) -> Result<LocalMachine> {
    let spec = mm_host::LaunchSpec {
        image: req.image.clone(),
        name: req.name.clone(),
        cpus: req.cpus,
        memory_mib: req.memory_mib,
        ssh: req.ssh,
        detach: true,
        state_root: host.state_root.clone(),
        kernel_path: host.kernel_path.clone(),
        mm_init_path: host.mm_init_path.clone(),
        sshd_path: host.sshd_path.clone(),
        reserved_ips,
    };
    let outcome = mm_host::launch(&spec)?;
    Ok(LocalMachine {
        uid: req.uid.clone(),
        namespace: req.namespace.clone(),
        name: req.name.clone(),
        image: req.image.clone(),
        vcpus: u32::from(req.cpus),
        memory_mib: req.memory_mib,
        ip: Some(outcome.ip.to_string()),
        pid: Some(outcome.pid),
        state: "running".to_string(),
    })
}

/// Stop a running machine by terminating its jailed worker. The worker's
/// `PR_SET_PDEATHSIG` cascade tears down the whole VMM tree and releases its TAP.
/// Idempotent: a missing process is treated as already stopped.
pub fn stop(machine: &LocalMachine) {
    #[cfg(target_os = "linux")]
    if let Some(pid) = machine.pid {
        // SAFETY: kill(2) with a pid + SIGTERM is always safe; ESRCH (gone) is fine.
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGTERM);
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = machine;
}

/// Stop the machine and clean up its host resources (TAP + per-instance overlay), so
/// the host is left as if the machine never ran. Idempotent.
pub fn destroy(machine: &LocalMachine, host: &HostConfig) {
    stop(machine);
    #[cfg(target_os = "linux")]
    {
        let tap = format!("mm-{}", machine.name);
        if let Err(e) = mm_net::teardown_tap(&tap) {
            tracing::warn!("removing TAP {tap}: {e}");
        }
        let images = mm_image::ImageStore::new(&host.state_root);
        if let Err(e) = images.remove_instance_overlay(&machine.name) {
            tracing::warn!("removing overlay for {}: {e}", machine.name);
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = host;
}
