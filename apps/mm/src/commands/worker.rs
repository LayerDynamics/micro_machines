//! `mm __vmm-worker` — the jailed VMM child (internal; not a user-facing command).
//!
//! Spawned by `mm run` after the privileged parent has built the rootfs, wired the
//! bridge/TAP/NAT, opened `/dev/kvm`, and prepared a chroot. This process inherits
//! the KVM + TAP fds, **confines itself** (cgroup v2 + mount/pid/net namespaces +
//! chroot + `no_new_privs` + drop to an unprivileged uid/gid), installs a
//! per-thread seccomp filter, and only then runs guest code (SPEC-1 FR-27). Because
//! the fds are passed in, the confined process never needs to open `/dev/kvm` or
//! `/dev/net/tun` after dropping privilege.
use std::path::PathBuf;

use anyhow::Result;

#[derive(Debug, clap::Args)]
pub struct WorkerArgs {
    /// Path to the serialized worker VM config (read before chrooting).
    #[arg(long)]
    pub config: PathBuf,
    /// Inherited `/dev/kvm` file descriptor number.
    #[arg(long)]
    pub kvm_fd: i32,
    /// Inherited TAP file descriptor number.
    #[arg(long)]
    pub tap_fd: i32,
    /// Per-VM chroot root.
    #[arg(long)]
    pub chroot: PathBuf,
    /// Unprivileged uid to drop to.
    #[arg(long)]
    pub uid: u32,
    /// Unprivileged gid to drop to.
    #[arg(long)]
    pub gid: u32,
    /// cgroup v2 leaf name.
    #[arg(long)]
    pub cgroup: String,
    /// `cpu.max` value (`"<quota_us> <period_us>"`).
    #[arg(long)]
    pub cpu_max: String,
    /// `memory.max` in bytes.
    #[arg(long)]
    pub mem_max: u64,
    /// Also enter a user namespace (maps inner-root to the unprivileged uid/gid).
    #[arg(long)]
    pub user_namespace: bool,
}

pub fn run(args: WorkerArgs) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::run(args)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        anyhow::bail!("the internal VMM worker is Linux-only");
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::{Context, Result};
    use mm_sandbox::{CgroupLimits, JailSpec};
    use mm_vmm::{Machine, VcpuHook, VmConfig, VmmError};

    use super::WorkerArgs;

    pub fn run(args: WorkerArgs) -> Result<()> {
        // Read + parse the config while still privileged and outside the chroot.
        let bytes = std::fs::read(&args.config)
            .with_context(|| format!("reading worker config {}", args.config.display()))?;
        let config: VmConfig =
            serde_json::from_slice(&bytes).context("parsing worker VM config")?;

        // Confine: cgroup v2 + namespaces + chroot + no_new_privs + uid/gid drop.
        // After this returns the process is unprivileged and isolated; it relies on
        // the inherited fds for KVM and the TAP.
        let spec = JailSpec {
            chroot_dir: args.chroot.clone(),
            uid: args.uid,
            gid: args.gid,
            cgroup: CgroupLimits {
                name: args.cgroup.clone(),
                cpu_max: args.cpu_max.clone(),
                memory_max_bytes: args.mem_max,
            },
            user_namespace: args.user_namespace,
        };
        mm_sandbox::confine(&spec).context("confining the VMM process")?;

        // Install the seccomp allowlist on each vCPU thread before it runs guest
        // code. PR_SET_NO_NEW_PRIVS was set by `confine`, so this works post-drop.
        let rules = Arc::new(mm_sandbox::vmm_thread_rules());
        let hook: VcpuHook = {
            let rules = rules.clone();
            Arc::new(move |_idx| {
                rules
                    .apply_to_current_thread()
                    .map_err(|e| VmmError::Device(format!("seccomp install failed: {e}")))
            })
        };

        // Boot using the inherited KVM + TAP fds (the confined process cannot open
        // them itself).
        let mut machine = Machine::boot_jailed(&config, args.kvm_fd, vec![args.tap_fd], Some(hook))
            .context("booting jailed microVM")?;
        let ready = machine
            .wait_for_ready(Duration::from_secs(10))
            .context("waiting for guest readiness")?;
        if ready {
            tracing::info!("guest signaled readiness over vsock");
        } else {
            tracing::warn!("guest did not signal readiness within 10s");
        }

        // Serve the guest for its full lifetime — until it powers itself off (a
        // workload that exits, or `mm stop` killing this process). We must NOT call
        // shutdown() here: that would force the vCPUs to stop right after readiness,
        // tearing down a long-running guest (and releasing its TAP) immediately.
        machine.wait_for_vcpus().context("running microVM")?;
        Ok(())
    }
}
