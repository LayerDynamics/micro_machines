//! `mm run` — build a rootfs, wire networking, harden, and boot a microVM.
//!
//! A thin adapter over [`mm_host::launch`]: it resolves CLI inputs and the on-disk
//! kernel/init/sshd locations, seeds the IP pool from the local registry, then
//! records the launched machine. All the privileged boot orchestration lives in
//! `mm-host` so the cluster agent reuses the exact same path.
use std::path::PathBuf;

use anyhow::{Context, Result};
use mm_api_types::{ObjectMeta, State};
use mm_host::LaunchSpec;
use time::OffsetDateTime;

use crate::store::MachineRecord;

/// Arguments for `mm run`.
#[derive(Debug, clap::Args)]
pub struct RunArgs {
    /// OCI image reference (e.g. `docker.io/library/alpine:latest`).
    pub image: String,
    /// Number of virtual CPUs.
    #[arg(long, default_value_t = 1)]
    pub cpus: u8,
    /// Memory in MiB.
    #[arg(long, default_value_t = 512)]
    pub memory: u64,
    /// Machine name (defaults to a name derived from the image).
    #[arg(long)]
    pub name: Option<String>,
    /// Boot into an SSH-reachable sandbox shell rather than the image workload.
    #[arg(long)]
    pub ssh: bool,
    /// Run the microVM in the background (its own session) and return immediately,
    /// capturing the guest console to a per-VM log, instead of staying foreground.
    #[arg(long, short = 'd')]
    pub detach: bool,
    /// Boot "branchable" (SPEC-1 FR-16): prepare the running-BRANCH userfaultfd at boot so
    /// a later `mm branch` of this machine uses the near-zero-pause write-protect engine
    /// instead of an in-place snapshot. The default (non-branchable) `mm branch` falls back
    /// to the resume-in-place snapshot. Off by default.
    #[arg(long)]
    pub branchable: bool,
}

/// Path to the guest kernel (`MM_KERNEL`, else `<root>/vmlinux`).
pub(crate) fn kernel_path() -> PathBuf {
    std::env::var_os("MM_KERNEL")
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::commands::state_root().join("vmlinux"))
}

/// Path to the guest `mm-init` binary injected as `/init` (`MM_INIT`, else
/// `<root>/mm-init`). Provisioned alongside the kernel, mirroring `kernel_path`.
fn mm_init_path() -> PathBuf {
    std::env::var_os("MM_INIT")
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::commands::state_root().join("mm-init"))
}

/// Path to the static sshd injected as `/sbin/dropbear` (`MM_SSHD`, else
/// `<root>/dropbear`). Returns `None` when no sshd is provisioned, in which case the
/// guest simply boots without SSH (the rest of `mm run` is unaffected).
fn mm_sshd_path() -> Option<PathBuf> {
    let path = std::env::var_os("MM_SSHD")
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::commands::state_root().join("dropbear"));
    path.exists().then_some(path)
}

pub fn run(args: RunArgs) -> Result<()> {
    let store = crate::commands::open_store()?;

    // Resolve the name and reject a collision before doing any work.
    let name = args
        .name
        .clone()
        .unwrap_or_else(|| mm_host::default_name(&args.image));
    if store.get(&name)?.is_some() {
        anyhow::bail!("a machine named {name} already exists");
    }
    // Seed the IP pool from already-known machines so the new one gets a free IP.
    let reserved_ips = store.list()?.into_iter().filter_map(|rec| rec.ip).collect();

    let spec = LaunchSpec {
        image: args.image.clone(),
        name: name.clone(),
        cpus: args.cpus,
        memory_mib: args.memory,
        ssh: args.ssh,
        detach: args.detach,
        state_root: crate::commands::state_root(),
        kernel_path: kernel_path(),
        mm_init_path: mm_init_path(),
        sshd_path: mm_sshd_path(),
        reserved_ips,
        branchable: args.branchable,
    };
    let mut outcome = mm_host::launch(&spec).context("launching microVM")?;

    // Record as running and report.
    let record = MachineRecord {
        meta: ObjectMeta::new(&name, "default", OffsetDateTime::now_utc()),
        state: State::Running,
        image: args.image.clone(),
        vcpus: args.cpus,
        memory_mib: args.memory,
        ip: Some(outcome.ip),
        tap: Some(outcome.tap_name.clone()),
        pid: Some(outcome.pid),
        clone_index: None,
        clone_upstream: None,
    };
    store.put(&record)?;
    println!("{name}\t{}", outcome.ip);

    if args.detach {
        // The worker runs in its own session; leave it running and return.
        println!(
            "detached; guest console -> {}",
            outcome.console_log.display()
        );
        return Ok(());
    }

    // Foreground: wait for the worker, then mark stopped.
    let status = outcome.child.wait().context("waiting for the VMM worker")?;
    if !status.success() {
        tracing::warn!("VMM worker exited with {status}");
    }
    let mut stopped = record;
    stopped.state = State::Stopped;
    stopped.pid = None;
    store.put(&stopped)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_run_flags() {
        use clap::Parser;
        #[derive(Parser)]
        struct Wrap {
            #[command(subcommand)]
            cmd: Cmd,
        }
        #[derive(clap::Subcommand)]
        enum Cmd {
            Run(RunArgs),
        }
        let Wrap {
            cmd: Cmd::Run(args),
        } = Wrap::try_parse_from([
            "mm",
            "run",
            "alpine:latest",
            "--cpus",
            "4",
            "--memory",
            "1024",
            "--name",
            "x",
            "--ssh",
        ])
        .unwrap();
        assert_eq!(args.image, "alpine:latest");
        assert_eq!(args.cpus, 4);
        assert_eq!(args.memory, 1024);
        assert_eq!(args.name.as_deref(), Some("x"));
        assert!(args.ssh);
    }
}
