//! `mm branch <name> <new-name>` — clone a *running* microVM into a new live machine
//! (SPEC-1 FR-16).
//!
//! Unlike `mm restore` (which boots from a previously-saved snapshot), `branch` acts on
//! the *live* source: its worker arms write-protection and materializes a coherent
//! point-in-time image **without freezing the source for a RAM dump** (the source keeps
//! running), then a fresh machine is booted from that branch image. The clone resumes
//! with the IP captured in the source's RAM, so — exactly like `mm restore` — don't rely
//! on two machines sharing that IP at once (re-IP-per-clone is a follow-up); reach the
//! clone over its own vsock bridge with `mm exec`.
use anyhow::{Context, Result};
use mm_api_types::{ObjectMeta, State};
use mm_host::control_proto::ControlRequest;
use mm_host::{restore_launch, RestoreSpec, SNAPSHOT_BUCKET};
use time::OffsetDateTime;

use crate::store::MachineRecord;

#[derive(Debug, clap::Args)]
pub struct BranchArgs {
    /// Source machine to clone (must be running).
    pub name: String,
    /// Name for the new cloned machine.
    pub new_name: String,
    /// After branching, keep only the N newest snapshots of the source (gc the rest).
    #[arg(long)]
    pub keep: Option<usize>,
}

pub fn run(args: BranchArgs) -> Result<()> {
    let store = crate::commands::open_store()?;
    if store.get(&args.new_name)?.is_some() {
        anyhow::bail!("a machine named {} already exists", args.new_name);
    }

    // 1. Branch the *live* source guest: the worker arms WP + copies RAM concurrently and
    //    returns the new branch id (the source keeps running throughout).
    let id = crate::commands::snapshot::request_snapshot(&args.name, ControlRequest::Branch)
        .with_context(|| format!("branching {}", args.name))?;

    // 2. Locate the branch dir (in the source's in-jail store) and the source's rootfs —
    //    the clone reuses the same device set.
    let snap = crate::commands::snapshot::store(&args.name)
        .find(SNAPSHOT_BUCKET, &id)
        .with_context(|| format!("looking up branch {id}"))?
        .ok_or_else(|| anyhow::anyhow!("branch {id} of {} disappeared", args.name))?;
    let src_root = crate::commands::snapshot::jail_dir(&args.name).join("root");
    let rootfs = src_root.join("rootfs.ext4");
    if !rootfs.exists() {
        anyhow::bail!(
            "source machine {}'s rootfs is missing at {} (was it removed?)",
            args.name,
            rootfs.display()
        );
    }

    // 3. Boot a fresh machine from the branch image — a live clone of the source.
    let reserved_ips = store.list()?.into_iter().filter_map(|r| r.ip).collect();
    let spec = RestoreSpec {
        name: args.new_name.clone(),
        snapshot_dir: snap.dir.clone(),
        rootfs_path: rootfs,
        kernel_path: crate::commands::run::kernel_path(),
        cpus: snap.manifest.vcpu_count,
        memory_mib: snap.manifest.memory_mib,
        // Clones run as detached, server-like resumes.
        detach: true,
        state_root: crate::commands::state_root(),
        reserved_ips,
    };
    let outcome = restore_launch(&spec)
        .with_context(|| format!("booting clone {} from branch {id}", args.new_name))?;

    let record = MachineRecord {
        meta: ObjectMeta::new(&args.new_name, "default", OffsetDateTime::now_utc()),
        state: State::Running,
        image: format!("branch:{}/{}", args.name, id),
        vcpus: snap.manifest.vcpu_count,
        memory_mib: snap.manifest.memory_mib,
        ip: Some(outcome.ip),
        tap: Some(outcome.tap_name.clone()),
        pid: Some(outcome.pid),
    };
    store.put(&record)?;

    if let Some(keep) = args.keep {
        for removed in crate::commands::snapshot::store(&args.name).gc(SNAPSHOT_BUCKET, keep)? {
            eprintln!("gc: removed {removed}");
        }
    }

    println!("{}\t{}", args.new_name, outcome.ip);
    println!(
        "branched live from {} (id {id}); the source keeps running. \
         reach the clone with: mm exec {} -- <cmd>",
        args.name, args.new_name
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Wrap {
        #[command(subcommand)]
        cmd: Cmd,
    }
    #[derive(clap::Subcommand)]
    enum Cmd {
        Branch(BranchArgs),
    }

    #[test]
    fn parses_branch_args() {
        let Wrap {
            cmd: Cmd::Branch(args),
        } = Wrap::try_parse_from(["mm", "branch", "web", "web-clone"]).unwrap();
        assert_eq!(args.name, "web");
        assert_eq!(args.new_name, "web-clone");
        assert_eq!(args.keep, None);
    }

    #[test]
    fn parses_branch_args_with_keep() {
        let Wrap {
            cmd: Cmd::Branch(args),
        } = Wrap::try_parse_from(["mm", "branch", "web", "web-clone", "--keep", "3"]).unwrap();
        assert_eq!(args.keep, Some(3));
    }
}
