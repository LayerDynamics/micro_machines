//! `mm branch <name> <new-name>` — clone a *running* microVM into a new live machine
//! (SPEC-1 FR-16).
//!
//! Unlike `mm restore` (which boots from a previously-saved snapshot), `branch` acts on
//! the *live* source: it snapshots the running guest in place (a brief pause to capture +
//! dump RAM, then the source resumes — see `Machine::snapshot_in_place`) and boots a
//! fresh machine from that image. The source keeps running throughout. The clone resumes
//! with the source's captured internal IP, so it is launched in its **own network
//! namespace** with that IP NAT'd to a unique host-routable `clone_ip` (SPEC-1 FR-16
//! per-clone networking): the clone is reachable at `clone_ip` while the source stays
//! reachable at its own IP, no collision. `mm rm` of the clone tears the netns down.
//!
//! (The near-zero-pause write-protected branch engine — `Machine::branch`, which arms
//! userfaultfd to copy RAM concurrently — needs the uffd created outside the jailed
//! worker to stay within the VMM seccomp sandbox; that's a follow-up. The in-place
//! snapshot path here needs no userfaultfd and works through the jail today.)
use std::collections::BTreeSet;

use anyhow::{Context, Result};
use mm_api_types::{ObjectMeta, State};
use mm_host::control_proto::ControlRequest;
use mm_host::{restore_launch, CloneNetConfig, RestoreSpec, SNAPSHOT_BUCKET};
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
    // Pre-flight in a scope so this store handle is dropped before `request_snapshot`,
    // which opens the same exclusive single-writer redb store internally (holding it
    // across that call would self-deadlock with "Database already open"). Capture the
    // source's internal IP and allocate this clone a unique veth slot + host-routable
    // clone_ip so it never collides with the still-running source.
    let (internal_ip, clone_index, clone_ip) = {
        let store = crate::commands::open_store()?;
        if store.get(&args.new_name)?.is_some() {
            anyhow::bail!("a machine named {} already exists", args.new_name);
        }
        let src = store
            .get(&args.name)?
            .ok_or_else(|| anyhow::anyhow!("no such machine: {}", args.name))?;
        let internal_ip = src.ip.ok_or_else(|| {
            anyhow::anyhow!("source machine {} has no recorded IP to clone", args.name)
        })?;
        let records = store.list()?;
        // Smallest veth slot not already taken by a live clone.
        let used: BTreeSet<u32> = records.iter().filter_map(|r| r.clone_index).collect();
        let clone_index = (0u32..)
            .find(|i| !used.contains(i))
            .expect("a free clone index exists in u32");
        // A unique host-routable address from the guest /24, disjoint from every machine's
        // IP (the source keeps its internal IP inside the netns; the host reaches the
        // clone here).
        let mut ipam = mm_net::Ipam::new([10, 0, 0], 1);
        for r in &records {
            if let Some(ip) = r.ip {
                ipam.reserve(ip);
            }
        }
        let clone_ip = ipam.allocate().context("clone IP pool exhausted")?;
        (internal_ip, clone_index, clone_ip)
    };

    // 1. Branch the *live* source. The worker uses the near-zero-pause write-protect
    //    engine if the source was booted `--branchable` (its uffd was created pre-confine),
    //    else falls back to a resume-in-place snapshot (brief pause). Either way the source
    //    keeps running and we get the new image's id.
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

    // 3. Boot the clone in its own network namespace, NAT'ing its captured internal IP to
    //    the unique clone_ip so it is host-reachable without colliding with the source.
    let store = crate::commands::open_store()?;
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
        clone_net: Some(CloneNetConfig {
            index: clone_index,
            internal_ip,
            clone_ip,
            upstream: None,
        }),
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
        clone_index: Some(clone_index),
        clone_upstream: None,
    };
    store.put(&record)?;

    if let Some(keep) = args.keep {
        for removed in crate::commands::snapshot::store(&args.name).gc(SNAPSHOT_BUCKET, keep)? {
            eprintln!("gc: removed {removed}");
        }
    }

    println!("{}\t{}", args.new_name, outcome.ip);
    println!(
        "branched live from {} (id {id}); the source keeps running. the clone is reachable \
         at {} (its own netns) and over its vsock with: mm exec {} -- <cmd>",
        args.name, outcome.ip, args.new_name
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
