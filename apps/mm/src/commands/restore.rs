//! `mm restore <name> <id> <new-name>` — boot a fresh microVM from a snapshot (FR-14).
//!
//! Restores snapshot `<id>` of machine `<name>` into a new machine `<new-name>`: the
//! guest resumes from the snapshot's captured memory + device + vCPU state, reusing the
//! source's rootfs and kernel. The restored guest comes back with the IP captured in its
//! RAM, so don't run two machines on that IP at once (re-IP-per-clone is a follow-up);
//! reach the restored machine over its own vsock bridge with `mm exec`.
use anyhow::{Context, Result};
use mm_api_types::{ObjectMeta, State};
use mm_host::{restore_launch, RestoreSpec, SNAPSHOT_BUCKET};
use time::OffsetDateTime;

use crate::store::MachineRecord;

#[derive(Debug, clap::Args)]
pub struct RestoreArgs {
    /// Source machine whose snapshot to restore.
    pub name: String,
    /// Snapshot id (from `mm snapshot ls <name>`).
    pub id: String,
    /// Name for the new restored machine.
    pub new_name: String,
}

pub fn run(args: RestoreArgs) -> Result<()> {
    let store = crate::commands::open_store()?;
    if store.get(&args.new_name)?.is_some() {
        anyhow::bail!("a machine named {} already exists", args.new_name);
    }

    // Locate the snapshot dir (in the source machine's in-jail store) and the source
    // machine's rootfs (the restored guest reuses the same device set).
    let snap = crate::commands::snapshot::store(&args.name)
        .find(SNAPSHOT_BUCKET, &args.id)
        .with_context(|| format!("looking up snapshot {}", args.id))?
        .ok_or_else(|| anyhow::anyhow!("no snapshot {} for machine {}", args.id, args.name))?;
    let src_root = crate::commands::snapshot::jail_dir(&args.name).join("root");
    let rootfs = src_root.join("rootfs.ext4");
    if !rootfs.exists() {
        anyhow::bail!(
            "source machine {}'s rootfs is missing at {} (was it removed?)",
            args.name,
            rootfs.display()
        );
    }

    let reserved_ips = store.list()?.into_iter().filter_map(|r| r.ip).collect();
    let spec = RestoreSpec {
        name: args.new_name.clone(),
        snapshot_dir: snap.dir.clone(),
        rootfs_path: rootfs,
        kernel_path: crate::commands::run::kernel_path(),
        cpus: snap.manifest.vcpu_count,
        memory_mib: snap.manifest.memory_mib,
        // Restored machines run as detached, server-like resumes.
        detach: true,
        state_root: crate::commands::state_root(),
        reserved_ips,
    };
    let outcome = restore_launch(&spec)
        .with_context(|| format!("restoring snapshot {} of {}", args.id, args.name))?;

    let record = MachineRecord {
        meta: ObjectMeta::new(&args.new_name, "default", OffsetDateTime::now_utc()),
        state: State::Running,
        image: format!("restore:{}/{}", args.name, args.id),
        vcpus: snap.manifest.vcpu_count,
        memory_mib: snap.manifest.memory_mib,
        ip: Some(outcome.ip),
        tap: Some(outcome.tap_name.clone()),
        pid: Some(outcome.pid),
    };
    store.put(&record)?;
    println!("{}\t{}", args.new_name, outcome.ip);
    println!(
        "restored from {}/{}; reach it with: mm exec {} -- <cmd>",
        args.name, args.id, args.new_name
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
        Restore(RestoreArgs),
    }

    #[test]
    fn parses_restore_args() {
        let Wrap {
            cmd: Cmd::Restore(args),
        } = Wrap::try_parse_from(["mm", "restore", "web", "00000000000000000007", "web-clone"])
            .unwrap();
        assert_eq!(args.name, "web");
        assert_eq!(args.id, "00000000000000000007");
        assert_eq!(args.new_name, "web-clone");
    }
}
