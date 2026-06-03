//! `mm snapshot` — create/list/remove/gc snapshots of a single-host microVM (FR-14).
//!
//! `create` connects to the running machine's worker control socket
//! (`<state_root>/jails/<name>/control.sock`) and asks it to snapshot the *live* guest;
//! the worker allocates the id and writes the snapshot into its in-jail store, which the
//! CLI then reads for `ls`/`rm`/`gc` at `<state_root>/jails/<name>/root/snapshots/<bucket>`.
//! (Cluster-routed snapshots — `--server` — are the control plane's `Snapshot` resource.)
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use mm_host::control_proto::{ControlRequest, ControlResponse};
use mm_host::SNAPSHOT_BUCKET;
use mm_vmm::snapshot::SnapshotStore;

#[derive(Debug, clap::Args)]
pub struct SnapshotArgs {
    #[command(subcommand)]
    pub cmd: SnapshotCmd,
}

#[derive(Debug, clap::Subcommand)]
pub enum SnapshotCmd {
    /// Snapshot a running machine (freeze → capture → resume), printing the new id.
    Create {
        /// Machine name.
        name: String,
        /// After creating, keep only the N newest snapshots (garbage-collect the rest).
        #[arg(long)]
        keep: Option<usize>,
    },
    /// List a machine's snapshots, newest first.
    Ls {
        /// Machine name.
        name: String,
    },
    /// Remove a snapshot by id.
    Rm {
        /// Machine name.
        name: String,
        /// Snapshot id (from `mm snapshot ls`).
        id: String,
    },
    /// Keep the N newest snapshots, removing the rest.
    Gc {
        /// Machine name.
        name: String,
        /// Number of newest snapshots to keep.
        #[arg(long)]
        keep: usize,
    },
}

/// The per-VM jail directory (`<state_root>/jails/<name>`).
pub(crate) fn jail_dir(name: &str) -> PathBuf {
    crate::commands::state_root().join("jails").join(name)
}

/// A `SnapshotStore` over the machine's in-jail snapshot dir, where the jailed worker
/// writes (so the CLI reads exactly what the worker wrote).
pub(crate) fn store(name: &str) -> SnapshotStore {
    SnapshotStore::new(jail_dir(name).join("root"))
}

/// Connect to a worker control UDS, send one request, and return its parsed response.
pub(crate) fn send_control(path: &Path, req: &ControlRequest) -> Result<ControlResponse> {
    let mut conn = UnixStream::connect(path)
        .with_context(|| format!("connecting to control socket {}", path.display()))?;
    // A live branch copies all of guest RAM before replying, so allow generous time.
    conn.set_read_timeout(Some(Duration::from_secs(180))).ok();
    conn.write_all(req.encode().as_bytes())?;
    conn.flush()?;
    let mut line = String::new();
    BufReader::new(&conn).read_line(&mut line)?;
    ControlResponse::parse(line.trim_end()).map_err(|e| anyhow::anyhow!(e))
}

/// Ask the running machine's worker to perform `req` (a snapshot or branch) on the live
/// guest, returning the worker-allocated snapshot id.
pub(crate) fn request_snapshot(name: &str, req: ControlRequest) -> Result<String> {
    let record = crate::commands::open_store()?
        .get(name)?
        .ok_or_else(|| anyhow::anyhow!("no such machine: {name}"))?;
    if record.pid.is_none() {
        anyhow::bail!("machine {name} is not running");
    }
    let control = jail_dir(name).join("control.sock");
    if !control.exists() {
        anyhow::bail!(
            "machine {name} has no control socket at {} (is it running?)",
            control.display()
        );
    }
    match send_control(&control, &req)? {
        ControlResponse::Ok { id } => Ok(id),
        ControlResponse::Err { msg } => anyhow::bail!("{msg}"),
    }
}

pub fn run(args: SnapshotArgs) -> Result<()> {
    match args.cmd {
        SnapshotCmd::Create { name, keep } => {
            let id = request_snapshot(&name, ControlRequest::Snapshot)
                .with_context(|| format!("snapshotting {name}"))?;
            println!("{id}");
            if let Some(keep) = keep {
                for removed in store(&name).gc(SNAPSHOT_BUCKET, keep)? {
                    eprintln!("gc: removed {removed}");
                }
            }
            Ok(())
        }
        SnapshotCmd::Ls { name } => {
            let snaps = store(&name)
                .list(SNAPSHOT_BUCKET)
                .with_context(|| format!("listing snapshots for {name}"))?;
            if snaps.is_empty() {
                println!("no snapshots for {name}");
                return Ok(());
            }
            let (id_h, ram_h, kind_h) = ("ID", "RAM(MiB)", "KIND");
            println!("{id_h:<22}  {ram_h:>9}  {kind_h}");
            for s in snaps {
                let (id, ram, kind) = (&s.id, s.manifest.memory_mib, s.manifest.kind);
                println!("{id:<22}  {ram:>9}  {kind:?}");
            }
            Ok(())
        }
        SnapshotCmd::Rm { name, id } => {
            store(&name)
                .remove(SNAPSHOT_BUCKET, &id)
                .with_context(|| format!("removing snapshot {id}"))?;
            println!("removed {id}");
            Ok(())
        }
        SnapshotCmd::Gc { name, keep } => {
            let removed = store(&name)
                .gc(SNAPSHOT_BUCKET, keep)
                .with_context(|| format!("gc snapshots for {name}"))?;
            for id in &removed {
                println!("removed {id}");
            }
            println!("kept the {keep} newest");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_control_round_trips_over_uds() {
        // A fake control server (a plain UDS) verifies the client's framing: it writes
        // one request line and reads one response line. No worker/KVM.
        let dir = std::env::temp_dir().join(format!("mm-ctl-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("control.sock");
        let _ = std::fs::remove_file(&sock);
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&conn).read_line(&mut line).unwrap();
            assert_eq!(line.trim_end(), "SNAPSHOT");
            conn.write_all(b"OK 00000000000000000007\n").unwrap();
        });

        let resp = send_control(&sock, &ControlRequest::Snapshot).unwrap();
        assert_eq!(
            resp,
            ControlResponse::Ok {
                id: "00000000000000000007".into()
            }
        );
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
