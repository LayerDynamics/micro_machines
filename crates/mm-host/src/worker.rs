//! The jailed VMM worker (internal; spawned via re-exec by [`crate::launch`]).
//!
//! The privileged parent builds the rootfs, wires the bridge/TAP/NAT, opens
//! `/dev/kvm`, and prepares a chroot, then re-execs the current binary with the
//! `__vmm-worker` subcommand. That child inherits the KVM + TAP fds, **confines
//! itself** (cgroup v2 + mount/pid namespaces + chroot + `no_new_privs` + drop to an
//! unprivileged uid/gid), installs a per-thread seccomp filter, and only then runs
//! guest code (SPEC-1 FR-27). Because the fds are passed in, the confined process
//! never needs to open `/dev/kvm` or `/dev/net/tun` after dropping privilege.
use std::path::PathBuf;

use anyhow::Result;

use crate::control_proto::{ControlRequest, ControlResponse};

/// Map one control request to its response via `act`, which performs the snapshot or
/// branch on the live `Machine` and returns the new snapshot id (or an error message).
/// Pure glue between the wire protocol and the engine — unit-tested without KVM.
// The only non-test caller is the Linux-only worker control loop, so on non-Linux this
// is exercised solely by the unit test; allow it to be "unused" in a non-test build.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn dispatch_control(
    req: &ControlRequest,
    act: &mut impl FnMut(&ControlRequest) -> std::result::Result<String, String>,
) -> ControlResponse {
    match act(req) {
        Ok(id) => ControlResponse::Ok { id },
        Err(msg) => ControlResponse::Err { msg },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_dispatch_maps_requests_to_responses() {
        // A fake "actor" stands in for the live-Machine snapshot/branch, so the
        // request→response mapping (verb dispatch, id echo, error mapping) is tested
        // with no Machine/KVM.
        let mut calls = Vec::new();
        let mut act = |req: &ControlRequest| -> std::result::Result<String, String> {
            calls.push(*req);
            match req {
                ControlRequest::Snapshot => Ok("snap-id".into()),
                ControlRequest::Branch => Err("no branch".into()),
            }
        };
        assert_eq!(
            dispatch_control(&ControlRequest::Snapshot, &mut act),
            ControlResponse::Ok {
                id: "snap-id".into()
            }
        );
        assert_eq!(
            dispatch_control(&ControlRequest::Branch, &mut act),
            ControlResponse::Err {
                msg: "no branch".into()
            }
        );
        assert_eq!(calls.len(), 2);
    }
}

/// Arguments for the internal `__vmm-worker` subcommand. Shared so both the `mm`
/// CLI and the cluster agent can expose the same hidden subcommand and dispatch it
/// to [`run`].
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
    /// Inherited host vsock UDS listener fd number (the exec bridge); absent on the
    /// readiness-only path.
    #[arg(long)]
    pub vsock_fd: Option<i32>,
    /// Inherited control UDS listener fd number (parent↔worker live snapshot/branch
    /// channel); absent when the worker is launched without a control channel.
    #[arg(long)]
    pub control_fd: Option<i32>,
    /// Restore the guest from this snapshot directory (chroot-relative, e.g. `/restore`)
    /// instead of cold-booting from the kernel/rootfs. Set by `mm restore`/`mm branch`.
    #[arg(long)]
    pub restore_dir: Option<PathBuf>,
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

/// Run the jailed worker: confine this process, install seccomp, and serve the
/// guest for its lifetime. Linux-only (KVM); errors elsewhere.
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
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::io::FromRawFd;
    use std::os::unix::net::UnixListener;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use anyhow::{Context, Result};
    use mm_sandbox::{CgroupLimits, JailSpec};
    use mm_vmm::{Machine, VcpuHook, VmConfig, VmmError};

    use mm_vmm::snapshot::SnapshotStore;

    use super::WorkerArgs;
    use crate::control_proto::{ControlRequest, ControlResponse};
    use crate::SNAPSHOT_BUCKET;

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

        // Bring the guest up using the inherited KVM + TAP fds (the confined process
        // cannot open them itself): either cold-boot from the kernel/rootfs, or — when a
        // restore dir was passed — restore the snapshot in that (chroot-relative) dir.
        let machine = match &args.restore_dir {
            Some(dir) => mm_vmm::snapshot::restore(
                &config,
                args.kvm_fd,
                vec![args.tap_fd],
                args.vsock_fd,
                Some(hook),
                dir,
            )
            .context("restoring jailed microVM from snapshot")?,
            // Cold boot. `mm branch` works on any running VM via KVM dirty-page logging
            // (it needs no pre-confine userfaultfd), so there is no separate branchable path.
            None => Machine::boot_jailed(
                &config,
                args.kvm_fd,
                vec![args.tap_fd],
                args.vsock_fd,
                Some(hook),
            )
            .context("booting jailed microVM")?,
        };
        let ready = machine
            .wait_for_ready(Duration::from_secs(10))
            .context("waiting for guest readiness")?;
        if ready {
            tracing::info!("guest signaled readiness over vsock");
        } else {
            tracing::warn!("guest did not signal readiness within 10s");
        }

        // Share the Machine so a control thread can act on the *live* guest while the
        // main thread reaps. The control loop only locks it briefly per request (a
        // snapshot pauses→captures→resumes; a branch arms WP then copies concurrently),
        // and the reaper polls liveness without holding the lock during the wait.
        let machine = Arc::new(Mutex::new(machine));

        if let Some(fd) = args.control_fd {
            // SAFETY: `fd` is the inherited, bound, listening control socket (fd 13);
            // we take sole ownership of it here.
            let listener = unsafe { UnixListener::from_raw_fd(fd) };
            let machine = machine.clone();
            std::thread::Builder::new()
                .name("mm-control".into())
                .spawn(move || serve_control(listener, machine))
                .context("spawning control thread")?;
        }

        // Reaper: serve the guest for its full lifetime — until it powers itself off (a
        // workload that exits, or `mm stop` killing this process). Poll the lock-free
        // power-off signal WITHOUT holding the machine lock (so an in-flight
        // snapshot/branch on the control thread is never blocked), then join the threads.
        // We must NOT call shutdown() here: that would tear down a long-running guest.
        loop {
            let off = machine.lock().map(|m| m.is_powered_off()).unwrap_or(true);
            if off {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        machine
            .lock()
            .expect("machine lock")
            .wait_for_vcpus()
            .context("running microVM")?;
        Ok(())
    }

    /// Serve the parent↔worker control UDS: one request line, one response line per
    /// connection. Each `SNAPSHOT`/`BRANCH` briefly locks the shared `Machine` and runs
    /// the engine into `/snapshots/<dir>` (inside the chroot), then replies `OK <id>` or
    /// `ERR <msg>`. Loops until the listener closes (process teardown).
    fn serve_control(listener: UnixListener, machine: Arc<Mutex<Machine>>) {
        for conn in listener.incoming() {
            let mut conn = match conn {
                Ok(c) => c,
                Err(_) => continue,
            };
            let mut line = String::new();
            if BufReader::new(&conn).read_line(&mut line).is_err() {
                continue;
            }
            let resp = match ControlRequest::parse(line.trim_end()) {
                Ok(req) => {
                    let mut act = |req: &ControlRequest| -> std::result::Result<String, String> {
                        let mut m = machine
                            .lock()
                            .map_err(|_| "machine lock poisoned".to_string())?;
                        // We are chrooted to the jail, so the host state root is "/"; the
                        // worker owns `/snapshots` (writable) and allocates the id itself.
                        let store = SnapshotStore::new("/");
                        let (id, dir) = store
                            .new_snapshot_dir(SNAPSHOT_BUCKET)
                            .map_err(|e| e.to_string())?;
                        match req {
                            // Resume-in-place: the guest keeps running after the snapshot
                            // (a live `mm snapshot`/cluster Snapshot must not freeze it).
                            // The freeze-only `snapshot::snapshot` exits the device/vCPU
                            // workers and is for the restore-into-a-fresh-VM flow only.
                            ControlRequest::Snapshot => m
                                .snapshot_in_place(&dir)
                                .map(|_| id)
                                .map_err(|e| e.to_string()),
                            // Live branch: materialize a coherent point-in-time image of the
                            // running guest via KVM dirty-page logging (the parent keeps
                            // running, paused only briefly at two barriers).
                            ControlRequest::Branch => {
                                m.branch(&dir).map(|_| id).map_err(|e| e.to_string())
                            }
                        }
                    };
                    super::dispatch_control(&req, &mut act)
                }
                Err(e) => ControlResponse::Err { msg: e },
            };
            let _ = conn.write_all(resp.encode().as_bytes());
        }
    }
}
