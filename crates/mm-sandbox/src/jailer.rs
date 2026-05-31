//! The jailer: confine the VMM process before it runs guest code (SPEC-1 FR-27).
//!
//! Modelled on Firecracker's jailer. The privileged setup the VMM needs — opening
//! `/dev/kvm`, creating the bridge/TAP — must already be done (SPEC-1 C6); this
//! routine then drops the process into a restricted box:
//!
//! 1. **cgroup v2 limits** — create a per-VM cgroup, cap `cpu.max` and
//!    `memory.max`, and move the process into it (done first, while still real
//!    root, since writing the cgroup tree needs privilege).
//! 2. **namespaces** — `CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET` isolate mounts,
//!    the PID space, and networking. (Like Firecracker's jailer we drop to an
//!    unprivileged uid rather than entering a user namespace; user-namespace
//!    mapping is additive hardening for a later milestone.)
//! 3. **fork into the PID namespace** — `unshare(CLONE_NEWPID)` does not move the
//!    caller into the new namespace, only its children. As a side effect the
//!    caller can no longer create threads (the kernel rejects `CLONE_THREAD` with
//!    `EINVAL` once its active PID namespace differs from `pid_ns_for_children`),
//!    which would break the multi-threaded VMM. We fork so the VMM runs as PID 1
//!    of the new namespace, where threads are allowed again; the parent reaps it.
//! 4. **chroot** — pivot into the per-VM root so the process cannot see the host
//!    filesystem.
//! 5. **no_new_privs + uid/gid drop** — forbid regaining privilege via setuid
//!    binaries, then drop to an unprivileged uid/gid.
//!
//! After `confine`, install the seccomp filter ([`crate::seccomp`]) on each thread.
use std::fs;
use std::path::{Path, PathBuf};

use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{chdir, chroot, fork, setgid, setgroups, setuid, ForkResult, Gid, Uid};

/// cgroup v2 resource limits for a jailed VM.
#[derive(Debug, Clone)]
pub struct CgroupLimits {
    /// cgroup name (a leaf directory under `/sys/fs/cgroup`).
    pub name: String,
    /// `cpu.max` value: `"<quota_us> <period_us>"`, or `"max"` for unlimited.
    pub cpu_max: String,
    /// `memory.max` in bytes.
    pub memory_max_bytes: u64,
}

/// Everything the jailer needs to confine a VMM process.
#[derive(Debug, Clone)]
pub struct JailSpec {
    /// Per-VM root the process is chrooted into.
    pub chroot_dir: PathBuf,
    /// Unprivileged uid the process drops to (or, with a user namespace, the outer
    /// uid that inner-root maps to).
    pub uid: u32,
    /// Unprivileged gid the process drops to (or the outer gid mapped to inner 0).
    pub gid: u32,
    /// cgroup v2 limits.
    pub cgroup: CgroupLimits,
    /// When true, also enter a **user namespace**, mapping inner-root to the outer
    /// `uid`/`gid` (additive hardening: a namespace escape lands as `uid`/`gid`,
    /// not real root). With this set we stay inner-root rather than `setuid`-ing,
    /// since being unprivileged outside the namespace is already the goal.
    pub user_namespace: bool,
}

/// Errors from confining a process.
#[derive(Debug, thiserror::Error)]
pub enum JailerError {
    #[error("cgroup setup failed: {0}")]
    Cgroup(std::io::Error),
    #[error("namespace unshare failed: {0}")]
    Namespace(nix::Error),
    #[error("fork into pid namespace failed: {0}")]
    Fork(nix::Error),
    #[error("making mounts private failed: {0}")]
    Mount(nix::Error),
    #[error("chroot to {path} failed: {source}")]
    Chroot { path: PathBuf, source: nix::Error },
    #[error("prctl(PR_SET_NO_NEW_PRIVS) failed: {0}")]
    NoNewPrivs(std::io::Error),
    #[error("user namespace setup failed: {0}")]
    UserNamespace(std::io::Error),
    #[error("dropping privileges failed: {0}")]
    DropPrivileges(nix::Error),
}

/// Confine the current process per `spec`. Returns once the process is jailed; the
/// caller then applies the seccomp filter and boots the VM.
pub fn confine(spec: &JailSpec) -> Result<(), JailerError> {
    // cgroup setup needs real root, so it runs before any namespace entry.
    apply_cgroup_limits(&spec.cgroup)?;
    // The user namespace (when requested) must be entered before the others so the
    // process holds the necessary capabilities *inside* it for chroot etc.
    if spec.user_namespace {
        enter_user_namespace(spec.uid, spec.gid)?;
    }
    enter_namespaces()?;
    // We have unshared a PID namespace, so this process can no longer spawn
    // threads. Fork into it: only the child (PID 1 of the new namespace) returns
    // here to finish confinement and boot the multi-threaded VMM; the parent
    // reaps the child and exits with an equivalent status and never returns.
    fork_into_pid_namespace()?;
    make_mounts_private()?;
    enter_chroot(&spec.chroot_dir)?;
    set_no_new_privs()?;
    // With a user namespace we are already unprivileged outside it (inner-root maps
    // to `uid`/`gid`), so no `setuid` drop — that uid is not mapped inside the ns.
    if !spec.user_namespace {
        drop_privileges(spec.uid, spec.gid)?;
    }
    Ok(())
}

/// Enter a new user namespace and map inner-root (uid/gid 0) to the outer
/// `uid`/`gid`. `setgroups` is denied first, as the kernel requires before writing
/// `gid_map` from an unprivileged-mapping context.
fn enter_user_namespace(uid: u32, gid: u32) -> Result<(), JailerError> {
    unshare(CloneFlags::CLONE_NEWUSER).map_err(JailerError::Namespace)?;
    std::fs::write("/proc/self/setgroups", "deny").map_err(JailerError::UserNamespace)?;
    std::fs::write("/proc/self/uid_map", format!("0 {uid} 1"))
        .map_err(JailerError::UserNamespace)?;
    std::fs::write("/proc/self/gid_map", format!("0 {gid} 1"))
        .map_err(JailerError::UserNamespace)?;
    Ok(())
}

/// Create the per-VM cgroup, write its limits, and move this process into it.
///
/// Exposed on its own because the CLI applies cgroup limits to the in-process VMM
/// even when it cannot apply the full namespace/chroot/uid-drop confinement (which
/// would break the in-process TAP/KVM access in M1 — see `confine`).
pub fn apply_cgroup_limits(cgroup: &CgroupLimits) -> Result<(), JailerError> {
    let base = Path::new("/sys/fs/cgroup").join(&cgroup.name);
    fs::create_dir_all(&base).map_err(JailerError::Cgroup)?;
    fs::write(base.join("cpu.max"), &cgroup.cpu_max).map_err(JailerError::Cgroup)?;
    fs::write(base.join("memory.max"), cgroup.memory_max_bytes.to_string())
        .map_err(JailerError::Cgroup)?;
    // Moving the process in must be last: once limits are set, joining enforces them.
    fs::write(base.join("cgroup.procs"), std::process::id().to_string())
        .map_err(JailerError::Cgroup)?;
    Ok(())
}

/// Unshare the mount, PID, and network namespaces.
fn enter_namespaces() -> Result<(), JailerError> {
    unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNET)
        .map_err(JailerError::Namespace)
}

/// Fork so the VMM runs as PID 1 of the freshly unshared PID namespace.
///
/// `unshare(CLONE_NEWPID)` places the caller's *children* — not the caller — in
/// the new namespace. As a side effect the caller's active PID namespace stops
/// matching its `pid_ns_for_children`, and the kernel then rejects `CLONE_THREAD`
/// (the clone flavour `pthread_create` uses) with `EINVAL`. The VMM is
/// multi-threaded (one thread per vCPU), so it must run from a process where the
/// two namespaces agree: the child of this fork, which is PID 1 of the new
/// namespace. The parent has nothing left to do but reap that child and mirror
/// its exit status, so to the launcher the worker still looks like one process.
///
/// The caller is single-threaded at this point (the preceding
/// `unshare(CLONE_NEWPID)` would have failed otherwise), so `fork()` is free of
/// the usual multi-threaded-fork hazards.
fn fork_into_pid_namespace() -> Result<(), JailerError> {
    // SAFETY: single-threaded process (see above); each branch only does
    // async-signal-safe work before the child returns / the parent exits.
    match unsafe { fork() }.map_err(JailerError::Fork)? {
        ForkResult::Child => Ok(()),
        ForkResult::Parent { child } => {
            let code = match waitpid(child, None) {
                Ok(WaitStatus::Exited(_, code)) => code,
                // Convention: 128 + signal number for a signal-terminated child.
                Ok(WaitStatus::Signaled(_, sig, _)) => 128 + sig as i32,
                _ => 1,
            };
            std::process::exit(code);
        }
    }
}

/// Make the whole mount tree private+recursive so chroot and any later mounts in
/// our namespace do not propagate to (or from) the host.
fn make_mounts_private() -> Result<(), JailerError> {
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(JailerError::Mount)
}

/// chroot into the per-VM root and move the cwd inside it.
fn enter_chroot(dir: &Path) -> Result<(), JailerError> {
    chroot(dir).map_err(|source| JailerError::Chroot {
        path: dir.to_path_buf(),
        source,
    })?;
    chdir("/").map_err(|source| JailerError::Chroot {
        path: PathBuf::from("/"),
        source,
    })
}

/// Forbid acquiring new privileges (defeats setuid/setgid binaries inside the jail).
fn set_no_new_privs() -> Result<(), JailerError> {
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS and otherwise-zero args is always safe.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(JailerError::NoNewPrivs(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Drop supplementary groups, then gid, then uid — order matters: the uid drop is
/// last because it removes the privilege needed for the group changes.
fn drop_privileges(uid: u32, gid: u32) -> Result<(), JailerError> {
    let gid = Gid::from_raw(gid);
    setgroups(&[gid]).map_err(JailerError::DropPrivileges)?;
    setgid(gid).map_err(JailerError::DropPrivileges)?;
    setuid(Uid::from_raw(uid)).map_err(JailerError::DropPrivileges)?;
    Ok(())
}
