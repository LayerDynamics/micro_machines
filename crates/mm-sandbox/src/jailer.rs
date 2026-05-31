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
//! 3. **chroot** — pivot into the per-VM root so the process cannot see the host
//!    filesystem.
//! 4. **no_new_privs + uid/gid drop** — forbid regaining privilege via setuid
//!    binaries, then drop to an unprivileged uid/gid.
//!
//! After `confine`, install the seccomp filter ([`crate::seccomp`]) on each thread.
use std::fs;
use std::path::{Path, PathBuf};

use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::unistd::{chdir, chroot, setgid, setgroups, setuid, Gid, Uid};

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
    /// Unprivileged uid the process drops to.
    pub uid: u32,
    /// Unprivileged gid the process drops to.
    pub gid: u32,
    /// cgroup v2 limits.
    pub cgroup: CgroupLimits,
}

/// Errors from confining a process.
#[derive(Debug, thiserror::Error)]
pub enum JailerError {
    #[error("cgroup setup failed: {0}")]
    Cgroup(std::io::Error),
    #[error("namespace unshare failed: {0}")]
    Namespace(nix::Error),
    #[error("making mounts private failed: {0}")]
    Mount(nix::Error),
    #[error("chroot to {path} failed: {source}")]
    Chroot { path: PathBuf, source: nix::Error },
    #[error("prctl(PR_SET_NO_NEW_PRIVS) failed: {0}")]
    NoNewPrivs(std::io::Error),
    #[error("dropping privileges failed: {0}")]
    DropPrivileges(nix::Error),
}

/// Confine the current process per `spec`. Returns once the process is jailed; the
/// caller then applies the seccomp filter and boots the VM.
pub fn confine(spec: &JailSpec) -> Result<(), JailerError> {
    apply_cgroup_limits(&spec.cgroup)?;
    enter_namespaces()?;
    make_mounts_private()?;
    enter_chroot(&spec.chroot_dir)?;
    set_no_new_privs()?;
    drop_privileges(spec.uid, spec.gid)?;
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
