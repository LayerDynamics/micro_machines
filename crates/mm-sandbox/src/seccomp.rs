//! Per-thread seccomp-BPF allowlist for VMM/vCPU threads (SPEC-1 FR-27).
//!
//! Before a vCPU ever runs guest code, the thread that will host it is locked down
//! to the minimal syscall set the VMM needs at steady state: KVM `ioctl`s, the
//! eventfd/epoll machinery the device workers use, memory management, and the
//! futex/signal primitives the runtime relies on. Everything else — crucially
//! `execve`, `clone`, `ptrace`, `socket` — is denied, so a guest escape that hijacks
//! a vCPU thread cannot spawn a shell or open new attack surface.
//!
//! The allowlist itself is plain, cross-platform data (a set of syscall *names*),
//! which keeps it unit-testable on any host. Compiling it to a BPF program and
//! installing it are Linux-only.
use std::collections::BTreeSet;

/// The set of syscalls a thread is permitted to make. Everything not in the set
/// is denied (with `EPERM`).
#[derive(Debug, Clone)]
pub struct SeccompAllowlist {
    allowed: BTreeSet<&'static str>,
}

impl SeccompAllowlist {
    /// Whether `syscall` (by name) is permitted by this allowlist.
    pub fn allows(&self, syscall: &str) -> bool {
        self.allowed.contains(syscall)
    }

    /// Iterate the permitted syscall names.
    pub fn syscalls(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.allowed.iter().copied()
    }
}

/// The allowlist for a VMM/vCPU thread after the guest is running. Deliberately
/// excludes `execve`/`fork`/`clone`/`ptrace`/`socket` (the guest VMM thread must
/// never exec or fork).
pub fn vmm_thread_rules() -> SeccompAllowlist {
    let allowed = [
        // KVM control + general file I/O.
        "ioctl",
        "read",
        "write",
        "readv",
        "writev",
        "pread64",
        "pwrite64",
        "preadv",
        "pwritev",
        "lseek",
        "close",
        "dup",
        "dup2",
        "dup3",
        "fcntl",
        "fstat",
        "fsync",
        "fdatasync",
        // Event loop: epoll + eventfd + timerfd the device workers use.
        "epoll_create1",
        "epoll_ctl",
        "epoll_wait",
        "epoll_pwait",
        "eventfd2",
        "timerfd_create",
        "timerfd_settime",
        "poll",
        "ppoll",
        // Memory management.
        "mmap",
        "munmap",
        "mremap",
        "mprotect",
        "madvise",
        "brk",
        // Scheduling, synchronization, and signals.
        "futex",
        "sched_yield",
        "rt_sigprocmask",
        "rt_sigreturn",
        "rt_sigaction",
        "sigaltstack",
        "tgkill",
        "restart_syscall",
        // Time.
        "clock_gettime",
        "clock_nanosleep",
        "nanosleep",
        "gettimeofday",
        // Entropy + thread/process exit.
        "getrandom",
        "exit",
        "exit_group",
        // Local message passing (vsock/uds helpers in later milestones).
        "recvmsg",
        "sendmsg",
        "accept4",
    ]
    .into_iter()
    .collect();
    SeccompAllowlist { allowed }
}

/// Errors from compiling or applying a seccomp filter.
#[derive(Debug, thiserror::Error)]
pub enum SeccompError {
    #[error("syscall {0:?} in the allowlist has no number on this architecture")]
    UnknownSyscall(String),
    #[error("seccomp backend error: {0}")]
    Backend(String),
}

#[cfg(target_os = "linux")]
mod apply {
    use std::collections::BTreeMap;
    use std::convert::TryInto;

    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};

    use super::{SeccompAllowlist, SeccompError};

    impl SeccompAllowlist {
        /// Compile the allowlist into a BPF program: every listed syscall is
        /// allowed unconditionally; everything else returns `EPERM`.
        pub fn compile(&self) -> Result<BpfProgram, SeccompError> {
            let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
            for name in self.allowed.iter() {
                let nr = syscall_number(name)
                    .ok_or_else(|| SeccompError::UnknownSyscall((*name).to_string()))?;
                // An empty rule vector means "allow this syscall for any args".
                rules.insert(nr, vec![]);
            }
            let arch = std::env::consts::ARCH
                .try_into()
                .map_err(|e| SeccompError::Backend(format!("unsupported arch: {e:?}")))?;
            let filter = SeccompFilter::new(
                rules,
                // Mismatch (not in the allowlist): deny with EPERM rather than kill,
                // so failures are debuggable instead of an opaque SIGSYS.
                SeccompAction::Errno(libc::EPERM as u32),
                // Match: allow.
                SeccompAction::Allow,
                arch,
            )
            .map_err(|e| SeccompError::Backend(e.to_string()))?;

            filter
                .try_into()
                .map_err(|e| SeccompError::Backend(format!("{e:?}")))
        }

        /// Compile and install the filter on the **current thread**. Call this on
        /// each VMM/vCPU thread before the first `vcpu.run()`.
        pub fn apply_to_current_thread(&self) -> Result<(), SeccompError> {
            let program = self.compile()?;
            seccompiler::apply_filter(&program).map_err(|e| SeccompError::Backend(e.to_string()))
        }
    }

    /// Map a syscall name to its number on the build architecture.
    fn syscall_number(name: &str) -> Option<i64> {
        let nr = match name {
            "ioctl" => libc::SYS_ioctl,
            "read" => libc::SYS_read,
            "write" => libc::SYS_write,
            "readv" => libc::SYS_readv,
            "writev" => libc::SYS_writev,
            "pread64" => libc::SYS_pread64,
            "pwrite64" => libc::SYS_pwrite64,
            "preadv" => libc::SYS_preadv,
            "pwritev" => libc::SYS_pwritev,
            "lseek" => libc::SYS_lseek,
            "close" => libc::SYS_close,
            "dup" => libc::SYS_dup,
            "dup2" => libc::SYS_dup2,
            "dup3" => libc::SYS_dup3,
            "fcntl" => libc::SYS_fcntl,
            "fstat" => libc::SYS_fstat,
            "fsync" => libc::SYS_fsync,
            "fdatasync" => libc::SYS_fdatasync,
            "epoll_create1" => libc::SYS_epoll_create1,
            "epoll_ctl" => libc::SYS_epoll_ctl,
            "epoll_wait" => libc::SYS_epoll_wait,
            "epoll_pwait" => libc::SYS_epoll_pwait,
            "eventfd2" => libc::SYS_eventfd2,
            "timerfd_create" => libc::SYS_timerfd_create,
            "timerfd_settime" => libc::SYS_timerfd_settime,
            "poll" => libc::SYS_poll,
            "ppoll" => libc::SYS_ppoll,
            "mmap" => libc::SYS_mmap,
            "munmap" => libc::SYS_munmap,
            "mremap" => libc::SYS_mremap,
            "mprotect" => libc::SYS_mprotect,
            "madvise" => libc::SYS_madvise,
            "brk" => libc::SYS_brk,
            "futex" => libc::SYS_futex,
            "sched_yield" => libc::SYS_sched_yield,
            "rt_sigprocmask" => libc::SYS_rt_sigprocmask,
            "rt_sigreturn" => libc::SYS_rt_sigreturn,
            "rt_sigaction" => libc::SYS_rt_sigaction,
            "sigaltstack" => libc::SYS_sigaltstack,
            "tgkill" => libc::SYS_tgkill,
            "restart_syscall" => libc::SYS_restart_syscall,
            "clock_gettime" => libc::SYS_clock_gettime,
            "clock_nanosleep" => libc::SYS_clock_nanosleep,
            "nanosleep" => libc::SYS_nanosleep,
            "gettimeofday" => libc::SYS_gettimeofday,
            "getrandom" => libc::SYS_getrandom,
            "exit" => libc::SYS_exit,
            "exit_group" => libc::SYS_exit_group,
            "recvmsg" => libc::SYS_recvmsg,
            "sendmsg" => libc::SYS_sendmsg,
            "accept4" => libc::SYS_accept4,
            _ => return None,
        };
        Some(nr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_includes_kvm_run_ioctl_and_denies_execve() {
        let rules = vmm_thread_rules();
        assert!(rules.allows("ioctl"));
        assert!(rules.allows("epoll_wait"));
        assert!(!rules.allows("execve"), "guest VMM thread must not exec");
    }

    #[test]
    fn allowlist_denies_process_creation_and_tracing() {
        let rules = vmm_thread_rules();
        for forbidden in [
            "execve", "execveat", "fork", "vfork", "clone", "ptrace", "socket",
        ] {
            assert!(!rules.allows(forbidden), "{forbidden} must be denied");
        }
    }

    #[test]
    fn allowlist_permits_the_event_loop_primitives() {
        let rules = vmm_thread_rules();
        for needed in [
            "ioctl",
            "read",
            "write",
            "epoll_wait",
            "futex",
            "mmap",
            "close",
        ] {
            assert!(rules.allows(needed), "{needed} must be allowed");
        }
    }
}
