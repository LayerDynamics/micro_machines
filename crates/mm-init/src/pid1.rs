//! PID-1 runtime for a MicroMachines guest (SPEC-1 FR-5).
//!
//! `mm-init` is the first userspace process the guest kernel execs. It owns the
//! whole boot: mount the core pseudo-filesystems, bring up loopback (the `eth0`
//! static address is already applied by the kernel from the `ip=` param produced
//! by [`mm-net`](../../mm-net), so init never runs DHCP), parse its instructions
//! from `/proc/cmdline`, then exec the workload. When the workload exits — or
//! anything panics — the machine is powered off immediately, mirroring nvrc's
//! fail-fast philosophy: a microVM has nothing to fall back to, so a half-booted
//! guest should die rather than hang.
use std::process::{Command, ExitCode};

use nix::mount::{mount, MsFlags};
use nix::sys::reboot::{reboot, RebootMode};

use crate::cmdline::{InitConfig, Mode};

/// Run as PID 1. Under normal operation this never returns: every path ends in a
/// power-off. The `ExitCode` return type exists only so `main` can name it.
pub fn run_pid1() -> ExitCode {
    install_panic_hook();

    if let Err(e) = mount_core_filesystems() {
        // No /proc guarantees yet, but the kernel console is wired to our stderr.
        eprintln!("mm-init: mounting core filesystems failed: {e}");
        poweroff();
    }

    if let Err(e) = bring_up_loopback() {
        // Loopback failure is not fatal for every workload; record and continue.
        eprintln!("mm-init: bringing up loopback failed: {e}");
    }

    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let cfg = InitConfig::parse(&cmdline);

    match cfg.mode {
        Mode::Workload => run_workload(&cfg),
        Mode::Sandbox => run_sandbox(&cfg),
    }
}

/// Replace the panic hook so an unwinding PID 1 powers the VM off instead of
/// aborting into a kernel "Attempted to kill init" panic.
fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default(info);
        poweroff();
    }));
}

/// Flush filesystem buffers and power the machine off. Diverges: on the rare
/// chance `reboot(2)` returns, we spin rather than fall through to undefined
/// PID-1 behavior.
fn poweroff() -> ! {
    // SAFETY: `sync(2)` takes no arguments and cannot fail; it only schedules a
    // best-effort writeback of the ephemeral overlay before we cut power.
    unsafe {
        libc::sync();
    }
    let _ = reboot(RebootMode::RB_POWER_OFF);
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

/// A single pseudo-filesystem mount the guest needs before userspace runs.
struct CoreMount {
    source: &'static str,
    target: &'static str,
    fstype: &'static str,
    flags: MsFlags,
}

/// Mount the pseudo-filesystems a Linux userspace expects (`/proc`, `/sys`,
/// `/dev`, `/run`, `/tmp`, and the unified cgroup2 hierarchy). `/proc` is mounted
/// first so the subsequent cmdline read works; `/sys` precedes cgroup2 because
/// the latter lives under `/sys/fs/cgroup`.
fn mount_core_filesystems() -> nix::Result<()> {
    let nodev_noexec_nosuid = MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID;
    let mounts = [
        CoreMount {
            source: "proc",
            target: "/proc",
            fstype: "proc",
            flags: nodev_noexec_nosuid,
        },
        CoreMount {
            source: "sysfs",
            target: "/sys",
            fstype: "sysfs",
            flags: nodev_noexec_nosuid,
        },
        CoreMount {
            source: "devtmpfs",
            target: "/dev",
            fstype: "devtmpfs",
            flags: MsFlags::MS_NOSUID,
        },
        CoreMount {
            source: "tmpfs",
            target: "/run",
            fstype: "tmpfs",
            flags: MsFlags::MS_NODEV | MsFlags::MS_NOSUID,
        },
        CoreMount {
            source: "tmpfs",
            target: "/tmp",
            fstype: "tmpfs",
            flags: MsFlags::MS_NODEV | MsFlags::MS_NOSUID,
        },
        CoreMount {
            source: "cgroup2",
            target: "/sys/fs/cgroup",
            fstype: "cgroup2",
            flags: nodev_noexec_nosuid,
        },
    ];

    for m in mounts {
        // The mount point may be absent on a minimal OCI-derived rootfs; create
        // it (ignoring "already exists") before mounting.
        let _ = std::fs::create_dir_all(m.target);
        mount(
            Some(m.source),
            m.target,
            Some(m.fstype),
            m.flags,
            None::<&str>,
        )?;
    }
    Ok(())
}

/// Bring the loopback interface up via `SIOCSIFFLAGS`. We use a raw ioctl rather
/// than pulling in an async netlink runtime, keeping init dependency-light.
fn bring_up_loopback() -> std::io::Result<()> {
    // SAFETY: `socket(2)` returns a non-negative fd or -1; we check and own it.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let result = set_loopback_up(fd);

    // SAFETY: `fd` is a valid descriptor we opened above and no longer use.
    unsafe {
        libc::close(fd);
    }
    result
}

/// Read `lo`'s current flags, OR in `IFF_UP | IFF_RUNNING`, and write them back.
fn set_loopback_up(fd: libc::c_int) -> std::io::Result<()> {
    // SAFETY: `ifreq` is a C POD; zeroing it is a valid initial state.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    // Copy "lo" into the fixed-size, NUL-terminated name field.
    for (slot, &byte) in ifr.ifr_name.iter_mut().zip(b"lo\0") {
        *slot = byte as libc::c_char;
    }

    // SAFETY: `fd` is a valid AF_INET socket and `ifr` is correctly sized for the
    // SIOCGIFFLAGS request, which fills `ifr_ifru.ifru_flags`. The request constant
    // is cast to `libc::Ioctl`, whose width differs between gnu (c_ulong) and musl
    // (c_int) — the guest binary targets musl, so this cast is load-bearing.
    if unsafe { libc::ioctl(fd, libc::SIOCGIFFLAGS as libc::Ioctl, &mut ifr) } < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: after a successful SIOCGIFFLAGS the `ifru_flags` union member is the
    // active one; we OR in the up/running bits.
    unsafe {
        ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
    }

    // SAFETY: same invariants as the GET request; SIOCSIFFLAGS reads `ifru_flags`.
    if unsafe { libc::ioctl(fd, libc::SIOCSIFFLAGS as libc::Ioctl, &ifr) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Workload mode: exec the configured binary and power off when it exits. A
/// non-zero exit or a missing/unexecutable workload powers off after logging.
fn run_workload(cfg: &InitConfig) -> ExitCode {
    let Some(workload) = cfg.workload.as_deref() else {
        eprintln!("mm-init: no mm.workload= specified on the kernel cmdline");
        poweroff();
    };

    match Command::new(workload).args(&cfg.args).status() {
        Ok(status) if status.success() => poweroff(),
        Ok(status) => {
            eprintln!("mm-init: workload {workload} exited with {status}");
            poweroff();
        }
        Err(e) => {
            eprintln!("mm-init: failed to exec workload {workload}: {e}");
            poweroff();
        }
    }
}

/// Sandbox mode (M1 degraded form): drop the operator onto an interactive shell
/// on the serial console so `mm ssh` has a usable session. The full vsock exec
/// agent — the real Sandbox Mode — is implemented in M3; this keeps the boot path
/// honest in the meantime rather than stubbing the branch out.
fn run_sandbox(_cfg: &InitConfig) -> ExitCode {
    let mut shell = sandbox_shell_command();
    match shell.status() {
        Ok(_) => poweroff(),
        Err(e) => {
            eprintln!("mm-init: failed to exec sandbox shell: {e}");
            poweroff();
        }
    }
}

/// Pick an interactive shell for sandbox mode, preferring a real `/bin/sh` and
/// falling back to busybox's applet form on a stripped rootfs.
fn sandbox_shell_command() -> Command {
    if std::path::Path::new("/bin/sh").exists() {
        Command::new("/bin/sh")
    } else {
        let mut c = Command::new("/bin/busybox");
        c.arg("sh");
        c
    }
}
