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

use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sys::reboot::{reboot, RebootMode};
use nix::unistd::{chdir, pivot_root};

use crate::cmdline::{InitConfig, Mode};

/// Run as PID 1. Under normal operation this never returns: every path ends in a
/// power-off. The `ExitCode` return type exists only so `main` can name it.
pub fn run_pid1() -> ExitCode {
    install_panic_hook();

    // Turn the read-only base into a writable root via an ephemeral overlay, so the
    // guest (and the workload) can write anywhere — not just the tmpfs mounts below.
    // Best-effort: on failure we keep booting on the read-only base.
    setup_overlay_root();

    // Best-effort; individual mount failures are logged, not fatal.
    mount_core_filesystems();

    if let Err(e) = bring_up_loopback() {
        // Loopback failure is not fatal for every workload; record and continue.
        eprintln!("mm-init: bringing up loopback failed: {e}");
    }

    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let cfg = InitConfig::parse(&cmdline);

    if let Some(key) = &cfg.authorized_key {
        if let Err(e) = install_authorized_key(key) {
            // Non-fatal: SSH may be unused; log and continue booting.
            eprintln!("mm-init: installing authorized key failed: {e}");
        }
    }

    // Tell the host we reached userspace *before* handing off to the workload, so
    // boot readiness is observable for any image — not only the test fixtures whose
    // workload happens to signal. Best-effort: a failure must not block the boot.
    signal_boot_ready();

    match cfg.mode {
        Mode::Workload => run_workload(&cfg),
        Mode::Sandbox => run_sandbox(&cfg),
    }
}

/// Signal boot readiness to the host VMM over the boot vsock — connect to
/// `VMADDR_CID_HOST` (2) port 1024; the host treats any vsock TX as the readiness
/// edge. Best-effort and non-fatal.
fn signal_boot_ready() {
    // SAFETY: each libc call is checked or best-effort; on any failure we simply
    // return and let the workload run.
    unsafe {
        let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return;
        }
        let mut addr: libc::sockaddr_vm = std::mem::zeroed();
        addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        addr.svm_cid = 2; // VMADDR_CID_HOST
        addr.svm_port = 1024;
        libc::connect(
            fd,
            (&addr as *const libc::sockaddr_vm).cast(),
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        );
        libc::close(fd);
    }
}

/// Write the injected SSH public key to `/root/.ssh/authorized_keys` with the
/// permissions OpenSSH requires (dir 0700, file 0600), so `mm ssh` works with no
/// in-guest setup (SPEC-1 FR-12). An in-guest sshd (from the image) still does the
/// actual authentication.
fn install_authorized_key(key: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::create_dir_all("/root/.ssh")?;
    std::fs::set_permissions("/root/.ssh", std::fs::Permissions::from_mode(0o700))?;

    let path = "/root/.ssh/authorized_keys";
    let mut contents = key.to_string();
    if !contents.ends_with('\n') {
        contents.push('\n');
    }
    std::fs::write(path, contents)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
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

/// Replace the read-only base root with a writable **ephemeral overlay**: lower =
/// the read-only base, upper+work = a fresh tmpfs, merged + pivoted into as the new
/// `/`. After this the whole filesystem is writable and every change is discarded at
/// shutdown — the container-style "writable layer over a shared read-only image".
/// Best-effort: a clear message is logged on success or failure, and on failure the
/// guest continues on the read-only base rather than failing to boot.
fn setup_overlay_root() {
    match try_setup_overlay_root() {
        Ok(()) => eprintln!("mm-init: writable overlay root active"),
        Err(e) => eprintln!("mm-init: writable overlay root unavailable, staying read-only: {e}"),
    }
}

fn try_setup_overlay_root() -> Result<(), String> {
    let m = |what: &str, r: nix::Result<()>| r.map_err(|e| format!("{what}: {e}"));
    let mkdir = |p: &str| std::fs::create_dir_all(p).map_err(|e| format!("mkdir {p}: {e}"));

    // Make root-mount propagation private so pivot_root is permitted.
    m(
        "make / private",
        mount(
            None::<&str>,
            "/",
            None::<&str>,
            MsFlags::MS_REC | MsFlags::MS_PRIVATE,
            None::<&str>,
        ),
    )?;

    // A tmpfs to back the overlay's upper + work dirs. /run exists in the base image
    // (injected by mm-image); we re-mount /run fresh after pivoting anyway.
    m(
        "mount tmpfs /run",
        mount(
            Some("tmpfs"),
            "/run",
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            None::<&str>,
        ),
    )?;
    mkdir("/run/upper")?;
    mkdir("/run/work")?;

    // Merge ro base (lower) with the writable upper at /mnt (injected mountpoint).
    m(
        "mount overlay /mnt",
        mount(
            Some("overlay"),
            "/mnt",
            Some("overlay"),
            MsFlags::empty(),
            Some("lowerdir=/,upperdir=/run/upper,workdir=/run/work"),
        ),
    )?;

    // Pivot into the writable merged root, stashing the old root at /mnt/oldroot
    // (writable via the overlay upper), then detach the old read-only base.
    mkdir("/mnt/oldroot")?;
    m("chdir /mnt", chdir("/mnt"))?;
    m("pivot_root", pivot_root(".", "oldroot"))?;
    m("chdir /", chdir("/"))?;
    // Lazy detach: the overlay keeps its own references to the lower + upper, so the
    // old base unmounts from the namespace while the overlay stays fully functional.
    m("detach /oldroot", umount2("/oldroot", MntFlags::MNT_DETACH))?;
    let _ = std::fs::remove_dir("/oldroot");
    Ok(())
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
///
/// Individual mounts are best-effort: a filesystem the kernel already mounted
/// (e.g. `devtmpfs` on `/dev` via `CONFIG_DEVTMPFS_MOUNT`) returns `EBUSY`, which
/// is not an error, and a single failure must not abort the whole boot.
fn mount_core_filesystems() {
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
        match mount(
            Some(m.source),
            m.target,
            Some(m.fstype),
            m.flags,
            None::<&str>,
        ) {
            Ok(()) => {}
            // Already mounted by the kernel (e.g. devtmpfs on /dev) — fine.
            Err(nix::errno::Errno::EBUSY) => {}
            Err(e) => {
                eprintln!("mm-init: mounting {} on {} failed: {e}", m.fstype, m.target);
            }
        }
    }
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
