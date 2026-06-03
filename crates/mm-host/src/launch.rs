//! Privileged microVM launch: build the rootfs, wire the bridge/TAP/NAT, open
//! `/dev/kvm`, prepare a per-VM chroot, then spawn the jailed `__vmm-worker` child —
//! passing it the KVM + TAP fds. The child confines itself and runs the guest.
//!
//! This is the orchestration `mm run` performed in M1, lifted into a library so the
//! cluster agent reuses the exact same boot path. It is decoupled from any registry:
//! the caller supplies a [`LaunchSpec`] (including the IPs already in use) and
//! receives a [`LaunchOutcome`] to persist however it likes.
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use anyhow::{Context, Result};
use mm_image::ImageStore;

use crate::config::{build_vm_config, mac_from_ip, NETMASK};
use crate::{LaunchOutcome, LaunchSpec};

/// The `/24` MicroMachines guests live on, plus the bridge name.
const SUBNET_BASE: [u8; 3] = [10, 0, 0];
const SUBNET_CIDR: &str = "10.0.0.0/24";
const BRIDGE: &str = "mm-br0";
/// Unprivileged uid/gid the jailed worker drops to (nobody/nogroup).
const WORKER_UID: u32 = 65534;
const WORKER_GID: u32 = 65534;
/// Fixed fd numbers the worker inherits the KVM + TAP + vsock + control fds at.
const WORKER_KVM_FD: RawFd = 10;
const WORKER_TAP_FD: RawFd = 11;
const WORKER_VSOCK_FD: RawFd = 12;
const WORKER_CONTROL_FD: RawFd = 13;

/// Encode an argv as the `mm.workload_argv` cmdline value: NUL-join the elements
/// (NUL can't appear in argv) and hex-encode, so arguments with spaces or commas
/// survive the whitespace-split kernel command line.
fn encode_argv(argv: &[String]) -> String {
    hex_encode(argv.join("\0").as_bytes())
}

/// Boot a microVM per `spec`, returning the running outcome. The spawned worker
/// owns its copies of the KVM + TAP fds; this function closes the parent's handles
/// before returning. Whether to wait on [`LaunchOutcome::child`] (foreground) or let
/// it run detached is the caller's choice.
pub fn launch(spec: &LaunchSpec) -> Result<LaunchOutcome> {
    let root = spec.state_root.as_path();

    // 1. OCI image -> read-only base rootfs (digest-cached), with mm-init injected
    //    as /init so the guest kernel's `init=/init` finds PID 1.
    let images = ImageStore::new(root);
    let rootfs = images
        .build_base_rootfs(&spec.image, &spec.mm_init_path, spec.sshd_path.as_deref())
        .with_context(|| format!("building rootfs for {}", spec.image))?;

    // 2. Allocate an IP, seeding the pool from the caller-supplied reservations.
    let name = spec.name.clone();
    let mut ipam = mm_net::Ipam::new(SUBNET_BASE, 1);
    for ip in &spec.reserved_ips {
        ipam.reserve(*ip);
    }
    let ip = ipam.allocate().context("guest IP pool exhausted")?;
    let gateway = ipam.gateway();

    // 3. Privileged host networking (must precede confinement, SPEC-1 C6).
    mm_net::ensure_bridge(BRIDGE, gateway, 24).context("ensuring bridge")?;
    let tap_name = format!("mm-{name}");
    let tap = mm_net::create_tap(&tap_name, BRIDGE).context("creating TAP")?;
    let egress = default_egress_iface().unwrap_or_else(|| "eth0".to_string());
    mm_net::enable_nat(SUBNET_CIDR, &egress).context("enabling NAT")?;

    // 4. Open an inheritable /dev/kvm fd for the worker.
    let kvm_fd = open_kvm_inheritable()?;

    // 5. Prepare the chroot: hardlink (or copy) the kernel + rootfs in, so the
    //    confined worker can open them at /vmlinux and /rootfs.ext4.
    let jail = root.join("jails").join(&name);
    let jail_root = jail.join("root");
    std::fs::create_dir_all(&jail_root)
        .with_context(|| format!("creating jail {}", jail_root.display()))?;
    let jail_kernel = jail_root.join("vmlinux");
    let jail_rootfs = jail_root.join("rootfs.ext4");
    link_or_copy(&spec.kernel_path, &jail_kernel)?;
    link_or_copy(&rootfs, &jail_rootfs)?;
    // Make the jail traversable and the kernel/rootfs readable by the dropped
    // (nobody) uid, failing loudly if a path is not — otherwise the confined worker
    // would hit an opaque "permission denied" deep inside the boot.
    prepare_jail_permissions(&jail, &jail_root, &[&jail_kernel, &jail_rootfs])?;

    // A writable snapshot dir *inside* the chroot (at `/snapshots` for the worker), owned
    // by the dropped uid so the confined worker can write live snapshots/branches into it
    // over the control channel (FR-14/FR-16). Unlike the read-only kernel/rootfs, this
    // must be writable by WORKER_UID.
    let jail_snapshots = jail_root.join("snapshots");
    std::fs::create_dir_all(&jail_snapshots)
        .with_context(|| format!("creating {}", jail_snapshots.display()))?;
    chown_to_worker(&jail_snapshots)?;

    // 6. Worker VM config with chroot-relative paths; serialized for the child.
    // Inject the managed SSH public key so `mm ssh` works with no in-guest setup.
    let authorized_key_hex = ensure_ssh_key(root)?;
    // Per-VM CRNG seed drawn from the host's (initialized) entropy pool — the guest
    // has none at boot and no virtio-rng, so mm-init credits this so getrandom(2)
    // doesn't block (notably dropbear's host-key generation).
    let random_seed_hex = host_random_seed_hex();
    // Workload: `--ssh` boots the sandbox shell; otherwise run the image's own
    // command (Entrypoint+Cmd), hex-encoded so args with spaces survive the cmdline.
    let workload_argv_hex = if spec.ssh {
        None
    } else {
        let argv = images
            .image_argv(&spec.image)
            .with_context(|| format!("reading the image command for {}", spec.image))?;
        Some(encode_argv(&argv))
    };
    let worker_cfg = build_vm_config(
        spec.cpus,
        spec.memory_mib,
        std::path::PathBuf::from("/vmlinux"),
        std::path::PathBuf::from("/rootfs.ext4"),
        ip,
        gateway,
        NETMASK,
        &name,
        tap_name.clone(),
        mac_from_ip(ip),
        workload_argv_hex.as_deref(),
        authorized_key_hex.as_deref(),
        random_seed_hex.as_deref(),
    );
    worker_cfg.validate().context("validating VM config")?;
    let cfg_path = jail.join("config.json");
    std::fs::write(&cfg_path, serde_json::to_vec(&worker_cfg)?)
        .with_context(|| format!("writing {}", cfg_path.display()))?;

    // 7. Bind the host vsock exec bridge UDS *outside* the chroot (in the per-VM jail
    //    dir, reachable by the launcher/agent) and pass its fd to the worker, which
    //    accepts on it after confinement (SPEC-1 FR-13).
    let vsock_path = jail.join("vsock.sock");
    let vsock_listener = bind_vsock_listener(&vsock_path)?;

    // Control UDS: the parent↔worker channel for live snapshot/branch (FR-14/FR-16),
    // bound outside the chroot in the per-VM jail dir (reachable by the launcher/agent)
    // and passed to the worker, which serves it post-confinement.
    let control_path = jail.join("control.sock");
    let control_listener = bind_vsock_listener(&control_path)?;

    // 8. Spawn the jailed worker, passing the KVM + TAP + vsock + control fds.
    let cgroup = format!("micro_machines/{name}");
    let cpu_max = format!("{} 100000", u64::from(spec.cpus) * 100_000);
    let mem_max = spec.memory_mib * 1024 * 1024;
    let console_log = jail.join("console.log");
    let child = spawn_worker(
        &cfg_path,
        kvm_fd,
        tap.as_raw_fd(),
        vsock_listener.as_raw_fd(),
        control_listener.as_raw_fd(),
        &jail_root,
        &cgroup,
        &cpu_max,
        mem_max,
        spec.detach,
        &console_log,
    )?;
    let pid = child.id();

    // The child now owns its copies of the fds; the persistent TAP survives the
    // parent dropping its handle, and the bound UDSes survive via the worker's copies.
    // SAFETY: `kvm_fd` is the fd we opened; the child inherited its own copy.
    unsafe { libc::close(kvm_fd) };
    drop(tap);
    drop(vsock_listener);
    drop(control_listener);

    Ok(LaunchOutcome {
        name,
        ip,
        tap_name,
        pid,
        console_log,
        vsock_path,
        control_path,
        child,
    })
}

/// Spawn the `__vmm-worker` subcommand of the current executable, dup'ing the KVM +
/// TAP fds to fixed numbers in the child so they survive `exec` at predictable
/// descriptors. When `detach` is set, the worker is put in its own session
/// (`setsid`) and its console is redirected to `log_path`, so it outlives the parent
/// and the terminal.
#[allow(clippy::too_many_arguments)]
fn spawn_worker(
    config: &Path,
    kvm_fd: RawFd,
    tap_fd: RawFd,
    vsock_fd: RawFd,
    control_fd: RawFd,
    chroot: &Path,
    cgroup: &str,
    cpu_max: &str,
    mem_max: u64,
    detach: bool,
    log_path: &Path,
) -> Result<Child> {
    let exe = std::env::current_exe().context("locating current executable")?;
    let mut cmd = Command::new(exe);
    cmd.arg("__vmm-worker")
        .arg("--config")
        .arg(config)
        .arg("--kvm-fd")
        .arg(WORKER_KVM_FD.to_string())
        .arg("--tap-fd")
        .arg(WORKER_TAP_FD.to_string())
        .arg("--vsock-fd")
        .arg(WORKER_VSOCK_FD.to_string())
        .arg("--control-fd")
        .arg(WORKER_CONTROL_FD.to_string())
        .arg("--chroot")
        .arg(chroot)
        .arg("--uid")
        .arg(WORKER_UID.to_string())
        .arg("--gid")
        .arg(WORKER_GID.to_string())
        .arg("--cgroup")
        .arg(cgroup)
        .arg("--cpu-max")
        .arg(cpu_max)
        .arg("--mem-max")
        .arg(mem_max.to_string());
    // Enter a user namespace by default (additive hardening); MM_NO_USERNS=1
    // disables it for kernels without unprivileged-userns or for debugging.
    if std::env::var_os("MM_NO_USERNS").is_none() {
        cmd.arg("--user-namespace");
    }

    // Detached: capture the guest console to a log and detach from stdin so the
    // worker does not depend on the parent's terminal.
    if detach {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .with_context(|| format!("opening console log {}", log_path.display()))?;
        let log_err = log.try_clone().context("cloning console log handle")?;
        cmd.stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err));
    }

    // SAFETY: `pre_exec` runs in the forked child before `exec`; `dup2` and `setsid`
    // are async-signal-safe; `dup2` clears CLOEXEC on the target so 10/11 survive
    // exec.
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(kvm_fd, WORKER_KVM_FD) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::dup2(tap_fd, WORKER_TAP_FD) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::dup2(vsock_fd, WORKER_VSOCK_FD) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::dup2(control_fd, WORKER_CONTROL_FD) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if detach && libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn().context("spawning VMM worker")
}

/// Bind the host vsock exec bridge UDS at `path`, replacing any stale socket left by
/// a previous run of the same machine. Returns the listening socket; its fd is passed
/// to the jailed worker (which accepts on it post-confinement) while the host side
/// connects to `path`.
fn bind_vsock_listener(path: &Path) -> Result<UnixListener> {
    // A leftover socket file from a prior boot would make bind fail with EADDRINUSE;
    // it is our own managed runtime artifact in the per-VM jail dir, so clear it.
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        use std::os::unix::fs::FileTypeExt;
        if meta.file_type().is_socket() {
            let _ = std::fs::remove_file(path);
        }
    }
    UnixListener::bind(path)
        .with_context(|| format!("binding vsock bridge socket {}", path.display()))
}

/// Open `/dev/kvm` read-write *without* CLOEXEC so the fd is inherited by the
/// re-exec'd worker.
fn open_kvm_inheritable() -> Result<RawFd> {
    let path = std::ffi::CString::new("/dev/kvm").expect("static path has no NUL");
    // SAFETY: `path` is a valid C string; we check the result.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return Err(anyhow::anyhow!(
            "opening /dev/kvm: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(fd)
}

/// Ensure a managed SSH keypair exists at `<root>/ssh/id_ed25519` (generating one
/// with `ssh-keygen` if absent) and return its public key hex-encoded for injection
/// on the kernel cmdline. `mm ssh` uses the matching private key.
fn ensure_ssh_key(root: &Path) -> Result<Option<String>> {
    let dir = root.join("ssh");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let key = dir.join("id_ed25519");
    let pubkey = dir.join("id_ed25519.pub");

    if !pubkey.exists() {
        let status = Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-C", "micromachines", "-f"])
            .arg(&key)
            .status()
            .context("running ssh-keygen (is OpenSSH installed?)")?;
        if !status.success() {
            anyhow::bail!("ssh-keygen failed with {status}");
        }
    }
    let contents =
        std::fs::read(&pubkey).with_context(|| format!("reading {}", pubkey.display()))?;
    // Trim a trailing newline so the injected key is exactly one line.
    let trimmed = contents
        .iter()
        .rposition(|&b| b != b'\n' && b != b'\r')
        .map(|i| &contents[..=i])
        .unwrap_or(&contents);
    Ok(Some(hex_encode(trimmed)))
}

/// Lowercase hex-encode bytes (for whitespace-safe cmdline transport).
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Draw a 32-byte CRNG seed from the host's `/dev/urandom` and hex-encode it for the
/// guest cmdline (`mm.random_seed=`). The host pool is already initialized, so this
/// is real entropy the guest can credit to unblock `getrandom(2)`. Returns `None` if
/// the host RNG is somehow unreadable (the guest then self-seeds slowly).
fn host_random_seed_hex() -> Option<String> {
    let mut seed = [0u8; 32];
    match std::fs::File::open("/dev/urandom").and_then(|mut f| {
        use std::io::Read;
        f.read_exact(&mut seed)
    }) {
        Ok(()) => Some(hex_encode(&seed)),
        Err(e) => {
            eprintln!("mm-host: reading host entropy for guest seed failed: {e}");
            None
        }
    }
}

/// Make the jail directories world-traversable (0755) and the kernel + rootfs
/// world-readable (0644), then verify the dropped uid can actually read them and
/// reach the chroot — failing loudly otherwise.
fn prepare_jail_permissions(jail: &Path, jail_root: &Path, files: &[&Path]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // The `<root>/jails` parent plus the per-VM dirs must be traversable.
    for dir in [jail.parent().unwrap_or(jail), jail, jail_root] {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("chmod 0755 {}", dir.display()))?;
    }
    for file in files {
        std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o644))
            .with_context(|| format!("chmod 0644 {}", file.display()))?;
        let mode = std::fs::metadata(file)
            .with_context(|| format!("stat {}", file.display()))?
            .permissions()
            .mode();
        if mode & 0o004 == 0 {
            anyhow::bail!(
                "{} is not world-readable (mode {:o}); the jailed uid {WORKER_UID} cannot read it",
                file.display(),
                mode & 0o777
            );
        }
    }
    verify_path_traversable(jail_root)?;
    Ok(())
}

/// Verify every directory from `path` up to the filesystem root is traversable by
/// "other" (the o+x bit), since the jailed uid must walk the whole path to reach the
/// chroot. Bails naming the first offending directory.
fn verify_path_traversable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut current = Some(path);
    while let Some(dir) = current {
        if let Ok(meta) = std::fs::metadata(dir) {
            let mode = meta.permissions().mode();
            if meta.is_dir() && mode & 0o001 == 0 {
                anyhow::bail!(
                    "directory {} is not world-traversable (mode {:o}); the jailed uid {WORKER_UID} cannot reach the chroot — `chmod o+x` it",
                    dir.display(),
                    mode & 0o777
                );
            }
        }
        current = dir.parent();
    }
    Ok(())
}

/// chown `path` to the unprivileged worker uid/gid so the confined (dropped) worker can
/// write into it — used for the in-jail snapshot dir (writable, unlike the read-only
/// kernel/rootfs).
fn chown_to_worker(path: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("path has interior NUL: {}", path.display()))?;
    // SAFETY: `c` is a valid C string path owned for the call; we check the result.
    let rc = unsafe { libc::chown(c.as_ptr(), WORKER_UID, WORKER_GID) };
    if rc != 0 {
        return Err(anyhow::anyhow!(
            "chown {} to {WORKER_UID}:{WORKER_GID}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Hardlink `src` into `dst`, falling back to a copy across filesystems. A
/// pre-existing `dst` is reused.
fn link_or_copy(src: &Path, dst: &Path) -> Result<()> {
    if dst.exists() {
        return Ok(());
    }
    if std::fs::hard_link(src, dst).is_ok() {
        return Ok(());
    }
    std::fs::copy(src, dst)
        .with_context(|| format!("copying {} -> {}", src.display(), dst.display()))?;
    Ok(())
}

/// Determine the default egress interface from the host routing table.
fn default_egress_iface() -> Option<String> {
    if let Ok(iface) = std::env::var("MM_EGRESS") {
        return Some(iface);
    }
    let output = Command::new("ip")
        .args(["route", "get", "1.1.1.1"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    // Parse "... dev <iface> ..." from the route line.
    let text = String::from_utf8_lossy(&output.stdout);
    let mut tokens = text.split_whitespace();
    while let Some(tok) = tokens.next() {
        if tok == "dev" {
            return tokens.next().map(str::to_string);
        }
    }
    None
}
