//! `mm run` — build a rootfs, wire networking, harden, and boot a microVM.
use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::Result;
use mm_vmm::{BlockDevice, VirtioDevice, VmConfig};

/// Arguments for `mm run`.
#[derive(Debug, clap::Args)]
pub struct RunArgs {
    /// OCI image reference (e.g. `docker.io/library/alpine:latest`).
    pub image: String,
    /// Number of virtual CPUs.
    #[arg(long, default_value_t = 1)]
    pub cpus: u8,
    /// Memory in MiB.
    #[arg(long, default_value_t = 512)]
    pub memory: u64,
    /// Machine name (defaults to a name derived from the image).
    #[arg(long)]
    pub name: Option<String>,
    /// Boot into an SSH-reachable sandbox shell rather than the image workload.
    #[arg(long)]
    pub ssh: bool,
    /// Run the microVM in the background (its own session) and return immediately,
    /// capturing the guest console to a per-VM log, instead of staying foreground.
    #[arg(long, short = 'd')]
    pub detach: bool,
}

/// The guest netmask for the MicroMachines `/24` (used when building the cmdline).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

/// Build the VM configuration from resolved inputs. Pure (no I/O) so it is unit
/// tested directly; the kernel cmdline carries the static `ip=` (no in-guest DHCP)
/// and the `mm.*` guest-init directives.
#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn build_vm_config(
    vcpus: u8,
    memory_mib: u64,
    kernel: PathBuf,
    rootfs: PathBuf,
    ip: Ipv4Addr,
    gateway: Ipv4Addr,
    mask: Ipv4Addr,
    hostname: &str,
    tap_name: String,
    mac: String,
    sandbox: bool,
    authorized_key_hex: Option<&str>,
) -> VmConfig {
    let ip_param = mm_net::ip_cmdline(ip, gateway, mask, hostname, "eth0");
    let mode = if sandbox {
        "mm.mode=sandbox".to_string()
    } else {
        "mm.workload=/sbin/init".to_string()
    };
    // root=/dev/vda: the rootfs is the first virtio-mmio block device. init=/init:
    // mm-init is PID 1 in the guest image. The rootfs is read-only in M1 (writes go
    // to tmpfs mounts that mm-init sets up).
    let mut kernel_cmdline =
        format!("console=ttyS0 root=/dev/vda ro init=/init reboot=k panic=1 {ip_param} {mode}");
    if let Some(hex) = authorized_key_hex {
        // Hex-encoded (no spaces) so it survives the whitespace-split cmdline.
        kernel_cmdline.push_str(&format!(" mm.authorized_key={hex}"));
    }
    VmConfig {
        vcpus,
        memory_mib,
        kernel,
        kernel_cmdline,
        rootfs: BlockDevice {
            path: rootfs,
            read_only: true,
        },
        devices: vec![VirtioDevice::Net { tap_name, mac }],
    }
}

/// Derive a default machine name from an image reference: last path component,
/// tag stripped, plus a short unique suffix.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn default_name(image: &str) -> String {
    let base = image
        .rsplit('/')
        .next()
        .unwrap_or(image)
        .split(':')
        .next()
        .unwrap_or("vm");
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    format!("{base}-{}", &suffix[..6])
}

/// A locally-administered MAC derived from the guest IP (stable per IP).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn mac_from_ip(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("02:00:00:{:02x}:{:02x}:{:02x}", o[1], o[2], o[3])
}

pub fn run(args: RunArgs) -> Result<()> {
    let store = crate::commands::open_store()?;
    #[cfg(target_os = "linux")]
    {
        linux::launch(&args, &store)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (&args, &store);
        anyhow::bail!("`mm run` boots a microVM and requires a Linux/KVM host");
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::io::RawFd;
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};

    use anyhow::{Context, Result};
    use mm_api_types::{ObjectMeta, State};
    use mm_image::ImageStore;
    use time::OffsetDateTime;

    use super::*;
    use crate::store::{MachineRecord, Store};

    /// The `/24` MicroMachines guests live on, plus the bridge name.
    const SUBNET_BASE: [u8; 3] = [10, 0, 0];
    const SUBNET_CIDR: &str = "10.0.0.0/24";
    const BRIDGE: &str = "mm-br0";
    /// Unprivileged uid/gid the jailed worker drops to (nobody/nogroup).
    const WORKER_UID: u32 = 65534;
    const WORKER_GID: u32 = 65534;
    /// Fixed fd numbers the worker inherits the KVM + TAP fds at.
    const WORKER_KVM_FD: RawFd = 10;
    const WORKER_TAP_FD: RawFd = 11;

    /// Path to the guest kernel (`MM_KERNEL`, else `<root>/vmlinux`).
    fn kernel_path() -> PathBuf {
        std::env::var_os("MM_KERNEL")
            .map(PathBuf::from)
            .unwrap_or_else(|| crate::commands::state_root().join("vmlinux"))
    }

    /// Privileged `mm run`: build the rootfs, wire the bridge/TAP/NAT, open
    /// `/dev/kvm`, prepare a per-VM chroot, then spawn the jailed `mm __vmm-worker`
    /// child — passing it the KVM + TAP fds. The child confines itself
    /// (namespaces/chroot/cgroup/seccomp/uid-drop) and runs the guest. This parent
    /// records the machine and waits in the foreground (background with `&`).
    pub fn launch(args: &RunArgs, store: &Store) -> Result<()> {
        let root = crate::commands::state_root();

        // 1. OCI image -> read-only base rootfs (digest-cached).
        let images = ImageStore::new(&root);
        let rootfs = images
            .build_base_rootfs(&args.image)
            .with_context(|| format!("building rootfs for {}", args.image))?;

        // 2. Name + IP (seed the pool from already-running machines).
        let name = args
            .name
            .clone()
            .unwrap_or_else(|| default_name(&args.image));
        if store.get(&name)?.is_some() {
            anyhow::bail!("a machine named {name} already exists");
        }
        let mut ipam = mm_net::Ipam::new(SUBNET_BASE, 1);
        for rec in store.list()? {
            if let Some(ip) = rec.ip {
                ipam.reserve(ip);
            }
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
        link_or_copy(&kernel_path(), &jail_kernel)?;
        link_or_copy(&rootfs, &jail_rootfs)?;
        // Make the jail traversable and the kernel/rootfs readable by the dropped
        // (nobody) uid, failing loudly if a path is not — otherwise the confined
        // worker would hit an opaque "permission denied" deep inside the boot.
        prepare_jail_permissions(&jail, &jail_root, &[&jail_kernel, &jail_rootfs])?;

        // 6. Worker VM config with chroot-relative paths; serialized for the child.
        // Inject the managed SSH public key so `mm ssh` works with no in-guest setup.
        let authorized_key_hex = ensure_ssh_key(&root)?;
        let worker_cfg = build_vm_config(
            args.cpus,
            args.memory,
            PathBuf::from("/vmlinux"),
            PathBuf::from("/rootfs.ext4"),
            ip,
            gateway,
            NETMASK,
            &name,
            tap_name.clone(),
            mac_from_ip(ip),
            args.ssh,
            authorized_key_hex.as_deref(),
        );
        worker_cfg.validate().context("validating VM config")?;
        let cfg_path = jail.join("config.json");
        std::fs::write(&cfg_path, serde_json::to_vec(&worker_cfg)?)
            .with_context(|| format!("writing {}", cfg_path.display()))?;

        // 7. Spawn the jailed worker, passing the KVM + TAP fds.
        let cgroup = format!("micro_machines/{name}");
        let cpu_max = format!("{} 100000", u64::from(args.cpus) * 100_000);
        let mem_max = args.memory * 1024 * 1024;
        let log_path = jail.join("console.log");
        let mut child = spawn_worker(
            &cfg_path,
            kvm_fd,
            tap.as_raw_fd(),
            &jail_root,
            &cgroup,
            &cpu_max,
            mem_max,
            args.detach,
            &log_path,
        )?;

        // 8. Record as running and report.
        let record = MachineRecord {
            meta: ObjectMeta::new(&name, "default", OffsetDateTime::now_utc()),
            state: State::Running,
            image: args.image.clone(),
            vcpus: args.cpus,
            memory_mib: args.memory,
            ip: Some(ip),
            tap: Some(tap_name),
            pid: Some(child.id()),
        };
        store.put(&record)?;
        println!("{name}\t{ip}");

        // The child now owns its copies of the fds; the persistent TAP survives the
        // parent dropping its handle.
        // SAFETY: `kvm_fd` is the fd we opened; the child inherited its own copy.
        unsafe { libc::close(kvm_fd) };
        drop(tap);

        if args.detach {
            // The worker runs in its own session; leave it running and return.
            println!("detached; guest console -> {}", log_path.display());
            return Ok(());
        }

        // 9. Foreground: wait for the worker, then mark stopped.
        let status = child.wait().context("waiting for the VMM worker")?;
        if !status.success() {
            tracing::warn!("VMM worker exited with {status}");
        }
        let mut stopped = record;
        stopped.state = State::Stopped;
        stopped.pid = None;
        store.put(&stopped)?;
        Ok(())
    }

    /// Spawn `mm __vmm-worker`, dup'ing the KVM + TAP fds to fixed numbers in the
    /// child so they survive `exec` at predictable descriptors. When `detach` is
    /// set, the worker is put in its own session (`setsid`) and its console is
    /// redirected to `log_path`, so it outlives the parent and the terminal.
    #[allow(clippy::too_many_arguments)]
    fn spawn_worker(
        config: &Path,
        kvm_fd: RawFd,
        tap_fd: RawFd,
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

        // SAFETY: `pre_exec` runs in the forked child before `exec`; `dup2` and
        // `setsid` are async-signal-safe; `dup2` clears CLOEXEC on the target so
        // 10/11 survive exec.
        unsafe {
            cmd.pre_exec(move || {
                if libc::dup2(kvm_fd, WORKER_KVM_FD) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::dup2(tap_fd, WORKER_TAP_FD) < 0 {
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

    /// Ensure a managed SSH keypair exists at `<root>/ssh/id_ed25519` (generating
    /// one with `ssh-keygen` if absent) and return its public key hex-encoded for
    /// injection on the kernel cmdline. `mm ssh` uses the matching private key.
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

    /// Make the jail directories world-traversable (0755) and the kernel + rootfs
    /// world-readable (0644), then verify the dropped uid can actually read them
    /// and reach the chroot — failing loudly otherwise.
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

    /// Verify every directory from `path` up to the filesystem root is traversable
    /// by "other" (the o+x bit), since the jailed uid must walk the whole path to
    /// reach the chroot. Bails naming the first offending directory.
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_config_carries_static_ip_and_workload_mode() {
        let cfg = build_vm_config(
            2,
            512,
            PathBuf::from("/k/vmlinux"),
            PathBuf::from("/r/root.ext4"),
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            NETMASK,
            "web-1",
            "mm-web-1".to_string(),
            "02:00:00:0a:00:02".to_string(),
            false,
            None,
        );
        assert_eq!(cfg.vcpus, 2);
        assert!(cfg
            .kernel_cmdline
            .contains("ip=10.0.0.2::10.0.0.1:255.255.255.0:web-1:eth0:off"));
        assert!(cfg.kernel_cmdline.contains("mm.workload=/sbin/init"));
        assert!(cfg.rootfs.read_only);
        assert_eq!(
            cfg.devices,
            vec![VirtioDevice::Net {
                tap_name: "mm-web-1".to_string(),
                mac: "02:00:00:0a:00:02".to_string()
            }]
        );
    }

    #[test]
    fn sandbox_flag_selects_sandbox_mode() {
        let cfg = build_vm_config(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(10, 0, 0, 1),
            NETMASK,
            "s",
            "tap".to_string(),
            "02:00:00:0a:00:05".to_string(),
            true,
            None,
        );
        assert!(cfg.kernel_cmdline.contains("mm.mode=sandbox"));
        assert!(!cfg.kernel_cmdline.contains("mm.workload"));
    }

    #[test]
    fn authorized_key_is_injected_on_cmdline() {
        let cfg = build_vm_config(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            Ipv4Addr::new(10, 0, 0, 7),
            Ipv4Addr::new(10, 0, 0, 1),
            NETMASK,
            "k",
            "tap".to_string(),
            "02:00:00:0a:00:07".to_string(),
            false,
            Some("deadbeef"),
        );
        assert!(cfg.kernel_cmdline.contains("mm.authorized_key=deadbeef"));
    }

    #[test]
    fn default_name_strips_registry_and_tag() {
        let n = default_name("docker.io/library/alpine:latest");
        assert!(n.starts_with("alpine-"), "got {n}");
        assert_eq!(n.len(), "alpine-".len() + 6);
    }

    #[test]
    fn mac_is_locally_administered_and_ip_derived() {
        assert_eq!(mac_from_ip(Ipv4Addr::new(10, 0, 0, 2)), "02:00:00:00:00:02");
        assert_eq!(mac_from_ip(Ipv4Addr::new(10, 1, 2, 3)), "02:00:00:01:02:03");
    }

    #[test]
    fn cli_parses_run_flags() {
        use clap::Parser;
        #[derive(Parser)]
        struct Wrap {
            #[command(subcommand)]
            cmd: Cmd,
        }
        #[derive(clap::Subcommand)]
        enum Cmd {
            Run(RunArgs),
        }
        let Wrap {
            cmd: Cmd::Run(args),
        } = Wrap::try_parse_from([
            "mm",
            "run",
            "alpine:latest",
            "--cpus",
            "4",
            "--memory",
            "1024",
            "--name",
            "x",
            "--ssh",
        ])
        .unwrap();
        assert_eq!(args.image, "alpine:latest");
        assert_eq!(args.cpus, 4);
        assert_eq!(args.memory, 1024);
        assert_eq!(args.name.as_deref(), Some("x"));
        assert!(args.ssh);
    }
}
