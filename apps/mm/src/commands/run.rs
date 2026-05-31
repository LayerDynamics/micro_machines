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
) -> VmConfig {
    let ip_param = mm_net::ip_cmdline(ip, gateway, mask, hostname, "eth0");
    let mode = if sandbox {
        "mm.mode=sandbox".to_string()
    } else {
        "mm.workload=/sbin/init".to_string()
    };
    let kernel_cmdline = format!("console=ttyS0 reboot=k panic=1 {ip_param} {mode}");
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
    use std::process::Command;
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::{Context, Result};
    use mm_api_types::{ObjectMeta, State};
    use mm_image::ImageStore;
    use mm_vmm::{Machine, VcpuHook, VmmError};
    use time::OffsetDateTime;

    use super::*;
    use crate::store::{MachineRecord, Store};

    /// The `/24` MicroMachines guests live on, plus the bridge name.
    const SUBNET_BASE: [u8; 3] = [10, 0, 0];
    const SUBNET_CIDR: &str = "10.0.0.0/24";
    const BRIDGE: &str = "mm-br0";

    /// Path to the guest kernel (`MM_KERNEL`, else `<root>/vmlinux`).
    fn kernel_path() -> PathBuf {
        std::env::var_os("MM_KERNEL")
            .map(PathBuf::from)
            .unwrap_or_else(|| crate::commands::state_root().join("vmlinux"))
    }

    /// Full `mm run` orchestration on Linux. Runs the VM in the foreground: it
    /// returns when the guest powers off (background it with `&` to keep using the
    /// CLI). Privileged host setup (bridge/TAP/NAT) happens first; the in-process
    /// VMM is then hardened with cgroup limits and a per-thread seccomp filter
    /// applied before any guest code runs.
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

        // 3. Privileged host networking (must precede any confinement, SPEC-1 C6).
        mm_net::ensure_bridge(BRIDGE, gateway, 24).context("ensuring bridge")?;
        let tap_name = format!("mm-{name}");
        let _tap = mm_net::create_tap(&tap_name, BRIDGE).context("creating TAP")?;
        let egress = default_egress_iface().unwrap_or_else(|| "eth0".to_string());
        mm_net::enable_nat(SUBNET_CIDR, &egress).context("enabling NAT")?;

        // 4. VM configuration.
        let cfg = build_vm_config(
            args.cpus,
            args.memory,
            kernel_path(),
            rootfs,
            ip,
            gateway,
            NETMASK,
            &name,
            tap_name.clone(),
            mac_from_ip(ip),
            args.ssh,
        );
        cfg.validate().context("validating VM config")?;

        // 5. Hardening that composes with the in-process VMM:
        //    (a) cgroup v2 cpu/memory caps; (b) per-thread seccomp before guest code.
        // NOTE: M1 `mm run` is the privileged (root) path. The seccomp install in
        // the vCPU hook relies on that privilege; it does NOT first set
        // PR_SET_NO_NEW_PRIVS (that happens in the not-yet-wired jailer `confine`),
        // so a rootless `mm run` would fail at the hook and abort the boot. See the
        // M1 plan TODO 1 (wiring the full jailer into the in-process boot).
        let cgroup = mm_sandbox::CgroupLimits {
            name: format!("micro_machines/{name}"),
            cpu_max: format!("{} 100000", u64::from(args.cpus) * 100_000),
            memory_max_bytes: args.memory * 1024 * 1024,
        };
        if let Err(e) = mm_sandbox::apply_cgroup_limits(&cgroup) {
            tracing::warn!("cgroup limits not applied ({e}); continuing without caps");
        }
        let rules = Arc::new(mm_sandbox::vmm_thread_rules());
        let hook: VcpuHook = {
            let rules = rules.clone();
            Arc::new(move |_idx| {
                rules
                    .apply_to_current_thread()
                    .map_err(|e| VmmError::Device(format!("seccomp install failed: {e}")))
            })
        };

        // 6. Boot.
        let mut machine = Machine::boot_with_hook(&cfg, Some(hook)).context("booting microVM")?;
        let ready = machine
            .wait_for_ready(Duration::from_secs(10))
            .context("waiting for guest readiness")?;
        if !ready {
            tracing::warn!("guest did not signal readiness within 10s");
        }

        // 7. Record as running and report.
        let record = MachineRecord {
            meta: ObjectMeta::new(&name, "default", OffsetDateTime::now_utc()),
            state: State::Running,
            image: args.image.clone(),
            vcpus: args.cpus,
            memory_mib: args.memory,
            ip: Some(ip),
            tap: Some(tap_name),
            pid: Some(std::process::id()),
        };
        store.put(&record)?;
        println!("{name}\t{ip}");

        // 8. Foreground: serve the guest until it powers off, then mark stopped.
        machine.shutdown().context("running microVM")?;
        let mut stopped = record;
        stopped.state = State::Stopped;
        stopped.pid = None;
        store.put(&stopped)?;
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
        );
        assert!(cfg.kernel_cmdline.contains("mm.mode=sandbox"));
        assert!(!cfg.kernel_cmdline.contains("mm.workload"));
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
