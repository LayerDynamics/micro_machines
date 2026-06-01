//! `mm-agent` — the MicroMachines host agent (SPEC-1 FR-17/FR-19, NFR-R2).
//!
//! Runs on each Linux/KVM host. It registers capacity with the controller, then
//! watches a stream of assignments and reconciles each into a real microVM via the
//! shared [`mm_host`] boot path, persisting what it owns to a local store so a
//! restart recovers without the controller. Observed state flows back as
//! `ReportEvent` calls.
//!
//! The binary is also the `__vmm-worker` re-exec target (`mm_host::launch` re-execs
//! `current_exe() __vmm-worker`), so it dispatches that subcommand *before* starting
//! any async runtime — the worker forks and enters namespaces, which must happen
//! single-threaded.
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tonic::transport::Channel;

use mm_agent::actuator::{self, BootRequest, HostConfig};
use mm_agent::capacity::{self, HostResources, Reservation};
use mm_agent::local_store::LocalStore;
use mm_proto::host_service_client::HostServiceClient;
use mm_proto::machine_service_client::MachineServiceClient;
use mm_proto::{Assignment, Capacity, HostRef, MachineEvent, State};

#[derive(Parser)]
#[command(name = "mm-agent", about = "MicroMachines host agent")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the host agent: register, watch assignments, and reconcile microVMs.
    Run(AgentArgs),
    /// (internal) Jailed VMM worker, spawned by the agent via re-exec. Not for
    /// direct use.
    #[command(name = "__vmm-worker", hide = true)]
    Worker(mm_host::WorkerArgs),
}

#[derive(clap::Args)]
struct AgentArgs {
    /// Controller gRPC endpoint (e.g. `http://controller:50051`).
    #[arg(long)]
    controller: String,
    /// This host's stable identifier.
    #[arg(long)]
    host_id: String,
    /// Root directory for host state (image cache + per-VM jails + agent registry).
    #[arg(long, default_value = "/var/lib/micro_machines")]
    state_root: PathBuf,
    /// Guest kernel image.
    #[arg(long, env = "MM_KERNEL")]
    kernel: PathBuf,
    /// Guest `mm-init` binary (injected as `/init`).
    #[arg(long, env = "MM_INIT")]
    init: PathBuf,
    /// Optional static sshd injected as `/sbin/dropbear`.
    #[arg(long, env = "MM_SSHD")]
    sshd: Option<PathBuf>,
    /// Total vCPUs this host offers to microVMs.
    #[arg(long, default_value_t = 8)]
    vcpus_total: u32,
    /// Total memory (MiB) this host offers to microVMs.
    #[arg(long, default_value_t = 16384)]
    mem_mib_total: u64,
    /// Directory holding the mTLS CA + client cert/key (wired in a later task).
    #[arg(long, default_value = "./certs")]
    tls_dir: PathBuf,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match Cli::parse().cmd {
        // Run the jailed worker on the current (single-threaded) process: it forks +
        // enters namespaces, so it must execute before any tokio runtime exists.
        Command::Worker(args) => mm_host::run_worker(args),
        Command::Run(args) => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("building async runtime")?
            .block_on(run_agent(args)),
    }
}

/// Run the agent: maintain a session with the controller, reconnecting forever.
async fn run_agent(args: AgentArgs) -> Result<()> {
    let store = LocalStore::open(args.state_root.join("agent.redb"))?;
    let host = HostConfig {
        state_root: args.state_root.clone(),
        kernel_path: args.kernel.clone(),
        mm_init_path: args.init.clone(),
        sshd_path: args.sshd.clone(),
    };
    let host_res = HostResources {
        vcpus_total: args.vcpus_total,
        mem_mib_total: args.mem_mib_total,
    };

    loop {
        if let Err(e) = serve_once(&store, &host, host_res, &args).await {
            tracing::warn!("controller session ended: {e}; retrying in 5s");
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// One controller session: connect, report capacity, heartbeat, and process the
/// assignment stream until it ends or errors.
async fn serve_once(
    store: &LocalStore,
    host: &HostConfig,
    host_res: HostResources,
    args: &AgentArgs,
) -> Result<()> {
    let mut endpoint =
        Channel::from_shared(args.controller.clone()).context("invalid controller endpoint")?;
    // Use mTLS when a CA is present in the cert dir (production); fall back to plain
    // gRPC for local/dev where no certs are provisioned.
    if args.tls_dir.join("ca.pem").exists() {
        let domain = controller_domain(&args.controller);
        endpoint = endpoint
            .tls_config(mm_agent::tls::client_config(&args.tls_dir, &domain)?)
            .context("configuring client mTLS")?;
    }
    let channel = endpoint
        .connect()
        .await
        .context("connecting to controller")?;
    let mut hosts = HostServiceClient::new(channel.clone());
    let mut machines = MachineServiceClient::new(channel);

    // Advertise current capacity so the scheduler can place onto this host.
    hosts
        .report_capacity(current_capacity(store, host_res, &args.host_id)?)
        .await
        .context("reporting capacity")?;
    tracing::info!(host = %args.host_id, "registered with controller");

    // Heartbeat in the background; aborted when this session ends.
    let heartbeat = {
        let mut hb = hosts.clone();
        let host_id = args.host_id.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(10));
            loop {
                tick.tick().await;
                if hb
                    .heartbeat(HostRef {
                        host_id: host_id.clone(),
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        })
    };
    // Ensure the heartbeat task is torn down when we leave this session.
    struct AbortOnDrop(tokio::task::JoinHandle<()>);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _guard = AbortOnDrop(heartbeat);

    let mut stream = machines
        .watch_assignments(HostRef {
            host_id: args.host_id.clone(),
        })
        .await
        .context("opening assignment stream")?
        .into_inner();

    while let Some(assignment) = stream.message().await.context("reading assignment")? {
        if let Err(e) = handle_assignment(store, host, assignment, &mut hosts).await {
            tracing::warn!("handling assignment: {e}");
        }
        // Capacity changed as machines start/stop — re-advertise.
        if let Ok(cap) = current_capacity(store, host_res, &args.host_id) {
            let _ = hosts.report_capacity(cap).await;
        }
    }
    Ok(())
}

/// Reconcile a single assignment toward its desired `spec.running`.
async fn handle_assignment(
    store: &LocalStore,
    host: &HostConfig,
    assignment: Assignment,
    hosts: &mut HostServiceClient<Channel>,
) -> Result<()> {
    let machine = assignment.machine.context("assignment without a machine")?;
    let mref = machine.r#ref.context("machine without a ref")?;
    let spec = machine.spec.context("machine without a spec")?;
    let uid = mref.uid;
    let existing = store.get(&uid)?;

    if spec.running {
        if existing
            .as_ref()
            .map(|m| m.state == "running")
            .unwrap_or(false)
        {
            return Ok(()); // already converged
        }
        let req = BootRequest {
            uid: uid.clone(),
            namespace: mref.namespace,
            name: host_name(&uid),
            image: spec.image,
            cpus: spec.vcpus.clamp(1, u32::from(u8::MAX)) as u8,
            memory_mib: spec.memory_mib,
            ssh: spec.ssh,
        };
        match actuator::boot(host, &req, reserved_ips(store)?) {
            Ok(machine) => {
                let ip = machine.ip.clone().unwrap_or_default();
                store.put(&machine)?;
                report(hosts, &uid, State::Running, "booted", &ip).await;
            }
            Err(e) => {
                tracing::warn!("booting {uid}: {e}");
                report(hosts, &uid, State::Failed, &e.to_string(), "").await;
            }
        }
    } else if let Some(machine) = existing {
        // Desired stopped: stop the worker and mark it stopped (the record stays so
        // it can be started again).
        actuator::stop(&machine);
        let mut stopped = machine;
        stopped.state = "stopped".to_string();
        stopped.pid = None;
        store.put(&stopped)?;
        report(hosts, &uid, State::Stopped, "stopped", "").await;
    }
    Ok(())
}

/// Report a machine's observed state transition to the controller (best-effort). A
/// `Running` event carries the guest IP the agent allocated at boot.
async fn report(
    hosts: &mut HostServiceClient<Channel>,
    uid: &str,
    state: State,
    message: &str,
    ip: &str,
) {
    let event = MachineEvent {
        uid: uid.to_string(),
        state: state as i32,
        message: message.to_string(),
        ip: ip.to_string(),
    };
    if let Err(e) = hosts.report_event(event).await {
        tracing::warn!("reporting event for {uid}: {e}");
    }
}

/// Current free/total capacity, as the controller's `Capacity` message.
fn current_capacity(
    store: &LocalStore,
    host_res: HostResources,
    host_id: &str,
) -> Result<Capacity> {
    let running: Vec<Reservation> = store
        .list()?
        .into_iter()
        .filter(|m| m.state == "running")
        .map(|m| Reservation {
            vcpus: m.vcpus,
            mem_mib: m.memory_mib,
        })
        .collect();
    let c = capacity::compute(host_res, &running);
    Ok(Capacity {
        host_id: host_id.to_string(),
        vcpus_total: c.vcpus_total,
        vcpus_free: c.vcpus_free,
        mem_mib_total: c.mem_mib_total,
        mem_mib_free: c.mem_mib_free,
    })
}

/// The IPs already held by machines on this host, to seed the launch IPAM pool.
fn reserved_ips(store: &LocalStore) -> Result<Vec<Ipv4Addr>> {
    Ok(store
        .list()?
        .into_iter()
        .filter_map(|m| m.ip.and_then(|s| s.parse().ok()))
        .collect())
}

/// Extract the host portion of a controller endpoint URL, used as the TLS server
/// name (which must match the controller certificate's SAN).
fn controller_domain(url: &str) -> String {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let host = after_scheme.split('/').next().unwrap_or(after_scheme);
    host.split(':').next().unwrap_or(host).to_string()
}

/// A short, stable host-local name derived from a machine uid. The TAP device name
/// (`mm-<name>`) must fit in `IFNAMSIZ` (16), so keep the name short.
fn host_name(uid: &str) -> String {
    let short: String = uid
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(10)
        .collect();
    format!("a{short}")
}
