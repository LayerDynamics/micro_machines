//! `mm` — the MicroMachines microVM manager (SPEC-1 FR-8/FR-9/FR-12, FR-29).
//!
//! `mm run/ps/stop/rm/ssh` manage the lifecycle of microVMs. By default they operate
//! on one local Linux/KVM host (the M1 path). With `--server <url>` (or `MM_SERVER`)
//! they instead drive a cluster control-plane over its REST API with a bearer JWT —
//! the same verbs, against many hosts.
mod commands;
mod store;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "mm",
    version,
    about = "MicroMachines microVM manager (single-host, or cluster with --server)"
)]
struct Cli {
    /// Control-plane URL. When set, `run/ps/stop/rm` operate against the cluster
    /// REST API instead of this host. Unset = local single-host mode (the default).
    #[arg(long, global = true, env = "MM_SERVER")]
    server: Option<String>,
    /// Bearer token (JWT) for the control-plane API.
    #[arg(long, global = true, env = "MM_TOKEN")]
    token: Option<String>,
    /// Namespace to operate in when talking to a controller.
    #[arg(long, global = true, env = "MM_NAMESPACE", default_value = "default")]
    namespace: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Boot a microVM from an OCI image.
    Run(commands::run::RunArgs),
    /// List machines and their state/IP.
    Ps(commands::ps::PsArgs),
    /// Stop a running machine.
    Stop(commands::stop::StopArgs),
    /// Remove a machine and clean up its resources.
    Rm(commands::rm::RmArgs),
    /// SSH into a machine by name.
    Ssh(commands::ssh::SshArgs),
    /// Run a command inside a running sandbox guest over vsock.
    Exec(commands::exec::ExecArgs),
    /// (internal) Jailed VMM worker, spawned by `mm run`. Not for direct use.
    #[command(name = "__vmm-worker", hide = true)]
    Worker(commands::worker::WorkerArgs),
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // The internal worker is always local (it re-execs from `mm run`); never remote.
    if let Command::Worker(args) = cli.command {
        return commands::worker::run(args);
    }

    // Cluster mode: drive the controller REST API for the lifecycle verbs. `ssh`
    // stays local (it needs the host-local managed key + record).
    if let Some(server) = cli.server.clone() {
        let client = commands::remote::RemoteClient::new(server, cli.token, cli.namespace);
        return match cli.command {
            Command::Run(args) => commands::remote::run(&client, args),
            Command::Ps(args) => commands::remote::ps(&client, args),
            Command::Stop(args) => commands::remote::stop(&client, args),
            Command::Rm(args) => commands::remote::rm(&client, args),
            Command::Ssh(_) => {
                anyhow::bail!("`mm ssh` is not available in cluster mode; ssh to the host or use the guest IP from `mm --server ... ps`")
            }
            Command::Exec(args) => commands::remote::exec(&client, args),
            Command::Worker(_) => unreachable!("handled above"),
        };
    }

    // Local single-host mode (M1).
    match cli.command {
        Command::Run(args) => commands::run::run(args),
        Command::Ps(args) => commands::ps::run(args),
        Command::Stop(args) => commands::stop::run(args),
        Command::Rm(args) => commands::rm::run(args),
        Command::Ssh(args) => commands::ssh::run(args),
        Command::Exec(args) => commands::exec::run(args),
        Command::Worker(_) => unreachable!("handled above"),
    }
}
