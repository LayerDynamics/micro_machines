//! `mm` — the MicroMachines single-host microVM manager (SPEC-1 FR-8/FR-9/FR-12).
//!
//! `mm run/ps/stop/rm/ssh` manage the lifecycle of microVMs on one Linux/KVM host:
//! `run` turns an OCI image into a booted, network-reachable microVM; the rest
//! operate on the local registry and clean up.
mod commands;
mod store;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "mm",
    version,
    about = "MicroMachines single-host microVM manager"
)]
struct Cli {
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
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Run(args) => commands::run::run(args),
        Command::Ps(args) => commands::ps::run(args),
        Command::Stop(args) => commands::stop::run(args),
        Command::Rm(args) => commands::rm::run(args),
        Command::Ssh(args) => commands::ssh::run(args),
    }
}
