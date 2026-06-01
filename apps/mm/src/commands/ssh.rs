//! `mm ssh` — connect to a machine's guest over SSH (SPEC-1 FR-12).
//!
//! The guest is reachable at its allocated IP with no manual sshd/key setup by the
//! operator: `mm` drives the system `ssh` client to `root@<ip>`, using a managed
//! identity at `<root>/ssh/id_ed25519` when present and disabling host-key
//! prompts (guest host keys are ephemeral). Shelling out to `ssh` keeps the auth
//! path standard and avoids linking a C TLS/SSH stack into the CLI.
use std::process::Command;

use anyhow::{Context, Result};

#[derive(Debug, clap::Args)]
pub struct SshArgs {
    /// Machine name.
    pub name: String,
    /// Optional command to run in the guest (otherwise an interactive shell).
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,
}

pub fn run(args: SshArgs) -> Result<()> {
    let store = crate::commands::open_store()?;
    let record = store
        .get(&args.name)?
        .ok_or_else(|| anyhow::anyhow!("no such machine: {}", args.name))?;
    let ip = record
        .ip
        .ok_or_else(|| anyhow::anyhow!("machine {} has no IP", args.name))?;

    let mut cmd = Command::new("ssh");
    cmd.args([
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "LogLevel=ERROR",
        // Fail fast instead of blocking on the kernel TCP timeout when the guest is
        // unreachable, and never fall back to an interactive password prompt (auth
        // is key-only). Keeps `mm ssh` responsive and scriptable.
        "-o",
        "ConnectTimeout=10",
        "-o",
        "BatchMode=yes",
    ]);
    let identity = crate::commands::state_root().join("ssh").join("id_ed25519");
    if identity.exists() {
        cmd.arg("-i").arg(&identity);
    }
    cmd.arg(format!("root@{ip}"));
    if !args.command.is_empty() {
        cmd.arg("--").args(&args.command);
    }

    let status = cmd
        .status()
        .context("failed to launch ssh (is the OpenSSH client installed?)")?;
    if !status.success() {
        anyhow::bail!("ssh to {} exited with {}", args.name, status);
    }
    Ok(())
}
