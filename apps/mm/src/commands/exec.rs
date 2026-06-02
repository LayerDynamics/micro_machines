//! `mm exec` — run a command inside a running sandbox guest (SPEC-1 FR-13).
//!
//! Single-host path: the guest's `mm-init` exec agent listens on a vsock port, and
//! the jailed VMM exposes a host Unix-domain bridge socket at
//! `<state_root>/jails/<name>/vsock.sock`. `mm exec` connects to that socket, speaks
//! the `CONNECT <port>\n` handshake, then streams the command's stdout/stderr back
//! and exits with the guest command's exit code — no SSH, no in-guest setup. (The
//! cluster path, controller -> agent -> guest, lives in [`crate::commands::remote::exec`]
//! and is used automatically when `--server` is set.)
use std::io::Write;

use anyhow::{Context, Result};

#[derive(Debug, clap::Args)]
pub struct ExecArgs {
    /// Machine name.
    pub name: String,
    /// Command (and arguments) to run in the guest.
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,
    /// Abort the command if it runs longer than this many milliseconds.
    #[arg(long, default_value_t = 60_000)]
    pub timeout_ms: u64,
}

pub fn run(args: ExecArgs) -> Result<()> {
    let store = crate::commands::open_store()?;
    let record = store
        .get(&args.name)?
        .ok_or_else(|| anyhow::anyhow!("no such machine: {}", args.name))?;
    if record.pid.is_none() {
        anyhow::bail!("machine {} is not running", args.name);
    }

    let vsock_path = crate::commands::state_root()
        .join("jails")
        .join(&args.name)
        .join("vsock.sock");
    if !vsock_path.exists() {
        anyhow::bail!(
            "machine {} has no vsock bridge socket at {} (is it running?)",
            args.name,
            vsock_path.display()
        );
    }

    // Retry the connect+handshake briefly: the guest's exec agent may not be listening
    // the instant the machine is recorded running (e.g. `mm exec` right after `mm run`).
    let result = mm_sandbox::exec::run_exec_over_uds_ready(
        &vsock_path,
        mm_sandbox::exec::EXEC_PORT,
        1,
        &args.command,
        args.timeout_ms,
        std::time::Duration::from_secs(30),
    )
    .with_context(|| format!("running exec in {}", args.name))?;

    // Forward the guest's streams to ours, then mirror its exit code.
    std::io::stdout().write_all(&result.stdout)?;
    std::io::stdout().flush()?;
    std::io::stderr().write_all(&result.stderr)?;
    std::io::stderr().flush()?;
    std::process::exit(result.exit_code);
}
