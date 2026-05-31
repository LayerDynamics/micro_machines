//! `mm stop` — stop a running machine.
use anyhow::Result;
use mm_api_types::State;

#[derive(Debug, clap::Args)]
pub struct StopArgs {
    /// Machine name.
    pub name: String,
}

pub fn run(args: StopArgs) -> Result<()> {
    let store = crate::commands::open_store()?;
    let mut record = store
        .get(&args.name)?
        .ok_or_else(|| anyhow::anyhow!("no such machine: {}", args.name))?;

    if record.state.is_terminal() {
        println!("{} is already {}", args.name, record.state);
        return Ok(());
    }

    // Signal the owning `mm run` foreground process to power the guest off; the
    // guest's panic=1/reboot=k then halts the vCPUs and that process records the
    // stopped state. If the process is gone, fall through to marking it stopped.
    if let Some(pid) = record.pid {
        signal_terminate(pid);
    }

    record.state = State::Stopped;
    record.pid = None;
    store.put(&record)?;
    println!("stopped {}", args.name);
    Ok(())
}

#[cfg(target_os = "linux")]
fn signal_terminate(pid: u32) {
    // SAFETY: kill(2) with a pid and SIGTERM is always safe to call; a missing
    // process simply yields ESRCH, which we ignore.
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
}

#[cfg(not(target_os = "linux"))]
fn signal_terminate(_pid: u32) {}
