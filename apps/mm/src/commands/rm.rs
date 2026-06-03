//! `mm rm` — remove a machine and clean up its host resources.
use anyhow::Result;

#[derive(Debug, clap::Args)]
pub struct RmArgs {
    /// Machine name.
    pub name: String,
    /// Remove even if the machine still appears to be running.
    #[arg(long)]
    pub force: bool,
}

pub fn run(args: RmArgs) -> Result<()> {
    let store = crate::commands::open_store()?;
    let record = store
        .get(&args.name)?
        .ok_or_else(|| anyhow::anyhow!("no such machine: {}", args.name))?;

    if !record.state.is_terminal() && !args.force {
        anyhow::bail!(
            "{} is {} — stop it first or pass --force",
            args.name,
            record.state
        );
    }

    // Tear down the TAP and the per-instance overlay; both are idempotent so a
    // partially-removed machine still cleans up.
    cleanup_host_resources(&record);

    store.delete(&args.name)?;
    println!("removed {}", args.name);
    Ok(())
}

#[cfg(target_os = "linux")]
fn cleanup_host_resources(record: &crate::store::MachineRecord) {
    if let Some(index) = record.clone_index {
        // A live `mm branch` clone: tear down its per-clone networking (netns + veth +
        // host route + MASQUERADE). Deleting the netns also removes the in-netns TAP, so
        // the shared-bridge `teardown_tap` below is skipped for clones.
        if let Some(clone_ip) = record.ip {
            if let Err(e) = mm_host::teardown_clone_net(
                &record.meta.name,
                index,
                clone_ip,
                record.clone_upstream.clone(),
            ) {
                tracing::warn!(
                    "failed to tear down clone net for {}: {e}",
                    record.meta.name
                );
            }
        }
    } else if let Some(tap) = &record.tap {
        if let Err(e) = mm_net::teardown_tap(tap) {
            tracing::warn!("failed to remove TAP {tap}: {e}");
        }
    }
    let images = mm_image::ImageStore::new(crate::commands::state_root());
    if let Err(e) = images.remove_instance_overlay(&record.meta.name) {
        tracing::warn!("failed to remove overlay for {}: {e}", record.meta.name);
    }
}

#[cfg(not(target_os = "linux"))]
fn cleanup_host_resources(_record: &crate::store::MachineRecord) {}
