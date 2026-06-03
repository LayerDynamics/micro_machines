//! `mm` subcommands and shared state-location helpers.
pub mod exec;
pub mod ps;
pub mod remote;
pub mod rm;
pub mod run;
pub mod snapshot;
pub mod ssh;
pub mod stop;
pub mod worker;

use std::path::PathBuf;

use anyhow::Result;

use crate::store::Store;

/// Root directory for all MicroMachines host state (images, instances, registry).
/// Overridable with `MM_ROOT` (handy for tests and rootless runs).
pub fn state_root() -> PathBuf {
    std::env::var_os("MM_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/micro_machines"))
}

/// Path to the machine registry database.
pub fn store_path() -> PathBuf {
    state_root().join("machines.redb")
}

/// Open the machine registry, creating the parent directory if needed.
pub fn open_store() -> Result<Store> {
    let path = store_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    Store::open(&path)
}
