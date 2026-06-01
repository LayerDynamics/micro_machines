//! Copy-on-write fork engine (SPEC-1 FR-15, NFR-P2). Linux/KVM-only.
//!
//! Forking fans many child microVMs off one warmed parent snapshot. Each child's
//! guest RAM is a `MAP_PRIVATE` mapping of the parent's `memory_file`
//! ([`Machine::fork`]), so the warm pages the parent loaded (kernel, libraries, app
//! state) are shared read-only across all children and only a child's *written* pages
//! are copied — the kernel does the copy-on-write lazily, per page. That is what keeps
//! per-child cold-start cheap enough to fan out N=100 children under the NFR-P2 budget
//! (p50 < 150 ms): no child copies the full RAM image.
//!
//! The deterministic accounting that gates a fork request (forkable? budget? child
//! ids?) is [`super::fork::plan_fork`]; this module is the engine that executes an
//! approved [`ForkPlan`].
use std::path::Path;

use crate::config::VmConfig;
use crate::machine::{Machine, Result};
use crate::snapshot::engine::{load_manifest, load_state};
use crate::snapshot::fork::ForkPlan;

/// Fork one child microVM per id in `plan` from the snapshot directory `dir`, each
/// with copy-on-write guest memory. Returns the running children in id order.
/// `config` must match the snapshot's device set (same rootfs/net/vsock).
///
/// Each child shares the parent's `memory_file` pages until it writes; the captured
/// vCPU/device/clock state is cloned per child and restored, so the children are
/// independent from the moment they resume.
pub fn fork_children(config: &VmConfig, dir: &Path, plan: &ForkPlan) -> Result<Vec<Machine>> {
    let manifest = load_manifest(dir)?;
    let state = load_state(dir, &manifest)?;
    let mem_path = dir.join(&manifest.memory_file);

    let mut children = Vec::with_capacity(plan.child_ids.len());
    for _child_id in &plan.child_ids {
        children.push(Machine::fork(config, state.clone(), &mem_path)?);
    }
    Ok(children)
}
