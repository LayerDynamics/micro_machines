//! Fork bookkeeping: assign child ids and account copy-on-write memory (SPEC-1
//! FR-15).
//!
//! The actual `mmap(MAP_PRIVATE)` / userfaultfd wiring is in the Linux fork engine;
//! this is the deterministic accounting + validation that gates a fork request, so a
//! fan-out is rejected up front if the parent isn't forkable or the host lacks the
//! memory headroom for the children's private/dirtied pages.
use super::manifest::SnapshotManifest;

/// Why a fork request was rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum ForkError {
    /// The parent snapshot is a diff or a future version — not forkable.
    NotForkable,
    /// `count` was zero.
    ZeroCount,
    /// The children's private-page budget exceeds the host's free memory.
    OverBudget,
}

/// A validated fork plan: the ids to assign and the CoW memory accounting.
#[derive(Debug, PartialEq, Eq)]
pub struct ForkPlan {
    pub child_ids: Vec<u64>,
    /// Parent RAM shared CoW across all children (not multiplied).
    pub shared_mib: u64,
    /// Budgeted private/dirtied + page-table memory per child.
    pub per_child_overhead_mib: u64,
}

/// Validate and plan a fork of `count` children from `parent`, given the host's free
/// MiB. CoW means children share the parent's `memory_mib` pages; only dirtied pages
/// cost extra, budgeted conservatively as `per_child_overhead_mib` each.
pub fn plan_fork(
    parent: &SnapshotManifest,
    count: u64,
    next_id: u64,
    free_mib: u64,
    per_child_overhead_mib: u64,
) -> Result<ForkPlan, ForkError> {
    if !parent.is_forkable() {
        return Err(ForkError::NotForkable);
    }
    if count == 0 {
        return Err(ForkError::ZeroCount);
    }
    let needed = count.saturating_mul(per_child_overhead_mib);
    if needed > free_mib {
        return Err(ForkError::OverBudget);
    }
    let child_ids = (next_id..next_id + count).collect();
    Ok(ForkPlan {
        child_ids,
        shared_mib: parent.memory_mib,
        per_child_overhead_mib,
    })
}

#[cfg(test)]
mod tests {
    use super::super::manifest::{SnapshotKind, SnapshotManifest};
    use super::*;

    fn parent() -> SnapshotManifest {
        SnapshotManifest {
            version: 1,
            vcpu_count: 1,
            memory_mib: 256,
            memory_file: "m".into(),
            state_file: "s".into(),
            kind: SnapshotKind::Full,
            parent_uid: None,
            host: Default::default(),
        }
    }

    #[test]
    fn plans_ids_and_shares_parent_memory() {
        let p = plan_fork(&parent(), 100, 1, 4096, 8).unwrap();
        assert_eq!(p.child_ids.len(), 100);
        assert_eq!(*p.child_ids.first().unwrap(), 1);
        assert_eq!(*p.child_ids.last().unwrap(), 100);
        assert_eq!(p.shared_mib, 256); // CoW: parent RAM shared, not multiplied
    }

    #[test]
    fn rejects_diff_parent_and_overbudget_and_zero() {
        let mut d = parent();
        d.kind = SnapshotKind::Diff;
        assert_eq!(plan_fork(&d, 1, 1, 4096, 8), Err(ForkError::NotForkable));
        assert_eq!(
            plan_fork(&parent(), 1000, 1, 100, 8),
            Err(ForkError::OverBudget)
        );
        assert_eq!(
            plan_fork(&parent(), 0, 1, 4096, 8),
            Err(ForkError::ZeroCount)
        );
    }

    #[test]
    fn ids_continue_from_next_id() {
        let p = plan_fork(&parent(), 3, 41, 4096, 8).unwrap();
        assert_eq!(p.child_ids, vec![41, 42, 43]);
    }
}
