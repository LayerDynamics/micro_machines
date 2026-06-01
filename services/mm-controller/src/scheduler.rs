//! Scheduler: choose a host with enough free capacity for a machine (SPEC-1 FR-17).
//!
//! Pure and deterministic so placement is unit-testable and reproducible: given the
//! same host capacities and demand, [`place`] always returns the same host. The
//! reconcile loop (Task 8) calls this when it decides `AssignAndStart`.
#[derive(Debug, Clone)]
pub struct HostCapacity {
    pub host_id: String,
    pub vcpus_free: u32,
    pub mem_mib_free: u64,
    pub healthy: bool,
}

/// The resources a machine needs to be placed.
#[derive(Debug, Clone, Copy)]
pub struct Demand {
    pub vcpus: u32,
    pub mem_mib: u64,
}

/// First-fit over healthy hosts that satisfy the demand, choosing the one with the
/// most free memory (best-fit-by-headroom). Deterministic; `None` when no healthy
/// host has room.
///
/// Picking the most-free host spreads load and leaves the tightest hosts for
/// smaller machines — a simple, predictable policy for M2; bin-packing/affinity are
/// later refinements.
pub fn place(hosts: &[HostCapacity], d: Demand) -> Option<&HostCapacity> {
    hosts
        .iter()
        .filter(|h| h.healthy && h.vcpus_free >= d.vcpus && h.mem_mib_free >= d.mem_mib)
        .max_by_key(|h| h.mem_mib_free)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(id: &str, v: u32, m: u64, ok: bool) -> HostCapacity {
        HostCapacity {
            host_id: id.into(),
            vcpus_free: v,
            mem_mib_free: m,
            healthy: ok,
        }
    }

    #[test]
    fn picks_host_with_most_free_mem() {
        let hosts = vec![h("a", 8, 2048, true), h("b", 8, 8192, true)];
        assert_eq!(
            place(
                &hosts,
                Demand {
                    vcpus: 2,
                    mem_mib: 512
                }
            )
            .unwrap()
            .host_id,
            "b"
        );
    }

    #[test]
    fn skips_unhealthy_and_too_small() {
        let hosts = vec![h("a", 1, 256, true), h("b", 8, 8192, false)];
        assert!(place(
            &hosts,
            Demand {
                vcpus: 2,
                mem_mib: 512
            }
        )
        .is_none());
    }

    #[test]
    fn respects_vcpu_limit_even_with_spare_memory() {
        // `b` has plenty of RAM but too few vCPUs; `a` fits exactly.
        let hosts = vec![h("a", 4, 1024, true), h("b", 1, 65536, true)];
        assert_eq!(
            place(
                &hosts,
                Demand {
                    vcpus: 4,
                    mem_mib: 512
                }
            )
            .unwrap()
            .host_id,
            "a"
        );
    }

    #[test]
    fn no_hosts_yields_none() {
        assert!(place(
            &[],
            Demand {
                vcpus: 1,
                mem_mib: 128
            }
        )
        .is_none());
    }
}
