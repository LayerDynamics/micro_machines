//! Host capacity accounting (SPEC-1 FR-17 input).
//!
//! The agent advertises how much room it has so the controller's scheduler can place
//! machines (`mm_controller::scheduler::place`). Free capacity is the host total
//! minus what the machines currently running on this host reserve. Pure and
//! testable; the host totals are probed once at startup, the running set comes from
//! the agent's local store.

/// Total resources a host offers to microVMs.
#[derive(Debug, Clone, Copy)]
pub struct HostResources {
    pub vcpus_total: u32,
    pub mem_mib_total: u64,
}

/// The resources one running machine reserves.
#[derive(Debug, Clone, Copy)]
pub struct Reservation {
    pub vcpus: u32,
    pub mem_mib: u64,
}

/// Free + total capacity, the shape reported to the controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capacity {
    pub vcpus_total: u32,
    pub vcpus_free: u32,
    pub mem_mib_total: u64,
    pub mem_mib_free: u64,
}

/// Compute free capacity as host total minus the sum of current reservations,
/// saturating at zero (an over-committed host reports zero free, never underflows).
pub fn compute(host: HostResources, running: &[Reservation]) -> Capacity {
    let used_vcpus: u32 = running.iter().map(|r| r.vcpus).sum();
    let used_mem: u64 = running.iter().map(|r| r.mem_mib).sum();
    Capacity {
        vcpus_total: host.vcpus_total,
        vcpus_free: host.vcpus_total.saturating_sub(used_vcpus),
        mem_mib_total: host.mem_mib_total,
        mem_mib_free: host.mem_mib_total.saturating_sub(used_mem),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: HostResources = HostResources {
        vcpus_total: 8,
        mem_mib_total: 16384,
    };

    #[test]
    fn free_equals_total_when_idle() {
        let c = compute(HOST, &[]);
        assert_eq!(c.vcpus_free, 8);
        assert_eq!(c.mem_mib_free, 16384);
    }

    #[test]
    fn subtracts_running_reservations() {
        let running = [
            Reservation {
                vcpus: 2,
                mem_mib: 512,
            },
            Reservation {
                vcpus: 1,
                mem_mib: 1024,
            },
        ];
        let c = compute(HOST, &running);
        assert_eq!(c.vcpus_free, 5);
        assert_eq!(c.mem_mib_free, 16384 - 1536);
    }

    #[test]
    fn overcommit_saturates_at_zero() {
        let running = [Reservation {
            vcpus: 32,
            mem_mib: 1 << 30,
        }];
        let c = compute(HOST, &running);
        assert_eq!(c.vcpus_free, 0);
        assert_eq!(c.mem_mib_free, 0);
    }
}
