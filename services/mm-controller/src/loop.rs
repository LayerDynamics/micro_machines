//! The reconciliation loop (SPEC-1 FR-22, NFR-R4): drive observed state toward
//! desired state, converging within seconds.
//!
//! Each tick loads every machine's `(spec, status, host_id)`, asks the pure
//! [`crate::reconcile::decide`] what to do, and actuates: schedule + push an
//! assignment to an agent, push a stop, etc. The decision being pure means the loop
//! is a thin, idempotent actuator — once a machine is observed `Running`, `decide`
//! returns `None` and nothing is re-pushed, so a controller restart re-converges
//! from Postgres without duplicate assignments (NFR-R2).
use std::time::Duration;

use anyhow::Result;
use mm_proto::Assignment;

use crate::convert::machine_to_proto;
use crate::grpc::AgentRegistry;
use crate::reconcile::{self, Action, Observed};
use crate::scheduler::{self, Demand, HostCapacity};
use crate::store::Store;

/// Retry budget for a failed machine before it rests (mirrors the reconciler).
const MAX_RETRIES: u32 = 3;
/// A host is eligible for placement if it heartbeat within this window.
const HOST_STALE_SECS: i64 = 30;

/// Run the reconcile loop forever, ticking every `interval`.
pub async fn run(store: Store, registry: AgentRegistry, interval: Duration) {
    let mut tick = tokio::time::interval(interval);
    loop {
        tick.tick().await;
        if let Err(e) = reconcile_once(&store, &registry).await {
            tracing::warn!("reconcile tick failed: {e}");
        }
    }
}

/// One reconcile pass over all machines. Public so tests can drive ticks
/// deterministically.
pub async fn reconcile_once(store: &Store, registry: &AgentRegistry) -> Result<()> {
    let machines = store.list_all_machines().await?;
    let hosts = load_host_capacities(store).await?;

    for m in machines {
        let obs = Observed {
            state: m.status.state,
            host_assigned: m.host_id.is_some(),
            retry_count: m.status.retry_count,
        };
        match reconcile::decide(m.spec.running, false, &obs, MAX_RETRIES) {
            Action::AssignAndStart | Action::Retry => {
                // Keep an existing placement; otherwise schedule onto a host with room.
                let host = match &m.host_id {
                    Some(h) => Some(h.clone()),
                    None => scheduler::place(
                        &hosts,
                        Demand {
                            vcpus: m.spec.vcpus,
                            mem_mib: m.spec.memory_mib,
                        },
                    )
                    .map(|h| h.host_id.clone()),
                };
                let Some(host) = host else {
                    tracing::warn!(uid = %m.uid, "no host with capacity; will retry next tick");
                    continue;
                };
                if m.host_id.as_deref() != Some(host.as_str()) {
                    store.assign_host(m.uid, &host).await?;
                }
                let mut desired = m.clone();
                desired.spec.running = true;
                desired.host_id = Some(host.clone());
                let assignment = Assignment {
                    machine: Some(machine_to_proto(&desired)),
                };
                if !registry.send(&host, assignment).await {
                    tracing::debug!(host, uid = %m.uid, "agent not connected; will retry");
                }
            }
            Action::Stop => {
                if let Some(host) = &m.host_id {
                    let mut desired = m.clone();
                    desired.spec.running = false;
                    let assignment = Assignment {
                        machine: Some(machine_to_proto(&desired)),
                    };
                    registry.send(host, assignment).await;
                }
            }
            // A deleted spec is removed from `machines`, so the loop never sees it;
            // agent-side teardown on delete is driven by the REST DELETE path.
            Action::Destroy | Action::None => {}
        }
    }
    Ok(())
}

/// Healthy, recently-heartbeating hosts with their free capacity, for the scheduler.
async fn load_host_capacities(store: &Store) -> Result<Vec<HostCapacity>> {
    let rows = store.live_host_capacities(HOST_STALE_SECS).await?;
    Ok(rows
        .into_iter()
        .filter_map(|(host_id, cap)| {
            let obj = cap.as_object()?;
            Some(HostCapacity {
                host_id,
                vcpus_free: obj.get("vcpus_free")?.as_u64()? as u32,
                mem_mib_free: obj.get("mem_mib_free")?.as_u64()?,
                healthy: true,
            })
        })
        .collect())
}
