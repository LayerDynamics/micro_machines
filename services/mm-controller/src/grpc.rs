//! The controller's gRPC servers (SPEC-1 FR-19): `MachineService` streams
//! assignments to agents; `HostService` ingests their capacity, heartbeats, and
//! observed-state events.
//!
//! The controller is the server; agents are clients. The reconcile loop (`crate::r#loop`)
//! pushes assignments to a connected agent through the [`AgentRegistry`], which maps a
//! host id to the sender side of that agent's open `WatchAssignments` stream.
// gRPC handlers return `Result<_, tonic::Status>`; `Status` is a large error type by
// design, so `result_large_err` is expected and not worth boxing here.
#![allow(clippy::result_large_err)]
use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use mm_proto::host_service_server::HostService;
use mm_proto::machine_service_server::MachineService;
use mm_proto::{Ack, Assignment, Capacity, HostRef, Machine, MachineEvent, MachineRef};

use crate::convert::{machine_to_proto, proto_state_name};
use crate::store::Store;

/// Sender to one connected agent's assignment stream.
type AssignmentTx = mpsc::Sender<Result<Assignment, Status>>;

/// Tracks connected agents so the reconcile loop can push assignments to a host.
#[derive(Clone, Default)]
pub struct AgentRegistry {
    agents: Arc<Mutex<HashMap<String, AssignmentTx>>>,
}

impl AgentRegistry {
    /// Register a freshly-connected agent and return the receive side of its stream.
    async fn connect(&self, host_id: String) -> ReceiverStream<Result<Assignment, Status>> {
        let (tx, rx) = mpsc::channel(64);
        self.agents.lock().await.insert(host_id, tx);
        ReceiverStream::new(rx)
    }

    /// Push an assignment to a host's agent. Returns `false` if no agent is connected
    /// or the stream has closed (so the loop can fall back to another host).
    pub async fn send(&self, host_id: &str, assignment: Assignment) -> bool {
        let tx = self.agents.lock().await.get(host_id).cloned();
        match tx {
            Some(tx) => tx.send(Ok(assignment)).await.is_ok(),
            None => false,
        }
    }

    /// Whether an agent is currently connected for `host_id`.
    pub async fn is_connected(&self, host_id: &str) -> bool {
        self.agents.lock().await.contains_key(host_id)
    }
}

/// `MachineService` implementation: streams assignments + answers machine queries.
pub struct MachineSvc {
    pub store: Store,
    pub registry: AgentRegistry,
}

#[tonic::async_trait]
impl MachineService for MachineSvc {
    type WatchAssignmentsStream = ReceiverStream<Result<Assignment, Status>>;

    async fn watch_assignments(
        &self,
        request: Request<HostRef>,
    ) -> Result<Response<Self::WatchAssignmentsStream>, Status> {
        let host_id = request.into_inner().host_id;
        tracing::info!(host = %host_id, "agent connected; streaming assignments");
        Ok(Response::new(self.registry.connect(host_id).await))
    }

    async fn get(&self, request: Request<MachineRef>) -> Result<Response<Machine>, Status> {
        let uid = parse_uid(&request.into_inner().uid)?;
        match self.store.get_machine_by_uid(uid).await.map_err(internal)? {
            Some(m) => Ok(Response::new(machine_to_proto(&m))),
            None => Err(Status::not_found("no such machine")),
        }
    }

    async fn assign(
        &self,
        _request: Request<Assignment>,
    ) -> Result<Response<mm_proto::MachineStatus>, Status> {
        // Assignments flow controller -> agent over the WatchAssignments stream; the
        // controller does not accept inbound Assign calls.
        Err(Status::unimplemented(
            "assignments are pushed via WatchAssignments, not Assign",
        ))
    }

    async fn delete(&self, request: Request<MachineRef>) -> Result<Response<Ack>, Status> {
        let r = request.into_inner();
        let uid = parse_uid(&r.uid)?;
        // Look up the name so we can delete by (namespace, name).
        let machine = self.store.get_machine_by_uid(uid).await.map_err(internal)?;
        match machine {
            Some(m) => {
                self.store
                    .delete_machine(&m.namespace, &m.name)
                    .await
                    .map_err(internal)?;
                Ok(Response::new(Ack {
                    ok: true,
                    message: String::new(),
                }))
            }
            None => Ok(Response::new(Ack {
                ok: true,
                message: "already gone".to_string(),
            })),
        }
    }
}

/// `HostService` implementation: ingests agent capacity, heartbeats, and events.
pub struct HostSvc {
    pub store: Store,
}

#[tonic::async_trait]
impl HostService for HostSvc {
    type StreamEventsStream = ReceiverStream<Result<MachineEvent, Status>>;

    async fn report_capacity(&self, request: Request<Capacity>) -> Result<Response<Ack>, Status> {
        let cap = request.into_inner();
        let host_id = cap.host_id.clone();
        let json = serde_json::to_value(CapacityRow::from(&cap))
            .map_err(|e| Status::internal(e.to_string()))?;
        self.store
            .upsert_host(&host_id, &json)
            .await
            .map_err(internal)?;
        Ok(Response::new(ack()))
    }

    async fn heartbeat(&self, request: Request<HostRef>) -> Result<Response<Ack>, Status> {
        self.store
            .touch_heartbeat(&request.into_inner().host_id)
            .await
            .map_err(internal)?;
        Ok(Response::new(ack()))
    }

    async fn report_event(&self, request: Request<MachineEvent>) -> Result<Response<Ack>, Status> {
        let ev = request.into_inner();
        let uid = parse_uid(&ev.uid)?;
        let state = proto_state_name(ev.state)
            .ok_or_else(|| Status::invalid_argument("unknown machine state"))?;
        self.store
            .set_observed_state(uid, state)
            .await
            .map_err(internal)?;
        tracing::info!(uid = %ev.uid, state, msg = %ev.message, "agent reported state");
        Ok(Response::new(ack()))
    }

    async fn stream_events(
        &self,
        _request: Request<HostRef>,
    ) -> Result<Response<Self::StreamEventsStream>, Status> {
        // The controller ingests events via ReportEvent (agent -> controller); the
        // reverse server-stream is not used in M2.
        Err(Status::unimplemented(
            "events are reported via ReportEvent, not streamed from the controller",
        ))
    }
}

/// The capacity shape stored in `hosts.capacity` JSONB (mirrors the scheduler input).
#[derive(serde::Serialize)]
struct CapacityRow {
    vcpus_total: u32,
    vcpus_free: u32,
    mem_mib_total: u64,
    mem_mib_free: u64,
}

impl From<&Capacity> for CapacityRow {
    fn from(c: &Capacity) -> Self {
        Self {
            vcpus_total: c.vcpus_total,
            vcpus_free: c.vcpus_free,
            mem_mib_total: c.mem_mib_total,
            mem_mib_free: c.mem_mib_free,
        }
    }
}

fn ack() -> Ack {
    Ack {
        ok: true,
        message: String::new(),
    }
}

fn parse_uid(s: &str) -> Result<Uuid, Status> {
    Uuid::parse_str(s).map_err(|_| Status::invalid_argument("uid is not a valid UUID"))
}

fn internal(e: sqlx::Error) -> Status {
    Status::internal(e.to_string())
}
