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

use mm_proto::host_service_server::HostService;
use mm_proto::machine_service_server::MachineService;
use mm_proto::{
    Ack, Assignment, Capacity, ExecChunk, ExecTask, HostRef, Machine, MachineEvent, MachineRef,
};
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use uuid::Uuid;

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

/// Sender to one connected agent's `WatchExec` task stream.
type ExecTaskTx = mpsc::Sender<Result<ExecTask, Status>>;
/// Sender that forwards a streamed exec result to the REST caller awaiting it.
type ChunkTx = mpsc::Sender<ExecChunk>;

/// Routes cluster exec (FR-13) across the controller↔agent boundary in both
/// directions. The agent is client-only, so — exactly like assignments — it dials in
/// and opens a `WatchExec` stream the controller pushes [`ExecTask`]s down; the agent
/// runs the command against the local guest and streams [`ExecChunk`]s back up via
/// `ReportExecResult`. A `request_id` carried on every chunk lets the controller route
/// output to the REST handler blocked awaiting it.
#[derive(Clone, Default)]
pub struct ExecDispatcher {
    /// host_id → that agent's open `WatchExec` stream.
    agents: Arc<Mutex<HashMap<String, ExecTaskTx>>>,
    /// request_id → the channel feeding the REST caller's response body.
    pending: Arc<Mutex<HashMap<String, ChunkTx>>>,
}

impl ExecDispatcher {
    /// Register a freshly-connected agent's exec channel and return the receive side
    /// of its `WatchExec` stream.
    async fn connect(&self, host_id: String) -> ReceiverStream<Result<ExecTask, Status>> {
        let (tx, rx) = mpsc::channel(16);
        self.agents.lock().await.insert(host_id, tx);
        ReceiverStream::new(rx)
    }

    /// Begin a pending exec request: register a `request_id` and return the receiver
    /// the REST handler streams to its client. The caller MUST [`finish`](Self::finish)
    /// the request when the stream ends so the pending entry does not leak.
    pub async fn begin(&self, request_id: String) -> mpsc::Receiver<ExecChunk> {
        let (tx, rx) = mpsc::channel(64);
        self.pending.lock().await.insert(request_id, tx);
        rx
    }

    /// Push an exec task to a host's agent. Returns `false` if no agent is connected
    /// for that host or its stream has closed (so the caller can fail fast).
    pub async fn dispatch(&self, host_id: &str, task: ExecTask) -> bool {
        let tx = self.agents.lock().await.get(host_id).cloned();
        match tx {
            Some(tx) => tx.send(Ok(task)).await.is_ok(),
            None => false,
        }
    }

    /// Drop a pending request's routing entry (on completion, timeout, or error).
    pub async fn finish(&self, request_id: &str) {
        self.pending.lock().await.remove(request_id);
    }

    /// Route one streamed chunk to the REST caller awaiting `chunk.request_id`. Returns
    /// `false` if no caller is waiting or it has hung up, so the agent's report stream
    /// can stop early.
    async fn route(&self, chunk: ExecChunk) -> bool {
        let tx = self.pending.lock().await.get(&chunk.request_id).cloned();
        match tx {
            Some(tx) => tx.send(chunk).await.is_ok(),
            None => false,
        }
    }
}

/// `MachineService` implementation: streams assignments + answers machine queries.
pub struct MachineSvc {
    pub store: Store,
    pub registry: AgentRegistry,
    pub exec: ExecDispatcher,
}

#[tonic::async_trait]
impl MachineService for MachineSvc {
    type WatchAssignmentsStream = ReceiverStream<Result<Assignment, Status>>;
    type WatchExecStream = ReceiverStream<Result<ExecTask, Status>>;

    async fn watch_assignments(
        &self,
        request: Request<HostRef>,
    ) -> Result<Response<Self::WatchAssignmentsStream>, Status> {
        let host_id = request.into_inner().host_id;
        tracing::info!(host = %host_id, "agent connected; streaming assignments");
        Ok(Response::new(self.registry.connect(host_id).await))
    }

    /// The agent opens this server-stream to receive exec tasks for its host (the
    /// reverse channel into the client-only agent, FR-13).
    async fn watch_exec(
        &self,
        request: Request<HostRef>,
    ) -> Result<Response<Self::WatchExecStream>, Status> {
        let host_id = request.into_inner().host_id;
        tracing::info!(host = %host_id, "agent connected; streaming exec tasks");
        Ok(Response::new(self.exec.connect(host_id).await))
    }

    /// The agent streams a command's output chunks back up (agent → controller); each
    /// is routed to the REST caller blocked on the matching `request_id`. The stream
    /// stops early if that caller has hung up.
    async fn report_exec_result(
        &self,
        request: Request<tonic::Streaming<ExecChunk>>,
    ) -> Result<Response<Ack>, Status> {
        let mut stream = request.into_inner();
        while let Some(chunk) = stream.message().await? {
            if !self.exec.route(chunk).await {
                // The waiting caller is gone; no point reading more.
                break;
            }
        }
        Ok(Response::new(ack()))
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
        // The agent learns the guest IP at boot, so a Running event carries it; other
        // events leave the stored IP untouched.
        if ev.ip.is_empty() {
            self.store.set_observed_state(uid, state).await
        } else {
            self.store.set_observed(uid, state, &ev.ip).await
        }
        .map_err(internal)?;
        tracing::info!(uid = %ev.uid, state, ip = %ev.ip, msg = %ev.message, "agent reported state");
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

#[cfg(test)]
mod tests {
    use mm_proto::ExecRequest;
    use tokio_stream::StreamExt as _;

    use super::*;

    fn task(request_id: &str) -> ExecTask {
        ExecTask {
            request_id: request_id.to_string(),
            request: Some(ExecRequest {
                r#ref: None,
                cmd: vec!["echo".into(), "hi".into()],
                timeout_ms: 1000,
            }),
        }
    }

    fn output(request_id: &str, data: &str) -> ExecChunk {
        ExecChunk {
            stream: "stdout".into(),
            data: data.as_bytes().to_vec(),
            exit_code: 0,
            done: false,
            request_id: request_id.to_string(),
            error: String::new(),
        }
    }

    #[tokio::test]
    async fn dispatch_to_unknown_host_fails_fast() {
        let d = ExecDispatcher::default();
        // No agent connected for this host.
        assert!(!d.dispatch("ghost-host", task("r1")).await);
    }

    #[tokio::test]
    async fn task_reaches_the_connected_agent() {
        let d = ExecDispatcher::default();
        let mut agent = d.connect("host-1".into()).await;
        assert!(d.dispatch("host-1", task("r1")).await);
        let received = agent.next().await.expect("a task").expect("ok task");
        assert_eq!(received.request_id, "r1");
    }

    #[tokio::test]
    async fn chunk_routes_to_the_waiting_caller_then_finish_drops_it() {
        let d = ExecDispatcher::default();
        let mut rx = d.begin("r1".into()).await;
        assert!(d.route(output("r1", "out")).await);
        let chunk = rx.recv().await.expect("a chunk");
        assert_eq!(chunk.data, b"out");

        // After finish, the request is no longer routable.
        d.finish("r1").await;
        assert!(!d.route(output("r1", "late")).await);
    }

    #[tokio::test]
    async fn chunk_for_unknown_request_is_not_routed() {
        let d = ExecDispatcher::default();
        assert!(!d.route(output("nobody", "x")).await);
    }
}
