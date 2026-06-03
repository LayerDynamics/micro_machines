//! Cluster snapshot on the agent side (SPEC-1 FR-14/FR-18).
//!
//! The agent dials the controller's `WatchSnapshots` server-stream (the reverse channel
//! into this client-only process); for each pushed [`SnapshotTask`] it resolves the
//! local machine's worker control socket, asks the worker to snapshot/branch the live
//! guest (the worker allocates the id), and reports the result back via
//! `ReportSnapshotResult`. Mirrors the cluster-exec agent path.
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use mm_host::control::request as control_request;
use mm_host::control_proto::{ControlRequest, ControlResponse};
use mm_proto::machine_service_client::MachineServiceClient;
use mm_proto::{SnapshotResult, SnapshotTask};
use tonic::transport::Channel;

use crate::actuator::HostConfig;
use crate::local_store::LocalStore;

/// Bound on waiting for the worker's reply. A live branch copies all of guest RAM before
/// replying, so this is generous (kept under the controller's REST `SNAPSHOT_WAIT`).
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(170);

/// Handle one pushed snapshot task end-to-end: drive the local worker's control channel
/// and report the result. Resolution/transport failures are reported as a failed result
/// (not dropped) so the waiting REST caller is always released.
pub async fn run_and_report(
    machines: &mut MachineServiceClient<Channel>,
    store: &Arc<LocalStore>,
    host: &HostConfig,
    task: SnapshotTask,
) -> Result<()> {
    let store = Arc::clone(store);
    let host = host.clone();
    // Keep the request_id so a panic in `compute` still routes a (failed) result back —
    // otherwise the waiting REST caller would block until its own timeout.
    let request_id = task.request_id.clone();
    // The control request is a blocking syscall stream that can take a while (a branch
    // copies RAM), so run it off the async runtime.
    let result = tokio::task::spawn_blocking(move || compute(&store, &host, task))
        .await
        .unwrap_or_else(|_| SnapshotResult {
            request_id,
            id: String::new(),
            ok: false,
            error: "agent snapshot task panicked".into(),
        });
    machines
        .report_snapshot_result(result)
        .await
        .context("reporting snapshot result to controller")?;
    Ok(())
}

/// A failed result carrying `request_id` so the controller can release the caller.
fn err(request_id: &str, msg: String) -> SnapshotResult {
    SnapshotResult {
        request_id: request_id.to_string(),
        id: String::new(),
        ok: false,
        error: msg,
    }
}

/// Resolve the target machine on this host and drive its worker control channel.
fn compute(store: &LocalStore, host: &HostConfig, task: SnapshotTask) -> SnapshotResult {
    let rid = task.request_id.clone();
    let uid = match &task.r#ref {
        Some(r) => r.uid.as_str(),
        None => return err(&rid, "snapshot task carried no machine ref".into()),
    };
    // The task carries the controller's uid; the host-local jail dir is named after the
    // record this agent persisted at boot, so look it up rather than reconstruct it.
    let record = match store.get(uid) {
        Ok(Some(m)) => m,
        Ok(None) => return err(&rid, format!("no machine {uid} on this host")),
        Err(e) => return err(&rid, format!("reading local store: {e}")),
    };
    if record.pid.is_none() {
        return err(&rid, format!("machine {} is not running", record.name));
    }
    let control = host
        .state_root
        .join("jails")
        .join(&record.name)
        .join("control.sock");
    let req = if task.branch {
        ControlRequest::Branch
    } else {
        ControlRequest::Snapshot
    };
    match control_request(&control, &req, SNAPSHOT_TIMEOUT) {
        Ok(ControlResponse::Ok { id }) => SnapshotResult {
            request_id: rid,
            id,
            ok: true,
            error: String::new(),
        },
        Ok(ControlResponse::Err { msg }) => err(&rid, msg),
        Err(e) => err(
            &rid,
            format!("control channel to {}: {e}", control.display()),
        ),
    }
}
