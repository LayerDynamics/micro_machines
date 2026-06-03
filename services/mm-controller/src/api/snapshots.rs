//! Snapshot endpoints (SPEC-1 FR-14/FR-18).
//!
//! The cluster path of `mm snapshot`: `create` resolves which host the machine is on,
//! pushes a [`SnapshotTask`] to that host's agent over the `WatchSnapshots` reverse
//! channel, waits for the agent's single [`SnapshotResult`] (the worker-allocated id),
//! and records it. Each handler authorizes the caller against their role in the path
//! namespace first.
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use mm_proto::{MachineRef, SnapshotTask};
use serde_json::{json, Value};
use uuid::Uuid;

use mm_api_types::State as MachineState;

use super::{ensure_allowed, ApiError, AppState};
use crate::authz::{Claims, Verb};
use crate::model::{CreateSnapshot, Snapshot};

/// How long the controller waits for the agent's snapshot result. A live branch copies
/// all of guest RAM before replying, so this is generous (matches the single-host CLI's
/// control-channel read timeout).
const SNAPSHOT_WAIT: Duration = Duration::from_secs(180);

/// `POST /v1alpha1/namespaces/:ns/machines/:name/snapshots` — snapshot a running
/// machine (operator+). `{"branch": true}` takes a live branch (FR-16) instead of a
/// paused snapshot. Blocks until the agent reports the result.
pub async fn create(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((ns, name)): Path<(String, String)>,
    Json(body): Json<CreateSnapshot>,
) -> Result<(StatusCode, Json<Snapshot>), ApiError> {
    ensure_allowed(&state, &claims, &ns, Verb::Create, "create_snapshot").await?;
    let machine = state
        .store
        .get_machine(&ns, &name)
        .await?
        .ok_or(ApiError::NotFound)?;
    if machine.status.state != MachineState::Running {
        return Err(ApiError::BadRequest(format!(
            "machine {name} is not running"
        )));
    }
    // Route to the host the machine is placed on (absent until placement → transient 503).
    let host_id = machine
        .host_id
        .clone()
        .ok_or_else(|| ApiError::ServiceUnavailable("machine is not placed on a host".into()))?;

    let request_id = Uuid::new_v4().to_string();
    let rx = state.snapshots.begin(request_id.clone()).await;
    let task = SnapshotTask {
        request_id: request_id.clone(),
        r#ref: Some(MachineRef {
            uid: machine.uid.to_string(),
            namespace: ns.clone(),
        }),
        branch: body.branch,
    };
    if !state.snapshots.dispatch(&host_id, task).await {
        state.snapshots.finish(&request_id).await;
        return Err(ApiError::ServiceUnavailable(format!(
            "no agent connected for host {host_id}"
        )));
    }

    let result = match tokio::time::timeout(SNAPSHOT_WAIT, rx).await {
        Ok(Ok(r)) => r,
        Ok(Err(_)) => {
            return Err(ApiError::ServiceUnavailable(
                "agent disconnected before the snapshot completed".into(),
            ));
        }
        Err(_) => {
            state.snapshots.finish(&request_id).await;
            return Err(ApiError::ServiceUnavailable("snapshot timed out".into()));
        }
    };
    if !result.ok {
        return Err(ApiError::Internal(format!(
            "snapshot failed on the agent: {}",
            result.error
        )));
    }

    let kind = if body.branch { "branch" } else { "full" };
    let snap = state
        .store
        .create_snapshot(
            &ns,
            &name,
            &result.id,
            kind,
            &host_id,
            machine.spec.memory_mib,
            "ready",
        )
        .await?;
    let _ = state
        .store
        .audit(
            &claims.sub,
            Some(&ns),
            "create_snapshot",
            Some(&name),
            "allowed",
        )
        .await;
    Ok((StatusCode::CREATED, Json(snap)))
}

/// `GET /v1alpha1/namespaces/:ns/machines/:name/snapshots` — list a machine's snapshots
/// (viewer+).
pub async fn list(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((ns, name)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    ensure_allowed(&state, &claims, &ns, Verb::List, "list_snapshots").await?;
    let snapshots = state.store.list_snapshots(&ns, &name).await?;
    Ok(Json(json!({ "snapshots": snapshots })))
}

/// `DELETE /v1alpha1/namespaces/:ns/snapshots/:id` — remove a snapshot record (admin).
///
/// This removes the control-plane record; reclaiming the snapshot's files on the host's
/// disk is done by the single-host `mm snapshot rm`/`gc` (a controller-driven host
/// reclaim is a follow-on, like destroy-on-delete for machines).
pub async fn delete(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((ns, id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    ensure_allowed(&state, &claims, &ns, Verb::Delete, "delete_snapshot").await?;
    let affected = state.store.delete_snapshot(&ns, &id).await?;
    if affected == 0 {
        return Err(ApiError::NotFound);
    }
    let _ = state
        .store
        .audit(
            &claims.sub,
            Some(&ns),
            "delete_snapshot",
            Some(&id),
            "allowed",
        )
        .await;
    Ok(StatusCode::NO_CONTENT)
}
