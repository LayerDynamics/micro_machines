//! Machine endpoints (SPEC-1 FR-7/FR-9/FR-18).
//!
//! `start`/`stop` flip the machine's desired `spec.running`; the reconcile loop
//! (Task 8) is what actually actuates the change on an agent. Every handler
//! authorizes the caller against their role in the path namespace first.
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::{Extension, Json};
use base64::Engine;
use mm_proto::{ExecChunk, ExecRequest, ExecTask, MachineRef};
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

use mm_api_types::State as MachineState;

use super::{ensure_allowed, ApiError, AppState};
use crate::authz::{Claims, Verb};
use crate::model::{CreateMachine, Machine};

/// `POST /v1alpha1/namespaces/:ns/machines` — create a machine (operator+).
pub async fn create(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(ns): Path<String>,
    Json(body): Json<CreateMachine>,
) -> Result<(StatusCode, Json<Machine>), ApiError> {
    ensure_allowed(&state, &claims, &ns, Verb::Create, "create_machine").await?;
    if !state.store.namespace_exists(&ns).await? {
        return Err(ApiError::NotFound);
    }
    if body.name.is_empty() {
        return Err(ApiError::BadRequest("machine name is required".into()));
    }
    let machine = state
        .store
        .create_machine(&ns, &body.fleet, &body.name, &body.spec)
        .await?;
    let _ = state
        .store
        .audit(
            &claims.sub,
            Some(&ns),
            "create_machine",
            Some(&body.name),
            "allowed",
        )
        .await;
    Ok((StatusCode::CREATED, Json(machine)))
}

/// `GET /v1alpha1/namespaces/:ns/machines/:name` — fetch one machine (viewer+).
pub async fn get(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((ns, name)): Path<(String, String)>,
) -> Result<Json<Machine>, ApiError> {
    ensure_allowed(&state, &claims, &ns, Verb::Get, "get_machine").await?;
    let machine = state
        .store
        .get_machine(&ns, &name)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(machine))
}

/// `GET /v1alpha1/namespaces/:ns/machines` — list a namespace's machines (viewer+).
pub async fn list(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path(ns): Path<String>,
) -> Result<Json<Value>, ApiError> {
    ensure_allowed(&state, &claims, &ns, Verb::List, "list_machines").await?;
    let machines = state.store.list_machines(&ns).await?;
    Ok(Json(json!({ "machines": machines })))
}

/// `DELETE /v1alpha1/namespaces/:ns/machines/:name` — remove a machine (admin).
pub async fn delete(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((ns, name)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    ensure_allowed(&state, &claims, &ns, Verb::Delete, "delete_machine").await?;
    let affected = state.store.delete_machine(&ns, &name).await?;
    if affected == 0 {
        return Err(ApiError::NotFound);
    }
    let _ = state
        .store
        .audit(
            &claims.sub,
            Some(&ns),
            "delete_machine",
            Some(&name),
            "allowed",
        )
        .await;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1alpha1/namespaces/:ns/machines/:name/start` — desire running (operator+).
pub async fn start(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((ns, name)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    set_running(&state, &claims, &ns, &name, true, "start_machine").await
}

/// `POST /v1alpha1/namespaces/:ns/machines/:name/stop` — desire stopped (operator+).
pub async fn stop(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((ns, name)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    set_running(&state, &claims, &ns, &name, false, "stop_machine").await
}

async fn set_running(
    state: &AppState,
    claims: &Claims,
    ns: &str,
    name: &str,
    running: bool,
    action: &str,
) -> Result<Json<Value>, ApiError> {
    ensure_allowed(state, claims, ns, Verb::Update, action).await?;
    let affected = state.store.set_running(ns, name, running).await?;
    if affected == 0 {
        return Err(ApiError::NotFound);
    }
    let _ = state
        .store
        .audit(&claims.sub, Some(ns), action, Some(name), "allowed")
        .await;
    Ok(Json(json!({ "name": name, "running": running })))
}

/// Default command timeout (matches the single-host `mm exec` default).
const DEFAULT_EXEC_TIMEOUT_MS: u64 = 60_000;
/// Grace the controller waits beyond the command's own timeout for the agent's
/// terminal frame, so a guest-side timeout surfaces as the command's result rather
/// than a premature controller timeout.
const EXEC_WAIT_GRACE_MS: u64 = 5_000;

/// The exec request body: argv to run plus an optional per-command timeout.
#[derive(serde::Deserialize)]
pub struct ExecBody {
    /// Command and arguments (`command[0]` is the program) to run in the guest.
    pub command: Vec<String>,
    /// Abort the command if it runs longer than this many milliseconds.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

/// `POST /v1alpha1/namespaces/:ns/machines/:name/exec` — run a command inside the
/// machine's running guest and stream its output back (operator+, SPEC-1 FR-13).
///
/// This is the cluster path of `mm exec`: the controller resolves which host the
/// machine is placed on, pushes an [`ExecTask`] to that host's agent over the
/// `WatchExec` reverse channel, and streams the agent's [`ExecChunk`]s straight to the
/// client as newline-delimited JSON — one `{"stream","data"}` object per output chunk
/// (`data` base64-encoded so non-UTF-8 output is preserved), then a terminal
/// `{"done":true,"exit_code"}` object, or `{"error"}` on a transport/exec failure.
pub async fn exec(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Path((ns, name)): Path<(String, String)>,
    Json(body): Json<ExecBody>,
) -> Result<Response, ApiError> {
    ensure_allowed(&state, &claims, &ns, Verb::Exec, "exec_machine").await?;
    if body.command.is_empty() {
        return Err(ApiError::BadRequest("command is required".into()));
    }
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
    // Route to the host the machine was scheduled onto. Absent until placement, so a
    // freshly-created machine that hasn't booted yet is a transient 503, not a 404.
    let host_id = machine
        .host_id
        .clone()
        .ok_or_else(|| ApiError::ServiceUnavailable("machine is not placed on a host".into()))?;

    let timeout_ms = body.timeout_ms.unwrap_or(DEFAULT_EXEC_TIMEOUT_MS);
    let request_id = Uuid::new_v4().to_string();
    let rx = state.exec.begin(request_id.clone()).await;

    let task = ExecTask {
        request_id: request_id.clone(),
        request: Some(ExecRequest {
            r#ref: Some(MachineRef {
                uid: machine.uid.to_string(),
                namespace: ns.clone(),
            }),
            cmd: body.command.clone(),
            timeout_ms,
        }),
    };
    if !state.exec.dispatch(&host_id, task).await {
        state.exec.finish(&request_id).await;
        return Err(ApiError::ServiceUnavailable(format!(
            "no agent connected for host {host_id}"
        )));
    }
    let _ = state
        .store
        .audit(
            &claims.sub,
            Some(&ns),
            "exec_machine",
            Some(&name),
            "allowed",
        )
        .await;

    // Forward chunks to the client as they arrive, with a bound on how long we wait
    // for the agent's terminal frame, then always release the pending entry.
    let exec = state.exec.clone();
    let wait = Duration::from_millis(timeout_ms.saturating_add(EXEC_WAIT_GRACE_MS));
    let (body_tx, body_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(64);
    tokio::spawn(async move {
        let mut rx = rx;
        loop {
            match tokio::time::timeout(wait, rx.recv()).await {
                Ok(Some(chunk)) => {
                    let terminal = chunk.done || !chunk.error.is_empty();
                    if body_tx
                        .send(Ok(Bytes::from(chunk_to_ndjson(&chunk))))
                        .await
                        .is_err()
                    {
                        break; // client hung up
                    }
                    if terminal {
                        break;
                    }
                }
                // The agent's report stream closed without a terminal frame.
                Ok(None) => {
                    let _ = body_tx
                        .send(Ok(Bytes::from(error_ndjson(
                            "agent disconnected before exec completed",
                        ))))
                        .await;
                    break;
                }
                Err(_) => {
                    let _ = body_tx
                        .send(Ok(Bytes::from(error_ndjson(
                            "exec timed out waiting for the guest",
                        ))))
                        .await;
                    break;
                }
            }
        }
        exec.finish(&request_id).await;
    });

    Response::builder()
        .header(axum::http::header::CONTENT_TYPE, "application/x-ndjson")
        .body(Body::from_stream(ReceiverStream::new(body_rx)))
        .map_err(|e| ApiError::Internal(e.to_string()))
}

/// Serialize one streamed exec chunk as a single NDJSON line.
fn chunk_to_ndjson(c: &ExecChunk) -> Vec<u8> {
    let value = if !c.error.is_empty() {
        json!({ "error": c.error })
    } else if c.done {
        json!({ "done": true, "exit_code": c.exit_code })
    } else {
        let data = base64::engine::general_purpose::STANDARD.encode(&c.data);
        json!({ "stream": c.stream, "data": data })
    };
    let mut line = serde_json::to_vec(&value).unwrap_or_default();
    line.push(b'\n');
    line
}

/// An NDJSON error line for a controller-side failure (timeout / agent disconnect).
fn error_ndjson(msg: &str) -> Vec<u8> {
    let mut line = serde_json::to_vec(&json!({ "error": msg })).unwrap_or_default();
    line.push(b'\n');
    line
}
