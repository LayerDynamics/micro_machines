//! Machine endpoints (SPEC-1 FR-7/FR-9/FR-18).
//!
//! `start`/`stop` flip the machine's desired `spec.running`; the reconcile loop
//! (Task 8) is what actually actuates the change on an agent. Every handler
//! authorizes the caller against their role in the path namespace first.
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde_json::{json, Value};

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
