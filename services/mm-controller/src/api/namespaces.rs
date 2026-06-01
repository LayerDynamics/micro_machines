//! Namespace endpoints (SPEC-1 FR-7/FR-18).
use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{ApiError, AppState};
use crate::authz::{Claims, Role};

#[derive(Debug, Deserialize)]
pub struct CreateNamespace {
    pub name: String,
}

/// `POST /v1alpha1/namespaces` — create a namespace. Any authenticated subject may
/// create one and is granted `admin` in it (bootstrap), so they can immediately
/// manage machines there without an out-of-band RBAC grant.
pub async fn create(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(body): Json<CreateNamespace>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    if body.name.is_empty() {
        return Err(ApiError::BadRequest("namespace name is required".into()));
    }
    state.store.create_namespace(&body.name).await?;
    state
        .store
        .put_binding(&claims.sub, &body.name, Role::Admin)
        .await?;
    let _ = state
        .store
        .audit(
            &claims.sub,
            Some(&body.name),
            "create_namespace",
            Some(&body.name),
            "allowed",
        )
        .await;
    Ok((StatusCode::CREATED, Json(json!({ "name": body.name }))))
}

/// `GET /v1alpha1/namespaces` — list namespaces. Authentication is required; listing
/// is cluster-wide for M2 (per-subject filtering is a later refinement).
pub async fn list(
    State(state): State<AppState>,
    Extension(_claims): Extension<Claims>,
) -> Result<Json<Value>, ApiError> {
    let names = state.store.list_namespaces().await?;
    Ok(Json(json!({ "namespaces": names })))
}
