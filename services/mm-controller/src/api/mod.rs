//! REST API surface (SPEC-1 FR-7/FR-9/FR-18).
//!
//! Every `/v1alpha1` route is authenticated (a verified JWT, see [`crate::auth`])
//! and namespace-scoped: a handler authorizes the caller's verb against their role
//! binding in the target namespace ([`crate::authz`]) before touching the store, and
//! records the outcome in the audit log. Namespace creation bootstraps access — the
//! creator is granted `admin` in the new namespace — so there is no out-of-band
//! seeding step.
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{header::AUTHORIZATION, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;

use crate::auth::JwtVerifier;
use crate::authz::{self, Claims, Verb};
use crate::store::Store;

mod machines;
mod namespaces;

/// Shared application state handed to every handler.
#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub verifier: Arc<JwtVerifier>,
}

/// API error → HTTP status. Unauthenticated requests get 401, RBAC denials 403,
/// missing resources 404, unique-constraint clashes 409, and everything else 500.
#[derive(Debug)]
pub enum ApiError {
    Unauthorized(&'static str),
    Forbidden,
    NotFound,
    Conflict(String),
    BadRequest(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            ApiError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m.to_string()),
            ApiError::Forbidden => (StatusCode::FORBIDDEN, "forbidden".to_string()),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, m),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        (status, Json(json!({ "error": msg }))).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        if let Some(db) = e.as_database_error() {
            if db.is_unique_violation() {
                return ApiError::Conflict("resource already exists".to_string());
            }
        }
        ApiError::Internal(e.to_string())
    }
}

/// Build the application router over the given state.
pub fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route(
            "/v1alpha1/namespaces",
            get(namespaces::list).post(namespaces::create),
        )
        .route(
            "/v1alpha1/namespaces/:ns/machines",
            get(machines::list).post(machines::create),
        )
        .route(
            "/v1alpha1/namespaces/:ns/machines/:name",
            get(machines::get).delete(machines::delete),
        )
        .route(
            "/v1alpha1/namespaces/:ns/machines/:name/start",
            post(machines::start),
        )
        .route(
            "/v1alpha1/namespaces/:ns/machines/:name/stop",
            post(machines::stop),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_auth,
        ));

    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .merge(protected)
        .with_state(state)
}

/// Authentication middleware: require a valid `Authorization: Bearer <jwt>`, verify
/// it, and stash the [`Claims`] in request extensions for handlers to read.
async fn require_auth(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let token = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized("missing bearer token"))?;
    let claims = state
        .verifier
        .verify(token)
        .map_err(|_| ApiError::Unauthorized("invalid or expired token"))?;
    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

/// Authorize `verb` in `namespace` for the caller, auditing a denial. On success the
/// handler proceeds and records its own success audit row.
async fn ensure_allowed(
    state: &AppState,
    claims: &Claims,
    namespace: &str,
    verb: Verb,
    action: &str,
) -> Result<(), ApiError> {
    let binding = state.store.role_binding(&claims.sub, namespace).await?;
    if authz::authorize(binding.map(|role| (namespace, role)), namespace, verb) {
        Ok(())
    } else {
        let _ = state
            .store
            .audit(&claims.sub, Some(namespace), action, None, "denied")
            .await;
        Err(ApiError::Forbidden)
    }
}
