//! Integration test for the control-plane REST API against a real PostgreSQL
//! (SPEC-1 FR-7/FR-9/FR-18, FR-29/FR-30).
//!
//! Drives the axum router in-process via `tower`'s `oneshot` (no network port), so
//! the whole stack runs for real — auth middleware, RBAC, handlers, and the sqlx
//! store against Postgres — while the test mints its own HS256 tokens with the same
//! secret the verifier is configured with (no external identity provider).
//!
//! Requires `DATABASE_URL` to point at a Postgres; the CI `controller` job provides
//! one. With no `DATABASE_URL` set (e.g. a local machine with no database) the test
//! skips, since the project runs DB-backed gates in CI rather than locally.
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

use mm_controller::api::{router, AppState};
use mm_controller::auth::JwtVerifier;
use mm_controller::authz::Claims;
use mm_controller::store::Store;

const SECRET: &[u8] = b"integration-test-secret";

/// Mint an HS256 token for `sub` that the controller's verifier (built with the
/// same secret) accepts. `exp` is far in the future.
fn mint(sub: &str) -> String {
    let claims = Claims {
        sub: sub.into(),
        iss: "https://issuer.test".into(),
        aud: "mm".into(),
        exp: 32_503_680_000,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(SECRET),
    )
    .expect("encode token")
}

/// Send a request through the router and collect (status, JSON body).
async fn send(
    app: &Router,
    method: Method,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let req = match body {
        Some(b) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&b).unwrap()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let resp = app.clone().oneshot(req).await.expect("router oneshot");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

#[tokio::test]
async fn rest_crud_roundtrip_and_cross_namespace_is_denied() {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping api_pg (DB gates run in CI)");
        return;
    };

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("connect Postgres");
    let store = Store::new(pool.clone());
    store.migrate().await.expect("run migrations");

    // Idempotent pre-clean so the test re-runs against a reused database. Deleting
    // the namespaces cascades to their machines + rbac bindings.
    sqlx::query("DELETE FROM namespaces WHERE name IN ('team-a','team-b')")
        .execute(&pool)
        .await
        .expect("pre-clean");

    let state = AppState {
        store,
        verifier: Arc::new(JwtVerifier::hs256(SECRET)),
        metrics: Arc::new(mm_controller::metrics::Metrics::new()),
    };
    let app = router(state);

    let alice = mint("alice");
    let bob = mint("bob");

    // Unauthenticated requests are rejected.
    let (status, _) = send(&app, Method::GET, "/v1alpha1/namespaces", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no token must be 401");

    // alice creates team-a (and is granted admin there).
    let (status, _) = send(
        &app,
        Method::POST,
        "/v1alpha1/namespaces",
        Some(&alice),
        Some(json!({ "name": "team-a" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create namespace");

    // alice creates a machine in team-a.
    let create_body = json!({
        "name": "web",
        "fleet": "default",
        "spec": { "image": "docker.io/library/alpine:latest", "vcpus": 2, "memory_mib": 512, "running": true }
    });
    let (status, machine) = send(
        &app,
        Method::POST,
        "/v1alpha1/namespaces/team-a/machines",
        Some(&alice),
        Some(create_body),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create machine: {machine:?}");
    assert_eq!(machine["name"], "web");
    assert_eq!(machine["spec"]["running"], true);

    // GET it back.
    let (status, got) = send(
        &app,
        Method::GET,
        "/v1alpha1/namespaces/team-a/machines/web",
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "get machine");
    assert_eq!(got["name"], "web");
    assert_eq!(got["status"]["state"], "created");

    // List shows it.
    let (status, list) = send(
        &app,
        Method::GET,
        "/v1alpha1/namespaces/team-a/machines",
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "list machines");
    let names: Vec<&str> = list["machines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"web"), "list contains web: {names:?}");

    // stop flips desired running to false.
    let (status, _) = send(
        &app,
        Method::POST,
        "/v1alpha1/namespaces/team-a/machines/web/stop",
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "stop machine");
    let (_, got) = send(
        &app,
        Method::GET,
        "/v1alpha1/namespaces/team-a/machines/web",
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(got["spec"]["running"], false, "stop cleared running");

    // bob has no binding in team-a (he only owns team-b) — cross-namespace denied.
    let (status, _) = send(
        &app,
        Method::POST,
        "/v1alpha1/namespaces",
        Some(&bob),
        Some(json!({ "name": "team-b" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "bob creates team-b");

    let (status, _) = send(
        &app,
        Method::GET,
        "/v1alpha1/namespaces/team-a/machines/web",
        Some(&bob),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "bob must not read team-a (FR-30 namespace isolation)"
    );

    let (status, _) = send(
        &app,
        Method::POST,
        "/v1alpha1/namespaces/team-a/machines",
        Some(&bob),
        Some(json!({ "name": "intruder", "spec": { "image": "x" } })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "bob must not create in team-a"
    );

    // alice deletes the machine.
    let (status, _) = send(
        &app,
        Method::DELETE,
        "/v1alpha1/namespaces/team-a/machines/web",
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "delete machine");

    let (status, _) = send(
        &app,
        Method::GET,
        "/v1alpha1/namespaces/team-a/machines/web",
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "machine gone after delete");

    // /metrics (NFR-P4) is public and has recorded the requests above. It returns
    // Prometheus text (not JSON), so read it raw.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/metrics")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.expect("metrics oneshot");
    assert_eq!(resp.status(), StatusCode::OK, "/metrics is public");
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let metrics = String::from_utf8_lossy(&bytes);
    assert!(
        metrics.contains("mm_api_request_duration_ms") && metrics.contains("quantile=\"0.95\""),
        "metrics missing latency summary:\n{metrics}"
    );

    // Clean up.
    sqlx::query("DELETE FROM namespaces WHERE name IN ('team-a','team-b')")
        .execute(&pool)
        .await
        .expect("cleanup");
}
