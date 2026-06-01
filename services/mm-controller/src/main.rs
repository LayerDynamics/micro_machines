//! MicroMachines control plane (M2): a REST API + scheduler + reconciler over a
//! PostgreSQL store, talking mTLS gRPC to per-host agents.
//!
//! This entrypoint owns configuration, the database, and serving the REST API. It
//! connects the pool, applies the embedded migrations on startup, builds the router
//! over the store + a JWT verifier, and serves until interrupted. The gRPC servers
//! and the reconcile loop (Task 8) are layered on next.
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use sqlx::postgres::PgPoolOptions;

use mm_controller::api::{self, AppState};
use mm_controller::auth::JwtVerifier;
use mm_controller::store::Store;

#[derive(Debug, Parser)]
#[command(name = "mm-controller", about = "MicroMachines control plane")]
struct Args {
    /// PostgreSQL connection string. Desired + observed state lives here, so the
    /// data plane survives a control-plane restart (the reconciler re-converges).
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,

    /// Listen address for the public REST API.
    #[arg(long, default_value = "0.0.0.0:8080")]
    listen: String,

    /// HS256 secret used to verify bearer tokens. Supplied by configuration rather
    /// than fetched from an OIDC provider, so token verification is offline and the
    /// signing authority is operator-controlled.
    #[arg(long, env = "JWT_HS256_SECRET")]
    jwt_hs256_secret: String,

    /// Directory holding the mTLS CA + controller cert/key for the gRPC servers
    /// (wired in a later task).
    #[arg(long, default_value = "./certs")]
    tls_dir: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let pool = PgPoolOptions::new()
        .max_connections(16)
        .connect(&args.database_url)
        .await
        .context("connecting to Postgres")?;

    let store = Store::new(pool);
    store
        .migrate()
        .await
        .context("applying database migrations")?;

    let state = AppState {
        store,
        verifier: Arc::new(JwtVerifier::hs256(args.jwt_hs256_secret.as_bytes())),
    };
    let app = api::router(state);

    let listener = tokio::net::TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("binding {}", args.listen))?;
    tracing::info!(listen = %args.listen, tls_dir = %args.tls_dir, "control plane serving REST API");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .context("serving REST API")?;
    tracing::info!("shutting down");
    Ok(())
}
