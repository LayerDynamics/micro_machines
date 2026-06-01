//! MicroMachines control plane (M2): a REST API + scheduler + reconciler over a
//! PostgreSQL store, talking mTLS gRPC to per-host agents.
//!
//! This entrypoint owns configuration and the database lifecycle: it connects the
//! pool and applies the embedded migrations on startup, then serves until
//! interrupted. The REST server (Task 6), the gRPC servers, and the reconcile loop
//! (Task 8) are layered onto this skeleton in later M2 tasks. The pure decision
//! logic they call — `reconcile`, `scheduler`, `authz` — is added and unit-tested
//! first (Tasks 3–5).
use anyhow::{Context, Result};
use clap::Parser;
use sqlx::postgres::PgPoolOptions;

#[derive(Debug, Parser)]
#[command(name = "mm-controller", about = "MicroMachines control plane")]
struct Args {
    /// PostgreSQL connection string. Desired + observed state lives here, so the
    /// data plane survives a control-plane restart (the reconciler re-converges).
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,

    /// Listen address for the public REST API (wired in a later task).
    #[arg(long, default_value = "0.0.0.0:8080")]
    listen: String,

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

    // Bring the schema to the latest migration on startup so a fresh database is
    // usable without an out-of-band step.
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("applying database migrations")?;
    tracing::info!(
        listen = %args.listen,
        tls_dir = %args.tls_dir,
        "control plane ready (schema migrated)"
    );

    // Serve until interrupted. The REST API, gRPC servers, and reconcile loop are
    // attached here in later M2 tasks; for now the process owns the migrated pool.
    tokio::signal::ctrl_c()
        .await
        .context("awaiting shutdown signal")?;
    tracing::info!("shutting down");
    Ok(())
}
