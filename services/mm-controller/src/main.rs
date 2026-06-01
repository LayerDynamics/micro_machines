//! MicroMachines control plane (M2): a REST API + scheduler + reconciler over a
//! PostgreSQL store, talking mTLS gRPC to per-host agents.
//!
//! This entrypoint owns configuration and the database, then runs three things
//! concurrently: the public REST API (axum), the controller↔agent gRPC servers
//! (tonic, mutual-TLS), and the reconcile loop that drives observed state toward
//! desired state by pushing assignments to connected agents.
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use mm_controller::api::{self, AppState};
use mm_controller::auth::JwtVerifier;
use mm_controller::grpc::{AgentRegistry, HostSvc, MachineSvc};
use mm_controller::store::Store;
use mm_controller::tls;
use mm_proto::host_service_server::HostServiceServer;
use mm_proto::machine_service_server::MachineServiceServer;
use sqlx::postgres::PgPoolOptions;
use tonic::transport::Server;

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

    /// Listen address for the controller↔agent gRPC server.
    #[arg(long, default_value = "0.0.0.0:50051")]
    grpc_listen: String,

    /// HS256 secret for verifying service/dev bearer tokens. Optional if an OIDC
    /// issuer is configured; at least one of the two must be set.
    #[arg(long, env = "JWT_HS256_SECRET")]
    jwt_hs256_secret: Option<String>,

    /// OIDC issuer URL. When set, the controller fetches the issuer's JWKS via its
    /// discovery document at startup and verifies RS256 tokens against it (FR-29).
    #[arg(long, env = "OIDC_ISSUER")]
    oidc_issuer: Option<String>,

    /// Directory holding the mTLS CA + controller cert/key (`ca.pem`, `server.pem`,
    /// `server.key`). When `ca.pem` is present the gRPC server requires client certs.
    #[arg(long, default_value = "./certs")]
    tls_dir: PathBuf,

    /// Reconcile loop tick interval, in seconds (convergence target < 30s, NFR-R4).
    #[arg(long, default_value_t = 5)]
    reconcile_interval_secs: u64,
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

    let registry = AgentRegistry::default();

    // Build the token verifier: an HS256 secret and/or an OIDC issuer's JWKS
    // (fetched once via the issuer's discovery document). At least one is required.
    let jwks = match &args.oidc_issuer {
        Some(issuer) => {
            tracing::info!(%issuer, "fetching OIDC JWKS");
            Some(
                mm_controller::auth::fetch_oidc_jwks(issuer)
                    .await
                    .context("OIDC discovery / JWKS fetch")?,
            )
        }
        None => None,
    };
    let verifier = JwtVerifier::new(
        args.jwt_hs256_secret.as_deref().map(str::as_bytes),
        jwks.as_ref(),
        args.oidc_issuer.clone(),
    )
    .context("configuring token verification")?;

    // REST API over the store.
    let state = AppState {
        store: store.clone(),
        verifier: Arc::new(verifier),
        metrics: Arc::new(mm_controller::metrics::Metrics::new()),
    };
    let rest_listener = tokio::net::TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("binding REST {}", args.listen))?;
    let rest = axum::serve(rest_listener, api::router(state));

    // gRPC servers (mTLS when a CA is configured).
    let grpc_addr: SocketAddr = args.grpc_listen.parse().context("parsing --grpc-listen")?;
    let mut grpc_builder = Server::builder();
    if args.tls_dir.join("ca.pem").exists() {
        grpc_builder = grpc_builder
            .tls_config(tls::server_config(&args.tls_dir)?)
            .context("configuring server mTLS")?;
    } else {
        tracing::warn!(
            "no CA in {} — gRPC server running without mTLS",
            args.tls_dir.display()
        );
    }
    let grpc = grpc_builder
        .add_service(MachineServiceServer::new(MachineSvc {
            store: store.clone(),
            registry: registry.clone(),
        }))
        .add_service(HostServiceServer::new(HostSvc {
            store: store.clone(),
        }))
        .serve(grpc_addr);

    // Reconcile loop.
    let reconcile = mm_controller::r#loop::run(
        store,
        registry,
        Duration::from_secs(args.reconcile_interval_secs),
    );

    tracing::info!(
        rest = %args.listen,
        grpc = %args.grpc_listen,
        "control plane serving"
    );

    // Run all three until one exits (an error) or the process is signalled.
    tokio::select! {
        r = rest => r.context("REST server")?,
        r = grpc => r.context("gRPC server")?,
        _ = reconcile => {}
        _ = tokio::signal::ctrl_c() => tracing::info!("shutting down"),
    }
    Ok(())
}
