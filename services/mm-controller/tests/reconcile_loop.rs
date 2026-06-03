//! Integration: the controller↔agent reconcile path over real mutual-TLS gRPC and a
//! real PostgreSQL (SPEC-1 FR-19/FR-22, NFR-R2/R4).
//!
//! Spins up the controller's gRPC servers over mTLS, connects a *fake agent* (a
//! gRPC client that reports `Running` when assigned, without actually booting a VM),
//! creates a machine, and drives the reconcile loop until it converges. Then it
//! re-runs reconciliation against the same Postgres to prove the data plane survives
//! a controller restart with no duplicate assignment.
//!
//! Requires `DATABASE_URL` (the CI `controller` job provides it) and `openssl` +
//! `bash` (for the dev cert script). Skips when `DATABASE_URL` is unset.
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use mm_agent::tls::client_config;
use mm_api_types::State;
use mm_controller::grpc::{AgentRegistry, HostSvc, MachineSvc};
use mm_controller::model::MachineSpec;
use mm_controller::store::Store;
use mm_controller::tls::server_config;
use mm_proto::host_service_client::HostServiceClient;
use mm_proto::host_service_server::HostServiceServer;
use mm_proto::machine_service_client::MachineServiceClient;
use mm_proto::machine_service_server::MachineServiceServer;
use mm_proto::{Capacity, HostRef, MachineEvent};
use sqlx::postgres::PgPoolOptions;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};

#[tokio::test]
async fn reconcile_schedules_boots_and_survives_restart() {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL unset — skipping reconcile_loop (DB gates run in CI)");
        return;
    };

    // 1. Generate a dev mTLS CA + server/client certs into a temp dir.
    let dir = std::env::temp_dir().join(format!("mm-recon-certs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/dev-certs.sh");
    let ok = std::process::Command::new("bash")
        .arg(script)
        .arg(&dir)
        .status()
        .expect("run dev-certs.sh")
        .success();
    assert!(ok, "dev-certs.sh failed");

    // 2. Store on real Postgres.
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("connect Postgres");
    let store = Store::new(pool.clone());
    store.migrate().await.expect("migrate");
    sqlx::query("DELETE FROM namespaces WHERE name = 'recon'")
        .execute(&pool)
        .await
        .expect("pre-clean");
    store.create_namespace("recon").await.expect("create ns");

    let registry = AgentRegistry::default();

    // 3. Start the controller gRPC servers over mTLS on an ephemeral port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    {
        let store = store.clone();
        let registry = registry.clone();
        let tls = server_config(&dir).expect("server tls");
        tokio::spawn(async move {
            Server::builder()
                .tls_config(tls)
                .expect("apply server tls")
                .add_service(MachineServiceServer::new(MachineSvc {
                    store: store.clone(),
                    registry,
                    exec: mm_controller::grpc::ExecDispatcher::default(),
                    snapshots: mm_controller::grpc::SnapshotDispatcher::default(),
                }))
                .add_service(HostServiceServer::new(HostSvc { store }))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .expect("grpc serve");
        });
    }

    // 4. Connect a fake agent over mTLS (retry until the server is ready). Dial the
    //    IP literal to avoid IPv6-localhost ambiguity; the TLS server name stays
    //    "localhost" (the cert SAN) via `client_config`.
    let url = format!("https://127.0.0.1:{port}");
    let channel = connect(&url, &dir).await;
    let mut hosts = HostServiceClient::new(channel.clone());
    let mut machines = MachineServiceClient::new(channel);

    // Advertise capacity so the scheduler can place onto this host.
    hosts
        .report_capacity(Capacity {
            host_id: "host-1".into(),
            vcpus_total: 8,
            vcpus_free: 8,
            mem_mib_total: 16384,
            mem_mib_free: 16384,
        })
        .await
        .expect("report capacity");

    // The fake agent watches assignments and reports Running for each (no real boot).
    let received = Arc::new(AtomicUsize::new(0));
    {
        let received = received.clone();
        let mut hosts = hosts.clone();
        let mut stream = machines
            .watch_assignments(HostRef {
                host_id: "host-1".into(),
            })
            .await
            .expect("watch assignments")
            .into_inner();
        tokio::spawn(async move {
            while let Ok(Some(assignment)) = stream.message().await {
                received.fetch_add(1, Ordering::SeqCst);
                if let Some(uid) = assignment.machine.and_then(|m| m.r#ref).map(|r| r.uid) {
                    let _ = hosts
                        .report_event(MachineEvent {
                            uid,
                            state: mm_controller::convert::api_state_to_proto(State::Running),
                            message: "booted".into(),
                            ip: "10.0.0.99".into(),
                        })
                        .await;
                }
            }
        });
    }

    // 5. Create a machine that should be running.
    let spec = MachineSpec {
        image: "docker.io/library/alpine:latest".into(),
        kernel: None,
        vcpus: 2,
        memory_mib: 512,
        ssh: false,
        workload: None,
        running: true,
    };
    let uid = store
        .create_machine("recon", "default", "web", &spec)
        .await
        .expect("create machine")
        .uid;

    // 6. Drive reconcile ticks until the machine converges to Running.
    let mut converged = false;
    for _ in 0..50 {
        mm_controller::r#loop::reconcile_once(&store, &registry)
            .await
            .expect("reconcile");
        tokio::time::sleep(Duration::from_millis(100)).await;
        let m = store.get_machine_by_uid(uid).await.unwrap().unwrap();
        if m.status.state == State::Running {
            converged = true;
            break;
        }
    }
    assert!(converged, "machine never converged to Running (NFR-R4)");
    // The agent's reported IP propagated into observed status.
    let m = store.get_machine_by_uid(uid).await.unwrap().unwrap();
    assert_eq!(
        m.status.ip.as_deref(),
        Some("10.0.0.99"),
        "agent-reported IP recorded in status"
    );
    let assignments_when_running = received.load(Ordering::SeqCst);

    // 7. Simulate a controller restart: a fresh registry (no in-flight state) plus a
    //    reconcile read purely from Postgres. Status must be preserved (NFR-R2) and
    //    no new assignment issued (the machine is Running ⇒ decide → None).
    let fresh_registry = AgentRegistry::default();
    mm_controller::r#loop::reconcile_once(&store, &fresh_registry)
        .await
        .expect("reconcile after restart");
    let m = store.get_machine_by_uid(uid).await.unwrap().unwrap();
    assert_eq!(
        m.status.state,
        State::Running,
        "running machine survives a control-plane restart (NFR-R2)"
    );

    // A further tick on the original (still-connected) registry must not re-assign.
    mm_controller::r#loop::reconcile_once(&store, &registry)
        .await
        .expect("idempotent reconcile");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        received.load(Ordering::SeqCst),
        assignments_when_running,
        "no duplicate assignment once a machine is Running"
    );

    // Cleanup.
    sqlx::query("DELETE FROM namespaces WHERE name = 'recon'")
        .execute(&pool)
        .await
        .ok();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Connect the mTLS gRPC channel, retrying briefly while the server starts.
async fn connect(url: &str, cert_dir: &std::path::Path) -> Channel {
    let tls = client_config(cert_dir, "localhost").expect("client tls");
    for _ in 0..50 {
        let attempt = Channel::from_shared(url.to_string())
            .unwrap()
            .tls_config(tls.clone())
            .unwrap()
            .connect()
            .await;
        if let Ok(ch) = attempt {
            return ch;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("agent could not connect to controller gRPC at {url}");
}
