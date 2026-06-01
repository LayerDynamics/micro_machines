//! PostgreSQL persistence for the control plane (SPEC-1 FR-22, §3.3).
//!
//! Uses sqlx's runtime query API (`query`/`query_as`) rather than the compile-time
//! `query!` macros, so the crate builds with no database available at compile time;
//! the SQL is exercised against a real Postgres by the integration tests in CI.
//!
//! `spec`/`status` are stored as JSONB and (de)serialized through the [`crate::model`]
//! types. Every mutation the API performs also writes an [`audit_log`](Store::audit)
//! row so privileged actions are traceable (SPEC-1 §3.3).
use serde_json::Value;
use sqlx::postgres::PgPool;
use sqlx::FromRow;
use uuid::Uuid;

use crate::authz::Role;
use crate::model::{Machine, MachineSpec, MachineStatus};

/// Thin handle over a Postgres connection pool.
#[derive(Clone)]
pub struct Store {
    pool: PgPool,
}

/// Raw machine row as stored (JSONB columns surface as `serde_json::Value`).
#[derive(FromRow)]
struct MachineRow {
    uid: Uuid,
    namespace: String,
    fleet: String,
    name: String,
    spec: Value,
    status: Value,
    host_id: Option<String>,
}

impl MachineRow {
    /// Decode the JSONB columns into the typed API shape.
    fn into_machine(self) -> Result<Machine, sqlx::Error> {
        let spec: MachineSpec = serde_json::from_value(self.spec).map_err(decode_err)?;
        let status: MachineStatus = serde_json::from_value(self.status).map_err(decode_err)?;
        Ok(Machine {
            uid: self.uid,
            namespace: self.namespace,
            fleet: self.fleet,
            name: self.name,
            spec,
            status,
            host_id: self.host_id,
        })
    }
}

fn decode_err(e: serde_json::Error) -> sqlx::Error {
    sqlx::Error::Decode(Box::new(e))
}

impl Store {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Apply the embedded migrations (used by tests and on startup).
    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        sqlx::migrate!("./migrations").run(&self.pool).await
    }

    // --- namespaces -------------------------------------------------------

    /// Create a namespace, ignoring a duplicate (idempotent create).
    pub async fn create_namespace(&self, name: &str) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO namespaces (name) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn namespace_exists(&self, name: &str) -> Result<bool, sqlx::Error> {
        let row: Option<(String,)> = sqlx::query_as("SELECT name FROM namespaces WHERE name = $1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    pub async fn list_namespaces(&self) -> Result<Vec<String>, sqlx::Error> {
        let rows: Vec<(String,)> = sqlx::query_as("SELECT name FROM namespaces ORDER BY name")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(n,)| n).collect())
    }

    // --- machines ---------------------------------------------------------

    /// Insert a new machine with the given desired spec and a default status.
    /// Returns the created machine, or a unique-violation error if the
    /// `(namespace, fleet, name)` already exists.
    pub async fn create_machine(
        &self,
        namespace: &str,
        fleet: &str,
        name: &str,
        spec: &MachineSpec,
    ) -> Result<Machine, sqlx::Error> {
        let uid = Uuid::new_v4();
        let status = MachineStatus::default();
        let spec_json = serde_json::to_value(spec).map_err(decode_err)?;
        let status_json = serde_json::to_value(&status).map_err(decode_err)?;

        let row: MachineRow = sqlx::query_as(
            "INSERT INTO machines (uid, namespace, fleet, name, spec, status)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING uid, namespace, fleet, name, spec, status, host_id",
        )
        .bind(uid)
        .bind(namespace)
        .bind(fleet)
        .bind(name)
        .bind(spec_json)
        .bind(status_json)
        .fetch_one(&self.pool)
        .await?;
        row.into_machine()
    }

    pub async fn get_machine(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<Machine>, sqlx::Error> {
        let row: Option<MachineRow> = sqlx::query_as(
            "SELECT uid, namespace, fleet, name, spec, status, host_id
             FROM machines WHERE namespace = $1 AND name = $2",
        )
        .bind(namespace)
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;
        row.map(MachineRow::into_machine).transpose()
    }

    pub async fn list_machines(&self, namespace: &str) -> Result<Vec<Machine>, sqlx::Error> {
        let rows: Vec<MachineRow> = sqlx::query_as(
            "SELECT uid, namespace, fleet, name, spec, status, host_id
             FROM machines WHERE namespace = $1 ORDER BY name",
        )
        .bind(namespace)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(MachineRow::into_machine).collect()
    }

    /// Every machine across all namespaces — the input the reconcile loop iterates.
    pub async fn list_all_machines(&self) -> Result<Vec<Machine>, sqlx::Error> {
        let rows: Vec<MachineRow> = sqlx::query_as(
            "SELECT uid, namespace, fleet, name, spec, status, host_id FROM machines",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(MachineRow::into_machine).collect()
    }

    /// Fetch a machine by its stable uid (the gRPC key).
    pub async fn get_machine_by_uid(&self, uid: Uuid) -> Result<Option<Machine>, sqlx::Error> {
        let row: Option<MachineRow> = sqlx::query_as(
            "SELECT uid, namespace, fleet, name, spec, status, host_id FROM machines WHERE uid = $1",
        )
        .bind(uid)
        .fetch_optional(&self.pool)
        .await?;
        row.map(MachineRow::into_machine).transpose()
    }

    /// Set a machine's observed lifecycle state (from an agent `ReportEvent`),
    /// merging into the existing status JSON. Returns rows changed.
    pub async fn set_observed_state(&self, uid: Uuid, state: &str) -> Result<u64, sqlx::Error> {
        let res = sqlx::query(
            "UPDATE machines
             SET status = jsonb_set(status, '{state}', to_jsonb($2::text)), updated_at = now()
             WHERE uid = $1",
        )
        .bind(uid)
        .bind(state)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Set both the observed state and the guest IP (the agent learns the IP when it
    /// boots the machine, so it reports both together). Returns rows changed.
    pub async fn set_observed(&self, uid: Uuid, state: &str, ip: &str) -> Result<u64, sqlx::Error> {
        let res = sqlx::query(
            "UPDATE machines
             SET status = jsonb_set(
                     jsonb_set(status, '{state}', to_jsonb($2::text)),
                     '{ip}', to_jsonb($3::text)),
                 updated_at = now()
             WHERE uid = $1",
        )
        .bind(uid)
        .bind(state)
        .bind(ip)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Set `spec.running` (the `start`/`stop` verbs) and bump `updated_at`. Returns
    /// the number of rows changed (0 if the machine does not exist).
    pub async fn set_running(
        &self,
        namespace: &str,
        name: &str,
        running: bool,
    ) -> Result<u64, sqlx::Error> {
        let res = sqlx::query(
            "UPDATE machines
             SET spec = jsonb_set(spec, '{running}', to_jsonb($3::bool)), updated_at = now()
             WHERE namespace = $1 AND name = $2",
        )
        .bind(namespace)
        .bind(name)
        .bind(running)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Replace a machine's observed status (called from agent reports / reconcile).
    pub async fn update_status(
        &self,
        uid: Uuid,
        status: &MachineStatus,
    ) -> Result<u64, sqlx::Error> {
        let status_json = serde_json::to_value(status).map_err(decode_err)?;
        let res = sqlx::query("UPDATE machines SET status = $2, updated_at = now() WHERE uid = $1")
            .bind(uid)
            .bind(status_json)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    /// Record the host a machine was scheduled onto.
    pub async fn assign_host(&self, uid: Uuid, host_id: &str) -> Result<u64, sqlx::Error> {
        let res =
            sqlx::query("UPDATE machines SET host_id = $2, updated_at = now() WHERE uid = $1")
                .bind(uid)
                .bind(host_id)
                .execute(&self.pool)
                .await?;
        Ok(res.rows_affected())
    }

    pub async fn delete_machine(&self, namespace: &str, name: &str) -> Result<u64, sqlx::Error> {
        let res = sqlx::query("DELETE FROM machines WHERE namespace = $1 AND name = $2")
            .bind(namespace)
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected())
    }

    // --- hosts ------------------------------------------------------------

    /// Insert or refresh a host's advertised capacity + heartbeat.
    pub async fn upsert_host(&self, host_id: &str, capacity: &Value) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO hosts (host_id, capacity, last_heartbeat, healthy)
             VALUES ($1, $2, now(), true)
             ON CONFLICT (host_id)
             DO UPDATE SET capacity = $2, last_heartbeat = now(), healthy = true",
        )
        .bind(host_id)
        .bind(capacity)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Refresh a host's heartbeat timestamp (keeps it marked healthy/live).
    pub async fn touch_heartbeat(&self, host_id: &str) -> Result<u64, sqlx::Error> {
        let res = sqlx::query(
            "UPDATE hosts SET last_heartbeat = now(), healthy = true WHERE host_id = $1",
        )
        .bind(host_id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Healthy hosts and their advertised capacity JSON, for the scheduler. A host
    /// is considered live if it heartbeat within `stale_after` seconds.
    pub async fn live_host_capacities(
        &self,
        stale_after_secs: i64,
    ) -> Result<Vec<(String, Value)>, sqlx::Error> {
        let rows: Vec<(String, Value)> = sqlx::query_as(
            "SELECT host_id, capacity FROM hosts
             WHERE healthy = true AND last_heartbeat > now() - make_interval(secs => $1::double precision)",
        )
        .bind(stale_after_secs as f64)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    // --- rbac + audit -----------------------------------------------------

    /// The role a subject holds in a namespace, if any (RBAC lookup by JWT `sub`).
    pub async fn role_binding(
        &self,
        subject: &str,
        namespace: &str,
    ) -> Result<Option<Role>, sqlx::Error> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT role FROM rbac_bindings WHERE subject = $1 AND namespace = $2")
                .bind(subject)
                .bind(namespace)
                .fetch_optional(&self.pool)
                .await?;
        match row {
            Some((role,)) => Role::parse(&role)
                .map(Some)
                .map_err(|e| sqlx::Error::Decode(Box::new(e))),
            None => Ok(None),
        }
    }

    /// Grant `subject` a `role` in `namespace` (upsert).
    pub async fn put_binding(
        &self,
        subject: &str,
        namespace: &str,
        role: Role,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO rbac_bindings (subject, namespace, role) VALUES ($1, $2, $3)
             ON CONFLICT (subject, namespace) DO UPDATE SET role = $3",
        )
        .bind(subject)
        .bind(namespace)
        .bind(role.as_str())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Append an audit row for an attempted action and its outcome.
    pub async fn audit(
        &self,
        actor: &str,
        namespace: Option<&str>,
        action: &str,
        resource: Option<&str>,
        outcome: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO audit_log (actor, namespace, action, resource, outcome)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(actor)
        .bind(namespace)
        .bind(action)
        .bind(resource)
        .bind(outcome)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
