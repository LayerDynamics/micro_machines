//! MicroMachines control plane (M2) — library surface.
//!
//! The binary (`src/main.rs`) is a thin entrypoint; the substance lives here as
//! independently-testable modules:
//!
//! - [`reconcile`] — the pure desired-vs-observed decision (no IO).
//! - [`scheduler`] — pure host placement for a machine's resource demand.
//! - [`authz`] — JWT claim shape + namespace-scoped RBAC.
//! - [`auth`] — JWT verification from a configured key (the OIDC/JWT seam).
//! - [`model`] — REST/JSONB object shapes (spec/status).
//! - [`store`] — PostgreSQL persistence (runtime sqlx queries).
//! - [`api`] — the axum router + handlers.
//!
//! Later M2 tasks add the gRPC servers and the reconcile loop alongside these.
pub mod api;
pub mod auth;
pub mod authz;
pub mod model;
pub mod reconcile;
pub mod scheduler;
pub mod store;
