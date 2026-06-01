//! MicroMachines control plane (M2) — library surface.
//!
//! The binary (`src/main.rs`) is a thin entrypoint; the substance lives here as
//! independently-testable modules:
//!
//! - [`reconcile`] — the pure desired-vs-observed decision (no IO).
//! - [`scheduler`] — pure host placement for a machine's resource demand.
//!
//! Later M2 tasks add `authz`, `store`, the `api` routers, the gRPC servers, and
//! the reconcile loop alongside these.
pub mod reconcile;
pub mod scheduler;
