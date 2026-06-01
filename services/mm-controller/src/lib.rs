//! MicroMachines control plane (M2) — library surface.
//!
//! The binary (`src/main.rs`) is a thin entrypoint; the substance lives here as
//! independently-testable modules:
//!
//! - [`reconcile`] — the pure desired-vs-observed decision (no IO).
//!
//! Later M2 tasks add `scheduler`, `authz`, `store`, the `api` routers, the gRPC
//! servers, and the reconcile loop alongside these.
pub mod reconcile;
