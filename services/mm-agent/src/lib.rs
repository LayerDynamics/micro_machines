//! `mm-agent` library — the host agent's testable pieces.
//!
//! - [`capacity`] — free/total host capacity accounting (reported to the scheduler).
//! - [`local_store`] — the agent's own durable machine registry (restart recovery).
//! - [`actuator`] — turning a controller assignment into a real microVM via mm-host.
//! - [`exec`] — cluster exec: run a command in a guest, streamed back to the
//!   controller (the agent side of SPEC-1 FR-13).
//! - [`snapshot`] — cluster snapshot/branch: drive a guest's worker control channel
//!   on a pushed task, result reported back (the agent side of SPEC-1 FR-14/FR-18).
//!
//! The binary (`src/main.rs`) wires these to the controller over gRPC.
pub mod actuator;
pub mod capacity;
pub mod exec;
pub mod local_store;
pub mod snapshot;
pub mod tls;
