//! `mm-agent` library — the host agent's testable pieces.
//!
//! - [`capacity`] — free/total host capacity accounting (reported to the scheduler).
//! - [`local_store`] — the agent's own durable machine registry (restart recovery).
//! - [`actuator`] — turning a controller assignment into a real microVM via mm-host.
//!
//! The binary (`src/main.rs`) wires these to the controller over gRPC.
pub mod actuator;
pub mod capacity;
pub mod local_store;
pub mod tls;
