//! Host<->guest exec channel for Sandbox Mode (SPEC-1 FR-13).
//!
//! [`protocol`] is the cross-platform wire format spoken by both the host exec
//! client ([`client`]) and the in-guest exec agent (`mm-init`).
pub mod client;
pub mod protocol;

/// The guest vsock port the in-guest exec agent listens on, and the host connector
/// targets. Shared so the host side and the guest agent (`mm-init`) cannot drift.
pub const EXEC_PORT: u32 = 1025;

pub use client::{run_exec, run_exec_over_uds, vsock_connect, ExecResult};
pub use protocol::{decode, encode, Frame, Stream};
