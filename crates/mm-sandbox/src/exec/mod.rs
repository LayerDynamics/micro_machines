//! Host<->guest exec channel for Sandbox Mode (SPEC-1 FR-13).
//!
//! [`protocol`] is the cross-platform wire format spoken by both the host exec
//! client and the in-guest exec agent (`mm-init`).
pub mod protocol;

pub use protocol::{decode, encode, Frame, Stream};
