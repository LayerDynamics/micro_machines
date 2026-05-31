//! Shared API types for MicroMachines (SPEC-1 §3.3).
//!
//! This crate is the contract layer: every other crate depends on these types
//! rather than redefining spec/status shapes. Keep it dependency-light.
#![forbid(unsafe_code)]

mod error;
mod meta;
mod state;

pub use error::Error;
pub use meta::ObjectMeta;
pub use state::State;
