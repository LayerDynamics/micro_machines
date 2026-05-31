//! Error types for `mm-api-types` validation and parsing.
//!
//! These are the canonical, typed failures every consumer of the contract layer
//! matches on, rather than stringly-typed errors. Backed by `thiserror` so the
//! `Display` messages stay consistent across the workspace.
use thiserror::Error;

/// Errors produced when validating or parsing MicroMachines API types.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    /// A resource `name` or `namespace` failed RFC 1123 label validation
    /// (the same rules Kubernetes applies to object names — SPEC-1 §3.3).
    #[error("invalid {field} {value:?}: {reason}")]
    InvalidName {
        /// Which metadata field failed (`"name"` or `"namespace"`).
        field: &'static str,
        /// The offending value, echoed back for diagnostics.
        value: String,
        /// Human-readable reason the value was rejected.
        reason: &'static str,
    },

    /// A string did not correspond to any known [`crate::State`] variant.
    #[error("unknown machine state {0:?}")]
    UnknownState(String),
}
