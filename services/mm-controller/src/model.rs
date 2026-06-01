//! REST + JSONB data shapes for control-plane objects (SPEC-1 §3.3, FR-7/FR-9).
//!
//! A machine's [`MachineSpec`] (desired) and [`MachineStatus`] (observed) are stored
//! verbatim as JSONB in the `machines` table and round-trip through these structs.
//! They parallel the gRPC `MachineSpec`/`MachineStatus` the agent consumes, but the
//! REST/JSONB and protobuf encodings are kept as separate representations on purpose.
use std::collections::BTreeMap;

use mm_api_types::State;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

fn default_vcpus() -> u32 {
    1
}
fn default_memory_mib() -> u64 {
    512
}

/// Desired state of a machine (strongly consistent; the source of truth).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineSpec {
    /// OCI image reference to boot.
    pub image: String,
    /// Optional kernel override; the agent uses its default when absent.
    #[serde(default)]
    pub kernel: Option<String>,
    #[serde(default = "default_vcpus")]
    pub vcpus: u32,
    #[serde(default = "default_memory_mib")]
    pub memory_mib: u64,
    /// Provision SSH access (inject sshd + key) — the M1 `--ssh` behaviour.
    #[serde(default)]
    pub ssh: bool,
    /// The workload command; absent means the image's own entrypoint.
    #[serde(default)]
    pub workload: Option<Workload>,
    /// Whether the operator wants this machine running. `start`/`stop` flip this;
    /// the reconciler actuates toward it.
    #[serde(default)]
    pub running: bool,
}

/// The command to run inside the guest.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Workload {
    pub entrypoint: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

/// Observed state of a machine (eventually consistent; updated from agent reports).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineStatus {
    pub state: State,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub health: String,
    #[serde(default)]
    pub host_id: Option<String>,
    #[serde(default)]
    pub retry_count: u32,
}

impl Default for MachineStatus {
    /// A freshly created machine has not been placed or started yet.
    fn default() -> Self {
        Self {
            state: State::Created,
            ip: None,
            health: String::new(),
            host_id: None,
            retry_count: 0,
        }
    }
}

/// A machine as returned by the API: identity + desired + observed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Machine {
    pub uid: Uuid,
    pub namespace: String,
    pub fleet: String,
    pub name: String,
    pub spec: MachineSpec,
    pub status: MachineStatus,
    #[serde(default)]
    pub host_id: Option<String>,
}

/// Request body to create a machine (identity comes from the URL path).
#[derive(Debug, Clone, Deserialize)]
pub struct CreateMachine {
    pub name: String,
    #[serde(default = "default_fleet")]
    pub fleet: String,
    pub spec: MachineSpec,
}

fn default_fleet() -> String {
    "default".to_string()
}
