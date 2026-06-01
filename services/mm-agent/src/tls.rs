//! Mutual-TLS configuration for the agent's gRPC client (SPEC-1 FR-19).
//!
//! The agent verifies the controller against the shared CA and presents its own
//! CA-issued client certificate, so the controller can authenticate it. Certs are
//! loaded from a directory (`ca.pem`, `client.pem`, `client.key`).
use std::path::Path;

use anyhow::{Context, Result};
use tonic::transport::{Certificate, ClientTlsConfig, Identity};

/// Build the client mTLS config from a cert directory. `domain` must match the
/// controller server certificate's subject-alternative name.
pub fn client_config(dir: &Path, domain: &str) -> Result<ClientTlsConfig> {
    let read = |name: &str| {
        std::fs::read(dir.join(name))
            .with_context(|| format!("reading {name} from {}", dir.display()))
    };
    let identity = Identity::from_pem(read("client.pem")?, read("client.key")?);
    let ca = Certificate::from_pem(read("ca.pem")?);
    Ok(ClientTlsConfig::new()
        .ca_certificate(ca)
        .identity(identity)
        .domain_name(domain))
}
