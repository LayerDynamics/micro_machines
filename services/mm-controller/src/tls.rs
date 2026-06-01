//! Mutual-TLS configuration for the controller's gRPC server (SPEC-1 FR-19).
//!
//! The controller presents its server certificate and *requires* a client
//! certificate signed by the shared CA, so only agents holding a CA-issued identity
//! can connect. Certs are loaded from a directory (`ca.pem`, `server.pem`,
//! `server.key`) produced by `scripts/dev-certs.sh` (or any PKI).
use std::path::Path;

use anyhow::{Context, Result};
use tonic::transport::{Certificate, Identity, ServerTlsConfig};

/// Build the server mTLS config from a cert directory. The presence of
/// `client_ca_root` makes client certificates mandatory.
pub fn server_config(dir: &Path) -> Result<ServerTlsConfig> {
    let read = |name: &str| {
        std::fs::read(dir.join(name))
            .with_context(|| format!("reading {name} from {}", dir.display()))
    };
    let identity = Identity::from_pem(read("server.pem")?, read("server.key")?);
    let ca = Certificate::from_pem(read("ca.pem")?);
    Ok(ServerTlsConfig::new().identity(identity).client_ca_root(ca))
}
