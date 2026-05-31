//! OCI image handling for MicroMachines: build a read-only base rootfs from an
//! OCI image and lay out per-instance writable overlays (SPEC-1 FR-6).
#![forbid(unsafe_code)]

pub mod rootfs;
pub use rootfs::{Digest, ImageError, ImageStore, OverlayPaths};
