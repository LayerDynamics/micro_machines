//! Generated gRPC contract shared by the controller and the host agent
//! (SPEC-1 FR-19, Appendix B.4).
//!
//! `proto/machine.proto` is the single source of truth; `build.rs` runs
//! `tonic-build` over it and this module re-exports the generated types: the
//! message structs, the `State` enum, and the `MachineService`/`HostService`
//! client + server stubs.
tonic::include_proto!("micromachines.v1alpha1");
