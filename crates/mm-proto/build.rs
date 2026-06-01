//! Compile the controller<->agent gRPC contract at build time.
//!
//! Uses a vendored `protoc` so the build is hermetic: no system protobuf compiler
//! is required on a developer machine or in CI.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // SAFETY: single-threaded build script; setting PROTOC before tonic-build reads it.
    std::env::set_var("PROTOC", protoc);

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/machine.proto"], &["proto"])?;
    Ok(())
}
