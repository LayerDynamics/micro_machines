//! mm-init — PID 1 inside a MicroMachines guest (SPEC-1 FR-5).
fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    {
        mm_init::run_pid1()
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("mm-init only runs as PID 1 inside a Linux guest");
        std::process::ExitCode::FAILURE
    }
}
