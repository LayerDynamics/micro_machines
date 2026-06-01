//! `mm __vmm-worker` — the jailed VMM child (internal; not a user-facing command).
//!
//! Spawned by `mm run` via re-exec after the privileged parent has built the rootfs,
//! wired the bridge/TAP/NAT, opened `/dev/kvm`, and prepared a chroot. The body lives
//! in [`mm_host`] so the cluster agent's `__vmm-worker` shares the identical
//! confine + boot path; this module just re-exports the arguments and delegates.
pub use mm_host::WorkerArgs;

pub fn run(args: WorkerArgs) -> anyhow::Result<()> {
    mm_host::run_worker(args)
}
