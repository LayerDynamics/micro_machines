//! End-to-end: fork child microVMs from a snapshot via copy-on-write memory on KVM
//! (SPEC-1 FR-15, NFR-P2). Boots a sandbox parent, snapshots it, fans out N children
//! with `MAP_PRIVATE` CoW guest RAM, and proves the children are **independent**:
//! writing a distinct value into each child's guest memory and reading it back must
//! return that child's own value (a `MAP_SHARED` mapping — the bug this guards
//! against — would make every child read the last write). Also reports the fan-out
//! latency tracked by NFR-P2 (p50 < 150 ms; the hard gate is liveness + isolation,
//! since the nested-KVM CI runner is slower than a bare-metal host).
//!
//! The full N=100 latency benchmark + in-guest exec independence is a follow-up layer.
//!
//! Requires /dev/kvm and the kernel + rootfs fixtures. `#[ignore]`d otherwise.
#![cfg(all(target_os = "linux", feature = "kvm-integration"))]

use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use mm_sandbox::exec::{run_exec_over_uds, ExecResult, EXEC_PORT};
use mm_vmm::snapshot::{fork_children, load_state, snapshot, ForkPlan};
use mm_vmm::{BlockDevice, Machine, VmConfig};
use vm_memory::{Bytes, GuestAddress};

#[cfg(target_arch = "aarch64")]
const GUEST_CONSOLE: &str = "console=ttyAMA0";
#[cfg(not(target_arch = "aarch64"))]
const GUEST_CONSOLE: &str = "console=ttyS0";

/// How many children to fan out concurrently for the CoW-isolation proof. Kept small
/// so all stay resident at once; the latency sweep below uses a much larger N.
const CHILDREN: usize = 4;
/// Children for the NFR-P2 latency sweep. Forked one at a time (only one resident at
/// once) so the shared nested-KVM CI runner is not overloaded by 100 live VMs.
const FANOUT: usize = 100;
/// A scratch guest-physical address inside the 128 MiB of RAM but well above what an
/// idle sandbox guest touches, used to prove per-child CoW isolation.
const SCRATCH_GPA: u64 = 0x0400_0000; // 64 MiB

fn fixture_config() -> VmConfig {
    VmConfig {
        vcpus: 1,
        memory_mib: 128,
        kernel: "tests/fixtures/vmlinux".into(),
        kernel_cmdline: format!(
            "{GUEST_CONSOLE} root=/dev/vda ro init=/init reboot=t panic=1 {} mm.mode=sandbox",
            mm_vmm::FAST_BOOT_ARGS,
        ),
        rootfs: BlockDevice {
            path: "tests/fixtures/rootfs.ext4".into(),
            read_only: true,
            rate_limit: None,
        },
        devices: vec![],
    }
}

/// A per-test scratch directory. The `tag` must be unique per test: cargo runs the
/// tests in this file concurrently, and each cleans up its own dir, so a shared path
/// would race (one test's cleanup deleting another's snapshot mid-run).
fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mm-fork-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

#[test]
#[ignore = "requires /dev/kvm and fixtures"]
fn fork_fans_out_independent_cow_children() {
    let cfg = fixture_config();
    cfg.validate().unwrap();

    // Warm parent: boot a sandbox guest to userspace, then snapshot it.
    let mut parent = Machine::boot(&cfg).expect("parent boots");
    assert!(
        parent
            .wait_for_ready(Duration::from_secs(10))
            .expect("readiness poll"),
        "parent reached userspace"
    );
    let dir = scratch_dir("isolation");
    let manifest = snapshot(&mut parent, &dir).expect("snapshot the warm parent");

    // Fan out CHILDREN children over CoW memory, timing the fan-out (NFR-P2).
    let plan = ForkPlan {
        child_ids: (1..=CHILDREN as u64).collect(),
        shared_mib: manifest.memory_mib,
        per_child_overhead_mib: 0,
    };
    let t0 = Instant::now();
    let children = fork_children(&cfg, &dir, &plan).expect("fork children");
    let elapsed = t0.elapsed();
    assert_eq!(children.len(), CHILDREN, "all children forked");
    println!(
        "fork fan-out: {CHILDREN} children in {} ms ({} ms/child) — NFR-P2 p50<150ms target",
        elapsed.as_millis(),
        elapsed.as_millis() / CHILDREN as u128
    );

    // CoW isolation: each child gets a distinct value written into its guest RAM;
    // reading it back must yield that child's own value. A MAP_SHARED mapping would
    // make all children (and the backing file) see the last write — this catches it.
    let addr = GuestAddress(SCRATCH_GPA);
    for (i, child) in children.iter().enumerate() {
        let sentinel = 0xC0DE_0000_u64 + i as u64;
        child
            .guest_memory()
            .write_obj(sentinel, addr)
            .expect("write child guest RAM");
    }
    for (i, child) in children.iter().enumerate() {
        let want = 0xC0DE_0000_u64 + i as u64;
        let got: u64 = child
            .guest_memory()
            .read_obj(addr)
            .expect("read child guest RAM");
        assert_eq!(
            got, want,
            "child {i} guest RAM is CoW-isolated (got {got:#x}, want {want:#x})"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "requires /dev/kvm and fixtures; long-running benchmark"]
fn fork_fanout_p50_tracks_nfr_p2() {
    let cfg = fixture_config();
    cfg.validate().unwrap();

    // Warm a parent and snapshot it (the source for every fork).
    let mut parent = Machine::boot(&cfg).expect("parent boots");
    assert!(
        parent
            .wait_for_ready(Duration::from_secs(10))
            .expect("readiness poll"),
        "parent reached userspace"
    );
    let dir = scratch_dir("fanout-p50");
    let manifest = snapshot(&mut parent, &dir).expect("snapshot the warm parent");
    drop(parent); // frozen parent is no longer needed

    // Load the captured state once; each fork gets its own CoW mapping + a clone of it.
    let state = load_state(&dir, &manifest).expect("load snapshot state");
    let mem_path = dir.join(&manifest.memory_file);

    // Fork children one at a time, timing each fork's time-to-running. Only one child
    // is resident at a time (shut down before the next), so 100 forks don't overload
    // the runner — and the per-child fork latency is exactly the NFR-P2 metric.
    let mut samples: Vec<Duration> = Vec::with_capacity(FANOUT);
    for _ in 0..FANOUT {
        let t0 = Instant::now();
        let mut child = Machine::fork(&cfg, state.clone(), &mem_path).expect("fork child");
        samples.push(t0.elapsed());
        child.shutdown().expect("stop forked child");
    }

    samples.sort_unstable();
    let quantile = |q: f64| samples[((samples.len() as f64 * q) as usize).min(samples.len() - 1)];
    let p50 = quantile(0.50);
    let p90 = quantile(0.90);
    println!(
        "fork fan-out N={FANOUT}: p50={} ms, p90={} ms, min={} ms, max={} ms — NFR-P2 p50<150ms target",
        p50.as_millis(),
        p90.as_millis(),
        samples.first().unwrap().as_millis(),
        samples.last().unwrap().as_millis(),
    );

    // The 150 ms p50 target is reported + tracked (like the boot NFR-P1 bench); the
    // hard gate is a generous bound that only catches a genuine regression, since the
    // nested-KVM CI runner is materially slower than a bare-metal host.
    assert!(
        p50.as_millis() < 2_000,
        "per-child fork p50 must be < 2s (got {} ms); NFR-P2 150ms tracked in the number above",
        p50.as_millis(),
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Fork one child off the snapshot with its own host vsock bridge bound at `uds`, so
/// the host can `exec` into it. Each child must use a distinct `uds`.
fn fork_bridged_child(
    cfg: &VmConfig,
    state: &mm_vmm::snapshot::VmState,
    mem_path: &Path,
    uds: &Path,
) -> Machine {
    let listener = UnixListener::bind(uds).expect("bind child vsock bridge");
    Machine::fork_with_vsock(cfg, state.clone(), mem_path, Some(listener))
        .expect("fork bridged child")
}

/// Run `/sbin/marker <args>` inside a forked child over its vsock bridge at `uds`,
/// returning the result. Retries the connect: a freshly-forked child's vsock device
/// reactor may not be accepting on the UDS the instant `fork` returns.
fn exec_marker(uds: &Path, args: &[&str]) -> ExecResult {
    let cmd: Vec<String> = std::iter::once("/sbin/marker".to_string())
        .chain(args.iter().map(|s| s.to_string()))
        .collect();
    let mut last_err = None;
    for _ in 0..50 {
        match run_exec_over_uds(uds, EXEC_PORT, 1, &cmd, 10_000) {
            Ok(result) => return result,
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    panic!("exec /sbin/marker {args:?} never connected over {uds:?}: {last_err:?}");
}

/// Foundation check for in-guest fork independence: a child forked from a snapshot,
/// with a fresh host vsock bridge, is actually reachable for `exec` — i.e. the
/// snapshot-restored vsock device works through a CoW fork. Writes a marker in the
/// guest and reads it back over the bridge.
#[test]
#[ignore = "requires /dev/kvm and fixtures"]
fn forked_child_is_execable_over_its_vsock_bridge() {
    let cfg = fixture_config();
    cfg.validate().unwrap();

    let mut parent = Machine::boot(&cfg).expect("parent boots");
    assert!(
        parent
            .wait_for_ready(Duration::from_secs(10))
            .expect("readiness poll"),
        "parent reached userspace"
    );
    let dir = scratch_dir("exec-foundation");
    let manifest = snapshot(&mut parent, &dir).expect("snapshot the warm parent");
    drop(parent);

    let state = load_state(&dir, &manifest).expect("load snapshot state");
    let mem_path = dir.join(&manifest.memory_file);

    let uds = dir.join("child-0.sock");
    let mut child = fork_bridged_child(&cfg, &state, &mem_path, &uds);

    let write = exec_marker(&uds, &["write", "FOUNDATION"]);
    assert_eq!(
        write.exit_code,
        0,
        "marker write failed (stderr: {})",
        String::from_utf8_lossy(&write.stderr)
    );
    let read = exec_marker(&uds, &["read"]);
    assert_eq!(read.exit_code, 0, "marker read failed");
    assert_eq!(
        String::from_utf8_lossy(&read.stdout),
        "FOUNDATION",
        "the forked child read back the marker it wrote over its own vsock bridge"
    );

    child.shutdown().expect("stop forked child");
    let _ = std::fs::remove_dir_all(&dir);
}
