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

use mm_sandbox::exec::{run_exec_over_uds_ready, ExecResult, EXEC_PORT};
use mm_vmm::snapshot::{fork_children, load_state, snapshot, ForkPlan};
use mm_vmm::{BlockDevice, Machine, VmConfig};
use userfaultfd::{Event, FaultKind, FeatureFlags, RegisterMode, UffdBuilder};
use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryRegion};

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

/// How long to wait for a forked child's in-guest exec agent to start serving before
/// giving up. A hard cap so the test FAILS FAST with a diagnostic instead of appearing
/// stuck — a healthy child reaches its listening state within a few seconds of resume.
const FORK_EXEC_READY_TIMEOUT: Duration = Duration::from_secs(15);

/// Run `/sbin/marker <args>` inside a forked child over its vsock bridge at `uds`,
/// returning the result. Uses the connector's bounded retry: a child forked from a
/// snapshot taken at boot-readiness must resume and *then* reach the point where its
/// in-guest exec agent is listening, so the first handshakes are expected to fail
/// until it comes up. Bounded by [`FORK_EXEC_READY_TIMEOUT`] so a child that never
/// comes up fails the test quickly rather than hanging.
fn exec_marker(uds: &Path, args: &[&str]) -> ExecResult {
    let cmd: Vec<String> = std::iter::once("/sbin/marker".to_string())
        .chain(args.iter().map(|s| s.to_string()))
        .collect();
    run_exec_over_uds_ready(uds, EXEC_PORT, 1, &cmd, 10_000, FORK_EXEC_READY_TIMEOUT)
        .unwrap_or_else(|e| panic!("exec /sbin/marker {args:?} over {uds:?}: {e}"))
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

/// In-guest fork exec-independence (SPEC-1 FR-15): fork several children, write a
/// distinct marker into each child's guest filesystem *via `exec`*, then read every
/// child back — each must see only its own value. The write-all-then-read-all order is
/// what makes a cross-child bleed (shared guest RAM/fs from a broken CoW fork) show up:
/// a leak would surface a sibling's marker on read-back. This is the end-to-end
/// counterpart of the host-level CoW-isolation check above, exercised through a real
/// command run inside each live child.
#[test]
#[ignore = "requires /dev/kvm and fixtures"]
fn forked_children_have_independent_guest_state() {
    let cfg = fixture_config();
    cfg.validate().unwrap();

    let mut parent = Machine::boot(&cfg).expect("parent boots");
    assert!(
        parent
            .wait_for_ready(Duration::from_secs(10))
            .expect("readiness poll"),
        "parent reached userspace"
    );
    let dir = scratch_dir("exec-independence");
    let manifest = snapshot(&mut parent, &dir).expect("snapshot the warm parent");
    drop(parent);

    let state = load_state(&dir, &manifest).expect("load snapshot state");
    let mem_path = dir.join(&manifest.memory_file);

    const N: usize = 3;
    // Fork N children, each with its own host vsock bridge, all resident at once.
    let mut children: Vec<(Machine, PathBuf)> = Vec::with_capacity(N);
    for i in 0..N {
        let uds = dir.join(format!("child-{i}.sock"));
        let child = fork_bridged_child(&cfg, &state, &mem_path, &uds);
        children.push((child, uds));
    }

    // Phase 1: write a distinct marker into each child's guest filesystem.
    for (i, (_, uds)) in children.iter().enumerate() {
        let value = format!("CHILD-{i}");
        let w = exec_marker(uds, &["write", value.as_str()]);
        assert_eq!(
            w.exit_code,
            0,
            "child {i} marker write failed (stderr: {})",
            String::from_utf8_lossy(&w.stderr)
        );
    }

    // Phase 2: read every child back — each must see ONLY its own value.
    for (i, (_, uds)) in children.iter().enumerate() {
        let r = exec_marker(uds, &["read"]);
        assert_eq!(r.exit_code, 0, "child {i} marker read failed");
        assert_eq!(
            String::from_utf8_lossy(&r.stdout),
            format!("CHILD-{i}"),
            "child {i} must read back its own marker — no cross-child bleed"
        );
    }

    for (mut child, _) in children {
        child.shutdown().expect("stop forked child");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// FR-16 Phase 0 feasibility probe (docs/plans/2026-06-02-fr16-running-branch-uffd-wp.md):
/// does userfaultfd write-protect deliver faults for a *running KVM guest's* writes on
/// this kernel? UFFD_WP on plain host memory is well-supported; on memory a KVM guest
/// writes via EPT it depends on kernel/KVM support, and that gates the whole
/// running-BRANCH design. Register the live guest's RAM in write-protect mode, arm
/// protection, and confirm the guest's own writes raise a `WriteProtected` fault. Each
/// fault is resolved (protection removed + waiter woken) so the guest never stays
/// blocked, and all protection is lifted before teardown.
#[test]
#[ignore = "requires /dev/kvm and fixtures; FR-16 UFFD_WP feasibility probe"]
fn uffd_wp_on_live_guest_is_supported() {
    let cfg = fixture_config();
    cfg.validate().unwrap();
    let mut parent = Machine::boot(&cfg).expect("parent boots");
    assert!(
        parent
            .wait_for_ready(Duration::from_secs(10))
            .expect("readiness poll"),
        "parent reached userspace"
    );

    // A non-blocking UFFD that *requires* the WP feature: create() fails loudly on a
    // kernel without write-protect faults (feasibility = no, cleanly).
    //
    // user_mode_only(false) is essential, not incidental: a KVM guest's write to a
    // WP'd page faults out via EPT in *kernel* context (KVM's fault handler forwards
    // it to userfaultfd), so a UFFD_USER_MODE_ONLY uffd — the crate default — would
    // never deliver guest faults and the probe would falsely observe zero. A full
    // (non-user-mode-only) uffd needs privilege OR an accessible /dev/userfaultfd; the
    // CI job grants the latter, which is exactly the unprivileged path the device adds.
    let uffd = UffdBuilder::new()
        .require_features(FeatureFlags::PAGEFAULT_FLAG_WP)
        .user_mode_only(false)
        .non_blocking(true)
        .create()
        .expect("create UFFD with PAGEFAULT_FLAG_WP (needs kernel >= 5.7 + uffd perms)");

    // Register every guest RAM region for write faults and arm write-protection.
    let gm = parent.guest_memory().clone();
    let regions: Vec<(*mut std::ffi::c_void, usize)> = gm
        .iter()
        .map(|r| (r.as_ptr() as *mut std::ffi::c_void, r.len() as usize))
        .collect();
    for &(ptr, len) in &regions {
        uffd.register_with_mode(ptr, len, RegisterMode::WRITE_PROTECT)
            .expect("register guest RAM for write-protect faults");
        uffd.write_protect(ptr, len).expect("arm write-protection");
    }

    // The running guest writes RAM; poll (bounded) for the first WriteProtected fault and
    // resolve it so the guest proceeds. One fault proves UFFD_WP works on live KVM-guest
    // memory here. read_event() returns Ok(None) when nothing is ready (non-blocking).
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut wp_events = 0u64;
    while Instant::now() < deadline {
        match uffd.read_event() {
            Ok(Some(Event::Pagefault {
                kind: FaultKind::WriteProtected,
                addr,
                ..
            })) => {
                wp_events += 1;
                let page = (addr as usize) & !0xfff;
                let _ = uffd.remove_write_protection(page as *mut std::ffi::c_void, 0x1000, true);
                break; // one fault is enough to confirm feasibility
            }
            Ok(_) => {}
            Err(_) => break,
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // Lift all protection so no guest write is left blocked, then tear down.
    for &(ptr, len) in &regions {
        let _ = uffd.remove_write_protection(ptr, len, true);
    }
    drop(uffd);
    println!(
        "FR-16 UFFD_WP probe: observed {wp_events} write-protect fault(s) from the live guest"
    );
    parent.shutdown().expect("stop parent");

    assert!(
        wp_events > 0,
        "no UFFD_WP fault from the running guest's writes — UFFD_WP on live KVM-guest \
         memory appears unsupported on this kernel; the FR-16 BRANCH design is blocked \
         (fall back to the proven snapshot-based fork)"
    );
}

/// FR-16 resume-in-place (Phase 1a): the foundation the running BRANCH is built on —
/// `Machine::checkpoint_in_place` pauses the vCPUs at a quiescent barrier, captures
/// their state, and **resumes them**, leaving the parent running (unlike the freeze-only
/// snapshot pause). Proven end-to-end through the guest: write a marker over the parent's
/// vsock bridge BEFORE the checkpoint, then read it back AFTER. The read only succeeds if
/// the parent's vCPUs re-entered KVM_RUN and the guest kept executing (its exec agent is
/// still serving); a broken resume leaves the guest dead and the bounded exec timeout
/// fails the test fast instead of hanging.
#[test]
#[ignore = "requires /dev/kvm and fixtures; FR-16 resume-in-place"]
fn checkpoint_in_place_keeps_parent_running() {
    let cfg = fixture_config();
    cfg.validate().unwrap();
    let dir = scratch_dir("checkpoint-resume");

    // Boot the parent with its own host vsock bridge so the host can exec into it.
    let uds = dir.join("parent.sock");
    let listener = UnixListener::bind(&uds).expect("bind parent vsock bridge");
    let mut parent = Machine::boot_with_vsock(&cfg, Some(listener)).expect("parent boots bridged");
    assert!(
        parent
            .wait_for_ready(Duration::from_secs(10))
            .expect("readiness poll"),
        "parent reached userspace"
    );

    // Parent serves exec BEFORE the checkpoint: write a marker into its guest fs.
    let write_cmd: Vec<String> = ["/sbin/marker", "write", "RESUMED"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let w = run_exec_over_uds_ready(
        &uds,
        EXEC_PORT,
        1,
        &write_cmd,
        10_000,
        FORK_EXEC_READY_TIMEOUT,
    )
    .expect("pre-checkpoint exec");
    assert_eq!(
        w.exit_code,
        0,
        "pre-checkpoint marker write (stderr: {})",
        String::from_utf8_lossy(&w.stderr)
    );

    // Checkpoint the RUNNING parent: pause vCPUs at the barrier, capture, resume in place.
    let states = parent.checkpoint_in_place().expect("checkpoint in place");
    assert_eq!(
        states.len(),
        cfg.vcpus as usize,
        "captured one vcpu state per vcpu"
    );

    // The parent must STILL be running: read the marker back over the same bridge.
    let read_cmd: Vec<String> = ["/sbin/marker", "read"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let r = run_exec_over_uds_ready(
        &uds,
        EXEC_PORT,
        1,
        &read_cmd,
        10_000,
        FORK_EXEC_READY_TIMEOUT,
    )
    .expect("post-checkpoint exec");
    assert_eq!(r.exit_code, 0, "post-checkpoint marker read failed");
    assert_eq!(
        String::from_utf8_lossy(&r.stdout),
        "RESUMED",
        "parent kept running after the checkpoint and its guest state survived"
    );

    parent.shutdown().expect("stop parent");
    let _ = std::fs::remove_dir_all(&dir);
}

/// FR-16 full resume-in-place (Phase 1b.1): `Machine::checkpoint_full_in_place` captures
/// the WHOLE consistent guest state — vCPUs **and** device workers (block + vsock here)
/// plus VM clock and irqchip — at one quiescent barrier, and resumes it. This exercises
/// the device-worker half of the capture-and-continue barrier (the workers drain
/// in-flight DMA, capture their queue cursors, park, and resume), which the WP branch
/// engine relies on to quiesce DMA while it arms write-protection. Proven through the
/// guest: a marker written over the parent's vsock bridge before the full checkpoint is
/// readable after it — so the vsock + block workers parked and resumed correctly and the
/// parent kept serving.
#[test]
#[ignore = "requires /dev/kvm and fixtures; FR-16 full resume-in-place"]
fn full_checkpoint_keeps_parent_and_devices_running() {
    let cfg = fixture_config();
    cfg.validate().unwrap();
    let dir = scratch_dir("full-checkpoint");

    let uds = dir.join("parent.sock");
    let listener = UnixListener::bind(&uds).expect("bind parent vsock bridge");
    let mut parent = Machine::boot_with_vsock(&cfg, Some(listener)).expect("parent boots bridged");
    assert!(
        parent
            .wait_for_ready(Duration::from_secs(10))
            .expect("readiness poll"),
        "parent reached userspace"
    );

    let write_cmd: Vec<String> = ["/sbin/marker", "write", "FULLCKPT"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let w = run_exec_over_uds_ready(
        &uds,
        EXEC_PORT,
        1,
        &write_cmd,
        10_000,
        FORK_EXEC_READY_TIMEOUT,
    )
    .expect("pre-checkpoint exec");
    assert_eq!(
        w.exit_code,
        0,
        "pre-checkpoint marker write (stderr: {})",
        String::from_utf8_lossy(&w.stderr)
    );

    // Full checkpoint of the RUNNING guest: vCPUs + device workers + clock + irqchip,
    // captured at one barrier, then resumed in place.
    let state = parent
        .checkpoint_full_in_place()
        .expect("full checkpoint in place");
    assert_eq!(
        state.vcpus.len(),
        cfg.vcpus as usize,
        "captured one vcpu state per vcpu"
    );
    assert!(
        !state.devices.is_empty(),
        "captured the snapshottable device cursors (block + vsock)"
    );

    // The parent and its devices must still be running: read the marker back over the
    // same vsock bridge (the bridge is served by the vsock worker that just parked+resumed).
    let read_cmd: Vec<String> = ["/sbin/marker", "read"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let r = run_exec_over_uds_ready(
        &uds,
        EXEC_PORT,
        1,
        &read_cmd,
        10_000,
        FORK_EXEC_READY_TIMEOUT,
    )
    .expect("post-checkpoint exec");
    assert_eq!(r.exit_code, 0, "post-checkpoint marker read failed");
    assert_eq!(
        String::from_utf8_lossy(&r.stdout),
        "FULLCKPT",
        "parent + device workers kept running after the full checkpoint"
    );

    parent.shutdown().expect("stop parent");
    let _ = std::fs::remove_dir_all(&dir);
}

/// FR-16 running BRANCH end-to-end (Phase 1b): branch a **running** parent (no freeze
/// for a RAM dump), then fork a child off the branch and prove three things at once —
/// the parent keeps running through the branch (it serves exec and writes a new marker
/// afterward); the child is a coherent point-in-time (T) snapshot (it reads back the
/// marker that existed at branch time); and there is no bleed (the parent's post-branch
/// divergence is not visible to the child).
///
/// The write-protect preserve path is exercised by the running guest's background writes
/// during the branch window: the engine logs how many pages it preserved by write-fault,
/// but this test does not assert on that count (an idle guest may not write during a fast
/// copy, which would make such an assertion flaky). A deterministic concurrent-writer test
/// that guarantees faults and checks the child sees a coherent earlier-or-equal value is
/// the immediate follow-up increment.
#[test]
#[ignore = "requires /dev/kvm and fixtures; FR-16 running BRANCH"]
fn branch_of_running_parent_forks_independent_child() {
    let cfg = fixture_config();
    cfg.validate().unwrap();
    let dir = scratch_dir("branch-running");

    // Bridged parent so we can exec into it before AND after the branch.
    let puds = dir.join("parent.sock");
    let listener = UnixListener::bind(&puds).expect("bind parent vsock bridge");
    let mut parent = Machine::boot_with_vsock(&cfg, Some(listener)).expect("parent boots bridged");
    assert!(
        parent
            .wait_for_ready(Duration::from_secs(10))
            .expect("readiness poll"),
        "parent reached userspace"
    );

    let marker = |val: &str| -> Vec<String> {
        ["/sbin/marker", "write", val]
            .iter()
            .map(|s| s.to_string())
            .collect()
    };
    let read_cmd: Vec<String> = ["/sbin/marker", "read"]
        .iter()
        .map(|s| s.to_string())
        .collect();

    // Marker present at branch time T.
    let w = run_exec_over_uds_ready(
        &puds,
        EXEC_PORT,
        1,
        &marker("ATBRANCH"),
        10_000,
        FORK_EXEC_READY_TIMEOUT,
    )
    .expect("pre-branch exec");
    assert_eq!(
        w.exit_code,
        0,
        "pre-branch write (stderr: {})",
        String::from_utf8_lossy(&w.stderr)
    );

    // Branch the RUNNING parent into `dir` (brief pause; no full-dump freeze).
    let branch_dir = dir.join("branch");
    let manifest = parent
        .branch(&branch_dir)
        .expect("branch the running parent")
        .manifest;

    // (1) The parent kept running: write a NEW marker over the same bridge and read it.
    let w2 = run_exec_over_uds_ready(
        &puds,
        EXEC_PORT,
        1,
        &marker("POSTBRANCH"),
        10_000,
        FORK_EXEC_READY_TIMEOUT,
    )
    .expect("post-branch exec");
    assert_eq!(
        w2.exit_code,
        0,
        "post-branch write (stderr: {})",
        String::from_utf8_lossy(&w2.stderr)
    );
    let pr = run_exec_over_uds_ready(
        &puds,
        EXEC_PORT,
        1,
        &read_cmd,
        10_000,
        FORK_EXEC_READY_TIMEOUT,
    )
    .expect("parent read");
    assert_eq!(
        String::from_utf8_lossy(&pr.stdout),
        "POSTBRANCH",
        "the parent kept running and diverged after the branch"
    );

    // (2)+(3) Fork a child off the branch: it must see the T-version marker (ATBRANCH),
    // NOT the parent's post-branch divergence (POSTBRANCH).
    let state = load_state(&branch_dir, &manifest).expect("load branch state");
    let mem_path = branch_dir.join(&manifest.memory_file);
    let cuds = dir.join("child.sock");
    let mut child = fork_bridged_child(&cfg, &state, &mem_path, &cuds);
    let cr = exec_marker_on(&cuds, &read_cmd);
    assert_eq!(
        String::from_utf8_lossy(&cr.stdout),
        "ATBRANCH",
        "the child is the point-in-time branch snapshot — no bleed of the parent's later write"
    );

    child.shutdown().expect("stop child");
    parent.shutdown().expect("stop parent");
    let _ = std::fs::remove_dir_all(&dir);
}

/// FR-16 WP-branch fidelity repro (the clone-net e2e flaked intermittently: a
/// WP-branched clone kernel-panicked in the IRQ path). The brief one-shot branch test
/// above doesn't run a clone long enough to surface it; this branches the running parent
/// repeatedly and runs each clone under **sustained timer-interrupt activity** (a guest
/// sleep loop), asserting every clone stays alive. Catches the intermittency that a single
/// quick exec misses — a deterministic gate for the capture-fidelity fix.
#[test]
#[ignore = "requires /dev/kvm and fixtures; FR-16 WP-branch fidelity repro"]
fn branch_clone_survives_sustained_interrupt_activity() {
    let cfg = fixture_config();
    cfg.validate().unwrap();
    let dir = scratch_dir("branch-fidelity");
    let puds = dir.join("parent.sock");
    let listener = UnixListener::bind(&puds).expect("bind parent vsock bridge");
    let mut parent = Machine::boot_with_vsock(&cfg, Some(listener)).expect("parent boots");
    assert!(
        parent
            .wait_for_ready(Duration::from_secs(10))
            .expect("readiness poll"),
        "parent reached userspace"
    );
    // Branch right at readiness (no settle) — matching the clone-net flake's early-boot
    // branch point — and rely on the loop + repeated exec to surface the intermittency.

    const ITERATIONS: usize = 8;
    // Per clone: spawn many short guest processes (each `/sbin/marker` exec forks/execs/
    // exits in the guest), driving the scheduler + timer/IRQ path. If the branch captured
    // inconsistent interrupt/clock state, a clone crashes (its exec agent stops answering)
    // or returns wrong data under this load. `/sbin/marker` is the known-present fixture
    // binary (the guest rootfs has no /bin/sh).
    const EXECS_PER_CLONE: usize = 15;
    for i in 0..ITERATIONS {
        let branch_dir = dir.join(format!("branch-{i}"));
        let manifest = parent
            .branch(&branch_dir)
            .unwrap_or_else(|e| panic!("iteration {i}: branch the running parent: {e}"))
            .manifest;
        let state = load_state(&branch_dir, &manifest)
            .unwrap_or_else(|e| panic!("iteration {i}: load branch state: {e}"));
        let mem_path = branch_dir.join(&manifest.memory_file);
        let cuds = dir.join(format!("child-{i}.sock"));
        let mut child = fork_bridged_child(&cfg, &state, &mem_path, &cuds);

        for j in 0..EXECS_PER_CLONE {
            let val = format!("IT{i}E{j}");
            let w = exec_marker(&cuds, &["write", &val]);
            assert_eq!(
                w.exit_code,
                0,
                "iteration {i} exec {j}: marker write exited {} — clone likely panicked \
                 (Fatal exception in interrupt); stderr: {}",
                w.exit_code,
                String::from_utf8_lossy(&w.stderr)
            );
            let rd = exec_marker(&cuds, &["read"]);
            assert_eq!(
                rd.exit_code, 0,
                "iteration {i} exec {j}: marker read exited {}",
                rd.exit_code
            );
            assert_eq!(
                String::from_utf8_lossy(&rd.stdout).trim(),
                val,
                "iteration {i} exec {j}: clone returned wrong data under load (state corruption)",
            );
        }
        child
            .shutdown()
            .unwrap_or_else(|e| panic!("iteration {i}: stop child: {e}"));
    }

    parent.shutdown().expect("stop parent");
    let _ = std::fs::remove_dir_all(&dir);
}

/// CONTROL for [`branch_clone_survives_sustained_interrupt_activity`]. Identical exec
/// hammer (8 iterations × 15 sustained `/sbin/marker` execs per forked child), but the
/// children are forked from a **frozen snapshot** — the parent is paused-and-captured
/// then dropped, so there is no live parent and no UFFD_WP write-protection in play.
///
/// This isolates the one variable the WP-branch repro never controlled: is the crash
/// caused by write-protect branching, or by *any* CoW-forked child under sustained
/// post-resume exec load? If this control ALSO dies at exec 4, the bug is in
/// fork/resume generally and every WP-branch hypothesis is misdirected. If it survives
/// all 120 execs while the branch repro dies, WP-branch is confirmed as the culprit.
#[test]
#[ignore = "requires /dev/kvm and fixtures"]
fn fork_snapshot_survives_sustained_interrupt_activity() {
    let cfg = fixture_config();
    cfg.validate().unwrap();
    let dir = scratch_dir("fork-fidelity");

    // Freeze a warm parent into a snapshot, then drop it: the children below fork from
    // the frozen image, with no live parent and no write-protection.
    let mut parent = Machine::boot(&cfg).expect("parent boots");
    assert!(
        parent
            .wait_for_ready(Duration::from_secs(10))
            .expect("readiness poll"),
        "parent reached userspace"
    );
    let snap_dir = dir.join("snapshot");
    let manifest = snapshot(&mut parent, &snap_dir).expect("snapshot the warm parent");
    drop(parent);
    let state = load_state(&snap_dir, &manifest).expect("load snapshot state");
    let mem_path = snap_dir.join(&manifest.memory_file);

    const ITERATIONS: usize = 8;
    const EXECS_PER_CLONE: usize = 15;
    for i in 0..ITERATIONS {
        let cuds = dir.join(format!("child-{i}.sock"));
        let mut child = fork_bridged_child(&cfg, &state, &mem_path, &cuds);

        for j in 0..EXECS_PER_CLONE {
            let val = format!("IT{i}E{j}");
            let w = exec_marker(&cuds, &["write", &val]);
            assert_eq!(
                w.exit_code,
                0,
                "CONTROL iteration {i} exec {j}: marker write exited {} — snapshot-forked \
                 clone crashed (no WP-branch involved); stderr: {}",
                w.exit_code,
                String::from_utf8_lossy(&w.stderr)
            );
            let rd = exec_marker(&cuds, &["read"]);
            assert_eq!(
                rd.exit_code, 0,
                "CONTROL iteration {i} exec {j}: marker read exited {}",
                rd.exit_code
            );
            assert_eq!(
                String::from_utf8_lossy(&rd.stdout).trim(),
                val,
                "CONTROL iteration {i} exec {j}: snapshot-forked clone returned wrong data",
            );
        }
        child
            .shutdown()
            .unwrap_or_else(|e| panic!("CONTROL iteration {i}: stop child: {e}"));
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// BASELINE control for the two sustained-exec hammers above. A freshly-booted guest —
/// no snapshot, no fork, no resume of any kind — runs the *identical* 8×15 `/sbin/marker`
/// hammer directly over its own vsock bridge. This is the one variable neither hammer
/// controlled: do sustained execs destabilize *any* guest (an exec-agent / vsock leak),
/// or only a CoW-forked/resumed one? FAILS here -> the root cause is the exec agent /
/// vsock under sustained load (fork and snapshot are red herrings); SURVIVES -> the
/// destabilization is specific to fork/resume and the agent itself is fine.
///
/// All execs target the same long-lived guest (a real client opens a fresh connection per
/// exec), so it exercises exactly the per-exec accumulation the forked hammers hit.
#[test]
#[ignore = "requires /dev/kvm and fixtures"]
fn booted_guest_survives_sustained_execs() {
    let cfg = fixture_config();
    cfg.validate().unwrap();
    let dir = scratch_dir("booted-hammer");
    let puds = dir.join("parent.sock");
    let listener = UnixListener::bind(&puds).expect("bind parent vsock bridge");
    let mut guest = Machine::boot_with_vsock(&cfg, Some(listener)).expect("guest boots");
    assert!(
        guest
            .wait_for_ready(Duration::from_secs(10))
            .expect("readiness poll"),
        "guest reached userspace"
    );

    // Same shape as the forked hammers: 8 "iterations" × 15 write/read exec pairs, but all
    // against this one never-forked guest.
    const ITERATIONS: usize = 8;
    const EXECS_PER_ITER: usize = 15;
    for i in 0..ITERATIONS {
        for j in 0..EXECS_PER_ITER {
            let val = format!("IT{i}E{j}");
            let w = exec_marker(&puds, &["write", &val]);
            assert_eq!(
                w.exit_code,
                0,
                "BASELINE iteration {i} exec {j}: marker write exited {} on a freshly-booted \
                 (never-forked) guest — exec-agent/vsock bug, not fork; stderr: {}",
                w.exit_code,
                String::from_utf8_lossy(&w.stderr)
            );
            let rd = exec_marker(&puds, &["read"]);
            assert_eq!(
                rd.exit_code, 0,
                "BASELINE iteration {i} exec {j}: marker read exited {}",
                rd.exit_code
            );
            assert_eq!(
                String::from_utf8_lossy(&rd.stdout).trim(),
                val,
                "BASELINE iteration {i} exec {j}: booted guest returned wrong data",
            );
        }
    }

    guest.shutdown().expect("stop guest");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Run an exec `cmd` over a child's vsock bridge at `uds` with the fork readiness retry,
/// returning the result (the generic form of [`exec_marker`]).
fn exec_marker_on(uds: &Path, cmd: &[String]) -> ExecResult {
    run_exec_over_uds_ready(uds, EXEC_PORT, 1, cmd, 10_000, FORK_EXEC_READY_TIMEOUT)
        .unwrap_or_else(|e| panic!("exec {cmd:?} over {uds:?}: {e}"))
}
