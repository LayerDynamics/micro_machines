//! End-to-end: the `mm snapshot`/`mm restore` user surface over the worker control
//! channel (SPEC-1 FR-14). Boots a real sandbox microVM, snapshots the **live** guest
//! via `mm snapshot create` (the worker control.sock), lists it, then restores it into a
//! fresh machine with `mm restore` and proves the restored guest is alive over its own
//! vsock bridge (`mm exec`) — and came back with the network device + IP captured in
//! its RAM (the restore-with-a-net-device path that no prior snapshot test exercised,
//! since they all used an empty device set).
//!
//! The source is stopped before restore so the restored guest's captured IP does not
//! collide on the bridge (re-IP-per-clone for *live* clones is the `mm branch` netns
//! milestone; restore here is the stopped-source path).
//!
//! Requires /dev/kvm, root, skopeo + umoci, network access, and the kernel + musl
//! mm-init fixtures — all provided by the CI snapshot-cli-integration job. `#[ignore]`d.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const TOKEN: &str = "MM_SNAP_OK_4f7a2c";
const IMAGE: &str = "docker.io/library/busybox:latest";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize repo root")
}

/// Poll `mm exec <name> -- echo TOKEN` until the guest's exec agent answers, or time out.
fn wait_exec_ready(mm: &dyn Fn(&[&str]) -> Command, name: &str, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        let out = mm(&["exec", name, "--", "echo", TOKEN])
            .output()
            .expect("run `mm exec`");
        if String::from_utf8_lossy(&out.stdout).contains(TOKEN) {
            return true;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    false
}

#[test]
#[ignore = "requires /dev/kvm, root, skopeo/umoci, network, fixtures"]
fn mm_snapshot_then_restore_round_trips_a_live_guest() {
    let root = repo_root();
    let kernel = root.join("crates/mm-vmm/tests/fixtures/vmlinux");
    let mm_init = root.join("target/x86_64-unknown-linux-musl/release/mm-init");
    for (what, p) in [("kernel", &kernel), ("mm-init", &mm_init)] {
        assert!(p.exists(), "missing {what} fixture {}", p.display());
    }

    let state = std::env::temp_dir().join(format!("mm-snap-test-{}", std::process::id()));
    std::fs::create_dir_all(&state).expect("create state root");
    let mm_bin = env!("CARGO_BIN_EXE_mm");
    let src = "snap-src";
    let clone = "snap-clone";

    let mm = |args: &[&str]| {
        let mut c = Command::new(mm_bin);
        c.args(args)
            .env("MM_ROOT", &state)
            .env("MM_KERNEL", &kernel)
            .env("MM_INIT", &mm_init);
        c
    };

    // 1. Boot a sandbox source VM (detached so it stays up) and capture its guest IP
    //    from `mm run`'s "<name>\t<ip>" line.
    let launch = mm(&["run", "--ssh", "--detach", "--name", src, IMAGE])
        .output()
        .expect("spawn `mm run`");
    assert!(
        launch.status.success(),
        "`mm run` failed: {}\n{}",
        String::from_utf8_lossy(&launch.stdout),
        String::from_utf8_lossy(&launch.stderr),
    );
    let src_ip = String::from_utf8_lossy(&launch.stdout)
        .lines()
        .next()
        .and_then(|l| l.split('\t').nth(1).map(str::to_owned))
        .expect("mm run printed <name>\\t<ip>");

    assert!(
        wait_exec_ready(&mm, src, 90),
        "source guest never became exec-ready"
    );

    // 2. Snapshot the LIVE source over the control channel; capture the printed id.
    let snap = mm(&["snapshot", "create", src])
        .output()
        .expect("mm snapshot create");
    let snap_out = String::from_utf8_lossy(&snap.stdout);
    let snap_err = String::from_utf8_lossy(&snap.stderr);
    assert!(
        snap.status.success(),
        "`mm snapshot create` failed: {snap_out}\n{snap_err}"
    );
    let id = snap_out
        .lines()
        .next()
        .expect("snapshot id on stdout")
        .trim()
        .to_string();
    assert!(!id.is_empty(), "empty snapshot id");

    // 3. `mm snapshot ls` shows it.
    let ls = mm(&["snapshot", "ls", src])
        .output()
        .expect("mm snapshot ls");
    assert!(
        String::from_utf8_lossy(&ls.stdout).contains(&id),
        "`mm snapshot ls` did not list {id}: {}",
        String::from_utf8_lossy(&ls.stdout)
    );

    // 4. Stop the source so its captured IP is free, then restore into a fresh machine.
    let _ = mm(&["stop", src]).output();
    let restore = mm(&["restore", src, &id, clone])
        .output()
        .expect("mm restore");
    assert!(
        restore.status.success(),
        "`mm restore` failed: {}\n{}",
        String::from_utf8_lossy(&restore.stdout),
        String::from_utf8_lossy(&restore.stderr),
    );

    // 5. The restored guest is alive over its own vsock bridge.
    let clone_ready = wait_exec_ready(&mm, clone, 90);

    // 6. ...and came back with the net device + the IP captured in its RAM (proving the
    //    restore-with-a-net-device + captured-network-state path).
    let mut ip_ok = false;
    let mut ip_diag = String::new();
    if clone_ready {
        let out = mm(&["exec", clone, "--", "ip", "addr", "show", "eth0"])
            .output()
            .expect("run `mm exec ip addr`");
        let stdout = String::from_utf8_lossy(&out.stdout);
        ip_ok = stdout.contains(&src_ip);
        ip_diag = format!("want {src_ip} in eth0; got:\n{stdout}");
    }

    // Diagnostics before teardown so a failure self-explains.
    let mut diag = String::new();
    if !clone_ready || !ip_ok {
        let console = state.join(format!("jails/{clone}/console.log"));
        let log =
            std::fs::read_to_string(&console).unwrap_or_else(|e| format!("(no console.log: {e})"));
        diag = format!(
            "--- restored guest console ({}) ---\n{log}\n--- end ---\n",
            console.display()
        );
    }

    let _ = mm(&["stop", clone]).output();
    let _ = std::fs::remove_dir_all(&state);

    assert!(
        clone_ready,
        "restored guest never became exec-ready (restore broke?).\n{diag}"
    );
    assert!(
        ip_ok,
        "restored guest did not come back with its captured IP.\n{ip_diag}\n{diag}"
    );
}
