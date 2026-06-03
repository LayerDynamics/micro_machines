//! End-to-end: `mm branch` per-clone networking (SPEC-1 FR-16). Boots a source microVM,
//! branches a **live** clone, and proves the clone is reachable at a unique host-routable
//! `clone_ip` (its captured internal IP NAT'd through its own network namespace) while the
//! source stays reachable at its own IP — no L2 collision — and that `mm rm` of the clone
//! leaves no netns/veth residue.
//!
//! Requires /dev/kvm, root, skopeo + umoci, network, the kernel + musl mm-init fixtures,
//! and host `ip_forward` — all provided by the CI `clone-net-integration` job. `#[ignore]`d.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const TOKEN: &str = "MM_CLONE_OK_9b1d3e";
const IMAGE: &str = "docker.io/library/busybox:latest";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize repo root")
}

fn am_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

/// Scan an `mm run`/`mm branch` "<name>\t<ip>" line out of stdout (tracing logs also go
/// to stdout and may precede it).
fn scan_ip(stdout: &str, name: &str) -> Option<String> {
    stdout
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{name}\t")))
        .map(|ip| ip.trim().to_string())
}

#[test]
#[ignore = "requires /dev/kvm, root, skopeo/umoci, network, fixtures, ip_forward"]
fn mm_branch_clone_is_reachable_at_a_unique_ip_without_colliding_with_the_source() {
    if !am_root() {
        eprintln!("not root — skipping clone-net e2e (runs in the CI job)");
        return;
    }
    let root = repo_root();
    let kernel = root.join("crates/mm-vmm/tests/fixtures/vmlinux");
    let mm_init = root.join("target/x86_64-unknown-linux-musl/release/mm-init");
    for (what, p) in [("kernel", &kernel), ("mm-init", &mm_init)] {
        assert!(p.exists(), "missing {what} fixture {}", p.display());
    }

    let state = std::env::temp_dir().join(format!("mm-clonenet-{}", std::process::id()));
    std::fs::create_dir_all(&state).expect("create state root");
    let mm_bin = env!("CARGO_BIN_EXE_mm");
    let src = "cn-src";
    let clone = "cn-clone";

    let mm = |args: &[&str]| {
        let mut c = Command::new(mm_bin);
        c.args(args)
            .env("MM_ROOT", &state)
            .env("MM_KERNEL", &kernel)
            .env("MM_INIT", &mm_init);
        c
    };
    let wait_exec = |name: &str, secs: u64| -> bool {
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
    };
    let ping = |ip: &str| -> bool {
        // Retry: the guest's net stack + the NAT path settle a beat after boot.
        for _ in 0..10 {
            let ok = Command::new("ping")
                .args(["-c", "1", "-W", "2", ip])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if ok {
                return true;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        false
    };

    // 1. Boot the source and wait until its exec agent answers. This test gates the
    //    per-clone NETWORKING (#2) on the *reliable* clone path — a resume-in-place
    //    snapshot clone (`mm branch` of a non-branchable source). The write-protect branch
    //    path (`mm run --branchable`) has a separate, intermittent guest-fidelity issue
    //    (a clone can kernel-panic in the IRQ path) tracked in the FR-16 follow-ups; gating
    //    networking on it would make this e2e flaky, so it is deliberately not exercised
    //    here. (`mm branch` of a non-branchable source falls back to snapshot-in-place.)
    let launch = mm(&["run", "--ssh", "--detach", "--name", src, IMAGE])
        .output()
        .expect("spawn `mm run`");
    assert!(
        launch.status.success(),
        "`mm run` failed: {}\n{}",
        String::from_utf8_lossy(&launch.stdout),
        String::from_utf8_lossy(&launch.stderr),
    );
    let src_ip = scan_ip(&String::from_utf8_lossy(&launch.stdout), src)
        .expect("mm run printed the source IP");
    assert!(wait_exec(src, 90), "source never became exec-ready");

    // 2. Branch a live clone; capture its (distinct, host-routable) clone_ip.
    let branch = mm(&["branch", src, clone]).output().expect("mm branch");
    assert!(
        branch.status.success(),
        "`mm branch` failed: {}\n{}",
        String::from_utf8_lossy(&branch.stdout),
        String::from_utf8_lossy(&branch.stderr),
    );
    let clone_ip = scan_ip(&String::from_utf8_lossy(&branch.stdout), clone)
        .expect("mm branch printed the clone IP");
    assert_ne!(
        clone_ip, src_ip,
        "the clone must get a unique IP, not the source's"
    );

    // 3. Both are independently alive over their own vsock bridges (the source kept
    //    running through the branch; the clone is a live copy).
    let clone_exec = wait_exec(clone, 90);
    let src_still = wait_exec(src, 30);

    // 4. The whole point: the clone is reachable at its clone_ip from the host, AND the
    //    source is still reachable at its own IP — no collision.
    let clone_reachable = ping(&clone_ip);
    let src_reachable = ping(&src_ip);

    // Diagnostics before assertions so a failure self-explains.
    if !clone_exec || !src_still || !clone_reachable || !src_reachable {
        for who in [clone, src] {
            let console = state.join(format!("jails/{who}/console.log"));
            if let Ok(log) = std::fs::read_to_string(&console) {
                eprintln!("--- {who} console ---\n{log}\n--- end ---");
            }
        }
        eprintln!("--- ip netns ---");
        let _ = Command::new("ip").args(["netns", "list"]).status();
    }

    assert!(clone_exec, "clone never became exec-ready");
    assert!(src_still, "source stopped serving exec after the branch");
    assert!(
        clone_reachable,
        "clone not reachable at its clone_ip {clone_ip} (per-clone netns NAT broken)"
    );
    assert!(
        src_reachable,
        "source not reachable at {src_ip} after the clone came up (collision/regression)"
    );

    // 5. Teardown leaves no residue: removing the clone deletes its netns + host veth.
    let _ = mm(&["stop", clone]).output();
    let rm = mm(&["rm", "--force", clone]).output().expect("mm rm clone");
    assert!(
        rm.status.success(),
        "`mm rm` failed: {}",
        String::from_utf8_lossy(&rm.stderr)
    );
    let netns_list = Command::new("ip")
        .args(["netns", "list"])
        .output()
        .expect("ip netns list");
    let listed = String::from_utf8_lossy(&netns_list.stdout);
    assert!(
        !listed.contains(&format!("mm-clone-{clone}")),
        "clone netns must be gone after `mm rm`; still listed:\n{listed}"
    );
    // The first clone gets veth slot 0 → host end `mmvh0`.
    let veth = Command::new("ip").args(["link", "show", "mmvh0"]).output();
    assert!(
        veth.map(|o| !o.status.success()).unwrap_or(true),
        "host veth mmvh0 must be gone after `mm rm`"
    );

    // Cleanup the source.
    let _ = mm(&["stop", src]).output();
    let _ = std::fs::remove_dir_all(&state);
}
