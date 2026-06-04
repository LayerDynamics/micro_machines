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

/// On a networking failure, dump the full host + clone-netns state so the failure pinpoints
/// host-side (netns/veth/NAT/route) vs guest-side (the clone's NIC never came up): an
/// in-netns `ping clone_ip` that succeeds while the host ping fails isolates it to the host
/// route/NAT; an in-netns ping that also fails points at the guest NIC.
fn dump_net_diag(state: &Path, clone: &str, clone_ip: &str) {
    let console = state.join(format!("jails/{clone}/console.log"));
    if let Ok(log) = std::fs::read_to_string(&console) {
        eprintln!("--- {clone} console ---\n{log}\n--- end ---");
    }
    let netns = format!("mm-clone-{clone}");
    let diag = |label: &str, prog: &str, args: &[&str]| match Command::new(prog).args(args).output()
    {
        Ok(o) => eprintln!(
            "--- {label} ---\n{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => eprintln!("--- {label} --- (failed to run: {e})"),
    };
    diag("ip netns list", "ip", &["netns", "list"]);
    diag("host: ip addr", "ip", &["-br", "addr"]);
    diag("host: route to clone_ip", "ip", &["route", "get", clone_ip]);
    diag("host: nat table", "iptables", &["-t", "nat", "-S"]);
    diag(
        "netns: ip addr",
        "ip",
        &["netns", "exec", &netns, "ip", "-br", "addr"],
    );
    diag(
        "netns: ip route",
        "ip",
        &["netns", "exec", &netns, "ip", "route"],
    );
    diag(
        "netns: nat table",
        "ip",
        &["netns", "exec", &netns, "iptables", "-t", "nat", "-S"],
    );
    diag(
        "netns: ping clone_ip",
        "ip",
        &[
            "netns", "exec", &netns, "ping", "-c", "1", "-W", "2", clone_ip,
        ],
    );
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

    // 1. Boot the source `--branchable` and wait until its exec agent answers. This
    //    exercises the real near-zero-pause write-protect branch path through the full
    //    jail/netns CLI — `mm branch` of a `--branchable` source uses the WP engine (not
    //    the resume-in-place snapshot fallback). That path previously had two now-fixed
    //    bugs: a clone kernel-panic in the IRQ/softirq path (missing FS/GS-base MSRs in the
    //    snapshot, b39886a) and an `exit -1` after sustained execs (a PID-1 reaper race in
    //    mm-init, fc36487/f6f14ca). Gating the per-clone NETWORKING (#2) on this path
    //    confirms both on the exact jailed path where the panic was first observed.
    let launch = mm(&[
        "run",
        "--ssh",
        "--branchable",
        "--detach",
        "--name",
        src,
        IMAGE,
    ])
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

    // 2. Loop the full live-branch cycle several times. The WP-branch clone networking was
    //    INTERMITTENTLY failing (the clone came up exec-able over vsock but unreachable at
    //    its NAT'd clone_ip) — a single branch is far too weak a gate for an intermittent
    //    bug, so branch → exec → ping → sustained-exec → teardown repeatedly and require
    //    EVERY round to pass. Each round tears the clone down (freeing veth slot 0 + its
    //    netns) so the next round starts clean and residue leaks surface immediately.
    const ROUNDS: usize = 6;
    for round in 0..ROUNDS {
        let clone = format!("cn-clone-{round}");

        // Branch a live clone; capture its (distinct, host-routable) clone_ip.
        let branch = mm(&["branch", src, &clone]).output().expect("mm branch");
        assert!(
            branch.status.success(),
            "round {round}: `mm branch` failed: {}\n{}",
            String::from_utf8_lossy(&branch.stdout),
            String::from_utf8_lossy(&branch.stderr),
        );
        let clone_ip = scan_ip(&String::from_utf8_lossy(&branch.stdout), &clone)
            .unwrap_or_else(|| panic!("round {round}: mm branch printed no clone IP"));
        assert_ne!(
            clone_ip, src_ip,
            "round {round}: the clone must get a unique IP, not the source's"
        );

        // The clone is alive over its own vsock bridge AND reachable at its clone_ip from
        // the host (the per-clone netns NAT). Dump the full network state on any failure.
        let clone_exec = wait_exec(&clone, 90);
        let clone_reachable = clone_exec && ping(&clone_ip);
        if !clone_exec || !clone_reachable {
            dump_net_diag(&state, &clone, &clone_ip);
        }
        assert!(clone_exec, "round {round}: clone never became exec-ready");
        assert!(
            clone_reachable,
            "round {round}: clone not reachable at its clone_ip {clone_ip} \
             (per-clone netns NAT broken)"
        );

        // Sustained-exec hammer on the live WP-branch clone — the exact load that surfaced
        // the PID-1 reaper race (`exit -1`) on the jailed exec path. Each must exit 0 AND
        // echo its value: the race corrupted the EXIT CODE (Exit{-1} when PID 1 stole the
        // child) even though stdout still streamed, so asserting `status.success()` — not
        // just the token — is what catches a regression.
        for i in 0..15 {
            let val = format!("R{round}E{i}");
            let out = mm(&["exec", &clone, "--", "echo", &val])
                .output()
                .expect("run `mm exec` on the clone");
            assert!(
                out.status.success() && String::from_utf8_lossy(&out.stdout).contains(&val),
                "round {round} exec #{i} failed (reaper-race regression?): status={:?}\n\
                 stdout={}\nstderr={}",
                out.status.code(),
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
            );
        }

        // The source kept running through the branch.
        assert!(
            wait_exec(src, 30),
            "round {round}: source stopped serving exec after the branch"
        );

        // Teardown leaves no residue: removing the clone deletes its netns + host veth.
        let _ = mm(&["stop", &clone]).output();
        let rm = mm(&["rm", "--force", &clone])
            .output()
            .expect("mm rm clone");
        assert!(
            rm.status.success(),
            "round {round}: `mm rm` failed: {}",
            String::from_utf8_lossy(&rm.stderr)
        );
        let netns_list = Command::new("ip")
            .args(["netns", "list"])
            .output()
            .expect("ip netns list");
        let listed = String::from_utf8_lossy(&netns_list.stdout);
        assert!(
            !listed.contains(&format!("mm-clone-{clone}")),
            "round {round}: clone netns must be gone after `mm rm`; still listed:\n{listed}"
        );
        // Each round's clone takes the smallest free veth slot — 0 once the prior round was
        // torn down → host end `mmvh0`; it must be gone after `mm rm`.
        let veth = Command::new("ip").args(["link", "show", "mmvh0"]).output();
        assert!(
            veth.map(|o| !o.status.success()).unwrap_or(true),
            "round {round}: host veth mmvh0 must be gone after `mm rm`"
        );
    }

    // 3. After all the branch/teardown churn, the source is still reachable at its own IP
    //    (no collision or leaked NAT left it stranded).
    assert!(
        ping(&src_ip),
        "source not reachable at {src_ip} after {ROUNDS} branch cycles (collision/regression)"
    );

    // Cleanup the source.
    let _ = mm(&["stop", src]).output();
    let _ = std::fs::remove_dir_all(&state);
}
