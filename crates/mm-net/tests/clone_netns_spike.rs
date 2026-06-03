//! fd/setns spike (SPEC-1 FR-16 clone networking, Step 0 gate): prove the load-bearing
//! assumption the per-clone netns design rests on — a TAP opened *inside* a network
//! namespace yields an fd that is valid and usable from the **root** netns (and from a
//! different thread, standing in for the jailed worker that never enters the netns).
//!
//! If this does not hold, the whole netns-per-clone topology needs rethinking, so it is
//! the first thing proven in CI before the veth/NAT/integration build.
//!
//! Requires root + `iproute2` (`ip`) + `/dev/net/tun`; `#[ignore]`d otherwise and run by
//! the `clone-net-spike` CI job.
#![cfg(target_os = "linux")]

use std::process::Command;

use mm_net::open_tun_in_netns;

fn am_root() -> bool {
    // No libc in the test crate; ask `id -u`.
    Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

fn ip(args: &[&str]) -> std::process::Output {
    Command::new("ip").args(args).output().expect("spawn `ip`")
}

#[test]
#[ignore = "requires root + ip + /dev/net/tun (clone-net-spike CI job)"]
fn tap_opened_in_netns_is_isolated_there_and_its_fd_is_usable_from_root() {
    if !am_root() {
        eprintln!("not root — skipping clone-net fd/setns spike (runs in the CI job)");
        return;
    }
    let ns = "mm-spike-ns";
    let tap = "mmspike0";

    // Idempotent pre-clean, then a fresh netns.
    let _ = ip(&["netns", "del", ns]);
    assert!(
        ip(&["netns", "add", ns]).status.success(),
        "ip netns add {ns}"
    );

    // The whole point: open the TAP *inside* the clone netns from this (root-netns)
    // process, via a throwaway setns thread. The returned fd must come back live.
    let file = open_tun_in_netns(ns, tap).expect("open TAP inside the clone netns");

    // (1) The device exists INSIDE the netns (proves the TAP landed in the right place;
    //     the fd is still held, so a non-persistent TAP is alive).
    let in_ns = ip(&["-n", ns, "link", "show", tap]);
    assert!(
        in_ns.status.success(),
        "TAP {tap} must exist inside netns {ns}: {}",
        String::from_utf8_lossy(&in_ns.stderr)
    );

    // (2) ...and NOT in the root netns (proves L2 isolation — the clone can keep the
    //     source's baked-in IP without colliding on the shared bridge).
    let in_root = ip(&["link", "show", tap]);
    assert!(
        !in_root.status.success(),
        "TAP {tap} must NOT be visible in the root netns (it belongs to {ns})"
    );

    // (3) The fd is valid + usable from a *different thread* — the worker model: the
    //     jailed worker (another execution context) read/writes this fd without ever
    //     entering the netns. `metadata()` is a real syscall on the fd; EBADF would fail.
    let usable = std::thread::spawn(move || file.metadata().is_ok())
        .join()
        .expect("fd-check thread");
    assert!(
        usable,
        "TAP fd opened in the netns must stay valid + usable from another thread"
    );

    // Teardown: deleting the netns removes the TAP + the in-netns veth/rules.
    let _ = ip(&["netns", "del", ns]);
}
