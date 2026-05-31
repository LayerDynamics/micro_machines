//! End-to-end: `mm ssh` reaches a guest over a real SSH session (SPEC-1 FR-12,
//! "automatic internal SSH access"). Boots a microVM from a real OCI image with an
//! injected static sshd, then runs a command in the guest via the `mm ssh` CLI and
//! checks the output comes back — proving key auth (the managed key), guest
//! reachability over the bridge, and the in-guest sshd all work with zero per-image
//! setup.
//!
//! Requires /dev/kvm, root, skopeo + umoci, the OpenSSH client, network access to
//! pull the image, and the kernel + musl mm-init + static dropbear fixtures. The CI
//! `ssh-integration` job provides all of it. `#[ignore]`d otherwise.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// A unique token we echo through the SSH session and look for in the output.
const TOKEN: &str = "MM_SSH_OK_4f3a9c";
const IMAGE: &str = "docker.io/library/busybox:latest";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize repo root")
}

#[test]
#[ignore = "requires /dev/kvm, root, skopeo/umoci, ssh client, network, fixtures"]
fn mm_ssh_reaches_the_guest() {
    let root = repo_root();
    let kernel = root.join("crates/mm-vmm/tests/fixtures/vmlinux");
    let mm_init = root.join("target/x86_64-unknown-linux-musl/release/mm-init");
    let sshd = root.join("crates/mm-vmm/tests/fixtures/dropbear");
    for (what, p) in [
        ("kernel", &kernel),
        ("mm-init", &mm_init),
        ("dropbear", &sshd),
    ] {
        assert!(p.exists(), "missing {what} fixture {} ", p.display());
    }

    let state = std::env::temp_dir().join(format!("mm-ssh-test-{}", std::process::id()));
    std::fs::create_dir_all(&state).expect("create state root");
    let mm_bin = env!("CARGO_BIN_EXE_mm");

    // Helper: an `mm` invocation with the fixtures + sandbox state wired in.
    let mm = |args: &[&str]| {
        let mut c = Command::new(mm_bin);
        c.args(args)
            .env("MM_ROOT", &state)
            .env("MM_KERNEL", &kernel)
            .env("MM_INIT", &mm_init)
            .env("MM_SSHD", &sshd);
        c
    };

    // Boot an SSH-reachable sandbox VM in the background (sandbox keeps PID 1 alive,
    // so the guest stays up for us to connect).
    let launch = mm(&["run", "--ssh", "--detach", "--name", "ssh-test", IMAGE])
        .output()
        .expect("spawn `mm run`");
    assert!(
        launch.status.success(),
        "`mm run --ssh --detach` failed: {}\n{}",
        String::from_utf8_lossy(&launch.stdout),
        String::from_utf8_lossy(&launch.stderr),
    );

    // DIAG(ssh-netns): the jailed worker enters a new netns; the host tap/bridge
    // came up DOWN. Force them up and capture carrier state to tell "admin-down"
    // (re-up fixes it) from "queue detached by the worker's netns" (carrier stays
    // off even after `up`).
    std::thread::sleep(Duration::from_secs(8));
    let probe = Command::new("sh")
        .args([
            "-c",
            "ip link set mm-ssh-test up; ip link set mm-br0 up; \
             echo '== after force-up =='; ip -d link show mm-ssh-test; ip -br addr",
        ])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    eprintln!("netns probe:\n{probe}");

    // Poll `mm ssh` until the guest has booted and dropbear is serving (host-key
    // generation on first connect can take a moment).
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut last = String::new();
    let mut reached = false;
    while Instant::now() < deadline {
        let out = mm(&["ssh", "ssh-test", "--", "echo", TOKEN])
            .output()
            .expect("run `mm ssh`");
        let stdout = String::from_utf8_lossy(&out.stdout);
        if stdout.contains(TOKEN) {
            reached = true;
            break;
        }
        last = format!(
            "status={:?}\nstdout={stdout}\nstderr={}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
        std::thread::sleep(Duration::from_secs(2));
    }

    // On failure, gather diagnostics (host net state + the guest boot console)
    // before tearing down, so the failure is self-explaining.
    let mut diag = String::new();
    if !reached {
        let sh = |c: &str| {
            String::from_utf8_lossy(
                &Command::new("sh")
                    .args(["-c", c])
                    .output()
                    .map(|o| o.stdout)
                    .unwrap_or_default(),
            )
            .into_owned()
        };
        diag.push_str(&format!("\n--- ip addr ---\n{}", sh("ip -br addr")));
        diag.push_str(&format!("--- ip route ---\n{}", sh("ip route")));
        let console = state.join("jails/ssh-test/console.log");
        let log =
            std::fs::read_to_string(&console).unwrap_or_else(|e| format!("(no console.log: {e})"));
        diag.push_str(&format!(
            "--- guest console ({}) ---\n{log}\n--- end ---\n",
            console.display()
        ));
    }

    // Tear down regardless of outcome.
    let _ = mm(&["stop", "ssh-test"]).output();
    let _ = std::fs::remove_dir_all(&state);

    assert!(
        reached,
        "`mm ssh` never returned the token from the guest.\nlast attempt:\n{last}\n{diag}"
    );
}
