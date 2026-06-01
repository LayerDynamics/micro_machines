//! End-to-end: `mm exec` runs a command inside a real sandbox guest over the full
//! host<->guest virtio-vsock bridge (SPEC-1 FR-13). Boots a microVM from a real OCI
//! image in sandbox mode (so the in-guest exec agent is listening on vsock port
//! 1025), then drives the `mm exec` CLI to run commands in the guest and checks the
//! output comes back — proving the vsock muxer device, the credit flow control, the
//! jail-crossing UDS bridge, the CONNECT/OK handshake, and the guest exec agent all
//! work together with zero per-image setup.
//!
//! Crucially it runs a **large-output** command (`seq 1 100000`, ~0.5 MiB) and
//! verifies every line arrives intact. A trivial `echo` fits the initial vsock
//! credit window and would pass even if flow control were broken; the large stream is
//! what actually exercises CREDIT_UPDATE / backpressure end to end.
//!
//! Requires /dev/kvm, root, skopeo + umoci, network access to pull the image, and the
//! kernel + musl mm-init fixtures. The CI KVM integration job provides all of it.
//! `#[ignore]`d otherwise.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const TOKEN: &str = "MM_EXEC_OK_9b21d7";
const IMAGE: &str = "docker.io/library/busybox:latest";
/// Number of lines `seq` emits — large enough to span many vsock credit windows.
const SEQ_N: usize = 100_000;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize repo root")
}

#[test]
#[ignore = "requires /dev/kvm, root, skopeo/umoci, network, fixtures"]
fn mm_exec_runs_commands_in_the_guest() {
    let root = repo_root();
    let kernel = root.join("crates/mm-vmm/tests/fixtures/vmlinux");
    let mm_init = root.join("target/x86_64-unknown-linux-musl/release/mm-init");
    for (what, p) in [("kernel", &kernel), ("mm-init", &mm_init)] {
        assert!(p.exists(), "missing {what} fixture {}", p.display());
    }

    let state = std::env::temp_dir().join(format!("mm-exec-test-{}", std::process::id()));
    std::fs::create_dir_all(&state).expect("create state root");
    let mm_bin = env!("CARGO_BIN_EXE_mm");
    let name = "exec-test";

    let mm = |args: &[&str]| {
        let mut c = Command::new(mm_bin);
        c.args(args)
            .env("MM_ROOT", &state)
            .env("MM_KERNEL", &kernel)
            .env("MM_INIT", &mm_init);
        c
    };

    // Boot a sandbox VM (no workload -> mm.mode=sandbox -> the exec agent runs and
    // PID 1 stays alive). Detached so the guest stays up while we exec into it.
    let launch = mm(&["run", "--ssh", "--detach", "--name", name, IMAGE])
        .output()
        .expect("spawn `mm run`");
    assert!(
        launch.status.success(),
        "`mm run --ssh --detach` failed: {}\n{}",
        String::from_utf8_lossy(&launch.stdout),
        String::from_utf8_lossy(&launch.stderr),
    );

    // Poll a trivial exec until the guest has booted and the exec agent is serving.
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut ready = false;
    let mut last = String::new();
    while Instant::now() < deadline {
        let out = mm(&["exec", name, "--", "echo", TOKEN])
            .output()
            .expect("run `mm exec`");
        if String::from_utf8_lossy(&out.stdout).contains(TOKEN) {
            ready = true;
            break;
        }
        last = format!(
            "status={:?}\nstdout={}\nstderr={}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        std::thread::sleep(Duration::from_secs(2));
    }

    // The load-bearing check: a large stream must arrive complete and in order,
    // exercising the credit/CREDIT_UPDATE path the trivial echo cannot.
    let mut big_ok = false;
    let mut big_diag = String::new();
    if ready {
        let n = SEQ_N.to_string();
        let out = mm(&["exec", name, "--", "seq", "1", n.as_str()])
            .output()
            .expect("run `mm exec seq`");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let lines: Vec<&str> = stdout.lines().collect();
        let exit = out.status.code();
        big_ok = exit == Some(0)
            && lines.len() == SEQ_N
            && lines.first() == Some(&"1")
            && lines.last() == Some(&n.as_str());
        big_diag = format!(
            "exit={exit:?} lines={} (want {SEQ_N}) first={:?} last={:?} stderr={}",
            lines.len(),
            lines.first(),
            lines.last(),
            String::from_utf8_lossy(&out.stderr),
        );
    }

    // Diagnostics from the guest console before teardown, so a failure self-explains.
    let mut diag = String::new();
    if !ready || !big_ok {
        let console = state.join(format!("jails/{name}/console.log"));
        let log =
            std::fs::read_to_string(&console).unwrap_or_else(|e| format!("(no console.log: {e})"));
        diag.push_str(&format!(
            "--- guest console ({}) ---\n{log}\n--- end ---\n",
            console.display()
        ));
    }

    let _ = mm(&["stop", name]).output();
    let _ = std::fs::remove_dir_all(&state);

    assert!(
        ready,
        "`mm exec` never returned the token from the guest.\nlast attempt:\n{last}\n{diag}"
    );
    assert!(
        big_ok,
        "large `mm exec seq` output did not arrive intact (credit flow-control bug?).\n{big_diag}\n{diag}"
    );
}
