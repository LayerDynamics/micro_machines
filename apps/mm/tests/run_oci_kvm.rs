//! End-to-end: `mm run <oci-image>` builds a rootfs from a real OCI image, injects
//! mm-init, wires the bridge/TAP/NAT, jails the worker, and boots the image as a
//! microVM — the product's headline path (SPEC-1 FR-5/FR-6/FR-27, container UX over
//! a real VM). This exercises the whole `mm run` orchestration end to end, not the
//! VMM in isolation.
//!
//! Proof of boot is the host-side readiness marker the jailed worker logs when the
//! guest's mm-init signals over vsock — which mm-init now does for *any* image,
//! before handing off to the image's command. (A clean process exit is not used as
//! proof: the workload, not the boot, controls that.)
//!
//! Requires /dev/kvm, root (bridge/TAP/NAT/cgroup/jail), skopeo + umoci, network
//! access to pull the image, and the kernel + musl mm-init fixtures. The CI
//! `mm-run-integration` job provides all of it. `#[ignore]`d otherwise.
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The marker the worker logs when the guest signals readiness over vsock.
const READY_MARKER: &str = "guest signaled readiness over vsock";
/// A tiny, multi-arch image whose default command (`sh`) exits on EOF.
const IMAGE: &str = "docker.io/library/busybox:latest";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize repo root")
}

/// Read `stream` line by line: append every line to `sink`, and send once on `tx`
/// the first time a line contains `READY_MARKER`. The returned handle completes when
/// the stream hits EOF (i.e. the child closed it), so the caller can join to be sure
/// all output has been captured before inspecting `sink`.
fn watch<R: Read + Send + 'static>(
    stream: R,
    sink: Arc<Mutex<String>>,
    tx: mpsc::Sender<()>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut signalled = false;
        for line in BufReader::new(stream).lines().map_while(Result::ok) {
            if let Ok(mut s) = sink.lock() {
                s.push_str(&line);
                s.push('\n');
            }
            if !signalled && line.contains(READY_MARKER) {
                signalled = true;
                let _ = tx.send(());
            }
        }
    })
}

#[test]
#[ignore = "requires /dev/kvm, root, skopeo/umoci, network, and fixtures"]
fn mm_run_boots_an_oci_image() {
    let root = repo_root();
    let kernel = root.join("crates/mm-vmm/tests/fixtures/vmlinux");
    let mm_init = root.join("target/x86_64-unknown-linux-musl/release/mm-init");
    assert!(
        kernel.exists(),
        "missing kernel fixture {} — run scripts/fetch-test-fixtures.sh",
        kernel.display()
    );
    assert!(
        mm_init.exists(),
        "missing musl mm-init {} — run scripts/fetch-test-fixtures.sh",
        mm_init.display()
    );

    // Sandbox all host state under a temp MM_ROOT so the run is isolated + cleanable.
    let state = std::env::temp_dir().join(format!("mm-run-test-{}", std::process::id()));
    std::fs::create_dir_all(&state).expect("create state root");

    let mm_bin = env!("CARGO_BIN_EXE_mm");
    let mut child = Command::new(mm_bin)
        .args(["run", "--name", "oci-test", IMAGE])
        .env("MM_ROOT", &state)
        .env("MM_KERNEL", &kernel)
        .env("MM_INIT", &mm_init)
        // /dev/null stdin → the guest's `sh` reads EOF and exits, so the VM powers
        // off on its own; we don't depend on that for the assertion, though.
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn `mm run`");

    let output = Arc::new(Mutex::new(String::new()));
    let (tx, rx) = mpsc::channel();
    let h_out = watch(child.stdout.take().unwrap(), output.clone(), tx.clone());
    let h_err = watch(child.stderr.take().unwrap(), output.clone(), tx);

    // Wait up to 120s for the guest to signal readiness (image pull + boot).
    let booted = rx.recv_timeout(Duration::from_secs(120)).is_ok();

    // Tear down: kill `mm run` and SIGTERM the jailed worker via `mm stop`.
    let _ = child.kill();
    let _ = child.wait();
    let _ = Command::new(mm_bin)
        .args(["stop", "oci-test"])
        .env("MM_ROOT", &state)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    // Join the readers (the pipes are now closed) so all output is captured.
    let _ = h_out.join();
    let _ = h_err.join();
    let log = output.lock().map(|s| s.clone()).unwrap_or_default();
    eprintln!("--- `mm run {IMAGE}` output ---\n{log}\n--- end ---");
    let _ = std::fs::remove_dir_all(&state);

    assert!(
        booted,
        "`mm run {IMAGE}` did not boot the image to userspace (no \"{READY_MARKER}\")"
    );
    // The guest must come up on a *writable* overlay root — not silently fall back to
    // the read-only base (which would break authorized-key injection and any workload
    // that writes outside /run,/tmp).
    assert!(
        log.contains("writable overlay root active"),
        "guest did not get a writable overlay root\noutput:\n{log}"
    );
}
