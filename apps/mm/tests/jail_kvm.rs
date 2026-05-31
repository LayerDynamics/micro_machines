//! End-to-end: drive the real `mm __vmm-worker` re-exec the way `mm run` does and
//! confirm a **fully jailed** microVM boots to userspace (SPEC-1 FR-27).
//!
//! This is the jailer counterpart to the plain boot test. It exercises the exact
//! production confinement path — cgroup v2 limits, mount/pid/net namespaces,
//! chroot into a per-VM root, `no_new_privs`, drop to an unprivileged uid/gid, and
//! a per-thread seccomp allowlist — and only then boots guest code using an
//! inherited `/dev/kvm` fd (the confined process cannot open it itself). Proof of
//! a successful jailed boot is twofold: the worker exits 0 **and** its tracing
//! reports the guest signalled readiness over vsock. The second check is load
//! bearing — the worker exits 0 even on a readiness *timeout*, so exit code alone
//! would pass a guest that never reached userspace (e.g. a device worker blocked
//! by an over-tight seccomp filter).
//!
//! No net device is configured: the jail is tested in isolation, so the worker
//! needs only the inherited KVM fd (the TAP fd is unused, passed as -1).
//!
//! Requires /dev/kvm, the fixtures (see crates/mm-vmm/tests/fixtures/README.md),
//! AND root — the jailer's cgroup writes, `unshare`, `chroot`, and uid-drop all
//! need privilege. The CI `jail-integration` job runs it under `sudo`. It is
//! `#[ignore]`d so a normal `cargo test` never confines anything.
#![cfg(target_os = "linux")]

use std::fs;
use std::io::Read;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use mm_vmm::{BlockDevice, VmConfig};

// Must match the worker spawn contract in apps/mm/src/commands/run.rs.
const WORKER_KVM_FD: i32 = 10;
const WORKER_UID: u32 = 65534; // nobody
const WORKER_GID: u32 = 65534; // nogroup

#[cfg(target_arch = "aarch64")]
const GUEST_CONSOLE: &str = "console=ttyAMA0";
#[cfg(not(target_arch = "aarch64"))]
const GUEST_CONSOLE: &str = "console=ttyS0";

/// Repository root, derived from this crate's manifest dir (apps/mm).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize repo root")
}

/// Recursively copy world-readable so the dropped-to uid can read the fixtures.
fn copy_readable(src: &Path, dst: &Path) {
    fs::copy(src, dst)
        .unwrap_or_else(|e| panic!("copy {} -> {}: {e}", src.display(), dst.display()));
    let mut perms = fs::metadata(dst).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o644);
    fs::set_permissions(dst, perms).unwrap();
}

#[test]
#[ignore = "requires /dev/kvm, fixtures, and root (jailer chroot/cgroup/uid-drop)"]
fn jailed_worker_boots_to_userspace() {
    // Firecracker-style jail: drop to an unprivileged uid under real root, no
    // user namespace.
    run_jailed_boot("uiddrop", false);
}

#[test]
#[ignore = "requires /dev/kvm, fixtures, root, and unprivileged user namespaces"]
fn jailed_worker_boots_with_user_namespace() {
    // The *default* `mm run` confinement: also enter a user namespace, mapping
    // inner-root to the unprivileged uid/gid (a namespace escape lands as that
    // uid, not real root). This path stays inner-root rather than setuid-dropping,
    // and wraps the same fork-into-PID-namespace step — so it is verified here
    // directly rather than reasoned about. Requires unprivileged userns on the
    // host (confirmed by the net-jail-preflight job: userns-clone=1).
    run_jailed_boot("userns", true);
}

/// Drive `mm __vmm-worker` exactly as `mm run` does and assert a confined microVM
/// boots to userspace and the worker exits 0 (which only happens if the jailed
/// guest signalled readiness over vsock). `user_namespace` toggles the
/// `--user-namespace` hardening (off = uid-drop only; on = the production
/// default). `tag` keeps the per-run cgroup + work dir unique so the two variants
/// can run concurrently.
fn run_jailed_boot(tag: &str, user_namespace: bool) {
    let root = repo_root();
    let fixtures = root.join("crates/mm-vmm/tests/fixtures");
    let kernel_src = fixtures.join("vmlinux");
    let rootfs_src = fixtures.join("rootfs.ext4");
    assert!(
        kernel_src.exists() && rootfs_src.exists(),
        "missing fixtures — run scripts/fetch-test-fixtures.sh first"
    );

    // Per-VM chroot the worker pivots into. The kernel + rootfs must live at the
    // paths the config names, since the VMM loads them *after* chroot.
    let slug = format!("mm-jail-{tag}-{}", std::process::id());
    let work = std::env::temp_dir().join(&slug);
    let jail = work.join("root");
    fs::create_dir_all(&jail).expect("create jail root");
    copy_readable(&kernel_src, &jail.join("vmlinux"));
    copy_readable(&rootfs_src, &jail.join("rootfs.ext4"));

    // Config names in-chroot paths and no net device. The fixture /init runs
    // /sbin/ready, which signals readiness over vsock then powers off.
    let cfg = VmConfig {
        vcpus: 1,
        memory_mib: 128,
        kernel: "/vmlinux".into(),
        kernel_cmdline: format!(
            "{GUEST_CONSOLE} root=/dev/vda ro init=/init reboot=k panic=1 {} mm.workload=/sbin/ready",
            mm_vmm::FAST_BOOT_ARGS,
        ),
        rootfs: BlockDevice {
            path: "/rootfs.ext4".into(),
            read_only: true,
        },
        devices: vec![],
    };
    cfg.validate().unwrap();
    // The worker reads the config *before* chroot, so it lives outside the jail.
    let cfg_path = work.join("worker-config.json");
    fs::write(&cfg_path, serde_json::to_vec(&cfg).unwrap()).expect("write worker config");

    // Open /dev/kvm without CLOEXEC and hand it to the worker at fd 10, exactly as
    // `mm run` does — the confined worker cannot open /dev/kvm after uid-drop.
    let kvm_fd = open_kvm_inheritable();

    let cgroup = slug.clone();
    let mm_bin = env!("CARGO_BIN_EXE_mm");
    let mut cmd = Command::new(mm_bin);
    cmd.arg("__vmm-worker")
        .arg("--config")
        .arg(&cfg_path)
        .arg("--kvm-fd")
        .arg(WORKER_KVM_FD.to_string())
        // No TAP: `=-1` form so clap does not treat -1 as a flag. The worker never
        // consumes it because the config has no net device.
        .arg("--tap-fd=-1")
        .arg("--chroot")
        .arg(&jail)
        .arg("--uid")
        .arg(WORKER_UID.to_string())
        .arg("--gid")
        .arg(WORKER_GID.to_string())
        .arg("--cgroup")
        .arg(&cgroup)
        .arg("--cpu-max")
        .arg("max")
        .arg("--mem-max")
        .arg((512u64 * 1024 * 1024).to_string());
    if user_namespace {
        cmd.arg("--user-namespace");
    }
    // Capture stdout — the worker's tracing (tracing_subscriber::fmt defaults to
    // stdout) *and* the guest serial console both land there. We need the tracing
    // to prove the guest reached userspace: the worker exits 0 even on a readiness
    // *timeout*, so a clean exit alone is not proof of boot. We re-print the
    // captured output afterward so CI logs still show it.
    cmd.stdout(Stdio::piped());

    // SAFETY: pre_exec runs in the forked child before exec; dup2 is
    // async-signal-safe and clears CLOEXEC on fd 10 so it survives exec.
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(kvm_fd, WORKER_KVM_FD) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = cmd.spawn().expect("spawn mm __vmm-worker");
    // SAFETY: kvm_fd is our copy; the child inherited its own dup at fd 10.
    unsafe { libc::close(kvm_fd) };

    // Drain the worker's stdout concurrently so its pipe never fills (the guest
    // console can be chatty), and so we can inspect it after exit. The reader
    // returns when the worker closes stdout.
    let mut stdout_pipe = child.stdout.take().expect("piped worker stdout");
    let stdout_reader = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stdout_pipe.read_to_string(&mut buf);
        buf
    });

    // Wait up to 60s for the jailed worker to boot the guest, observe readiness,
    // and exit. std has no timed wait, so poll.
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll worker") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            cleanup(&work, &cgroup);
            panic!("jailed worker did not exit within 60s (guest never signalled readiness)");
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    let output = stdout_reader.join().unwrap_or_default();
    cleanup(&work, &cgroup);
    // Surface the worker's output in CI logs (stdout was piped, not inherited).
    eprintln!("--- worker stdout (user_namespace={user_namespace}) ---\n{output}\n--- end ---");

    assert!(
        status.success(),
        "jailed worker (user_namespace={user_namespace}) exited unsuccessfully: \
         code={:?} signal={:?}",
        status.code(),
        status.signal()
    );
    // A clean exit is not enough: the worker exits 0 even if readiness timed out.
    // Require the positive readiness marker so a guest that never reaches userspace
    // (e.g. a device worker blocked by an over-tight seccomp filter) fails the test.
    assert!(
        output.contains("guest signaled readiness over vsock"),
        "jailed guest did not reach userspace (no readiness signal) — \
         user_namespace={user_namespace}\nworker output:\n{output}"
    );
}

/// Open `/dev/kvm` read-write without CLOEXEC (mirrors run.rs::open_kvm_inheritable).
fn open_kvm_inheritable() -> i32 {
    let path = std::ffi::CString::new("/dev/kvm").unwrap();
    // SAFETY: path is a valid C string; result is checked.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
    assert!(
        fd >= 0,
        "open /dev/kvm: {}",
        std::io::Error::last_os_error()
    );
    fd
}

/// Best-effort teardown: remove the work dir and the (now-empty) cgroup.
fn cleanup(work: &Path, cgroup: &str) {
    let _ = fs::remove_dir_all(work);
    let _ = fs::remove_dir(Path::new("/sys/fs/cgroup").join(cgroup));
}
