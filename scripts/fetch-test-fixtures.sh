#!/usr/bin/env bash
#
# Populate the KVM boot integration fixtures used by
# crates/mm-vmm/tests/boot_kvm.rs:
#
#   crates/mm-vmm/tests/fixtures/vmlinux       — an x86_64 Linux kernel (ELF/bzImage)
#   crates/mm-vmm/tests/fixtures/rootfs.ext4   — a minimal rootfs whose /init
#                                                 (mm-init) signals readiness over
#                                                 vsock, then powers off.
#
# Idempotent: existing artifacts are reused. Intended for the self-hosted KVM CI
# runner, but runnable by hand on any Linux/KVM host with the listed tools.
#
# Requirements: curl, rustup/cargo (with the musl target), and mke2fs (e2fsprogs).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURES_DIR="${REPO_ROOT}/crates/mm-vmm/tests/fixtures"
KERNEL="${FIXTURES_DIR}/vmlinux"
ROOTFS="${FIXTURES_DIR}/rootfs.ext4"

# --- Architecture selection (x86_64 and aarch64) ---
# Normalize the host arch, pick the guest serial console for that arch, and the
# musl target the guest binaries are built for.
ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64 | amd64)
    ARCH="x86_64"
    GUEST_CONSOLE="ttyS0"
    ;;
  aarch64 | arm64)
    ARCH="aarch64"
    GUEST_CONSOLE="ttyAMA0"
    ;;
  *)
    echo "unsupported architecture: ${ARCH} (expected x86_64 or aarch64)" >&2
    exit 1
    ;;
esac
MUSL_TARGET="${ARCH}-unknown-linux-musl"

# The M1 VMM boot protocol (GDT, page tables, long-mode regs) is x86_64-only.
# aarch64 fixtures are still built so they are ready when aarch64 VMM support
# lands, but the boot test will not pass on aarch64 until then.
if [[ "${ARCH}" != "x86_64" ]]; then
  echo "NOTE: M1 VMM boot is x86_64-only; building ${ARCH} fixtures anyway, but the" >&2
  echo "      boot integration test will not pass on ${ARCH} yet." >&2
fi

# A known-good, publicly hosted test kernel for this arch. Override with
# MM_TEST_KERNEL_URL. The guest console for the arch is exported for the test.
KERNEL_URL="${MM_TEST_KERNEL_URL:-https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/${ARCH}/kernels/vmlinux.bin}"

echo "arch=${ARCH} musl-target=${MUSL_TARGET} guest-console=${GUEST_CONSOLE}"
mkdir -p "${FIXTURES_DIR}"

fetch_kernel() {
  if [[ -f "${KERNEL}" ]]; then
    echo "kernel already present: ${KERNEL}"
    return
  fi
  echo "fetching test kernel: ${KERNEL_URL}"
  curl -fsSL "${KERNEL_URL}" -o "${KERNEL}.tmp"
  mv "${KERNEL}.tmp" "${KERNEL}"
}

# Build a tiny static `ready` helper. It emits two best-effort readiness edges
# then powers off: (1) a UDP datagram to the gateway over the guest NIC — the
# edge the net integration test observes; (2) an AF_VSOCK connect — the edge the
# plain boot test waits on. Whichever device the VM lacks simply makes its send
# fail and is ignored.
build_ready_helper() {
  local stage="$1"
  local proj="${stage}/.ready-src"
  mkdir -p "${proj}/src"

  cat >"${proj}/Cargo.toml" <<'EOF'
[package]
name = "ready"
version = "0.0.0"
edition = "2021"

[dependencies]
libc = "0.2"

[[bin]]
name = "ready"
path = "src/main.rs"

[profile.release]
opt-level = "z"
strip = true
panic = "abort"
EOF

  cat >"${proj}/src/main.rs" <<'EOF'
// Signal boot readiness to the host. Two best-effort signals, then power off:
//   1. a UDP datagram to the gateway (10.0.0.1:1234) over the guest NIC — this
//      is the edge the net integration test observes (proves virtio-net TX +
//      the kernel's static `ip=` config brought eth0 up);
//   2. an AF_VSOCK connect to the host — the edge the plain boot test waits on.
// On the no-net boot test the UDP send simply fails (no route) and is ignored;
// on the net test the vsock connect fails the same way. Either way we power off
// so the vCPU halts and the host-side gate fires.
fn main() {
    // SAFETY: each libc call is checked or best-effort; on failure we still
    // power off so the test's vCPU halts.
    unsafe {
        // (1) UDP to the gateway over eth0 — the net test's readiness edge.
        let ufd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if ufd >= 0 {
            let mut dst: libc::sockaddr_in = core::mem::zeroed();
            dst.sin_family = libc::AF_INET as libc::sa_family_t;
            dst.sin_port = 1234u16.to_be(); // host byte order -> network
            // 10.0.0.1 as raw network-order bytes.
            dst.sin_addr.s_addr = u32::from_ne_bytes([10, 0, 0, 1]);
            let msg = b"mm-ready";
            libc::sendto(
                ufd,
                msg.as_ptr().cast(),
                msg.len(),
                0,
                (&dst as *const libc::sockaddr_in).cast(),
                core::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
            libc::close(ufd);
        }

        // (2) vsock connect — the plain boot test's readiness edge.
        let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0);
        if fd >= 0 {
            let mut addr: libc::sockaddr_vm = core::mem::zeroed();
            addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
            addr.svm_cid = 2; // VMADDR_CID_HOST
            addr.svm_port = 1024;
            // The connect attempt emits vsock tx — that is the readiness signal.
            libc::connect(
                fd,
                (&addr as *const libc::sockaddr_vm).cast(),
                core::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            );
            libc::close(fd);
        }
        libc::sync();
        // Reboot (not power off): with reboot=t the kernel resets via a triple
        // fault, which KVM reports to the VMM as a shutdown exit so the worker's
        // vCPU thread returns. A power-off would halt the CPU and block KVM_RUN.
        libc::reboot(libc::RB_AUTOBOOT);
    }
}
EOF

  ( cd "${proj}" && cargo build --release --target "${MUSL_TARGET}" )
  cp "${proj}/target/${MUSL_TARGET}/release/ready" "${stage}/sbin/ready"
}

# A tiny guest helper for the fork exec-independence test (fork_kvm.rs): the minimal
# rootfs has no shell, so we ship a purpose-built static binary the guest exec agent
# can run. `marker write <v>` records <v> in the guest's (writable, ephemeral-overlay)
# filesystem; `marker read` prints it back. Forking N children and asserting each reads
# back only its own value proves per-child guest isolation end to end.
build_marker_helper() {
  local stage="$1"
  local proj="${stage}/.marker-src"
  mkdir -p "${proj}/src"

  cat >"${proj}/Cargo.toml" <<'EOF'
[package]
name = "marker"
version = "0.0.0"
edition = "2021"

[[bin]]
name = "marker"
path = "src/main.rs"

[profile.release]
opt-level = "z"
strip = true
panic = "abort"
EOF

  cat >"${proj}/src/main.rs" <<'EOF'
// In-guest marker for the fork exec-independence test. Pure std, no deps.
//   marker write <value>  -> write <value> to /tmp/mm-marker (writable overlay)
//   marker read           -> print /tmp/mm-marker, or "EMPTY" if unset
use std::io::Write;

const PATH: &str = "/tmp/mm-marker";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("write") => {
            let value = args.get(2).cloned().unwrap_or_default();
            if std::fs::write(PATH, value.as_bytes()).is_err() {
                std::process::exit(1);
            }
        }
        Some("read") => {
            let out = std::fs::read(PATH).unwrap_or_else(|_| b"EMPTY".to_vec());
            let _ = std::io::stdout().write_all(&out);
            let _ = std::io::stdout().flush();
        }
        _ => {
            let _ = writeln!(std::io::stderr(), "usage: marker write <value> | marker read");
            std::process::exit(2);
        }
    }
}
EOF

  ( cd "${proj}" && cargo build --release --target "${MUSL_TARGET}" )
  cp "${proj}/target/${MUSL_TARGET}/release/marker" "${stage}/sbin/marker"
}

build_rootfs() {
  if [[ -f "${ROOTFS}" ]]; then
    echo "rootfs already present: ${ROOTFS}"
    return
  fi
  echo "building minimal rootfs at ${ROOTFS}"

  # mm-init is PID 1 inside the guest.
  rustup target add "${MUSL_TARGET}" >/dev/null 2>&1 || true
  cargo build -p mm-init --release --target "${MUSL_TARGET}"

  local stage
  stage="$(mktemp -d)"
  trap 'rm -rf "${stage}"' RETURN
  mkdir -p "${stage}"/{sbin,proc,sys,dev,run,tmp,root/.ssh}

  cp "${REPO_ROOT}/target/${MUSL_TARGET}/release/mm-init" "${stage}/init"
  build_ready_helper "${stage}"
  build_marker_helper "${stage}"

  # Populate an ext4 image directly from the staging directory.
  mke2fs -q -t ext4 -F -d "${stage}" "${ROOTFS}.tmp" 64M
  mv "${ROOTFS}.tmp" "${ROOTFS}"
}

fetch_kernel
build_rootfs
echo "fixtures ready:"
echo "  ${KERNEL}"
echo "  ${ROOTFS}"
