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

# Build a tiny static `ready` helper: it opens an AF_VSOCK connection (any vsock
# traffic is the readiness edge the M1 vsock device waits on), then powers off.
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
// Signal boot readiness to the host VMM over vsock, then power off.
fn main() {
    // SAFETY: each libc call is checked or best-effort; on failure we still
    // power off so the boot test's vCPU halts.
    unsafe {
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
        libc::reboot(libc::RB_POWER_OFF);
    }
}
EOF

  ( cd "${proj}" && cargo build --release --target "${MUSL_TARGET}" )
  cp "${proj}/target/${MUSL_TARGET}/release/ready" "${stage}/sbin/ready"
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

  # Populate an ext4 image directly from the staging directory.
  mke2fs -q -t ext4 -F -d "${stage}" "${ROOTFS}.tmp" 64M
  mv "${ROOTFS}.tmp" "${ROOTFS}"
}

fetch_kernel
build_rootfs
echo "fixtures ready:"
echo "  ${KERNEL}"
echo "  ${ROOTFS}"
