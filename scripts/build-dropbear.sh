#!/usr/bin/env bash
#
# Build a **static** dropbear SSH server for injection into guest rootfs images,
# so every MicroMachines microVM is SSH-reachable out of the box regardless of the
# source image (FR-12, "automatic internal SSH access"). Static + musl so it runs
# in any guest userland (glibc, musl, or a FROM-scratch image).
#
# Output: a single `dropbear` binary at $OUT (default crates/mm-vmm/tests/fixtures/
# dropbear). The VMM consumes it via MM_SSHD; mm-image injects it as /sbin/dropbear.
#
# Requirements: curl, tar, make, and musl-gcc (apt: musl-tools).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-${REPO_ROOT}/crates/mm-vmm/tests/fixtures/dropbear}"
VERSION="${DROPBEAR_VERSION:-2022.83}"

if [[ -f "${OUT}" ]]; then
  echo "dropbear already built: ${OUT}"
  exit 0
fi

command -v musl-gcc >/dev/null || {
  echo "musl-gcc not found (install musl-tools)" >&2
  exit 1
}

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

# The release tarball ships a pre-generated ./configure. Two mirrors for resilience.
tarball="dropbear-${VERSION}.tar.bz2"
url1="https://matt.ucc.asn.au/dropbear/releases/${tarball}"
url2="https://github.com/mkj/dropbear/releases/download/DROPBEAR_${VERSION}/${tarball}"
echo "fetching dropbear ${VERSION}"
curl -fsSL "${url1}" -o "${work}/${tarball}" || curl -fsSL "${url2}" -o "${work}/${tarball}"

tar -xjf "${work}/${tarball}" -C "${work}"
src="${work}/dropbear-${VERSION}"

# Static musl build of just the server. --disable-zlib drops the only optional
# external dependency; -R (delayed host keys) is a runtime flag, no build option.
(
  cd "${src}"
  ./configure --enable-static --disable-zlib CC=musl-gcc >/dev/null
  make -j"$(nproc)" PROGRAMS=dropbear STATIC=1 >/dev/null
)

mkdir -p "$(dirname "${OUT}")"
cp "${src}/dropbear" "${OUT}"
chmod 0755 "${OUT}"
echo "built: ${OUT}"
file "${OUT}" || true
