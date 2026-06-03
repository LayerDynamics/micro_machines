# MicroMachines

A Rust, KVM-based virtual machine monitor (VMM) that runs secure, multi-tenant
**microVMs with a container UX** — the same microVM lineage as Firecracker, but
shipping the batteries a typical dev/deploy workflow needs out of the box.

You `mm run` an OCI image and get a real hardware-isolated VM that boots in well under
a second, comes up with an IP and SSH already wired, and can be snapshotted, forked,
branched while still running, and exec'd into — locally on one host, or scheduled
across a cluster through a Git-friendly control plane.

## Why MicroMachines

Teams running untrusted or multi-tenant code face a forced choice: containers (great
UX, shared-kernel isolation) or VMs (real isolation, heavy UX). MicroMachines collapses
that choice. Five capabilities define the product:

- **Container UX over real VM isolation** — `mm run <image>` feels like a container
  but boots an actual microVM with its own kernel. Multi-tenant and serverless-style.
- **Automatic internal IP / SSH access** — guests come up reachable, with no manual
  network plumbing: IPAM, a host bridge/TAP, and NAT are wired at boot.
- **Built-in GitOps management** — a declarative, Git-driven fleet lifecycle, not a
  bolt-on. *(Planned — see Status.)*
- **A build-target matrix** — compile one workload into a microVM, a self-contained
  executable, or a unikernel image. *(Planned — see Status.)*
- **Sandbox Mode** — run agents/apps *inside* the sandboxed guest, with a host→guest
  exec channel and a seccomp-jailed VMM, single-host or routed through the cluster.

## Status

MicroMachines is built as a *walking skeleton first* — the load-bearing VMM core proven
end-to-end on one host — then independently valuable milestones on top. Each milestone
below is verified by its own integration job in CI.

| Milestone | Scope | State |
| --- | --- | --- |
| **M1 — Walking skeleton** | Hardened single microVM, OCI rootfs, auto IP/SSH, Rust VMM core + guest init | ✅ Implemented, CI-green |
| **M2 — Cluster control plane** | Multi-host scheduling + reconciliation, RBAC/JWT auth, mTLS, Postgres-backed state | ✅ Implemented, CI-green |
| **M3 — Sandbox + snapshot/fork** | Sandbox Mode, snapshot/restore, copy-on-write fork, cluster exec | ✅ Implemented, CI-green |
| **M4 — GitOps** | Declarative Git-driven fleet + HA leader failover | ◻ Planned |
| **M5 — Build-target matrix** | microVM / executable / unikernel from one manifest | ◻ Planned |
| **M6 — Node edge** | SDK + dashboard + gateway | ◻ Planned |

This is pre-1.0 (`0.0.0`); interfaces may change.

## Requirements

The VMM core runs on **Linux with KVM** (`/dev/kvm`); microVMs cannot boot on other
platforms. The cross-platform crates (configuration, API types, the CLI's remote mode,
pure logic) build and test on macOS too, but anything that boots a guest must run on a
Linux/KVM host.

### Toolchain

- **Rust** — stable, with `rustfmt` and `clippy`. `rust-toolchain.toml` pins the channel
  and components, so `rustup` installs the right toolchain automatically on first build.
  It also declares the `x86_64-unknown-linux-musl` / `aarch64-unknown-linux-musl` targets
  used to build the static guest binaries.
- **Node ≥ 20** and **pnpm ≥ 9** — only for the JS/TS workspace (`package.json` `engines`).
- A protobuf compiler is **not** required: `mm-proto` builds the gRPC contract with a
  vendored `protoc`.

### Runtime (booting microVMs, on Linux)

- Access to `/dev/kvm`, and root (or `CAP_NET_ADMIN` + `CAP_SYS_ADMIN`) to create the
  host bridge/TAP and jail the VMM worker.
- A guest kernel (point `MM_KERNEL` at it, or place a `vmlinux` under the state root).
- **PostgreSQL** — for the cluster control plane (`mm-controller`); CI runs against
  PostgreSQL 16. Building the controller does not need a database; running it does.

### Building guest fixtures / the OCI flow (Debian/Ubuntu package names)

- `musl-tools` (provides `musl-gcc`) — static guest binaries (`mm-init`, dropbear).
- `e2fsprogs` (provides `mke2fs`) — build the guest `ext4` rootfs.
- `skopeo` — pull OCI images; **umoci** — unpack them (released static binary, not in apt).
- `openssl` — dev mTLS certs (`scripts/dev-certs.sh`); `curl`, `tar`, `make`, `file` — fetch/build helpers.

## Install (build from source)

There are no published binaries yet; build from source. On a Debian/Ubuntu Linux host:

```bash
# 1. System dependencies for the guest-image / OCI build path.
sudo apt-get update
sudo apt-get install -y musl-tools e2fsprogs skopeo openssl curl tar make file
# umoci is not packaged in apt — install the released static binary:
sudo curl -fsSL -o /usr/local/bin/umoci \
  https://github.com/opencontainers/umoci/releases/download/v0.4.7/umoci.amd64
sudo chmod 0755 /usr/local/bin/umoci

# 2. Rust toolchain — rustup reads rust-toolchain.toml and installs the pinned
#    stable channel, components, and musl targets on the first cargo invocation.
#    (Install rustup from https://rustup.rs if you don't have it.)

# 3. Clone and build the workspace.
git clone https://github.com/layerdynamics/micro_machines.git
cd micro_machines
cargo build --workspace --release
```

The binaries land in `target/release/`: `mm` (CLI), `mm-controller`, `mm-agent`.

On macOS you can build and test the cross-platform crates (`cargo build -p mm`,
`cargo test --workspace`), but booting a microVM requires a Linux/KVM host.

## Quickstart (single host)

On a Linux/KVM host, build the CLI and run an OCI image as a microVM:

```bash
cargo build -p mm
# Point at a guest kernel (or place one at <state-root>/vmlinux):
export MM_KERNEL=/path/to/vmlinux

# Boot a microVM from an OCI image, with SSH + a managed IP:
mm run docker.io/library/alpine:latest --name demo --ssh

mm ps                      # list machines (name, state, IP, image)
mm ssh demo                # SSH into the guest over its auto-assigned IP
mm exec demo -- echo hello # run a command in the guest over the vsock bridge
mm stop demo               # stop the microVM
mm rm demo                 # remove it
```

`mm run --ssh` puts the guest in Sandbox Mode so it stays up after its workload exits.
Booting needs root (or the appropriate capabilities) to create the bridge/TAP and jail
the worker.

### Snapshots & restore

Snapshot a **live** microVM (no full pause — the worker captures it over a control
channel), list/prune snapshots, and restore one into a fresh machine:

```bash
mm snapshot create demo            # snapshot the running guest; prints the new id
mm snapshot ls demo                # list demo's snapshots (id, RAM, kind)
mm restore demo <id> demo-restored # boot a new machine from that snapshot
mm exec demo-restored -- uname -a  # the restored guest is live (reach it over vsock)
mm snapshot gc demo --keep 3       # keep the 3 newest, remove the rest
mm snapshot rm demo <id>           # remove one snapshot
```

A restored machine resumes with the IP captured in the snapshot, so restore a *stopped*
source (or reach the restored guest over its own vsock bridge with `mm exec`). Branching
a *running* guest into an independently-addressable live clone (`mm branch`) is a
follow-on (see `docs/plans/2026-06-03-clone-networking-netns.md`).

## Cluster mode

The control plane is a `mm-controller` (REST API + scheduler + reconciler + gRPC,
backed by Postgres) talking mutual-TLS to per-host `mm-agent`s that boot the microVMs.
The CLI drives it with `--server`:

```bash
# Controller (REST :8080, controller↔agent gRPC :50051):
mm-controller --database-url "$DATABASE_URL" --jwt-hs256-secret "$SECRET" --tls-dir ./certs

# Host agent (dials the controller, boots assigned microVMs):
mm-agent run --controller https://controller:50051 --host-id host-1 \
  --kernel "$MM_KERNEL" --init "$MM_INIT" --tls-dir ./certs

# Same CLI, cluster-routed via the controller:
mm --server http://controller:8080 --token "$JWT" --namespace team-a run alpine:latest --ssh
mm --server http://controller:8080 --token "$JWT" --namespace team-a exec demo -- echo hi
```

`mm exec` in cluster mode forwards the command controller → agent → guest and streams
the output back; the agent reverse-connects (it has no inbound address), so exec rides a
push channel rather than an inbound call. State lives in Postgres, so the data plane
survives a control-plane restart — the reconciler re-converges.

`scripts/cluster-e2e.sh` stands up the whole stack (controller + agent + a real microVM)
over mTLS and exercises this path end to end; it is what the `cluster-integration` CI
job runs.

## Architecture

MicroMachines is a hybrid monorepo: a Rust workspace (the VMM core and everything that
touches KVM) alongside a pnpm-managed JS/TS workspace scaffolded for future tooling.

### Rust workspace

| Crate | Role |
| --- | --- |
| `crates/mm-api-types` | Shared contract types every other crate depends on |
| `crates/mm-vmm` | Native VMM core on the rust-vmm crates: vCPUs, memory, virtio block/net/vsock, boot, snapshot/restore, copy-on-write fork, live branch (userfaultfd write-protect), rate limiting |
| `crates/mm-net` | Host networking: IPAM, bridge/TAP, NAT, guest boot params |
| `crates/mm-image` | OCI image handling: read-only base rootfs + per-instance writable overlays |
| `crates/mm-init` | Guest `init`: cmdline parsing, mounts, workload exec, the in-guest exec agent |
| `crates/mm-sandbox` | Host-side sandbox: seccomp jail + the host↔guest exec wire protocol/client |
| `crates/mm-host` | Shared host actuation (build rootfs → network → jail → boot the worker), reused by the CLI and the agent |
| `crates/mm-proto` | Generated controller↔agent gRPC contract |
| `apps/mm` | The `mm` CLI: single-host (`run`/`ps`/`stop`/`rm`/`ssh`/`exec`) and cluster mode (`--server`) |
| `services/mm-controller` | Control plane: REST API, scheduler, reconciler, Postgres store, gRPC server |
| `services/mm-agent` | Host agent: reconciles assignments into real microVMs, reports state, runs cluster exec |

### JS/TS workspace

A pnpm workspace (`pnpm-workspace.yaml`, `package.json`) is scaffolded for forthcoming
JS/TS tooling and the control-plane surface; no packages are published in it yet.

## Build & test

Rust (from the repo root; the VMM core requires Linux/KVM to *run*):

```bash
cargo build --workspace
cargo test --workspace                 # unit + cross-platform tests
cargo clippy --workspace --all-targets # lint
cargo fmt --all                        # format
```

KVM integration tests are `#[ignore]`d by default (they need `/dev/kvm` and fixtures)
and run as dedicated CI jobs. To run one locally on a Linux/KVM host:

```bash
./scripts/fetch-test-fixtures.sh
cargo test -p mm-vmm --features kvm-integration --test boot_kvm -- --ignored --nocapture
```

JS/TS workspace:

```bash
pnpm install
pnpm -r build
pnpm -r test
```

### Continuous integration

CI runs unit/lint jobs (`rust`, `node`, `controller`) plus a suite of real-KVM
integration jobs on GitHub-hosted runners with nested virtualization:
`kvm-integration` (boot to userspace), `snapshot-integration`, `fork-integration`,
`net-integration`, `jail-integration`, `mm-run-integration`, `ssh-integration`,
`exec-integration`, and `cluster-integration` (full controller + agent + microVM over
mTLS). See `.github/workflows/ci.yml`.

## Repository layout

```text
crates/     Rust crates — VMM core, networking, image, init, sandbox, host, proto, api-types
apps/       The mm CLI
services/   Long-running services — control plane (controller) and host agent
scripts/    Dev/CI helpers — fixtures, dev certs, dropbear build, cluster e2e
docs/       Specification (docs/specs) and implementation plans (docs/plans)
```

## Documentation

- `docs/specs/SPEC-1-micromachines.md` — the full 1.0 specification (requirements,
  milestones, risks).
- `docs/plans/` — per-milestone implementation plans and design notes.
- `docs/MicroMachines.md` — product overview.

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
