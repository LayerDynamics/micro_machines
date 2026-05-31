# SPEC-1: MicroMachines

> A Rust, KVM-based virtual machine monitor that runs secure multi-tenant microVMs with a container UX, built-in GitOps, automatic IP/SSH access, a built-in agent/app Sandbox Mode, and a build-target matrix that compiles a workload into a microVM, a self-contained executable, or a unikernel image.

**Date:** 2026-05-31
**Author:** layerdynamics@proton.me + Claude
**Status:** Draft
**Version:** 1.0

---

## How to read this spec

MicroMachines 1.0 is deliberately a **broad** product: the maintainer has chosen to treat every headline capability as a 1.0 goal rather than trim scope up front. To keep that honest, the requirements record the **full 1.0 vision** (every selected capability is a MUST), while the realism lives in two places:

- **§5 Milestones** sequences the work as a *walking skeleton first* — the hard, load-bearing VMM core proven end-to-end on a single host — followed by independently valuable milestones. Each milestone is sized for a solo maintainer.
- **§7 Risks** names *"maximal 1.0 scope vs. solo / open-ended capacity"* as the #1 risk, with an explicit cut-list to apply under timeline pressure.

So "everything is a MUST" means *everything is in the 1.0 north star and nothing is silently dropped* — not *everything ships in the first release at once*.

The `development/reference_only/` projects (firecracker, ignite, flintlock, ravel, unik, krunvm, muvm, nvrc, ssh-hypervisor, microvm.nix, bake, forkd, shuru, HyperVisor, firecracker-demo, firecracker-init-lab, awesome-microvm) are cited throughout as **prior art and feasibility evidence only**. They are never imported, vendored, or copied — they prove an approach is achievable and inform design; the implementation is original.

---

## 1. Background

### 1.1 Problem Statement

Teams that want to run untrusted or multi-tenant code today face a forced choice:

- **Containers** are fast and ergonomic but share the host kernel — a weak boundary for genuinely untrusted workloads (AI agents executing arbitrary code, multi-tenant CI, customer functions).
- **Full VMs** give a hardware-grade isolation boundary but are heavy, slow to boot, and operationally clumsy — nothing like the `docker run` experience developers expect.
- **Existing microVM tooling is fragmented.** Firecracker provides a superb minimal VMM but no orchestration, no image UX, no GitOps, and no build pipeline. Ignite layered a container UX and GitOps over Firecracker but is deprecated and Go-based. Flintlock is a lifecycle service with no UX. Ravel is an orchestrator with no build story. unik compiles unikernels but doesn't run a fleet. bake embeds a microVM in an executable but isn't a platform. forkd does fast snapshot/fork sandboxing but only that. A team that wants *all* of these stitches together five projects in three languages.

MicroMachines unifies the microVM lifecycle — **build, run, network, orchestrate, and sandbox** — behind one container-like UX with VM-grade isolation, in a single Rust-first stack.

### 1.2 Current State

- **Industry:** The capabilities exist but are scattered (see §1.1). No single project delivers VMM core + container UX + GitOps + auto-networking + a build-target matrix + a fast sandbox in one coherent, isolation-first product.
- **This repository:** A greenfield scaffold. The Cargo workspace root (`Cargo.toml`) and pnpm workspace root (`pnpm-workspace.yaml`) are present but empty; `apps/ crates/ data/ packages/ services/ tools/ vms/` are empty. The only substantive content is `development/reference_only/` (prior art) and the project description in `README.md` / `docs/MicroMachines.md`. There is no MicroMachines code yet; this spec defines what to build.

### 1.3 Target Users

MicroMachines 1.0 serves a **general microVM toolkit** audience — three concrete personas, all first-class:

| Persona | Need | Marquee capability for them |
|---------|------|------------------------------|
| **AI-agent platform builder** | Run untrusted agent-generated code in fast, ephemeral, isolated sandboxes at fan-out | Sandbox Mode + snapshot/CoW fork; exec SDK |
| **Self-hosted serverless / PaaS operator** | Deploy OCI images as microVMs with a container UX and declarative GitOps across a fleet | OCI→microVM, control plane, GitOps reconciliation, multi-tenancy |
| **Developer running CI / ephemeral envs** | Boot a workload as a microVM or a single self-contained executable for isolated test/run | Build-target matrix (microVM / executable / unikernel), auto IP/SSH |

### 1.4 Motivation

- **Untrusted-code isolation is now a mainstream need.** The explosion of agentic systems executing model-generated code makes a container-grade UX over a VM-grade boundary valuable *now*, not eventually.
- **The prior art proves every piece is feasible** (Firecracker's VMM, Ignite's UX+GitOps, forkd's ~100 ms CoW fan-out, bake's embed-in-executable, unik's unikernel pipeline) — but no one has unified them. The opportunity is integration, in a memory-safe systems language.
- **Rust is the right substrate.** The mature `rust-vmm` crate ecosystem (used by Firecracker, Cloud Hypervisor, krunvm, muvm) means the VMM core can be built on proven, audited building blocks rather than from scratch.

### 1.5 Assumptions

- A1: Hosts run Linux with KVM available (`/dev/kvm`), kernel ≥ 5.10, on `x86_64` or `aarch64`.
- A2: Guests are Linux. (Windows/macOS guests are an explicit non-goal — §2.4.)
- A3: An OCI registry / containerd is available for image pull; OCI images are the primary rootfs source.
- A4: Operators can grant the per-host agent the privileges a VMM requires (`/dev/kvm`, networking, cgroup v2), within a jailer-confined boundary.
- A5: The maintainer can vendor or build a compatible guest kernel and a minimal guest init; a stock distro kernel is acceptable for V1.
- A6: Userfaultfd (`UFFD_WP`) and the kernel features required for fast CoW fork are available on target kernels (≥ 5.7 for write-protect faults).

---

## 2. Requirements

### 2.1 Functional Requirements

All capabilities below are **1.0 (MUST) goals** — the user confirmed the full set. The *order* in which they are delivered is defined in §5, not by demotion here. IDs are grouped by subsystem.

#### VMM core & boot

| ID | Priority | Requirement |
|----|----------|-------------|
| FR-1 | MUST | The system MUST run a Linux guest as a KVM microVM using a native Rust VMM built on the `rust-vmm` crate ecosystem (no external VMM binary required for the core path). |
| FR-2 | MUST | The VMM MUST load a guest kernel and rootfs directly (no firmware/bootloader stage) and boot to guest userspace. |
| FR-3 | MUST | The VMM MUST present a minimal virtio device model: block, net, vsock, and balloon, plus a serial console and the minimal legacy devices required to boot. |
| FR-4 | MUST | Each microVM MUST be configurable for vCPU count, memory size, kernel image, kernel cmdline, rootfs, and attached devices via a typed configuration object. |
| FR-5 | MUST | The system MUST provide a minimal Rust guest init (PID 1) that mounts core filesystems, brings up networking, parses configuration from the kernel cmdline and/or a vsock boot channel, launches the workload, and powers off the VM fail-fast on workload exit or panic. |

#### Container UX & images

| ID | Priority | Requirement |
|----|----------|-------------|
| FR-6 | MUST | The system MUST import an OCI/Docker image and use it as a microVM root filesystem (ext4 or squashfs), with a read-only base layer and a writable ephemeral overlay per instance. |
| FR-7 | MUST | The system MUST manage three object kinds — `Image`, `Kernel`, and `Machine` (microVM) — with Kubernetes-style metadata (name, uid, namespace, labels, annotations, timestamps). |
| FR-8 | MUST | The CLI MUST provide container-like verbs: `run`, `ps`, `start`, `stop`, `rm`, `logs`, `ssh`, `exec`, `images`, `kernels`. |
| FR-9 | MUST | Each `Machine` MUST follow a spec/status model: `spec` is the desired state (incl. `running`), `status` is observed actual state (incl. assigned IP, lifecycle state, health). |

#### Networking & access

| ID | Priority | Requirement |
|----|----------|-------------|
| FR-10 | MUST | The system MUST provision guest networking automatically: a host bridge, a per-VM TAP/veth interface, NAT/masquerade for egress, and IP allocation from a managed pool (IPAM), with no manual plumbing required. |
| FR-11 | MUST | The system MUST configure the guest IP via kernel `ip=` boot parameter (no in-guest DHCP/cloud-init dependency), compatible with a read-only rootfs. |
| FR-12 | MUST | The system MUST provide automatic SSH/console access to a guest (`mm ssh <machine>`) without the operator manually injecting keys or configuring a guest sshd, using key injection and/or a vsock-fronted access path. |

#### Sandbox Mode & snapshot/fork

| ID | Priority | Requirement |
|----|----------|-------------|
| FR-13 | MUST | The system MUST provide a Sandbox Mode that runs an agent/app inside a microVM and exposes an exec API (run command, stream stdout/stderr, return exit code) over vsock and/or an in-guest agent. |
| FR-14 | MUST | The system MUST snapshot a paused microVM (memory + device + vCPU state) and restore it. |
| FR-15 | MUST | The system MUST fork many children from a warmed parent snapshot using copy-on-write memory sharing, so fan-out cold-start meets the target in NFR-perf. |
| FR-16 | SHOULD | The system SHOULD support branching a *running* sandbox (pause, diff-snapshot in-flight state, resume + fork) to enable speculative fan-out. |

#### GitOps & control plane

| ID | Priority | Requirement |
|----|----------|-------------|
| FR-17 | MUST | The system MUST run a multi-host control plane (control plane + per-host agents) that schedules and tracks microVMs across a cluster. |
| FR-18 | MUST | The control plane MUST expose a public REST/JSON API organized as `Namespace → Fleet → Machine`, plus `Image`, `Kernel`, `Snapshot`, `Disk`, and `Secret` resources. |
| FR-19 | MUST | The control plane and agents MUST communicate over gRPC, with the agent reporting host capacity/health and reconciling assigned microVMs against desired state. |
| FR-20 | MUST | The system MUST provide built-in GitOps: watch a Git repository of declarative manifests, run a reconciliation loop that drives actual state toward `spec`, and react to create/modify/delete of manifests. |
| FR-21 | SHOULD | GitOps MUST support drift reporting and SHOULD support bidirectional sync (committing operator/CLI-induced changes back to Git). |
| FR-22 | MUST | The control plane MUST persist desired and observed state durably (relational store), and survive control-plane restarts without destroying running data-plane microVMs. |

#### Build-target matrix

| ID | Priority | Requirement |
|----|----------|-------------|
| FR-23 | MUST | The build system MUST compile a workload into a **microVM artifact** (kernel + rootfs + machine manifest) runnable by the VMM. |
| FR-24 | MUST | The build system MUST compile a workload into a **self-contained executable**: a single ELF that embeds VMM + kernel + rootfs and is dual-mode (host launcher when PID≠1, guest init when PID=1). |
| FR-25 | MUST | The build system MUST compile a workload into a **unikernel image** (lightweight bootable disk image) via a pluggable compiler/provider toolchain abstraction. |
| FR-26 | MUST | The build system MUST accept a declarative build manifest (TOML/YAML) describing target, resources, kernel, entrypoint, args, and env. |

#### Security & multi-tenancy

| ID | Priority | Requirement |
|----|----------|-------------|
| FR-27 | MUST | Each microVM process MUST run under a jailer (chroot + namespaces + cgroup v2 resource limits) and a per-thread seccomp-BPF filter installed before guest code executes. |
| FR-28 | MUST | virtio block and net devices MUST support token-bucket rate limiting (bandwidth + ops/sec) for fair multi-tenant sharing. |
| FR-29 | MUST | The API MUST authenticate users via OIDC/JWT, authorize via namespace-scoped RBAC, and secure control-plane↔agent traffic with mTLS. |
| FR-30 | MUST | Tenant isolation MUST be enforced at the namespace boundary in the API and by the KVM/jailer boundary at runtime; one tenant MUST NOT observe or affect another tenant's microVMs. |

#### Node / TypeScript surfaces

| ID | Priority | Requirement |
|----|----------|-------------|
| FR-31 | MUST | The system MUST provide a TypeScript client SDK for programmatic control (machine lifecycle, `sandbox.exec()`, image/snapshot ops) against the public REST API. |
| FR-32 | MUST | The system MUST provide a web dashboard for managing namespaces, fleets, machines, images, GitOps state, and logs. |
| FR-33 | MUST | The system MUST provide a control-plane API gateway service (auth, rate limiting, REST surface) fronting the Rust control plane. |
| FR-34 | MUST | The primary CLI MUST be a Rust binary (`mm`); Node tooling supports build/dev workflows but is not the primary CLI. |

### 2.2 Non-Functional Requirements

#### Performance (NFR-perf) — committed V1 targets

These are MicroMachines' **own committed targets** (the maintainer selected "Firecracker-class"). Reference benchmarks (e.g. forkd's ~100 ms CoW fan-out) are cited elsewhere only as feasibility evidence.

| ID | Metric | Target | Measurement |
|----|--------|--------|-------------|
| NFR-P1 | microVM cold boot to guest userspace | p50 < 125 ms | Instrument VMM start → init "ready" signal over vsock |
| NFR-P2 | Snapshot/fork fan-out (per child, warmed parent) | p50 < 150 ms | Time `fork()` → child init ready, N=100 |
| NFR-P3 | microVM density per host | > 100 concurrent microVMs (subject to RAM) | Load test on a reference 32-core/128 GB host |
| NFR-P4 | Public API latency | p95 < 200 ms (excluding VM boot) | Server-side request histogram |
| NFR-P5 | Per-VM memory overhead (VMM, excl. guest RAM) | < 5 MiB | RSS sampling of jailed VMM process |

#### Reliability (NFR-rel)

| ID | Metric | Target |
|----|--------|--------|
| NFR-R1 | Control-plane availability | 99.95% (HA, leader-elected) |
| NFR-R2 | Data-plane survival of control-plane restart | 100% — running microVMs unaffected by control-plane/agent restart |
| NFR-R3 | Control-plane recovery time objective (RTO) | < 60 s to a healthy leader after failure |
| NFR-R4 | Reconciliation convergence | Desired→actual drift corrected within 30 s of detection under normal load |

#### Security & Compliance

- **AuthN:** OIDC/JWT bearer tokens for users; mTLS (mutual cert auth) between control plane and agents.
- **AuthZ:** Namespace-scoped RBAC (roles: viewer, operator, admin per namespace).
- **Isolation:** KVM hardware boundary + jailer (chroot/namespaces/cgroup v2) + per-thread seccomp-BPF + rate-limited virtio. Read-only base rootfs + ephemeral overlay.
- **Data sensitivity:** Tenant workloads may process arbitrary tenant data; the platform treats all guest memory/disk as sensitive and tenant-private. Secrets are namespace-scoped and never logged.
- **Compliance:** No formal certification targeted for 1.0; design to not preclude SOC2 (audit logging, RBAC, encryption in transit are in scope).
- **Audit:** All state-changing API calls and lifecycle transitions are audit-logged with actor, namespace, resource, and outcome.

#### Scalability (NFR-scale)

- **Cluster size (V1 target):** up to ~100 hosts and ~10,000 concurrent microVMs.
- **Control plane:** horizontally scalable read path; HA via leader election for the reconciliation/scheduling path.
- **Growth:** architecture must not preclude 10× host growth; multi-region/federation is explicitly out of scope for V1 (§2.4).

### 2.3 Constraints

| ID | Constraint |
|----|------------|
| C1 | **Language/runtime:** Rust for VMM core, agent, control plane, build system, guest init, and primary CLI. TypeScript/Node (pnpm workspace) for SDK, web dashboard, and API gateway. |
| C2 | **Platform:** Linux + KVM only for V1; `x86_64` and `aarch64`. No macOS/Windows host support. |
| C3 | **License:** Apache-2.0 for the whole project. All dependencies must be license-compatible; `development/reference_only/` code must never be imported or copied (each has its own license). |
| C4 | **VMM foundation:** Build on the `rust-vmm` crate ecosystem; do not reimplement KVM ioctl/memory/loader primitives from scratch. |
| C5 | **Monorepo:** Hybrid Cargo workspace (`crates/`, `services/`, `apps/`, `tools/`) + pnpm workspace (`packages/`). Workspace manifests must be populated as members are added. |
| C6 | **Privilege model:** The data-plane VMM must run unprivileged inside the jailer; privileged setup happens in a separate, auditable step. |

### 2.4 Explicit Non-Goals (V1)

| ID | Non-Goal | Rationale |
|----|----------|-----------|
| NG1 | **Windows/macOS guests** | V1 runs Linux guests only; cross-OS guest support is a large, separable effort. |
| NG2 | **Live migration** | Moving a *running* microVM between hosts with no downtime is excluded. Snapshot/restore (cold move) is in scope; live migration is not. |
| NG3 | **GPU / device passthrough** | PCIe passthrough, GPU acceleration, SR-IOV are excluded from V1. |
| NG4 | **Multi-region / federation** | V1 is a single cluster; cross-region orchestration and cluster federation are excluded. |
| NG5 | **macOS/Windows *host* support** | Native rust-vmm KVM core is Linux-only by construction; the libkrun path that would enable macOS hosts was not chosen. |

---

## 3. Architecture

### 3.1 System Overview

MicroMachines is layered: a **TypeScript edge** (SDK, dashboard, API gateway) over a **Rust control plane**, which orchestrates **per-host Rust agents**, each of which drives the **Rust VMM core** that runs **microVM guests** (booted by a minimal Rust guest init). A separate **build system** produces the three artifact types the runtime consumes.

```
                    ┌──────────────────────────────────────────────┐
                    │                 USERS / CI / AGENTS           │
                    └───────┬───────────────┬───────────────┬───────┘
                            │ REST/JSON      │ Browser       │ TS SDK
                    ┌───────▼───────────────▼───────────────▼───────┐
   TS / Node edge   │  API Gateway   │  Web Dashboard  │  Client SDK │
   (packages/)      │  (auth, RBAC, rate-limit, OIDC/JWT)            │
                    └───────────────────────┬──────────────────────-┘
                                             │ REST  (mTLS terminates here)
                    ┌────────────────────────▼───────────────────────┐
   Rust control     │              CONTROL PLANE  (services/)         │
   plane            │  ┌────────────┐ ┌──────────────┐ ┌───────────┐ │
                    │  │ API server │ │ Scheduler /  │ │ GitOps    │ │
                    │  │ (REST)     │ │ reconciler   │ │ controller│ │
                    │  └────────────┘ └──────────────┘ └───────────┘ │
                    │  State store: PostgreSQL (desired + observed)   │
                    │  HA: leader election                            │
                    └───────────────┬─────────────────────────────────┘
                                    │ gRPC + mTLS (assign / report / stream)
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
     ┌────────▼────────┐   ┌────────▼────────┐   ┌────────▼────────┐
     │  HOST AGENT     │   │  HOST AGENT     │   │  HOST AGENT     │   (apps/ or services/)
     │  - reconcile    │   │   ...           │   │   ...           │
     │  - IPAM/bridge  │   │                 │   │                 │
     │  - image cache  │   │                 │   │                 │
     │  - local store  │   │                 │   │                 │
     │    (embedded KV)│   │                 │   │                 │
     └────────┬────────┘   └─────────────────┘   └─────────────────┘
              │ spawn + jailer + seccomp
     ┌────────▼─────────────────────────────────────────────────────┐
     │                      VMM CORE  (crates/)                       │
     │  vCPU loop (KVM_RUN) │ vm-memory │ virtio: blk/net/vsock/balloon│
     │  linux-loader (boot) │ event-manager (epoll) │ rate limiters    │
     │  snapshot / CoW fork (userfaultfd)                              │
     └────────┬───────────────────────────────────────────────────────┘
              │ KVM ioctls (kvm-ioctls / kvm-bindings)
     ┌────────▼────────┐        ┌──────────────────────────────────┐
     │   Linux / KVM   │        │  GUEST microVM                    │
     │   (/dev/kvm)    │◄──────►│  Rust guest init (PID 1)          │
     └─────────────────┘ virtio │  → mounts, net (ip=), workload    │
                                │  → vsock exec agent (Sandbox Mode)│
                                └──────────────────────────────────┘

     ┌──────────────────────────────────────────────────────────────┐
     │  BUILD SYSTEM (tools/ + crates/)                               │
     │  manifest → { microVM artifact | self-contained ELF | unikernel}│
     │  pluggable compiler/provider abstraction                       │
     └──────────────────────────────────────────────────────────────┘
```

### 3.2 Component Design

#### Component: VMM Core (`crates/mm-vmm`)
- **Responsibility:** Create and run a single KVM microVM — vCPUs, guest memory, virtio device model, boot, and snapshot/fork.
- **Technology:** Rust on the `rust-vmm` ecosystem — `kvm-ioctls`, `kvm-bindings`, `vm-memory`, `vmm-sys-util`, `linux-loader`, `virtio-queue`/`vm-virtio`, `vm-superio`, `vm-allocator`, `event-manager`, `vhost`, `userfaultfd`, `seccompiler` (versions pinned in Cargo manifests, not here).
- **Interfaces:** A typed in-process API (config object + lifecycle calls: configure, boot, pause, resume, snapshot, restore, fork, shutdown); a local control socket for the agent.
- **Dependencies:** `/dev/kvm`, guest kernel + rootfs, the jailer environment.

#### Component: Guest Init (`crates/mm-init`)
- **Responsibility:** Be PID 1 inside the guest — mount core filesystems, bring up loopback + configure the `ip=`-provided NIC, parse config (kernel cmdline + vsock boot channel), set up the overlay root, launch the workload (or the sandbox exec agent), and power off fail-fast on exit/panic.
- **Technology:** Rust, statically linked (musl), no systemd.
- **Interfaces:** Kernel cmdline parameters (`mm.*`), a vsock boot-manifest channel, a vsock exec channel for Sandbox Mode.
- **Dependencies:** The kernel ABI; virtio-vsock.

#### Component: Host Agent (`services/mm-agent`)
- **Responsibility:** Own one host — reconcile the microVMs assigned to it, manage IPAM/bridge/TAP, cache OCI images, enforce cgroup/jailer setup, and report capacity/health to the control plane.
- **Technology:** Rust; embedded KV store (e.g. `redb`/`sled`) for local durable state; gRPC client/stream to the control plane.
- **Interfaces:** gRPC to control plane (assignments in, status/capacity out); local control socket to VMM Core instances; host networking and cgroup v2.
- **Dependencies:** VMM Core, containerd/OCI image source, the control plane.

#### Component: Control Plane (`services/mm-controller`)
- **Responsibility:** Cluster brain — accept desired state via REST, schedule microVMs onto hosts, run the reconciliation loop, run the GitOps controller, and persist all state.
- **Technology:** Rust; PostgreSQL state store; leader election for HA; gRPC server toward agents; REST server toward the gateway.
- **Interfaces:** REST (public, via gateway); gRPC (to agents); Postgres (state); Git (GitOps source).
- **Dependencies:** PostgreSQL, agents, a Git remote.

#### Component: GitOps Controller (within `mm-controller`)
- **Responsibility:** Clone/watch a Git manifest repo, diff manifests against stored desired state, drive reconciliation, report drift, and (optionally) push observed changes back.
- **Technology:** Rust + `git2`.
- **Interfaces:** Git repo (in), control-plane state (out).
- **Dependencies:** Control-plane state store, the reconciler.

#### Component: Build System (`tools/mm-build` + `crates/mm-builder`)
- **Responsibility:** Turn a workload + build manifest into one of three artifacts via a pluggable compiler/provider abstraction.
- **Technology:** Rust. microVM target: assemble kernel+rootfs+manifest. Executable target: embed VMM+kernel+rootfs into a dual-mode ELF (custom sections + memfd). Unikernel target: drive a pluggable unikernel toolchain (compiler+provider interfaces).
- **Interfaces:** CLI + declarative manifest (TOML/YAML).
- **Dependencies:** A guest kernel, a rootfs source, unikernel toolchains (for the unikernel target).

#### Component: API Gateway (`packages/mm-gateway`)
- **Responsibility:** Public edge — terminate user auth (OIDC/JWT), enforce RBAC and rate limits, and expose the REST API surface to SDK/dashboard.
- **Technology:** Node/TypeScript.
- **Interfaces:** REST (public) ↔ control-plane REST/gRPC (internal).
- **Dependencies:** Control plane, an OIDC provider.

#### Component: Web Dashboard (`packages/mm-dashboard`)
- **Responsibility:** Browser UI for namespaces, fleets, machines, images, GitOps state, and logs.
- **Technology:** TypeScript SPA consuming the SDK.
- **Dependencies:** Client SDK, API gateway.

#### Component: Client SDK (`packages/mm-sdk`)
- **Responsibility:** Typed TS client for machine lifecycle, `sandbox.exec()`, image/snapshot operations.
- **Technology:** TypeScript over the public REST API.
- **Dependencies:** API gateway.

#### Component: CLI (`apps/mm`)
- **Responsibility:** Primary operator/developer CLI (`mm run/ps/ssh/exec/build/...`).
- **Technology:** Rust (`clap`).
- **Dependencies:** Control plane (remote) or agent/VMM (local single-host mode).

### 3.3 Data Model

Kubernetes-style objects, each with `metadata` (name, uid, namespace, labels, annotations, created/updated/deleted timestamps), `spec` (desired), and `status` (observed).

```
Namespace 1───* Fleet 1───* Machine *───1 Image
                                │            
                                ├──────1 Kernel
                                ├──────* Snapshot   (parent/child fork tree)
                                ├──────* Disk       (persistent volumes)
                                └──────* (uses) Secret
```

| Entity | Key fields | Notes |
|--------|------------|-------|
| **Namespace** | name, RBAC bindings, quotas | Top-level tenant isolation boundary |
| **Fleet** | namespace, labels, default machine template | Logical grouping of machines |
| **Machine** (microVM) | spec{image, kernel, vcpus, memory, ssh, networking, workload, restart_policy}, status{state, ip, health, host, events[]} | Core runtime object; `state ∈ {created, preparing, starting, running, paused, stopping, stopped, failed, destroying, destroyed}` |
| **Image** | OCI ref, digest, cached rootfs (ext4/squashfs) | Root filesystem source |
| **Kernel** | OCI ref or path, arch, cmdline defaults | Separately versioned from images |
| **Snapshot** | parent uid, memory+device+vcpu state ref, kind{full, diff} | Enables restore and CoW fork; forms a fork tree |
| **Disk** | namespace, size, backing | Persistent volumes |
| **Secret** | namespace, encrypted value | Namespace-scoped, never logged |
| **Host** (agent-reported) | capacity, allocatable, health, labels | Scheduling input; not user-writable |

**Lifecycle & consistency:** Desired state (`spec`) is strongly consistent in PostgreSQL; observed state (`status`) is eventually consistent (agents report asynchronously, reconciler converges). GitOps repo is the source of truth when GitOps mode is enabled for a namespace.

### 3.4 API & Interface Design

**Public REST (via gateway)** — resource hierarchy:

```
POST   /v1/namespaces
GET    /v1/namespaces
POST   /v1/namespaces/{ns}/fleets
GET    /v1/namespaces/{ns}/fleets
POST   /v1/namespaces/{ns}/fleets/{fleet}/machines
GET    /v1/namespaces/{ns}/fleets/{fleet}/machines/{id}
POST   /v1/namespaces/{ns}/fleets/{fleet}/machines/{id}/start
POST   /v1/namespaces/{ns}/fleets/{fleet}/machines/{id}/stop
POST   /v1/namespaces/{ns}/fleets/{fleet}/machines/{id}/exec     # Sandbox Mode
POST   /v1/namespaces/{ns}/fleets/{fleet}/machines/{id}/snapshot
POST   /v1/namespaces/{ns}/fleets/{fleet}/machines/{id}/fork
GET    /v1/namespaces/{ns}/images   |  /kernels  |  /disks  |  /secrets
```

**Internal gRPC (control plane ↔ agent):** `MachineService` (Assign, Delete, Get, List, WatchAssignments), `HostService` (ReportCapacity, Heartbeat, StreamEvents). Spec/status messages mirror §3.3.

**Guest interfaces:** kernel cmdline `mm.*` params (workload path/args, network, mode); vsock ports for boot manifest delivery and the exec channel.

Concrete contracts are detailed in **Appendix B**.

### 3.5 Data Flow

**Flow A — `mm run nginx:latest` (single machine, happy path):**
1. CLI → gateway (`POST .../machines`), auth + RBAC check.
2. Gateway → control plane; control plane writes `Machine{spec.running=true}` to Postgres.
3. Scheduler picks a host; control plane streams an assignment to that host's agent over gRPC.
4. Agent pulls/locates the OCI image, builds the rootfs (RO base + ephemeral overlay), allocates an IP (IPAM), creates bridge/TAP.
5. Agent sets up the jailer + seccomp, spawns a VMM Core instance with the config (kernel `ip=` param, vsock boot channel).
6. VMM Core boots the guest; guest init configures the NIC, launches the workload, signals "ready" over vsock.
7. Agent reports `status{state=running, ip=...}` → control plane → Postgres → visible via `mm ps`.

**Flow B — Sandbox fan-out:**
1. Operator boots a parent microVM with warmup (deps/model loaded), then `snapshot` (FR-14).
2. `fork` N children (FR-15): each child `mmap(MAP_PRIVATE)` the parent memory image; kernel CoW per page; each child gets its own netns/veth/cgroup.
3. SDK calls `sandbox.exec(code)` → control plane/agent → guest exec agent over vsock → returns stdout/stderr/exit code.

**Flow C — GitOps reconciliation:**
1. GitOps controller clones/watches the manifest repo.
2. Manifest create/modify/delete → diff vs stored desired state → update `spec`.
3. Reconciler compares `spec` vs `status`; emits transitions (create→assign→start, delete→destroy, running flip→start/stop) until convergence (NFR-R4); reports drift.

### 3.6 Integration Points

| System | Direction | Purpose |
|--------|-----------|---------|
| OCI registry / containerd | pull | Image source for rootfs |
| Git remote (SSH/HTTPS) | clone/watch/push | GitOps manifests |
| PostgreSQL | read/write | Control-plane state store |
| OIDC provider | verify | User authentication |
| Linux KVM (`/dev/kvm`) | ioctl | VM execution |
| Unikernel toolchains | invoke | Unikernel build target |

### 3.7 Security Architecture

- **Trust boundaries:** (1) user ↔ gateway (OIDC/JWT, RBAC, rate limit); (2) gateway/control plane ↔ agent (mTLS); (3) agent ↔ VMM process (jailer + seccomp); (4) host ↔ guest (KVM + virtio, the primary isolation boundary).
- **Runtime hardening:** every VMM process runs in a jailer (chroot, user/mount/net/pid namespaces, cgroup v2 limits) with a per-thread seccomp-BPF allowlist installed before any guest instruction runs; virtio devices are rate-limited (token bucket).
- **Filesystem:** read-only base rootfs + per-instance ephemeral overlay; no shared writable base across tenants.
- **Secrets:** namespace-scoped, encrypted at rest, injected via vsock/boot channel (not baked into shared images), never logged.
- **Encryption in transit:** mTLS internally, TLS at the gateway.
- Full attacker model and mitigations in **Appendix C**.

### 3.8 Resilience Design

- **Reconciliation as the recovery primitive:** desired state in Postgres is authoritative; on agent/control-plane restart, reconciliation re-converges (NFR-R2/R3).
- **Agent local store:** embedded KV cache lets an agent recover its view of local microVMs without the control plane.
- **Retries/backoff:** gRPC calls and image pulls use bounded exponential backoff; failed machines carry a retry counter and surface `status=failed` after exhaustion.
- **Rate limiting / backpressure:** per-device token buckets (data plane) and per-tenant API rate limits (gateway).
- **Fail-fast guest:** guest init powers off on workload exit/panic — no zombie/undefined guest states.

### 3.9 Observability

- **Logs:** structured JSON (`tracing`) across control plane, agents, VMM; audit log for state-changing API calls.
- **Metrics:** Prometheus endpoints — boot latency, fork latency, density, API latency, reconcile lag, per-host capacity.
- **Tracing:** OpenTelemetry spans across gateway → control plane → agent → VMM for request flows.
- **Alerting:** triggers in §6.3.

### 3.10 Infrastructure & Deployment

- **Build:** Cargo workspace (`cargo build --workspace`); pnpm workspace (`pnpm -r build`). CI runs fmt, clippy, tests, and KVM-dependent integration tests on Linux runners.
- **Artifacts:** Rust binaries (control plane, agent, CLI, build tool, guest init); Node bundles (gateway, dashboard, SDK package).
- **Environments:** dev (single host), staging (small cluster), prod (HA cluster). Control plane + Postgres deployed HA; agents are a per-host daemon.
- **Deployment strategy:** rolling agent upgrades (drain → upgrade → rejoin); control plane blue-green behind the gateway; data plane unaffected by control-plane redeploys (NFR-R2).

---

## 4. Implementation Plan

### 4.1 Build Phases

The phases below are the delivery sequence for the 1.0 vision. Each is independently valuable and solo-sized; later phases depend on earlier ones (see §5 dependency graph). The **walking skeleton (Phase 1)** proves the hard, load-bearing VMM core end-to-end before breadth is added.

#### Phase 1 — Walking skeleton: hardened single microVM
- **Goal:** Boot one OCI-derived rootfs as a hardened microVM on a single host with auto-IP/SSH, driven by the native Rust VMM core + minimal guest init.
- **Scope:** FR-1..FR-6 (VMM core, boot, virtio blk/net/vsock, OCI→rootfs), FR-10..FR-12 (auto networking + SSH), FR-27 (jailer + seccomp), the `mm run/ps/ssh/stop/rm` CLI verbs (subset of FR-8).
- **Exit criteria:** `mm run <oci-image>` boots to userspace in < 125 ms p50 (NFR-P1), guest gets an IP automatically, `mm ssh` works, VMM runs jailed + seccomped, `mm rm` cleans up. Integration test on a Linux/KVM runner.

#### Phase 2 — Multi-host control plane & reconciliation
- **Goal:** Turn the single-host runtime into a scheduled cluster.
- **Scope:** FR-7, FR-9 (object model + spec/status), FR-17..FR-19, FR-22 (control plane, REST, agent gRPC, Postgres state), scheduler + reconciler, FR-29/FR-30 (mTLS, OIDC/JWT, RBAC, namespace isolation).
- **Exit criteria:** Create a machine via REST; scheduler places it; agent reconciles; survives control-plane restart (NFR-R2); RBAC denies cross-namespace access; reconvergence < 30 s (NFR-R4).

#### Phase 3 — Sandbox Mode + snapshot/fork
- **Goal:** Fast ephemeral sandboxes for agents/apps.
- **Scope:** FR-13 (exec API over vsock), FR-14 (snapshot/restore), FR-15 (CoW fork fan-out), FR-28 (rate-limited devices).
- **Exit criteria:** Snapshot/restore round-trips; fork fan-out p50 < 150 ms (NFR-P2), N=100; `sandbox.exec()` returns correct stdout/stderr/exit code.

#### Phase 4 — Built-in GitOps
- **Goal:** Declarative, Git-driven fleet management.
- **Scope:** FR-20 (watch + reconcile), FR-21 (drift report; bidirectional sync), HA leader election (NFR-R1/R3).
- **Exit criteria:** A manifest repo drives machine create/update/delete; drift is reported; leader failover keeps reconciliation running (RTO < 60 s).

#### Phase 5 — Build-target matrix
- **Goal:** Compile a workload to microVM / executable / unikernel.
- **Scope:** FR-23 (microVM artifact), FR-24 (self-contained dual-mode ELF), FR-25 (unikernel via pluggable toolchain), FR-26 (declarative build manifest).
- **Exit criteria:** All three targets build from one manifest and run; the self-contained ELF boots its embedded microVM with no external files.

#### Phase 6 — Node edge: SDK, dashboard, gateway
- **Goal:** Complete the TypeScript surfaces and polish the product.
- **Scope:** FR-31 (SDK), FR-32 (dashboard), FR-33 (API gateway), FR-34 (CLI parity), FR-16 (running-sandbox branch — SHOULD).
- **Exit criteria:** SDK drives lifecycle + `sandbox.exec()`; dashboard manages namespaces/fleets/machines/GitOps/logs; gateway enforces auth/RBAC/rate-limit end-to-end.

### 4.2 Testing Strategy

- **Unit:** Rust crate tests (VMM config, IPAM, reconciler logic, build manifest parsing); TS unit tests for SDK/gateway.
- **Integration (KVM-gated):** real boot/snapshot/fork on Linux/KVM CI runners; agent↔control-plane gRPC; OCI→rootfs.
- **End-to-end:** full path browser/SDK → gateway → control plane → agent → real microVM → observable result (no mocked layers), per the project's E2E definition. E.g. "create machine via SDK, assert it boots, gets an IP, `exec` returns expected output, `rm` cleans up."
- **Load:** density (NFR-P3) and fork fan-out (NFR-P2) benchmarks; API latency (NFR-P4).
- **Security:** seccomp-filter coverage tests, jailer escape attempts, cross-namespace RBAC denial tests, rate-limit enforcement; regression tests for every fixed isolation bug.

### 4.3 Rollout Strategy

- Pre-1.0 milestone tags (M1…M6) shipped as the phases complete; each tag is independently usable (single-host from M1, cluster from M2, etc.).
- Feature-gate incomplete subsystems behind config flags so a tag never exposes a half-built capability as ready.
- Agent upgrades roll host-by-host with drain; control plane blue-green; data plane untouched.

### 4.4 Operational Readiness

Before a production 1.0: metrics/dashboards live (boot, fork, density, API, reconcile lag); audit logging on; runbooks for agent-down, control-plane-failover, image-pull-failure, and IP-pool-exhaustion; leader-election failover drilled; backup/restore for Postgres validated.

---

## 5. Milestones

| Milestone | Goal | Exit Criteria | Target | Owner |
|-----------|------|---------------|--------|-------|
| **M1** Walking skeleton | Hardened single microVM, auto IP/SSH, Rust VMM core + init | Phase 1 exit criteria met; KVM integration test green | Open-ended | Core maintainer |
| **M2** Cluster control plane | Multi-host scheduling + reconciliation + auth | Phase 2 exit criteria; survives CP restart; RBAC enforced | After M1 | Core maintainer |
| **M3** Sandbox + snapshot/fork | Fast ephemeral sandboxes | Phase 3 exit; fork p50 < 150 ms @ N=100 | After M1 | Core maintainer |
| **M4** GitOps | Declarative Git-driven fleet + HA | Phase 4 exit; leader failover RTO < 60 s | After M2 | Core maintainer |
| **M5** Build-target matrix | microVM / executable / unikernel | Phase 5 exit; all three build + run from one manifest | After M1 | Core maintainer |
| **M6** Node edge | SDK + dashboard + gateway; 1.0 | Phase 6 exit; full E2E green; docs complete | After M2, M3 | Core maintainer + community |

### Dependency Graph

```
            ┌──────────────┐
            │ M1 skeleton  │  (native VMM core — the load-bearing risk)
            └──┬───┬───┬───┘
               │   │   │
      ┌────────┘   │   └─────────┐
      ▼            ▼             ▼
┌───────────┐ ┌──────────┐ ┌──────────────┐
│ M2 cluster│ │ M3 sandbox│ │ M5 build-matrix│
└────┬───┬──┘ └────┬─────┘ └──────────────┘
     │   │         │
     ▼   └────┐    │
┌─────────┐  └────▼────────┐
│ M4 GitOps│  │ M6 Node edge │  (needs M2 + M3)
└─────────┘  └──────────────┘
```

M3 and M5 can proceed in parallel with M2 once M1 lands; M4 needs M2; M6 needs M2 + M3. Under timeline pressure, apply the cut-list in Risk R1.

---

## 6. Success Criteria

### 6.1 Launch Metrics

| Metric | Target | Measurement Method |
|--------|--------|--------------------|
| Cold boot to userspace | p50 < 125 ms | VMM start → guest "ready" vsock signal |
| Fork fan-out (warmed) | p50 < 150 ms, N=100 | `fork` → child ready |
| Density per host | > 100 microVMs | Load test, reference host |
| API latency | p95 < 200 ms | Server histogram |
| Control-plane availability | 99.95% | Uptime monitor over rolling 30 days |
| Build-target coverage | 3/3 targets build+run from one manifest | CI build matrix |
| Isolation test suite | 100% pass (no cross-tenant leakage, no jailer escape) | Security CI |

### 6.2 Ongoing Monitoring

- Dashboards: boot/fork latency, density, API latency, reconcile lag, per-host capacity, error rates.
- Review cadence: weekly metrics review pre-1.0; monthly post-1.0.
- Alerts wired to the triggers in §6.3.

### 6.3 Remediation Triggers

| Trigger | Action |
|---------|--------|
| Boot p50 > 125 ms sustained 1 h | Investigate VMM/boot regression; block release |
| Fork p50 > 150 ms @ N=100 | Investigate CoW/userfaultfd path |
| API error rate > 1% over 5 min | Page; check control plane / Postgres |
| Reconcile lag > 60 s | Check leader health / agent connectivity |
| IP pool > 90% utilized | Expand pool / alert operator |
| Any cross-tenant isolation test failure | Halt release; security incident process |

---

## 7. Risks

| ID | Risk | Impact | Likelihood | Mitigation | Contingency |
|----|------|--------|-----------|------------|-------------|
| **R1** | **Maximal 1.0 scope vs. solo / open-ended capacity** — six large subsystems for one maintainer | High | High | Strict milestone gating (M1 walking skeleton first); each milestone independently shippable; **cut-list under pressure (in order): unikernel target (FR-25) → running-sandbox branch (FR-16) → bidirectional GitOps sync (FR-21) → HA leader election (defer to single control-plane instance)** | Ship M1–M3 as an "early access" product; recruit contributors for M4–M6 |
| R2 | Native rust-vmm VMM core is hard to get correct/secure (boot, virtio, snapshot) | High | Medium | Build on proven rust-vmm crates; mirror Firecracker's validated patterns; KVM integration tests from M1; security review of the device model | Temporarily fall back to a libkrun-backed backend behind the VMM abstraction to unblock upper layers |
| R3 | Snapshot/CoW fork depends on kernel features (`userfaultfd`/`UFFD_WP`) and tight memory semantics | Medium | Medium | Gate on kernel ≥ 5.7; isolate fork behind a trait; benchmark early (M3); forkd demonstrates ~100 ms fan-out is achievable | Ship slower snapshot-restore (no live CoW) and optimize later |
| R4 | HA control plane (leader election, consistency) adds distributed-systems complexity | Medium | Medium | Use a battle-tested election mechanism; keep desired-state authority in Postgres; data plane survives CP outage (NFR-R2) | Run single control-plane instance for early milestones (cut-list R1) |
| R5 | Multi-tenant isolation flaw enables guest→host escape or cross-tenant leakage | High | Low | Defense in depth (KVM + jailer + seccomp + rate limits); threat model (Appendix C); mandatory isolation test suite + regression test per fixed bug | Security disclosure process; hotfix + revoke affected images |
| R6 | Unikernel target scope (multiple toolchains/languages) balloons | Medium | Medium | Pluggable compiler/provider abstraction; ship ONE toolchain first, mark others as extension points | Defer additional toolchains post-1.0 (cut-list R1) |
| R7 | OCI/containerd integration friction (image formats, snapshotter) | Low | Medium | Lean on standard OCI tooling; overlay base rootfs to save disk | Support a manual rootfs path as a fallback |

---

## 8. Open Questions

| # | Question | Owner | Due |
|---|----------|-------|-----|
| Q1 | Which guest kernel strategy for V1 — vendor a tuned minimal kernel, or consume a stock distro kernel image? | Core maintainer | Before M1 |
| Q2 | Which embedded KV store for the agent's local state — `redb` vs `sled`? | Core maintainer | Before M2 |
| Q3 | Which leader-election mechanism for HA — Postgres advisory locks vs an external coordinator? | Core maintainer | Before M4 |
| Q4 | First unikernel toolchain to support (e.g. rumprun vs OSv vs a Rust-native unikernel) given Rust workloads dominate? | Core maintainer | Before M5 |
| Q5 | SSH access mechanism — inject keys into guest sshd, or front access via a vsock proxy with no in-guest sshd? | Core maintainer | Before M1 (affects FR-12) |
| Q6 | OIDC provider(s) to support out of the box for V1? | Core maintainer | Before M2 |

---

## Appendices

### Appendix A — Glossary

| Term | Definition |
|------|------------|
| **VMM (Virtual Machine Monitor)** | The userspace process that creates and runs a VM via KVM. |
| **microVM** | A minimal VM with a tiny device model, fast boot, and low overhead. |
| **KVM** | Linux Kernel-based Virtual Machine; the hypervisor interface (`/dev/kvm`) the VMM drives via ioctls. |
| **rust-vmm** | A set of community Rust crates providing reusable VMM building blocks. |
| **virtio** | Paravirtualized device standard (block, net, vsock, balloon) used for guest I/O. |
| **vsock** | Virtio socket — host↔guest communication without a network device. |
| **jailer** | A process that sets up chroot/namespaces/cgroups, then execs the VMM unprivileged. |
| **seccomp-BPF** | A syscall-filtering mechanism restricting what the VMM process may call. |
| **unikernel** | A specialized single-address-space image that boots directly as a VM, compiling app + minimal OS into one bootable disk image. |
| **Snapshot** | Saved memory + device + vCPU state of a paused microVM. |
| **CoW fork** | Spawning child microVMs that share a parent's memory copy-on-write for fast fan-out. |
| **GitOps** | Managing desired system state declaratively from a Git repository via a reconciliation loop. |
| **Reconciliation** | The loop that drives observed state toward desired state. |
| **Fleet / Namespace** | Logical grouping of machines / the tenant isolation boundary. |
| **IPAM** | IP Address Management — automatic allocation of guest IPs from a pool. |
| **Sandbox Mode** | Running an agent/app inside a microVM with an exec API, for isolated untrusted execution. |

### Appendix B — API Contracts

**B.1 Public REST — create a machine**
```http
POST /v1/namespaces/{ns}/fleets/{fleet}/machines
Authorization: Bearer <jwt>
Content-Type: application/json

{
  "metadata": { "name": "web-1", "labels": { "app": "web" } },
  "spec": {
    "image": "docker.io/library/nginx:latest",
    "kernel": "micromachines/kernel:6.1",
    "vcpus": 2,
    "memory_mb": 512,
    "ssh": true,
    "workload": { "entrypoint": "/usr/sbin/nginx", "args": ["-g","daemon off;"], "env": {} },
    "networking": { "mode": "auto" },
    "restart_policy": "on-failure"
  }
}
→ 201 Created
{ "metadata": { "uid": "…", "name": "web-1", "namespace": "{ns}" },
  "status": { "state": "preparing", "ip": null, "health": "unknown", "host": null } }
```

**B.2 Public REST — sandbox exec**
```http
POST /v1/namespaces/{ns}/fleets/{fleet}/machines/{id}/exec
{ "cmd": ["python3","-c","print(2+2)"], "timeout_ms": 5000 }
→ 200 OK
{ "exit_code": 0, "stdout": "4\n", "stderr": "", "duration_ms": 7 }
```

**B.3 Public REST — fork from snapshot**
```http
POST /v1/namespaces/{ns}/fleets/{fleet}/machines/{id}/fork
{ "count": 100, "from_snapshot": "snap-abc" }
→ 202 Accepted
{ "children": ["…uid1…", "…uid2…", "…"] }
```

**B.4 Internal gRPC (sketch)**
```proto
service MachineService {
  rpc Assign(AssignRequest) returns (MachineStatus);
  rpc Delete(MachineRef) returns (Ack);
  rpc Get(MachineRef) returns (Machine);
  rpc List(ListRequest) returns (stream Machine);
  rpc WatchAssignments(HostRef) returns (stream Assignment); // control plane → agent
}
service HostService {
  rpc ReportCapacity(Capacity) returns (Ack);
  rpc Heartbeat(HostRef) returns (Ack);
  rpc StreamEvents(HostRef) returns (stream MachineEvent);
}
message MachineSpec { string image = 1; string kernel = 2; uint32 vcpus = 3;
  uint64 memory_mb = 4; bool ssh = 5; Workload workload = 6; Networking net = 7; }
message MachineStatus { State state = 1; string ip = 2; Health health = 3;
  string host = 4; uint32 retry_count = 5; repeated MachineEvent events = 6; }
enum State { CREATED=0; PREPARING=1; STARTING=2; RUNNING=3; PAUSED=4;
  STOPPING=5; STOPPED=6; FAILED=7; DESTROYING=8; DESTROYED=9; }
```

**B.5 Guest interfaces**
- Kernel cmdline: `mm.workload=/usr/sbin/nginx mm.args="-g 'daemon off;'" ip=10.0.0.5::10.0.0.1:255.255.255.0:web-1:eth0:off mm.vsock_boot_port=13 mm.mode=sandbox`
- vsock ports: boot-manifest delivery (config), exec channel (Sandbox Mode), ready signal.

### Appendix C — Security Threat Model

**Assets:** tenant guest memory/disk, tenant secrets, the host kernel, other tenants' microVMs, the control-plane state store.

**Trust boundaries & threats:**

| Boundary | Threat | Mitigation |
|----------|--------|------------|
| User ↔ Gateway | Forged/replayed tokens; privilege escalation across namespaces | OIDC/JWT verification, namespace-scoped RBAC, rate limiting, audit log |
| Gateway/CP ↔ Agent | MITM, rogue agent joining cluster | mTLS with cert pinning; agent enrollment/attestation |
| Agent ↔ VMM process | Compromised VMM escalates on host | Jailer (chroot/namespaces/cgroup v2) + per-thread seccomp-BPF installed pre-guest; unprivileged VMM |
| Host ↔ Guest (primary) | Guest→host escape via device/hypervisor bug | Minimal virtio surface; rate-limited devices; KVM boundary; keep crates patched; fuzz device emulation |
| Guest ↔ Guest | Cross-tenant info leak (side channels, shared base) | Per-instance ephemeral overlay (no shared writable fs); per-VM netns; cgroup isolation; document microarchitectural side-channel residual risk |
| Secrets | Leakage via logs/images | Namespace-scoped, encrypted at rest, injected via vsock, never logged |

**Residual risks:** microarchitectural side channels (Spectre-class) are not fully eliminated by virtualization; documented and tracked. Untrusted-code execution still depends on a sound KVM/kernel — a kernel 0-day is out of MicroMachines' control but mitigated by jailer + seccomp narrowing of the host attack surface.

**Verification:** isolation test suite is a release gate (§6.3); every fixed isolation bug gets a regression test.

### Appendix D — Decision Log & Risk Register

**D.1 Decision Log**

| # | Decision | Rationale | Alternatives rejected |
|---|----------|-----------|------------------------|
| D1 | Native rust-vmm VMM core (not libkrun) | Matches "a VMM that uses KVM"; max control + feature depth; proven crate ecosystem | libkrun wrapper (less control, but kept as R2 contingency); hybrid |
| D2 | Multi-host cluster from day one | Maintainer requirement; serverless/PaaS persona needs a fleet | Single-host-first (kept as a milestone sequencing, not architecture) |
| D3 | All three build targets are 1.0 goals | Maintainer selected all; core differentiator vs. single-purpose prior art | Trimming to microVM-only |
| D4 | gRPC internal + REST public | Typed/streaming internally (Flintlock); easy public consumption (Ravel) | gRPC-everywhere; REST-everywhere |
| D5 | mTLS + OIDC/JWT + RBAC | Multi-tenant + untrusted posture demands strong authz | API-keys-only; single-tenant trust |
| D6 | Firecracker-class perf targets | Aligns with prior-art-demonstrated feasibility; meaningful product bar | Relaxed / best-effort |
| D7 | Full hardening (jailer + seccomp + rate limits) | Required for untrusted multi-tenant code | KVM+cgroups only |
| D8 | PostgreSQL control-plane store | Strong consistency for desired state; HA-friendly | Embedded-only; etcd |
| D9 | Apache-2.0 | Patent grant; ecosystem norm (Firecracker/Flintlock/Ignite); rust-vmm fit | MIT; AGPL; dual MIT/Apache |
| D10 | Linux/KVM only (no macOS host) | Native rust-vmm core is Linux-bound; avoids libkrun detour | Linux + macOS |

**D.2 Risk Register** — maintained in §7 (R1–R7). R1 (scope vs. capacity) is the top risk and carries the explicit cut-list.
