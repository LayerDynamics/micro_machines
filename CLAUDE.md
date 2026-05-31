# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What MicroMachines is

MicroMachines is a Rust **virtual machine monitor (VMM)** built on the Linux Kernel
Virtual Machine (KVM) that runs microVMs — the same lineage as Firecracker, but
shipping the batteries a typical dev/deploy workflow needs out of the box. Its
defining product traits:

- **Container UX over real VM isolation** — multi-tenant, secure, serverless-style
  operation that *feels* like containers but boots actual microVMs.
- **Built-in GitOps management** — declarative, Git-driven lifecycle, not a bolt-on.
- **Automatic internal IP/SSH access** — guests are reachable without manual network
  plumbing.
- **Multiple build targets** — a workload can be compiled into a self-contained
  executable, a **unikernel** (lightweight bootable disk image), or a MicroVM, rather
  than only a plain binary.
- **Sandbox Mode** — run agents/apps *inside* the sandboxed guest environment.

When reasoning about a change, anchor it to one of these five traits. If a proposed
design doesn't serve VM isolation, GitOps, zero-config networking, the build-target
matrix, or sandboxing, question whether it belongs here.

## Current repository state (read this first)

This is a **greenfield scaffold**. As of now, every source directory is empty and both
workspace manifests are zero-byte placeholders:

- `Cargo.toml` (empty) — intended as the **Rust workspace root**.
- `pnpm-workspace.yaml` (empty) — intended as the **pnpm/JS-TS workspace root**.
- `apps/  crates/  data/  packages/  services/  tools/  vms/` — all empty.

So MicroMachines is a **hybrid monorepo**: a Rust workspace (the VMM core and anything
touching KVM) alongside a pnpm-managed JS/TS workspace (likely tooling, CLI surface,
GitOps/control-plane services). When you create the first crate or package, you must
also populate the corresponding workspace manifest — neither is wired up yet.

Do not invent or assume code that isn't here. Verify the actual tree before claiming a
module exists or is missing — most of it has not been written.

### Intended layout (inferred from directory names — confirm/establish as you build)

| Dir         | Workspace | Purpose                                              |
|-------------|-----------|------------------------------------------------------|
| `crates/`   | Cargo     | Rust crates — VMM core, KVM glue, unikernel builder  |
| `apps/`     | mixed     | End-user applications / binaries                     |
| `services/` | mixed     | Long-running services (GitOps controller, API)       |
| `packages/` | pnpm      | JS/TS libraries                                      |
| `tools/`    | mixed     | Developer/build tooling                              |
| `vms/`      | —         | VM image definitions / unikernel artifacts           |
| `data/`     | —         | Data / fixtures                                      |

## `development/reference_only/` — hard constraint

`development/reference_only/` holds 17 cloned upstream projects kept for **inspiration
and context ONLY**. **Never import, copy, vendor, or build against them directly.** Each
carries its own license. Read them to understand prior art, then write original code.

These references map onto MicroMachines' feature set — use them as the relevant prior art
when implementing a given area:

- **`firecracker`**, **`firecracker-demo`**, **`firecracker-init-lab`** — the core
  KVM-based microVM/VMM model.
- **`ignite`** (Weave Ignite) — the closest overall analog: Firecracker microVMs with a
  container UX plus GitOps. Primary reference for the product's headline combination.
- **`flintlock`** — microVM lifecycle management / declarative control plane.
- **`ravel`** — Fly.io-style microVM orchestration (Go).
- **`unik`** — unikernel compilation (the "compile to bootable disk image" target).
- **`krunvm`**, **`muvm`** — libkrun-based microVMs (self-contained executable target).
- **`ssh-hypervisor`** — automatic SSH/console access into guests.
- **`nvrc`** — minimal guest init / early boot.
- **`microvm.nix`** — declarative microVM definitions.
- **`forkd`**, **`bake`**, **`shuru`**, **`HyperVisor`**, **`awesome-microvm`** — assorted
  VMM/build/orchestration prior art.

## Build & test commands

No code exists yet, so these are the workspace-level commands that will apply once crates
and packages are added. The platform target is **Linux/KVM** — the VMM core cannot run on
macOS (this dev machine is macOS; KVM-dependent code must be built/run on a Linux host or
VM, and such commands need to be provided rather than run locally).

Rust (from repo root, operates on the Cargo workspace):

```bash
cargo build --workspace            # build all crates
cargo test --workspace             # run all tests
cargo test -p <crate> <test_name>  # run a single test in one crate
cargo clippy --workspace --all-targets   # lint
cargo fmt --all                    # format
```

JS/TS (pnpm workspace):

```bash
pnpm install                       # install across the workspace
pnpm -r build                      # recursive build
pnpm -r test                       # recursive test
pnpm --filter <package> test       # test a single package
```

As real build/lint/test entry points get defined (Makefiles, cargo aliases, package
scripts), document the exact invocations here and replace these defaults.
