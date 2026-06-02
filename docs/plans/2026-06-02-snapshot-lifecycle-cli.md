# Snapshot lifecycle CLI + worker-triggered creation

**Date:** 2026-06-02
**Status:** Design (foundation landed; creation path pending)
**Tracks:** M3 follow-up #6 (snapshot GC/retention + cross-host restore)

## Goal

Make snapshots a first-class, user-managed resource: create a snapshot of a running
single-host microVM, list/inspect them, restore one into a fresh microVM, and prune old
ones — all through the `mm` CLI, backed by an on-disk store with retention.

## What already exists (landed)

- **Snapshot/restore engine** (`mm_vmm::snapshot::{snapshot, restore}`) — pause a live
  `Machine`, capture vCPU + irqchip/PIT + XCR0 + TSC-deadline + device + clock state,
  dump RAM, and restore it into a fresh, *live* VM. Proven by `snapshot_kvm` and the
  fork exec-independence tests.
- **Cross-host restore guard** (`HostFingerprint` in the manifest) — restore refuses a
  host whose CPU feature set differs (would crash the guest). Commit `d48be5a`.
- **Snapshot store + retention** (`mm_vmm::snapshot::SnapshotStore`) — owns
  `<state_root>/snapshots/<machine>/<id>/`, allocates snapshot dirs, lists newest-first
  (skipping partial dirs), finds by id, and `gc(keep N)`. Commit `ead6f86`,
  unit-tested.

The gap is **wiring**: the engine needs a *live `Machine`* to snapshot, but `mm run`
detaches the VMM into a jailed worker process (`mm_host::launch` → `__vmm-worker`), so
the `mm` CLI never holds the `Machine`. Creation therefore needs the worker to do it
on request.

## Design

### 1. Worker control channel (the keystone)

Mirror the existing vsock exec bridge: the privileged parent binds a **control UDS**
(`<jail>/control.sock`, outside the chroot) before launch and passes its fd to the
worker (alongside `kvm_fd` 10 / `tap_fd` 11 / `vsock_fd` 12 → `control_fd` 13). The
worker, after boot, runs a small control loop on that socket in parallel with its
reaper:

- `SNAPSHOT <dir>\n` → pause the `Machine`, run `snapshot()` into `<dir>` (a store dir
  the parent created), resume (or stay paused per a flag), reply `OK\n` / `ERR <msg>\n`.

This requires the worker to hold the `Machine` behind a handle its control loop can
reach (today `boot_jailed` returns the `Machine` to `run_worker`, which waits/reaps —
move the `Machine` behind an `Arc<Mutex>`/command channel so the control loop can pause
+ snapshot it without racing the vCPU/reaper threads). `snapshot()` already quiesces
vCPUs + devices, so the coordination is: control loop takes the snapshot lock → engine
pauses/captures → releases.

### 2. `mm snapshot` CLI surface

- `mm snapshot create <name> [--keep N]` — look up the running machine (local `Store`),
  `SnapshotStore::new_snapshot_dir(name)`, connect to its control UDS, send
  `SNAPSHOT <dir>`, then optionally `gc(name, keep)`. Prints the new snapshot id.
- `mm snapshot ls <name>` — `SnapshotStore::list` → table (id, created, RAM, kind).
- `mm snapshot rm <name> <id>` — `SnapshotStore::remove`.
- `mm snapshot gc <name> --keep N` — `SnapshotStore::gc`.

### 3. `mm restore <name> <id>`

Resolve the snapshot dir via the store, then boot a fresh microVM from it through the
jailed restore path (`mm_host` launch wired to `mm_vmm::snapshot::restore` instead of a
cold boot), reusing the same rootfs/net/vsock the snapshot was taken with. The
cross-host guard already fires here (refuses an incompatible CPU).

## Sequencing / tasks

1. Worker control channel: parent binds `control.sock`, passes fd; worker control loop
   with the `SNAPSHOT` verb; `Machine` reachable from the control loop. **(largest)**
2. `mm snapshot create` end-to-end + a KVM e2e (`mm run --sandbox` → `mm snapshot
   create` → assert a store dir with a valid manifest appears).
3. `mm snapshot ls/rm/gc` over the store (thin; unit-testable).
4. `mm restore <name> <id>` via the jailed restore path + a KVM e2e (restore → guest
   alive + exec-able, reusing the fork/restore harness).
5. Retention wired into `create --keep` and a standalone `gc`.

## Out of scope (separate efforts)

- Cluster snapshot/restore (controller→agent), like cluster exec but for snapshots.
- Full cross-host *migration* (TSC scaling + CPUID normalization) — the guard refuses
  incompatible restores; migrating across CPUs is a larger feature.
- Diff/incremental snapshots (the manifest already models `SnapshotKind::Diff`).
