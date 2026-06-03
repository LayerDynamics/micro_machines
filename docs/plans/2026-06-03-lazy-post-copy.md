# Lazy post-copy branching (FR-16 Phase 2)

**Date:** 2026-06-03
**Status:** Engine written (`crates/mm-vmm/src/snapshot/lazy.rs`); impure wiring + KVM e2e remain.
**Tracks:** the last of the three deferred FR-16 milestones. #1 (out-of-jail uffd) and #2
(clone networking) + #3a (WP-assert gate) are shipped + CI-green; this is #3b.

## Goal

Phase-1 `Machine::branch` materializes a **complete** T-copy of the running parent's RAM
into the branch file (concurrent with the parent — no freeze — but still writes all of
guest RAM, and children `MAP_PRIVATE`-CoW the full file). Lazy post-copy avoids the eager
full copy: the parent stays write-protected for the branch's lifetime; the branch file
holds **only** the pages the parent overwrites (their T-version, preserved on the write
fault); a child's guest RAM is served **on demand** — each page faulted in from the branch
file if the parent has diverged it, else read straight from the parent's still-T RAM.
Untouched pages are never copied.

## Provenance invariant (the correctness core — already unit-tested via `branch_core`)

Per guest page `p`, the parent's WP handler orders: **copy `p`'s T-version to the file →
mark present → remove write-protection**. Therefore:
- `p` not-present ⇒ still WP'd in the parent ⇒ parent RAM at `p` still holds T ⇒ a child
  reads it from the parent. (A racing parent write is blocked by WP until T is preserved.)
- `p` present ⇒ T-version is in the file ⇒ child reads the file.

A child's missing-page handler checks "present?" first; if not, it reads the parent's RAM,
which is guaranteed still-T by the WP block. Single handler thread per child ⇒ faults are
serviced serially (no same-page race).

## Lifecycle

The parent (and its WP handler) **must outlive every lazy child** — children read the
parent's live RAM for not-yet-diverged pages. Teardown order: stop all children + their
handlers, then `LazyBranch::finish` (stop the WP handler + disarm WP over all regions).

## What's written (`snapshot/lazy.rs`, `#[cfg(feature = "branch")]`)

`LazyBranch`:
- `arm(uffd, regions, branch_path)` — WP-arm the (pre-registered, via
  `branch::create_registered_uffd`) parent uffd, create the sparse branch file, spawn the
  persistent `wp_handler_loop` (preserve-on-write, no eager copier). Call while the parent
  is paused at the checkpoint barrier; caller resumes after.
- `spawn_child_handler(child_regions, child_stop)` — register a MISSING-mode uffd over the
  child's (already-allocated, anonymous) guest RAM and spawn `child_handler_loop` (serve
  file-or-parent per the invariant). Returns the handler `JoinHandle`.
- `preserved_count()`, `finish()` (disarm + join).

Reuses `branch_core::{PreserveMap, RegionMap, PAGE_SIZE}` (the proven pure coordination).

## Remaining wiring (the impure, KVM-only, locally-unverifiable part)

1. `snapshot/mod.rs`: `#[cfg(feature = "branch")] pub(crate) mod lazy;`.
2. `Machine::branch_lazy(&mut self, out_dir) -> Result<LazyBranch>`: `quiesce_at_barrier(true)`
   → capture `VmState` (collect_vcpu/device/clock/irqchip) + `write_snapshot_metadata`
   (state.bin + manifest, memory_file="memory.bin") → source the uffd (stashed `branch_uffd`
   or `create_registered_uffd`) → `LazyBranch::arm(uffd, &self.guest_ram_regions(), &mem_file)`
   → `release_barrier` → return the `LazyBranch` (parent keeps running, WP-armed).
3. `Machine::fork_lazy(lazy, config, state, child_stop) -> Result<(Machine, JoinHandle)>`:
   `allocate_guest_memory(config.memory_mib)` (anonymous) → regions = its
   `iter().map(|r| (r.as_ptr() as usize, r.len()))` → `lazy.spawn_child_handler(&regions,
   child_stop)` (registers uffd-missing + spawns handler) → `with_resources_memory(config,
   Kvm::new()?, vec![], guest_memory)` → `resume_from_state(state.clone())`. Return
   `(machine, handler)`.
4. KVM e2e in `fork_kvm.rs` (the gate): boot a sandbox parent; `branch_lazy`; `fork_lazy` a
   child; `mm exec`/marker the child (proves it runs from lazily-served RAM); assert the
   child sees the **T-version** marker (not the parent's post-branch divergence) AND the
   parent keeps running + diverges; assert `lazy.preserved_count()` < total (laziness — not
   every page copied); teardown leaves the parent runnable (`finish`). `--test-threads=1`.

## Blind-API risks to verify FIRST (cheap probes before the full build)

These are why this is a focused-session build, not a confident one-shot:
- **userfaultfd MISSING mode delivering a KVM guest's EPT fault** to a user handler on the
  CI kernel (Phase-0 proved WP-mode does; MISSING is the Firecracker uffd-restore mechanism
  but unproven here). A tiny probe (register anonymous mem missing-mode, have a KVM guest
  read it, observe the fault + UFFDIO_COPY) de-risks the whole thing — mirror the existing
  `uffd_wp_on_live_guest_is_supported` probe.
- `userfaultfd` crate API exacts: `Uffd::register` (missing default), `uffd.copy(src,dst,len,
  wake)` return/`Error` shape, `read_event` `Pagefault` (no `kind` filter for missing).
- `vm_memory` anonymous `GuestMemoryMmap` region host-addr stability across the move into
  `with_resources_memory` (same as the proven CoW-fork path, so low risk).
- A wrong guess hangs the guest ⇒ CI timeout; debug via the in-process `eprintln` method
  that cracked the fork-exec stalls (instrument both handler + guest console under
  `--nocapture`).

## Why this is gated behind the two functional milestones

#1 + #2 closed real functional gaps (jailed WP branch; clone IP reachability) and are green.
Lazy post-copy is a **performance optimization** on the already-working, now-jailed branch
(children already demand-page the full file via the OS page cache + CoW). Its value is
avoiding the eager full-RAM file write at branch time, at the cost of parent-outlives-children
lifecycle + per-child handlers. Worth doing, but correctly — hence the probe-first plan.
