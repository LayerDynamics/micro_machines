# FR-16: branch a running sandbox via userfaultfd write-protect (UFFD_WP)

**Date:** 2026-06-02
**Status:** Phase 0 PASSED — feasibility confirmed on the CI kernel; Phase 1 (engine) unblocked.
**Tracks:** M3 follow-up #5 (FR-16 running BRANCH) / #7 (UFFD_WP), now in scope by request.

## Phase 0 result (2026-06-02) — FEASIBLE

The feasibility probe (`uffd_wp_on_live_guest_is_supported` in
`crates/mm-vmm/tests/fork_kvm.rs`, fork-integration CI job) passed:

```
FR-16 UFFD_WP probe: observed 1 write-protect fault(s) from the live guest
test uffd_wp_on_live_guest_is_supported ... ok
```

A **full** (`user_mode_only(false)`) userfaultfd registered over the running guest's
RAM in write-protect mode **does** receive `WriteProtected` faults for the guest's own
writes (faulted out via EPT through KVM in kernel context). So the hard open question is
answered yes on this kernel, and the rest of this plan (Phase 1+) is unblocked.

Two harness requirements the probe surfaced, load-bearing for the engine too:
- The uffd must be **non-user-mode-only** — a `UFFD_USER_MODE_ONLY` uffd never sees the
  guest's kernel-context faults (it would falsely observe zero).
- It needs an **accessible `/dev/userfaultfd`** (or `CAP_SYS_PTRACE` / the
  `vm.unprivileged_userfaultfd=1` sysctl). The userfaultfd crate does not fall back to
  the `userfaultfd(2)` syscall once the device node exists, so a root-only device node
  yields `OpenDevUserfaultfd(EACCES)`. CI grants the runner user access to it.

## Goal

Fork children off a **running** parent microVM at a consistent point-in-time **without
pausing the parent for a full RAM dump**. Today's fork (`Machine::fork`) forks a
*paused snapshot*: the parent is frozen, its RAM is dumped to a file, and each child
`MAP_PRIVATE`-maps that file (proven, p50 < 1 ms/child). BRANCH removes the dump and
keeps the parent live — the source-pause shrinks to just capturing vCPU/device state
and arming write-protection.

## Mechanism (source-driven copy-on-write)

At branch time T, for the parent's guest RAM regions (host mmaps, `region.as_ptr()`):

1. **Brief pause** the parent vCPUs and capture vCPU + irqchip/PIT + XCR0 +
   TSC-deadline + device + clock state (the same capture the snapshot engine already
   does — *no RAM dump*).
2. **Arm WP:** register the parent's RAM with `userfaultfd` in write-protect mode and
   `write_protect` the whole range.
3. **Resume** the parent.
4. **Children** are created sharing the parent's pages copy-on-write. The novel part is
   the **source's** writes: when the *parent* writes a WP'd page, a `UFFD_WP` pagefault
   fires; the handler thread copies the **pre-write (T-version)** page into the branch
   backing the children read from, then `write_unprotect`s that page so the parent
   proceeds. Children thus keep the T-snapshot of any page the parent later changes,
   while untouched pages stay shared (the lazy savings).

A handler thread loops on `uffd.read_event()`; on `Event::Pagefault{ kind: WriteProtect,
addr }` it preserves the original page for the branch and `write_unprotect`s + wakes.

## The hard open question — de-risk FIRST (Phase 0)

**Does `UFFD_WP` work on a *running KVM guest's* memory on the CI runner kernel?**
UFFD_WP on plain host memory is well-supported (≥ 5.7); UFFD_WP on memory a KVM guest
writes via EPT has historically been gated on newer kernels / specific KVM support
(KVM must fault guest writes out to userfaultfd rather than handling them in-kernel).
If the runner kernel doesn't deliver WP events for guest writes, the whole mechanism is
infeasible there and we fall back to the snapshot-based fork (which already works).

**Phase 0 experiment (cheap, KVM job):** register a booted guest's RAM with UFFD_WP,
write-protect a page, have the guest write it, and assert the host handler receives a
`WriteProtect` event. This single test decides feasibility before any engine is built.
Until it passes, the rest of this plan is on hold.

## Child memory model

Each child needs its own divergent RAM (children also write). Options, to be chosen
after Phase 0:
- **Branch file + MAP_PRIVATE (simplest):** the handler writes preserved T-pages into a
  branch `memory_file`; children `MAP_PRIVATE` it (reusing `allocate_cow_guest_memory`).
  Pages the parent never touches must still be readable at T — so either pre-seed the
  file from the parent (defeats the "no dump" goal) or have children *also* UFFD-fault
  untouched pages from the parent on first read (post-copy style). The latter keeps it
  lazy but adds a read-fault path.
- **Shared read-only + per-child overlay:** children map the parent pages read-only and
  keep a private overlay for their own writes; needs a second UFFD layer per child.

The read-fault (post-copy) variant is the faithful "no dump" design but materially more
complex; the branch-file variant is simpler but partially reintroduces copying.

## Phased build (each KVM-verified; halt if Phase 0 fails)

0. **Feasibility:** UFFD_WP-on-live-guest experiment (above). Gate.
1. **WP engine:** `branch_engine` — register guest RAM with UFFD_WP, the handler thread,
   arm/disarm. Unit-test the handler's page-preserve logic where possible.
2. **`Machine::branch`:** pause→capture (reuse snapshot capture)→arm WP→resume→produce
   children via the chosen memory model. KVM e2e mirroring `fork_kvm`: parent keeps
   running, children are independent and exec-able (reuse the fork exec-independence
   harness), and the parent's post-branch writes don't bleed into children.
3. **Accounting/CLI/cluster** as applicable (mirrors fork's `plan_fork`).

## Why design-first

This is research-grade (CRIU/forkd territory), KVM-only (no local validation), and its
feasibility hinges on a kernel/KVM capability we have not yet confirmed. Building the
engine before Phase 0 risks a large blind effort against a possibly-unsupported
primitive. The existing snapshot-based fork remains the proven path and the fallback.
