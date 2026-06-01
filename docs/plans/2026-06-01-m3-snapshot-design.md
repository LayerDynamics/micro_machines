# M3 Snapshot/Restore — Device & vCPU State Capture Design

> Design note for **Task 50 (snapshot/restore engine, FR-14)**. Approve before
> implementation. Scope: snapshot a paused microVM (RAM + device + vCPU state) and
> restore it into a fresh VM. Fork (Task 53) builds on the same capture path.

## The constraint (why this needs design, not just code)

After `Machine::start()`, the state we must snapshot **lives inside worker threads,
not in the `Machine` struct** — this is correct and optimal for a *running* VM (no
locks on the hot path), but it means the `Machine` cannot reach in and read it:

- **vCPU register state** — `machine.rs:388` moves each `Vcpu` (and its `VcpuFd`)
  into its own thread: `for mut vcpu in std::mem::take(&mut self.vcpus)`. After
  `start()`, `self.vcpus` is empty.
- **virtio queue cursors** — each device's `activate()` `swap_remove`s its `Queue`s
  into a detached worker (`net.rs:92-94`, block, vsock). The live `next_avail` /
  `next_used` cursors live in those workers.

There is **no bug here** — M1/M2/exec all depend on this design. But snapshot must
*capture state from within the threads at a quiescent point*, via a cooperative
pause, rather than reaching in from outside.

## Key simplification: snapshot freezes, it does not resume-in-place

M3 needs snapshot/restore and fork — **all three build a *fresh* VM from captured
state** (restore = new `Machine` from files; fork = new child VMs from the parent's
snapshot + CoW memory). None of them require resuming the *same* paused process in
place. So "pause" = **quiesce → capture → freeze**, with no condvar/resume
machinery. This drops a large amount of complexity. (Resumable in-place pause, if
ever wanted, is a later add and not in M3 scope — note as TODO.)

## What a snapshot is (on disk)

Per the existing `SnapshotManifest` (Task 2, done): a `memory_file` + a `state_file`.

- **`memory_file`** — a raw dump of the `GuestMemoryMmap` regions (copied out under
  pause). Restore mmaps fresh guest RAM and loads this back.
- **`state_file`** — a serialized `VmState`:
  ```
  VmState {
    vcpus:  Vec<VcpuState>,     // one per vCPU, in index order
    devices: Vec<DeviceState>,  // one per virtio device, in attach order
  }
  VcpuState  { regs, sregs, fpu, msrs: Vec<(idx,val)>, lapic, mp_state }
             // cpuid2 is rebuilt deterministically at restore (vcpu.rs build_cpuid),
             // not saved — it is a function of host + index, not guest runtime state.
  DeviceState { kind, queues: Vec<QueueState>, extra }
             // QueueState { next_avail, next_used, .. } round-trips via
             // Queue: TryFrom<QueueState> (verified in virtio-queue 0.16 state.rs).
             // `extra`: device-specific (serial FIFO; vsock has none worth keeping —
             // live exec sessions are intentionally NOT preserved across a snapshot).
  ```

## The pause-and-capture mechanism

### vCPU threads
Add a `pause: Arc<AtomicBool>` (distinct from the existing teardown `vcpu_stop`) plus
a shared `Arc<Vec<Mutex<Option<VcpuState>>>>` (one slot per vCPU). Reuse the **existing
SIGUSR1 kick** (`VCPU_STOP_SIGNAL`, `vcpu_tids`) to break each vCPU out of `KVM_RUN`.
On a pause kick, the thread — which owns its `VcpuFd` — captures its own state
(`get_regs`/`get_sregs`/`get_fpu`/`get_msrs`/`get_lapic`/`get_mp_state`) into its slot,
then returns (freeze). `Machine::snapshot()` joins the threads and collects the slots.

### Device workers
Each worker blocks on an eventfd (block) or epoll (net/vsock). To wake them for
capture, `activate()` additionally hands each device:
- a cloned **`pause_evt: EventFd`** added to the worker's wait set, and
- a shared **`Arc<Mutex<Option<Vec<QueueState>>>>`** output slot.

On `pause_evt`, the worker drains to a quiescent point, writes `queue.state()` for each
queue into its slot, and exits. The `Machine` holds the other ends. (Serial has no
queues; vsock records none — exec connections are ephemeral by design.)

## Snapshot / restore flow

- `Machine::snapshot(out_dir) -> SnapshotManifest`: set `pause`; SIGUSR1-kick + join
  vCPU threads (collect `VcpuState`s); signal `pause_evt` to each device + join
  (collect `QueueState`s); copy `GuestMemoryMmap` regions → `memory_file`; serialize
  `VmState` → `state_file`; emit `SnapshotManifest { kind: Full, .. }`.
- `restore(manifest) -> Machine`: build a fresh VM + memory (reuse `with_resources`),
  load `memory_file` into guest RAM, recreate vCPUs and apply `VcpuState` via the
  matching `KVM_SET_*` ioctls, rebuild each device's queues via
  `Queue::try_from(QueueState)` and re-activate workers, then resume.

## Phasing (each phase committed + verified before the next)

- **A — contract (host, unit-tested):** `VmState`/`VcpuState`/`DeviceState` types +
  (de)serialization; confirm `QueueState` round-trip. No KVM.
- **B — vCPU pause/capture (KVM):** `pause` flag + slots + capture in `Vcpu::run`;
  `Machine` accessors. Add `get_*`/`set_*` wrappers on `Vcpu`.
- **C — device quiesce/capture (KVM):** `pause_evt` + output slot threaded through
  `VirtioDevice::activate` and each worker loop.
- **D — snapshot engine (KVM):** RAM dump + `VmState` assembly + manifest.
- **E — restore engine (KVM):** fresh VM from files; `KVM_SET_*` + queue rebuild.
- **F — KVM e2e:** boot → write a sentinel into guest RAM via a workload → snapshot →
  restore → assert the sentinel survives and execution continues. (Large/meaningful
  assertion, console dump on failure — same discipline as the exec e2e.)

## Decisions I need from you

1. **Freeze-only pause (no in-place resume) for M3** — confirmed acceptable? (Restore
   and fork both build fresh VMs, so I believe yes; flagging because it shapes B/C.)
2. **`activate()` signature change** — adding `pause_evt` + a state slot touches every
   device's `activate` (block/net/vsock/balloon/serial). OK to make that the
   foundational refactor in Phase C, or prefer a separate `Snapshottable` side-trait?
3. **Scope of device `extra` state** — for M3 I propose: serial = drop in-flight FIFO
   (cosmetic), vsock = drop live exec sessions, block/net = queue cursors only (their
   backing files/TAP are reattached at restore). Acceptable, or must any be preserved?
