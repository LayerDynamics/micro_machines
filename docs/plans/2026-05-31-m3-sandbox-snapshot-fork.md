# M3 — Sandbox Mode + Snapshot/Fork Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use `lore:execute` to implement this plan task-by-task.
> **Scope guard:** Do ONLY what is listed here. If you discover adjacent issues, note them as a TODO and continue. Do NOT fix them. GitOps (M4), the build matrix (M5), and the Node edge (M6) are LATER milestones. The *running-sandbox BRANCH* (FR-16, SHOULD) is OUT of M3 scope — M3 delivers snapshot/restore + CoW fork of a paused parent only; note BRANCH as a TODO.

**Goal:** Add fast, ephemeral sandboxes: run an agent/app inside a microVM with an exec API over vsock, snapshot a paused microVM (memory + device + vCPU state) and restore it, and fork many children from a warmed parent snapshot via copy-on-write — with fan-out cold-start meeting NFR-P2 (< 150 ms p50).
**Architecture:** `crates/mm-vmm` gains pause/snapshot/restore/fork on the M1 VMM core (userfaultfd-backed CoW); `crates/mm-sandbox` gains a host-side exec client and the guest gains a vsock exec agent (`mm-init` Sandbox mode); the control plane (M2) exposes `exec`, `snapshot`, and `fork` over REST and routes them to the owning agent. Per-child isolation reuses M1 netns/cgroup/jailer.
**Tech Stack:** Rust; `userfaultfd` (write-protect CoW), `vm-memory`, `kvm-ioctls` (`KVM_GET/SET_*` for vCPU + device state), `vsock`/`tokio-vsock`, `nix` (mmap MAP_PRIVATE, cgroup `memory.max`). Reuses M1 (`mm-vmm`, `mm-init`, `mm-sandbox`) and M2 (`mm-controller`, `mm-agent`, `mm-proto`).
**Practices:** Contract-first — define the vsock exec wire protocol and the snapshot manifest format BEFORE the engine. TDD for pure logic (exec frame encode/decode, snapshot manifest (de)serialization, fork id/accounting, per-child memory math). KVM integration tests for snapshot/restore correctness and fork fan-out latency. Verify-before-done gate every task.
**Required skills:** `lore:execute`, `lore:test-driven-development`.
**Traceability:** Satisfies SPEC-1 FR-13 (exec API), FR-14 (snapshot/restore), FR-15 (CoW fork), FR-28 (rate-limited devices); targets NFR-P2 (fork fan-out p50 < 150 ms, N=100). FR-16 (running BRANCH) explicitly deferred. Implements §3.5 Flow B. Prior art (reference only): forkd (`forkd-vmm` snapshot/`restore_many`, ~100 ms fan-out, userfaultfd), shuru (checkpoint, vsock port-forward), bake (vsock exec).

> **PLATFORM:** vsock-protocol framing, snapshot manifest, fork accounting, and exec routing are cross-platform and fully TDD-able on this macOS dev host. Actual pause/snapshot/restore/fork and the fan-out latency benchmark are **Linux/KVM-only** (need `/dev/kvm`, `userfaultfd`, kernel ≥ 5.7 for `UFFD_WP`). Tasks are tagged. Run linux+kvm tasks on the KVM runner from M1 Task 13.

---

### Task 0: Add M3 module surface to the workspace [host: any]

**Files:**
- Modify: `Cargo.toml` (`workspace.dependencies`: add `userfaultfd`, `tokio-vsock`)

**Step 1:** No new crates — M3 extends existing M1/M2 crates. Add to `[workspace.dependencies]`:
```toml
userfaultfd = "0.x"
tokio-vsock = "0.x"
```

**Step 2: Verify**
```bash
cargo metadata --no-deps >/dev/null && echo "workspace ok"
```
→ Expected: `workspace ok`.

---

### Task 1 (TDD): vsock exec wire protocol — contract-first [host: any]

**Files:**
- Create: `crates/mm-sandbox/src/exec/protocol.rs`
- Modify: `crates/mm-sandbox/src/lib.rs`

**Traceability:** FR-13 (exec API: run command, stream stdout/stderr, return exit code). SPEC-1 Appendix B.2.

**Step 1: Write the failing test + the framed protocol**
```rust
//! Host<->guest exec protocol over vsock (SPEC-1 FR-13 / App.B.2).
//! Length-prefixed JSON frames; the guest agent (Task 4) speaks the same protocol.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Frame {
    /// host -> guest: run a command
    Exec { id: u64, cmd: Vec<String>, timeout_ms: u64 },
    /// guest -> host: a chunk of output
    Output { id: u64, stream: Stream, data: Vec<u8> },
    /// guest -> host: terminal result
    Exit { id: u64, code: i32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stream { Stdout, Stderr }

/// Encode a frame as a 4-byte big-endian length prefix + JSON body.
pub fn encode(frame: &Frame) -> Vec<u8> {
    let body = serde_json::to_vec(frame).expect("frame serializes");
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

/// Decode one frame from the front of `buf`; returns (frame, bytes_consumed) or None if incomplete.
pub fn decode(buf: &[u8]) -> Option<(Frame, usize)> {
    if buf.len() < 4 { return None; }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + len { return None; }
    let frame = serde_json::from_slice(&buf[4..4 + len]).ok()?;
    Some((frame, 4 + len))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trips_exec_frame() {
        let f = Frame::Exec { id: 7, cmd: vec!["python3".into(), "-c".into(), "print(2+2)".into()], timeout_ms: 5000 };
        let bytes = encode(&f);
        let (got, n) = decode(&bytes).unwrap();
        assert_eq!(got, f);
        assert_eq!(n, bytes.len());
    }
    #[test]
    fn decode_waits_for_complete_frame() {
        let f = Frame::Exit { id: 1, code: 0 };
        let bytes = encode(&f);
        assert!(decode(&bytes[..3]).is_none(), "incomplete length prefix");
        assert!(decode(&bytes[..bytes.len()-1]).is_none(), "incomplete body");
        assert!(decode(&bytes).is_some());
    }
    #[test]
    fn handles_two_frames_in_one_buffer() {
        let mut buf = encode(&Frame::Exit { id: 1, code: 0 });
        buf.extend(encode(&Frame::Exit { id: 2, code: 1 }));
        let (f1, n1) = decode(&buf).unwrap();
        let (f2, _) = decode(&buf[n1..]).unwrap();
        assert_eq!(f1, Frame::Exit { id: 1, code: 0 });
        assert_eq!(f2, Frame::Exit { id: 2, code: 1 });
    }
}
```

**Step 2: Verify (gate)**
```bash
cargo test -p mm-sandbox exec::protocol
```
→ Expected: `3 passed`.

**Step 3: Commit**
```bash
git add crates/mm-sandbox/src/exec && git commit -m "feat(sandbox): vsock exec wire protocol (SPEC-1 FR-13/App.B.2)"
```

---

### Task 2 (TDD): Snapshot manifest — contract-first [host: any]

**Files:**
- Create: `crates/mm-vmm/src/snapshot/manifest.rs`
- Create: `crates/mm-vmm/src/snapshot/mod.rs`
- Modify: `crates/mm-vmm/src/lib.rs`

**Traceability:** FR-14 (snapshot = memory + device + vCPU state).

**Step 1: Write the failing test + manifest types**
```rust
//! Snapshot manifest — describes a saved microVM (SPEC-1 FR-14).
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Everything needed to restore (or fork) a paused microVM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub version: u32,
    pub vcpu_count: u8,
    pub memory_mib: u64,
    /// Backing file holding guest RAM (mmap'd MAP_PRIVATE by children on fork).
    pub memory_file: PathBuf,
    /// Serialized vCPU register/sregs/CPUID + device state.
    pub state_file: PathBuf,
    pub kind: SnapshotKind,
    /// Set for diff snapshots: the parent this diff layers on.
    pub parent_uid: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotKind { Full, Diff }

impl SnapshotManifest {
    pub const CURRENT_VERSION: u32 = 1;

    /// A manifest is forkable if it is a complete, current-version full snapshot.
    pub fn is_forkable(&self) -> bool {
        self.version == Self::CURRENT_VERSION && self.kind == SnapshotKind::Full
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn full() -> SnapshotManifest {
        SnapshotManifest {
            version: 1, vcpu_count: 1, memory_mib: 128,
            memory_file: "mem.bin".into(), state_file: "state.bin".into(),
            kind: SnapshotKind::Full, parent_uid: None,
        }
    }
    #[test] fn round_trips_json() {
        let m = full();
        let s = serde_json::to_string(&m).unwrap();
        assert_eq!(serde_json::from_str::<SnapshotManifest>(&s).unwrap(), m);
    }
    #[test] fn full_current_is_forkable_diff_is_not() {
        assert!(full().is_forkable());
        let mut d = full(); d.kind = SnapshotKind::Diff; d.parent_uid = Some("p".into());
        assert!(!d.is_forkable());
    }
}
```

**Step 2: `snapshot/mod.rs`** → `pub mod manifest; pub use manifest::{SnapshotManifest, SnapshotKind};` and (linux-only) the engine added in Task 3. Update `lib.rs` to `pub mod snapshot;`.

**Step 3: Verify (gate)**
```bash
cargo test -p mm-vmm snapshot::manifest
```
→ Expected: `2 passed`.

**Step 4: Commit**
```bash
git add crates/mm-vmm/src/snapshot crates/mm-vmm/src/lib.rs && git commit -m "feat(vmm): snapshot manifest contract (SPEC-1 FR-14)"
```

---

### Task 3: Snapshot/restore engine [host: linux+kvm]

**Files:**
- Create: `crates/mm-vmm/src/snapshot/engine.rs` (cfg linux)

**Traceability:** FR-14.

**Implementation:**
- `pause(&mut Machine)`: stop vCPU threads at a quiescent point; quiesce virtio queues.
- `snapshot(&Machine, out_dir) -> SnapshotManifest`:
  - Dump guest RAM to `memory_file` (copy the `GuestMemoryMmap` regions).
  - Serialize per-vCPU state via `kvm-ioctls`: `get_regs`, `get_sregs`, `get_fpu`, `get_msrs`, `get_lapic`, `get_cpuid2`, plus `get_mp_state`; serialize device model state (virtio queue cursors, serial). Write to `state_file`.
  - Emit a `SnapshotManifest { kind: Full, .. }` (Task 2).
- `restore(manifest) -> Machine`: recreate the VM + memory, load RAM from `memory_file`, set vCPU/device state with the matching `KVM_SET_*` ioctls, resume.

**Step 1: Integration test — snapshot/restore correctness**
```rust
// crates/mm-vmm/tests/snapshot_kvm.rs  (#[ignore], feature = kvm-integration)
// boot -> write a sentinel into guest memory via a workload -> pause -> snapshot
// -> restore -> assert the sentinel + execution continues correctly.
```

**Step 2: Verify (gate, on KVM host)**
```bash
cargo test -p mm-vmm --features kvm-integration -- --ignored snapshot_restore
```
→ Expected: restored VM resumes with identical state.

**Step 3: Commit**
```bash
git add crates/mm-vmm/src/snapshot/engine.rs crates/mm-vmm/tests/snapshot_kvm.rs && git commit -m "feat(vmm): snapshot/restore engine (SPEC-1 FR-14)"
```

---

### Task 4: Guest exec agent in `mm-init` (Sandbox mode) [host: linux+kvm]

**Files:**
- Create: `crates/mm-init/src/exec_agent.rs` (cfg linux)
- Modify: `crates/mm-init/src/pid1.rs` (Sandbox branch now starts the agent)

**Traceability:** FR-13 (in-guest exec agent over vsock).

**Implementation:**
- When `InitConfig.mode == Sandbox` (M1 Task 3 parsed it), bind a vsock listener on a fixed port; read `Frame::Exec` (Task 1 protocol), spawn the command, stream `Frame::Output` chunks, send `Frame::Exit{code}`. Enforce `timeout_ms`.
- Keep it dependency-light (no async runtime needed; a simple blocking vsock loop is fine for PID 1).

**Step 1: TDD the command runner mapping** (pure): `Frame::Exec` → spawned process args/stdio wiring; timeout → kill + `Exit` code convention.

**Step 2: Build the guest binary**
```bash
cargo build -p mm-init --release --target x86_64-unknown-linux-musl
```
→ Expected: static binary builds (linux).

**Step 3: Verify (gate)**
```bash
cargo test -p mm-init --lib && cargo clippy -p mm-init --all-targets --target x86_64-unknown-linux-musl
```
→ Expected: tests pass; clippy clean.

**Step 4: Commit**
```bash
git add crates/mm-init && git commit -m "feat(init): vsock exec agent for Sandbox Mode (SPEC-1 FR-13)"
```

---

### Task 5 (TDD): Fork accounting + per-child memory math (pure) [host: any]

**Files:**
- Create: `crates/mm-vmm/src/snapshot/fork.rs`

**Traceability:** FR-15 (CoW fork), NFR-P2 (fan-out). Prior art: forkd CoW fork (reference only).

**Step 1: Write the failing test + the pure fork bookkeeping**
```rust
//! Fork bookkeeping: assign child ids and account CoW memory (SPEC-1 FR-15).
//! The actual mmap(MAP_PRIVATE)/userfaultfd wiring is in Task 6 (linux); this is the
//! deterministic accounting/validation that gates a fork request.
use super::manifest::SnapshotManifest;

#[derive(Debug, PartialEq, Eq)]
pub enum ForkError { NotForkable, ZeroCount, OverBudget }

#[derive(Debug, PartialEq, Eq)]
pub struct ForkPlan { pub child_ids: Vec<u64>, pub shared_mib: u64, pub per_child_overhead_mib: u64 }

/// Validate and plan a fork of `count` children from `parent`, given the host's free MiB.
/// CoW means children share the parent's `memory_mib` pages; only dirtied pages cost extra.
/// We budget a conservative `per_child_overhead_mib` for private/dirtied pages + page tables.
pub fn plan_fork(parent: &SnapshotManifest, count: u64, next_id: u64, free_mib: u64, per_child_overhead_mib: u64)
    -> Result<ForkPlan, ForkError>
{
    if !parent.is_forkable() { return Err(ForkError::NotForkable); }
    if count == 0 { return Err(ForkError::ZeroCount); }
    let needed = count.saturating_mul(per_child_overhead_mib);
    if needed > free_mib { return Err(ForkError::OverBudget); }
    let child_ids = (next_id..next_id + count).collect();
    Ok(ForkPlan { child_ids, shared_mib: parent.memory_mib, per_child_overhead_mib })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::manifest::{SnapshotKind, SnapshotManifest};
    fn parent() -> SnapshotManifest {
        SnapshotManifest { version: 1, vcpu_count: 1, memory_mib: 256,
            memory_file: "m".into(), state_file: "s".into(), kind: SnapshotKind::Full, parent_uid: None }
    }
    #[test] fn plans_ids_and_shares_parent_memory() {
        let p = plan_fork(&parent(), 100, 1, 4096, 8).unwrap();
        assert_eq!(p.child_ids.len(), 100);
        assert_eq!(*p.child_ids.first().unwrap(), 1);
        assert_eq!(p.shared_mib, 256); // CoW: parent RAM shared, not multiplied
    }
    #[test] fn rejects_diff_parent_and_overbudget() {
        let mut d = parent(); d.kind = SnapshotKind::Diff;
        assert_eq!(plan_fork(&d, 1, 1, 4096, 8), Err(ForkError::NotForkable));
        assert_eq!(plan_fork(&parent(), 1000, 1, 100, 8), Err(ForkError::OverBudget));
    }
}
```

**Step 2: Verify (gate)**
```bash
cargo test -p mm-vmm snapshot::fork
```
→ Expected: `2 passed`.

**Step 3: Commit**
```bash
git add crates/mm-vmm/src/snapshot/fork.rs && git commit -m "feat(vmm): fork accounting + CoW memory planning (SPEC-1 FR-15)"
```

---

### Task 6: CoW fork engine (userfaultfd) [host: linux+kvm]

**Files:**
- Create: `crates/mm-vmm/src/snapshot/fork_engine.rs` (cfg linux)

**Traceability:** FR-15, NFR-P2. Prior art: forkd userfaultfd CoW (reference only).

**Implementation:**
- `fork_children(parent_manifest, plan: ForkPlan) -> Vec<Machine>`: for each child id in `plan.child_ids`:
  - `mmap(MAP_PRIVATE)` the parent's `memory_file` so the kernel does page-level CoW (children read shared pages, copy on write).
  - Register the region with `userfaultfd` in `UFFD_WP` mode so dirty pages are tracked/copied lazily (keeps the source-pause window small per forkd v0.4).
  - Create a fresh VM + vCPUs, point guest memory at the CoW mapping, load vCPU/device state from `state_file`, place each child in its own netns/veth + cgroup `memory.max` (reuse M1 `mm-net`/`mm-sandbox`).
  - Resume; child signals ready over vsock.

**Step 1: Integration test — fork fan-out latency (NFR-P2)**
```rust
// crates/mm-vmm/tests/fork_kvm.rs  (#[ignore], feature = kvm-integration)
// warm a parent (load deps in the guest) -> snapshot -> fork N=100 children
// -> measure per-child time-to-ready -> assert p50 < 150 ms (NFR-P2)
// -> exec a distinct command in 3 random children, assert independent results.
```

**Step 2: Verify (gate, on KVM host)**
```bash
cargo test -p mm-vmm --features kvm-integration -- --ignored fork_fanout
```
→ Expected: 100 children spawn; p50 time-to-ready < 150 ms (record the number); children are independent (CoW isolation holds).

**Step 3: Commit**
```bash
git add crates/mm-vmm/src/snapshot/fork_engine.rs crates/mm-vmm/tests/fork_kvm.rs && git commit -m "feat(vmm): userfaultfd CoW fork engine (SPEC-1 FR-15, NFR-P2)"
```

---

### Task 7: virtio device rate limiting (token bucket) [host: linux+kvm for wiring; any for logic]

**Files:**
- Create: `crates/mm-vmm/src/devices/ratelimit.rs`
- Modify: `crates/mm-vmm/src/devices/{block,net}.rs`

**Traceability:** FR-28 (token-bucket rate limiting on blk/net for fair multi-tenant sharing). Prior art: firecracker token-bucket (reference only).

**Step 1 (TDD): token-bucket logic (pure)**
```rust
//! Token-bucket rate limiter for virtio devices (SPEC-1 FR-28). Pure / testable.
pub struct TokenBucket { capacity: u64, tokens: u64, refill_per_ms: u64 }

impl TokenBucket {
    pub fn new(capacity: u64, refill_per_ms: u64) -> Self { Self { capacity, tokens: capacity, refill_per_ms } }
    /// Advance time by `ms`, refilling tokens up to capacity.
    pub fn refill(&mut self, ms: u64) { self.tokens = (self.tokens + ms * self.refill_per_ms).min(self.capacity); }
    /// Try to consume `n` tokens; returns false (throttle) if insufficient.
    pub fn consume(&mut self, n: u64) -> bool {
        if self.tokens >= n { self.tokens -= n; true } else { false }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn throttles_then_refills() {
        let mut b = TokenBucket::new(100, 10);
        assert!(b.consume(100));
        assert!(!b.consume(1), "empty -> throttled");
        b.refill(5);                 // +50 tokens
        assert!(b.consume(50));
        assert!(!b.consume(1));
    }
    #[test] fn refill_caps_at_capacity() {
        let mut b = TokenBucket::new(100, 10);
        b.refill(1_000_000);
        assert!(b.consume(100) && !b.consume(1));
    }
}
```

**Step 2:** Wire the bucket into virtio-blk/net request paths (consume on bytes + ops; throttle when empty).

**Step 3: Verify (gate)**
```bash
cargo test -p mm-vmm ratelimit && cargo clippy -p mm-vmm --all-targets
```
→ Expected: `2 passed`; clippy clean.

**Step 4: Commit**
```bash
git add crates/mm-vmm/src/devices && git commit -m "feat(vmm): token-bucket rate limiting on virtio blk/net (SPEC-1 FR-28)"
```

---

### Task 8: Expose exec / snapshot / fork via control plane + agent [host: any for logic]

**Files:**
- Modify: `crates/mm-proto/proto/machine.proto` (add `Exec`, `Snapshot`, `Fork` RPCs + messages)
- Modify: `services/mm-agent/src/actuator.rs` (handle exec/snapshot/fork via `mm-vmm`/`mm-sandbox`)
- Modify: `services/mm-controller/src/api/machines.rs` (add `/exec`, `/snapshot`, `/fork` REST handlers from SPEC-1 App.B.2/B.3)

**Traceability:** FR-13, FR-14, FR-15; SPEC-1 §3.4, App.B.2/B.3.

**Step 1: Extend the proto** — add:
```proto
rpc Exec(ExecRequest) returns (stream ExecChunk);
rpc Snapshot(MachineRef) returns (SnapshotRef);
rpc Fork(ForkRequest) returns (ForkReply);
message ExecRequest { MachineRef ref = 1; repeated string cmd = 2; uint64 timeout_ms = 3; }
message ExecChunk { string stream = 1; bytes data = 2; int32 exit_code = 3; bool done = 4; }
message SnapshotRef { string snapshot_uid = 1; }
message ForkRequest { MachineRef parent = 1; uint32 count = 2; string from_snapshot = 3; }
message ForkReply { repeated string child_uids = 1; }
```

**Step 2:** Controller REST handlers (auth + RBAC + audit as in M2) translate to the new gRPC calls; agent actuator routes exec frames to the guest vsock agent (Task 4), snapshot/fork to the engines (Tasks 3/6).

**Step 3: Integration test (controller↔agent, exec path)**
```bash
# with the M2 dev Postgres + a kvm agent: POST /machines/{id}/exec {cmd:["echo","hi"]} -> 200 {exit_code:0,stdout:"hi\n"}
cargo test -p mm-controller --test exec_route
```
→ Expected: exec routes end-to-end and returns the correct exit code + output.

**Step 4: Verify (gate)**
```bash
cargo build -p mm-proto && cargo clippy -p mm-controller -p mm-agent --all-targets
```
→ Expected: proto compiles; clippy clean.

**Step 5: Commit**
```bash
git add crates/mm-proto services/mm-agent services/mm-controller && git commit -m "feat: expose exec/snapshot/fork via REST+gRPC (SPEC-1 FR-13/14/15, App.B)"
```

---

### Task 9: SDK-less CLI surface for sandbox [host: any]

**Files:**
- Modify: `apps/mm/src/main.rs` (add `mm exec`, `mm snapshot`, `mm fork`)
- Create: `apps/mm/src/commands/{exec,snapshot,fork}.rs`

**Traceability:** FR-13/14/15 from the CLI (the TS SDK is M6; the Rust CLI exercises the API now).

**Step 1: TDD argument parsing + request building** (pure) for the three verbs.

**Step 2: Manual smoke (cluster + kvm agent)**
```bash
mm --server $S run alpine --name box --sandbox
mm --server $S exec box -- echo hi          # -> hi, exit 0
mm --server $S snapshot box                  # -> snapshot uid
mm --server $S fork box --count 100          # -> 100 child uids; fan-out < 150ms p50 (NFR-P2)
```

**Step 3: Verify (gate)**
```bash
cargo test -p mm && cargo clippy -p mm --all-targets
```
→ Expected: parser tests pass; clippy clean.

**Step 4: Commit**
```bash
git add apps/mm && git commit -m "feat(cli): exec/snapshot/fork sandbox verbs (SPEC-1 FR-13/14/15)"
```

---

### Task 10: M3 verification gate

**Step 1: Cross-platform logic gate (any host)**
```bash
cargo test -p mm-sandbox exec::protocol
cargo test -p mm-vmm snapshot::manifest snapshot::fork ratelimit
cargo test -p mm-init --lib
cargo test -p mm
cargo clippy --workspace --all-targets && cargo fmt --all --check
```
→ Expected: exec protocol, snapshot manifest, fork accounting, rate-limit, init, CLI tests all pass; clippy + fmt clean.

**Step 2: KVM gate (linux+kvm host)**
```bash
cargo test -p mm-vmm --features kvm-integration -- --ignored snapshot_restore fork_fanout
mm --server $S run alpine --name m3 --sandbox && mm --server $S exec m3 -- echo ok   # -> ok
mm --server $S snapshot m3 && mm --server $S fork m3 --count 100                       # fan-out p50 < 150ms
```
→ Expected: snapshot/restore preserves state; 100-child fork p50 < 150 ms (NFR-P2, recorded); exec returns correct results; children independent.

**Exit criteria (M3 complete when ALL true):** ✅ ALL MET — gate signed off 2026-06-02.
- [x] Snapshot of a paused microVM captures memory + vCPU + device state and restores to an identical, resumable VM (FR-14). — `snapshot-integration` CI job green.
- [x] CoW fork spawns N=100 children from a warmed parent; per-child time-to-ready p50 < 150 ms (FR-15, NFR-P2) — number recorded; children are CoW-isolated. — `fork-integration` green; N=100 measured p50 <1 ms, p90 1 ms, max 4 ms (CI run 26814151459).
- [x] `exec` runs a command in a sandbox guest over vsock and returns correct stdout/stderr/exit code (FR-13), routed through controller→agent→guest. — `cluster-integration` green; `cluster-e2e.sh` asserts real guest stdout + non-zero exit + reverse-channel survival across a controller restart (CI run 26817967954).
- [x] virtio blk/net enforce token-bucket rate limits (FR-28). — ratelimit units + device wiring green.
- [x] All pure-logic units have passing tests; KVM integration tests pass on the kvm runner; clippy + fmt clean; every task committed. — full CI run 26817967954 green (15/15 jobs).
- [x] Running-sandbox BRANCH (FR-16) is recorded as a TODO, NOT implemented (out of M3 scope). — see below.

**TODOs discovered during M3** (note, do NOT fix now):
- **FR-16 running-sandbox BRANCH** (SHOULD, out of M3 scope) — branch a *running* (not paused) sandbox via diff snapshots + `UFFD_WP` live page copy, so the parent keeps running while children fork. M3 forks a paused parent only.
- ~~**Full N=100 fork fan-out sweep**~~ — DONE (`fork_kvm.rs::fork_fanout_p50_tracks_nfr_p2`, `fork-integration` job): forks 100 children one-at-a-time from a warmed parent snapshot and reports the p50 (measured <1 ms, far under NFR-P2's 150 ms). The N=4 concurrent-isolation test remains as the CoW-independence proof.
- ~~**In-guest fork independence via exec**~~ — DONE (`fork_kvm.rs::forked_children_have_independent_guest_state` + `forked_child_is_execable_over_its_vsock_bridge`, `fork-integration` green, run 26840673453): forks N=3 children each with its own vsock bridge, writes a distinct marker into each via `exec`, reads all back, asserts no cross-child bleed. Surfaced — and required fixing — three live-restore fidelity gaps the snapshot was missing (a CoW-forked guest must run new processes, keep time, and serve vsock, not just round-trip its state): **(1) in-kernel irqchip (PIC master/slave + IOAPIC) + PIT** (`KVM_GET/SET_IRQCHIP`×3 + `GET/SET_PIT2`) — without it the resumed guest oopsed in the tty IRQ path; **(2) XCR0** (`KVM_GET/SET_XCRS`) — without it the guest faulted in `XRSTOR` (`ex_handler_fprestore`); **(3) the LAPIC TSC-deadline timer MSR** (`MSR_IA32_TSC_DEADLINE`) — without it the guest got no timer interrupt and any `sleep`/scheduler tick stalled. `Machine::fork_with_vsock` adds a per-child host bridge so the host can exec into a forked child.
- ~~**Cluster exec forwarding (Task 8/55)**~~ — DONE: controller→agent→guest `exec` over the control plane lands via a `WatchExec`/`ReportExecResult` reverse channel into the client-only agent (commit 93794ac, `cluster-integration` green). Output streams end-to-end; `mm --server … exec` is the cluster entry point.
- **Snapshot GC/retention + cross-host restore** — snapshots accrete files under the state dir; restore currently assumes the same host (TSC/CPUID).
- **userfaultfd UFFD_WP fork optimization** — M3's fork uses kernel `MAP_PRIVATE` CoW (proven, fast). The plan's `UFFD_WP` lazy-copy is an optional optimization to shrink the source-pause window further; not required for the proven core.
