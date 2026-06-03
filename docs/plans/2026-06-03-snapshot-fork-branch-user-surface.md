# Snapshot / Fork / Branch User Surface Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:execute to implement this plan task-by-task.
> **Scope guard:** Do ONLY what is listed here. If you discover adjacent issues, note them as a TODO and continue. Do NOT fix them.

**Goal:** Make the already-built snapshot/restore/branch engines reachable by users — a worker control channel so a parent can act on a *live* jailed VM, single-host `mm snapshot/restore/branch` CLI verbs, and a first-class cluster `Snapshot` REST resource (Postgres model + controller↔agent gRPC).

**Architecture:** The jailed `__vmm-worker` gains a control UDS (`control.sock`, fd 13, bound outside the chroot exactly like the vsock bridge at fd 12) on which a control thread serves a tiny line protocol (`SNAPSHOT <dir>` / `BRANCH <dir>`), holding the `Machine` behind an `Arc<Mutex>` so it can pause→capture→resume without racing the vCPU reaper. `mm snapshot create` connects to that socket; `mm snapshot ls/rm/gc` use the on-disk `SnapshotStore`; `mm restore`/`mm branch` boot a fresh microVM from a snapshot dir via a new `mm_host::restore_launch` that reuses the jail/fd plumbing but calls `mm_vmm::snapshot::restore`. Cluster-side, a `Snapshot` resource (REST + Postgres + a `WatchSnapshot`/`ReportSnapshotResult` reverse-channel mirroring the existing `WatchExec` exec path) lets the controller drive a snapshot on the agent owning the machine's host.

**Tech Stack:** Rust (rust-vmm/KVM, axum, sqlx/Postgres, tonic/prost, redb, clap), the existing `mm_vmm::snapshot::{snapshot, restore, fork_children, SnapshotStore}` + `Machine::branch` engines.

**Practices:** Contract-first (define the control-channel wire protocol + proto messages before impl) · TDD / pure-core (failing host-side unit tests first for protocol parse/encode, store paths, arg handling, model serde) · Typed-first (define Rust types/enums before logic). KVM-dependent behavior is verified by `#[ignore]`d integration tests wired to CI jobs (the macOS dev host cannot boot guests); pure logic is unit-tested locally.

**Required skills:** none

---

## Context: what already exists (do NOT rebuild)

- **Engines (linux+kvm, CI-green):** `mm_vmm::snapshot::snapshot(&mut Machine, dir) -> SnapshotManifest`, `mm_vmm::snapshot::restore(config, kvm_fd, tap_fds, vsock_fd, hook, dir) -> Machine`, `mm_vmm::snapshot::fork_children(config, dir, &ForkPlan)`, `Machine::branch(&mut self, out_dir) -> SnapshotManifest` (feature `branch`), and `SnapshotStore` (`crates/mm-vmm/src/snapshot/store.rs`: `new_snapshot_dir`, `list`, `find`, `gc(keep)`, `remove`, path-sanitized).
- **Worker/launch plumbing:** `crates/mm-host/src/launch.rs` (`launch`, `spawn_worker`, fd-passing at 10/11/12, `LaunchOutcome`), `crates/mm-host/src/worker.rs` (`WorkerArgs`, `run` → `boot_jailed` → `wait_for_vcpus`).
- **Single-host CLI:** `apps/mm/src/main.rs` (the `Command` enum), `apps/mm/src/store.rs` (`Store`/`MachineRecord` keyed by name), `apps/mm/src/commands/exec.rs` (the UDS-client pattern + `<state_root>/jails/<name>/vsock.sock` resolution), `apps/mm/src/commands/{run,ps,stop,rm,ssh}.rs`.
- **Cluster:** `services/mm-controller/src/api/{mod.rs,machines.rs,namespaces.rs}` (auth→authorize→store→audit handler pattern; `AppState`), `services/mm-controller/src/{model.rs,store.rs,grpc.rs}` (the `ExecDispatcher` + `WatchExec`/`ReportExecResult` reverse-channel), `crates/mm-proto/proto/machine.proto`, `services/mm-controller/migrations/0001_init.sql`, `services/mm-agent/src/{exec.rs,actuator.rs}`.

The design note this plan executes: `docs/plans/2026-06-02-snapshot-lifecycle-cli.md`.

---

# Phase A — Worker control channel (single-host keystone)

## Task A1: Control-channel wire protocol (contract-first, pure, TDD)

**Files:**
- Create: `crates/mm-host/src/control_proto.rs`
- Modify: `crates/mm-host/src/lib.rs` (add `pub mod control_proto;`)
- Test: inline `#[cfg(test)]` in `control_proto.rs`

**Step 1 — Write the failing test** (define the contract first):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_request_round_trips() {
        let req = ControlRequest::Snapshot { dir: "snap-1".into() };
        let line = req.encode();
        assert_eq!(line, "SNAPSHOT snap-1\n");
        assert_eq!(ControlRequest::parse(line.trim_end()).unwrap(), req);
    }

    #[test]
    fn branch_request_round_trips() {
        let req = ControlRequest::Branch { dir: "branch-1".into() };
        assert_eq!(req.encode(), "BRANCH branch-1\n");
        assert_eq!(ControlRequest::parse("BRANCH branch-1").unwrap(), req);
    }

    #[test]
    fn rejects_unknown_verb_and_pathsep() {
        assert!(ControlRequest::parse("BOGUS x").is_err());
        // A dir token must be a single path segment (no '/' or NUL) — defense in depth;
        // the parent only ever sends store-allocated ids, but the worker must not be
        // tricked into writing outside the per-VM dir.
        assert!(ControlRequest::parse("SNAPSHOT ../etc").is_err());
        assert!(ControlRequest::parse("SNAPSHOT a/b").is_err());
    }

    #[test]
    fn responses_round_trip() {
        assert_eq!(ControlResponse::Ok { id: "snap-1".into() }.encode(), "OK snap-1\n");
        assert_eq!(ControlResponse::Err { msg: "boom".into() }.encode(), "ERR boom\n");
        assert_eq!(ControlResponse::parse("OK snap-1").unwrap(),
                   ControlResponse::Ok { id: "snap-1".into() });
        assert_eq!(ControlResponse::parse("ERR boom").unwrap(),
                   ControlResponse::Err { msg: "boom".into() });
    }
}
```

**Step 2 — Run to verify it fails:** `cargo test -p mm-host control_proto` → Expected: FAIL (module doesn't exist).

**Step 3 — Write the implementation** (`crates/mm-host/src/control_proto.rs`):

```rust
//! The line protocol the privileged parent speaks to the jailed `__vmm-worker` over
//! its control UDS (`control.sock`) to act on a *live* guest (SPEC-1 FR-14/FR-16).
//!
//! One request line, one response line, newline-terminated:
//!   `SNAPSHOT <dir>\n` | `BRANCH <dir>\n`  →  `OK <id>\n` | `ERR <message>\n`
//! `<dir>` is a single path segment (a store-allocated id) the worker joins under the
//! snapshot dir the parent created; it must not contain `/` or NUL (path safety).
//! Pure parse/encode so it is unit-tested on the dev host with no KVM.

/// A control request from the parent to the worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlRequest {
    /// Freeze-snapshot the live guest into `<snapshot-root>/<dir>`.
    Snapshot { dir: String },
    /// Branch the *running* guest into `<snapshot-root>/<dir>` (no freeze-for-dump).
    Branch { dir: String },
}

/// The worker's reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlResponse {
    Ok { id: String },
    Err { msg: String },
}

/// A path segment is safe iff non-empty and free of `/`, NUL, and `.`-only traversal.
fn is_safe_segment(s: &str) -> bool {
    !s.is_empty() && s != "." && s != ".." && !s.contains('/') && !s.contains('\0')
}

impl ControlRequest {
    pub fn encode(&self) -> String {
        match self {
            ControlRequest::Snapshot { dir } => format!("SNAPSHOT {dir}\n"),
            ControlRequest::Branch { dir } => format!("BRANCH {dir}\n"),
        }
    }

    pub fn parse(line: &str) -> Result<Self, String> {
        let (verb, arg) = line
            .split_once(' ')
            .ok_or_else(|| format!("malformed control request: {line:?}"))?;
        if !is_safe_segment(arg) {
            return Err(format!("unsafe dir segment: {arg:?}"));
        }
        match verb {
            "SNAPSHOT" => Ok(ControlRequest::Snapshot { dir: arg.to_string() }),
            "BRANCH" => Ok(ControlRequest::Branch { dir: arg.to_string() }),
            other => Err(format!("unknown control verb: {other}")),
        }
    }
}

impl ControlResponse {
    pub fn encode(&self) -> String {
        match self {
            ControlResponse::Ok { id } => format!("OK {id}\n"),
            ControlResponse::Err { msg } => format!("ERR {msg}\n"),
        }
    }

    pub fn parse(line: &str) -> Result<Self, String> {
        match line.split_once(' ') {
            Some(("OK", id)) => Ok(ControlResponse::Ok { id: id.to_string() }),
            Some(("ERR", msg)) => Ok(ControlResponse::Err { msg: msg.to_string() }),
            _ => Err(format!("malformed control response: {line:?}")),
        }
    }
}
```

**Step 4 — Run to verify it passes:** `cargo test -p mm-host control_proto` → Expected: PASS. Then `cargo clippy -p mm-host --all-targets` clean.

**Step 5 — Commit:** `git add crates/mm-host/src/control_proto.rs crates/mm-host/src/lib.rs && git commit -m "feat(host): control-channel wire protocol for live snapshot/branch (contract-first)"`

---

## Task A2: Worker holds the Machine shareable + serves the control loop

This is the keystone. Today `worker::run` calls `machine.wait_for_vcpus()` which borrows `&mut machine` and blocks for the guest's whole life — so no second caller can reach the `Machine` to snapshot it. Fix: own the `Machine` in an `Arc<Mutex<Machine>>`, detect power-off via a non-blocking signal, and serve the control UDS on a thread that briefly locks the `Machine` per request.

**Files:**
- Modify: `crates/mm-vmm/src/machine.rs` — add a non-`&mut`, non-blocking liveness signal + accessor (see Step 3a).
- Modify: `crates/mm-host/src/worker.rs:18-53` (add `--control-fd`), `:80-140` (control loop).

**Step 1 — Write the failing test** (pure, host-side: the worker's control-loop dispatch logic factored into a pure function over a trait, so it is testable without KVM):

```rust
// crates/mm-host/src/worker.rs  (#[cfg(test)] mod tests)
// A fake "snapshotter" lets us unit-test the control-loop request→response mapping
// (verb dispatch, error mapping, id echo) with no Machine/KVM.
#[test]
fn control_dispatch_maps_requests_to_responses() {
    use crate::control_proto::{ControlRequest, ControlResponse};
    let mut calls = vec![];
    let mut snap = |req: &ControlRequest| -> Result<String, String> {
        calls.push(req.clone());
        match req {
            ControlRequest::Snapshot { dir } => Ok(dir.clone()),
            ControlRequest::Branch { .. } => Err("no branch".into()),
        }
    };
    assert_eq!(
        dispatch_control(&ControlRequest::Snapshot { dir: "s1".into() }, &mut snap),
        ControlResponse::Ok { id: "s1".into() }
    );
    assert_eq!(
        dispatch_control(&ControlRequest::Branch { dir: "b1".into() }, &mut snap),
        ControlResponse::Err { msg: "no branch".into() }
    );
    assert_eq!(calls.len(), 2);
}
```

**Step 2 — Run to verify it fails:** `cargo test -p mm-host control_dispatch` → Expected: FAIL.

**Step 3 — Implement.**

**3a. `Machine` liveness signal** (`crates/mm-vmm/src/machine.rs`). Add a `powered_off: Arc<AtomicBool>` set when the vCPU threads exit, plus accessors, so the worker can wait for power-off WITHOUT holding a `&mut`/the Mutex during the blocking wait:
- Add field `powered_off: Arc<AtomicBool>` (init `false` in the constructor next to `vcpu_stop`).
- In `wait_for_vcpus` (machine.rs:535) the threads are joined; refactor the per-thread join so each thread sets `powered_off` when it returns — simplest: keep `wait_for_vcpus` as-is for existing callers, and add:
```rust
/// Whether all vCPU threads have exited (guest powered off / shut down). Cheap,
/// lock-free — lets a holder of a shared `Machine` poll liveness without taking a
/// long-lived borrow. Set by the vCPU threads as they exit.
pub fn is_powered_off(&self) -> bool { self.powered_off.load(Ordering::Acquire) }
```
  and set `self.powered_off.store(true, Ordering::Release)` at the end of the run-loop closure each vCPU thread runs (the spawn sites at machine.rs:464 and :1239 — store after `vcpu.run(...)` returns, before the thread ends). Because all vCPUs must exit for power-off, store from each; `is_powered_off` returning true after the first is acceptable for the worker's "stop serving" decision (the reaper then joins).

**3b. Worker control fd** (`crates/mm-host/src/worker.rs`): add to `WorkerArgs`:
```rust
/// Inherited control UDS listener fd (parent ↔ worker live-snapshot channel); absent
/// when the worker is launched without a control channel.
#[arg(long)]
pub control_fd: Option<i32>,
```

**3c. Pure dispatch helper** (top of `worker.rs`, outside the `linux` module so it builds + tests everywhere):
```rust
use crate::control_proto::{ControlRequest, ControlResponse};

/// Map one control request to its response via `act` (which performs the snapshot or
/// branch and returns the new snapshot id, or an error message). Pure glue — unit-
/// tested without KVM.
pub(crate) fn dispatch_control(
    req: &ControlRequest,
    act: &mut impl FnMut(&ControlRequest) -> Result<String, String>,
) -> ControlResponse {
    match act(req) {
        Ok(id) => ControlResponse::Ok { id },
        Err(msg) => ControlResponse::Err { msg },
    }
}
```

**3d. Wire the control loop into `linux::run`** (`worker.rs:80-140`). After `boot_jailed` + `wait_for_ready`, replace the bare `machine.wait_for_vcpus()` with: move the machine into `Arc<Mutex<Machine>>`; if `control_fd` was passed, build a `UnixListener` from it (`UnixListener::from_raw_fd`) and spawn a control thread; the main thread waits for power-off, then joins. Concretely:
```rust
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};
use std::io::{BufRead, BufReader, Write};

let machine = Arc::new(Mutex::new(machine));

// Serve the control UDS (live snapshot/branch) on a thread, if the parent passed one.
if let Some(fd) = args.control_fd {
    // SAFETY: `fd` is the inherited, bound, listening control socket (fd 13).
    let listener = unsafe { UnixListener::from_raw_fd(fd) };
    let machine = machine.clone();
    std::thread::Builder::new().name("mm-control".into()).spawn(move || {
        for conn in listener.incoming() {
            let mut conn = match conn { Ok(c) => c, Err(_) => continue };
            let mut line = String::new();
            if BufReader::new(&conn).read_line(&mut line).is_err() { continue; }
            let resp = match ControlRequest::parse(line.trim_end()) {
                Ok(req) => {
                    let mut act = |req: &ControlRequest| -> Result<String, String> {
                        let mut m = machine.lock().map_err(|_| "machine lock poisoned".to_string())?;
                        // The control root is the chroot-relative snapshot dir the parent
                        // created and made writable; join the requested segment under it.
                        let root = std::path::Path::new("/snapshots");
                        match req {
                            ControlRequest::Snapshot { dir } => {
                                let out = root.join(dir);
                                mm_vmm::snapshot::snapshot(&mut m, &out)
                                    .map(|_| dir.clone())
                                    .map_err(|e| e.to_string())
                            }
                            ControlRequest::Branch { dir } => {
                                let out = root.join(dir);
                                m.branch(&out).map(|_| dir.clone()).map_err(|e| e.to_string())
                            }
                        }
                    };
                    super::dispatch_control(&req, &mut act)
                }
                Err(e) => ControlResponse::Err { msg: e },
            };
            let _ = conn.write_all(resp.encode().as_bytes());
        }
    }).context("spawning control thread")?;
}

// Reaper: wait for the guest to power off without holding the machine lock, then join.
while !machine.lock().map(|m| m.is_powered_off()).unwrap_or(true) {
    std::thread::sleep(Duration::from_millis(100));
}
machine.lock().expect("machine lock").wait_for_vcpus().context("running microVM")?;
Ok(())
```
> Note for the executor: `Machine::branch` is behind the `branch` feature; gate the `BRANCH` arm and add `branch` to `mm-host`'s feature set (or always-enable for the worker binary). `snapshot()`/`branch()` need the snapshot dir reachable *inside* the chroot — the parent (Task A3) creates `<jail_root>/snapshots/<id>` and passes the id; the worker writes to `/snapshots/<id>` post-chroot. The vCPU pause/resume this relies on is the already-CI-green resume-in-place barrier (`checkpoint_full_in_place`), so the live path is proven.

**Step 4 — Run to verify it passes:** `cargo test -p mm-host` (pure dispatch test passes) → Expected: PASS. `cargo clippy -p mm-host --all-targets` clean. Cross-check the linux build: `cargo check -p mm-host --target x86_64-unknown-linux-gnu`.

**Step 5 — Commit:** `git add -A && git commit -m "feat(host,vmm): worker control channel — live snapshot/branch over control.sock; Machine power-off signal"`

---

## Task A3: Parent binds `control.sock` + passes fd 13 (launch plumbing)

**Files:**
- Modify: `crates/mm-host/src/launch.rs:28-31` (add `WORKER_CONTROL_FD: RawFd = 13`), `:125-166` (bind + pass), `:173-250` (`spawn_worker` arg + `dup2`), `crates/mm-host/src/lib.rs` (`LaunchOutcome.control_path`).

**Step 1–2 (no pure unit test; this is fd plumbing — covered by the KVM e2e in Task B-final).** State this explicitly in the commit.

**Step 3 — Implement** (mirror the vsock-listener handling exactly):
- Add `const WORKER_CONTROL_FD: RawFd = 13;`.
- Create the snapshot root the worker writes into, inside the jail so it survives the chroot: `let snap_root = jail_root.join("snapshots"); std::fs::create_dir_all(&snap_root)?;` and make it writable by the dropped uid (it must be writable, unlike the 0644 read-only kernel/rootfs — `chmod 0777` or chown to `WORKER_UID`; prefer chown to `WORKER_UID:WORKER_GID` then 0755).
- Bind the control socket next to the vsock one: `let control_path = jail.join("control.sock"); let control_listener = bind_vsock_listener(&control_path)?;` (reuse the helper — rename its doc, it just binds a UDS replacing a stale socket).
- Pass `control_listener.as_raw_fd()` into `spawn_worker`; add `--control-fd WORKER_CONTROL_FD` and a `dup2(control_fd, WORKER_CONTROL_FD)` in `pre_exec`.
- `drop(control_listener)` after spawn (the worker owns its copy), and add `control_path` to `LaunchOutcome`.

**Step 4 — Verify:** `cargo check -p mm-host --target x86_64-unknown-linux-gnu` → Expected: builds. `cargo clippy` clean.

**Step 5 — Commit:** `git add -A && git commit -m "feat(host): bind control.sock + pass fd 13 to the jailed worker"`

---

# Phase B — Single-host CLI verbs

## Task B1: `mm snapshot` client connector (pure-testable framing + control client)

**Files:**
- Create: `apps/mm/src/commands/snapshot.rs`
- Modify: `apps/mm/src/commands/mod.rs` (`pub mod snapshot;`), `apps/mm/src/main.rs:33-50` (+ `Snapshot(commands::snapshot::SnapshotArgs)`), `:85-93` (local dispatch).

**Step 1 — Typed-first + failing test.** Define `SnapshotArgs` (clap subcommands `create`/`ls`/`rm`/`gc`) and a pure `control_client::send(path, ControlRequest) -> Result<ControlResponse>` whose framing is unit-tested over a `UnixListener` pair on the dev host (no KVM — a plain UDS echo):

```rust
#[test]
fn control_client_round_trips_over_uds() {
    let dir = std::env::temp_dir().join(format!("mm-ctl-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("control.sock");
    let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let h = std::thread::spawn(move || {
        use std::io::{BufRead, BufReader, Write};
        let (mut c, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(&c).read_line(&mut line).unwrap();
        assert_eq!(line.trim_end(), "SNAPSHOT s1");
        c.write_all(b"OK s1\n").unwrap();
    });
    let resp = send_control(&sock, &mm_host::control_proto::ControlRequest::Snapshot { dir: "s1".into() }).unwrap();
    assert_eq!(resp, mm_host::control_proto::ControlResponse::Ok { id: "s1".into() });
    h.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
```

**Step 2 — Run:** `cargo test -p mm snapshot` → FAIL.

**Step 3 — Implement** `send_control` (connect, write `req.encode()`, read one line, `ControlResponse::parse`) and `SnapshotArgs` + `run`:
- `mm snapshot create <name> [--keep N] [--branch]`: resolve the machine via `Store` (mirror `exec.rs:27-33`), `SnapshotStore::new_snapshot_dir(name)` (under `<state_root>/snapshots/<name>/`), but the **worker** writes inside its jail — so the create path is: allocate the id, `send_control(<state_root>/jails/<name>/control.sock, Snapshot{dir:id})` (or `Branch` with `--branch`), then the worker writes `<jail_root>/snapshots/<id>`. Reconcile the two locations: the jail's `snapshots/` is the store root for that machine (bind the store at `<jail_root>/snapshots` OR have the parent move/symlink). **Simplest:** point `SnapshotStore` at `<jail_root>/snapshots` for create/ls/rm/gc so the parent and worker share one directory. Print the new id. Then `gc(name, keep)` if `--keep`.
- `mm snapshot ls <name>`: `SnapshotStore::list` → table (id, created, RAM, kind).
- `mm snapshot rm <name> <id>`: `SnapshotStore::remove`.
- `mm snapshot gc <name> --keep N`: `SnapshotStore::gc`.

**Step 4 — Verify:** `cargo test -p mm snapshot` PASS; `cargo build -p mm` (macOS ok); `cargo clippy -p mm --all-targets` clean.

**Step 5 — Commit:** `git add -A && git commit -m "feat(cli): mm snapshot create/ls/rm/gc over the worker control channel + SnapshotStore"`

## Task B2: `mm_host::restore_launch` — boot a fresh microVM from a snapshot dir

**Files:**
- Create: `crates/mm-host/src/restore.rs` (+ `pub use` in `lib.rs`)
- Modify: `crates/mm-host/src/worker.rs` (a `--restore-dir` path that calls `mm_vmm::snapshot::restore` instead of `Machine::boot_jailed`).

**Step 1–2:** fd/boot plumbing — verified by the Task B-final KVM e2e, not a pure unit test (state this in the commit). Add a pure unit test only for any new arg parsing.

**Step 3 — Implement** `restore_launch(spec, snapshot_dir)`: identical to `launch` through the jail/fd/TAP/vsock/control setup, but (a) it does NOT build a rootfs from an OCI image (the snapshot's `memory.bin`+`state.bin` carry the guest), (b) it links the snapshot dir into the jail, (c) the worker, given `--restore-dir`, calls `mm_vmm::snapshot::restore(&config, kvm_fd, tap_fds, vsock_fd, hook, dir)` to get a live `Machine`, then proceeds exactly as the boot path (wait_for_ready optional; serve + control loop). Reuse `build_vm_config` for the device set (must match the snapshot's). The cross-host CPU guard already fires inside `restore`.

**Step 4 — Verify:** `cargo check -p mm-host --target x86_64-unknown-linux-gnu` builds; clippy clean.

**Step 5 — Commit:** `git add -A && git commit -m "feat(host): restore_launch — boot a fresh jailed microVM from a snapshot dir"`

## Task B3: `mm restore` + `mm branch` CLI verbs

**Files:**
- Create: `apps/mm/src/commands/restore.rs`, `apps/mm/src/commands/branch.rs`
- Modify: `apps/mm/src/commands/mod.rs`, `apps/mm/src/main.rs` (+ `Restore`, `Branch` variants + local dispatch; in cluster mode they route via REST — see Phase C, or bail with a clear message until C lands).

**Step 1 — Typed-first + failing test:** arg structs (`RestoreArgs { name, id, new_name }`, `BranchArgs { name, new_name, [--keep N] }`) with a unit test asserting clap parses them (e.g. `RestoreArgs::try_parse_from`).

**Step 2 — Run:** `cargo test -p mm restore` / `branch` → FAIL.

**Step 3 — Implement:**
- `mm restore <name> <id> <new-name>`: resolve `<name>`'s snapshot dir via `SnapshotStore::find`, call `mm_host::restore_launch` with a `LaunchSpec` for `<new-name>` pointing at that dir, persist a new `MachineRecord` (mirror `run.rs`).
- `mm branch <name> <new-name> [--keep N]`: `send_control(.../control.sock, Branch{dir:id})` to materialize a branch snapshot of the live `<name>`, then `restore_launch` a new machine `<new-name>` from that branch dir (a live clone). Persist its record.

**Step 4 — Verify:** `cargo test -p mm` PASS; clippy clean; `cargo build -p mm`.

**Step 5 — Commit:** `git add -A && git commit -m "feat(cli): mm restore <id> + mm branch — boot a machine from a snapshot/branch"`

## Task B4: single-host KVM e2e (the proof)

**Files:**
- Create: `apps/mm/tests/snapshot_cli_kvm.rs` (`#[ignore]`, `#![cfg(all(target_os="linux", feature="kvm-integration"))]` mirroring `apps/mm/tests/exec_kvm.rs`)
- Modify: `.github/workflows/ci.yml` (add a `snapshot-cli-integration` job mirroring `exec-integration`).

**Step 1 — Write the e2e:** `mm run --sandbox` a guest → `mm snapshot create <name>` (assert a store dir with a valid `manifest.json` appears) → `mm restore <name> <id> clone` → `mm exec clone -- ...` returns expected output (the restored guest is alive) → `mm branch <name> live-clone` → `mm exec live-clone` works AND the original `<name>` is still running. Assert exit codes + output.

**Step 2 — Run (CI only):** `cargo test -p mm --features kvm-integration --test snapshot_cli_kvm -- --ignored --nocapture --test-threads=1` → Expected (CI): PASS. (Serial like `fork_kvm` — these boot multiple guests.)

**Step 3 — n/a (test is the deliverable).**

**Step 5 — Commit:** `git add -A && git commit -m "test(cli): KVM e2e — mm snapshot/restore/branch end-to-end + CI job"`

---

# Phase C — Cluster `Snapshot` resource (REST + Postgres + gRPC)

## Task C1: `snapshots` table migration (contract-first schema)

**Files:** Create `services/mm-controller/migrations/0002_snapshots.sql`.

```sql
-- Snapshot resource (SPEC-1 FR-18). A point-in-time image of a machine, taken on the
-- agent owning its host and recorded here for listing/restore.
CREATE TABLE snapshots (
  uid UUID PRIMARY KEY,
  namespace TEXT NOT NULL REFERENCES namespaces(name) ON DELETE CASCADE,
  machine TEXT NOT NULL,            -- source machine name
  name TEXT NOT NULL,               -- snapshot id (store-allocated)
  kind TEXT NOT NULL,               -- 'full' | 'branch'
  host_id TEXT NOT NULL,            -- host the snapshot lives on
  memory_mib BIGINT NOT NULL,
  status TEXT NOT NULL,             -- 'creating' | 'ready' | 'failed'
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (namespace, machine, name)
);
CREATE INDEX snapshots_ns_idx ON snapshots(namespace);
```

**Verify:** the `controller` CI job applies migrations against `postgres:16`; this runs there. Locally `cargo build -p mm-controller` (sqlx offline/macro check). **Commit:** `git commit -m "feat(controller): snapshots table migration (FR-18 Snapshot resource)"`.

## Task C2: `Snapshot` model + store CRUD (typed-first, TDD pure serde)

**Files:** Modify `services/mm-controller/src/model.rs` (+ `Snapshot` struct, serde, mirroring the `Machine` record), `services/mm-controller/src/store.rs` (+ `create_snapshot`/`list_snapshots`/`get_snapshot`/`delete_snapshot`/`set_snapshot_status`, mirroring the machine CRUD).

**Step 1 — Failing test:** a serde round-trip unit test for `Snapshot` in `model.rs` (mirror existing model tests).
**Step 3 — Implement** the struct + sqlx queries (mirror `store.rs` machine methods; `set_snapshot_status` mirrors `increment_retry_count`'s update shape).
**Verify:** `cargo test -p mm-controller model` PASS; CI `controller` job covers the DB queries. **Commit:** `git commit -m "feat(controller): Snapshot model + Postgres CRUD"`.

## Task C3: Snapshot reverse-channel proto (contract-first)

**Files:** Modify `crates/mm-proto/proto/machine.proto`.

Mirror the exec reverse-channel exactly (the agent is client-only):
```proto
// In service MachineService:
rpc WatchSnapshots(HostRef) returns (stream SnapshotTask);   // controller -> agent
rpc ReportSnapshotResult(SnapshotResult) returns (Ack);      // agent -> controller

message SnapshotTask {
  string request_id = 1; MachineRef ref = 2; string dir = 3; bool branch = 4;
}
message SnapshotResult {
  string request_id = 1; string id = 2; bool ok = 3; string error = 4;
  uint64 memory_mib = 5;
}
```

**Verify:** `cargo build -p mm-proto` regenerates; `cargo build -p mm-controller -p mm-agent`. **Commit:** `git commit -m "feat(proto): WatchSnapshots/ReportSnapshotResult reverse-channel"`.

## Task C4: controller `SnapshotDispatcher` + gRPC wiring

**Files:** Modify `services/mm-controller/src/grpc.rs` (add a `SnapshotDispatcher` mirroring `ExecDispatcher`: `request_id → oneshot/stream` routing, host→task-stream, timeout/cleanup, 503 when no agent), implement `WatchSnapshots`/`ReportSnapshotResult`.

**Step 1 — Failing test:** a unit test of the dispatcher routing (a result for `request_id` reaches the waiting caller; unknown host → unavailable) mirroring any existing `ExecDispatcher` test.
**Step 3 — Implement** mirroring `ExecDispatcher`.
**Verify:** `cargo test -p mm-controller grpc` PASS; clippy clean. **Commit:** `git commit -m "feat(controller): SnapshotDispatcher + gRPC reverse-channel handlers"`.

## Task C5: `Snapshot` REST resource

**Files:** Create `services/mm-controller/src/api/snapshots.rs`; modify `services/mm-controller/src/api/mod.rs:26-27` (`mod snapshots;`) + `:82-111` (routes).

Mirror `machines.rs` (auth → `ensure_allowed(Verb::Operator, ...)` → store → audit). Routes:
```
POST   /v1alpha1/namespaces/:ns/machines/:name/snapshots   -> snapshots::create  (dispatches WatchSnapshots task to the machine's host agent; records 'creating'→'ready')
GET    /v1alpha1/namespaces/:ns/machines/:name/snapshots   -> snapshots::list
DELETE /v1alpha1/namespaces/:ns/snapshots/:id              -> snapshots::delete
```
`create` resolves the machine's `host_id`, calls `state.snapshots.dispatch(host_id, SnapshotTask{...})` (the new dispatcher in `AppState`), persists the `Snapshot` row on the reported result. Add `pub snapshots: crate::grpc::SnapshotDispatcher` to `AppState` (mirror `exec`).

**Step 1 — Failing test:** extend `services/mm-controller/tests/api_pg.rs` (the DB-backed API test) with create/list/delete snapshot against a fake agent (mirror the exec test path), asserting RBAC (cross-ns → 403) + the row lifecycle.
**Verify:** `cargo build -p mm-controller`; the `controller` CI job runs `api_pg`. **Commit:** `git commit -m "feat(controller): Snapshot REST resource (create/list/delete) routed to the host agent"`.

## Task C6: agent — serve snapshot tasks against its host worker

**Files:** Modify `services/mm-agent/src/exec.rs` (or a new `snapshot.rs`) — open `WatchSnapshots`, on a `SnapshotTask` resolve the local machine's `control.sock` (the agent boots via `mm_host::launch`, so it knows the jail path), `send_control(Snapshot|Branch)`, and `ReportSnapshotResult`. Mirror the existing `WatchExec` handler in the agent.

**Step 1 — Failing test:** unit-test the task→control-request mapping (pure) if factored; otherwise covered by `cluster-e2e.sh`.
**Step 3 — Implement** mirroring the agent's exec reverse-channel.
**Verify:** `cargo build -p mm-agent`; clippy. Extend `scripts/cluster-e2e.sh` with a snapshot create→list assertion (runs in `cluster-integration`). **Commit:** `git commit -m "feat(agent): serve cluster snapshot tasks via the worker control channel"`.

---

# Phase D — Docs + memory

## Task D1: README + design-doc + memory updates
- `README.md`: add `snapshot`, `restore`, `branch` to the CLI verb list + a `Snapshot` row to the REST resource description; a short "Snapshots & live clones" subsection in Quickstart (real commands only).
- `docs/plans/2026-06-02-snapshot-lifecycle-cli.md`: mark the creation path BUILT.
- Update memory `m3-sandbox-progress.md`: snapshot/branch user surface shipped.
- **Commit:** `git commit -m "docs: snapshot/restore/branch user surface (CLI + cluster Snapshot resource)"`.

---

## Verification strategy (per the chosen "pure-core local + KVM e2e in CI")
- **Local (macOS dev host):** control protocol round-trips (A1), control dispatch (A2), control-client UDS framing (B1), CLI arg parsing (B3), Snapshot serde (C2), dispatcher routing (C4). `cargo test -p mm-host -p mm` + `cargo clippy --workspace --all-targets` + `cargo check -p mm-vmm/-p mm-host --target x86_64-unknown-linux-gnu`.
- **CI:** `snapshot-cli-integration` (B4, single-host `mm snapshot/restore/branch` on `/dev/kvm`), the `controller` job (C1/C2/C5 against `postgres:16`), and `cluster-integration` (`cluster-e2e.sh` extended in C6).

## Out of scope (separate efforts / their own plans)
- FR-16 Phase 2 (fully-lazy post-copy branch) + the deterministic concurrent-writer WP-assert test.
- `start`/`logs`/`images`/`kernels` CLI verbs; `Image`/`Kernel`/`Disk`/`Secret`/`Fleet` REST resources.
- Per-tenant quota enforcement; destroy-on-delete agent teardown; M4 GitOps; M5 build-target matrix; M6 Node/TS edge; HA leader election.
