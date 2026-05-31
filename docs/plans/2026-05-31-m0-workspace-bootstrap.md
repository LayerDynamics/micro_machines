# M0 — Workspace Bootstrap Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use `lore:execute` to implement this plan task-by-task.
> **Scope guard:** Do ONLY what is listed here. If you discover adjacent issues, note them as a TODO and continue. Do NOT fix them.

**Goal:** Turn the empty MicroMachines scaffold into a working hybrid Cargo + pnpm monorepo with CI, licensing, a shared types crate, and dev tooling — the foundation every later milestone builds on.
**Architecture:** A Cargo workspace (`crates/`, `services/`, `apps/`, `tools/`) and a pnpm workspace (`packages/`) rooted at the repo. M0 creates only the shared foundation crate `mm-api-types` (real, immediately-used types) so the workspace compiles; component crates are created by the milestone that first needs them (YAGNI — no empty shells).
**Tech Stack:** Rust (stable, pinned via `rust-toolchain.toml`), Cargo workspace; Node 20 + pnpm workspace; GitHub Actions CI; Apache-2.0.
**Practices:** TDD for unit-testable logic (the `mm-api-types` tasks); contract-first (types defined before any consumer); verify-before-done gate on every task (a build/clippy/test command whose output is checked before the task is marked complete).
**Required skills:** `lore:execute` (run this plan), `lore:test-driven-development` (TDD tasks).
**Traceability:** Satisfies SPEC-1 constraints C1 (Rust + Node), C3 (Apache-2.0; no `reference_only` imports), C5 (hybrid monorepo, populate manifests), and seeds the §3.3 data model types.

> **Platform note:** M0 is fully cross-platform (no KVM). It can be built and verified on this macOS dev host. M1+ require Linux/KVM.

---

### Task 1: Initialize git and ignore rules

**Files:**
- Create: `.gitignore`

**Step 1: Initialize the repository**
```bash
cd /Users/ryanoboyle/micro_machines && git init && git branch -M main
```
→ Expected: `Initialized empty Git repository …`

**Step 2: Write `.gitignore`**
```gitignore
# Rust
/target
**/*.rs.bk
Cargo.lock.orig

# Node
node_modules/
dist/
.pnpm-store/
*.tsbuildinfo

# Editor / OS
.DS_Store
.idea/
.vscode/*
!.vscode/extensions.json

# MicroMachines build artifacts / VM images
/vms/*.img
/vms/*.elf
/data/*.db
*.log
```

**Step 3: Verify reference_only is preserved, not ignored**
```bash
git status --porcelain development/reference_only | head -1
```
→ Expected: a line beginning `?? development/reference_only/` (present, untracked — we will NOT commit these large vendored references; see Step 4).

**Step 4: Exclude reference_only from the repo (kept locally, never committed/imported)**
Append to `.gitignore`:
```gitignore
# Reference-only upstreams: inspiration/context, never imported or committed
/development/reference_only/
```

**Step 5: Verify**
```bash
git status --porcelain development/reference_only | wc -l
```
→ Expected: `0`

**Step 6: Commit**
```bash
git add .gitignore && git commit -m "chore: initialize git repo and gitignore"
```

---

### Task 2: Add the Apache-2.0 license

**Files:**
- Create: `LICENSE`
- Create: `NOTICE`

**Step 1: Fetch the canonical Apache-2.0 text**
```bash
curl -fsSL https://www.apache.org/licenses/LICENSE-2.0.txt -o LICENSE
```
→ Expected: a `LICENSE` file ~11 KB, first line `Apache License`.

**Step 2: Verify**
```bash
head -2 LICENSE && wc -l LICENSE
```
→ Expected: `Apache License` / `Version 2.0, January 2004` and ~202 lines.

**Step 3: Write `NOTICE`**
```text
MicroMachines
Copyright 2026 The MicroMachines Authors

This product includes software developed by The MicroMachines Authors.
Licensed under the Apache License, Version 2.0.
```

**Step 4: Commit**
```bash
git add LICENSE NOTICE && git commit -m "chore: add Apache-2.0 license and NOTICE"
```

---

### Task 3: Pin the Rust toolchain

**Files:**
- Create: `rust-toolchain.toml`
- Create: `rustfmt.toml`
- Create: `.cargo/config.toml`

**Step 1: `rust-toolchain.toml`**
```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
targets = ["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"]
```

**Step 2: `rustfmt.toml`**
```toml
edition = "2021"
max_width = 100
imports_granularity = "Module"
group_imports = "StdExternalCrate"
```

**Step 3: `.cargo/config.toml`** (workspace-wide lint denials so CI and local agree)
```toml
[build]
# Keep default host target locally; CI cross-builds the musl guest targets explicitly.

[target.'cfg(all())']
rustflags = ["-Dwarnings"]
```

**Step 4: Verify the toolchain resolves**
```bash
rustup show active-toolchain || rustc --version
```
→ Expected: a `stable-*` toolchain and a `rustc 1.x` version line (no error).

**Step 5: Commit**
```bash
git add rust-toolchain.toml rustfmt.toml .cargo/config.toml && git commit -m "chore: pin rust toolchain and lint config"
```

---

### Task 4: Define the Cargo workspace root

**Files:**
- Modify: `Cargo.toml` (currently empty)

**Step 1: Write the workspace manifest**
```toml
[workspace]
resolver = "2"
members = [
    "crates/mm-api-types",
]

[workspace.package]
version = "0.0.0"
edition = "2021"
license = "Apache-2.0"
repository = "https://github.com/layerdynamics/micro_machines"
authors = ["The MicroMachines Authors"]
rust-version = "1.74"

[workspace.dependencies]
# Shared third-party deps are declared here once; member crates reference them
# with `serde = { workspace = true }`. Versions are managed in this single place.
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
uuid = { version = "1", features = ["v4", "serde"] }
time = { version = "0.3", features = ["serde", "formatting", "parsing"] }

[profile.release]
lto = "thin"
codegen-units = 1
```

> **Note:** Only `mm-api-types` is a member now. Later milestones add their crates to `members` as the first task of that milestone (M1 adds `crates/mm-vmm`, `crates/mm-init`; M2 adds `services/*`; etc.). This keeps the workspace buildable with no empty placeholder crates.

**Step 2: Verify it parses (will fail until Task 5 creates the member)**
```bash
cargo metadata --no-deps --format-version 1 >/dev/null 2>&1; echo "exit=$?"
```
→ Expected: `exit=` non-zero (member `mm-api-types` does not exist yet). This is expected; Task 5 makes it pass. Do not commit yet.

---

### Task 5 (TDD): Create `mm-api-types` with the shared `ObjectMeta` and `State`

**Files:**
- Create: `crates/mm-api-types/Cargo.toml`
- Create: `crates/mm-api-types/src/lib.rs`
- Create: `crates/mm-api-types/src/meta.rs`
- Create: `crates/mm-api-types/src/state.rs`

**Traceability:** SPEC-1 §3.3 (data model — `metadata`, `Machine.status.state`), FR-7, FR-9.

**Step 1: `crates/mm-api-types/Cargo.toml`**
```toml
[package]
name = "mm-api-types"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
uuid = { workspace = true }
time = { workspace = true }
```

**Step 2: Write the failing test** — `crates/mm-api-types/src/state.rs`
```rust
//! Machine lifecycle state — SPEC-1 §3.3.
use serde::{Deserialize, Serialize};

/// The lifecycle state of a Machine (microVM). SPEC-1 §3.3 / Appendix B.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Created,
    Preparing,
    Starting,
    Running,
    Paused,
    Stopping,
    Stopped,
    Failed,
    Destroying,
    Destroyed,
}

impl State {
    /// A state is terminal if no further transition is expected without a new spec.
    pub fn is_terminal(self) -> bool {
        matches!(self, State::Stopped | State::Failed | State::Destroyed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_serializes_snake_case() {
        let json = serde_json::to_string(&State::Running).unwrap();
        assert_eq!(json, "\"running\"");
    }

    #[test]
    fn terminal_states_are_classified() {
        assert!(State::Stopped.is_terminal());
        assert!(State::Failed.is_terminal());
        assert!(!State::Running.is_terminal());
    }
}
```

**Step 3: Write `meta.rs`** — `crates/mm-api-types/src/meta.rs`
```rust
//! Common object metadata shared by all MicroMachines resources. SPEC-1 §3.3.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use uuid::Uuid;

/// Kubernetes-style metadata attached to every resource (SPEC-1 §3.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectMeta {
    pub uid: Uuid,
    pub name: String,
    #[serde(default = "default_namespace")]
    pub namespace: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

fn default_namespace() -> String {
    "default".to_string()
}

impl ObjectMeta {
    /// Create metadata for a new object in a namespace, generating a fresh uid.
    /// `now` is injected (not read from the clock) so callers stay testable.
    pub fn new(name: impl Into<String>, namespace: impl Into<String>, now: OffsetDateTime) -> Self {
        Self {
            uid: Uuid::new_v4(),
            name: name.into(),
            namespace: namespace.into(),
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
            created_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_meta_has_namespace_and_unique_uid() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let a = ObjectMeta::new("web", "team-a", now);
        let b = ObjectMeta::new("web", "team-a", now);
        assert_eq!(a.namespace, "team-a");
        assert_ne!(a.uid, b.uid, "each object gets a distinct uid");
    }

    #[test]
    fn namespace_defaults_when_absent_in_json() {
        let json = r#"{"uid":"00000000-0000-0000-0000-000000000000","name":"x","created_at":"1970-01-01T00:00:00Z"}"#;
        let m: ObjectMeta = serde_json::from_str(json).unwrap();
        assert_eq!(m.namespace, "default");
    }
}
```

**Step 4: `crates/mm-api-types/src/lib.rs`**
```rust
//! Shared API types for MicroMachines (SPEC-1 §3.3).
//!
//! This crate is the contract layer: every other crate depends on these types
//! rather than redefining spec/status shapes. Keep it dependency-light.
#![forbid(unsafe_code)]

mod meta;
mod state;

pub use meta::ObjectMeta;
pub use state::State;
```

**Step 5: Run the tests (verify-before-done gate)**
```bash
cargo test -p mm-api-types
```
→ Expected: `test result: ok. 4 passed; 0 failed`.

**Step 6: Lint and format gate**
```bash
cargo fmt --all --check && cargo clippy -p mm-api-types --all-targets
```
→ Expected: no diff from fmt; clippy finishes with no warnings (warnings are denied).

**Step 7: Commit**
```bash
git add Cargo.toml crates/mm-api-types && git commit -m "feat(api-types): add ObjectMeta and State (SPEC-1 §3.3)"
```

---

### Task 6: Establish the pnpm workspace root

**Files:**
- Modify: `pnpm-workspace.yaml` (currently empty)
- Create: `package.json`
- Create: `.npmrc`
- Create: `tsconfig.base.json`

**Step 1: `pnpm-workspace.yaml`**
```yaml
packages:
  - "packages/*"
```

**Step 2: `package.json` (root, private)**
```json
{
  "name": "micromachines",
  "private": true,
  "version": "0.0.0",
  "license": "Apache-2.0",
  "engines": { "node": ">=20", "pnpm": ">=9" },
  "scripts": {
    "build": "pnpm -r build",
    "test": "pnpm -r test",
    "lint": "pnpm -r lint",
    "typecheck": "pnpm -r typecheck"
  },
  "devDependencies": {
    "typescript": "^5.5.0"
  }
}
```

**Step 3: `.npmrc`**
```ini
engine-strict=true
```

**Step 4: `tsconfig.base.json`** (extended by each package later)
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "declaration": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true
  }
}
```

**Step 5: Verify the workspace resolves (no packages yet is valid)**
```bash
pnpm install
```
→ Expected: completes; resolves the root `typescript` devDependency; "Done" with no errors. (An empty `packages/*` glob is valid.)

**Step 6: Commit**
```bash
git add pnpm-workspace.yaml package.json .npmrc tsconfig.base.json pnpm-lock.yaml && git commit -m "chore: establish pnpm workspace root"
```

---

### Task 7: CI pipeline (fmt, clippy, test; KVM job placeholder gated to Linux)

**Files:**
- Create: `.github/workflows/ci.yml`

**Step 1: Write the workflow**
```yaml
name: CI
on:
  push: { branches: [main] }
  pull_request: {}

jobs:
  rust:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { components: rustfmt, clippy }
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --all --check
      - run: cargo clippy --workspace --all-targets
      - run: cargo test --workspace

  node:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
        with: { version: 9 }
      - uses: actions/setup-node@v4
        with: { node-version: 20, cache: pnpm }
      - run: pnpm install --frozen-lockfile
      - run: pnpm -r typecheck
      - run: pnpm -r test

  # KVM-gated integration tests (added by M1). Runs only where /dev/kvm exists.
  kvm-integration:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Check KVM availability
        run: |
          if [ -e /dev/kvm ]; then echo "kvm=present"; else echo "kvm=absent (GitHub-hosted runners lack nested KVM; M1 wires a self-hosted/KVM-enabled runner)"; fi
      # M1 Task: add `cargo test -p mm-vmm --features kvm-integration -- --ignored` here.
```

**Step 2: Validate YAML locally**
```bash
python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('yaml ok')"
```
→ Expected: `yaml ok`.

**Step 3: Commit**
```bash
git add .github/workflows/ci.yml && git commit -m "ci: add fmt/clippy/test and Node pipelines (KVM job stub for M1)"
```

---

### Task 8: Repo README pointer and project doc map

**Files:**
- Modify: `README.md` (append a "Repository layout & docs" section; do NOT alter the existing product description)

**Step 1: Append (after the existing content)**
```markdown

## Repository layout

| Path | What lives here |
|------|-----------------|
| `crates/` | Rust libraries (VMM core, guest init, shared types, build lib) |
| `services/` | Long-running Rust services (host agent, control plane) |
| `apps/` | Binaries (the `mm` CLI) |
| `tools/` | Build/dev tooling (the build CLI) |
| `packages/` | TypeScript packages (SDK, dashboard, API gateway) |
| `vms/` | VM image / unikernel artifacts (git-ignored) |
| `docs/specs/` | Specifications — start with `SPEC-1-micromachines.md` |
| `docs/plans/` | Milestone implementation plans (M0–…) |
| `development/reference_only/` | Upstream projects for inspiration only — never imported (git-ignored) |

## Development

```bash
cargo build --workspace          # build all Rust crates
cargo test --workspace           # all Rust tests
cargo test -p <crate> <name>     # a single test
pnpm install && pnpm -r build    # build TypeScript packages
```

See `docs/specs/SPEC-1-micromachines.md` for the full architecture and `docs/plans/` for milestone breakdowns.
```

**Step 2: Verify the doc references resolve**
```bash
test -f docs/specs/SPEC-1-micromachines.md && echo "spec ok"; ls docs/plans/*.md | head
```
→ Expected: `spec ok` and the M0–M3 plan files listed.

**Step 3: Commit**
```bash
git add README.md && git commit -m "docs: add repository layout and dev commands to README"
```

---

### Task 9: Final M0 verification gate

**Step 1: Full workspace build + test + lint**
```bash
cargo build --workspace && cargo test --workspace && cargo clippy --workspace --all-targets && cargo fmt --all --check
```
→ Expected: build ok; `mm-api-types` 4 tests pass; clippy clean; fmt clean.

**Step 2: Node workspace check**
```bash
pnpm install --frozen-lockfile && pnpm -r typecheck
```
→ Expected: install ok; typecheck reports nothing to do (no packages yet) with no error.

**Step 3: Confirm git history**
```bash
git log --oneline
```
→ Expected: ~8 commits (Tasks 1–8), newest first.

**Exit criteria (M0 complete when ALL true):**
- [ ] `cargo build --workspace` and `cargo test --workspace` pass on a clean checkout.
- [ ] `cargo clippy --workspace --all-targets` is warning-free; `cargo fmt --all --check` clean.
- [ ] `pnpm install` succeeds; CI workflow YAML validates.
- [ ] `mm-api-types` exports `ObjectMeta` and `State` with passing tests (SPEC-1 §3.3).
- [ ] Apache-2.0 `LICENSE`/`NOTICE` present; `development/reference_only/` is git-ignored (never committed/imported).
- [ ] Git initialized; every task above is its own commit.

**TODOs discovered during M0** (note here, do NOT fix now): _none expected; record any here._
