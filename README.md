# MicroMachines

MicroMachines is a rust based open source virtualization technology that is purpose-built
for creating and managing secure, multi-tenant container and function-based
services that provide serverless operational models with a container UX and
built-in GitOps management built in.

MicroMachines is a virtual machine monitor (VMM) that uses the Linux Kernel Virtual Machine (KVM) to create and run microVMs, like FireCracker but with more built in features useful for most development/deployment situations like internal automatic ip/ssh access, you can compile the vm into a self contained executable, or you can compile into unikernels (lightweight bootable disk images) and MicroVM rather than binaries. It also comes with a built in "Sandbox" Mode, which allows you to run agents/apps from within the sandboxed enviroment.

**Development/Reference_Only/** : is reference only, using them for inspiration and context never mporting them directly.

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
