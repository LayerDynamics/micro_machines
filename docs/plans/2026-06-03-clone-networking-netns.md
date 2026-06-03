# Clone networking: per-clone netns + NAT re-IP (`mm branch` live clones)

**Date:** 2026-06-03
**Status:** Design (milestone-scale; recommended as a focused build, ideally a fresh session)
**Tracks:** FR-16 `mm branch` live clones — the networking half. The snapshot/restore/branch
*engine* (FR-14/15/16) and the single-host snapshot/restore *user surface* (worker control
channel + `mm snapshot`/`mm restore`) are built + CI-green; this doc covers only the
networking a *live* clone needs.

## Problem

A restored/branched guest resumes with the IP baked into its captured RAM (e.g. `10.0.0.2`,
set by the kernel `ip=` param at original boot — the cmdline is discarded on restore). Two
machines with the same internal IP/MAC on one bridge collide at L2. For `mm restore` of a
**stopped** source this is fine (the IP is free) — that path is shipped. For `mm branch`'s
**live** clone (source still running) it is not: the clone needs a unique, routable host
identity while keeping its internal IP.

`mm exec` (vsock UDS) is **orthogonal and already works** for clones regardless of IP — this
milestone is only about IP-level reachability/egress for live clones.

## Topology (Firecracker clone-networking pattern; ref `development/reference_only/firecracker/docs/snapshotting/network-for-clones.md`)

Per clone `idx`:
1. **netns** `mm-clone-<name>`: `ip netns add mm-clone-<name>`. L2-isolates the clone so it
   can keep `10.0.0.2`/its MAC without colliding with the source or other clones.
2. **Guest TAP inside the netns**: the worker's virtio-net TAP must live in the clone netns.
   The parent enters the netns, creates the TAP, then exits (see fd/setns model below).
   `ip netns exec <ns> ip addr add <internal-gw>/24 dev <tap>` + up.
3. **veth pair** netns↔root: `ip link add veth-h-<idx> type veth peer name veth-c-<idx> netns
   mm-clone-<name>`. Host end `veth-h-<idx>` gets a unique `/30` (e.g. `10.<a>.<b>.1`); the
   netns end `veth-c-<idx>` gets `10.<a>.<b>.2`; default route in the netns via the host end.
4. **NAT (clone-local addressing)**, exact rules from the firecracker recipe:
   - egress: inside the netns, `iptables -t nat -A POSTROUTING -s <internal-subnet> -o
     veth-c-<idx> -j SNAT --to <clone-ip>` (so the guest's `10.0.0.2` appears as the unique
     `<clone-ip>` on the host network); and on the host, MASQUERADE the veth `/30` to the
     upstream iface.
   - ingress: host route `<clone-ip>` via the netns veth end; in the netns,
     `iptables -t nat -A PREROUTING -i veth-c-<idx> -d <clone-ip> -j DNAT --to 10.0.0.2`.
   - `iptables -P FORWARD ACCEPT` (host + netns) and `sysctl net.ipv4.ip_forward=1`.

The guest is unaware: it keeps `10.0.0.2`; the host reaches it at `<clone-ip>`.

## fd / setns model (the load-bearing risk — verify, don't assume)

The jailed worker takes a **TAP fd** and never enters the netns. The parent:
1. `setns(open("/proc/self/ns/net"), CLONE_NEWNET)` saved; `setns` into the clone netns,
2. `open_tun(<tap>)` — the TAP is created **in the clone netns**,
3. `setns` back to the original netns,
4. pass the TAP fd to the worker as today (fd 11).

**Must verify on CI (Phase-0 style spike before building the rest):**
- a TAP fd opened in a netns stays valid after the opener returns to its own netns and is
  used from a different process (the worker) — expected to hold (fd references the device),
  but prove it;
- `mm_sandbox::confine` (mount/pid/user-ns + chroot + cgroup) does **not** disturb the
  worker's use of that fd (it shouldn't — confine doesn't enter a net namespace), and the
  worker does not itself need `CAP_NET_ADMIN` (it only read/writes the fd).
- the veth/netns/NAT setup is all privileged parent work, before confinement (SPEC-1 C6).

## mm-net additions

- `clone_netns(name) -> NetnsHandle` (create/teardown netns).
- `veth_pair(...)`, `set_addr_in_netns(...)`, `route_in_netns(...)` — thin `ip` wrappers,
  mirroring `host.rs`'s `run()` style.
- `clone_nat(internal_subnet, clone_ip, veth, upstream)` — the SNAT/DNAT/MASQUERADE rule set,
  with **pure arg-builder fns** (like `masq_args`) unit-tested natively.
- `open_tun_in_netns(ns, name)` — setns-in, `open_tun`, setns-out; returns the fd.
- A **clone-IP IPAM** (pure, native-tested): allocate unique `<clone-ip>` + veth `/30`s,
  disjoint from the guest-internal `10.0.0.0/24`.

## Teardown (grows significantly — connects to the destroy-on-delete audit gap)

`mm rm` of a clone must remove: the netns (`ip netns del`), the host veth, the host route,
and the host-side iptables rules (the in-netns rules vanish with the netns). Today
`mm rm`/`teardown_tap` only deletes the TAP. Extend teardown to a `CloneNet` cleanup keyed by
the machine record (record the netns name + clone-ip + veth on the `MachineRecord`).

## Integration

- `RestoreSpec`/`restore_launch` gain an optional `CloneNet` (None = today's shared-bridge
  restore; Some = netns clone). `mm branch <name> <new>` builds the live branch (control
  `BRANCH` → snapshot dir) then `restore_launch` with a freshly-allocated `CloneNet`.
- `MachineRecord` gains the clone-net fields for teardown.

## Verification (pure-core local + KVM in CI)

- Native: clone-IP IPAM; the `ip`/`iptables` arg builders.
- New CI job **clone-net-integration**: `mm run` a source, `mm branch` a live clone, assert
  (a) `mm exec` into the clone works (vsock), (b) the clone is reachable at its `<clone-ip>`
  from the host while the source stays reachable at its IP (no collision), (c) teardown
  leaves no netns/veth/iptables residue. Plus the fd/setns spike test first.

## Sequencing

0. **fd/setns + confine spike** (cheap KVM test) — prove the TAP-in-netns fd model. Gate.
1. Pure cores (clone-IP IPAM + arg builders) + native tests.
2. mm-net netns/veth/NAT module + `open_tun_in_netns`.
3. `restore_launch` CloneNet integration + `MachineRecord` fields + teardown.
4. `mm branch` CLI.
5. clone-net-integration CI job + e2e.

## Why a focused/fresh build

This is a real networking subsystem (netns + veth + per-clone NAT + setns fd handling +
teardown), entirely Linux/KVM and not locally compilable (mm-host pulls the `branch`
feature/userfaultfd). It benefits from fresh context. The snapshot/restore surface it builds
on is shipped + CI-green; `mm exec` already covers vsock-reachable live clones today, so this
milestone adds IP-level reachability, not basic clone usability.
