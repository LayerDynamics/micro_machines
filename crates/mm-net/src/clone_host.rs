//! Privileged Linux executor for per-clone networking (SPEC-1 FR-16): create / tear down
//! a clone's network namespace + veth pair + NAT from a [`CloneNetPlan`], and open the
//! guest TAP **inside** the clone netns.
//!
//! The jailed worker never enters the netns — it only ever read/writes the TAP fd this
//! module hands it (fd 11, exactly like the shared-bridge path). All work here is
//! privileged and runs in the parent **before** the worker is confined (SPEC-1 C6).
//!
//! `setns(CLONE_NEWNET)` moves only the **calling thread**, so [`open_tun_in_netns`] does
//! it on a scoped thread whose namespace change never touches the caller; the returned fd
//! references the device and stays valid process-wide after that thread ends.
use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::thread;

use crate::clone_net::CloneNetPlan;
use crate::host::{open_tun, run, HostNetError};

/// Open `/dev/net/tun` and create TAP `tap` inside network namespace `netns` (which must
/// already exist, e.g. via `ip netns add`), returning the owning fd. The device lives in
/// the clone netns; the fd is usable from the root netns (and passable to the worker).
pub fn open_tun_in_netns(netns: &str, tap: &str) -> Result<File, HostNetError> {
    let netns = netns.to_string();
    let tap = tap.to_string();
    // Do the namespace switch + TAP create on a throwaway thread so the caller's process
    // netns is never changed. The fd outlives the thread (fds are process-wide).
    let raw: RawFd = thread::spawn(move || -> Result<RawFd, HostNetError> {
        let ns_path = format!("/run/netns/{netns}");
        let ns_file = File::open(&ns_path).map_err(HostNetError::Io)?;
        // SAFETY: `ns_file` is an open network-namespace fd; CLONE_NEWNET re-associates
        // only this thread's network namespace.
        if unsafe { libc::setns(ns_file.as_raw_fd(), libc::CLONE_NEWNET) } < 0 {
            return Err(HostNetError::Io(std::io::Error::last_os_error()));
        }
        // Created in THIS thread's (now the clone's) netns.
        let tap_file = open_tun(&tap)?;
        // Transfer ownership out of the thread without closing it on drop.
        Ok(tap_file.into_raw_fd())
    })
    .join()
    .map_err(|_| HostNetError::Spawn("open_tun_in_netns worker thread panicked".into()))??;

    // SAFETY: `raw` is an fd this process owns, handed back from the worker thread; no
    // other owner exists (the thread leaked its `File` via `into_raw_fd`).
    Ok(unsafe { File::from_raw_fd(raw) })
}

/// Convert a plan's owned-`String` arg vector into the `&str` slice `run` wants.
fn refs(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

/// `ip <args>` in the root netns.
fn ip(args: &[String]) -> Result<(), HostNetError> {
    run("ip", &refs(args))
}

/// `ip -n <ns> <args>` — an `ip` command inside the clone netns.
fn ip_in(ns: &str, args: &[String]) -> Result<(), HostNetError> {
    let mut v = vec!["-n", ns];
    let owned = refs(args);
    v.extend_from_slice(&owned);
    run("ip", &v)
}

/// `ip netns exec <ns> iptables <args>` — an `iptables` command inside the clone netns.
fn iptables_in(ns: &str, args: &[String]) -> Result<(), HostNetError> {
    let mut v = vec!["netns", "exec", ns, "iptables"];
    let owned = refs(args);
    v.extend_from_slice(&owned);
    run("ip", &v)
}

/// Create the clone's network namespace (`ip netns add <ns>`). Call **first**, before
/// [`open_tun_in_netns`] (the TAP is created inside this netns).
pub fn create_netns(plan: &CloneNetPlan) -> Result<(), HostNetError> {
    ip(&plan.netns_add_args())?;
    // Bring loopback up inside the fresh netns (some guest userland expects it).
    ip_in(&plan.netns, &plan.netns_lo_up_args())
}

/// Wire the clone's networking **after** the netns exists and its TAP has been created by
/// [`open_tun_in_netns`]: the veth pair (clone end placed in the netns), host + netns
/// addressing, the in-netns TAP gateway, routes, and the SNAT/DNAT/MASQUERADE rule set.
pub fn wire_clone_net(plan: &CloneNetPlan) -> Result<(), HostNetError> {
    // veth pair: host end in root netns, clone end dropped into the clone netns.
    ip(&plan.veth_add_args())?;
    ip(&plan.host_addr_args())?;
    ip(&plan.host_link_up_args())?;

    // Clone-netns end + the guest's internal gateway on the TAP + the default route out.
    ip_in(&plan.netns, &plan.netns_veth_addr_args())?;
    ip_in(&plan.netns, &plan.netns_veth_up_args())?;
    ip_in(&plan.netns, &plan.netns_tap_addr_args())?;
    ip_in(&plan.netns, &plan.netns_tap_up_args())?;
    ip_in(&plan.netns, &plan.netns_default_route_args())?;

    // Forwarding: route between the veth and the TAP inside the netns (host-wide
    // ip_forward is assumed enabled by setup/CI), with a permissive FORWARD policy on
    // both sides so the NAT'd path is not dropped.
    run(
        "ip",
        &[
            "netns",
            "exec",
            &plan.netns,
            "sysctl",
            "-q",
            "-w",
            "net.ipv4.ip_forward=1",
        ],
    )?;
    iptables_in(
        &plan.netns,
        &["-P".into(), "FORWARD".into(), "ACCEPT".into()],
    )?;
    run("iptables", &["-P", "FORWARD", "ACCEPT"])?;

    // NAT: rewrite the guest's internal IP ↔ the unique clone_ip, and masquerade the
    // /30 out the host upstream.
    iptables_in(&plan.netns, &plan.snat_args("-A"))?;
    iptables_in(&plan.netns, &plan.dnat_args("-A"))?;
    run("iptables", &refs(&plan.host_masq_args("-A")))?;

    // Host ingress route to the clone_ip via the netns veth end.
    ip(&plan.host_route_args())
}

/// Tear down everything [`create_netns`]/[`wire_clone_net`] built. Best-effort: each step
/// is attempted even if an earlier one failed (the netns/veth may be partially set up),
/// and the in-netns rules + clone veth end vanish with the netns. Returns the first error.
pub fn teardown_clone_net(plan: &CloneNetPlan) -> Result<(), HostNetError> {
    // Attempt every host-side teardown eagerly (the array runs all four), even if an
    // earlier one fails — a partially built clone net must still be cleaned. The in-netns
    // rules + clone veth end go away with the netns. Return the first error, if any.
    let mut first_err = None;
    for r in [
        run("iptables", &refs(&plan.host_masq_args("-D"))),
        ip(&plan.host_route_del_args()),
        ip(&plan.veth_del_args()),
        ip(&plan.netns_del_args()),
    ] {
        if let Err(e) = r {
            if first_err.is_none() {
                first_err = Some(e);
            }
        }
    }
    first_err.map_or(Ok(()), Err)
}
