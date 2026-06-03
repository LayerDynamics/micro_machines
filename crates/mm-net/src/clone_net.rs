//! Per-clone networking *planning* — netns + veth + NAT re-IP for `mm branch` live
//! clones (SPEC-1 FR-16).
//!
//! A restored/branched guest resumes with the IP baked into its captured RAM (e.g.
//! `10.0.0.2`), so two clones of one source would collide at L2 on the shared bridge.
//! This module computes the addressing + the exact `ip`/`iptables` argument vectors that
//! put each clone in its own network namespace and NAT its internal IP to a unique,
//! host-routable `clone_ip` (the Firecracker "network for clones" recipe). The guest is
//! unaware — it keeps its internal IP; the host reaches it at `clone_ip`.
//!
//! Everything here is **pure and host-agnostic** (native-tested). The privileged
//! execution (running `ip`/`iptables`, `setns`, opening the TAP in the netns) is
//! Linux-only and lives in [`clone_host`](crate::clone_host).
use std::net::Ipv4Addr;

/// Base /16 the clone↔host veth `/30` point-to-point links are carved from. Private and
/// deliberately disjoint from the guest-internal `10.0.0.0/24`, so a veth address can
/// never collide with a guest's baked-in IP. 16384 `/30` blocks ⇒ 16384 concurrent clones.
pub const VETH_BASE: [u8; 2] = [10, 201];

/// The `/30` point-to-point link between the host root netns and one clone's netns.
/// Carved from [`VETH_BASE`]`/16` by clone slot `index`: block `index*4`, host end at
/// `+1`, netns end at `+2` (`.0` network, `.3` broadcast unused).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VethLink {
    /// Root-netns end of the link (`.1` of the `/30`) — the clone's default gateway.
    pub host_addr: Ipv4Addr,
    /// Clone-netns end of the link (`.2` of the `/30`).
    pub netns_addr: Ipv4Addr,
    /// Prefix length of the link subnet (always 30).
    pub prefix_len: u8,
}

impl VethLink {
    /// The `/30` for clone slot `index`. Returns `None` if `index` overflows the `/16`
    /// (≥ 16384), so allocation fails cleanly rather than aliasing another clone's link.
    pub fn for_index(index: u32) -> Option<Self> {
        // 4 addresses per /30; the /16 holds 65536, i.e. indices 0..16384.
        let offset = index.checked_mul(4)?;
        if offset >= 65536 {
            return None;
        }
        let third = (offset >> 8) as u8;
        let host_octet = (offset & 0xff) as u8;
        Some(Self {
            host_addr: Ipv4Addr::new(VETH_BASE[0], VETH_BASE[1], third, host_octet + 1),
            netns_addr: Ipv4Addr::new(VETH_BASE[0], VETH_BASE[1], third, host_octet + 2),
            prefix_len: 30,
        })
    }

    /// The host end as `addr/prefix` (for `ip addr add`).
    pub fn host_cidr(&self) -> String {
        format!("{}/{}", self.host_addr, self.prefix_len)
    }

    /// The netns end as `addr/prefix` (for `ip addr add` inside the netns).
    pub fn netns_cidr(&self) -> String {
        format!("{}/{}", self.netns_addr, self.prefix_len)
    }
}

/// The network namespace name for a clone machine (`mm-clone-<name>`).
pub fn netns_name(machine: &str) -> String {
    format!("mm-clone-{machine}")
}

/// The root-netns (host) end veth interface name for clone slot `index`. Kept within the
/// 15-char Linux interface-name limit (`mmvh` + up to 11 digits).
pub fn host_veth_name(index: u32) -> String {
    format!("mmvh{index}")
}

/// The clone-netns end veth interface name for clone slot `index` (`mmvc<index>`).
pub fn netns_veth_name(index: u32) -> String {
    format!("mmvc{index}")
}

/// A fully-resolved per-clone networking plan: the addresses, names, and the upstream
/// egress interface needed to build (and tear down) one clone's netns + veth + NAT.
/// `internal_ip` is the guest's baked-in IP (kept inside the netns); `clone_ip` is the
/// unique host-routable address the clone is reached at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloneNetPlan {
    pub index: u32,
    pub netns: String,
    pub host_veth: String,
    pub netns_veth: String,
    pub link: VethLink,
    /// The guest's internal IP (DNAT target inside the netns; the guest keeps using it).
    pub internal_ip: Ipv4Addr,
    /// The unique host-routable address the clone is reached at (SNAT source on egress).
    pub clone_ip: Ipv4Addr,
    /// The host's upstream/egress interface that clone traffic is masqueraded out of.
    pub upstream: String,
    /// The guest's internal TAP device name (created inside the netns).
    pub tap: String,
}

impl CloneNetPlan {
    /// Assemble a plan for clone slot `index`. Returns `None` if `index` overflows the
    /// veth `/16` (see [`VethLink::for_index`]).
    pub fn new(
        index: u32,
        machine: &str,
        internal_ip: Ipv4Addr,
        clone_ip: Ipv4Addr,
        upstream: &str,
        tap: &str,
    ) -> Option<Self> {
        Some(Self {
            index,
            netns: netns_name(machine),
            host_veth: host_veth_name(index),
            netns_veth: netns_veth_name(index),
            link: VethLink::for_index(index)?,
            internal_ip,
            clone_ip,
            upstream: upstream.to_string(),
            tap: tap.to_string(),
        })
    }

    // --- `ip` argument vectors (run via the privileged Linux executor) ----------------

    /// `ip netns add <ns>`.
    pub fn netns_add_args(&self) -> Vec<String> {
        vec!["netns".into(), "add".into(), self.netns.clone()]
    }

    /// `ip netns del <ns>` (teardown; also removes the in-netns end of the veth + rules).
    pub fn netns_del_args(&self) -> Vec<String> {
        vec!["netns".into(), "del".into(), self.netns.clone()]
    }

    /// `ip link add <host_veth> type veth peer name <netns_veth> netns <ns>` — create the
    /// pair with the clone end placed directly into the clone netns.
    pub fn veth_add_args(&self) -> Vec<String> {
        vec![
            "link".into(),
            "add".into(),
            self.host_veth.clone(),
            "type".into(),
            "veth".into(),
            "peer".into(),
            "name".into(),
            self.netns_veth.clone(),
            "netns".into(),
            self.netns.clone(),
        ]
    }

    /// `ip link del <host_veth>` — teardown of the host end (the netns end goes with the
    /// netns). Idempotent at the call site (a missing link is not an error to surface).
    pub fn veth_del_args(&self) -> Vec<String> {
        vec!["link".into(), "del".into(), self.host_veth.clone()]
    }

    /// `ip addr add <host_cidr> dev <host_veth>` — address the root-netns end.
    pub fn host_addr_args(&self) -> Vec<String> {
        vec![
            "addr".into(),
            "add".into(),
            self.link.host_cidr(),
            "dev".into(),
            self.host_veth.clone(),
        ]
    }

    /// `ip link set <host_veth> up`.
    pub fn host_link_up_args(&self) -> Vec<String> {
        vec![
            "link".into(),
            "set".into(),
            self.host_veth.clone(),
            "up".into(),
        ]
    }

    /// `ip route add <clone_ip>/32 via <netns_addr>` — host ingress route to the clone.
    pub fn host_route_args(&self) -> Vec<String> {
        vec![
            "route".into(),
            "add".into(),
            format!("{}/32", self.clone_ip),
            "via".into(),
            self.link.netns_addr.to_string(),
        ]
    }

    /// `ip route del <clone_ip>/32` — teardown of the host ingress route.
    pub fn host_route_del_args(&self) -> Vec<String> {
        vec![
            "route".into(),
            "del".into(),
            format!("{}/32", self.clone_ip),
        ]
    }

    // --- in-netns `ip` argument vectors (prefixed `ip -n <ns> ...` by the executor) ---

    /// `addr add <netns_cidr> dev <netns_veth>` — address the clone end.
    pub fn netns_veth_addr_args(&self) -> Vec<String> {
        vec![
            "addr".into(),
            "add".into(),
            self.link.netns_cidr(),
            "dev".into(),
            self.netns_veth.clone(),
        ]
    }

    /// `link set <netns_veth> up`.
    pub fn netns_veth_up_args(&self) -> Vec<String> {
        vec![
            "link".into(),
            "set".into(),
            self.netns_veth.clone(),
            "up".into(),
        ]
    }

    /// `link set lo up` — the loopback inside the fresh netns.
    pub fn netns_lo_up_args(&self) -> Vec<String> {
        vec!["link".into(), "set".into(), "lo".into(), "up".into()]
    }

    /// `route add default via <host_addr>` — the clone's default route via the host end.
    pub fn netns_default_route_args(&self) -> Vec<String> {
        vec![
            "route".into(),
            "add".into(),
            "default".into(),
            "via".into(),
            self.link.host_addr.to_string(),
        ]
    }

    /// `addr add <internal_gw>/24 dev <tap>` — the in-netns gateway the guest talks to on
    /// its internal subnet (the guest keeps `internal_ip`; the netns owns the `.1`).
    pub fn netns_tap_addr_args(&self) -> Vec<String> {
        vec![
            "addr".into(),
            "add".into(),
            format!("{}/24", internal_gateway(self.internal_ip)),
            "dev".into(),
            self.tap.clone(),
        ]
    }

    /// `link set <tap> up`.
    pub fn netns_tap_up_args(&self) -> Vec<String> {
        vec!["link".into(), "set".into(), self.tap.clone(), "up".into()]
    }

    // --- `iptables` argument vectors (`-n <ns>`/host context applied by the executor) --

    /// In-netns egress SNAT: the guest's internal IP appears as `clone_ip` upstream.
    /// `-t nat <action> POSTROUTING -s <internal_ip> -o <netns_veth> -j SNAT --to <clone_ip>`.
    pub fn snat_args(&self, action: &str) -> Vec<String> {
        vec![
            "-t".into(),
            "nat".into(),
            action.into(),
            "POSTROUTING".into(),
            "-s".into(),
            self.internal_ip.to_string(),
            "-o".into(),
            self.netns_veth.clone(),
            "-j".into(),
            "SNAT".into(),
            "--to".into(),
            self.clone_ip.to_string(),
        ]
    }

    /// In-netns ingress DNAT: traffic to `clone_ip` is rewritten to the guest's internal
    /// IP. `-t nat <action> PREROUTING -i <netns_veth> -d <clone_ip> -j DNAT --to <internal_ip>`.
    pub fn dnat_args(&self, action: &str) -> Vec<String> {
        vec![
            "-t".into(),
            "nat".into(),
            action.into(),
            "PREROUTING".into(),
            "-i".into(),
            self.netns_veth.clone(),
            "-d".into(),
            self.clone_ip.to_string(),
            "-j".into(),
            "DNAT".into(),
            "--to".into(),
            self.internal_ip.to_string(),
        ]
    }

    /// Host-side MASQUERADE of the clone's veth `/30` out the upstream interface.
    /// `-t nat <action> POSTROUTING -s <link/30> -o <upstream> -j MASQUERADE`.
    pub fn host_masq_args(&self, action: &str) -> Vec<String> {
        vec![
            "-t".into(),
            "nat".into(),
            action.into(),
            "POSTROUTING".into(),
            "-s".into(),
            format!("{}/{}", network_addr(self.link.host_addr, 30), 30),
            "-o".into(),
            self.upstream.clone(),
            "-j".into(),
            "MASQUERADE".into(),
        ]
    }
}

/// The internal gateway (`.1`) of the guest's `/24` — what the in-netns TAP is addressed
/// with so the guest's existing default route (to its `.1`) still resolves.
fn internal_gateway(internal_ip: Ipv4Addr) -> Ipv4Addr {
    let o = internal_ip.octets();
    Ipv4Addr::new(o[0], o[1], o[2], 1)
}

/// The network (lowest) address of the `/prefix` block containing `addr`. Used to render
/// the veth `/30` as its network CIDR for the MASQUERADE source match.
fn network_addr(addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let bits = u32::from(addr);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from(bits & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn veth_links_are_disjoint_per_index_and_in_the_private_16() {
        let l0 = VethLink::for_index(0).unwrap();
        assert_eq!(l0.host_addr, Ipv4Addr::new(10, 201, 0, 1));
        assert_eq!(l0.netns_addr, Ipv4Addr::new(10, 201, 0, 2));
        assert_eq!(l0.prefix_len, 30);

        let l1 = VethLink::for_index(1).unwrap();
        assert_eq!(l1.host_addr, Ipv4Addr::new(10, 201, 0, 5));
        assert_eq!(l1.netns_addr, Ipv4Addr::new(10, 201, 0, 6));

        // Crossing the third-octet boundary: index 64 → offset 256.
        let l64 = VethLink::for_index(64).unwrap();
        assert_eq!(l64.host_addr, Ipv4Addr::new(10, 201, 1, 1));
    }

    #[test]
    fn veth_index_overflow_is_rejected_not_aliased() {
        assert!(VethLink::for_index(16383).is_some());
        assert!(VethLink::for_index(16384).is_none());
    }

    #[test]
    fn interface_names_are_within_the_15_char_limit() {
        // Even at the top of the index range the names fit Linux's IFNAMSIZ-1.
        assert!(host_veth_name(16383).len() <= 15);
        assert!(netns_veth_name(16383).len() <= 15);
        assert_eq!(host_veth_name(7), "mmvh7");
        assert_eq!(netns_veth_name(7), "mmvc7");
        assert_eq!(netns_name("web"), "mm-clone-web");
    }

    fn plan() -> CloneNetPlan {
        CloneNetPlan::new(
            3,
            "web",
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 50),
            "eth0",
            "mmtap3",
        )
        .unwrap()
    }

    #[test]
    fn veth_add_places_clone_end_in_the_netns() {
        let p = plan();
        assert_eq!(
            p.veth_add_args(),
            vec![
                "link",
                "add",
                "mmvh3",
                "type",
                "veth",
                "peer",
                "name",
                "mmvc3",
                "netns",
                "mm-clone-web"
            ]
        );
    }

    #[test]
    fn snat_rewrites_internal_ip_to_clone_ip_on_egress() {
        let p = plan();
        assert_eq!(
            p.snat_args("-A"),
            vec![
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                "10.0.0.2",
                "-o",
                "mmvc3",
                "-j",
                "SNAT",
                "--to",
                "10.0.0.50"
            ]
        );
        // The check/delete form differs only in the action token.
        assert_eq!(p.snat_args("-C")[2], "-C");
    }

    #[test]
    fn dnat_rewrites_clone_ip_to_internal_ip_on_ingress() {
        let p = plan();
        assert_eq!(
            p.dnat_args("-A"),
            vec![
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-i",
                "mmvc3",
                "-d",
                "10.0.0.50",
                "-j",
                "DNAT",
                "--to",
                "10.0.0.2"
            ]
        );
    }

    #[test]
    fn host_masq_uses_the_links_30_network_address() {
        let p = plan();
        // index 3 → offset 12 → host .13, netns .14; the /30 network is .12.
        assert_eq!(p.link.host_addr, Ipv4Addr::new(10, 201, 0, 13));
        assert_eq!(
            p.host_masq_args("-A"),
            vec![
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                "10.201.0.12/30",
                "-o",
                "eth0",
                "-j",
                "MASQUERADE"
            ]
        );
    }

    #[test]
    fn host_route_and_default_route_use_the_link_ends() {
        let p = plan();
        assert_eq!(
            p.host_route_args(),
            vec!["route", "add", "10.0.0.50/32", "via", "10.201.0.14"]
        );
        assert_eq!(
            p.netns_default_route_args(),
            vec!["route", "add", "default", "via", "10.201.0.13"]
        );
    }

    #[test]
    fn netns_tap_is_addressed_with_the_internal_gateway() {
        let p = plan();
        assert_eq!(
            p.netns_tap_addr_args(),
            vec!["addr", "add", "10.0.0.1/24", "dev", "mmtap3"]
        );
    }
}
