//! Generate the kernel `ip=` parameter for static guest networking (SPEC-1 FR-11).
use std::net::Ipv4Addr;

/// Build the `ip=<client>::<gw>:<mask>:<host>:<iface>:off` kernel cmdline fragment.
/// This removes any in-guest DHCP/cloud-init dependency (works with a read-only rootfs).
pub fn ip_cmdline(
    client: Ipv4Addr,
    gateway: Ipv4Addr,
    mask: Ipv4Addr,
    hostname: &str,
    iface: &str,
) -> String {
    format!("ip={client}::{gateway}:{mask}:{hostname}:{iface}:off")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn formats_static_ip_param() {
        let s = ip_cmdline(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            "web-1",
            "eth0",
        );
        assert_eq!(s, "ip=10.0.0.2::10.0.0.1:255.255.255.0:web-1:eth0:off");
    }
}
