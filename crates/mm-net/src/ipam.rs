//! IP address management — allocate guest IPs from a /24 pool (SPEC-1 FR-10).
use std::collections::BTreeSet;
use std::net::Ipv4Addr;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IpamError {
    #[error("ip pool exhausted")]
    Exhausted,
}

/// Allocates host-usable IPs from a /24, skipping network, gateway, and broadcast.
pub struct Ipam {
    base: [u8; 3],    // e.g. [10, 0, 0] for 10.0.0.0/24
    gateway_host: u8, // e.g. 1 -> 10.0.0.1 reserved as gateway
    allocated: BTreeSet<u8>,
}

impl Ipam {
    pub fn new(base: [u8; 3], gateway_host: u8) -> Self {
        Self {
            base,
            gateway_host,
            allocated: BTreeSet::new(),
        }
    }

    pub fn gateway(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.base[0], self.base[1], self.base[2], self.gateway_host)
    }

    /// Allocate the next free host octet in 1..=254, skipping gateway.
    pub fn allocate(&mut self) -> Result<Ipv4Addr, IpamError> {
        for host in 1u8..=254 {
            if host == self.gateway_host || self.allocated.contains(&host) {
                continue;
            }
            self.allocated.insert(host);
            return Ok(Ipv4Addr::new(
                self.base[0],
                self.base[1],
                self.base[2],
                host,
            ));
        }
        Err(IpamError::Exhausted)
    }

    pub fn release(&mut self, addr: Ipv4Addr) {
        self.allocated.remove(&addr.octets()[3]);
    }

    /// Mark `addr` as already in use without allocating a fresh one. Used to seed
    /// the pool from persisted state (each CLI invocation rebuilds the IPAM and
    /// must avoid IPs already handed out to running machines).
    pub fn reserve(&mut self, addr: Ipv4Addr) {
        self.allocated.insert(addr.octets()[3]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn skips_gateway_and_increments() {
        let mut ipam = Ipam::new([10, 0, 0], 1);
        assert_eq!(ipam.allocate().unwrap(), Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(ipam.allocate().unwrap(), Ipv4Addr::new(10, 0, 0, 3));
    }
    #[test]
    fn release_makes_address_reusable() {
        let mut ipam = Ipam::new([10, 0, 0], 1);
        let a = ipam.allocate().unwrap();
        ipam.release(a);
        assert_eq!(ipam.allocate().unwrap(), a);
    }
    #[test]
    fn exhausts_after_pool_is_full() {
        // 253 usable hosts (1..=254 minus the gateway at .1).
        let mut ipam = Ipam::new([10, 0, 0], 1);
        for _ in 0..253 {
            ipam.allocate().expect("address available");
        }
        assert_eq!(ipam.allocate(), Err(IpamError::Exhausted));
    }
}
