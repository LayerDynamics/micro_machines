//! Privileged host networking: bridge, TAP, and NAT (SPEC-1 FR-10).
//!
//! MicroMachines gives each guest a static IP with zero in-guest config (the
//! kernel `ip=` param does that — see [`crate::bootparam`]). The host side of that
//! is a Linux bridge holding the gateway address, one TAP per microVM attached to
//! the bridge, and a MASQUERADE rule so guests reach the outside world. TAP
//! creation uses the `/dev/net/tun` ioctls directly (we need the fd and the exact
//! `IFF_TAP | IFF_NO_PI` flags); bridge/address/NAT setup shells out to the host
//! `ip`/`iptables`/`sysctl` tools, which is both robust and matches the prior art.
//!
//! All of this is privileged and must run **before** the jailer confines the VMM
//! (SPEC-1 C6): the unprivileged VMM process only ever sees the TAP fd.
use std::fs::File;
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::process::Command;

// /dev/net/tun ioctls and TAP interface flags (not all surfaced by `libc`).
const TUNSETIFF: libc::Ioctl = 0x4004_54ca;
const TUNSETPERSIST: libc::Ioctl = 0x4004_54cb;
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;

/// Errors from privileged host-network setup.
#[derive(Debug, thiserror::Error)]
pub enum HostNetError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to spawn `{0}` (is it installed and on PATH?)")]
    Spawn(String),
    #[error("command `{cmd}` failed: {stderr}")]
    Command { cmd: String, stderr: String },
    #[error("interface name too long: {0}")]
    NameTooLong(String),
}

/// A host TAP device attached to the bridge. Holds the owning fd; the device is
/// made persistent so the (jailed, unprivileged) VMM can open it by name.
#[derive(Debug)]
pub struct Tap {
    name: String,
    fd: File,
}

impl Tap {
    /// The TAP interface name (what the VMM opens / what `teardown` removes).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The owning file descriptor (usable directly as the virtio-net backend).
    pub fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.fd.as_raw_fd()
    }
}

/// Ensure bridge `name` exists, holds `gateway`/`prefix_len`, and is up. Idempotent.
pub fn ensure_bridge(name: &str, gateway: Ipv4Addr, prefix_len: u8) -> Result<(), HostNetError> {
    if !link_exists(name) {
        run("ip", &["link", "add", "name", name, "type", "bridge"])?;
    }
    // Assigning an address that is already present is not an error we care about.
    let cidr = format!("{gateway}/{prefix_len}");
    let _ = run("ip", &["addr", "add", &cidr, "dev", name]);
    run("ip", &["link", "set", name, "up"])
}

/// Create a persistent TAP named `name`, attach it to `bridge`, bring it up, and
/// return its owning fd. The IP for the guest behind this TAP is allocated by the
/// caller via [`crate::Ipam`] and applied inside the guest via the kernel `ip=`.
pub fn create_tap(name: &str, bridge: &str) -> Result<Tap, HostNetError> {
    let fd = open_tun(name)?;
    set_persist(&fd)?;
    run("ip", &["link", "set", name, "master", bridge])?;
    run("ip", &["link", "set", name, "up"])?;
    Ok(Tap {
        name: name.to_string(),
        fd,
    })
}

/// Install a MASQUERADE rule so traffic from `subnet_cidr` egresses via
/// `egress_iface`, and enable IPv4 forwarding. Idempotent.
pub fn enable_nat(subnet_cidr: &str, egress_iface: &str) -> Result<(), HostNetError> {
    // Only append the rule if an identical one is not already present (`-C`).
    if !iptables_rule_exists(subnet_cidr, egress_iface) {
        run("iptables", &masq_args("-A", subnet_cidr, egress_iface))?;
    }
    run("sysctl", &["-w", "net.ipv4.ip_forward=1"])?;
    Ok(())
}

/// Remove a TAP device by name (idempotent). The caller releases the guest IP
/// back to the [`crate::Ipam`] pool separately.
pub fn teardown_tap(name: &str) -> Result<(), HostNetError> {
    if link_exists(name) {
        run("ip", &["link", "del", name])?;
    }
    Ok(())
}

/// Build an `iptables` MASQUERADE argument vector for the given action (`-A`/`-C`).
fn masq_args<'a>(action: &'a str, subnet_cidr: &'a str, egress_iface: &'a str) -> Vec<&'a str> {
    vec![
        "-t",
        "nat",
        action,
        "POSTROUTING",
        "-s",
        subnet_cidr,
        "-o",
        egress_iface,
        "-j",
        "MASQUERADE",
    ]
}

fn iptables_rule_exists(subnet_cidr: &str, egress_iface: &str) -> bool {
    Command::new("iptables")
        .args(masq_args("-C", subnet_cidr, egress_iface))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn link_exists(name: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run a command, turning a non-zero exit into a descriptive error.
fn run(cmd: &str, args: &[&str]) -> Result<(), HostNetError> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|_| HostNetError::Spawn(cmd.to_string()))?;
    if !output.status.success() {
        return Err(HostNetError::Command {
            cmd: format!("{cmd} {}", args.join(" ")),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(())
}

/// Open `/dev/net/tun` and create TAP `name` with `IFF_TAP | IFF_NO_PI`.
fn open_tun(name: &str) -> Result<File, HostNetError> {
    let path = std::ffi::CString::new("/dev/net/tun").expect("static path has no NUL");
    // SAFETY: `path` is a valid NUL-terminated C string.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return Err(HostNetError::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: zeroing a C POD is a valid initial state.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let bytes = name.as_bytes();
    if bytes.len() >= ifr.ifr_name.len() {
        // SAFETY: closing the fd we just opened before bailing out.
        unsafe { libc::close(fd) };
        return Err(HostNetError::NameTooLong(name.to_string()));
    }
    for (slot, &b) in ifr.ifr_name.iter_mut().zip(bytes) {
        *slot = b as libc::c_char;
    }
    // Writing a union field (no read) is safe.
    ifr.ifr_ifru.ifru_flags = IFF_TAP | IFF_NO_PI;

    // SAFETY: `fd` is a valid /dev/net/tun fd; `ifr` is correctly sized for TUNSETIFF.
    if unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) } < 0 {
        let err = std::io::Error::last_os_error();
        // SAFETY: closing the fd we own.
        unsafe { libc::close(fd) };
        return Err(HostNetError::Io(err));
    }

    // SAFETY: `fd` is an open descriptor we transfer ownership of to `File`.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Make the TAP persist after the creating fd is closed so the VMM can reopen it.
fn set_persist(tap: &File) -> Result<(), HostNetError> {
    // SAFETY: `tap` is a valid TAP fd; TUNSETPERSIST takes an int (1 = persist).
    if unsafe { libc::ioctl(tap.as_raw_fd(), TUNSETPERSIST, 1 as libc::c_int) } < 0 {
        return Err(HostNetError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masq_args_build_a_full_masquerade_rule() {
        let add = masq_args("-A", "10.0.0.0/24", "eth0");
        assert_eq!(
            add,
            vec![
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                "10.0.0.0/24",
                "-o",
                "eth0",
                "-j",
                "MASQUERADE",
            ]
        );
        // The check form differs only in the action verb.
        assert_eq!(masq_args("-C", "10.0.0.0/24", "eth0")[2], "-C");
    }
}
