//! Parse `mm.*` parameters from /proc/cmdline (SPEC-1 FR-5).

/// Config the guest init derives from the kernel command line.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct InitConfig {
    pub workload: Option<String>,
    pub args: Vec<String>,
    pub mode: Mode,
    pub vsock_boot_port: Option<u32>,
    /// SSH authorized-keys content to install at `/root/.ssh/authorized_keys`.
    /// Passed hex-encoded on the cmdline (`mm.authorized_key=`) because the kernel
    /// command line is whitespace-separated and SSH keys contain spaces.
    pub authorized_key: Option<String>,
    /// Real entropy from the host (hex-encoded on the cmdline as `mm.random_seed=`)
    /// used to seed the guest CRNG via `RNDADDENTROPY`. A fresh microVM has no
    /// entropy source — and this fixture kernel has no virtio-rng driver — so
    /// `getrandom(2)` blocks until the CRNG is initialized, which stalls anything
    /// that needs randomness at boot (notably dropbear generating its host key:
    /// "Connection timed out during banner exchange"). Crediting host entropy here
    /// unblocks it. The seed is generated per-VM by `mm run`.
    pub random_seed: Option<Vec<u8>>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Workload,
    Sandbox,
}

impl InitConfig {
    /// Parse a raw /proc/cmdline string. Recognizes `mm.workload=`, `mm.args=`,
    /// `mm.workload_argv=`, `mm.mode=`, `mm.vsock_boot_port=`, `mm.authorized_key=`.
    /// Unknown tokens are ignored.
    ///
    /// `mm.workload_argv=<hex>` is the robust form `mm run` uses for OCI images: the
    /// hex decodes to the full argv joined by NUL bytes, so arguments may contain
    /// spaces or commas (which `mm.workload`/`mm.args` cannot carry on the
    /// whitespace-split, comma-split command line). It sets `workload` (argv[0]) and
    /// `args` (the rest).
    pub fn parse(cmdline: &str) -> Self {
        let mut cfg = InitConfig::default();
        for tok in cmdline.split_whitespace() {
            match tok.split_once('=') {
                Some(("mm.workload", v)) => cfg.workload = Some(v.to_string()),
                Some(("mm.args", v)) => {
                    cfg.args = v
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect()
                }
                Some(("mm.workload_argv", v)) => {
                    if let Some(argv) = decode_hex(v).map(|bytes| {
                        bytes
                            .split(|b| *b == 0)
                            .filter(|s| !s.is_empty())
                            .filter_map(|s| std::str::from_utf8(s).ok().map(String::from))
                            .collect::<Vec<String>>()
                    }) {
                        if let Some((first, rest)) = argv.split_first() {
                            cfg.workload = Some(first.clone());
                            cfg.args = rest.to_vec();
                        }
                    }
                }
                Some(("mm.mode", "sandbox")) => cfg.mode = Mode::Sandbox,
                Some(("mm.vsock_boot_port", v)) => cfg.vsock_boot_port = v.parse().ok(),
                Some(("mm.authorized_key", v)) => {
                    cfg.authorized_key =
                        decode_hex(v).and_then(|bytes| String::from_utf8(bytes).ok());
                }
                Some(("mm.random_seed", v)) => {
                    cfg.random_seed = decode_hex(v).filter(|b| !b.is_empty());
                }
                _ => {}
            }
        }
        cfg
    }
}

/// Decode a lowercase/uppercase hex string to bytes, returning `None` on any
/// non-hex character or odd length.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = nibble(pair[0])?;
        let lo = nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_workload_and_args() {
        let c = InitConfig::parse(
            "console=ttyS0 mm.workload=/app mm.args=--port,8080 ip=10.0.0.2::...",
        );
        assert_eq!(c.workload.as_deref(), Some("/app"));
        assert_eq!(c.args, vec!["--port", "8080"]);
        assert_eq!(c.mode, Mode::Workload);
    }
    #[test]
    fn parses_workload_argv_hex_with_spaces() {
        // argv whose args contain spaces — impossible via mm.workload/mm.args.
        let argv = ["/bin/sh", "-c", "echo a b"];
        let hex: String = argv
            .join("\0")
            .bytes()
            .map(|b| format!("{b:02x}"))
            .collect();
        let c = InitConfig::parse(&format!("console=ttyS0 mm.workload_argv={hex} ip=10.0.0.2"));
        assert_eq!(c.workload.as_deref(), Some("/bin/sh"));
        assert_eq!(c.args, vec!["-c", "echo a b"]);
    }

    #[test]
    fn detects_sandbox_mode_and_vsock_port() {
        let c = InitConfig::parse("mm.mode=sandbox mm.vsock_boot_port=13");
        assert_eq!(c.mode, Mode::Sandbox);
        assert_eq!(c.vsock_boot_port, Some(13));
    }
    #[test]
    fn decodes_hex_encoded_authorized_key() {
        // hex("ssh-ed25519 AAAA") = 7373682d656432353531392041414141
        let c = InitConfig::parse("mm.authorized_key=7373682d656432353531392041414141");
        assert_eq!(c.authorized_key.as_deref(), Some("ssh-ed25519 AAAA"));
    }
    #[test]
    fn rejects_malformed_authorized_key_hex() {
        assert_eq!(
            InitConfig::parse("mm.authorized_key=xyz").authorized_key,
            None
        );
        assert_eq!(
            InitConfig::parse("mm.authorized_key=abc").authorized_key,
            None
        );
    }
    #[test]
    fn decodes_hex_encoded_random_seed() {
        let c = InitConfig::parse("mm.random_seed=00ff10ab");
        assert_eq!(c.random_seed, Some(vec![0x00, 0xff, 0x10, 0xab]));
        // Malformed or empty hex yields no seed (init simply skips CRNG crediting).
        assert_eq!(InitConfig::parse("mm.random_seed=xyz").random_seed, None);
        assert_eq!(InitConfig::parse("mm.random_seed=").random_seed, None);
    }
    #[test]
    fn decode_hex_roundtrips() {
        assert_eq!(decode_hex("00ff10"), Some(vec![0x00, 0xff, 0x10]));
        assert_eq!(decode_hex("0g"), None);
        assert_eq!(decode_hex("abc"), None);
    }
}
