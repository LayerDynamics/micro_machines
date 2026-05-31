//! Parse `mm.*` parameters from /proc/cmdline (SPEC-1 FR-5).

/// Config the guest init derives from the kernel command line.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct InitConfig {
    pub workload: Option<String>,
    pub args: Vec<String>,
    pub mode: Mode,
    pub vsock_boot_port: Option<u32>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Workload,
    Sandbox,
}

impl InitConfig {
    /// Parse a raw /proc/cmdline string. Recognizes `mm.workload=`, `mm.args=`,
    /// `mm.mode=`, `mm.vsock_boot_port=`. Unknown tokens are ignored.
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
                Some(("mm.mode", "sandbox")) => cfg.mode = Mode::Sandbox,
                Some(("mm.vsock_boot_port", v)) => cfg.vsock_boot_port = v.parse().ok(),
                _ => {}
            }
        }
        cfg
    }
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
    fn detects_sandbox_mode_and_vsock_port() {
        let c = InitConfig::parse("mm.mode=sandbox mm.vsock_boot_port=13");
        assert_eq!(c.mode, Mode::Sandbox);
        assert_eq!(c.vsock_boot_port, Some(13));
    }
}
