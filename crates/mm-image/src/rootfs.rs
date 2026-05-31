//! OCI image → rootfs: a digest-cached read-only base plus a per-instance writable
//! overlay (SPEC-1 FR-6).
//!
//! MicroMachines turns an OCI image into a bootable disk in two layers:
//!
//! * a **read-only base** ext4 image, content-addressed by the image's manifest
//!   digest so identical images are built once and shared;
//! * a **per-instance overlay** (a writable upperdir + workdir, plus a merged
//!   mountpoint) so each microVM gets an ephemeral, isolated writable layer over
//!   the shared base — the guest mounts `overlay(lower=base, upper=ephemeral)`.
//!
//! Building the base shells out to standard rootless tooling (`skopeo` to fetch
//! the image into an OCI layout, `umoci` to unpack it into a rootfs honoring
//! whiteouts, and `mke2fs -d` to populate an ext4 image from that rootfs). The
//! path/layout logic — which is what determines caching correctness — is pure and
//! unit-tested on any host.
use std::path::{Path, PathBuf};
use std::process::Command;

/// Errors from building or laying out rootfs images.
#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    #[error("invalid OCI digest {0:?} (expected `<algo>:<hex>`)")]
    InvalidDigest(String),
    #[error("i/o error at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to spawn `{0}` (is it installed and on PATH?)")]
    Spawn(String),
    #[error("command `{cmd}` failed: {stderr}")]
    Command { cmd: String, stderr: String },
}

/// A parsed OCI content digest, e.g. `sha256:abc123…`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digest {
    pub algorithm: String,
    pub hex: String,
}

impl Digest {
    /// Parse an `<algorithm>:<hex>` digest string, validating both halves.
    pub fn parse(s: &str) -> Result<Digest, ImageError> {
        let (algorithm, hex) = s
            .split_once(':')
            .ok_or_else(|| ImageError::InvalidDigest(s.to_string()))?;
        let valid = !algorithm.is_empty()
            && !hex.is_empty()
            && algorithm.chars().all(|c| c.is_ascii_alphanumeric())
            && hex.chars().all(|c| c.is_ascii_hexdigit());
        if !valid {
            return Err(ImageError::InvalidDigest(s.to_string()));
        }
        Ok(Digest {
            algorithm: algorithm.to_string(),
            hex: hex.to_string(),
        })
    }
}

/// The writable layer paths for one microVM instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayPaths {
    /// overlayfs upperdir (the guest's writable layer).
    pub upper: PathBuf,
    /// overlayfs workdir (overlayfs scratch; must be on the same fs as `upper`).
    pub work: PathBuf,
    /// Where the merged view is mounted.
    pub merged: PathBuf,
}

/// Content-addressed store for read-only base images plus per-instance overlays,
/// all rooted under a single cache directory.
#[derive(Debug, Clone)]
pub struct ImageStore {
    root: PathBuf,
}

impl ImageStore {
    /// Create a store rooted at `root` (e.g. `/var/lib/micro_machines`).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Deterministic cache path of the read-only base ext4 image for `digest`:
    /// `<root>/images/<algo>/<hex>.ext4`.
    pub fn base_image_path(&self, digest: &Digest) -> PathBuf {
        self.root
            .join("images")
            .join(&digest.algorithm)
            .join(format!("{}.ext4", digest.hex))
    }

    /// Per-instance overlay paths under `<root>/instances/<instance_id>/`.
    pub fn overlay_paths(&self, instance_id: &str) -> OverlayPaths {
        let base = self.root.join("instances").join(instance_id);
        OverlayPaths {
            upper: base.join("upper"),
            work: base.join("work"),
            merged: base.join("merged"),
        }
    }

    /// Whether the base image for `digest` is already built and cached.
    pub fn is_base_cached(&self, digest: &Digest) -> bool {
        self.base_image_path(digest).exists()
    }

    /// Build (or reuse the cached) read-only base ext4 image for `image_ref`.
    /// Returns the path to the ext4 image.
    ///
    /// Pipeline (all rootless): resolve the manifest digest with `skopeo inspect`,
    /// short-circuit if already cached, otherwise `skopeo copy` into an OCI layout,
    /// `umoci unpack` to a rootfs bundle, and `mke2fs -d` to populate an ext4 image.
    pub fn build_base_rootfs(&self, image_ref: &str) -> Result<PathBuf, ImageError> {
        let digest = self.resolve_digest(image_ref)?;
        let target = self.base_image_path(&digest);
        if target.exists() {
            tracing::debug!("base rootfs for {image_ref} already cached at {target:?}");
            return Ok(target);
        }
        create_dir_all(target.parent().expect("base image path has a parent"))?;

        let scratch = self.root.join("build").join(&digest.hex);
        let oci_dir = scratch.join("oci");
        let bundle = scratch.join("bundle");
        // Clean any partial previous attempt.
        let _ = std::fs::remove_dir_all(&scratch);
        create_dir_all(&scratch)?;

        run(
            "skopeo",
            &[
                "copy",
                &format!("docker://{image_ref}"),
                &format!("oci:{}:latest", oci_dir.display()),
            ],
        )?;
        run(
            "umoci",
            &[
                "unpack",
                "--rootless",
                "--image",
                &format!("{}:latest", oci_dir.display()),
                &bundle.display().to_string(),
            ],
        )?;

        let rootfs = bundle.join("rootfs");
        let size_bytes = ext4_image_size(&rootfs)?;
        // Build into a temp path, then rename for an atomic cache publish.
        let tmp_image = scratch.join("rootfs.ext4");
        run(
            "mke2fs",
            &[
                "-t",
                "ext4",
                "-F",
                "-d",
                &rootfs.display().to_string(),
                &tmp_image.display().to_string(),
                &format!("{}", size_bytes / 1024), // size in 1K blocks
            ],
        )?;
        rename(&tmp_image, &target)?;
        // The base image is shared read-only and, under the jailer, opened by an
        // unprivileged uid — make it world-readable so the dropped uid can read it.
        set_world_readable(&target)?;
        let _ = std::fs::remove_dir_all(&scratch);
        Ok(target)
    }

    /// Create the per-instance overlay directories and return their paths.
    pub fn instance_overlay(&self, instance_id: &str) -> Result<OverlayPaths, ImageError> {
        let paths = self.overlay_paths(instance_id);
        create_dir_all(&paths.upper)?;
        create_dir_all(&paths.work)?;
        create_dir_all(&paths.merged)?;
        Ok(paths)
    }

    /// Remove an instance's overlay directories (best-effort cleanup on `rm`).
    pub fn remove_instance_overlay(&self, instance_id: &str) -> Result<(), ImageError> {
        let base = self.root.join("instances").join(instance_id);
        if base.exists() {
            std::fs::remove_dir_all(&base).map_err(|source| ImageError::Io {
                path: base.clone(),
                source,
            })?;
        }
        Ok(())
    }

    /// Resolve an image reference to its manifest digest via `skopeo inspect`.
    fn resolve_digest(&self, image_ref: &str) -> Result<Digest, ImageError> {
        let output = Command::new("skopeo")
            .args([
                "inspect",
                "--format",
                "{{.Digest}}",
                &format!("docker://{image_ref}"),
            ])
            .output()
            .map_err(|_| ImageError::Spawn("skopeo".to_string()))?;
        if !output.status.success() {
            return Err(ImageError::Command {
                cmd: format!("skopeo inspect docker://{image_ref}"),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        }
        let digest = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Digest::parse(&digest)
    }
}

/// Compute the ext4 image size for a rootfs: its apparent size plus generous
/// slack (filesystem metadata + a little headroom), rounded up to a 1 MiB block,
/// with a sane minimum.
fn ext4_image_size(rootfs: &Path) -> Result<u64, ImageError> {
    let used = dir_size(rootfs)?;
    // 40% slack for ext4 metadata/inodes + 64 MiB floor for tiny images.
    let with_slack = used + used / 2 + 16 * 1024 * 1024;
    let min = 64 * 1024 * 1024;
    let size = with_slack.max(min);
    // Round up to 1 MiB.
    Ok(size.div_ceil(1024 * 1024) * 1024 * 1024)
}

/// Recursively sum the apparent file sizes under `path`.
fn dir_size(path: &Path) -> Result<u64, ImageError> {
    let mut total = 0u64;
    let entries = std::fs::read_dir(path).map_err(|source| ImageError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| ImageError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let meta = entry.metadata().map_err(|source| ImageError::Io {
            path: entry.path(),
            source,
        })?;
        if meta.is_dir() {
            total += dir_size(&entry.path())?;
        } else {
            total += meta.len();
        }
    }
    Ok(total)
}

fn create_dir_all(path: &Path) -> Result<(), ImageError> {
    std::fs::create_dir_all(path).map_err(|source| ImageError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn rename(from: &Path, to: &Path) -> Result<(), ImageError> {
    std::fs::rename(from, to).map_err(|source| ImageError::Io {
        path: to.to_path_buf(),
        source,
    })
}

/// Make a file readable by owner/group/other (0644) so an unprivileged jailed VMM
/// can open the shared, read-only base image.
fn set_world_readable(path: &Path) -> Result<(), ImageError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).map_err(|source| {
        ImageError::Io {
            path: path.to_path_buf(),
            source,
        }
    })
}

/// Run a command, turning a non-zero exit into a descriptive error.
fn run(cmd: &str, args: &[&str]) -> Result<(), ImageError> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|_| ImageError::Spawn(cmd.to_string()))?;
    if !output.status.success() {
        return Err(ImageError::Command {
            cmd: format!("{cmd} {}", args.join(" ")),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_parses_algorithm_and_hex() {
        let d = Digest::parse("sha256:0a1b2c3d").unwrap();
        assert_eq!(d.algorithm, "sha256");
        assert_eq!(d.hex, "0a1b2c3d");
    }

    #[test]
    fn digest_rejects_malformed() {
        assert!(Digest::parse("sha256").is_err(), "no colon");
        assert!(Digest::parse("sha256:").is_err(), "empty hex");
        assert!(Digest::parse(":abc").is_err(), "empty algo");
        assert!(Digest::parse("sha256:xyz").is_err(), "non-hex");
    }

    #[test]
    fn base_image_path_is_content_addressed() {
        let store = ImageStore::new("/var/lib/mm");
        let digest = Digest::parse("sha256:deadbeef").unwrap();
        assert_eq!(
            store.base_image_path(&digest),
            PathBuf::from("/var/lib/mm/images/sha256/deadbeef.ext4")
        );
    }

    #[test]
    fn overlay_paths_are_per_instance_and_sibling_dirs() {
        let store = ImageStore::new("/var/lib/mm");
        let o = store.overlay_paths("web-1");
        assert_eq!(o.upper, PathBuf::from("/var/lib/mm/instances/web-1/upper"));
        assert_eq!(o.work, PathBuf::from("/var/lib/mm/instances/web-1/work"));
        assert_eq!(
            o.merged,
            PathBuf::from("/var/lib/mm/instances/web-1/merged")
        );
        // upper and work must share a parent (overlayfs requirement).
        assert_eq!(o.upper.parent(), o.work.parent());
    }

    #[test]
    fn ext4_size_has_a_floor_and_mib_alignment() {
        // dir_size of an empty temp dir is 0 -> floor applies, 1 MiB aligned.
        let tmp = std::env::temp_dir().join("mm-image-empty-sizing");
        let _ = std::fs::create_dir_all(&tmp);
        let size = ext4_image_size(&tmp).unwrap();
        assert!(size >= 64 * 1024 * 1024, "at least the 64 MiB floor");
        assert_eq!(size % (1024 * 1024), 0, "1 MiB aligned");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
