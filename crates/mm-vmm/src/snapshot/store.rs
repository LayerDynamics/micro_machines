//! On-disk snapshot store + retention (SPEC-1 FR-14).
//!
//! Owns the layout of saved snapshots under a host state directory:
//!
//! ```text
//! <state_root>/snapshots/<machine>/<snapshot-id>/
//!     manifest.json   # SnapshotManifest
//!     state.bin       # serialized vCPU + device + clock state
//!     memory.bin      # guest RAM
//! ```
//!
//! A `<snapshot-id>` is a zero-padded creation timestamp, so directory ids sort
//! chronologically — newest last lexicographically — which makes "keep the N newest"
//! retention a simple suffix of the sorted list.
//!
//! This module is the *lifecycle owner*: it allocates snapshot directories (which the
//! Linux-only engine then fills via [`super::engine::snapshot`]), enumerates a
//! machine's snapshots, locates one for restore, and garbage-collects old ones. It is
//! pure filesystem + manifest parsing, so it is cross-platform and unit-tested without
//! KVM.
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs, io};

use crate::snapshot::manifest::SnapshotManifest;

const MANIFEST_FILE: &str = "manifest.json";

/// A snapshot directory store rooted under a host state directory.
#[derive(Debug, Clone)]
pub struct SnapshotStore {
    root: PathBuf,
}

/// One stored snapshot: its id, directory, and parsed manifest.
#[derive(Debug, Clone)]
pub struct SnapshotRef {
    /// Sortable creation-timestamp id (the directory name).
    pub id: String,
    /// Absolute path to the snapshot directory.
    pub dir: PathBuf,
    /// The snapshot's manifest.
    pub manifest: SnapshotManifest,
}

impl SnapshotStore {
    /// A store rooted at `<state_root>/snapshots`.
    pub fn new(state_root: impl AsRef<Path>) -> Self {
        Self {
            root: state_root.as_ref().join("snapshots"),
        }
    }

    /// The directory holding `machine`'s snapshots. The machine name is sanitized to a
    /// single safe path component so a crafted name cannot escape the store root.
    fn machine_dir(&self, machine: &str) -> PathBuf {
        self.root.join(sanitize(machine))
    }

    /// The directory for a specific snapshot (whether or not it exists).
    pub fn dir(&self, machine: &str, id: &str) -> PathBuf {
        self.machine_dir(machine).join(sanitize(id))
    }

    /// Allocate a fresh, empty snapshot directory for `machine` and return its id and
    /// path. The caller (the engine) fills it with the manifest + state + memory. The
    /// id is unique even for snapshots taken in the same instant (it bumps until the
    /// directory does not already exist).
    pub fn new_snapshot_dir(&self, machine: &str) -> io::Result<(String, PathBuf)> {
        let machine_dir = self.machine_dir(machine);
        fs::create_dir_all(&machine_dir)?;
        let base = now_id();
        for bump in 0..1_000_000 {
            let id = format!("{:020}", base.saturating_add(bump));
            let dir = machine_dir.join(&id);
            match fs::create_dir(&dir) {
                Ok(()) => return Ok((id, dir)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique snapshot id",
        ))
    }

    /// List `machine`'s snapshots, newest first. Directories without a parseable
    /// `manifest.json` (e.g. a snapshot still being written) are skipped, so a partial
    /// snapshot never appears as restorable nor counts toward retention.
    pub fn list(&self, machine: &str) -> io::Result<Vec<SnapshotRef>> {
        let machine_dir = self.machine_dir(machine);
        let entries = match fs::read_dir(&machine_dir) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut snaps = Vec::new();
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let dir = entry.path();
            let Some(id) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(bytes) = fs::read(dir.join(MANIFEST_FILE)) else {
                continue; // no manifest yet (partial) — not a complete snapshot
            };
            let Ok(manifest) = serde_json::from_slice::<SnapshotManifest>(&bytes) else {
                continue; // unparseable manifest — skip rather than surface as valid
            };
            snaps.push(SnapshotRef { id, dir, manifest });
        }
        // Ids are zero-padded timestamps, so a plain reverse sort is newest-first.
        snaps.sort_by(|a, b| b.id.cmp(&a.id));
        Ok(snaps)
    }

    /// Locate a complete snapshot by id (its directory must hold a valid manifest).
    pub fn find(&self, machine: &str, id: &str) -> io::Result<Option<SnapshotRef>> {
        Ok(self.list(machine)?.into_iter().find(|s| s.id == id))
    }

    /// Retention: keep the `keep` newest complete snapshots of `machine` and remove the
    /// rest, returning the ids removed (oldest first). `keep == 0` removes all complete
    /// snapshots. Partial/unparseable directories are left untouched.
    pub fn gc(&self, machine: &str, keep: usize) -> io::Result<Vec<String>> {
        let snaps = self.list(machine)?; // newest first
        let mut removed = Vec::new();
        for snap in snaps.into_iter().skip(keep) {
            fs::remove_dir_all(&snap.dir)?;
            removed.push(snap.id);
        }
        removed.reverse(); // report oldest-first
        Ok(removed)
    }

    /// Remove a single snapshot by id. Idempotent: a missing snapshot is a no-op.
    pub fn remove(&self, machine: &str, id: &str) -> io::Result<()> {
        match fs::remove_dir_all(self.dir(machine, id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// Current time as nanoseconds since the epoch, the basis for a sortable snapshot id.
/// Falls back to 0 if the clock is before the epoch (it never is in practice).
fn now_id() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Reduce an untrusted name to a single safe path component: keep ASCII alphanumerics,
/// `-`, `_`, and `.`, replace everything else with `_`. Prevents `..`/separators from
/// escaping the store root. An empty result becomes `_`.
fn sanitize(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    // A lone "." or ".." would be path-traversal even after the char filter.
    if out.is_empty() || out == "." || out == ".." {
        out = "_".to_string();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::manifest::{HostFingerprint, SnapshotKind};

    fn write_manifest(dir: &Path) {
        let m = SnapshotManifest {
            version: 1,
            vcpu_count: 1,
            memory_mib: 128,
            memory_file: "memory.bin".into(),
            state_file: "state.bin".into(),
            kind: SnapshotKind::Full,
            parent_uid: None,
            host: HostFingerprint::default(),
        };
        fs::write(dir.join(MANIFEST_FILE), serde_json::to_vec(&m).unwrap()).unwrap();
    }

    fn temp_root() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "mm-snapstore-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&p);
        p
    }

    /// Allocate `n` complete snapshots for `machine`, returning their ids oldest-first.
    fn seed(store: &SnapshotStore, machine: &str, n: usize) -> Vec<String> {
        let mut ids = Vec::new();
        for _ in 0..n {
            let (id, dir) = store.new_snapshot_dir(machine).unwrap();
            write_manifest(&dir);
            ids.push(id);
        }
        ids
    }

    #[test]
    fn new_snapshot_dir_is_unique_and_under_machine() {
        let root = temp_root();
        let store = SnapshotStore::new(&root);
        let (id1, d1) = store.new_snapshot_dir("web").unwrap();
        let (id2, d2) = store.new_snapshot_dir("web").unwrap();
        assert_ne!(id1, id2, "ids are unique even back-to-back");
        assert!(d1.starts_with(root.join("snapshots").join("web")));
        assert!(d2.exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn list_is_newest_first_and_skips_partial_dirs() {
        let root = temp_root();
        let store = SnapshotStore::new(&root);
        let ids = seed(&store, "web", 3);
        // A directory with no manifest (a snapshot mid-write) must not appear.
        let (_partial, _) = store.new_snapshot_dir("web").unwrap();

        let listed = store.list("web").unwrap();
        assert_eq!(listed.len(), 3, "partial dir is skipped");
        let listed_ids: Vec<&str> = listed.iter().map(|s| s.id.as_str()).collect();
        let mut newest_first = ids.clone();
        newest_first.reverse();
        assert_eq!(listed_ids, newest_first, "newest first");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn gc_keeps_the_newest_and_removes_the_rest() {
        let root = temp_root();
        let store = SnapshotStore::new(&root);
        let ids = seed(&store, "web", 5); // oldest-first

        let removed = store.gc("web", 2).unwrap();
        // The 3 oldest are removed, reported oldest-first.
        assert_eq!(removed, ids[..3].to_vec());
        let kept: Vec<String> = store
            .list("web")
            .unwrap()
            .into_iter()
            .map(|s| s.id)
            .collect();
        let mut want = ids[3..].to_vec();
        want.reverse(); // newest first
        assert_eq!(kept, want, "only the 2 newest survive");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn gc_keep_zero_removes_all_and_find_remove_work() {
        let root = temp_root();
        let store = SnapshotStore::new(&root);
        let ids = seed(&store, "web", 3);

        assert!(store.find("web", &ids[1]).unwrap().is_some());
        store.remove("web", &ids[1]).unwrap();
        assert!(store.find("web", &ids[1]).unwrap().is_none());
        store.remove("web", &ids[1]).unwrap(); // idempotent

        let removed = store.gc("web", 0).unwrap();
        assert_eq!(removed.len(), 2, "gc(0) removes all remaining");
        assert!(store.list("web").unwrap().is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn list_of_unknown_machine_is_empty_and_names_are_sanitized() {
        let root = temp_root();
        let store = SnapshotStore::new(&root);
        assert!(store.list("never-snapshotted").unwrap().is_empty());
        // A traversal-y name is reduced to safe components under the store root: the
        // path stays rooted and contains no `..` component that could escape.
        let dir = store.dir("../../etc", "..");
        assert!(dir.starts_with(root.join("snapshots")));
        assert!(!dir
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir)));
        let _ = fs::remove_dir_all(&root);
    }
}
