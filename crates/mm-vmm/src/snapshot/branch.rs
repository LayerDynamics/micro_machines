//! FR-16 running-BRANCH write-protect engine (Linux + `branch` feature).
//!
//! Materializes a complete point-in-time (T) copy of a **running** parent's guest RAM
//! into a branch file, without freezing the parent for a full RAM dump. The parent is
//! paused only briefly (by [`Machine::branch`](crate::Machine::branch), to capture vCPU
//! /device/clock state and arm this engine); then it resumes and this engine fills the
//! branch file concurrently:
//!
//! - the parent's RAM is registered with `userfaultfd` in **write-protect** mode, so a
//!   write to any page the parent has not yet had preserved faults out to the handler;
//! - a **fault handler** thread (the sole owner of the uffd) services those faults: it
//!   copies the faulting page's T-version into the branch file, then removes the page's
//!   write-protection so the parent's write proceeds;
//! - a background **copier** walks every page and copies the ones the parent has not
//!   touched, so untouched pages also reach the branch file.
//!
//! Each page is claimed exactly once (the copier and handler race via
//! [`PreserveMap`](crate::branch_core)); only the claimer copies it, and the handler is
//! the only thread that talks to the uffd. When every page's T-version is in the file,
//! the branch file is a coherent T-snapshot — identical in layout to a frozen snapshot's
//! `memory.bin`, so children fork from it with the proven `MAP_PRIVATE` path.
//!
//! Scope note (Phase 1): this materializes a *complete* RAM copy concurrently with the
//! running parent — it buys the "no freeze for the dump" win, not lazy memory sharing.
//! The fully-lazy post-copy variant (untouched pages never copied) is a later phase.
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use userfaultfd::{Event, FaultKind, FeatureFlags, RegisterMode, Uffd, UffdBuilder};

use crate::branch_core::{PreserveMap, RegionMap, PAGE_SIZE};
use crate::machine::{Result, VmmError};

/// How long to wait for the branch file to be fully materialized before giving up (a
/// stuck handler/copier should fail the branch, not hang the parent forever).
const COMPLETE_TIMEOUT: Duration = Duration::from_secs(120);

/// The write-protect branch engine. Built (and the uffd armed) while the parent is
/// paused; then the handler is spawned, the parent resumed, and the copier run.
pub(crate) struct BranchEngine {
    region_map: Arc<RegionMap>,
    preserve: Arc<PreserveMap>,
    file: Arc<File>,
    /// The uffd, taken by [`spawn_handler`](Self::spawn_handler) — the handler owns it.
    uffd: Option<Uffd>,
}

impl BranchEngine {
    /// Create the uffd, register every guest RAM region in write-protect mode and arm
    /// protection, and create the branch file sized to hold all pages. Call while the
    /// parent is paused at the checkpoint barrier (no writers), so arming is atomic
    /// w.r.t. the guest. `regions` are `(host_base, len_bytes)` in ascending order.
    pub(crate) fn arm(regions: &[(usize, usize)], branch_path: &Path) -> Result<Self> {
        let total_pages: usize = regions.iter().map(|(_, len)| len / PAGE_SIZE).sum();
        let region_map = Arc::new(RegionMap::new(regions));
        let preserve = Arc::new(PreserveMap::new(total_pages));

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(branch_path)
            .map_err(VmmError::Io)?;
        file.set_len((total_pages * PAGE_SIZE) as u64)
            .map_err(VmmError::Io)?;
        let file = Arc::new(file);

        // A full (non-user-mode-only) uffd: a KVM guest's write faults out via EPT in
        // kernel context, so a USER_MODE_ONLY uffd would never see it (proven in Phase 0).
        let uffd = UffdBuilder::new()
            .require_features(FeatureFlags::PAGEFAULT_FLAG_WP)
            .user_mode_only(false)
            .non_blocking(true)
            .create()
            .map_err(|e| VmmError::Device(format!("branch: create uffd: {e}")))?;
        for &(base, len) in regions {
            uffd.register_with_mode(base as *mut c_void, len, RegisterMode::WRITE_PROTECT)
                .map_err(|e| VmmError::Device(format!("branch: register region: {e}")))?;
            uffd.write_protect(base as *mut c_void, len)
                .map_err(|e| VmmError::Device(format!("branch: arm write-protection: {e}")))?;
        }

        Ok(Self {
            region_map,
            preserve,
            file,
            uffd: Some(uffd),
        })
    }

    /// Spawn the fault-handler thread (sole owner of the uffd). It must be running
    /// before the parent resumes, so the parent's first write fault is serviced. Returns
    /// the handle; the thread returns the number of write-protect faults it handled.
    pub(crate) fn spawn_handler(&mut self) -> Result<JoinHandle<Result<u64>>> {
        let uffd = self
            .uffd
            .take()
            .ok_or_else(|| VmmError::Device("branch: handler already started".into()))?;
        let region_map = self.region_map.clone();
        let preserve = self.preserve.clone();
        let file = self.file.clone();
        std::thread::Builder::new()
            .name("mm-branch-wp".into())
            .spawn(move || handler_loop(uffd, region_map, preserve, file))
            .map_err(VmmError::Io)
    }

    /// Copy every page the parent has not already faulted (and the handler has not
    /// claimed) into the branch file. Runs on the caller's thread after the parent has
    /// resumed. Returns the number of pages this copier wrote.
    pub(crate) fn run_copier(&self) -> Result<u64> {
        let total = self.preserve.total_pages();
        let mut copied = 0u64;
        for page in 0..total {
            if self.preserve.try_claim(page) {
                let addr = self
                    .region_map
                    .addr_of_page(page)
                    .ok_or_else(|| VmmError::Device(format!("branch: page {page} out of range")))?;
                copy_page(&self.region_map, &self.file, &self.preserve, addr, page)?;
                copied += 1;
            }
        }
        Ok(copied)
    }

    /// Block until every page's T-version is in the branch file, or time out.
    pub(crate) fn await_complete(&self) -> Result<()> {
        let deadline = Instant::now() + COMPLETE_TIMEOUT;
        while !self.preserve.is_complete() {
            if Instant::now() >= deadline {
                return Err(VmmError::Device(format!(
                    "branch: only {}/{} pages materialized within the timeout",
                    self.preserve.copied_count(),
                    self.preserve.total_pages()
                )));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    }
}

/// Copy one page's T-version from the live guest RAM into the branch file, then record
/// it. The page is write-protected while this runs (the guest cannot mutate it), so the
/// read sees a stable T-version.
fn copy_page(
    region_map: &RegionMap,
    file: &File,
    preserve: &PreserveMap,
    host_addr: usize,
    page: usize,
) -> Result<()> {
    // SAFETY: `host_addr` is the base of a mapped, page-sized guest RAM page (from the
    // region map built off the live guest mmap), valid for PAGE_SIZE bytes for reads.
    let src = unsafe { std::slice::from_raw_parts(host_addr as *const u8, PAGE_SIZE) };
    file.write_all_at(src, region_map.file_offset_of_page(page))
        .map_err(VmmError::Io)?;
    preserve.mark_copied(page);
    Ok(())
}

/// The fault-handler loop: own the uffd, service write-protect faults until the branch
/// file is complete, then drain once more so any just-faulted writer proceeds promptly.
/// Returns the number of faults handled.
fn handler_loop(
    uffd: Uffd,
    region_map: Arc<RegionMap>,
    preserve: Arc<PreserveMap>,
    file: Arc<File>,
) -> Result<u64> {
    let mut faulted = 0u64;
    while !preserve.is_complete() {
        // Wait (bounded) for a fault to be ready, then drain all of them. The timeout
        // bounds how often we re-check completion.
        let mut pfd = libc::pollfd {
            fd: uffd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid, initialized pollfd for the duration of the call.
        let _ = unsafe { libc::poll(&mut pfd, 1, 10) };
        faulted += drain_faults(&uffd, &region_map, &preserve, &file)?;
    }
    // Final drain: a writer may have faulted on an already-copied page right as we
    // completed; service it so it proceeds without waiting for the uffd to be dropped.
    faulted += drain_faults(&uffd, &region_map, &preserve, &file)?;
    Ok(faulted)
}

/// Service every write-protect fault currently ready on the uffd. For each faulting
/// page: if we claim it, copy its T-version; otherwise the copier claimed it, so wait
/// until the copier has written it. Either way the T-version is in the branch file
/// before we remove write-protection (waking the blocked writer). Returns the count.
fn drain_faults(
    uffd: &Uffd,
    region_map: &RegionMap,
    preserve: &PreserveMap,
    file: &File,
) -> Result<u64> {
    let mut handled = 0u64;
    loop {
        match uffd.read_event() {
            Ok(Some(Event::Pagefault {
                kind: FaultKind::WriteProtected,
                addr,
                ..
            })) => {
                handled += 1;
                let page_base = (addr as usize) & !(PAGE_SIZE - 1);
                let page = match region_map.page_of_addr(page_base) {
                    Some(p) => p,
                    None => continue, // outside guest RAM — should not happen
                };
                if preserve.try_claim(page) {
                    copy_page(region_map, file, preserve, page_base, page)?;
                } else {
                    // The copier claimed it; wait until its T-version is in the file so
                    // the writer cannot race ahead of the copier's read.
                    while !preserve.is_page_copied(page) {
                        std::hint::spin_loop();
                    }
                }
                uffd.remove_write_protection(page_base as *mut c_void, PAGE_SIZE, true)
                    .map_err(|e| VmmError::Device(format!("branch: remove WP: {e}")))?;
            }
            // Non-blocking uffd: Ok(None) means no more events are ready right now.
            Ok(None) => break,
            // Other event kinds (e.g. unregister) — ignore.
            Ok(Some(_)) => continue,
            Err(_) => break,
        }
    }
    Ok(handled)
}
