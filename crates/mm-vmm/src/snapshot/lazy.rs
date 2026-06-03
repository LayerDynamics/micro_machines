//! Lazy post-copy branching (SPEC-1 FR-16 Phase 2, `branch` feature).
//!
//! Phase 1 ([`crate::snapshot::branch`]) materializes a *complete* point-in-time (T) copy
//! of the running parent's RAM into a branch file — it buys "no freeze for the dump" but
//! still writes all of guest RAM. Lazy post-copy avoids that eager full copy: the parent
//! stays write-protected for the branch's lifetime, the branch file accumulates **only**
//! the pages the parent overwrites (their T-version, preserved on the write fault), and a
//! child's guest RAM is served **on demand** — each page faulted in from the branch file
//! if the parent has since diverged it, otherwise read straight from the parent's still-T
//! RAM. Untouched pages are never copied at all.
//!
//! Provenance invariant (per guest page `p`), maintained by ordering in the parent's WP
//! handler — copy `p`'s T-version to the file, **then** mark it present, **then** remove
//! write-protection:
//! - `p` not-yet-present ⇒ it is still write-protected in the parent ⇒ the parent's RAM
//!   at `p` still holds T ⇒ a child reads it from the parent. (A racing parent write is
//!   blocked by WP until the handler preserves T, so the parent's RAM cannot diverge while
//!   a child observes "not present".)
//! - `p` present ⇒ its T-version is in the file ⇒ a child reads it from the file.
//!
//! Lifecycle: the parent (and its WP handler) **must outlive** every lazy child — children
//! read the parent's live RAM for not-yet-diverged pages. [`LazyBranch::finish`] tears the
//! parent's write-protection down once all children are gone.
//!
//! The pure coordination ([`PreserveMap`], [`RegionMap`]) is shared with Phase 1 and
//! unit-tested in [`crate::branch_core`]; this module is the `userfaultfd` + KVM plumbing.
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use userfaultfd::{Event, FaultKind, Uffd, UffdBuilder};

use crate::branch_core::{PreserveMap, RegionMap, PAGE_SIZE};
use crate::machine::{Result, VmmError};

/// A live lazy branch: the parent is write-protected and its handler preserves overwritten
/// pages into `file` (a sparse image of only-diverged pages) for the branch's lifetime.
/// Children fork off it via [`spawn_child_handler`](Self::spawn_child_handler); the parent
/// must outlive them. [`finish`](Self::finish) disarms the parent's write-protection.
pub(crate) struct LazyBranch {
    region_map: Arc<RegionMap>,
    preserve: Arc<PreserveMap>,
    file: Arc<File>,
    /// The parent's guest RAM `(host_base, len)` regions — disarmed on teardown and read by
    /// child handlers for not-yet-diverged pages. Valid only while the parent Machine lives.
    regions: Vec<(usize, usize)>,
    /// Shared with the parent WP handler; set by [`finish`](Self::finish) to stop it.
    stop: Arc<AtomicBool>,
    wp_handler: Option<JoinHandle<Result<u64>>>,
    /// The parent's write-protect uffd, shared with the handler. Kept alive (and used to
    /// disarm) until teardown.
    uffd: Arc<Uffd>,
}

impl LazyBranch {
    /// Arm write-protection over the parent's `regions` using a pre-registered `uffd`
    /// (WRITE_PROTECT mode — created by [`crate::snapshot::branch::create_registered_uffd`]),
    /// create the sparse branch file, and spawn a persistent WP handler. The parent must be
    /// paused at the checkpoint barrier when this is called (no writers), so arming is
    /// atomic w.r.t. the guest; the caller resumes the parent afterward.
    pub(crate) fn arm(uffd: Uffd, regions: &[(usize, usize)], branch_path: &Path) -> Result<Self> {
        let region_map = Arc::new(RegionMap::new(regions));
        let total_pages = region_map.total_pages();
        let preserve = Arc::new(PreserveMap::new(total_pages));

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(branch_path)
            .map_err(VmmError::Io)?;
        // Size it to the full image so a present page's offset == page * PAGE_SIZE (the
        // RegionMap layout); absent pages stay sparse holes on disk.
        file.set_len((total_pages * PAGE_SIZE) as u64)
            .map_err(VmmError::Io)?;
        let file = Arc::new(file);

        for &(base, len) in regions {
            uffd.write_protect(base as *mut c_void, len)
                .map_err(|e| VmmError::Device(format!("lazy branch: arm WP: {e}")))?;
        }
        let uffd = Arc::new(uffd);

        let stop = Arc::new(AtomicBool::new(false));
        let wp_handler = {
            let (uffd, region_map, preserve, file, stop) = (
                uffd.clone(),
                region_map.clone(),
                preserve.clone(),
                file.clone(),
                stop.clone(),
            );
            std::thread::Builder::new()
                .name("mm-lazy-wp".into())
                .spawn(move || wp_handler_loop(uffd, region_map, preserve, file, stop))
                .map_err(VmmError::Io)?
        };

        Ok(Self {
            region_map,
            preserve,
            file,
            regions: regions.to_vec(),
            stop,
            wp_handler: Some(wp_handler),
            uffd,
        })
    }

    /// Register a lazy child's already-allocated guest RAM `child_regions`
    /// (`(host_base, len)`, same sizes/order as the parent's) with a MISSING-mode
    /// `userfaultfd` and spawn the handler that fills each faulted page from the branch
    /// file (if the parent diverged it) or the parent's live RAM (otherwise). The caller
    /// builds the child's `GuestMemoryMmap` (anonymous) and passes its regions here BEFORE
    /// resuming the child's vCPUs. The handler runs until `child_stop` is set. The uffd is
    /// owned by the handler thread for the child's lifetime.
    pub(crate) fn spawn_child_handler(
        &self,
        child_regions: &[(usize, usize)],
        child_stop: Arc<AtomicBool>,
    ) -> Result<JoinHandle<Result<u64>>> {
        // A MISSING-mode uffd over the child's RAM: a guest (or host) access to an
        // unpopulated page faults out to our handler, which UFFDIO_COPYs the right bytes.
        // Full (non-user-mode-only) so the KVM guest's EPT faults are delivered.
        let uffd = UffdBuilder::new()
            .user_mode_only(false)
            .non_blocking(true)
            .create()
            .map_err(|e| VmmError::Device(format!("lazy child: create uffd: {e}")))?;
        for &(base, len) in child_regions {
            uffd.register(base as *mut c_void, len)
                .map_err(|e| VmmError::Device(format!("lazy child: register: {e}")))?;
        }

        // The handler maps child-region addresses → global page (a RegionMap over the
        // CHILD bases) so it can locate each faulted page's source (same page layout as
        // the parent, so the global index is shared).
        let child_map = Arc::new(RegionMap::new(child_regions));
        let (region_map, preserve, file) = (
            self.region_map.clone(),
            self.preserve.clone(),
            self.file.clone(),
        );
        std::thread::Builder::new()
            .name("mm-lazy-child".into())
            .spawn(move || {
                child_handler_loop(uffd, child_map, region_map, preserve, file, child_stop)
            })
            .map_err(VmmError::Io)
    }

    /// Number of parent pages diverged (preserved into the file) so far — diagnostic.
    pub(crate) fn preserved_count(&self) -> usize {
        self.preserve.copied_count()
    }

    /// Stop the parent's WP handler and disarm write-protection over every region, leaving
    /// the parent fully running again. Call only after all lazy children are gone (they
    /// read the parent's RAM). Idempotent-ish: safe to call once.
    pub(crate) fn finish(mut self) -> Result<u64> {
        self.stop.store(true, Ordering::Release);
        let faulted = match self.wp_handler.take() {
            Some(h) => h
                .join()
                .map_err(|_| VmmError::Device("lazy branch: WP handler panicked".into()))??,
            None => 0,
        };
        // Clear write-protection on every page (faulted pages were already cleared; this
        // covers the untouched majority), so the parent can write freely again.
        for &(base, len) in &self.regions {
            self.uffd
                .remove_write_protection(base as *mut c_void, len, true)
                .map_err(|e| VmmError::Device(format!("lazy branch: disarm WP: {e}")))?;
        }
        Ok(faulted)
    }
}

/// Copy `page`'s current parent RAM (its T-version, since it is still write-protected)
/// into the branch file, then mark it present. Mirrors Phase 1's `copy_page`.
fn preserve_page(
    region_map: &RegionMap,
    file: &File,
    preserve: &PreserveMap,
    host_addr: usize,
    page: usize,
) -> Result<()> {
    // SAFETY: `host_addr` is a mapped, write-protected (stable) guest page, PAGE_SIZE long.
    let src = unsafe { std::slice::from_raw_parts(host_addr as *const u8, PAGE_SIZE) };
    file.write_all_at(src, region_map.file_offset_of_page(page))
        .map_err(VmmError::Io)?;
    preserve.mark_copied(page);
    Ok(())
}

/// The parent's persistent write-protect handler: until `stop`, service write faults —
/// preserve the faulting page's T-version into the file (ordered copy → mark → unprotect,
/// upholding the provenance invariant) so the parent's write may then proceed. Returns the
/// number of faults handled.
fn wp_handler_loop(
    uffd: Arc<Uffd>,
    region_map: Arc<RegionMap>,
    preserve: Arc<PreserveMap>,
    file: Arc<File>,
    stop: Arc<AtomicBool>,
) -> Result<u64> {
    let mut faulted = 0u64;
    while !stop.load(Ordering::Acquire) {
        let mut pfd = libc::pollfd {
            fd: uffd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd for the call; 20ms bounds the stop re-check.
        let _ = unsafe { libc::poll(&mut pfd, 1, 20) };
        loop {
            match uffd.read_event() {
                Ok(Some(Event::Pagefault {
                    kind: FaultKind::WriteProtected,
                    addr,
                    ..
                })) => {
                    faulted += 1;
                    let page_base = (addr as usize) & !(PAGE_SIZE - 1);
                    let page = match region_map.page_of_addr(page_base) {
                        Some(p) => p,
                        None => continue,
                    };
                    // Claim → copy → mark (in preserve_page) → THEN unprotect: a child that
                    // sees "not present" is guaranteed the page is still WP'd here, so the
                    // parent RAM it reads is still T.
                    if preserve.try_claim(page) {
                        preserve_page(&region_map, &file, &preserve, page_base, page)?;
                    } else {
                        while !preserve.is_page_copied(page) {
                            std::hint::spin_loop();
                        }
                    }
                    uffd.remove_write_protection(page_base as *mut c_void, PAGE_SIZE, true)
                        .map_err(|e| VmmError::Device(format!("lazy branch: unprotect: {e}")))?;
                }
                Ok(None) => break,
                Ok(Some(_)) => continue,
                Err(_) => break,
            }
        }
    }
    Ok(faulted)
}

/// A lazy child's MISSING-page handler: until `child_stop`, fill each faulted page —
/// from the branch file if the parent has diverged it (present), else from the parent's
/// live RAM (still T). Returns the number of pages it filled.
fn child_handler_loop(
    uffd: Uffd,
    child_map: Arc<RegionMap>,
    parent_map: Arc<RegionMap>,
    preserve: Arc<PreserveMap>,
    file: Arc<File>,
    child_stop: Arc<AtomicBool>,
) -> Result<u64> {
    let mut filled = 0u64;
    let mut buf = vec![0u8; PAGE_SIZE];
    while !child_stop.load(Ordering::Acquire) {
        let mut pfd = libc::pollfd {
            fd: uffd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd for the call.
        let _ = unsafe { libc::poll(&mut pfd, 1, 20) };
        loop {
            match uffd.read_event() {
                Ok(Some(Event::Pagefault { addr, .. })) => {
                    let child_page_base = (addr as usize) & !(PAGE_SIZE - 1);
                    // Map the child fault address → global page index (child + parent share
                    // the same page layout / sizes), then to the parent's host address.
                    let page = match child_map.page_of_addr(child_page_base) {
                        Some(p) => p,
                        None => continue,
                    };
                    // Provenance: present in the file ⇒ read the file; else the parent's RAM
                    // still holds T (it is write-protected until preserved).
                    if preserve.is_page_copied(page) {
                        file.read_exact_at(&mut buf, parent_map.file_offset_of_page(page))
                            .map_err(VmmError::Io)?;
                    } else {
                        let psrc = parent_map.addr_of_page(page).ok_or_else(|| {
                            VmmError::Device(format!("lazy child: page {page} out of range"))
                        })?;
                        // SAFETY: `psrc` is a mapped parent guest page (the parent outlives
                        // this handler), PAGE_SIZE long; copying out a stable T-version.
                        let src =
                            unsafe { std::slice::from_raw_parts(psrc as *const u8, PAGE_SIZE) };
                        buf.copy_from_slice(src);
                    }
                    // SAFETY: `child_page_base` is a registered, currently-missing page in
                    // the child's mapping; `buf` is PAGE_SIZE. UFFDIO_COPY installs it.
                    // A single handler thread processes faults serially, so no two faults
                    // race on the same page; any copy error is real and fails the child.
                    unsafe {
                        uffd.copy(
                            buf.as_ptr() as *const c_void,
                            child_page_base as *mut c_void,
                            PAGE_SIZE,
                            true,
                        )
                    }
                    .map_err(|e| VmmError::Device(format!("lazy child: copy: {e}")))?;
                    filled += 1;
                }
                Ok(None) => break,
                Ok(Some(_)) => continue,
                Err(_) => break,
            }
        }
    }
    Ok(filled)
}
