//! Pure coordination cores for the FR-16 running-BRANCH write-protect engine.
//!
//! The engine (`snapshot::branch`) materializes a complete point-in-time (T) copy of a
//! *running* parent's guest RAM into a branch file, using `userfaultfd` write-protection
//! so that a page the parent modifies after T is preserved (its T-version copied aside)
//! before the modification is allowed. Two actors race to fill the branch file: a
//! background **copier** that walks every page, and a **fault handler** that copies a
//! page the moment the parent tries to write it. The correctness of that race lives in
//! these two pure types — no `userfaultfd`, no KVM — so they are unit-tested on the
//! (non-Linux) dev host, which is the only place the engine's logic can be validated
//! locally.
//!
//! Protocol (per guest page):
//! - whoever **claims** the page ([`PreserveMap::try_claim`]) copies its T-version into
//!   the branch file and then records it [`copied`](PreserveMap::mark_copied). Exactly
//!   one actor claims a page.
//! - only the fault handler touches `userfaultfd` (it is the sole owner of the uffd, so
//!   no cross-thread uffd sharing is needed). On a write fault for page `p`: if the
//!   handler claims `p` it copies + marks + removes write-protection (+ wakes the
//!   writer); if `p` was already claimed by the copier, the handler waits until the
//!   copier has [`marked it copied`](PreserveMap::is_page_copied) — so the T-version is
//!   safely in the branch file — and only then removes write-protection. Waiting on the
//!   *copied* bit (not merely *claimed*) is what prevents the writer from racing ahead
//!   of the copier's read.
//! - completion is when every page has been **copied** ([`PreserveMap::is_complete`]),
//!   not merely claimed — a claimed-but-not-yet-copied page is still in flight.

/// Guest page size (x86-64 4 KiB). Guest RAM regions are always page-multiples.
pub(crate) const PAGE_SIZE: usize = 4096;

/// Claim-once bitmap plus a copied-page counter, shared by the copier and the fault
/// handler. `try_claim` transitions a page Unclaimed→Claimed atomically so exactly one
/// actor copies it; `mark_copied` records that a claimed page's T-version has actually
/// landed in the branch file, and `is_complete` reports when all pages have.
pub(crate) struct PreserveMap {
    /// One bit per page; set when the page has been claimed for copying.
    claimed: Vec<std::sync::atomic::AtomicU64>,
    /// One bit per page; set once the page's T-version is in the branch file. The fault
    /// handler waits on this before unprotecting a page the copier claimed.
    copied: Vec<std::sync::atomic::AtomicU64>,
    /// Number of pages whose T-version has been written to the branch file.
    copied_count: std::sync::atomic::AtomicUsize,
    total_pages: usize,
}

impl PreserveMap {
    pub(crate) fn new(total_pages: usize) -> Self {
        let words = total_pages.div_ceil(64);
        let mk = || {
            let mut v = Vec::with_capacity(words);
            for _ in 0..words {
                v.push(std::sync::atomic::AtomicU64::new(0));
            }
            v
        };
        Self {
            claimed: mk(),
            copied: mk(),
            copied_count: std::sync::atomic::AtomicUsize::new(0),
            total_pages,
        }
    }

    pub(crate) fn total_pages(&self) -> usize {
        self.total_pages
    }

    /// Atomically claim `page` for copying. Returns `true` iff this caller is the one
    /// that transitioned it from unclaimed → claimed (and therefore must copy it).
    pub(crate) fn try_claim(&self, page: usize) -> bool {
        use std::sync::atomic::Ordering;
        let (word, bit) = (page / 64, page % 64);
        let mask = 1u64 << bit;
        // AcqRel so the claim is globally ordered w.r.t. the subsequent copy.
        let prev = self.claimed[word].fetch_or(mask, Ordering::AcqRel);
        prev & mask == 0
    }

    /// Record that `page`'s T-version has been written to the branch file. Set the
    /// per-page bit with Release ordering so a handler that observes it (Acquire) also
    /// sees the completed file write.
    pub(crate) fn mark_copied(&self, page: usize) {
        use std::sync::atomic::Ordering;
        let (word, bit) = (page / 64, page % 64);
        self.copied[word].fetch_or(1u64 << bit, Ordering::Release);
        self.copied_count.fetch_add(1, Ordering::AcqRel);
    }

    /// Whether `page`'s T-version is already in the branch file.
    pub(crate) fn is_page_copied(&self, page: usize) -> bool {
        use std::sync::atomic::Ordering;
        let (word, bit) = (page / 64, page % 64);
        self.copied[word].load(Ordering::Acquire) & (1u64 << bit) != 0
    }

    pub(crate) fn copied_count(&self) -> usize {
        self.copied_count.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Every page's T-version is in the branch file — the branch is fully materialized.
    pub(crate) fn is_complete(&self) -> bool {
        self.copied_count() >= self.total_pages
    }
}

/// One guest RAM region's placement: its host mapping base, its page count, and the
/// global page index of its first page.
#[derive(Clone, Copy, Debug)]
struct RegionSpan {
    host_base: usize,
    pages: usize,
    first_global_page: usize,
}

/// Maps between a faulting host address, a global page index, and a branch-file offset.
///
/// Guest RAM is one or more host mmap regions (split around the 32-bit MMIO hole). The
/// branch file holds those regions concatenated in ascending order with no padding
/// (matching `dump_guest_memory` / `allocate_cow_guest_memory`), so global page `g`'s
/// file offset is simply `g * PAGE_SIZE`. Global page indices run contiguously across
/// regions in order.
pub(crate) struct RegionMap {
    spans: Vec<RegionSpan>,
    total_pages: usize,
}

impl RegionMap {
    /// Build from `(host_base, len_bytes)` pairs in ascending guest-address order. Each
    /// `len` must be a multiple of [`PAGE_SIZE`] (guest RAM regions always are).
    pub(crate) fn new(regions: &[(usize, usize)]) -> Self {
        let mut spans = Vec::with_capacity(regions.len());
        let mut next_global = 0usize;
        for &(host_base, len) in regions {
            let pages = len / PAGE_SIZE;
            spans.push(RegionSpan {
                host_base,
                pages,
                first_global_page: next_global,
            });
            next_global += pages;
        }
        Self {
            spans,
            total_pages: next_global,
        }
    }

    pub(crate) fn total_pages(&self) -> usize {
        self.total_pages
    }

    /// The global page index containing host address `addr`, or `None` if `addr` is
    /// outside every region.
    pub(crate) fn page_of_addr(&self, addr: usize) -> Option<usize> {
        for s in &self.spans {
            let end = s.host_base + s.pages * PAGE_SIZE;
            if addr >= s.host_base && addr < end {
                let off_page = (addr - s.host_base) / PAGE_SIZE;
                return Some(s.first_global_page + off_page);
            }
        }
        None
    }

    /// The host base address of global page `page`, or `None` if out of range.
    pub(crate) fn addr_of_page(&self, page: usize) -> Option<usize> {
        for s in &self.spans {
            if page >= s.first_global_page && page < s.first_global_page + s.pages {
                let off_page = page - s.first_global_page;
                return Some(s.host_base + off_page * PAGE_SIZE);
            }
        }
        None
    }

    /// The branch-file byte offset of global page `page` (regions are concatenated with
    /// no padding, so this is just `page * PAGE_SIZE`).
    pub(crate) fn file_offset_of_page(&self, page: usize) -> u64 {
        (page * PAGE_SIZE) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn region_map_single_region_round_trips() {
        // 8 pages at host base 0x1000_0000.
        let base = 0x1000_0000usize;
        let rm = RegionMap::new(&[(base, 8 * PAGE_SIZE)]);
        assert_eq!(rm.total_pages(), 8);

        for p in 0..8 {
            let addr = rm.addr_of_page(p).unwrap();
            assert_eq!(addr, base + p * PAGE_SIZE);
            // An address anywhere inside the page maps back to the same page.
            assert_eq!(rm.page_of_addr(addr).unwrap(), p);
            assert_eq!(rm.page_of_addr(addr + 17).unwrap(), p);
            assert_eq!(rm.file_offset_of_page(p), (p * PAGE_SIZE) as u64);
        }
        // Out of range below and above.
        assert_eq!(rm.page_of_addr(base - 1), None);
        assert_eq!(rm.page_of_addr(base + 8 * PAGE_SIZE), None);
        assert_eq!(rm.addr_of_page(8), None);
    }

    #[test]
    fn region_map_two_regions_are_contiguous_in_file() {
        // Mirrors the >3GiB split: region A (3 pages) low, region B (2 pages) high. The
        // file concatenates them, so B's first page sits right after A in the file even
        // though its host/guest addresses are far away.
        let a = 0x2000_0000usize;
        let b = 0x9000_0000usize;
        let rm = RegionMap::new(&[(a, 3 * PAGE_SIZE), (b, 2 * PAGE_SIZE)]);
        assert_eq!(rm.total_pages(), 5);

        // Region A: global pages 0..3 at file offsets 0..3.
        assert_eq!(rm.page_of_addr(a).unwrap(), 0);
        assert_eq!(rm.page_of_addr(a + 2 * PAGE_SIZE).unwrap(), 2);
        // Region B: global pages 3..5, file offsets continue (no gap).
        assert_eq!(rm.page_of_addr(b).unwrap(), 3);
        assert_eq!(rm.addr_of_page(3).unwrap(), b);
        assert_eq!(rm.addr_of_page(4).unwrap(), b + PAGE_SIZE);
        assert_eq!(rm.file_offset_of_page(3), (3 * PAGE_SIZE) as u64);
        // The gap between the two host regions is not mapped.
        assert_eq!(rm.page_of_addr(a + 3 * PAGE_SIZE), None);
    }

    #[test]
    fn preserve_map_claims_each_page_exactly_once() {
        let map = PreserveMap::new(200);
        // First claim of a page wins; a second claim of the same page loses.
        assert!(map.try_claim(0));
        assert!(!map.try_claim(0));
        assert!(map.try_claim(63));
        assert!(map.try_claim(64)); // crosses a word boundary
        assert!(!map.try_claim(64));
        assert!(!map.is_complete());

        // The copied bit is independent of the claim and tracks the actual file write.
        assert!(!map.is_page_copied(0));
        map.mark_copied(0);
        assert!(map.is_page_copied(0));
        assert!(!map.is_page_copied(63));
    }

    #[test]
    fn preserve_map_concurrent_claims_total_exactly_once() {
        // The copier-vs-handler race: many threads claim the same page set; across all
        // of them, each page must be claimed by exactly one thread, and the copied
        // counter must reach total when each winner marks its page copied.
        const PAGES: usize = 1000;
        let map = Arc::new(PreserveMap::new(PAGES));
        let wins = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let map = map.clone();
                let wins = wins.clone();
                std::thread::spawn(move || {
                    for p in 0..PAGES {
                        if map.try_claim(p) {
                            wins.fetch_add(1, Ordering::AcqRel);
                            map.mark_copied(p); // "copied this page's T-version"
                        }
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(
            wins.load(Ordering::Acquire),
            PAGES,
            "each page claimed by exactly one thread"
        );
        assert_eq!(map.copied_count(), PAGES);
        assert!(map.is_complete());
    }
}
