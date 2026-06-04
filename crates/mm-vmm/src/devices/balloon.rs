//! virtio-balloon — reclaim guest memory back to the host (SPEC-1 FR-3).
//!
//! The balloon advertises an inflation `num_pages` target in its config space.
//! The guest's balloon driver hands the device the page frame numbers (PFNs) of
//! pages it has freed on the **inflate** queue; the device `madvise(DONTNEED)`s
//! the backing host pages, returning that RAM to the host. The **deflate** queue
//! is the reverse: the guest reclaims pages and the device hints `WILLNEED`. The
//! `actual` config field tracks how much is currently ballooned out.
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use crate::GuestMemoryMmap;
use virtio_queue::{Queue, QueueT};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryRegion};
use vmm_sys_util::eventfd::EventFd;

use super::{Interrupt, VirtioDevice, QUEUE_SIZE, TYPE_BALLOON, VIRTIO_F_VERSION_1};
use crate::machine::{Result, VmmError};

/// 4 KiB pages per MiB.
const PAGES_PER_MIB: u32 = 256;
/// virtio-balloon reports pages as 4 KiB PFNs.
const BALLOON_PFN_SHIFT: u64 = 12;
const PAGE_SIZE: usize = 4096;

const INFLATE_QUEUE: usize = 0;
const DEFLATE_QUEUE: usize = 1;

/// A virtio memory balloon. Inflation reclaims `target` MiB of guest RAM.
pub struct Balloon {
    /// Inflation target in 4 KiB pages (the `num_pages` config field).
    target_pages: u32,
    /// Pages currently ballooned out (the `actual` config field), shared with the
    /// inflate/deflate workers.
    actual: Arc<AtomicU32>,
    queue_max_sizes: [u16; 2],
}

impl Balloon {
    /// Create a balloon whose inflation target is `target_mib` MiB.
    pub fn new(target_mib: u64) -> Self {
        let target_pages = u32::try_from(target_mib)
            .unwrap_or(u32::MAX / PAGES_PER_MIB)
            .saturating_mul(PAGES_PER_MIB);
        Self {
            target_pages,
            actual: Arc::new(AtomicU32::new(0)),
            queue_max_sizes: [QUEUE_SIZE, QUEUE_SIZE],
        }
    }
}

impl VirtioDevice for Balloon {
    fn device_type(&self) -> u32 {
        TYPE_BALLOON
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.queue_max_sizes
    }

    fn features(&self) -> u64 {
        VIRTIO_F_VERSION_1
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // Config: num_pages (u32 LE) @0, actual (u32 LE) @4.
        let mut config = [0u8; 8];
        config[0..4].copy_from_slice(&self.target_pages.to_le_bytes());
        config[4..8].copy_from_slice(&self.actual.load(Ordering::SeqCst).to_le_bytes());
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = config.get(offset as usize + i).copied().unwrap_or(0);
        }
    }

    fn activate(
        &mut self,
        mem: Arc<GuestMemoryMmap>,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
        interrupt: Arc<Interrupt>,
    ) -> Result<()> {
        if queues.len() < 2 || queue_evts.len() < 2 {
            return Err(VmmError::Device(
                "balloon: expected inflate and deflate queues".to_string(),
            ));
        }
        // Remove the higher index first so the lower index stays valid.
        let deflate_queue = queues.swap_remove(DEFLATE_QUEUE);
        let inflate_queue = queues.swap_remove(INFLATE_QUEUE);
        let deflate_evt = queue_evts.swap_remove(DEFLATE_QUEUE);
        let inflate_evt = queue_evts.swap_remove(INFLATE_QUEUE);

        // Inflate worker: reclaim pages (MADV_DONTNEED), grow `actual`.
        spawn_worker(
            "mm-balloon-inflate",
            inflate_queue,
            inflate_evt,
            mem.clone(),
            interrupt.clone(),
            self.actual.clone(),
            true,
        )?;
        // Deflate worker: hint pages back (MADV_WILLNEED), shrink `actual`.
        spawn_worker(
            "mm-balloon-deflate",
            deflate_queue,
            deflate_evt,
            mem,
            interrupt,
            self.actual.clone(),
            false,
        )?;
        Ok(())
    }
}

/// Spawn a detached worker draining one balloon queue.
fn spawn_worker(
    name: &str,
    queue: Queue,
    evt: EventFd,
    mem: Arc<GuestMemoryMmap>,
    interrupt: Arc<Interrupt>,
    actual: Arc<AtomicU32>,
    reclaim: bool,
) -> Result<()> {
    std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || worker_loop(queue, evt, mem, interrupt, actual, reclaim))
        .map_err(VmmError::Io)?;
    Ok(())
}

fn worker_loop(
    mut queue: Queue,
    evt: EventFd,
    mem: Arc<GuestMemoryMmap>,
    interrupt: Arc<Interrupt>,
    actual: Arc<AtomicU32>,
    reclaim: bool,
) {
    loop {
        if evt.read().is_err() {
            break;
        }
        if let Err(e) = process_queue(&mut queue, &mem, &interrupt, &actual, reclaim) {
            tracing::error!("balloon: queue processing failed: {e}");
        }
    }
}

/// Drain every available chain: each descriptor is an array of 4-byte PFNs whose
/// backing host pages we advise the kernel on, then return the buffer.
fn process_queue(
    queue: &mut Queue,
    mem: &Arc<GuestMemoryMmap>,
    interrupt: &Interrupt,
    actual: &AtomicU32,
    reclaim: bool,
) -> Result<()> {
    let mut signalled = false;
    while let Some(chain) = queue.pop_descriptor_chain(mem.clone()) {
        let head = chain.head_index();
        let descs: Vec<(GuestAddress, u32)> = chain.map(|d| (d.addr(), d.len())).collect();

        let mut pages = 0u32;
        for (addr, len) in descs {
            let mut raw = vec![0u8; len as usize];
            mem.read_slice(&mut raw, addr)
                .map_err(|e| VmmError::Device(format!("balloon pfn read: {e}")))?;
            for chunk in raw.chunks_exact(4) {
                let pfn = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                advise_page(mem, u64::from(pfn) << BALLOON_PFN_SHIFT, reclaim);
                pages += 1;
            }
        }

        if reclaim {
            actual.fetch_add(pages, Ordering::SeqCst);
        } else {
            // Saturating decrement so `actual` never underflows.
            let mut current = actual.load(Ordering::SeqCst);
            loop {
                let next = current.saturating_sub(pages);
                match actual.compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst) {
                    Ok(_) => break,
                    Err(observed) => current = observed,
                }
            }
        }

        queue
            .add_used(mem.as_ref(), head, 0)
            .map_err(|e| VmmError::Device(format!("balloon add_used: {e}")))?;
        signalled = true;
    }
    if signalled {
        interrupt.signal_used_queue()?;
    }
    Ok(())
}

/// `madvise` the host page backing `guest_addr`: `DONTNEED` to reclaim (inflate),
/// `WILLNEED` to hint it back (deflate). Out-of-range PFNs are ignored.
fn advise_page(mem: &GuestMemoryMmap, guest_addr: u64, reclaim: bool) {
    let Some((region, region_addr)) = mem.to_region_addr(GuestAddress(guest_addr)) else {
        return;
    };
    let offset = region_addr.raw_value() as usize;
    if offset + PAGE_SIZE > region.len() as usize {
        return;
    }
    let advice = if reclaim {
        libc::MADV_DONTNEED
    } else {
        libc::MADV_WILLNEED
    };
    // SAFETY: `region.as_ptr() + offset` is within the region's mmap (bounds
    // checked above), page-advice does not invalidate Rust references, and a
    // failed madvise is non-fatal (best-effort reclamation).
    unsafe {
        let host = region.as_ptr().add(offset);
        libc::madvise(host as *mut libc::c_void, PAGE_SIZE, advice);
    }
    if reclaim {
        // MADV_DONTNEED zeroes the page through the host mapping — a raw `madvise`, not a
        // `Bytes` write, so it bypasses BOTH the KVM dirty log and the per-page dirty
        // bitmap. Mark it dirty explicitly so a concurrent `Machine::branch` re-copies the
        // now-zeroed page at its final barrier instead of capturing the stale pre-reclaim
        // contents. (`(**region)` reaches the `MmapRegion`'s inherent `AtomicBitmap` past
        // `GuestRegionMmap`'s Deref; the trait `bitmap()` returns only a slice.)
        (**region).bitmap().set_addr_range(offset, PAGE_SIZE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_pages_scale_with_mib() {
        let balloon = Balloon::new(4);
        assert_eq!(balloon.target_pages, 4 * PAGES_PER_MIB);
    }

    #[test]
    fn config_reports_num_pages_and_actual() {
        let balloon = Balloon::new(2);
        balloon.actual.store(13, Ordering::SeqCst);
        let mut config = [0u8; 8];
        balloon.read_config(0, &mut config);
        assert_eq!(
            u32::from_le_bytes(config[0..4].try_into().unwrap()),
            2 * PAGES_PER_MIB
        );
        assert_eq!(u32::from_le_bytes(config[4..8].try_into().unwrap()), 13);
    }
}
