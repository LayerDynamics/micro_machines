//! virtio-blk backed by the rootfs image file (SPEC-1 FR-3, FR-6).
//!
//! M1 backs the device with a single image file: a read-only base, or a writable
//! ephemeral overlay (the overlay is assembled by `mm-image`/`mm-init`; this
//! device just serves whatever file it is handed). The worker drains the request
//! virtqueue, performs positioned file I/O per the virtio-blk request, writes the
//! status byte, and raises the used-ring interrupt.
use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::Arc;

use virtio_queue::{Queue, QueueT};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
use vmm_sys_util::eventfd::EventFd;

use super::{Interrupt, VirtioDevice, QUEUE_SIZE, TYPE_BLOCK, VIRTIO_F_VERSION_1};
use crate::machine::{Result, VmmError};

const SECTOR_SIZE: u64 = 512;
const VIRTIO_BLK_HDR_LEN: usize = 16;

// virtio-blk request types (virtio spec §5.2.6).
const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;
const VIRTIO_BLK_T_FLUSH: u32 = 4;

// virtio-blk status byte values.
const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;
const VIRTIO_BLK_S_UNSUPP: u8 = 2;

// virtio-blk feature bits.
const VIRTIO_BLK_F_RO: u64 = 1 << 5;
const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;

/// A virtio block device serving `file` as a linear disk of 512-byte sectors.
pub struct Block {
    capacity_sectors: u64,
    read_only: bool,
    file: Option<File>,
    queue_max_sizes: [u16; 1],
    rate_limit: Option<crate::config::RateLimit>,
    /// Snapshot pause handle (set by the Machine before activation); the worker
    /// captures its queue cursor here when signalled (SPEC-1 FR-14).
    pause: Option<super::DevicePause>,
}

impl Block {
    /// Open `path` as the backing image. `read_only` opens it read-only and
    /// advertises `VIRTIO_BLK_F_RO` so the guest mounts it accordingly.
    /// `rate_limit` optionally caps throughput (SPEC-1 FR-28).
    pub fn new(
        path: &Path,
        read_only: bool,
        rate_limit: Option<crate::config::RateLimit>,
    ) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(!read_only)
            .open(path)
            .map_err(VmmError::Io)?;
        let len = file.metadata().map_err(VmmError::Io)?.len();
        Ok(Self {
            capacity_sectors: len / SECTOR_SIZE,
            read_only,
            file: Some(file),
            queue_max_sizes: [QUEUE_SIZE],
            rate_limit,
            pause: None,
        })
    }
}

impl VirtioDevice for Block {
    fn device_type(&self) -> u32 {
        TYPE_BLOCK
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.queue_max_sizes
    }

    fn features(&self) -> u64 {
        let mut features = VIRTIO_F_VERSION_1 | VIRTIO_BLK_F_FLUSH;
        if self.read_only {
            features |= VIRTIO_BLK_F_RO;
        }
        features
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // Config space: capacity in 512-byte sectors at offset 0 (u64, LE).
        let capacity = self.capacity_sectors.to_le_bytes();
        for (i, byte) in data.iter_mut().enumerate() {
            let idx = offset as usize + i;
            *byte = capacity.get(idx).copied().unwrap_or(0);
        }
    }

    fn set_pause_handle(&mut self, pause: super::DevicePause) {
        self.pause = Some(pause);
    }

    fn activate(
        &mut self,
        mem: Arc<GuestMemoryMmap>,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
        interrupt: Arc<Interrupt>,
    ) -> Result<()> {
        let queue = queues
            .pop()
            .ok_or_else(|| VmmError::Device("block: missing request queue".to_string()))?;
        let evt = queue_evts
            .pop()
            .ok_or_else(|| VmmError::Device("block: missing queue eventfd".to_string()))?;
        let file = self
            .file
            .take()
            .ok_or_else(|| VmmError::Device("block: already activated".to_string()))?;
        let read_only = self.read_only;
        let rate_limit = self.rate_limit.take();
        let pause = self.pause.take();

        // The worker is detached: it lives as long as its notify eventfd (owned by
        // the transport) stays open, and exits cleanly when the VM tears down.
        std::thread::Builder::new()
            .name("mm-blk".to_string())
            .spawn(move || {
                block_worker(queue, evt, mem, interrupt, file, read_only, rate_limit, pause)
            })
            .map_err(VmmError::Io)?;
        Ok(())
    }
}

/// Block worker loop: wait for a queue notify (or a snapshot pause request), then
/// drain all pending requests. Polls both the notify eventfd and — when snapshotting
/// is wired — the pause eventfd, so a snapshot can quiesce the device and capture its
/// queue cursor (SPEC-1 FR-14).
#[allow(clippy::too_many_arguments)]
fn block_worker(
    mut queue: Queue,
    evt: EventFd,
    mem: Arc<GuestMemoryMmap>,
    interrupt: Arc<Interrupt>,
    mut file: File,
    read_only: bool,
    rate_limit: Option<crate::config::RateLimit>,
    pause: Option<super::DevicePause>,
) {
    let mut limiter = crate::ratelimit::DeviceRateLimiter::from_config(rate_limit.as_ref());
    let mut drain = |queue: &mut Queue, file: &mut File| {
        if let Err(e) = process_queue(queue, &mem, &interrupt, file, read_only, &mut limiter) {
            tracing::error!("block: queue processing failed: {e}");
        }
    };

    loop {
        let mut fds = [
            libc::pollfd {
                fd: evt.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: pause.as_ref().map_or(-1, |p| p.evt.as_raw_fd()),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: `fds` is a valid, initialized pollfd slice for the call's duration;
        // a fd of -1 is ignored by poll.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if rc < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }

        if fds[0].revents & libc::POLLIN != 0 {
            // A read error means the notify eventfd was closed -> shut down.
            if evt.read().is_err() {
                break;
            }
            drain(&mut queue, &mut file);
        }

        if fds[1].revents & libc::POLLIN != 0 {
            if let Some(p) = pause.as_ref() {
                let _ = p.evt.read();
                // Final drain so next_avail reaches avail.idx, then capture the cursor
                // and exit (the VM is frozen for the snapshot).
                drain(&mut queue, &mut file);
                if let Ok(mut slot) = p.slot.lock() {
                    *slot = Some(vec![queue.state().into()]);
                }
            }
            break;
        }
    }
}

/// Drain every available request chain, servicing each and updating the used ring.
fn process_queue(
    queue: &mut Queue,
    mem: &Arc<GuestMemoryMmap>,
    interrupt: &Interrupt,
    file: &mut File,
    read_only: bool,
    limiter: &mut Option<crate::ratelimit::DeviceRateLimiter>,
) -> Result<()> {
    let mut signalled = false;
    while let Some(chain) = queue.pop_descriptor_chain(mem.clone()) {
        let head = chain.head_index();
        let descs: Vec<(GuestAddress, u32, bool)> = chain
            .map(|d| (d.addr(), d.len(), d.is_write_only()))
            .collect();
        // Rate limit (FR-28): one op + the data-descriptor bytes (the header +
        // status descriptors are control, not data). Blocks briefly when throttled.
        if let Some(l) = limiter.as_mut() {
            let data_bytes: u64 = descs
                .get(1..descs.len().saturating_sub(1))
                .unwrap_or(&[])
                .iter()
                .map(|(_, len, _)| u64::from(*len))
                .sum();
            l.wait_admit(1, data_bytes, std::time::Duration::from_millis(200));
        }
        let used_len = service_request(mem, file, read_only, &descs)?;
        queue
            .add_used(mem.as_ref(), head, used_len)
            .map_err(|e| VmmError::Device(format!("block add_used: {e}")))?;
        signalled = true;
    }
    if signalled {
        interrupt.signal_used_queue()?;
    }
    Ok(())
}

/// Service one virtio-blk request described by `descs` (header, data*, status),
/// returning the number of bytes written to device-writable descriptors.
fn service_request(
    mem: &Arc<GuestMemoryMmap>,
    file: &mut File,
    read_only: bool,
    descs: &[(GuestAddress, u32, bool)],
) -> Result<u32> {
    if descs.len() < 2 {
        return Err(VmmError::Device(
            "block: request chain too short".to_string(),
        ));
    }
    let (header_addr, header_len, _) = descs[0];
    if (header_len as usize) < VIRTIO_BLK_HDR_LEN {
        return Err(VmmError::Device("block: short request header".to_string()));
    }

    let mut header = [0u8; VIRTIO_BLK_HDR_LEN];
    mem.read_slice(&mut header, header_addr)
        .map_err(|e| VmmError::Device(format!("block: header read: {e}")))?;
    let req_type = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    let sector = u64::from_le_bytes([
        header[8], header[9], header[10], header[11], header[12], header[13], header[14],
        header[15],
    ]);

    let (status_addr, _, _) = *descs.last().unwrap();
    let data = &descs[1..descs.len() - 1];

    let mut written_to_guest = 0u32;
    let status = match req_type {
        VIRTIO_BLK_T_IN => read_request(mem, file, sector, data).map(|n| {
            written_to_guest = n;
            VIRTIO_BLK_S_OK
        }),
        VIRTIO_BLK_T_OUT if read_only => Ok(VIRTIO_BLK_S_IOERR),
        VIRTIO_BLK_T_OUT => write_request(mem, file, sector, data).map(|_| VIRTIO_BLK_S_OK),
        VIRTIO_BLK_T_FLUSH => file
            .sync_all()
            .map(|_| VIRTIO_BLK_S_OK)
            .map_err(VmmError::Io),
        _ => Ok(VIRTIO_BLK_S_UNSUPP),
    }
    .unwrap_or(VIRTIO_BLK_S_IOERR);

    mem.write_slice(&[status], status_addr)
        .map_err(|e| VmmError::Device(format!("block: status write: {e}")))?;

    // Used length: device-writable bytes (data for reads) plus the status byte.
    Ok(written_to_guest + 1)
}

/// Read sectors from the file into the guest's writable data descriptors.
fn read_request(
    mem: &Arc<GuestMemoryMmap>,
    file: &File,
    sector: u64,
    data: &[(GuestAddress, u32, bool)],
) -> Result<u32> {
    let mut offset = sector * SECTOR_SIZE;
    let mut total = 0u32;
    for &(addr, len, write_only) in data {
        if !write_only {
            return Err(VmmError::Device(
                "block: read request with read-only data descriptor".to_string(),
            ));
        }
        let mut buf = vec![0u8; len as usize];
        file.read_exact_at(&mut buf, offset).map_err(VmmError::Io)?;
        mem.write_slice(&buf, addr)
            .map_err(|e| VmmError::Device(format!("block: data write: {e}")))?;
        offset += u64::from(len);
        total += len;
    }
    Ok(total)
}

/// Write the guest's readable data descriptors to the file at the request sector.
fn write_request(
    mem: &Arc<GuestMemoryMmap>,
    file: &mut File,
    sector: u64,
    data: &[(GuestAddress, u32, bool)],
) -> Result<()> {
    let mut offset = sector * SECTOR_SIZE;
    for &(addr, len, _) in data {
        let mut buf = vec![0u8; len as usize];
        mem.read_slice(&mut buf, addr)
            .map_err(|e| VmmError::Device(format!("block: data read: {e}")))?;
        file.write_all_at(&buf, offset).map_err(VmmError::Io)?;
        offset += u64::from(len);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use virtio_queue::mock::MockSplitQueue;
    use vm_memory::GuestAddress;

    fn guest_mem() -> Arc<GuestMemoryMmap> {
        Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x100_0000)]).unwrap())
    }

    #[test]
    fn block_capacity_config_reports_sectors() {
        let mut tmp = std::env::temp_dir();
        tmp.push("mm-block-cap-test.img");
        {
            let mut f = File::create(&tmp).unwrap();
            f.write_all(&vec![0u8; 4096]).unwrap(); // 8 sectors
        }
        let blk = Block::new(&tmp, true, None).unwrap();
        assert_eq!(blk.capacity_sectors, 8);
        let mut cfg = [0u8; 8];
        blk.read_config(0, &mut cfg);
        assert_eq!(u64::from_le_bytes(cfg), 8);
        assert!(
            blk.features() & VIRTIO_BLK_F_RO != 0,
            "RO image advertises RO"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn read_request_serves_file_contents_into_guest() {
        // Backing file: sector 0 is all 0xAB.
        let mut tmp = std::env::temp_dir();
        tmp.push("mm-block-read-test.img");
        {
            let mut f = File::create(&tmp).unwrap();
            f.write_all(&vec![0xABu8; 512]).unwrap();
        }
        let file = OpenOptions::new().read(true).open(&tmp).unwrap();
        let mem = guest_mem();

        // Lay out a virtio-blk IN request in guest memory: header, data, status.
        let header_addr = GuestAddress(0x1000);
        let data_addr = GuestAddress(0x2000);
        let status_addr = GuestAddress(0x3000);
        // type = IN (0), reserved = 0, sector = 0.
        let mut header = [0u8; VIRTIO_BLK_HDR_LEN];
        header[..4].copy_from_slice(&VIRTIO_BLK_T_IN.to_le_bytes());
        mem.write_slice(&header, header_addr).unwrap();

        let descs = [
            (header_addr, VIRTIO_BLK_HDR_LEN as u32, false),
            (data_addr, 512, true),
            (status_addr, 1, true),
        ];
        let mut f = file;
        let used = service_request(&mem, &mut f, true, &descs).unwrap();
        assert_eq!(used, 512 + 1, "512 data bytes + 1 status byte");

        let mut out = [0u8; 512];
        mem.read_slice(&mut out, data_addr).unwrap();
        assert!(out.iter().all(|&b| b == 0xAB), "guest buffer got file data");

        let mut status = [0u8; 1];
        mem.read_slice(&mut status, status_addr).unwrap();
        assert_eq!(status[0], VIRTIO_BLK_S_OK);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn write_to_read_only_device_reports_ioerr() {
        let mut tmp = std::env::temp_dir();
        tmp.push("mm-block-ro-test.img");
        {
            let mut f = File::create(&tmp).unwrap();
            f.write_all(&vec![0u8; 512]).unwrap();
        }
        let mut f = OpenOptions::new().read(true).open(&tmp).unwrap();
        let mem = guest_mem();
        let header_addr = GuestAddress(0x1000);
        let data_addr = GuestAddress(0x2000);
        let status_addr = GuestAddress(0x3000);
        let mut header = [0u8; VIRTIO_BLK_HDR_LEN];
        header[..4].copy_from_slice(&VIRTIO_BLK_T_OUT.to_le_bytes());
        mem.write_slice(&header, header_addr).unwrap();
        let descs = [
            (header_addr, VIRTIO_BLK_HDR_LEN as u32, false),
            (data_addr, 512, false),
            (status_addr, 1, true),
        ];
        service_request(&mem, &mut f, true, &descs).unwrap();
        let mut status = [0u8; 1];
        mem.read_slice(&mut status, status_addr).unwrap();
        assert_eq!(status[0], VIRTIO_BLK_S_IOERR, "write to RO device fails");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn mock_queue_builds_a_chain() {
        // Sanity that the mock queue API we rely on in CI is wired correctly.
        let mem = guest_mem();
        let vq = MockSplitQueue::new(mem.as_ref(), 16);
        let _queue: Queue = vq.create_queue().unwrap();
    }

    #[test]
    fn worker_captures_queue_cursor_on_pause() {
        // On a snapshot pause signal, the worker captures its queue cursor into the
        // slot and exits — the device half of the FR-14 pause/capture mechanism.
        let mem = guest_mem();
        let queue = MockSplitQueue::create(mem.as_ref(), GuestAddress(0), 16)
            .create_queue::<Queue>()
            .unwrap();
        let notify = EventFd::new(0).unwrap();
        let interrupt = Arc::new(Interrupt::new(EventFd::new(0).unwrap()));
        let file = File::open("/dev/null").unwrap();
        let pause_evt = EventFd::new(0).unwrap();
        let slot = Arc::new(std::sync::Mutex::new(None));
        let pause = crate::devices::DevicePause {
            evt: pause_evt.try_clone().unwrap(),
            slot: slot.clone(),
        };

        let worker = std::thread::spawn(move || {
            block_worker(queue, notify, mem, interrupt, file, true, None, Some(pause));
        });
        // Ask the worker to pause + capture; it captures its cursor and returns.
        pause_evt.write(1).unwrap();
        worker.join().unwrap();

        let cursors = slot.lock().unwrap().take().expect("cursor was captured");
        assert_eq!(cursors.len(), 1, "block has one request queue");
        assert_eq!(cursors[0].next_avail, 0, "a fresh queue's cursor is at 0");
    }
}
