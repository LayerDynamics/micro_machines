//! virtio-net bound to a host TAP device (SPEC-1 FR-3, FR-10).
//!
//! Transmit is driven by guest queue notifications; receive is driven by the TAP
//! becoming readable. Because those two readiness sources are independent, the
//! worker runs an [`event_manager`] epoll loop watching the TAP fd and the tx/rx
//! notify eventfds — this is the one device whose processing genuinely needs an
//! event loop rather than a single blocking wait. The guest speaks virtio-net
//! (frames prefixed by a 12-byte `virtio_net_hdr`); the TAP carries raw Ethernet,
//! so the worker strips the header on tx and prepends a zeroed one on rx.
use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use event_manager::{EventManager, EventOps, EventSet, Events, MutEventSubscriber, SubscriberOps};
use virtio_queue::{Queue, QueueT};
use vm_memory::{Bytes, GuestMemoryMmap};
use vmm_sys_util::eventfd::EventFd;

use super::{DevicePause, Interrupt, VirtioDevice, QUEUE_SIZE, TYPE_NET, VIRTIO_F_VERSION_1};
use crate::machine::{Result, VmmError};

/// Length of the `virtio_net_hdr_v1` the guest prepends to every frame.
const VIRTIO_NET_HDR_LEN: usize = 12;
/// `VIRTIO_NET_F_MAC` — we provide the guest its MAC address via config space.
const VIRTIO_NET_F_MAC: u64 = 1 << 5;
/// Max Ethernet frame + virtio header (jumbo-safe upper bound).
const MAX_FRAME_LEN: usize = 65_562;
/// Bound on buffered receive frames when the guest has not posted RX buffers.
/// When full, the oldest frame is dropped (and logged) to cap memory use.
const RX_BACKLOG_MAX: usize = 64;

const RX_QUEUE_INDEX: usize = 0;
const TX_QUEUE_INDEX: usize = 1;

/// A virtio network device bridged to a host TAP interface.
pub struct Net {
    tap: Option<File>,
    mac: [u8; 6],
    queue_max_sizes: [u16; 2],
    rate_limit: Option<crate::config::RateLimit>,
    /// Snapshot pause handle (SPEC-1 FR-14); the worker captures its rx/tx cursors.
    pause: Option<DevicePause>,
}

impl Net {
    /// Create a net device backed by the already-opened TAP `tap`, advertising
    /// `mac` to the guest. `rate_limit` optionally caps tx throughput (SPEC-1 FR-28).
    pub fn new(tap: File, mac: [u8; 6], rate_limit: Option<crate::config::RateLimit>) -> Self {
        Self {
            tap: Some(tap),
            mac,
            queue_max_sizes: [QUEUE_SIZE, QUEUE_SIZE],
            rate_limit,
            pause: None,
        }
    }
}

impl VirtioDevice for Net {
    fn device_type(&self) -> u32 {
        TYPE_NET
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.queue_max_sizes
    }

    fn features(&self) -> u64 {
        VIRTIO_F_VERSION_1 | VIRTIO_NET_F_MAC
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // Config space: 6-byte MAC at offset 0.
        for (i, byte) in data.iter_mut().enumerate() {
            let idx = offset as usize + i;
            *byte = self.mac.get(idx).copied().unwrap_or(0);
        }
    }

    fn set_pause_handle(&mut self, pause: DevicePause) {
        self.pause = Some(pause);
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
                "net: expected rx and tx queues".to_string(),
            ));
        }
        // swap_remove the higher index first to keep indices valid.
        let tx_queue = queues.swap_remove(TX_QUEUE_INDEX);
        let rx_queue = queues.swap_remove(RX_QUEUE_INDEX);
        let tx_evt = queue_evts.swap_remove(TX_QUEUE_INDEX);
        let rx_evt = queue_evts.swap_remove(RX_QUEUE_INDEX);

        let tap = self
            .tap
            .take()
            .ok_or_else(|| VmmError::Device("net: already activated".to_string()))?;
        set_nonblocking(&tap)?;

        // Shared flag the subscriber sets after capturing its cursors, so the detached
        // epoll loop knows to stop (a snapshot froze the guest, SPEC-1 FR-14).
        let pause_done = Arc::new(AtomicBool::new(false));
        let worker = NetWorker {
            rx_queue,
            tx_queue,
            rx_evt,
            tx_evt,
            tap,
            mem,
            interrupt,
            rx_backlog: VecDeque::new(),
            limiter: crate::ratelimit::DeviceRateLimiter::from_config(
                self.rate_limit.take().as_ref(),
            ),
            pause: self.pause.take(),
            pause_done: pause_done.clone(),
        };

        let mut manager = EventManager::<NetWorker>::new()
            .map_err(|e| VmmError::Device(format!("net epoll: {e:?}")))?;
        manager.add_subscriber(worker);

        // Detached epoll loop; exits when the eventfds/tap are closed at teardown, or
        // when the worker has captured its cursors for a snapshot.
        std::thread::Builder::new()
            .name("mm-net".to_string())
            .spawn(move || loop {
                if manager.run().is_err() || pause_done.load(Ordering::Acquire) {
                    break;
                }
            })
            .map_err(VmmError::Io)?;
        Ok(())
    }
}

/// The epoll subscriber owning the net device's queues, TAP, and notify eventfds.
struct NetWorker {
    rx_queue: Queue,
    tx_queue: Queue,
    rx_evt: EventFd,
    tx_evt: EventFd,
    tap: File,
    mem: Arc<GuestMemoryMmap>,
    interrupt: Arc<Interrupt>,
    /// Frames (each already prefixed with its virtio-net header) received from the
    /// TAP while the guest had no RX buffers posted; drained FIFO when buffers
    /// become available.
    rx_backlog: VecDeque<Vec<u8>>,
    /// Optional tx throughput limiter (SPEC-1 FR-28).
    limiter: Option<crate::ratelimit::DeviceRateLimiter>,
    /// Snapshot pause handle; on its eventfd the worker captures rx/tx cursors.
    pause: Option<DevicePause>,
    /// Set after capturing, so the detached epoll loop stops.
    pause_done: Arc<AtomicBool>,
}

impl NetWorker {
    /// Drain the transmit queue: assemble each chain, strip the virtio-net header,
    /// and write the Ethernet frame to the TAP.
    fn process_tx(&mut self) -> Result<()> {
        let mut signalled = false;
        while let Some(chain) = self.tx_queue.pop_descriptor_chain(self.mem.clone()) {
            let head = chain.head_index();
            let mut frame = Vec::with_capacity(VIRTIO_NET_HDR_LEN + 1500);
            for desc in chain {
                let mut buf = vec![0u8; desc.len() as usize];
                self.mem
                    .read_slice(&mut buf, desc.addr())
                    .map_err(|e| VmmError::Device(format!("net tx read: {e}")))?;
                frame.extend_from_slice(&buf);
            }
            if frame.len() > VIRTIO_NET_HDR_LEN {
                // Rate limit (FR-28): one op + the Ethernet payload bytes. Throttling
                // briefly blocks this worker; the tx descriptors are kept (never
                // dropped) so no frames are lost.
                if let Some(l) = self.limiter.as_mut() {
                    let payload = (frame.len() - VIRTIO_NET_HDR_LEN) as u64;
                    l.wait_admit(1, payload, std::time::Duration::from_millis(200));
                }
                // Best-effort send; a full TAP drops the frame (Ethernet semantics).
                let _ = self.tap.write(&frame[VIRTIO_NET_HDR_LEN..]);
            }
            self.tx_queue
                .add_used(self.mem.as_ref(), head, 0)
                .map_err(|e| VmmError::Device(format!("net tx add_used: {e}")))?;
            signalled = true;
        }
        if signalled {
            self.interrupt.signal_used_queue()?;
        }
        Ok(())
    }

    /// Copy one fully-formed frame (already including its virtio-net header) into
    /// the next available guest RX chain. Returns `Ok(false)` if the guest has no
    /// RX buffer posted (so the caller can buffer the frame instead of dropping it).
    fn deliver_to_guest(&mut self, frame: &[u8]) -> Result<bool> {
        let Some(chain) = self.rx_queue.pop_descriptor_chain(self.mem.clone()) else {
            return Ok(false);
        };
        let head = chain.head_index();
        let mut copied = 0usize;
        for desc in chain {
            if copied >= frame.len() {
                break;
            }
            let want = std::cmp::min(desc.len() as usize, frame.len() - copied);
            self.mem
                .write_slice(&frame[copied..copied + want], desc.addr())
                .map_err(|e| VmmError::Device(format!("net rx write: {e}")))?;
            copied += want;
        }
        self.rx_queue
            .add_used(self.mem.as_ref(), head, copied as u32)
            .map_err(|e| VmmError::Device(format!("net rx add_used: {e}")))?;
        Ok(true)
    }

    /// Deliver as many backlogged frames as the guest now has buffers for, in FIFO
    /// order. Returns how many were delivered.
    fn drain_backlog(&mut self) -> Result<usize> {
        let mut delivered = 0;
        while let Some(frame) = self.rx_backlog.pop_front() {
            if self.deliver_to_guest(&frame)? {
                delivered += 1;
            } else {
                // No buffer yet: put it back at the front and stop (preserve order).
                self.rx_backlog.push_front(frame);
                break;
            }
        }
        Ok(delivered)
    }

    /// Buffer a frame for later delivery, bounding the backlog by dropping (and
    /// logging) the oldest frame when the limit is reached.
    fn enqueue_backlog(&mut self, frame: &[u8]) {
        if self.rx_backlog.len() >= RX_BACKLOG_MAX {
            self.rx_backlog.pop_front();
            tracing::warn!("net: rx backlog full ({RX_BACKLOG_MAX}); dropped oldest frame");
        }
        self.rx_backlog.push_back(frame.to_vec());
    }

    /// Pull frames from the TAP and deliver each into a receive chain (prepending a
    /// zeroed virtio-net header). Frames that arrive while the guest has no RX
    /// buffers are buffered in `rx_backlog` and delivered on the next RX
    /// notification rather than dropped.
    fn process_rx(&mut self) -> Result<()> {
        // First flush any backlog into newly-available buffers.
        let mut signalled = self.drain_backlog()? > 0;

        let mut buf = vec![0u8; MAX_FRAME_LEN];
        loop {
            let n = match self.tap.read(&mut buf[VIRTIO_NET_HDR_LEN..]) {
                Ok(0) => break,
                Ok(n) => n,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    tracing::warn!("net: tap read failed: {e}");
                    break;
                }
            };
            // Zero the virtio-net header; num_buffers (offset 10, LE u16) = 1.
            buf[..VIRTIO_NET_HDR_LEN].fill(0);
            buf[10] = 1;
            let total = VIRTIO_NET_HDR_LEN + n;
            let frame = &buf[..total];

            // Preserve ordering: only deliver directly when the backlog is empty;
            // otherwise enqueue so earlier frames are not overtaken.
            if self.rx_backlog.is_empty() && self.deliver_to_guest(frame)? {
                signalled = true;
            } else {
                self.enqueue_backlog(frame);
            }
        }

        if signalled {
            self.interrupt.signal_used_queue()?;
        }
        Ok(())
    }
}

impl MutEventSubscriber for NetWorker {
    fn init(&mut self, ops: &mut EventOps) {
        let _ = ops.add(Events::new(&self.tap, EventSet::IN));
        let _ = ops.add(Events::new(&self.tx_evt, EventSet::IN));
        let _ = ops.add(Events::new(&self.rx_evt, EventSet::IN));
        if let Some(p) = self.pause.as_ref() {
            let _ = ops.add(Events::new(&p.evt, EventSet::IN));
        }
    }

    fn process(&mut self, events: Events, _ops: &mut EventOps) {
        let fd = events.fd();
        if fd == self.tap.as_raw_fd() {
            if let Err(e) = self.process_rx() {
                tracing::error!("net: rx failed: {e}");
            }
        } else if fd == self.tx_evt.as_raw_fd() {
            let _ = self.tx_evt.read();
            if let Err(e) = self.process_tx() {
                tracing::error!("net: tx failed: {e}");
            }
        } else if fd == self.rx_evt.as_raw_fd() {
            // Guest added receive buffers; drain whatever the TAP has waiting.
            let _ = self.rx_evt.read();
            if let Err(e) = self.process_rx() {
                tracing::error!("net: rx (notify) failed: {e}");
            }
        } else if self.pause.as_ref().is_some_and(|p| fd == p.evt.as_raw_fd()) {
            // Pause: drain once and capture rx/tx cursors (the vCPUs are paused, so the
            // queues are stable). Split the borrows so the mutable drains don't overlap
            // the immutable `pause` borrow.
            if let Some(p) = self.pause.as_ref() {
                let _ = p.evt.read();
            }
            let _ = self.process_tx();
            let _ = self.process_rx();
            let cursors = vec![self.rx_queue.state().into(), self.tx_queue.state().into()];
            if let Some(p) = self.pause.as_ref() {
                if let Ok(mut slot) = p.slot.lock() {
                    *slot = Some(cursors);
                }
                if p.checkpoint.is_requested() {
                    // Running BRANCH (FR-16): park this epoll thread at the barrier; when
                    // released, `process` returns and the manager keeps serving events.
                    p.checkpoint.park();
                } else {
                    // Freeze (snapshot, FR-14): signal the detached loop to stop.
                    self.pause_done.store(true, Ordering::Release);
                }
            }
        }
    }
}

/// Put a file descriptor into non-blocking mode (for the epoll-driven TAP reads).
fn set_nonblocking(file: &File) -> Result<()> {
    let fd = file.as_raw_fd();
    // SAFETY: `fd` is a valid descriptor owned by `file`; fcntl reads/sets flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(VmmError::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: same fd; we only add O_NONBLOCK to the existing flag set.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(VmmError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use virtio_queue::mock::MockSplitQueue;
    use vm_memory::GuestAddress;

    use super::*;
    use crate::devices::Interrupt;

    #[test]
    fn config_reports_mac() {
        // A net device over a throwaway pipe-like file is awkward; test config
        // directly on a constructed device using /dev/null as a stand-in fd.
        let f = File::open("/dev/null").unwrap();
        let mac = [0x02, 0x00, 0x00, 0x12, 0x34, 0x56];
        let net = Net::new(f, mac, None);
        let mut cfg = [0u8; 6];
        net.read_config(0, &mut cfg);
        assert_eq!(cfg, mac);
        assert!(net.features() & VIRTIO_NET_F_MAC != 0);
    }

    /// Build a worker with empty (no available buffers) RX/TX queues.
    fn empty_worker() -> NetWorker {
        let mem = Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x100_0000)]).unwrap());
        let rx_queue = MockSplitQueue::new(mem.as_ref(), 16)
            .create_queue::<Queue>()
            .unwrap();
        let tx_queue = MockSplitQueue::new(mem.as_ref(), 16)
            .create_queue::<Queue>()
            .unwrap();
        let interrupt = Arc::new(Interrupt::new(EventFd::new(0).unwrap()));
        NetWorker {
            rx_queue,
            tx_queue,
            rx_evt: EventFd::new(0).unwrap(),
            tx_evt: EventFd::new(0).unwrap(),
            tap: File::open("/dev/null").unwrap(),
            mem,
            interrupt,
            rx_backlog: VecDeque::new(),
            limiter: None,
            pause: None,
            pause_done: Arc::new(AtomicBool::new(false)),
        }
    }

    #[test]
    fn frames_are_buffered_when_no_guest_buffer() {
        let mut worker = empty_worker();
        // No posted RX buffers -> delivery reports "not delivered".
        assert!(!worker.deliver_to_guest(&[0u8; 64]).unwrap());
        worker.enqueue_backlog(&[1u8; 64]);
        assert_eq!(worker.rx_backlog.len(), 1);
        // Draining with still no buffers leaves the frame queued (not dropped).
        assert_eq!(worker.drain_backlog().unwrap(), 0);
        assert_eq!(worker.rx_backlog.len(), 1);
    }

    #[test]
    fn backlog_is_bounded_and_drops_oldest() {
        let mut worker = empty_worker();
        for i in 0..(RX_BACKLOG_MAX + 5) {
            worker.enqueue_backlog(&[(i % 256) as u8; 32]);
        }
        assert_eq!(
            worker.rx_backlog.len(),
            RX_BACKLOG_MAX,
            "backlog is capped at RX_BACKLOG_MAX"
        );
    }
}
