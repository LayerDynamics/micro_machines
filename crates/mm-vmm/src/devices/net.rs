//! virtio-net bound to a host TAP device (SPEC-1 FR-3, FR-10).
//!
//! Transmit is driven by guest queue notifications; receive is driven by the TAP
//! becoming readable. Because those two readiness sources are independent, the
//! worker runs an [`event_manager`] epoll loop watching the TAP fd and the tx/rx
//! notify eventfds — this is the one device whose processing genuinely needs an
//! event loop rather than a single blocking wait. The guest speaks virtio-net
//! (frames prefixed by a 12-byte `virtio_net_hdr`); the TAP carries raw Ethernet,
//! so the worker strips the header on tx and prepends a zeroed one on rx.
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use event_manager::{EventManager, EventOps, EventSet, Events, MutEventSubscriber, SubscriberOps};
use virtio_queue::{Queue, QueueT};
use vm_memory::{Bytes, GuestMemoryMmap};
use vmm_sys_util::eventfd::EventFd;

use super::{Interrupt, VirtioDevice, QUEUE_SIZE, TYPE_NET, VIRTIO_F_VERSION_1};
use crate::machine::{Result, VmmError};

/// Length of the `virtio_net_hdr_v1` the guest prepends to every frame.
const VIRTIO_NET_HDR_LEN: usize = 12;
/// `VIRTIO_NET_F_MAC` — we provide the guest its MAC address via config space.
const VIRTIO_NET_F_MAC: u64 = 1 << 5;
/// Max Ethernet frame + virtio header (jumbo-safe upper bound).
const MAX_FRAME_LEN: usize = 65_562;

const RX_QUEUE_INDEX: usize = 0;
const TX_QUEUE_INDEX: usize = 1;

/// A virtio network device bridged to a host TAP interface.
pub struct Net {
    tap: Option<File>,
    mac: [u8; 6],
    queue_max_sizes: [u16; 2],
}

impl Net {
    /// Create a net device backed by the already-opened TAP `tap`, advertising
    /// `mac` to the guest.
    pub fn new(tap: File, mac: [u8; 6]) -> Self {
        Self {
            tap: Some(tap),
            mac,
            queue_max_sizes: [QUEUE_SIZE, QUEUE_SIZE],
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

        let worker = NetWorker {
            rx_queue,
            tx_queue,
            rx_evt,
            tx_evt,
            tap,
            mem,
            interrupt,
        };

        let mut manager = EventManager::<NetWorker>::new()
            .map_err(|e| VmmError::Device(format!("net epoll: {e:?}")))?;
        manager.add_subscriber(worker);

        // Detached epoll loop; exits when the eventfds/tap are closed at teardown.
        std::thread::Builder::new()
            .name("mm-net".to_string())
            .spawn(move || loop {
                if manager.run().is_err() {
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

    /// Pull frames from the TAP and deliver each into a receive chain, prepending
    /// a zeroed virtio-net header.
    fn process_rx(&mut self) -> Result<()> {
        let mut signalled = false;
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

            let Some(chain) = self.rx_queue.pop_descriptor_chain(self.mem.clone()) else {
                // No guest buffer available: drop (M1 has no rx backlog buffering).
                break;
            };
            let head = chain.head_index();
            let mut copied = 0usize;
            for desc in chain {
                if copied >= total {
                    break;
                }
                let want = std::cmp::min(desc.len() as usize, total - copied);
                self.mem
                    .write_slice(&buf[copied..copied + want], desc.addr())
                    .map_err(|e| VmmError::Device(format!("net rx write: {e}")))?;
                copied += want;
            }
            self.rx_queue
                .add_used(self.mem.as_ref(), head, copied as u32)
                .map_err(|e| VmmError::Device(format!("net rx add_used: {e}")))?;
            signalled = true;
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
    use super::*;

    #[test]
    fn config_reports_mac() {
        // A net device over a throwaway pipe-like file is awkward; test config
        // directly on a constructed device using /dev/null as a stand-in fd.
        let f = File::open("/dev/null").unwrap();
        let mac = [0x02, 0x00, 0x00, 0x12, 0x34, 0x56];
        let net = Net::new(f, mac);
        let mut cfg = [0u8; 6];
        net.read_config(0, &mut cfg);
        assert_eq!(cfg, mac);
        assert!(net.features() & VIRTIO_NET_F_MAC != 0);
    }
}
