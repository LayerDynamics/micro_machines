//! virtio-vsock — M1 scope: carry the guest's boot "ready" signal (SPEC-1 FR-3).
//!
//! The full host<->guest vsock exec channel (used by Sandbox Mode) is M3. In M1
//! the device exists for one job: let `mm-init` tell the VMM it has reached
//! userspace. The guest opens the configured boot port and writes; the device
//! treats any transmit-queue activity as the readiness edge, sets a flag, and
//! signals an eventfd the VMM's boot path waits on. Buffers are returned to the
//! guest via the used ring so the driver does not stall.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use virtio_queue::{Queue, QueueT};
use vm_memory::GuestMemoryMmap;
use vmm_sys_util::eventfd::EventFd;

use super::{Interrupt, VirtioDevice, QUEUE_SIZE, TYPE_VSOCK, VIRTIO_F_VERSION_1};
use crate::machine::{Result, VmmError};

/// Index of the guest-to-host (transmit) virtqueue in a virtio-vsock device.
const TX_QUEUE_INDEX: usize = 1;

/// The readiness signal shared between the vsock worker and the VMM boot path.
pub struct VsockReady {
    flag: AtomicBool,
    evt: EventFd,
}

impl VsockReady {
    fn new() -> Result<Self> {
        Ok(Self {
            flag: AtomicBool::new(false),
            // Non-blocking: the boot path only `poll()`s this fd, never blocking-reads
            // it, so a reader (or the unit test) checking an unsignalled fd gets
            // `WouldBlock` instead of hanging.
            evt: EventFd::new(libc::EFD_NONBLOCK).map_err(VmmError::Io)?,
        })
    }

    /// Whether the guest has signalled readiness.
    pub fn is_ready(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// The eventfd that is written once when the guest first signals readiness;
    /// the boot path polls it with a timeout.
    pub fn event_fd(&self) -> &EventFd {
        &self.evt
    }

    fn mark_ready(&self) {
        // Only signal the eventfd on the first transition.
        if !self.flag.swap(true, Ordering::SeqCst) {
            let _ = self.evt.write(1);
        }
    }
}

/// virtio-vsock device. Holds the readiness signal and (after activation) the
/// worker draining the transmit queue.
pub struct Vsock {
    cid: u64,
    ready: Arc<VsockReady>,
    queue_max_sizes: [u16; 3],
}

impl Vsock {
    /// Create a vsock device with guest context id `cid`.
    pub fn new(cid: u64) -> Result<Self> {
        Ok(Self {
            cid,
            ready: Arc::new(VsockReady::new()?),
            // rx, tx, event queues.
            queue_max_sizes: [QUEUE_SIZE, QUEUE_SIZE, QUEUE_SIZE],
        })
    }

    /// Handle to the readiness signal, shared with the VMM boot path.
    pub fn ready_signal(&self) -> Arc<VsockReady> {
        self.ready.clone()
    }
}

impl VirtioDevice for Vsock {
    fn device_type(&self) -> u32 {
        TYPE_VSOCK
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &self.queue_max_sizes
    }

    fn features(&self) -> u64 {
        VIRTIO_F_VERSION_1
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // Config space: guest_cid (u64, LE) at offset 0.
        let cid = self.cid.to_le_bytes();
        for (i, byte) in data.iter_mut().enumerate() {
            let idx = offset as usize + i;
            *byte = cid.get(idx).copied().unwrap_or(0);
        }
    }

    fn activate(
        &mut self,
        mem: Arc<GuestMemoryMmap>,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
        interrupt: Arc<Interrupt>,
    ) -> Result<()> {
        if queues.len() <= TX_QUEUE_INDEX {
            return Err(VmmError::Device("vsock: missing tx queue".to_string()));
        }
        // We only need the transmit queue + its eventfd for the readiness signal.
        let tx_queue = queues.swap_remove(TX_QUEUE_INDEX);
        let tx_evt = queue_evts.swap_remove(TX_QUEUE_INDEX);
        let ready = self.ready.clone();

        // Detached worker; lives as long as its notify eventfd stays open.
        std::thread::Builder::new()
            .name("mm-vsock".to_string())
            .spawn(move || vsock_worker(tx_queue, tx_evt, mem, interrupt, ready))
            .map_err(VmmError::Io)?;
        Ok(())
    }
}

/// Worker: on every transmit notification, drain the queue (returning buffers via
/// the used ring) and mark the guest ready.
fn vsock_worker(
    mut tx_queue: Queue,
    tx_evt: EventFd,
    mem: Arc<GuestMemoryMmap>,
    interrupt: Arc<Interrupt>,
    ready: Arc<VsockReady>,
) {
    loop {
        if tx_evt.read().is_err() {
            break;
        }
        if let Err(e) = drain_tx(&mut tx_queue, &mem, &interrupt) {
            tracing::error!("vsock: tx drain failed: {e}");
        }
        ready.mark_ready();
    }
}

/// Consume every available transmit chain and return it to the guest. The vsock
/// payload itself is not interpreted in M1 — its arrival is the readiness edge.
fn drain_tx(queue: &mut Queue, mem: &Arc<GuestMemoryMmap>, interrupt: &Interrupt) -> Result<()> {
    let mut signalled = false;
    while let Some(chain) = queue.pop_descriptor_chain(mem.clone()) {
        let head = chain.head_index();
        queue
            .add_used(mem.as_ref(), head, 0)
            .map_err(|e| VmmError::Device(format!("vsock add_used: {e}")))?;
        signalled = true;
    }
    if signalled {
        interrupt.signal_used_queue()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_reports_cid() {
        let vsock = Vsock::new(42).unwrap();
        let mut cfg = [0u8; 8];
        vsock.read_config(0, &mut cfg);
        assert_eq!(u64::from_le_bytes(cfg), 42);
    }

    #[test]
    fn ready_signal_edges_once() {
        let ready = VsockReady::new().unwrap();
        assert!(!ready.is_ready());
        ready.mark_ready();
        assert!(ready.is_ready());
        assert_eq!(ready.event_fd().read().unwrap(), 1);
        // A second mark must not write the eventfd again.
        ready.mark_ready();
        assert!(ready.event_fd().read().is_err(), "no second signal");
    }
}
