//! virtio-mmio device model + serial console (SPEC-1 FR-3).
//!
//! MicroMachines exposes its guests a small, modern device set over the
//! **virtio-mmio** transport (no PCI): a block device for the rootfs, a net
//! device bound to a host TAP, a vsock channel (M1 uses it only for the guest's
//! "ready" signal; full host<->guest exec is M3), and an 8250 serial console.
//!
//! Architecture:
//! * [`MmioTransport`] implements the virtio-mmio register interface a guest
//!   driver programs (features, queue addresses, status). When the driver sets
//!   `DRIVER_OK`, the transport hands each device its configured [`Queue`]s,
//!   notify eventfds, guest memory, and interrupt line via [`VirtioDevice::activate`].
//! * Each device runs its own worker (a thread blocking on its queue-notify
//!   eventfd, or — for net — an [`event_manager`] epoll loop over the TAP + tx
//!   notify). Queue *processing* therefore happens off the vCPU threads; the only
//!   work on a vCPU thread is the cheap MMIO register write that pokes the eventfd.
//! * [`Bus`] maps guest MMIO ranges (and the serial PIO ports) to devices and
//!   implements [`IoDispatch`] so the vCPU run loop can route exits to it.
mod balloon;
mod block;
mod net;
mod serial;
mod vsock;

pub use balloon::Balloon;
pub use block::Block;
pub use net::Net;
pub use serial::{EventFdTrigger, SerialDevice, COM1_BASE_PORT, COM1_IRQ};
pub use vsock::{Vsock, VsockReady};

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use virtio_queue::{Queue, QueueT};
use vm_memory::GuestMemoryMmap;
use vmm_sys_util::eventfd::EventFd;

use crate::machine::{IoDispatch, Result, VmmError};

// --- virtio device type ids (virtio spec §5). ---
pub const TYPE_NET: u32 = 1;
pub const TYPE_BLOCK: u32 = 2;
pub const TYPE_BALLOON: u32 = 5;
pub const TYPE_VSOCK: u32 = 19;

/// `VIRTIO_F_VERSION_1` — every device negotiates the modern (1.0) interface.
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;

// --- virtio-mmio register offsets (virtio spec §4.2.2, MMIO v2). ---
const REG_MAGIC: u64 = 0x000;
const REG_VERSION: u64 = 0x004;
const REG_DEVICE_ID: u64 = 0x008;
const REG_VENDOR_ID: u64 = 0x00c;
const REG_DEVICE_FEATURES: u64 = 0x010;
const REG_DEVICE_FEATURES_SEL: u64 = 0x014;
const REG_DRIVER_FEATURES: u64 = 0x020;
const REG_DRIVER_FEATURES_SEL: u64 = 0x024;
const REG_QUEUE_SEL: u64 = 0x030;
const REG_QUEUE_NUM_MAX: u64 = 0x034;
const REG_QUEUE_NUM: u64 = 0x038;
const REG_QUEUE_READY: u64 = 0x044;
const REG_QUEUE_NOTIFY: u64 = 0x050;
const REG_INTERRUPT_STATUS: u64 = 0x060;
const REG_INTERRUPT_ACK: u64 = 0x064;
const REG_STATUS: u64 = 0x070;
const REG_QUEUE_DESC_LOW: u64 = 0x080;
const REG_QUEUE_DESC_HIGH: u64 = 0x084;
const REG_QUEUE_AVAIL_LOW: u64 = 0x090;
const REG_QUEUE_AVAIL_HIGH: u64 = 0x094;
const REG_QUEUE_USED_LOW: u64 = 0x0a0;
const REG_QUEUE_USED_HIGH: u64 = 0x0a4;
const REG_CONFIG_GENERATION: u64 = 0x0fc;
/// Device-specific configuration space begins here.
const REG_CONFIG_SPACE: u64 = 0x100;

const MMIO_MAGIC_VALUE: u32 = 0x7472_6976; // "virt", little-endian
const MMIO_VERSION: u32 = 2;
const MMIO_VENDOR_ID: u32 = 0x4d4d_0000; // 'MM\0\0'

// --- device status bits (virtio spec §2.1). ---
const STATUS_DRIVER_OK: u32 = 0x04;
const STATUS_FAILED: u32 = 0x80;

/// Interrupt-status bit: a used ring was updated.
const VIRTIO_MMIO_INT_VRING: u32 = 0x01;

/// Default per-device virtqueue size.
pub const QUEUE_SIZE: u16 = 256;

/// The guest-visible interrupt line for a virtio device: an eventfd registered
/// with KVM as an irqfd, plus the virtio interrupt-status register the guest
/// reads/acks. Cloned (via `Arc`) into each device's worker so it can raise an
/// interrupt when it adds buffers to a used ring.
pub struct Interrupt {
    evt: EventFd,
    status: AtomicU32,
}

impl Interrupt {
    /// Wrap an eventfd that has already been registered with KVM at a GSI.
    pub fn new(evt: EventFd) -> Self {
        Self {
            evt,
            status: AtomicU32::new(0),
        }
    }

    /// Raise a "used ring updated" interrupt to the guest.
    pub fn signal_used_queue(&self) -> Result<()> {
        self.status
            .fetch_or(VIRTIO_MMIO_INT_VRING, Ordering::SeqCst);
        self.evt.write(1).map_err(VmmError::Io)
    }

    /// Current interrupt-status register value (guest read of `InterruptStatus`).
    fn status(&self) -> u32 {
        self.status.load(Ordering::SeqCst)
    }

    /// Clear the bits the guest acked (`InterruptACK` write).
    fn ack(&self, value: u32) {
        self.status.fetch_and(!value, Ordering::SeqCst);
    }
}

/// A virtio device backend. The transport drives the register protocol and hands
/// the device its resources at [`activate`](VirtioDevice::activate); the device
/// owns queue processing from then on.
pub trait VirtioDevice: Send {
    /// virtio device type id (e.g. [`TYPE_BLOCK`]).
    fn device_type(&self) -> u32;
    /// Maximum size of each virtqueue, one entry per queue.
    fn queue_max_sizes(&self) -> &[u16];
    /// The 64-bit feature bits this device offers.
    fn features(&self) -> u64;
    /// Read device-specific configuration space at `offset` into `data`.
    fn read_config(&self, offset: u64, data: &mut [u8]);
    /// Write device-specific configuration space (default: read-only config).
    fn write_config(&mut self, _offset: u64, _data: &[u8]) {}
    /// Take ownership of the configured queues + resources and start processing.
    fn activate(
        &mut self,
        mem: Arc<GuestMemoryMmap>,
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
        interrupt: Arc<Interrupt>,
    ) -> Result<()>;
}

/// The virtio-mmio transport for a single device: it implements the register
/// interface the guest driver programs and activates the device on `DRIVER_OK`.
pub struct MmioTransport {
    device: Box<dyn VirtioDevice>,
    mem: Arc<GuestMemoryMmap>,
    interrupt: Arc<Interrupt>,
    queues: Vec<Queue>,
    queue_max_sizes: Vec<u16>,
    queue_evts: Vec<EventFd>,
    queue_select: u32,
    device_features_select: u32,
    driver_features_select: u32,
    driver_features: u64,
    status: u32,
    activated: bool,
}

impl MmioTransport {
    /// Build a transport for `device`, allocating one (blocking) notify eventfd
    /// and one [`Queue`] per virtqueue.
    pub fn new(
        device: Box<dyn VirtioDevice>,
        mem: Arc<GuestMemoryMmap>,
        interrupt: Arc<Interrupt>,
    ) -> Result<Self> {
        let queue_max_sizes = device.queue_max_sizes().to_vec();
        let mut queues = Vec::with_capacity(queue_max_sizes.len());
        for &size in &queue_max_sizes {
            queues
                .push(Queue::new(size).map_err(|e| VmmError::Device(format!("queue init: {e}")))?);
        }
        let mut queue_evts = Vec::with_capacity(queue_max_sizes.len());
        for _ in 0..queue_max_sizes.len() {
            // Blocking eventfd: device workers wait on it with a blocking read.
            queue_evts.push(EventFd::new(0).map_err(VmmError::Io)?);
        }
        Ok(Self {
            device,
            mem,
            interrupt,
            queues,
            queue_max_sizes,
            queue_evts,
            queue_select: 0,
            device_features_select: 0,
            driver_features_select: 0,
            driver_features: 0,
            status: 0,
            activated: false,
        })
    }

    fn selected_queue_mut(&mut self) -> Option<&mut Queue> {
        self.queues.get_mut(self.queue_select as usize)
    }

    /// Handle a guest MMIO read of this device's register window.
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        if offset >= REG_CONFIG_SPACE {
            self.device.read_config(offset - REG_CONFIG_SPACE, data);
            return;
        }
        if data.len() != 4 {
            return;
        }
        let value = match offset {
            REG_MAGIC => MMIO_MAGIC_VALUE,
            REG_VERSION => MMIO_VERSION,
            REG_DEVICE_ID => self.device.device_type(),
            REG_VENDOR_ID => MMIO_VENDOR_ID,
            REG_DEVICE_FEATURES => {
                let features = self.device.features();
                if self.device_features_select == 1 {
                    (features >> 32) as u32
                } else {
                    features as u32
                }
            }
            REG_QUEUE_NUM_MAX => self
                .queue_max_sizes
                .get(self.queue_select as usize)
                .map(|&s| u32::from(s))
                .unwrap_or(0),
            REG_QUEUE_READY => self
                .queues
                .get(self.queue_select as usize)
                .map(|q| u32::from(q.ready()))
                .unwrap_or(0),
            REG_INTERRUPT_STATUS => self.interrupt.status(),
            REG_STATUS => self.status,
            REG_CONFIG_GENERATION => 0,
            _ => 0,
        };
        data.copy_from_slice(&value.to_le_bytes());
    }

    /// Handle a guest MMIO write to this device's register window.
    fn write(&mut self, offset: u64, data: &[u8]) {
        if offset >= REG_CONFIG_SPACE {
            self.device.write_config(offset - REG_CONFIG_SPACE, data);
            return;
        }
        if data.len() != 4 {
            return;
        }
        let value = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        match offset {
            REG_DEVICE_FEATURES_SEL => self.device_features_select = value,
            REG_DRIVER_FEATURES => {
                let shift = if self.driver_features_select == 1 {
                    32
                } else {
                    0
                };
                let mask = 0xffff_ffffu64 << shift;
                self.driver_features = (self.driver_features & !mask) | (u64::from(value) << shift);
            }
            REG_DRIVER_FEATURES_SEL => self.driver_features_select = value,
            REG_QUEUE_SEL => self.queue_select = value,
            REG_QUEUE_NUM => {
                if let Some(q) = self.selected_queue_mut() {
                    q.set_size(value as u16);
                }
            }
            REG_QUEUE_READY => {
                if let Some(q) = self.selected_queue_mut() {
                    q.set_ready(value == 1);
                }
            }
            REG_QUEUE_NOTIFY => self.notify(value),
            REG_INTERRUPT_ACK => self.interrupt.ack(value),
            REG_STATUS => self.set_status(value),
            REG_QUEUE_DESC_LOW => {
                if let Some(q) = self.selected_queue_mut() {
                    q.set_desc_table_address(Some(value), None);
                }
            }
            REG_QUEUE_DESC_HIGH => {
                if let Some(q) = self.selected_queue_mut() {
                    q.set_desc_table_address(None, Some(value));
                }
            }
            REG_QUEUE_AVAIL_LOW => {
                if let Some(q) = self.selected_queue_mut() {
                    q.set_avail_ring_address(Some(value), None);
                }
            }
            REG_QUEUE_AVAIL_HIGH => {
                if let Some(q) = self.selected_queue_mut() {
                    q.set_avail_ring_address(None, Some(value));
                }
            }
            REG_QUEUE_USED_LOW => {
                if let Some(q) = self.selected_queue_mut() {
                    q.set_used_ring_address(Some(value), None);
                }
            }
            REG_QUEUE_USED_HIGH => {
                if let Some(q) = self.selected_queue_mut() {
                    q.set_used_ring_address(None, Some(value));
                }
            }
            _ => {}
        }
    }

    /// Poke the notify eventfd for `queue_index` so the device worker processes it.
    fn notify(&self, queue_index: u32) {
        if let Some(evt) = self.queue_evts.get(queue_index as usize) {
            if let Err(e) = evt.write(1) {
                tracing::error!("failed to notify queue {queue_index}: {e}");
            }
        }
    }

    /// Apply a guest write of the status register, activating the device when the
    /// driver signals `DRIVER_OK`.
    fn set_status(&mut self, value: u32) {
        if value == 0 {
            // Device reset: drop activation state. Re-activation re-runs the driver
            // handshake (not exercised in M1's one-shot boot, but kept correct).
            self.status = 0;
            self.activated = false;
            return;
        }
        self.status = value;
        if value & STATUS_DRIVER_OK != 0 && !self.activated {
            if let Err(e) = self.activate() {
                tracing::error!("device activation failed: {e}");
                self.status |= STATUS_FAILED;
            } else {
                self.activated = true;
            }
        }
    }

    /// Move the configured queues + cloned notify eventfds into the device and
    /// start its worker.
    fn activate(&mut self) -> Result<()> {
        let queues = std::mem::take(&mut self.queues);
        let mut device_evts = Vec::with_capacity(self.queue_evts.len());
        for evt in &self.queue_evts {
            device_evts.push(evt.try_clone().map_err(VmmError::Io)?);
        }
        self.device.activate(
            self.mem.clone(),
            queues,
            device_evts,
            self.interrupt.clone(),
        )
    }
}

/// One device's MMIO window on the guest physical bus.
struct MmioRange {
    base: u64,
    size: u64,
    transport: Arc<Mutex<MmioTransport>>,
}

/// Routes guest I/O exits to the right device: MMIO ranges to virtio transports,
/// and the COM1 port range to the serial console.
pub struct Bus {
    mmio: Vec<MmioRange>,
    serial: Option<Arc<Mutex<SerialDevice>>>,
}

impl Default for Bus {
    fn default() -> Self {
        Self::new()
    }
}

impl Bus {
    pub fn new() -> Self {
        Self {
            mmio: Vec::new(),
            serial: None,
        }
    }

    /// Map a virtio-mmio device into the guest physical address space.
    pub fn add_mmio_device(&mut self, base: u64, size: u64, transport: Arc<Mutex<MmioTransport>>) {
        self.mmio.push(MmioRange {
            base,
            size,
            transport,
        });
    }

    /// Install the serial console handling the COM1 PIO ports.
    pub fn set_serial(&mut self, serial: Arc<Mutex<SerialDevice>>) {
        self.serial = Some(serial);
    }

    fn mmio_range(&self, addr: u64) -> Option<&MmioRange> {
        self.mmio
            .iter()
            .find(|r| addr >= r.base && addr < r.base + r.size)
    }
}

impl IoDispatch for Bus {
    fn pio_read(&self, port: u16, data: &mut [u8]) {
        if let Some(serial) = &self.serial {
            if (COM1_BASE_PORT..COM1_BASE_PORT + 8).contains(&port) && data.len() == 1 {
                data[0] = serial
                    .lock()
                    .expect("serial mutex")
                    .read((port - COM1_BASE_PORT) as u8);
                return;
            }
        }
        // Unmapped port: emulate an open bus (all ones), as real hardware does for
        // I/O with no device. This makes the guest's legacy probes — notably the
        // i8042 PS/2 controller at 0x60/0x64 — fail *fast* (Linux reads 0xff, flushes
        // the phantom buffer, and reports "No controller found") instead of
        // busy-waiting on a status bit that never sets. That i8042 timeout alone
        // otherwise stalls the boot ~0.6s (NFR-P1). Returning 0x00 (the previous
        // behavior) is what triggered the stall.
        for b in data.iter_mut() {
            *b = 0xff;
        }
    }

    fn pio_write(&self, port: u16, data: &[u8]) {
        if let Some(serial) = &self.serial {
            if (COM1_BASE_PORT..COM1_BASE_PORT + 8).contains(&port) && data.len() == 1 {
                serial
                    .lock()
                    .expect("serial mutex")
                    .write((port - COM1_BASE_PORT) as u8, data[0]);
            }
        }
    }

    fn mmio_read(&self, addr: u64, data: &mut [u8]) {
        if let Some(range) = self.mmio_range(addr) {
            range
                .transport
                .lock()
                .expect("transport mutex")
                .read(addr - range.base, data);
        }
    }

    fn mmio_write(&self, addr: u64, data: &[u8]) {
        if let Some(range) = self.mmio_range(addr) {
            range
                .transport
                .lock()
                .expect("transport mutex")
                .write(addr - range.base, data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::IoDispatch;

    #[test]
    fn unmapped_pio_reads_as_open_bus() {
        // No serial, no devices: every port is unmapped and must read all-ones, so
        // legacy probes (e.g. the i8042 status port 0x64) fail fast instead of
        // busy-waiting on a status bit that never sets.
        let bus = Bus::new();
        let mut status = [0u8; 1];
        bus.pio_read(0x64, &mut status);
        assert_eq!(status, [0xff], "i8042 status port must read as open bus");
        let mut wide = [0u8; 4];
        bus.pio_read(0x0cf8, &mut wide);
        assert_eq!(wide, [0xff; 4], "wide unmapped read must be all-ones");
    }
}
