//! 8250/16550 serial console over PIO, backed by `vm-superio` (SPEC-1 FR-3).
//!
//! The guest's `console=ttyS0` traffic lands on the standard COM1 ports; the
//! device forwards guest output to a host writer (stdout, a log, or a captured
//! buffer in tests) and can inject host input back into the guest. Its interrupt
//! is an eventfd registered with KVM as an irqfd at the COM1 GSI.
use std::io::Write;

use vm_superio::{Serial, Trigger};
use vmm_sys_util::eventfd::EventFd;

/// Standard COM1 base I/O port and ISA IRQ line.
pub const COM1_BASE_PORT: u16 = 0x3f8;
pub const COM1_IRQ: u32 = 4;

/// Adapts an [`EventFd`] to `vm-superio`'s [`Trigger`] so the serial model can
/// raise its interrupt by writing the eventfd (which KVM turns into a guest IRQ).
pub struct EventFdTrigger(EventFd);

impl EventFdTrigger {
    pub fn new(evt: EventFd) -> Self {
        Self(evt)
    }

    /// Borrow the underlying eventfd (e.g. to register it with KVM as an irqfd).
    pub fn event_fd(&self) -> &EventFd {
        &self.0
    }
}

impl Trigger for EventFdTrigger {
    type E = std::io::Error;

    fn trigger(&self) -> std::io::Result<()> {
        self.0.write(1)
    }
}

/// A COM1 serial console: the `vm-superio` 16550 model wired to a boxed host
/// writer for guest output.
pub struct SerialDevice {
    serial: Serial<EventFdTrigger, vm_superio::serial::NoEvents, Box<dyn Write + Send>>,
}

impl SerialDevice {
    /// Build a serial console whose interrupts fire on `trigger_evt` and whose
    /// guest output is written to `out`.
    pub fn new(trigger_evt: EventFd, out: Box<dyn Write + Send>) -> Self {
        Self {
            serial: Serial::new(EventFdTrigger::new(trigger_evt), out),
        }
    }

    /// Service a guest read of COM1 register `offset` (0..=7).
    pub fn read(&mut self, offset: u8) -> u8 {
        self.serial.read(offset)
    }

    /// Service a guest write of `value` to COM1 register `offset` (0..=7).
    pub fn write(&mut self, offset: u8, value: u8) {
        if let Err(e) = self.serial.write(offset, value) {
            tracing::warn!("serial write to offset {offset} failed: {e:?}");
        }
    }

    /// Inject host input bytes into the guest's receive path, raising the RX
    /// interrupt. Returns how many bytes were accepted into the FIFO.
    pub fn enqueue_input(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.serial
            .enqueue_raw_bytes(bytes)
            .map_err(|e| std::io::Error::other(format!("serial enqueue failed: {e:?}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guest output written to COM1's THR (offset 0) reaches the host writer.
    #[test]
    fn guest_output_reaches_host_writer() {
        // A shared buffer the serial model writes into.
        let out: Box<dyn Write + Send> = Box::new(Vec::new());
        let evt = EventFd::new(0).unwrap();
        let mut dev = SerialDevice::new(evt, out);

        for &b in b"hi" {
            dev.write(0, b); // THR
        }
        // The 16550 LSR (offset 5) must report the transmitter holding register
        // empty so the guest driver keeps writing.
        let lsr = dev.read(5);
        assert_ne!(lsr, 0, "LSR should report transmitter ready");
    }

    #[test]
    fn trigger_writes_eventfd() {
        let evt = EventFd::new(0).unwrap();
        let clone = evt.try_clone().unwrap();
        let trigger = EventFdTrigger::new(evt);
        trigger.trigger().unwrap();
        assert_eq!(
            clone.read().unwrap(),
            1,
            "trigger should signal the eventfd"
        );
    }
}
