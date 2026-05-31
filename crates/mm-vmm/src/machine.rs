//! KVM machine: device-independent VM setup — the `/dev/kvm` handle, guest RAM,
//! the in-kernel interrupt controller + PIT, and vCPU creation (SPEC-1 FR-1).
//!
//! This module owns everything that does not depend on the concrete device set:
//! it builds the VM, maps guest memory into KVM, and constructs (but does not yet
//! run) the vCPUs. Kernel loading lives in [`crate::boot`], the device model in
//! [`crate::devices`], and the end-to-end [`Machine::boot`] orchestration is added
//! in Task 8.
use std::sync::Arc;

use kvm_bindings::{kvm_pit_config, kvm_userspace_memory_region};
use kvm_ioctls::{Kvm, VmFd};
use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

use crate::config::{ConfigError, VmConfig};
use crate::vcpu::Vcpu;

/// Start of the 32-bit MMIO hole on x86: guest RAM is split around it so device
/// BARs and the LAPIC/IOAPIC windows are never backed by RAM (matches the
/// conventional PC memory map).
const MMIO_GAP_START: u64 = 0xc000_0000; // 3 GiB
/// Where RAM resumes above the 4 GiB boundary when a guest is given > 3 GiB.
const RAM_64BIT_START: u64 = 0x1_0000_0000; // 4 GiB

/// Errors from VMM setup and the run loop (SPEC-1 §3.2).
#[derive(Debug, thiserror::Error)]
pub enum VmmError {
    #[error("invalid configuration: {0}")]
    Config(#[from] ConfigError),
    #[error("kvm ioctl failed: {0}")]
    Kvm(#[from] kvm_ioctls::Error),
    #[error("guest memory setup failed: {0}")]
    Memory(String),
    #[error("kernel load failed: {0}")]
    KernelLoad(String),
    #[error("vcpu setup failed: {0}")]
    Vcpu(String),
    #[error("device error: {0}")]
    Device(String),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("timed out waiting for the guest ready signal")]
    ReadyTimeout,
}

/// Crate-internal result alias.
pub type Result<T> = std::result::Result<T, VmmError>;

/// The dispatch seam between a running vCPU and the device model. The vCPU run
/// loop ([`Vcpu::run`]) translates KVM port-I/O and MMIO exits into these calls;
/// the device [`Bus`](crate::devices) implements the trait. Defining it here keeps
/// the vCPU loop independent of the concrete devices (which arrive in Task 7).
pub trait IoDispatch: Send + Sync {
    /// Serve a guest `IN` from an I/O port into `data`.
    fn pio_read(&self, port: u16, data: &mut [u8]);
    /// Serve a guest `OUT` of `data` to an I/O port.
    fn pio_write(&self, port: u16, data: &[u8]);
    /// Serve a guest MMIO read at `addr` into `data`.
    fn mmio_read(&self, addr: u64, data: &mut [u8]);
    /// Serve a guest MMIO write of `data` at `addr`.
    fn mmio_write(&self, addr: u64, data: &[u8]);
}

/// A constructed (not yet booted) microVM: the KVM/VM handles, mapped guest RAM,
/// and the vCPUs. [`crate::boot`] loads a kernel into `guest_memory`, and Task 8's
/// orchestration configures the vCPUs and runs them.
pub struct Machine {
    kvm: Kvm,
    vm: Arc<VmFd>,
    guest_memory: Arc<GuestMemoryMmap>,
    vcpus: Vec<Vcpu>,
    config: VmConfig,
}

impl Machine {
    /// Create the VM: validate the config, open `/dev/kvm`, allocate and map guest
    /// RAM, set up the in-kernel IRQ chip + PIT, and create the vCPUs.
    pub fn new(config: &VmConfig) -> Result<Self> {
        config.validate()?;

        let kvm = Kvm::new()?;
        let vm = kvm.create_vm()?;

        let guest_memory = Self::allocate_guest_memory(config.memory_mib)?;
        Self::register_memory(&vm, &guest_memory)?;

        // In-kernel interrupt controller + programmable interval timer. These let
        // the guest take timer/IRQ interrupts without us emulating a PIC/APIC.
        vm.create_irq_chip()?;
        vm.create_pit2(kvm_pit_config::default())?;

        let vm = Arc::new(vm);
        let guest_memory = Arc::new(guest_memory);

        let mut vcpus = Vec::with_capacity(config.vcpus as usize);
        for index in 0..config.vcpus {
            vcpus.push(Vcpu::new(&kvm, &vm, index)?);
        }

        Ok(Self {
            kvm,
            vm,
            guest_memory,
            vcpus,
            config: config.clone(),
        })
    }

    /// Build the guest physical memory map, splitting RAM around the 32-bit MMIO
    /// hole when the guest is given more than 3 GiB.
    fn allocate_guest_memory(memory_mib: u64) -> Result<GuestMemoryMmap> {
        let mem_size = memory_mib
            .checked_mul(1 << 20)
            .ok_or_else(|| VmmError::Memory(format!("memory size {memory_mib} MiB overflows")))?;

        let ranges = if mem_size <= MMIO_GAP_START {
            vec![(GuestAddress(0), mem_size as usize)]
        } else {
            vec![
                (GuestAddress(0), MMIO_GAP_START as usize),
                (
                    GuestAddress(RAM_64BIT_START),
                    (mem_size - MMIO_GAP_START) as usize,
                ),
            ]
        };

        GuestMemoryMmap::from_ranges(&ranges)
            .map_err(|e| VmmError::Memory(format!("from_ranges failed: {e}")))
    }

    /// Hand every guest RAM region to KVM as a userspace memory slot so the guest
    /// physical addresses resolve to our mmap'd host pages.
    fn register_memory(vm: &VmFd, guest_memory: &GuestMemoryMmap) -> Result<()> {
        for (slot, region) in guest_memory.iter().enumerate() {
            let memory_region = kvm_userspace_memory_region {
                slot: slot as u32,
                guest_phys_addr: region.start_addr().raw_value(),
                memory_size: region.len(),
                userspace_addr: region.as_ptr() as u64,
                flags: 0,
            };
            // SAFETY: `region` is owned by `guest_memory`, which outlives the VM,
            // so the userspace mapping stays valid for the slot's lifetime.
            unsafe {
                vm.set_user_memory_region(memory_region)?;
            }
        }
        Ok(())
    }

    /// Shared guest memory handle (used by the device model and kernel loader).
    pub fn guest_memory(&self) -> &Arc<GuestMemoryMmap> {
        &self.guest_memory
    }

    /// The KVM VM handle.
    pub fn vm(&self) -> &Arc<VmFd> {
        &self.vm
    }

    /// The top-level `/dev/kvm` handle (needed to query supported CPUID, etc.).
    pub fn kvm(&self) -> &Kvm {
        &self.kvm
    }

    /// The configured vCPUs.
    pub fn vcpus(&self) -> &[Vcpu] {
        &self.vcpus
    }

    /// The configuration this machine was built from.
    pub fn config(&self) -> &VmConfig {
        &self.config
    }
}
