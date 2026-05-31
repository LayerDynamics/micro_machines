//! vCPU creation, CPUID filtering, x86_64 64-bit boot-protocol register setup,
//! and the KVM run loop (SPEC-1 FR-1, FR-2).
//!
//! Booting a Linux kernel via the 64-bit boot protocol means handing the vCPU a
//! machine that is *already* in long mode: a flat GDT, identity-mapped page
//! tables for low memory, the long-mode bits set in CR0/CR4/EFER, `RIP` at the
//! kernel entry point, and `RSI` pointing at the zero page (`boot_params`). KVM
//! does none of this for us — the VMM is the firmware. The constants and segment
//! layout below follow the standard PC/Linux boot conventions.
use std::sync::Arc;

use kvm_bindings::{
    kvm_fpu, kvm_msr_entry, kvm_regs, kvm_segment, kvm_sregs, CpuId, Msrs, KVM_MAX_CPUID_ENTRIES,
};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryMmap};

use crate::machine::{IoDispatch, Result, VmmError};

// --- Guest-physical layout for boot structures (low memory, below the kernel). ---
const BOOT_GDT_OFFSET: u64 = 0x500;
const BOOT_IDT_OFFSET: u64 = 0x520;
const BOOT_GDT_ENTRIES: usize = 4;
const PML4_START: u64 = 0x9000;
const PDPTE_START: u64 = 0xa000;
const PDE_START: u64 = 0xb000;
const BOOT_STACK_POINTER: u64 = 0x8ff0;

// --- Control-register / EFER bits for entering 64-bit long mode. ---
const X86_CR0_PE: u64 = 0x1;
const X86_CR0_PG: u64 = 0x8000_0000;
const X86_CR4_PAE: u64 = 0x20;
const EFER_LME: u64 = 0x100;
const EFER_LMA: u64 = 0x400;

// --- Page-table entry flags. ---
const PTE_PRESENT_RW: u64 = 0x3; // present + writable
const PDE_PRESENT_RW_PS: u64 = 0x83; // present + writable + 2 MiB page

// --- Boot MSR indices (set to a clean initial state before the kernel runs). ---
const MSR_IA32_SYSENTER_CS: u32 = 0x0000_0174;
const MSR_IA32_SYSENTER_ESP: u32 = 0x0000_0175;
const MSR_IA32_SYSENTER_EIP: u32 = 0x0000_0176;
const MSR_IA32_TSC: u32 = 0x0000_0010;
const MSR_IA32_MISC_ENABLE: u32 = 0x0000_01a0;
const MSR_IA32_MISC_ENABLE_FAST_STRING: u64 = 0x1;
const MSR_STAR: u32 = 0xc000_0081;
const MSR_LSTAR: u32 = 0xc000_0082;
const MSR_CSTAR: u32 = 0xc000_0083;
const MSR_SYSCALL_MASK: u32 = 0xc000_0084;
const MSR_KERNEL_GS_BASE: u32 = 0xc000_0102;

/// How a vCPU run loop ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VcpuRunExit {
    /// The guest executed `HLT` (e.g. after `poweroff`).
    Halted,
    /// KVM reported a triple fault / shutdown.
    Shutdown,
}

/// A single virtual CPU: its KVM fd plus its index (used as the local APIC id).
pub struct Vcpu {
    fd: VcpuFd,
    index: u8,
}

impl Vcpu {
    /// Create vCPU `index` and program its CPUID from the host-supported set,
    /// patching in the per-CPU local APIC id.
    pub fn new(kvm: &Kvm, vm: &VmFd, index: u8) -> Result<Self> {
        let fd = vm.create_vcpu(u64::from(index))?;

        let mut cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?;
        filter_cpuid(index, &mut cpuid);
        fd.set_cpuid2(&cpuid)?;

        Ok(Self { fd, index })
    }

    /// This vCPU's index / local APIC id.
    pub fn index(&self) -> u8 {
        self.index
    }

    /// Put the vCPU into the state the Linux 64-bit boot protocol expects: long
    /// mode enabled, flat segments, identity-mapped low memory, `RIP` at the
    /// kernel entry, and `RSI` at the zero page (`boot_params`).
    pub fn configure_boot(
        &self,
        guest_memory: &GuestMemoryMmap,
        entry_point: GuestAddress,
        boot_params_addr: GuestAddress,
    ) -> Result<()> {
        let mut sregs = self.fd.get_sregs()?;
        configure_segments_and_sregs(guest_memory, &mut sregs)?;
        setup_page_tables(guest_memory, &mut sregs)?;
        self.fd.set_sregs(&sregs)?;

        // A clean FPU state (default control words) so the kernel does not inherit
        // garbage x87/SSE state.
        let fpu = kvm_fpu {
            fcw: 0x37f,
            mxcsr: 0x1f80,
            ..Default::default()
        };
        self.fd.set_fpu(&fpu)?;

        // Boot MSRs the kernel expects to be initialized (SYSENTER/SYSCALL targets
        // zeroed, TSC zeroed, fast-string copies enabled).
        let msrs = boot_msrs()?;
        let written = self.fd.set_msrs(&msrs)?;
        if written != msrs.as_slice().len() {
            return Err(VmmError::Vcpu(format!(
                "set_msrs wrote {written}/{} entries",
                msrs.as_slice().len()
            )));
        }

        let regs = kvm_regs {
            // Bit 1 of RFLAGS is reserved and must be set.
            rflags: 0x0000_0000_0000_0002,
            rip: entry_point.raw_value(),
            rsp: BOOT_STACK_POINTER,
            rbp: BOOT_STACK_POINTER,
            rsi: boot_params_addr.raw_value(),
            ..Default::default()
        };
        self.fd.set_regs(&regs)?;
        Ok(())
    }

    /// Run this vCPU until it halts or shuts down, dispatching every port-I/O and
    /// MMIO exit to the device model. Returns how the loop ended.
    pub fn run(&mut self, dispatch: &Arc<dyn IoDispatch>) -> Result<VcpuRunExit> {
        // Bounded early-boot exit trace (diagnostic): the first N exits reveal what
        // the guest is doing. An empty trace means it is spinning in-guest with no
        // I/O; serial OUT bytes are the console characters.
        const TRACE_LIMIT: usize = 200;
        let mut traced = 0usize;

        loop {
            // Surface a KVM_RUN failure (e.g. invalid entry state) instead of
            // letting `?` drop it silently into the thread result.
            let exit = match self.fd.run() {
                Ok(exit) => exit,
                Err(e) => {
                    let rip = self.fd.get_regs().map(|r| r.rip).unwrap_or(0);
                    eprintln!(
                        "mm-vmm: vcpu {} KVM_RUN failed at rip=0x{rip:x}: {e}",
                        self.index
                    );
                    return Err(VmmError::Kvm(e));
                }
            };
            // Reduce the exit to an owned (is_shutdown, description) for terminal
            // exits (None = keep running). Folding to owned data here ends the
            // `&mut self.fd` borrow the `VcpuExit` holds, so we can read registers
            // afterwards for the fault diagnostic.
            let terminal: Option<(bool, String)> = match exit {
                VcpuExit::IoIn(port, data) => {
                    if traced < TRACE_LIMIT {
                        eprintln!(
                            "mm-vmm: exit#{traced} IO_IN port=0x{port:x} len={}",
                            data.len()
                        );
                        traced += 1;
                    }
                    dispatch.pio_read(port, data);
                    None
                }
                VcpuExit::IoOut(port, data) => {
                    if traced < TRACE_LIMIT {
                        eprintln!("mm-vmm: exit#{traced} IO_OUT port=0x{port:x} data={data:02x?}");
                        traced += 1;
                    }
                    dispatch.pio_write(port, data);
                    None
                }
                VcpuExit::MmioRead(addr, data) => {
                    if traced < TRACE_LIMIT {
                        eprintln!(
                            "mm-vmm: exit#{traced} MMIO_READ addr=0x{addr:x} len={}",
                            data.len()
                        );
                        traced += 1;
                    }
                    dispatch.mmio_read(addr, data);
                    None
                }
                VcpuExit::MmioWrite(addr, data) => {
                    if traced < TRACE_LIMIT {
                        eprintln!(
                            "mm-vmm: exit#{traced} MMIO_WRITE addr=0x{addr:x} data={data:02x?}"
                        );
                        traced += 1;
                    }
                    dispatch.mmio_write(addr, data);
                    None
                }
                VcpuExit::Hlt => return Ok(VcpuRunExit::Halted),
                VcpuExit::Shutdown => Some((true, "SHUTDOWN (triple fault)".to_string())),
                other => Some((false, format!("unexpected exit {other:?}"))),
            };

            if let Some((is_shutdown, description)) = terminal {
                let rip = self.fd.get_regs().map(|r| r.rip).unwrap_or(0);
                eprintln!("mm-vmm: vcpu {} {description} at rip=0x{rip:x}", self.index);
                if is_shutdown {
                    return Ok(VcpuRunExit::Shutdown);
                }
                return Err(VmmError::Vcpu(format!(
                    "vcpu {}: {description}",
                    self.index
                )));
            }
        }
    }
}

/// Build the boot MSR set: SYSENTER/SYSCALL targets and TSC zeroed, fast-string
/// string copies enabled.
fn boot_msrs() -> Result<Msrs> {
    let entry = |index: u32, data: u64| kvm_msr_entry {
        index,
        data,
        ..Default::default()
    };
    let entries = [
        entry(MSR_IA32_SYSENTER_CS, 0),
        entry(MSR_IA32_SYSENTER_ESP, 0),
        entry(MSR_IA32_SYSENTER_EIP, 0),
        entry(MSR_STAR, 0),
        entry(MSR_CSTAR, 0),
        entry(MSR_LSTAR, 0),
        entry(MSR_KERNEL_GS_BASE, 0),
        entry(MSR_SYSCALL_MASK, 0),
        entry(MSR_IA32_TSC, 0),
        entry(MSR_IA32_MISC_ENABLE, MSR_IA32_MISC_ENABLE_FAST_STRING),
    ];
    Msrs::from_entries(&entries).map_err(|e| VmmError::Vcpu(format!("building boot MSRs: {e:?}")))
}

/// Patch the supported CPUID: write this vCPU's local APIC id into leaf 1 EBX
/// and ensure the APIC feature bit is advertised.
fn filter_cpuid(index: u8, cpuid: &mut CpuId) {
    for entry in cpuid.as_mut_slice() {
        if entry.function == 1 {
            // EBX[31:24] = initial local APIC id.
            entry.ebx &= 0x00ff_ffff;
            entry.ebx |= u32::from(index) << 24;
            // EDX[9] = on-chip APIC present.
            entry.edx |= 1 << 9;
        }
    }
}

/// Build a flat GDT (null/code/data/TSS), write it to guest memory, and load the
/// matching long-mode segment registers + CR0(PE)/EFER(LME|LMA) into `sregs`.
fn configure_segments_and_sregs(
    guest_memory: &GuestMemoryMmap,
    sregs: &mut kvm_sregs,
) -> Result<()> {
    let gdt: [u64; BOOT_GDT_ENTRIES] = [
        gdt_entry(0, 0, 0),             // null
        gdt_entry(0xa09b, 0, 0xf_ffff), // code: present, ring0, exec/read, long mode
        gdt_entry(0xc093, 0, 0xf_ffff), // data: present, ring0, read/write
        gdt_entry(0x808b, 0, 0xf_ffff), // TSS
    ];

    let code = kvm_segment_from_gdt(gdt[1], 1);
    let data = kvm_segment_from_gdt(gdt[2], 2);
    let tss = kvm_segment_from_gdt(gdt[3], 3);

    for (i, entry) in gdt.iter().enumerate() {
        let addr = GuestAddress(BOOT_GDT_OFFSET + (i * std::mem::size_of::<u64>()) as u64);
        guest_memory
            .write_obj(*entry, addr)
            .map_err(|e| VmmError::Memory(format!("writing GDT entry {i}: {e}")))?;
    }
    sregs.gdt.base = BOOT_GDT_OFFSET;
    sregs.gdt.limit = (std::mem::size_of_val(&gdt) - 1) as u16;

    // A single null IDT entry; the guest installs its own IDT during boot.
    guest_memory
        .write_obj(0u64, GuestAddress(BOOT_IDT_OFFSET))
        .map_err(|e| VmmError::Memory(format!("writing IDT: {e}")))?;
    sregs.idt.base = BOOT_IDT_OFFSET;
    sregs.idt.limit = (std::mem::size_of::<u64>() - 1) as u16;

    sregs.cs = code;
    sregs.ds = data;
    sregs.es = data;
    sregs.fs = data;
    sregs.gs = data;
    sregs.ss = data;
    sregs.tr = tss;

    sregs.cr0 |= X86_CR0_PE;
    sregs.efer |= EFER_LME | EFER_LMA;
    Ok(())
}

/// Identity-map the first 1 GiB of guest physical memory with 2 MiB pages and
/// point CR3 at the PML4, enabling paging (CR0.PG) and PAE (CR4.PAE).
fn setup_page_tables(guest_memory: &GuestMemoryMmap, sregs: &mut kvm_sregs) -> Result<()> {
    // PML4[0] -> PDPTE, PDPTE[0] -> PDE.
    guest_memory
        .write_obj(PDPTE_START | PTE_PRESENT_RW, GuestAddress(PML4_START))
        .map_err(|e| VmmError::Memory(format!("writing PML4: {e}")))?;
    guest_memory
        .write_obj(PDE_START | PTE_PRESENT_RW, GuestAddress(PDPTE_START))
        .map_err(|e| VmmError::Memory(format!("writing PDPTE: {e}")))?;

    // 512 * 2 MiB = 1 GiB identity map.
    for i in 0..512u64 {
        let entry = (i << 21) | PDE_PRESENT_RW_PS;
        guest_memory
            .write_obj(
                entry,
                GuestAddress(PDE_START + i * std::mem::size_of::<u64>() as u64),
            )
            .map_err(|e| VmmError::Memory(format!("writing PDE[{i}]: {e}")))?;
    }

    sregs.cr3 = PML4_START;
    sregs.cr4 |= X86_CR4_PAE;
    sregs.cr0 |= X86_CR0_PG;
    Ok(())
}

/// Encode a GDT entry from `flags`, `base`, and `limit` into the packed 64-bit
/// descriptor form the CPU expects.
fn gdt_entry(flags: u16, base: u32, limit: u32) -> u64 {
    ((u64::from(base) & 0xff00_0000) << (56 - 24))
        | ((u64::from(flags) & 0x0000_f0ff) << 40)
        | ((u64::from(limit) & 0x000f_0000) << (48 - 16))
        | ((u64::from(base) & 0x00ff_ffff) << 16)
        | (u64::from(limit) & 0x0000_ffff)
}

/// Decode a packed GDT entry into the `kvm_segment` KVM wants for `set_sregs`.
fn kvm_segment_from_gdt(entry: u64, table_index: u8) -> kvm_segment {
    let base = ((entry >> 16) & 0x00ff_ffff) | ((entry >> 32) & 0xff00_0000);
    let limit = (((entry & 0x000f_0000_0000_0000) >> 32) | (entry & 0x0000_0000_0000_ffff)) as u32;
    let present = ((entry >> 47) & 1) as u8;
    kvm_segment {
        base,
        limit,
        selector: u16::from(table_index) * 8,
        type_: ((entry >> 40) & 0xf) as u8,
        present,
        dpl: ((entry >> 45) & 0x3) as u8,
        db: ((entry >> 54) & 1) as u8,
        s: ((entry >> 44) & 1) as u8,
        l: ((entry >> 53) & 1) as u8,
        g: ((entry >> 55) & 1) as u8,
        avl: ((entry >> 52) & 1) as u8,
        // A non-present segment is "unusable" to the CPU.
        unusable: u8::from(present == 0),
        padding: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gdt_entry_roundtrips_through_segment() {
        // Code segment: base 0, 4 GiB limit (granularity), long mode.
        let entry = gdt_entry(0xa09b, 0, 0xf_ffff);
        let seg = kvm_segment_from_gdt(entry, 1);
        assert_eq!(seg.base, 0);
        assert_eq!(seg.limit, 0xf_ffff);
        assert_eq!(seg.selector, 8);
        assert_eq!(seg.present, 1);
        assert_eq!(seg.l, 1, "code segment must be long-mode");
        assert_eq!(seg.dpl, 0, "ring 0");
    }

    #[test]
    fn null_segment_is_unusable() {
        let seg = kvm_segment_from_gdt(gdt_entry(0, 0, 0), 0);
        assert_eq!(seg.present, 0);
        assert_eq!(seg.unusable, 1);
    }
}
