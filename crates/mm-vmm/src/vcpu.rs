//! vCPU creation, CPUID filtering, x86_64 64-bit boot-protocol register setup,
//! and the KVM run loop (SPEC-1 FR-1, FR-2).
//!
//! Booting a Linux kernel via the 64-bit boot protocol means handing the vCPU a
//! machine that is *already* in long mode: a flat GDT, identity-mapped page
//! tables for low memory, the long-mode bits set in CR0/CR4/EFER, `RIP` at the
//! kernel entry point, and `RSI` pointing at the zero page (`boot_params`). KVM
//! does none of this for us — the VMM is the firmware. The constants and segment
//! layout below follow the standard PC/Linux boot conventions.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use kvm_bindings::{
    kvm_cpuid_entry2, kvm_fpu, kvm_msr_entry, kvm_regs, kvm_segment, kvm_sregs, kvm_vcpu_events,
    kvm_xcrs, CpuId, Msrs, KVM_MAX_CPUID_ENTRIES,
};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryMmap};

use crate::checkpoint::Checkpoint;
use crate::machine::{IoDispatch, Result, VmmError};
use crate::snapshot::state::{MsrEntry, VcpuState};

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
const MSR_FS_BASE: u32 = 0xc000_0100;
const MSR_GS_BASE: u32 = 0xc000_0101;
const MSR_KERNEL_GS_BASE: u32 = 0xc000_0102;

/// How a vCPU run loop ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VcpuRunExit {
    /// The guest executed `HLT` (e.g. after `poweroff`).
    Halted,
    /// KVM reported a triple fault / shutdown.
    Shutdown,
    /// The vCPU was paused for a snapshot; its state was captured into the pause
    /// slot before the thread returned.
    Paused,
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

        let supported = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?;
        let cpuid = build_cpuid(index, &supported, &fd)?;
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

    /// Run this vCPU until it halts, shuts down, or `stop` is set, dispatching every
    /// port-I/O and MMIO exit to the device model. With the in-kernel irqchip a
    /// guest `HLT` is handled inside KVM (KVM_RUN blocks rather than returning), so
    /// teardown signals the thread: the signal interrupts KVM_RUN with `EINTR`, we
    /// observe `stop`, and return.
    pub(crate) fn run(
        &mut self,
        dispatch: &Arc<dyn IoDispatch>,
        stop: &AtomicBool,
        pause: &AtomicBool,
        pause_out: &Mutex<Option<VcpuState>>,
        checkpoint: &Checkpoint,
    ) -> Result<VcpuRunExit> {
        loop {
            if stop.load(Ordering::Acquire) {
                return Ok(VcpuRunExit::Halted);
            }
            if pause.load(Ordering::Acquire) {
                return self.do_pause(pause_out);
            }
            // Capture-and-continue checkpoint (FR-16 running BRANCH): unlike the
            // freeze-only `pause` above, capture state into the slot, park at the
            // barrier, then resume KVM_RUN where we left off — the vCPU never exits.
            if checkpoint.is_requested() {
                self.checkpoint(pause_out, checkpoint)?;
                continue;
            }
            let exit = match self.fd.run() {
                Ok(exit) => exit,
                // A stop/pause/checkpoint signal interrupts KVM_RUN with EINTR; re-check.
                Err(e) if e.errno() == libc::EINTR => {
                    if stop.load(Ordering::Acquire) {
                        return Ok(VcpuRunExit::Halted);
                    }
                    if pause.load(Ordering::Acquire) {
                        return self.do_pause(pause_out);
                    }
                    if checkpoint.is_requested() {
                        self.checkpoint(pause_out, checkpoint)?;
                    }
                    continue;
                }
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
                    dispatch.pio_read(port, data);
                    None
                }
                VcpuExit::IoOut(port, data) => {
                    dispatch.pio_write(port, data);
                    None
                }
                VcpuExit::MmioRead(addr, data) => {
                    dispatch.mmio_read(addr, data);
                    None
                }
                VcpuExit::MmioWrite(addr, data) => {
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

    /// Capture this vCPU's state into `pause_out` and report a paused exit. Called
    /// once the pause flag is observed — always *outside* `KVM_RUN` (the run loop
    /// checks the flag at the top and right after an `EINTR`), so the state-read
    /// ioctls are safe.
    fn do_pause(&self, pause_out: &Mutex<Option<VcpuState>>) -> Result<VcpuRunExit> {
        let state = self.capture_state()?;
        if let Ok(mut slot) = pause_out.lock() {
            *slot = Some(state);
        }
        Ok(VcpuRunExit::Paused)
    }

    /// Capture-and-continue: store this vCPU's state into `pause_out`, then park at the
    /// `checkpoint` barrier until the orchestrator releases. Like [`do_pause`] the
    /// state is read **outside** `KVM_RUN` (the caller checks the flag at the top of
    /// the loop or right after `EINTR`), but the vCPU resumes instead of exiting — the
    /// resume-in-place primitive the running BRANCH is built on. The store must happen
    /// before `park` so "all parked" implies "all captured" for the orchestrator.
    fn checkpoint(
        &self,
        pause_out: &Mutex<Option<VcpuState>>,
        checkpoint: &Checkpoint,
    ) -> Result<()> {
        let state = self.capture_state()?;
        if let Ok(mut slot) = pause_out.lock() {
            *slot = Some(state);
        }
        checkpoint.park();
        Ok(())
    }

    /// Capture this vCPU's full execution context for a snapshot (SPEC-1 FR-14).
    /// Must be called with the vCPU quiesced (not inside `KVM_RUN`). CPUID is not
    /// captured — it is rebuilt deterministically from the host + index at restore.
    pub fn capture_state(&self) -> Result<VcpuState> {
        let regs = self.fd.get_regs().map_err(VmmError::Kvm)?;
        let sregs = self.fd.get_sregs().map_err(VmmError::Kvm)?;
        let fpu = fpu_to_bytes(&self.fd.get_fpu().map_err(VmmError::Kvm)?);
        let xcrs = xcrs_to_bytes(&self.fd.get_xcrs().map_err(VmmError::Kvm)?);
        let lapic = self.fd.get_lapic().map_err(VmmError::Kvm)?;
        let mp_state = self.fd.get_mp_state().map_err(VmmError::Kvm)?;
        // Pending event-injection state (exceptions / interrupt being injected / NMI /
        // interrupt shadow). Required for resume fidelity: a guest paused mid-injection
        // resumes inconsistent and crashes in the IRQ path without it (FR-16 live BRANCH).
        let vcpu_events = vcpu_events_to_bytes(&self.fd.get_vcpu_events().map_err(VmmError::Kvm)?);

        // Query the curated MSR set: build a `Msrs` holding the indices, let KVM fill
        // in the data, then read it back as plain pairs.
        let entries: Vec<kvm_msr_entry> = SNAPSHOT_MSRS
            .iter()
            .map(|&index| kvm_msr_entry {
                index,
                ..Default::default()
            })
            .collect();
        let mut msrs = Msrs::from_entries(&entries)
            .map_err(|e| VmmError::Vcpu(format!("building snapshot MSRs: {e:?}")))?;
        let read = self.fd.get_msrs(&mut msrs).map_err(VmmError::Kvm)?;
        if read != SNAPSHOT_MSRS.len() {
            // KVM_GET_MSRS processes the list in order and stops at the first index it
            // rejects, returning the count read so far. A short read means every MSR
            // after the offender is silently dropped from the snapshot — restore would
            // then quietly omit them. Surface it rather than capturing a partial state.
            tracing::warn!(
                "get_msrs read {read}/{} snapshot MSRs — index {:#x} rejected; \
                 trailing MSRs dropped from snapshot",
                SNAPSHOT_MSRS.len(),
                SNAPSHOT_MSRS.get(read).copied().unwrap_or(0),
            );
        }
        let msrs = msrs.as_slice()[..read]
            .iter()
            .map(|e| MsrEntry {
                index: e.index,
                data: e.data,
            })
            .collect();

        // TSC frequency (kHz). Best-effort: hosts without KVM_CAP_GET_TSC_KHZ report
        // 0, meaning "do not re-apply at restore".
        let tsc_khz = self.fd.get_tsc_khz().unwrap_or(0);

        Ok(VcpuState {
            regs,
            sregs,
            fpu,
            xcrs,
            lapic,
            mp_state,
            msrs,
            tsc_khz,
            vcpu_events,
        })
    }

    /// Restore a captured [`VcpuState`] onto this (freshly created, not yet run)
    /// vCPU, the inverse of [`capture_state`](Self::capture_state).
    pub fn restore_state(&self, state: &VcpuState) -> Result<()> {
        // Re-apply the TSC frequency first so the guest's time base matches the
        // snapshot. Best-effort: only if captured and the host supports scaling.
        if state.tsc_khz != 0 {
            if let Err(e) = self.fd.set_tsc_khz(state.tsc_khz) {
                tracing::warn!("restore: set_tsc_khz({}) failed: {e}", state.tsc_khz);
            }
        }
        self.fd.set_sregs(&state.sregs).map_err(VmmError::Kvm)?;
        // Restore XCR0 after sregs (XSETBV requires CR4.OSXSAVE, set by set_sregs) and
        // before the guest runs, so its enabled XSAVE feature set matches what the
        // restored kernel expects — otherwise its first XRSTOR faults. Skipped for
        // pre-XCRS snapshots (empty bytes).
        if !state.xcrs.is_empty() {
            self.fd
                .set_xcrs(&xcrs_from_bytes(&state.xcrs)?)
                .map_err(VmmError::Kvm)?;
        }
        self.fd
            .set_fpu(&fpu_from_bytes(&state.fpu)?)
            .map_err(VmmError::Kvm)?;
        self.fd.set_lapic(&state.lapic).map_err(VmmError::Kvm)?;
        self.fd
            .set_mp_state(state.mp_state)
            .map_err(VmmError::Kvm)?;

        let entries: Vec<kvm_msr_entry> = state
            .msrs
            .iter()
            .map(|m| kvm_msr_entry {
                index: m.index,
                data: m.data,
                ..Default::default()
            })
            .collect();
        let msrs = Msrs::from_entries(&entries)
            .map_err(|e| VmmError::Vcpu(format!("building restore MSRs: {e:?}")))?;
        let written = self.fd.set_msrs(&msrs).map_err(VmmError::Kvm)?;
        if written != entries.len() {
            return Err(VmmError::Vcpu(format!(
                "set_msrs wrote {written}/{} entries on restore",
                entries.len()
            )));
        }

        // Restore pending event-injection state (exceptions / in-flight interrupt / NMI /
        // interrupt shadow) so a guest captured mid-injection resumes consistently rather
        // than faulting in the IRQ path. Skipped for pre-events state files (empty bytes).
        if !state.vcpu_events.is_empty() {
            self.fd
                .set_vcpu_events(&vcpu_events_from_bytes(&state.vcpu_events)?)
                .map_err(VmmError::Kvm)?;
        }

        // Set general-purpose registers last so RIP/RSP are not perturbed by the
        // other ioctls.
        self.fd.set_regs(&state.regs).map_err(VmmError::Kvm)?;
        Ok(())
    }
}

/// MSRs captured/restored across a snapshot: the SYSENTER/SYSCALL targets, the TSC and
/// its LAPIC TSC-deadline timer, MISC_ENABLE, and the kvm-clock paravirt-clock MSRs the
/// guest relies on (the guest is configured to use kvm-clock in `build_cpuid`). EFER
/// and the FS/GS bases live in `sregs`, so they are not duplicated here.
const SNAPSHOT_MSRS: &[u32] = &[
    MSR_IA32_SYSENTER_CS,
    MSR_IA32_SYSENTER_ESP,
    MSR_IA32_SYSENTER_EIP,
    MSR_STAR,
    MSR_LSTAR,
    MSR_CSTAR,
    MSR_SYSCALL_MASK,
    // The 64-bit FS/GS bases. KVM treats these MSRs (not the sregs segment .base fields)
    // as authoritative in long mode; without restoring the active GS base a resumed guest
    // faults in per-CPU (GS-relative) accesses — e.g. crashes in __do_softirq on the first
    // interrupt after resume (SPEC-1 FR-16 live BRANCH fidelity). KERNEL_GS_BASE is the
    // SWAPGS shadow; all three are needed (mirrors Firecracker's snapshot MSR set).
    MSR_FS_BASE,
    MSR_GS_BASE,
    MSR_KERNEL_GS_BASE,
    MSR_IA32_TSC,
    MSR_IA32_TSC_DEADLINE,
    MSR_IA32_MISC_ENABLE,
    MSR_KVM_WALL_CLOCK_NEW,
    MSR_KVM_SYSTEM_TIME_NEW,
];

/// The LAPIC TSC-deadline timer (the armed deadline at which KVM injects the next
/// timer interrupt). Linux on KVM uses TSC-deadline timer mode, so without restoring
/// this a resumed/forked guest gets no timer interrupt — `nanosleep`/the scheduler
/// tick stall — which manifests as any guest code that sleeps hanging after a fork.
const MSR_IA32_TSC_DEADLINE: u32 = 0x0000_06e0;
/// kvm-clock paravirt-clock MSRs (the guest programs these to find its clock pages).
const MSR_KVM_WALL_CLOCK_NEW: u32 = 0x4b56_4d00;
const MSR_KVM_SYSTEM_TIME_NEW: u32 = 0x4b56_4d01;

/// Serialize a `kvm_vcpu_events` to its raw bytes for the snapshot state file (it has
/// unions, so no serde — same byte-copy approach as `kvm_xcrs`/`kvm_fpu`).
fn vcpu_events_to_bytes(ev: &kvm_vcpu_events) -> Vec<u8> {
    // SAFETY: `kvm_vcpu_events` is a fixed-size `repr(C)` POD; reading `size_of` bytes is
    // sound and yields an exact, restorable copy.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (ev as *const kvm_vcpu_events).cast::<u8>(),
            std::mem::size_of::<kvm_vcpu_events>(),
        )
    };
    bytes.to_vec()
}

/// Rebuild a `kvm_vcpu_events` from snapshot bytes, validating the length.
fn vcpu_events_from_bytes(bytes: &[u8]) -> Result<kvm_vcpu_events> {
    let want = std::mem::size_of::<kvm_vcpu_events>();
    if bytes.len() != want {
        return Err(VmmError::Vcpu(format!(
            "snapshot VCPU_EVENTS state is {} bytes, expected {want}",
            bytes.len()
        )));
    }
    let mut ev = kvm_vcpu_events::default();
    // SAFETY: `kvm_vcpu_events` is POD; copy exactly `size_of` bytes into a zeroed instance
    // (length checked above).
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            (&mut ev as *mut kvm_vcpu_events).cast::<u8>(),
            want,
        );
    }
    Ok(ev)
}

/// Serialize a `kvm_xcrs` to its raw bytes for the snapshot state file.
fn xcrs_to_bytes(xcrs: &kvm_xcrs) -> Vec<u8> {
    // SAFETY: `kvm_xcrs` is a fixed-size `repr(C)` POD; reading `size_of` bytes is
    // sound and yields an exact, restorable copy.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (xcrs as *const kvm_xcrs).cast::<u8>(),
            std::mem::size_of::<kvm_xcrs>(),
        )
    };
    bytes.to_vec()
}

/// Rebuild a `kvm_xcrs` from snapshot bytes, validating the length.
fn xcrs_from_bytes(bytes: &[u8]) -> Result<kvm_xcrs> {
    let want = std::mem::size_of::<kvm_xcrs>();
    if bytes.len() != want {
        return Err(VmmError::Vcpu(format!(
            "snapshot XCRS state is {} bytes, expected {want}",
            bytes.len()
        )));
    }
    let mut xcrs = kvm_xcrs::default();
    // SAFETY: `kvm_xcrs` is POD; copy exactly `size_of` bytes into a zeroed instance
    // (length checked above).
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            (&mut xcrs as *mut kvm_xcrs).cast::<u8>(),
            want,
        );
    }
    Ok(xcrs)
}

/// Serialize a `kvm_fpu` to its raw bytes for the snapshot state file.
fn fpu_to_bytes(fpu: &kvm_fpu) -> Vec<u8> {
    // SAFETY: `kvm_fpu` is a fixed-size `repr(C)` POD; reading `size_of` bytes of it
    // is sound and yields an exact, restorable copy.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (fpu as *const kvm_fpu).cast::<u8>(),
            std::mem::size_of::<kvm_fpu>(),
        )
    };
    bytes.to_vec()
}

/// Rebuild a `kvm_fpu` from snapshot bytes, validating the length.
fn fpu_from_bytes(bytes: &[u8]) -> Result<kvm_fpu> {
    let want = std::mem::size_of::<kvm_fpu>();
    if bytes.len() != want {
        return Err(VmmError::Vcpu(format!(
            "snapshot FPU state is {} bytes, expected {want}",
            bytes.len()
        )));
    }
    let mut fpu = kvm_fpu::default();
    // SAFETY: `kvm_fpu` is POD; we copy exactly `size_of::<kvm_fpu>()` bytes into a
    // zeroed instance, and the length was checked above.
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            (&mut fpu as *mut kvm_fpu).cast::<u8>(),
            want,
        );
    }
    Ok(fpu)
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

/// Build this vCPU's CPUID from the host-supported set: patch leaf 1 (local APIC
/// id, on-chip APIC, **hypervisor-present**) and append the **KVM paravirt** leaves
/// so the guest uses kvm-clock and reads its TSC frequency directly — skipping the
/// legacy PIT-based TSC calibration that otherwise spins forever polling the
/// unemulated port 0x61.
fn build_cpuid(index: u8, supported: &CpuId, fd: &VcpuFd) -> Result<CpuId> {
    let mut entries: Vec<kvm_cpuid_entry2> = supported.as_slice().to_vec();

    for entry in entries.iter_mut() {
        if entry.function == 1 && entry.index == 0 {
            entry.ebx = (entry.ebx & 0x00ff_ffff) | (u32::from(index) << 24); // APIC id
            entry.edx |= 1 << 9; // on-chip APIC
            entry.ecx |= 1 << 31; // hypervisor present
        }
    }

    // KVM signature leaf: EAX = highest paravirt leaf; EBX/ECX/EDX = "KVMKVMKVM".
    entries.push(kvm_cpuid_entry2 {
        function: 0x4000_0000,
        eax: 0x4000_0010,
        ebx: 0x4b4d_564b, // "KVMK"
        ecx: 0x564b_4d56, // "VMKV"
        edx: 0x0000_004d, // "M"
        ..Default::default()
    });
    // KVM feature leaf: kvm-clock (clocksource + clocksource2 + stable TSC) and
    // no-op I/O delay so the kernel does not busy-wait on port 0x80.
    entries.push(kvm_cpuid_entry2 {
        function: 0x4000_0001,
        eax: (1 << 0) | (1 << 1) | (1 << 3) | (1 << 24),
        ..Default::default()
    });
    // TSC frequency leaf (kHz) so the guest never falls back to PIT calibration.
    if let Ok(tsc_khz) = fd.get_tsc_khz() {
        entries.push(kvm_cpuid_entry2 {
            function: 0x4000_0010,
            eax: tsc_khz,
            ..Default::default()
        });
    }

    CpuId::from_entries(&entries).map_err(|e| VmmError::Vcpu(format!("building cpuid: {e:?}")))
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
