//! KVM machine: device-independent VM setup — the `/dev/kvm` handle, guest RAM,
//! the in-kernel interrupt controller + PIT, and vCPU creation (SPEC-1 FR-1).
//!
//! It builds the VM, maps guest memory into KVM, creates the vCPUs, and — via
//! [`Machine::boot`] — wires the device model ([`crate::devices`]), loads the
//! kernel ([`crate::boot`]), configures the vCPUs for the boot protocol, and runs
//! them. [`Machine::wait_for_ready`] blocks on the guest's vsock readiness signal.
use std::fmt::Write as _;
use std::fs::File;
use std::io::{Read as _, Write as _IoWrite};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use kvm_bindings::{
    kvm_clock_data, kvm_irqchip, kvm_pit_config, kvm_pit_state2, kvm_userspace_memory_region,
    KVM_IRQCHIP_IOAPIC, KVM_IRQCHIP_PIC_MASTER, KVM_IRQCHIP_PIC_SLAVE, KVM_MAX_CPUID_ENTRIES,
    KVM_MEM_LOG_DIRTY_PAGES, KVM_PIT_SPEAKER_DUMMY,
};
use kvm_ioctls::{Kvm, VmFd};
use vm_memory::{
    Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion, GuestRegionMmap,
};
use vmm_sys_util::eventfd::EventFd;

use crate::checkpoint::Checkpoint;
use crate::config::{ConfigError, VirtioDevice as ConfigDevice, VmConfig};
use crate::devices::{
    Balloon, Block, Bus, DevicePause, Interrupt, MmioTransport, Net, SerialDevice, VirtioDevice,
    Vsock, VsockReady, COM1_IRQ,
};
use crate::snapshot::manifest::HostFingerprint;
use crate::snapshot::state::{DeviceState, IrqChipState, QueueCursor, VcpuState, VmState};
use crate::vcpu::{Vcpu, VcpuRunExit};

/// Start of the 32-bit MMIO hole on x86: guest RAM is split around it so device
/// BARs and the LAPIC/IOAPIC windows are never backed by RAM (matches the
/// conventional PC memory map).
const MMIO_GAP_START: u64 = 0xc000_0000; // 3 GiB
/// Where RAM resumes above the 4 GiB boundary when a guest is given > 3 GiB.
const RAM_64BIT_START: u64 = 0x1_0000_0000; // 4 GiB

/// Base of the virtio-mmio device window (inside the 32-bit MMIO hole).
const MMIO_DEVICE_BASE: u64 = 0xd000_0000;
/// Per-device MMIO window size (one 4 KiB page, the virtio-mmio convention).
const MMIO_DEVICE_SIZE: u64 = 0x1000;
/// First GSI for virtio devices; COM1 takes GSI 4 ([`COM1_IRQ`]).
const FIRST_VIRTIO_GSI: u32 = 5;
/// The default guest context id for the boot vsock channel.
const DEFAULT_GUEST_CID: u64 = 3;

/// KVM identity-map page and TSS region (3 pages), in the MMIO hole below 4 GiB
/// (the canonical Firecracker addresses).
const IDENTITY_MAP_ADDR: u64 = 0xfffb_c000;
const TSS_ADDR: u64 = 0xfffb_d000;

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

/// A hook invoked inside each vCPU thread *after* the VMM has finished opening
/// resources but *before* the first `vcpu.run()`. The argument is the vCPU index.
/// This is the seam the CLI uses to install a per-thread seccomp-BPF filter at the
/// only correct moment — once the file/ioctl setup is done, before guest code runs
/// (SPEC-1 FR-27). If it returns an error, that vCPU thread aborts before running.
pub type VcpuHook = Arc<dyn Fn(u8) -> Result<()> + Send + Sync>;

/// A microVM. After [`Machine::new`] it is constructed but idle; after
/// [`Machine::boot`] its vCPUs are running in their own threads and its device
/// workers are live. The KVM/VM handles and guest RAM are retained so the running
/// machine (and its devices) stay valid for the VM's lifetime.
pub struct Machine {
    kvm: Kvm,
    vm: Arc<VmFd>,
    guest_memory: Arc<GuestMemoryMmap>,
    vcpus: Vec<Vcpu>,
    config: VmConfig,
    /// Running vCPU threads (populated by [`Machine::boot`]).
    vcpu_threads: Vec<JoinHandle<Result<VcpuRunExit>>>,
    /// The device bus, kept alive while vCPUs reference it.
    bus: Option<Arc<Bus>>,
    /// The guest readiness signal from the boot vsock device.
    ready: Option<Arc<VsockReady>>,
    /// Optional per-vCPU-thread pre-run hook (e.g. seccomp install).
    vcpu_hook: Option<VcpuHook>,
    /// Pre-opened TAP fds, consumed in order by configured net devices. Non-empty
    /// only on the jailed boot path, where the (now unprivileged) VMM cannot open
    /// the TAP itself — the privileged parent opened it and passed the fd in.
    tap_fds: Vec<RawFd>,
    /// Host UDS listener for the vsock exec bridge (SPEC-1 FR-13). Set only on the
    /// jailed boot path: the privileged parent binds it outside the chroot and passes
    /// the fd in, so the confined worker can `accept()` host exec connections without
    /// touching the filesystem. `None` -> the vsock device is readiness-only (M1).
    vsock_listener: Option<UnixListener>,
    /// Set by `shutdown` to ask the vCPU threads to stop.
    vcpu_stop: Arc<AtomicBool>,
    /// Set by each vCPU thread as it exits its run loop (guest powered off / shut down
    /// / errored). Lets a holder of a *shared* `Machine` (the jailed worker's control
    /// loop) poll liveness with [`is_powered_off`](Self::is_powered_off) without taking
    /// a long-lived `&mut` borrow.
    powered_off: Arc<AtomicBool>,
    /// Set by `pause_and_capture_vcpus` to ask the vCPU threads to capture their
    /// state and freeze (snapshot, SPEC-1 FR-14), distinct from the teardown stop.
    vcpu_pause: Arc<AtomicBool>,
    /// Per-vCPU capture slots, filled when the threads observe `vcpu_pause` (freeze)
    /// **or** a `checkpoint` request (capture-and-continue), then drained by
    /// `pause_and_capture_vcpus` / `checkpoint_in_place`. One per vCPU, in index order.
    vcpu_states: Vec<Arc<Mutex<Option<VcpuState>>>>,
    /// Capture-and-continue barrier for resume-in-place (SPEC-1 FR-16 running BRANCH):
    /// `checkpoint_in_place` uses it to pause the vCPUs at a quiescent point, capture
    /// their state, and resume them — without the freeze-and-exit of `vcpu_pause`.
    checkpoint: Arc<Checkpoint>,
    /// Snapshot capture handles for the snapshottable devices, in device-attach
    /// order. Each lets `pause_devices` signal the device's worker and read back its
    /// queue cursors (SPEC-1 FR-14).
    device_captures: Vec<DeviceCapture>,
    /// pthread ids of the running vCPU threads, so `shutdown` can signal them out
    /// of a halted KVM_RUN.
    vcpu_tids: Arc<Mutex<Vec<libc::pthread_t>>>,
}

/// The Machine's half of a device snapshot handle: signal `evt` to ask the device's
/// worker to quiesce and fill `slot` with its queue cursors.
struct DeviceCapture {
    device_type: u32,
    evt: EventFd,
    slot: Arc<Mutex<Option<Vec<QueueCursor>>>>,
}

/// The signal used to kick a vCPU thread out of `KVM_RUN` at teardown. A no-op
/// handler (installed once) makes the signal interrupt the blocking ioctl with
/// `EINTR` without terminating the thread.
const VCPU_STOP_SIGNAL: libc::c_int = libc::SIGUSR1;

/// Install the no-op `SIGUSR1` handler exactly once per process.
fn install_vcpu_stop_handler() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        extern "C" fn noop(_: libc::c_int) {}
        let handler = noop as extern "C" fn(libc::c_int);
        // SAFETY: a no-op handler with no SA_RESTART so blocking syscalls return
        // EINTR rather than auto-restarting.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = handler as usize;
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_flags = 0;
            libc::sigaction(VCPU_STOP_SIGNAL, &action, std::ptr::null_mut());
        }
    });
}

/// The result of [`Machine::branch`]: the written manifest plus how the image was
/// materialized. `copied` is the number of pages written by the live full-RAM copy;
/// `recopied` is the number re-copied coherently at the final barrier (every page KVM's
/// dirty log flagged as written since logging began — by the guest's vCPUs or by KVM's own
/// paravirt-page writes). `recopied` is direct evidence the dirty-log final pass ran.
pub struct BranchOutcome {
    pub manifest: crate::snapshot::SnapshotManifest,
    pub copied: u64,
    pub recopied: u64,
}

/// A guest RAM page written since dirty logging was enabled: its host address and the byte
/// offset of that page within the branch `memory.bin` (regions are laid out in slot order).
struct DirtyPage {
    host_addr: usize,
    file_offset: u64,
}

/// Guest RAM page size for the branch dirty-log materializer (KVM tracks dirty state and
/// lays out `memory.bin` in 4 KiB pages).
const BRANCH_PAGE_SIZE: usize = 4096;

/// Write every guest RAM region into the branch `memory.bin`, in slot order, returning the
/// total page count. Runs while the parent is executing (a live copy); pages mutated during
/// the copy are caught by the dirty log and re-copied coherently at the final barrier.
fn write_branch_image(regions: &[(usize, usize)], path: &std::path::Path) -> Result<u64> {
    use std::os::unix::fs::FileExt;
    let total: usize = regions.iter().map(|(_, len)| *len).sum();
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(VmmError::Io)?;
    file.set_len(total as u64).map_err(VmmError::Io)?;
    let mut offset = 0u64;
    for &(base, len) in regions {
        // SAFETY: `base`/`len` is a mapped guest RAM region (from `guest_ram_regions`),
        // owned by `guest_memory` which outlives this call; valid for `len` bytes of read.
        let src = unsafe { std::slice::from_raw_parts(base as *const u8, len) };
        file.write_all_at(src, offset).map_err(VmmError::Io)?;
        offset += len as u64;
    }
    Ok((total / BRANCH_PAGE_SIZE) as u64)
}

/// Re-copy the given dirtied pages from live guest RAM into the branch `memory.bin` at their
/// recorded offsets. Called at the final barrier (parent parked), so each page's bytes are
/// stable; this makes the whole image coherent at that instant. Returns the count.
fn recopy_branch_pages(path: &std::path::Path, dirty: &[DirtyPage]) -> Result<u64> {
    use std::os::unix::fs::FileExt;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(VmmError::Io)?;
    for page in dirty {
        // SAFETY: `host_addr` is a 4 KiB-aligned page base within a mapped guest RAM region
        // (from `collect_dirty_pages`), valid for `BRANCH_PAGE_SIZE` bytes of read.
        let src =
            unsafe { std::slice::from_raw_parts(page.host_addr as *const u8, BRANCH_PAGE_SIZE) };
        file.write_all_at(src, page.file_offset)
            .map_err(VmmError::Io)?;
    }
    Ok(dirty.len() as u64)
}

impl Machine {
    /// Create the VM: validate the config, open `/dev/kvm`, allocate and map guest
    /// RAM, set up the in-kernel IRQ chip + PIT, and create the vCPUs.
    pub fn new(config: &VmConfig) -> Result<Self> {
        Self::with_resources(config, Kvm::new()?, Vec::new())
    }

    /// Like [`Machine::new`] but uses a pre-opened `kvm` handle and pre-opened TAP
    /// fds — the jailed boot path passes both in because the confined, unprivileged
    /// VMM can no longer open `/dev/kvm` or `/dev/net/tun` itself.
    fn with_resources(config: &VmConfig, kvm: Kvm, tap_fds: Vec<RawFd>) -> Result<Self> {
        let guest_memory = Self::allocate_guest_memory(config.memory_mib)?;
        Self::with_resources_memory(config, kvm, tap_fds, guest_memory)
    }

    /// Like [`with_resources`](Self::with_resources) but takes pre-built guest memory
    /// — the seam the CoW fork path uses to hand in a `MAP_PRIVATE` file-backed
    /// mapping instead of a fresh anonymous one.
    fn with_resources_memory(
        config: &VmConfig,
        kvm: Kvm,
        tap_fds: Vec<RawFd>,
        guest_memory: GuestMemoryMmap,
    ) -> Result<Self> {
        config.validate()?;
        install_vcpu_stop_handler();

        let vm = kvm.create_vm()?;

        // On Intel hosts (including the nested KVM on CI runners, where
        // unrestricted_guest may be off) KVM_RUN requires a TSS region and an
        // identity-map page to be set before vCPUs are created — otherwise entry
        // into the guest fails outright. Place them in the MMIO hole just below
        // 4 GiB, clear of guest RAM. These are x86 ioctls (this VMM is x86_64-only).
        vm.set_identity_map_address(IDENTITY_MAP_ADDR)?;
        vm.set_tss_address(TSS_ADDR as usize)?;

        Self::register_memory(&vm, &guest_memory)?;

        // In-kernel interrupt controller + programmable interval timer. These let
        // the guest take timer/IRQ interrupts without us emulating a PIC/APIC. The
        // SPEAKER_DUMMY flag makes KVM also emulate port 0x61 (the PIT channel-2
        // gate/speaker port) in-kernel — otherwise it exits to userspace and the
        // guest's PIT-based timer calibration spins on it forever.
        vm.create_irq_chip()?;
        vm.create_pit2(kvm_pit_config {
            flags: KVM_PIT_SPEAKER_DUMMY,
            ..Default::default()
        })?;

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
            vcpu_threads: Vec::new(),
            bus: None,
            ready: None,
            vcpu_hook: None,
            tap_fds,
            vsock_listener: None,
            vcpu_stop: Arc::new(AtomicBool::new(false)),
            powered_off: Arc::new(AtomicBool::new(false)),
            vcpu_pause: Arc::new(AtomicBool::new(false)),
            vcpu_states: Vec::new(),
            checkpoint: Arc::new(Checkpoint::default()),
            device_captures: Vec::new(),
            vcpu_tids: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Build **and start** a microVM: assemble the device set (rootfs block, boot
    /// vsock, serial console, plus any configured net devices), build the kernel
    /// command line (appending the discovered `virtio_mmio.device=` params), load
    /// the kernel, configure the vCPUs for the boot protocol, and spawn a thread
    /// per vCPU. Returns once the guest is executing.
    pub fn boot(config: &VmConfig) -> Result<Self> {
        Self::boot_with_hook(config, None)
    }

    /// Like [`Machine::boot`], but installs `vcpu_hook` in each vCPU thread before
    /// it runs guest code — the seam the CLI uses to apply a seccomp filter
    /// (SPEC-1 FR-27).
    pub fn boot_with_hook(config: &VmConfig, vcpu_hook: Option<VcpuHook>) -> Result<Self> {
        let mut machine = Self::new(config)?;
        machine.vcpu_hook = vcpu_hook;
        machine.start()?;
        Ok(machine)
    }

    /// Like [`Machine::boot`], but bridge the boot vsock device to the host through
    /// `vsock_listener` (an already-bound Unix-domain listener), so the host can `exec`
    /// into the running guest over its own bridge — the non-jailed counterpart of
    /// [`fork_with_vsock`](Self::fork_with_vsock)'s child bridging. `start` consumes the
    /// listener (vs. the unbridged `Vsock::new`). With `None` this is exactly
    /// [`boot`](Self::boot).
    pub fn boot_with_vsock(
        config: &VmConfig,
        vsock_listener: Option<UnixListener>,
    ) -> Result<Self> {
        let mut machine = Self::new(config)?;
        machine.vsock_listener = vsock_listener;
        machine.start()?;
        Ok(machine)
    }

    /// Boot using resources opened by a privileged parent: an inherited `/dev/kvm`
    /// fd and one inherited TAP fd per configured net device (in config order).
    /// This is the entry point for the jailed worker, which has already been
    /// confined (namespaces/chroot/cgroup/uid-drop) and therefore cannot open these
    /// itself. `vcpu_hook` installs the per-thread seccomp filter before guest code.
    ///
    /// When present, `vsock_listener_fd` is an inherited UDS listener (already bound
    /// and listening outside the chroot) that the vsock device bridges host exec
    /// connections through (SPEC-1 FR-13). `None` keeps the vsock device
    /// readiness-only.
    ///
    /// # Safety
    /// `kvm_fd`, each entry of `tap_fds`, and `vsock_listener_fd` must be valid, open
    /// file descriptors that ownership is transferred to this call.
    pub fn boot_jailed(
        config: &VmConfig,
        kvm_fd: RawFd,
        tap_fds: Vec<RawFd>,
        vsock_listener_fd: Option<RawFd>,
        vcpu_hook: Option<VcpuHook>,
    ) -> Result<Self> {
        // SAFETY: the caller guarantees `kvm_fd` is an open /dev/kvm fd we now own.
        let kvm = unsafe { Kvm::from_raw_fd(kvm_fd) };
        let mut machine = Self::with_resources(config, kvm, tap_fds)?;
        if let Some(fd) = vsock_listener_fd {
            // SAFETY: the caller transfers ownership of an open, bound, listening UDS
            // fd; we wrap it so the vsock device can accept on it post-confinement.
            machine.vsock_listener = Some(unsafe { UnixListener::from_raw_fd(fd) });
        }
        machine.vcpu_hook = vcpu_hook;
        machine.start()?;
        Ok(machine)
    }

    /// Wire up devices, load the kernel, and launch the vCPU threads.
    fn start(&mut self) -> Result<()> {
        let mut bus = Bus::new();
        let mut mmio_cmdline = String::new();
        let mut next_mmio = MMIO_DEVICE_BASE;
        let mut next_gsi = FIRST_VIRTIO_GSI;

        // Serial console on COM1 (always present so `console=ttyS0` works).
        let serial_irq = EventFd::new(libc::EFD_NONBLOCK).map_err(VmmError::Io)?;
        self.vm.register_irqfd(&serial_irq, COM1_IRQ)?;
        // Wrap stdout so every guest console byte is flushed immediately — block
        // buffering (stdout -> pipe) otherwise swallows early kernel messages.
        let serial = Arc::new(Mutex::new(SerialDevice::new(
            serial_irq,
            Box::new(AutoFlush(std::io::stdout())),
        )));
        bus.set_serial(serial);

        // Rootfs block device (always present). Snapshottable: install a pause handle
        // so its queue cursor can be captured (SPEC-1 FR-14).
        let block = Block::new(
            &self.config.rootfs.path,
            self.config.rootfs.read_only,
            self.config.rootfs.rate_limit.clone(),
        )?;
        let mut block: Box<dyn VirtioDevice> = Box::new(block);
        self.install_device_pause(&mut block)?;
        self.attach_virtio(
            &mut bus,
            &mut mmio_cmdline,
            &mut next_mmio,
            &mut next_gsi,
            block,
        )?;

        // Boot vsock channel (always present): carries the guest "ready" signal, and
        // — when the jailed parent passed a host UDS listener — bridges Sandbox exec
        // connections to the guest (SPEC-1 FR-13).
        let vsock = match self.vsock_listener.take() {
            Some(listener) => Vsock::with_host_bridge(DEFAULT_GUEST_CID, listener)?,
            None => Vsock::new(DEFAULT_GUEST_CID)?,
        };
        self.ready = Some(vsock.ready_signal());
        let mut vsock: Box<dyn VirtioDevice> = Box::new(vsock);
        self.install_device_pause(&mut vsock)?;
        self.attach_virtio(
            &mut bus,
            &mut mmio_cmdline,
            &mut next_mmio,
            &mut next_gsi,
            vsock,
        )?;

        // Pre-opened TAP fds (jailed boot) are consumed in net-device order; an
        // empty queue means the in-process boot opens the TAP by name itself.
        let mut tap_fds = std::mem::take(&mut self.tap_fds).into_iter();

        // Configured devices: net (attach to its TAP). The boot vsock above already
        // covers M1's single vsock use; balloon is a tracked M1 TODO, so a config
        // that asks for it fails loudly rather than being silently dropped. Clone the
        // list so the loop body can take `&mut self` (e.g. install_device_pause).
        let config_devices = self.config.devices.clone();
        for device in &config_devices {
            match device {
                ConfigDevice::Net {
                    tap_name,
                    mac,
                    rate_limit,
                } => {
                    let tap = match tap_fds.next() {
                        // SAFETY: the parent passed us this open TAP fd via fd
                        // inheritance; we take exclusive ownership of it here.
                        Some(fd) => unsafe { std::fs::File::from_raw_fd(fd) },
                        None => open_tap(tap_name)?,
                    };
                    let net = Net::new(tap, parse_mac(mac)?, rate_limit.clone());
                    let mut net: Box<dyn VirtioDevice> = Box::new(net);
                    self.install_device_pause(&mut net)?;
                    self.attach_virtio(
                        &mut bus,
                        &mut mmio_cmdline,
                        &mut next_mmio,
                        &mut next_gsi,
                        net,
                    )?;
                }
                ConfigDevice::Vsock { .. } => {
                    // M1 uses the single boot vsock created above.
                }
                ConfigDevice::Balloon { target_mib } => {
                    let balloon = Balloon::new(*target_mib);
                    self.attach_virtio(
                        &mut bus,
                        &mut mmio_cmdline,
                        &mut next_mmio,
                        &mut next_gsi,
                        Box::new(balloon),
                    )?;
                }
            }
        }

        // Assemble the final cmdline and load the kernel + boot params.
        let cmdline = format!("{}{}", self.config.kernel_cmdline, mmio_cmdline);
        let mem_size = self
            .config
            .memory_mib
            .checked_mul(1 << 20)
            .ok_or_else(|| VmmError::Memory("memory size overflow".to_string()))?;
        let kernel_boot = crate::boot::load_and_configure(
            &self.guest_memory,
            &self.config.kernel,
            &cmdline,
            mem_size,
        )?;

        // Configure each vCPU for the 64-bit boot protocol.
        for vcpu in &self.vcpus {
            vcpu.configure_boot(
                &self.guest_memory,
                kernel_boot.entry_point,
                kernel_boot.boot_params_addr,
            )?;
        }

        // Hand the bus to the vCPU threads and start them.
        let bus = Arc::new(bus);
        self.bus = Some(bus.clone());
        let dispatch: Arc<dyn IoDispatch> = bus;
        for mut vcpu in std::mem::take(&mut self.vcpus) {
            let dispatch = dispatch.clone();
            let hook = self.vcpu_hook.clone();
            let stop = self.vcpu_stop.clone();
            let pause = self.vcpu_pause.clone();
            let checkpoint = self.checkpoint.clone();
            let powered_off = self.powered_off.clone();
            let tids = self.vcpu_tids.clone();
            // Per-vCPU slot the thread fills if it is paused for a snapshot.
            let pause_out = Arc::new(Mutex::new(None));
            self.vcpu_states.push(pause_out.clone());
            let handle = std::thread::Builder::new()
                .name(format!("mm-vcpu-{}", vcpu.index()))
                .spawn(move || {
                    // Register this thread so `shutdown`/`pause` can signal it out of
                    // KVM_RUN. SAFETY: `pthread_self` is always safe.
                    let tid = unsafe { libc::pthread_self() };
                    if let Ok(mut guard) = tids.lock() {
                        guard.push(tid);
                    }
                    // Run the pre-run hook (e.g. seccomp install) on this thread,
                    // after the VMM's opens, before any guest code executes.
                    let result = (|| {
                        if let Some(hook) = &hook {
                            hook(vcpu.index())?;
                        }
                        vcpu.run(&dispatch, &stop, &pause, &pause_out, &checkpoint)
                    })();
                    // Signal power-off however the run loop ended (shutdown, error, or a
                    // failed hook), so a holder of a shared Machine stops waiting on a
                    // dead guest.
                    powered_off.store(true, Ordering::Release);
                    result
                })
                .map_err(VmmError::Io)?;
            self.vcpu_threads.push(handle);
        }
        Ok(())
    }

    /// Allocate an MMIO window + GSI for `device`, register its interrupt with KVM,
    /// place its transport on the bus, and append its `virtio_mmio.device=` cmdline
    /// fragment so the guest discovers it.
    fn attach_virtio(
        &self,
        bus: &mut Bus,
        cmdline: &mut String,
        next_mmio: &mut u64,
        next_gsi: &mut u32,
        device: Box<dyn VirtioDevice>,
    ) -> Result<Arc<Mutex<MmioTransport>>> {
        let base = *next_mmio;
        let gsi = *next_gsi;

        let irq = EventFd::new(libc::EFD_NONBLOCK).map_err(VmmError::Io)?;
        self.vm.register_irqfd(&irq, gsi)?;
        let interrupt = Arc::new(Interrupt::new(irq));

        let transport = Arc::new(Mutex::new(MmioTransport::new(
            device,
            self.guest_memory.clone(),
            interrupt,
        )?));
        bus.add_mmio_device(base, MMIO_DEVICE_SIZE, transport.clone());

        // e.g. " virtio_mmio.device=4K@0xd0000000:5"
        let _ = write!(cmdline, " virtio_mmio.device=4K@0x{base:x}:{gsi}");

        *next_mmio += MMIO_DEVICE_SIZE;
        *next_gsi += 1;
        Ok(transport)
    }

    /// Wait up to `timeout` for the guest to signal readiness over the boot vsock.
    /// Returns `Ok(true)` if the guest reached userspace, `Ok(false)` on timeout.
    pub fn wait_for_ready(&self, timeout: Duration) -> Result<bool> {
        let ready = self
            .ready
            .as_ref()
            .ok_or_else(|| VmmError::Device("no vsock readiness signal".to_string()))?;
        if ready.is_ready() {
            return Ok(true);
        }
        let mut poll_fd = libc::pollfd {
            fd: ready.event_fd().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: `poll_fd` is a valid, initialized pollfd describing one fd.
        let rc = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
        if rc < 0 {
            return Err(VmmError::Io(std::io::Error::last_os_error()));
        }
        Ok(rc > 0 && (poll_fd.revents & libc::POLLIN) != 0)
    }

    /// Whether a vCPU thread has exited its run loop (the guest powered off, shut down,
    /// or a vCPU errored). Cheap and lock-free: the jailed worker's control loop holds
    /// the `Machine` behind a `Mutex` and polls this to decide when to stop serving and
    /// reap, without taking a long-lived `&mut` borrow that would block snapshots.
    pub fn is_powered_off(&self) -> bool {
        self.powered_off.load(Ordering::Acquire)
    }

    /// Serve the guest until it powers itself off: join the vCPU threads, each of
    /// which exits its run loop when KVM reports a shutdown (the guest resets via a
    /// triple fault — `reboot=t`). Unlike [`shutdown`], this does **not**
    /// force the vCPUs to stop — it is how a long-running guest (a real workload or
    /// an SSH-reachable sandbox) is run for its full lifetime. The VM is torn down
    /// abruptly only if the worker process is killed (e.g. `mm stop`).
    pub fn wait_for_vcpus(&mut self) -> Result<()> {
        for handle in self.vcpu_threads.drain(..) {
            match handle.join() {
                Ok(Ok(_exit)) => {}
                Ok(Err(e)) => tracing::error!("vcpu thread exited with error: {e}"),
                Err(_) => tracing::error!("vcpu thread panicked"),
            }
        }
        Ok(())
    }

    /// Stop the VM: ask the vCPU threads to stop and signal them out of any halted
    /// `KVM_RUN` (the in-kernel irqchip handles guest `HLT` internally, so KVM_RUN
    /// blocks rather than returning), then join them.
    pub fn shutdown(&mut self) -> Result<()> {
        self.vcpu_stop.store(true, Ordering::Release);

        let tids: Vec<libc::pthread_t> = self
            .vcpu_tids
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default();

        // Kicker: repeatedly signal the vCPU threads until they have all joined.
        // Repeating closes the race where a signal lands just before a thread
        // re-enters KVM_RUN (a thread that already exited just yields ESRCH).
        let kicker_done = Arc::new(AtomicBool::new(false));
        let kicker = {
            let done = kicker_done.clone();
            std::thread::spawn(move || {
                while !done.load(Ordering::Acquire) {
                    for &tid in &tids {
                        // SAFETY: VCPU_STOP_SIGNAL has a no-op handler; this only
                        // interrupts a blocking KVM_RUN.
                        unsafe {
                            libc::pthread_kill(tid, VCPU_STOP_SIGNAL);
                        }
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            })
        };

        for handle in self.vcpu_threads.drain(..) {
            match handle.join() {
                Ok(Ok(_exit)) => {}
                Ok(Err(e)) => tracing::error!("vcpu thread exited with error: {e}"),
                Err(_) => tracing::error!("vcpu thread panicked"),
            }
        }

        kicker_done.store(true, Ordering::Release);
        let _ = kicker.join();
        Ok(())
    }

    /// Pause the vCPUs at a quiescent point and capture each one's state for a
    /// snapshot (SPEC-1 FR-14). Sets the pause flag, kicks the threads out of any
    /// blocking `KVM_RUN` (reusing the teardown signal), joins them, and returns the
    /// captured [`VcpuState`]s in vCPU-index order. The VM is **frozen** afterwards
    /// (the vCPU threads have exited); restore rebuilds a fresh `Machine`.
    pub fn pause_and_capture_vcpus(&mut self) -> Result<Vec<VcpuState>> {
        self.vcpu_pause.store(true, Ordering::Release);

        let tids: Vec<libc::pthread_t> = self
            .vcpu_tids
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default();

        // Same repeating kicker as `shutdown`: a no-op-handler signal interrupts a
        // blocking KVM_RUN so the thread observes `vcpu_pause` and captures state.
        let kicker_done = Arc::new(AtomicBool::new(false));
        let kicker = {
            let done = kicker_done.clone();
            std::thread::spawn(move || {
                while !done.load(Ordering::Acquire) {
                    for &tid in &tids {
                        // SAFETY: VCPU_STOP_SIGNAL has a no-op handler; this only
                        // interrupts a blocking KVM_RUN.
                        unsafe {
                            libc::pthread_kill(tid, VCPU_STOP_SIGNAL);
                        }
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            })
        };

        // A capture error (or panic) is fatal for a snapshot — surface it rather than
        // silently producing a partial state file.
        let mut join_err = None;
        for handle in self.vcpu_threads.drain(..) {
            match handle.join() {
                Ok(Ok(_exit)) => {}
                Ok(Err(e)) => join_err = Some(e),
                Err(_) => {
                    join_err = Some(VmmError::Vcpu("vcpu thread panicked during pause".into()))
                }
            }
        }

        kicker_done.store(true, Ordering::Release);
        let _ = kicker.join();

        if let Some(e) = join_err {
            return Err(e);
        }

        // Drain the per-vCPU slots in index order.
        let mut states = Vec::with_capacity(self.vcpu_states.len());
        for (index, slot) in self.vcpu_states.iter().enumerate() {
            let captured = slot.lock().ok().and_then(|mut g| g.take()).ok_or_else(|| {
                VmmError::Vcpu(format!("vcpu {index} state was not captured during pause"))
            })?;
            states.push(captured);
        }
        Ok(states)
    }

    /// Pause the vCPUs at a quiescent barrier, capture each one's state, and **resume
    /// them in place** (SPEC-1 FR-16 running BRANCH) — the running counterpart to the
    /// freeze-only [`pause_and_capture_vcpus`](Self::pause_and_capture_vcpus). The vCPU
    /// threads do **not** exit: after this returns the guest keeps executing exactly
    /// where it was. Returns the captured [`VcpuState`]s in vCPU-index order (the basis
    /// a branch's children resume from).
    ///
    /// Orchestration mirrors the snapshot pause's repeating kicker but **releases** the
    /// barrier instead of joining the threads: request a checkpoint, kick the vCPUs out
    /// of any blocking `KVM_RUN` until all have parked (each captures its state before
    /// parking, so "all parked" ⇒ "all captured"), release them to resume, then read
    /// the captured slots. The barrier is released on every exit path so a vCPU is
    /// never stranded parked.
    pub fn checkpoint_in_place(&mut self) -> Result<Vec<VcpuState>> {
        self.quiesce_at_barrier(false)?;
        let states = self.collect_vcpu_states();
        // Release before propagating a capture error so a vCPU is never stranded parked.
        self.release_barrier()?;
        states
    }

    /// Capture the **full** consistent state of the running guest — vCPUs, devices, VM
    /// clock, and in-kernel irqchip/PIT — at one quiescent barrier, and **resume it in
    /// place** (SPEC-1 FR-16 running BRANCH). Unlike [`pause_and_capture_vcpus`] +
    /// [`pause_devices`] (freeze-only, for a snapshot), the vCPU threads and device
    /// workers all park at the barrier and then resume, so the parent keeps running.
    /// Returns the [`VmState`] a branch's children resume from.
    pub fn checkpoint_full_in_place(&mut self) -> Result<VmState> {
        self.quiesce_at_barrier(true)?;
        // All participants parked at a quiescent point and have filled their slots;
        // capture everything before releasing so it is one coherent point-in-time.
        let captured = (|| {
            let vcpus = self.collect_vcpu_states()?;
            let devices = self.collect_device_states()?;
            let clock = self.capture_clock()?;
            let irqchip = self.capture_irqchip()?;
            Ok(VmState {
                vcpus,
                devices,
                clock,
                irqchip,
            })
        })();
        self.release_barrier()?;
        captured
    }

    /// Snapshot a **running** guest into `out_dir` and **resume it in place** (SPEC-1
    /// FR-14). Unlike [`crate::snapshot::snapshot`] — which pauses the vCPUs and lets the
    /// device workers *exit* (the guest is frozen afterwards, for a restore-into-a-fresh-
    /// `Machine` flow) — this parks every participant at the checkpoint barrier, captures
    /// the coherent [`VmState`], dumps guest RAM **while parked**, then releases the
    /// barrier so the guest keeps executing exactly where it was. This is what the live
    /// worker (`mm snapshot` / the cluster Snapshot resource) needs: the snapshot is a
    /// side effect, not the end of the VM's life.
    ///
    /// The guest is paused for the full RAM-dump duration (fine for typical guests;
    /// [`branch`](Self::branch) is the near-zero-pause variant that copies RAM
    /// concurrently under write-protection). The resulting directory is layout-identical
    /// to a frozen [`snapshot`](crate::snapshot::snapshot), so restore is unchanged.
    pub fn snapshot_in_place(
        &mut self,
        out_dir: &Path,
    ) -> Result<crate::snapshot::SnapshotManifest> {
        std::fs::create_dir_all(out_dir).map_err(VmmError::Io)?;

        // Park vCPUs + device workers at the barrier, then capture everything and dump
        // RAM before releasing — one coherent point-in-time (nothing mutates guest state
        // while parked, exactly as the freeze path relies on for its dump).
        self.quiesce_at_barrier(true)?;
        let captured = (|| -> Result<VmState> {
            let vcpus = self.collect_vcpu_states()?;
            let devices = self.collect_device_states()?;
            let clock = self.capture_clock()?;
            let irqchip = self.capture_irqchip()?;
            self.dump_guest_memory(&out_dir.join("memory.bin"))?;
            Ok(VmState {
                vcpus,
                devices,
                clock,
                irqchip,
            })
        })();
        // Resume on every path so a vCPU is never stranded parked; surface a capture
        // error in preference to a release error.
        let released = self.release_barrier();
        let vm_state = captured?;
        released?;

        let host = crate::snapshot::manifest::HostFingerprint {
            cpuid_hash: self.cpuid_hash()?,
            tsc_khz: vm_state.vcpus.first().map_or(0, |v| v.tsc_khz),
        };
        let manifest = crate::snapshot::SnapshotManifest {
            version: crate::snapshot::SnapshotManifest::CURRENT_VERSION,
            vcpu_count: self.config().vcpus,
            memory_mib: self.config().memory_mib,
            memory_file: "memory.bin".into(),
            state_file: "state.bin".into(),
            kind: crate::snapshot::SnapshotKind::Full,
            parent_uid: None,
            host,
        };
        crate::snapshot::engine::write_snapshot_metadata(out_dir, &vm_state, &manifest)?;
        Ok(manifest)
    }

    /// Request a checkpoint and quiesce all participants at the barrier: optionally wake
    /// the device workers (so they drain in-flight DMA, capture their cursors, and park),
    /// then kick the vCPUs out of `KVM_RUN` until **every** participant has parked. Each
    /// participant fills its capture slot before parking, so "all parked" ⇒ "all
    /// captured". On timeout the barrier is released so no participant is stranded.
    fn quiesce_at_barrier(&self, include_devices: bool) -> Result<()> {
        let n_vcpu = self.vcpu_states.len();
        if n_vcpu == 0 {
            return Err(VmmError::Vcpu("checkpoint: no running vcpus".into()));
        }
        let n_dev = if include_devices {
            self.device_captures.len()
        } else {
            0
        };
        let total = n_vcpu + n_dev;

        self.checkpoint.request();
        // The device workers only consult the checkpoint when their pause eventfd fires,
        // so wake them explicitly; the vCPUs are kicked out of KVM_RUN below.
        if include_devices {
            for cap in &self.device_captures {
                cap.evt.write(1).map_err(VmmError::Io)?;
            }
        }

        let tids: Vec<libc::pthread_t> = self
            .vcpu_tids
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default();

        let deadline = Instant::now() + Duration::from_secs(10);
        while !self
            .checkpoint
            .wait_until_parked(total, Duration::from_millis(20))
        {
            for &tid in &tids {
                // SAFETY: VCPU_STOP_SIGNAL has a no-op handler; this only interrupts a
                // blocking KVM_RUN so the thread observes the checkpoint request.
                unsafe {
                    libc::pthread_kill(tid, VCPU_STOP_SIGNAL);
                }
            }
            if Instant::now() >= deadline {
                self.checkpoint.release();
                let _ = self.checkpoint.wait_until_resumed(Duration::from_secs(2));
                return Err(VmmError::Vcpu(
                    "participants did not reach the checkpoint barrier within the timeout".into(),
                ));
            }
        }
        Ok(())
    }

    /// Release the checkpoint barrier and wait for every participant to leave it, so the
    /// guest is fully running again and a subsequent checkpoint starts from a clean slate.
    fn release_barrier(&self) -> Result<()> {
        self.checkpoint.release();
        if !self.checkpoint.wait_until_resumed(Duration::from_secs(5)) {
            return Err(VmmError::Vcpu(
                "participants did not resume from the checkpoint barrier within the timeout".into(),
            ));
        }
        Ok(())
    }

    /// Drain the per-vCPU capture slots in index order. Call while parked (after
    /// [`quiesce_at_barrier`](Self::quiesce_at_barrier)); the slots are stable because a
    /// participant fills its slot before parking and does not touch it again until the
    /// next checkpoint.
    fn collect_vcpu_states(&self) -> Result<Vec<VcpuState>> {
        let mut states = Vec::with_capacity(self.vcpu_states.len());
        for (index, slot) in self.vcpu_states.iter().enumerate() {
            let captured = slot.lock().ok().and_then(|mut g| g.take()).ok_or_else(|| {
                VmmError::Vcpu(format!(
                    "vcpu {index} state was not captured at the checkpoint"
                ))
            })?;
            states.push(captured);
        }
        Ok(states)
    }

    /// Drain the device capture slots in attach order. Call while parked (after a
    /// device-inclusive [`quiesce_at_barrier`](Self::quiesce_at_barrier)).
    fn collect_device_states(&self) -> Result<Vec<DeviceState>> {
        let mut out = Vec::with_capacity(self.device_captures.len());
        for cap in &self.device_captures {
            let cursors = cap
                .slot
                .lock()
                .ok()
                .and_then(|mut g| g.take())
                .ok_or_else(|| {
                    VmmError::Device(
                        "a device did not capture its queue cursors at the checkpoint".into(),
                    )
                })?;
            out.push(DeviceState {
                device_type: cap.device_type,
                queues: cursors,
            });
        }
        Ok(out)
    }

    /// **Branch** a running microVM into `out_dir` (SPEC-1 FR-16): produce a coherent
    /// point-in-time snapshot directory (`manifest.json` + `state.bin` + `memory.bin`)
    /// **without freezing the parent for a full RAM dump**. The parent is paused only
    /// briefly twice (at two barriers); in between it keeps running while its RAM is copied.
    ///
    /// Uses **KVM dirty-page logging** (the standard live-migration technique) so the image
    /// is coherent at the *final* barrier (call it T2):
    ///
    /// 1. Park at an initial barrier; enable `KVM_MEM_LOG_DIRTY_PAGES` over guest RAM (from
    ///    a clean baseline); resume.
    /// 2. Copy all of guest RAM into `memory.bin` while the parent runs. Pages the parent —
    ///    *or KVM itself* (pvclock/steal-time/PV-EOI host-side writes, which no userspace
    ///    write-protect can intercept) — touches during the copy are recorded in the dirty
    ///    log.
    /// 3. Park at the final barrier (T2); capture vCPU/device/clock/irqchip state **at T2**,
    ///    re-copy every page KVM marked dirty (now stable, parked) so the whole image is
    ///    coherent at T2, disable dirty logging, and resume.
    ///
    /// Capturing the CPU/device state at the *same* instant the dirtied pages are re-copied
    /// is what makes the image consistent — re-copying at T2 with CPU state from an earlier
    /// instant would tear timekeeping/PV state and the clone faults in the kernel timer
    /// path. The resulting directory is layout-identical to a frozen
    /// [`snapshot`](crate::snapshot::snapshot), so children fork from it with the proven
    /// `MAP_PRIVATE` path ([`fork_children`](crate::snapshot::fork_children)).
    ///
    /// Returns the written [`SnapshotManifest`] plus how the image was materialized (see
    /// [`BranchOutcome`]).
    pub fn branch(&mut self, out_dir: &std::path::Path) -> Result<BranchOutcome> {
        std::fs::create_dir_all(out_dir).map_err(VmmError::Io)?;
        let mem_file = out_dir.join("memory.bin");
        let regions = self.guest_ram_regions();

        // 1. Park, enable dirty logging from a clean baseline, resume. Any write from here
        //    on (guest vCPU *or* KVM host-side) is recorded for the re-copy at step 3.
        self.quiesce_at_barrier(true)?;
        let armed = (|| -> Result<()> {
            self.set_dirty_logging(true)?;
            self.collect_dirty_pages()?; // drain+discard so logging starts clean
            Ok(())
        })();
        if let Err(e) = armed {
            let _ = self.set_dirty_logging(false);
            let _ = self.release_barrier();
            return Err(e);
        }
        self.release_barrier()?;

        // 2. Copy all of guest RAM while the parent runs (vCPUs execute on their own
        //    threads). Pages written during this copy are caught by the dirty log.
        let copied = match write_branch_image(&regions, &mem_file) {
            Ok(c) => c,
            Err(e) => {
                self.quiesce_at_barrier(true)?;
                let _ = self.set_dirty_logging(false);
                let _ = self.release_barrier();
                return Err(e);
            }
        };

        // 3. Final barrier (T2): capture coherent state and re-copy the dirtied pages so the
        //    whole image matches T2, then stop logging.
        self.quiesce_at_barrier(true)?;
        let finished = (|| -> Result<(VmState, u64)> {
            let vcpus = self.collect_vcpu_states()?;
            let devices = self.collect_device_states()?;
            let clock = self.capture_clock()?;
            let irqchip = self.capture_irqchip()?;
            let dirty = self.collect_dirty_pages()?;
            let recopied = recopy_branch_pages(&mem_file, &dirty)?;
            Ok((
                VmState {
                    vcpus,
                    devices,
                    clock,
                    irqchip,
                },
                recopied,
            ))
        })();
        let _ = self.set_dirty_logging(false);
        let released = self.release_barrier();
        let (vm_state, recopied) = match finished {
            Ok(v) => v,
            Err(e) => {
                let _ = released;
                return Err(e);
            }
        };
        released?;
        eprintln!(
            "branch: dirty-log snapshot — {copied} pages copied live, {recopied} re-copied coherently at the final barrier"
        );

        // 4. Write the snapshot metadata; memory.bin is now the coherent T2 image.
        let host = HostFingerprint {
            cpuid_hash: self.cpuid_hash()?,
            tsc_khz: vm_state.vcpus.first().map_or(0, |v| v.tsc_khz),
        };
        let manifest = crate::snapshot::SnapshotManifest {
            version: crate::snapshot::SnapshotManifest::CURRENT_VERSION,
            vcpu_count: self.config().vcpus,
            memory_mib: self.config().memory_mib,
            memory_file: "memory.bin".into(),
            state_file: "state.bin".into(),
            kind: crate::snapshot::SnapshotKind::Full,
            parent_uid: None,
            host,
        };
        crate::snapshot::engine::write_snapshot_metadata(out_dir, &vm_state, &manifest)?;
        Ok(BranchOutcome {
            manifest,
            copied,
            recopied,
        })
    }

    /// The parent's guest RAM regions as `(host_base_addr, len_bytes)` in ascending
    /// guest-address order (the same order as the KVM memslots and the `memory.bin` layout).
    fn guest_ram_regions(&self) -> Vec<(usize, usize)> {
        use vm_memory::{GuestMemory, GuestMemoryRegion};
        self.guest_memory
            .iter()
            .map(|r| (r.as_ptr() as usize, r.len() as usize))
            .collect()
    }

    /// Enable (or disable) `KVM_MEM_LOG_DIRTY_PAGES` on every guest RAM memslot by
    /// re-setting it with the same mapping but new flags. Enabling makes KVM track every
    /// write to guest RAM — by the guest's vCPUs *and* by KVM's own paravirt writes — in a
    /// per-slot dirty bitmap; disabling frees the bitmap.
    fn set_dirty_logging(&self, enable: bool) -> Result<()> {
        use vm_memory::{GuestMemory, GuestMemoryRegion};
        let flags = if enable { KVM_MEM_LOG_DIRTY_PAGES } else { 0 };
        for (slot, region) in self.guest_memory.iter().enumerate() {
            let memory_region = kvm_userspace_memory_region {
                slot: slot as u32,
                guest_phys_addr: region.start_addr().raw_value(),
                memory_size: region.len(),
                userspace_addr: region.as_ptr() as u64,
                flags,
            };
            // SAFETY: same mapping the slot was created with (register_memory); only the
            // flags change. `guest_memory` outlives the VM, so the mapping stays valid.
            unsafe {
                self.vm.set_user_memory_region(memory_region)?;
            }
        }
        Ok(())
    }

    /// Read and clear the dirty bitmap of every guest RAM memslot, returning the host
    /// address + `memory.bin` file offset of each page written since logging was enabled
    /// (or since the last call). `memory.bin` lays regions out in slot order, so the file
    /// offset is the running byte count of preceding regions plus the page's offset.
    fn collect_dirty_pages(&self) -> Result<Vec<DirtyPage>> {
        use vm_memory::{GuestMemory, GuestMemoryRegion};
        let mut pages = Vec::new();
        let mut file_base = 0u64;
        for (slot, region) in self.guest_memory.iter().enumerate() {
            let len = region.len();
            let bitmap = self
                .vm
                .get_dirty_log(slot as u32, len as usize)
                .map_err(VmmError::Kvm)?;
            let host_base = region.as_ptr() as usize;
            for (word_idx, word) in bitmap.iter().enumerate() {
                if *word == 0 {
                    continue;
                }
                for bit in 0..64 {
                    if word & (1u64 << bit) == 0 {
                        continue;
                    }
                    let page = word_idx * 64 + bit;
                    let page_off = (page * BRANCH_PAGE_SIZE) as u64;
                    if page_off >= len {
                        continue; // bitmap is rounded up to a word; ignore padding bits
                    }
                    pages.push(DirtyPage {
                        host_addr: host_base + page * BRANCH_PAGE_SIZE,
                        file_offset: file_base + page_off,
                    });
                }
            }
            file_base += len;
        }
        Ok(pages)
    }

    /// Create a snapshot pause handle, give one end to `device`, and record the other
    /// for [`pause_devices`](Self::pause_devices). Call once per snapshottable device
    /// before it is activated.
    fn install_device_pause(&mut self, device: &mut Box<dyn VirtioDevice>) -> Result<()> {
        let evt = EventFd::new(libc::EFD_NONBLOCK).map_err(VmmError::Io)?;
        let slot = Arc::new(Mutex::new(None));
        device.set_pause_handle(DevicePause {
            evt: evt.try_clone().map_err(VmmError::Io)?,
            slot: slot.clone(),
            // Shared barrier: a checkpoint (FR-16) makes the worker park-and-resume; a
            // freeze (FR-14) — no checkpoint requested — makes it exit after capturing.
            checkpoint: self.checkpoint.clone(),
        });
        self.device_captures.push(DeviceCapture {
            device_type: device.device_type(),
            evt,
            slot,
        });
        Ok(())
    }

    /// Quiesce the snapshottable devices and capture each one's queue cursors for a
    /// snapshot (SPEC-1 FR-14), in device-attach order. Call **after**
    /// [`pause_and_capture_vcpus`](Self::pause_and_capture_vcpus) — the guest is then
    /// frozen, so each device's worker drains to a stable point before capturing.
    pub fn pause_devices(&self) -> Result<Vec<DeviceState>> {
        let mut out = Vec::with_capacity(self.device_captures.len());
        for cap in &self.device_captures {
            cap.evt.write(1).map_err(VmmError::Io)?;
            let cursors = Self::wait_for_capture(&cap.slot, Duration::from_secs(2))?;
            out.push(DeviceState {
                device_type: cap.device_type,
                queues: cursors,
            });
        }
        Ok(out)
    }

    /// Poll a device's capture slot until its worker fills it, or time out.
    fn wait_for_capture(
        slot: &Mutex<Option<Vec<QueueCursor>>>,
        timeout: Duration,
    ) -> Result<Vec<QueueCursor>> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(cursors) = slot.lock().ok().and_then(|mut g| g.take()) {
                return Ok(cursors);
            }
            if Instant::now() >= deadline {
                return Err(VmmError::Device(
                    "a device did not capture its queue cursors within the pause timeout"
                        .to_string(),
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
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

    /// Capture the VM-wide kvm-clock master clock for a snapshot (SPEC-1 FR-14).
    pub fn capture_clock(&self) -> Result<kvm_clock_data> {
        self.vm.get_clock().map_err(VmmError::Kvm)
    }

    /// Restore the VM-wide kvm-clock master clock at restore time.
    pub fn restore_clock(&self, clock: &kvm_clock_data) -> Result<()> {
        self.vm.set_clock(clock).map_err(VmmError::Kvm)
    }

    /// Capture the in-kernel interrupt-controller (PIC master/slave + IOAPIC) and PIT
    /// state for a snapshot (SPEC-1 FR-14). Restored by [`restore_irqchip`] before any
    /// vCPU runs; without it a resumed/forked guest's interrupt routing (e.g. the COM1
    /// serial IRQ) is reset to defaults while the guest still expects what it
    /// programmed, and it oopses in the interrupt path on the first device interrupt.
    pub fn capture_irqchip(&self) -> Result<IrqChipState> {
        Ok(IrqChipState {
            pic_master: self.get_irqchip_bytes(KVM_IRQCHIP_PIC_MASTER)?,
            pic_slave: self.get_irqchip_bytes(KVM_IRQCHIP_PIC_SLAVE)?,
            ioapic: self.get_irqchip_bytes(KVM_IRQCHIP_IOAPIC)?,
            pit: pit_to_bytes(&self.vm.get_pit2().map_err(VmmError::Kvm)?),
        })
    }

    /// Restore the in-kernel irqchip + PIT state captured by [`capture_irqchip`]. Must
    /// run before the vCPU threads start so interrupt routing is in place when guest
    /// code first touches an interrupt-driven device.
    pub fn restore_irqchip(&self, state: &IrqChipState) -> Result<()> {
        self.set_irqchip_bytes(KVM_IRQCHIP_PIC_MASTER, &state.pic_master)?;
        self.set_irqchip_bytes(KVM_IRQCHIP_PIC_SLAVE, &state.pic_slave)?;
        self.set_irqchip_bytes(KVM_IRQCHIP_IOAPIC, &state.ioapic)?;
        self.vm
            .set_pit2(&pit_from_bytes(&state.pit)?)
            .map_err(VmmError::Kvm)
    }

    /// `KVM_GET_IRQCHIP` for one chip, returned as the raw bytes of the whole
    /// `kvm_irqchip` (chip id + union), which [`set_irqchip_bytes`] feeds back verbatim.
    fn get_irqchip_bytes(&self, chip_id: u32) -> Result<Vec<u8>> {
        let mut chip = kvm_irqchip {
            chip_id,
            ..Default::default()
        };
        self.vm.get_irqchip(&mut chip).map_err(VmmError::Kvm)?;
        Ok(irqchip_to_bytes(&chip))
    }

    /// `KVM_SET_IRQCHIP` from bytes produced by [`get_irqchip_bytes`] (the embedded
    /// `chip_id` selects the chip).
    fn set_irqchip_bytes(&self, chip_id: u32, bytes: &[u8]) -> Result<()> {
        let chip = irqchip_from_bytes(chip_id, bytes)?;
        self.vm.set_irqchip(&chip).map_err(VmmError::Kvm)
    }

    /// Dump all guest RAM regions, in ascending address order, to `path` — the
    /// snapshot `memory_file`. Streamed in 1 MiB chunks so large guests don't need a
    /// full-size host buffer.
    pub fn dump_guest_memory(&self, path: &Path) -> Result<()> {
        let mut file = File::create(path).map_err(VmmError::Io)?;
        let mut buf = vec![0u8; 1 << 20];
        for region in self.guest_memory.iter() {
            let start = region.start_addr();
            let len = region.len();
            let mut offset = 0u64;
            while offset < len {
                let n = ((len - offset) as usize).min(buf.len());
                let addr = start
                    .checked_add(offset)
                    .ok_or_else(|| VmmError::Memory("dump: address overflow".to_string()))?;
                self.guest_memory
                    .read_slice(&mut buf[..n], addr)
                    .map_err(|e| VmmError::Memory(format!("dump read: {e}")))?;
                file.write_all(&buf[..n]).map_err(VmmError::Io)?;
                offset += n as u64;
            }
        }
        file.flush().map_err(VmmError::Io)?;
        Ok(())
    }

    /// Load guest RAM from a snapshot `memory_file` (the inverse of
    /// [`dump_guest_memory`](Self::dump_guest_memory)), in the same region order.
    pub fn load_guest_memory(&self, path: &Path) -> Result<()> {
        let mut file = File::open(path).map_err(VmmError::Io)?;
        let mut buf = vec![0u8; 1 << 20];
        for region in self.guest_memory.iter() {
            let start = region.start_addr();
            let len = region.len();
            let mut offset = 0u64;
            while offset < len {
                let n = ((len - offset) as usize).min(buf.len());
                file.read_exact(&mut buf[..n]).map_err(VmmError::Io)?;
                let addr = start
                    .checked_add(offset)
                    .ok_or_else(|| VmmError::Memory("load: address overflow".to_string()))?;
                self.guest_memory
                    .write_slice(&buf[..n], addr)
                    .map_err(|e| VmmError::Memory(format!("load write: {e}")))?;
                offset += n as u64;
            }
        }
        Ok(())
    }

    /// Restore a snapshot into a fresh, running microVM (SPEC-1 FR-14). Like
    /// [`boot_jailed`](Self::boot_jailed) it takes the inherited KVM/TAP/vsock fds,
    /// but instead of loading a kernel and configuring the boot protocol it loads the
    /// guest RAM from `mem_path`, rebuilds the devices from their saved queue cursors,
    /// restores each vCPU's state + the VM clock, and resumes execution mid-flight.
    ///
    /// # Safety
    /// `kvm_fd`, `tap_fds`, and `vsock_listener_fd` must be valid open fds whose
    /// ownership transfers to this call.
    #[allow(clippy::too_many_arguments)]
    pub fn restore_jailed(
        config: &VmConfig,
        kvm_fd: RawFd,
        tap_fds: Vec<RawFd>,
        vsock_listener_fd: Option<RawFd>,
        vcpu_hook: Option<VcpuHook>,
        state: VmState,
        mem_path: &Path,
        expected_host: &HostFingerprint,
    ) -> Result<Self> {
        // SAFETY: the caller guarantees `kvm_fd` is an open /dev/kvm fd we now own.
        let kvm = unsafe { Kvm::from_raw_fd(kvm_fd) };
        let mut machine = Self::with_resources(config, kvm, tap_fds)?;
        // Refuse a cross-host restore onto an incompatible CPU before touching guest
        // state, so the failure is loud and cheap rather than a guest crash mid-run.
        machine.verify_host(expected_host)?;
        if let Some(fd) = vsock_listener_fd {
            // SAFETY: caller transfers an open, bound, listening UDS fd.
            machine.vsock_listener = Some(unsafe { UnixListener::from_raw_fd(fd) });
        }
        machine.vcpu_hook = vcpu_hook;
        machine.restore_start(state, mem_path)?;
        Ok(machine)
    }

    /// Restore a snapshot in-process (opens `/dev/kvm` itself), the restore
    /// counterpart to [`boot`](Self::boot). For the non-jailed path (tests, local
    /// single-host restore without inherited fds).
    pub fn restore(
        config: &VmConfig,
        state: VmState,
        mem_path: &Path,
        expected_host: &HostFingerprint,
    ) -> Result<Self> {
        let mut machine = Self::with_resources(config, Kvm::new()?, Vec::new())?;
        machine.verify_host(expected_host)?;
        machine.restore_start(state, mem_path)?;
        Ok(machine)
    }

    /// Hash of this host's KVM-supported CPUID leaves — the guest-visible CPU feature
    /// set a snapshot taken here is tied to. Recorded in the manifest at snapshot and
    /// compared at restore (see [`HostFingerprint`]).
    pub fn cpuid_hash(&self) -> Result<u64> {
        cpuid_hash(&self.kvm)
    }

    /// Refuse to restore a snapshot taken on `expected` onto this host if the CPU
    /// feature sets differ (which would crash the guest). A no-op for a snapshot with
    /// an unset fingerprint (taken before fingerprinting existed).
    fn verify_host(&self, expected: &HostFingerprint) -> Result<()> {
        let live = HostFingerprint {
            cpuid_hash: cpuid_hash(&self.kvm)?,
            tsc_khz: 0,
        };
        expected.check_restore_onto(&live).map_err(VmmError::Device)
    }

    /// Fork a running child microVM from a snapshot via copy-on-write memory
    /// (SPEC-1 FR-15). The child's guest RAM is a `MAP_PRIVATE` mapping of the
    /// parent's `memory_file`, so unmodified pages stay shared and only written pages
    /// are copied — the fast path for fanning many children off one warmed parent
    /// (NFR-P2). The RAM is *not* loaded byte-by-byte (the mapping already is the
    /// RAM); the child then restores device/clock/vCPU state and resumes. Opens
    /// `/dev/kvm` itself (non-jailed); `config` must match the snapshot.
    pub fn fork(config: &VmConfig, state: VmState, mem_path: &Path) -> Result<Self> {
        Self::fork_with_vsock(config, state, mem_path, None)
    }

    /// Like [`fork`](Self::fork), but bridge the child's vsock device to the host
    /// through `vsock_listener` (an already-bound Unix-domain listener), so the host
    /// can `exec` into the forked child over its own bridge. Each child must get a
    /// *distinct* listener — that is what makes them independently reachable and lets a
    /// test prove per-child guest isolation end-to-end (not just at the host
    /// memory-mapping level). With `None` the child's vsock is unbridged (the lean
    /// fan-out path that needs no host exec channel).
    pub fn fork_with_vsock(
        config: &VmConfig,
        state: VmState,
        mem_path: &Path,
        vsock_listener: Option<UnixListener>,
    ) -> Result<Self> {
        let guest_memory = Self::allocate_cow_guest_memory(config.memory_mib, mem_path)?;
        let mut machine =
            Self::with_resources_memory(config, Kvm::new()?, Vec::new(), guest_memory)?;
        // Set before resume: `resume_from_state` takes the listener to build a
        // host-bridged vsock (vs. the unbridged `Vsock::new`).
        machine.vsock_listener = vsock_listener;
        machine.resume_from_state(state)?;
        Ok(machine)
    }

    /// Build CoW guest memory backed by the snapshot `memory_file`: each RAM region is
    /// `mmap(MAP_PRIVATE)` of the corresponding slice of the file, so forked children
    /// share the parent's pages until they write (SPEC-1 FR-15). The region layout
    /// mirrors [`allocate_guest_memory`](Self::allocate_guest_memory); the file holds
    /// the regions concatenated in ascending-address order (as written by
    /// [`dump_guest_memory`](Self::dump_guest_memory)).
    fn allocate_cow_guest_memory(memory_mib: u64, mem_path: &Path) -> Result<GuestMemoryMmap> {
        use vm_memory::mmap::MmapRegionBuilder;
        use vm_memory::FileOffset;

        let file = File::open(mem_path).map_err(VmmError::Io)?;
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

        let mut regions = Vec::with_capacity(ranges.len());
        let mut file_offset = 0u64;
        for (gpa, size) in ranges {
            let fo = FileOffset::new(file.try_clone().map_err(VmmError::Io)?, file_offset);
            let region = MmapRegionBuilder::new(size)
                // PROT_READ|PROT_WRITE is required: the builder defaults to PROT_NONE,
                // and KVM (and the host) must be able to read/write guest RAM — without
                // it KVM_RUN faults with EFAULT and host accesses SIGSEGV.
                .with_mmap_prot(libc::PROT_READ | libc::PROT_WRITE)
                .with_mmap_flags(libc::MAP_NORESERVE | libc::MAP_PRIVATE)
                .with_file_offset(fo)
                .build()
                .map_err(|e| VmmError::Memory(format!("cow mmap: {e:?}")))?;
            regions.push(
                GuestRegionMmap::new(region, gpa)
                    .map_err(|e| VmmError::Memory(format!("cow region: {e:?}")))?,
            );
            file_offset += size as u64;
        }
        GuestMemoryMmap::from_regions(regions)
            .map_err(|e| VmmError::Memory(format!("cow from_regions: {e:?}")))
    }

    /// Restore a snapshot whose RAM lives in a file: load it into anonymous guest
    /// memory, then resume. The CoW fork path skips the load (its memory *is* the
    /// file, mapped `MAP_PRIVATE`) and calls [`resume_from_state`](Self::resume_from_state) directly.
    fn restore_start(&mut self, state: VmState, mem_path: &Path) -> Result<()> {
        // Guest RAM (kernel, page tables, and the virtqueue rings all live here).
        self.load_guest_memory(mem_path)?;
        self.resume_from_state(state)
    }

    /// Wire the device model + vCPUs from a snapshot and resume — the restore
    /// counterpart to [`start`](Self::start), assuming guest RAM is already in place
    /// (loaded from a file by restore, or CoW-mapped by fork). Attaches each device
    /// and re-activates it from its saved cursors (bypassing the guest's `DRIVER_OK`
    /// handshake, since the guest is mid-execution), restores vCPU + clock state, and
    /// spawns the (already-running) vCPU threads. No kernel load, no `configure_boot`.
    fn resume_from_state(&mut self, state: VmState) -> Result<()> {
        let mut bus = Bus::new();
        // The cmdline is discarded on restore — the guest already booted and its
        // drivers are bound to the (deterministic) MMIO addresses recreated below.
        let mut cmdline = String::new();
        let mut next_mmio = MMIO_DEVICE_BASE;
        let mut next_gsi = FIRST_VIRTIO_GSI;

        let serial_irq = EventFd::new(libc::EFD_NONBLOCK).map_err(VmmError::Io)?;
        self.vm.register_irqfd(&serial_irq, COM1_IRQ)?;
        let serial = Arc::new(Mutex::new(SerialDevice::new(
            serial_irq,
            Box::new(AutoFlush(std::io::stdout())),
        )));
        bus.set_serial(serial);

        // Device cursors, consumed in the same attach order they were captured.
        let mut device_states = state.devices.into_iter();

        // 2. Devices, in the same order as `start`: block, vsock, then nets. Each is
        //    re-activated from its saved cursors instead of waiting for DRIVER_OK.
        let block = Block::new(
            &self.config.rootfs.path,
            self.config.rootfs.read_only,
            self.config.rootfs.rate_limit.clone(),
        )?;
        let mut block: Box<dyn VirtioDevice> = Box::new(block);
        self.install_device_pause(&mut block)?;
        let block_t =
            self.attach_virtio(&mut bus, &mut cmdline, &mut next_mmio, &mut next_gsi, block)?;
        restore_activate_next(&block_t, device_states.next())?;

        let vsock = match self.vsock_listener.take() {
            Some(listener) => Vsock::with_host_bridge(DEFAULT_GUEST_CID, listener)?,
            None => Vsock::new(DEFAULT_GUEST_CID)?,
        };
        self.ready = Some(vsock.ready_signal());
        let mut vsock: Box<dyn VirtioDevice> = Box::new(vsock);
        self.install_device_pause(&mut vsock)?;
        let vsock_t =
            self.attach_virtio(&mut bus, &mut cmdline, &mut next_mmio, &mut next_gsi, vsock)?;
        restore_activate_next(&vsock_t, device_states.next())?;

        let config_devices = self.config.devices.clone();
        let mut tap_fds = std::mem::take(&mut self.tap_fds).into_iter();
        for device in &config_devices {
            if let ConfigDevice::Net {
                tap_name,
                mac,
                rate_limit,
            } = device
            {
                let tap = match tap_fds.next() {
                    // SAFETY: inherited open TAP fd; we take ownership.
                    Some(fd) => unsafe { File::from_raw_fd(fd) },
                    None => open_tap(tap_name)?,
                };
                let net = Net::new(tap, parse_mac(mac)?, rate_limit.clone());
                let mut net: Box<dyn VirtioDevice> = Box::new(net);
                self.install_device_pause(&mut net)?;
                let net_t =
                    self.attach_virtio(&mut bus, &mut cmdline, &mut next_mmio, &mut next_gsi, net)?;
                restore_activate_next(&net_t, device_states.next())?;
            }
        }

        // 3. Restore the VM-wide clock before any vCPU runs, so the guest's paravirt
        //    clock does not jump.
        self.restore_clock(&state.clock)?;

        // 3b. Restore the in-kernel irqchip (PIC + IOAPIC) and PIT before any vCPU
        //     runs, so interrupt routing matches what the (restored) guest programmed.
        //     The fresh VM's irqchip is otherwise at defaults and the guest oopses in
        //     the interrupt path on its first interrupt-driven device access. Older
        //     snapshots without this state carry empty byte vectors — skip those so a
        //     pre-existing snapshot still restores (just without irqchip fidelity).
        if !state.irqchip.ioapic.is_empty() {
            self.restore_irqchip(&state.irqchip)?;
        }

        // 4. Hand the bus to the vCPU threads, restore each vCPU's state, and resume.
        let bus = Arc::new(bus);
        self.bus = Some(bus.clone());
        let dispatch: Arc<dyn IoDispatch> = bus;
        let mut vcpu_states = state.vcpus.into_iter();
        for mut vcpu in std::mem::take(&mut self.vcpus) {
            let vstate = vcpu_states.next().ok_or_else(|| {
                VmmError::Vcpu(format!("restore: no saved state for vcpu {}", vcpu.index()))
            })?;
            vcpu.restore_state(&vstate)?;

            let dispatch = dispatch.clone();
            let hook = self.vcpu_hook.clone();
            let stop = self.vcpu_stop.clone();
            let pause = self.vcpu_pause.clone();
            let checkpoint = self.checkpoint.clone();
            let powered_off = self.powered_off.clone();
            let tids = self.vcpu_tids.clone();
            let pause_out = Arc::new(Mutex::new(None));
            self.vcpu_states.push(pause_out.clone());
            let handle = std::thread::Builder::new()
                .name(format!("mm-vcpu-{}", vcpu.index()))
                .spawn(move || {
                    // SAFETY: `pthread_self` is always safe.
                    let tid = unsafe { libc::pthread_self() };
                    if let Ok(mut guard) = tids.lock() {
                        guard.push(tid);
                    }
                    let result = (|| {
                        if let Some(hook) = &hook {
                            hook(vcpu.index())?;
                        }
                        vcpu.run(&dispatch, &stop, &pause, &pause_out, &checkpoint)
                    })();
                    // Signal power-off on any exit path (see the boot spawn site).
                    powered_off.store(true, Ordering::Release);
                    result
                })
                .map_err(VmmError::Io)?;
            self.vcpu_threads.push(handle);
        }
        Ok(())
    }
}

/// Serialize a `kvm_irqchip` to its raw bytes for the snapshot state file.
fn irqchip_to_bytes(chip: &kvm_irqchip) -> Vec<u8> {
    // SAFETY: `kvm_irqchip` is a fixed-size `repr(C)` POD (a chip id plus a union of
    // PIC/IOAPIC state); reading `size_of` bytes of it is sound and restorable.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (chip as *const kvm_irqchip).cast::<u8>(),
            std::mem::size_of::<kvm_irqchip>(),
        )
    };
    bytes.to_vec()
}

/// Rebuild a `kvm_irqchip` from snapshot bytes, forcing `chip_id` (which selects the
/// chip for `KVM_SET_IRQCHIP`) and validating the length.
fn irqchip_from_bytes(chip_id: u32, bytes: &[u8]) -> Result<kvm_irqchip> {
    let want = std::mem::size_of::<kvm_irqchip>();
    if bytes.len() != want {
        return Err(VmmError::Device(format!(
            "snapshot irqchip state is {} bytes, expected {want}",
            bytes.len()
        )));
    }
    let mut chip = kvm_irqchip::default();
    // SAFETY: `kvm_irqchip` is POD; copy exactly `size_of` bytes into a zeroed instance
    // (length checked above).
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            (&mut chip as *mut kvm_irqchip).cast::<u8>(),
            want,
        );
    }
    chip.chip_id = chip_id;
    Ok(chip)
}

/// Serialize a `kvm_pit_state2` to its raw bytes for the snapshot state file.
fn pit_to_bytes(pit: &kvm_pit_state2) -> Vec<u8> {
    // SAFETY: `kvm_pit_state2` is a fixed-size `repr(C)` POD.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (pit as *const kvm_pit_state2).cast::<u8>(),
            std::mem::size_of::<kvm_pit_state2>(),
        )
    };
    bytes.to_vec()
}

/// Rebuild a `kvm_pit_state2` from snapshot bytes, validating the length.
fn pit_from_bytes(bytes: &[u8]) -> Result<kvm_pit_state2> {
    let want = std::mem::size_of::<kvm_pit_state2>();
    if bytes.len() != want {
        return Err(VmmError::Device(format!(
            "snapshot PIT state is {} bytes, expected {want}",
            bytes.len()
        )));
    }
    let mut pit = kvm_pit_state2::default();
    // SAFETY: `kvm_pit_state2` is POD; copy exactly `size_of` bytes into a zeroed
    // instance (length checked above).
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            (&mut pit as *mut kvm_pit_state2).cast::<u8>(),
            want,
        );
    }
    Ok(pit)
}

/// FNV-1a hash of the host's KVM-supported CPUID leaves — a stable, order-sensitive
/// fingerprint of the guest-visible CPU feature set. Recorded in a snapshot's manifest
/// so a restore can refuse a host whose features differ (which would crash the guest).
fn cpuid_hash(kvm: &Kvm) -> Result<u64> {
    let cpuid = kvm
        .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
        .map_err(VmmError::Kvm)?;

    // The fingerprint must be identical for two calls on the *same* host — otherwise a
    // same-host snapshot→restore round trip wrongly trips the cross-host guard (it did:
    // `snapshot_restore_round_trip_preserves_state` failed with two different hashes).
    // Two sources of same-host instability are canonicalized away here so both the
    // snapshot path and `verify_host` derive the identical value from this one place:
    //
    //   1. Entry *order*: KVM_GET_SUPPORTED_CPUID does not guarantee a stable order, so
    //      sort by (function, index) before hashing.
    //   2. Caller-context *fields*: CPUID leaf 0xD (XSAVE) reports XSAVE-area *sizes* that
    //      KVM derives from the calling thread's live XCR0/XSS — sub-leaf 0 EBX/ECX and
    //      sub-leaf 1 EBX. Those are not feature presence and vary with FPU context, so
    //      zero them. The actual supported-feature bitmaps (EAX/EDX, and every other
    //      leaf) are kept, so the guard still compares the real CPU feature set.
    //
    // NB: this canonicalization changes the hash value, so a fingerprint recorded by an
    // older build won't match — fine for ephemeral/greenfield snapshots.
    let mut entries: Vec<[u32; 7]> = cpuid
        .as_slice()
        .iter()
        .map(|e| {
            let (mut ebx, mut ecx, mut edx) = (e.ebx, e.ecx, e.edx);
            match e.function {
                // Leaf 1 EBX[31:24] is the *initial APIC ID* — the physical APIC ID of
                // whichever logical CPU the KVM_GET_SUPPORTED_CPUID ioctl thread ran on,
                // so it varies between two calls on the same host (it did: 0x00 vs 0x02).
                // Mask those 8 bits; keep brand index / CLFLUSH size / max-logical-IDs.
                0x1 => ebx &= 0x00FF_FFFF,
                // Leaf 0xD (XSAVE) reports XSAVE-area *sizes* KVM derives from the caller's
                // live XCR0/XSS — not feature presence. Zero the volatile size fields.
                0xD => match e.index {
                    0 => {
                        ebx = 0; // XSAVE size for features enabled in the caller's XCR0
                        ecx = 0; // max XSAVE size (size, redundant with the bitmaps)
                    }
                    1 => ebx = 0, // XSAVE size for XCR0|XSS-enabled features
                    _ => {}
                },
                // Extended-topology leaves: EDX is the per-CPU x2APIC ID (pure identity,
                // never a feature). KVM usually zeroes it for the system query, but mask
                // it so a runner that doesn't can't destabilize the fingerprint.
                0xB | 0x1F => edx = 0,
                _ => {}
            }
            [e.function, e.index, e.flags, e.eax, ebx, ecx, edx]
        })
        .collect();
    entries.sort_unstable();

    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = FNV_OFFSET;
    for e in &entries {
        for word in e {
            for b in word.to_le_bytes() {
                h ^= u64::from(b);
                h = h.wrapping_mul(FNV_PRIME);
            }
        }
        // Self-diagnosing (debug builds, incl. `cargo test`): print the exact canonical
        // leaves hashed. The snapshot and restore-verify streams both land in the same
        // --nocapture log, so if any field still differs between them it is visible by
        // eye instead of just re-failing with two opaque hashes.
        #[cfg(debug_assertions)]
        eprintln!(
            "cpuid_fp: fn={:#010x} idx={} flags={:#x} eax={:#010x} ebx={:#010x} ecx={:#010x} edx={:#010x}",
            e[0], e[1], e[2], e[3], e[4], e[5], e[6]
        );
    }
    #[cfg(debug_assertions)]
    eprintln!(
        "cpuid_fp: canonical hash = {h:#018x} ({} leaves)",
        entries.len()
    );
    Ok(h)
}

/// Re-activate a restored device's transport from its captured `DeviceState`. A free
/// function so it does not borrow `&mut self` while the restore loop holds the config.
fn restore_activate_next(
    transport: &Arc<Mutex<MmioTransport>>,
    state: Option<DeviceState>,
) -> Result<()> {
    let state =
        state.ok_or_else(|| VmmError::Device("restore: missing device state".to_string()))?;
    transport
        .lock()
        .expect("transport mutex")
        .restore_activate(&state.queues)
}

/// A `Write` adapter that flushes the inner writer after every write, so guest
/// serial output reaches a block-buffered pipe (CI logs) immediately rather than
/// sitting in an 8 KiB buffer that may never flush before the process exits.
struct AutoFlush<W>(W);

impl<W: std::io::Write> std::io::Write for AutoFlush<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = std::io::Write::write(&mut self.0, buf)?;
        std::io::Write::flush(&mut self.0)?;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.0)
    }
}

// TUNSETIFF and TAP interface flags (not always surfaced by the `libc` crate).
const TUNSETIFF: libc::Ioctl = 0x4004_54ca;
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;

/// Open and attach to an existing host TAP device by name, returning a file for
/// the virtio-net device to read/write raw Ethernet frames. The TAP itself is
/// created and bridged by `mm-net` (Task 9); here we only obtain its fd.
fn open_tap(name: &str) -> Result<std::fs::File> {
    use std::os::unix::io::FromRawFd;

    let path = std::ffi::CString::new("/dev/net/tun")
        .map_err(|e| VmmError::Device(format!("tun path: {e}")))?;
    // SAFETY: `path` is a valid NUL-terminated C string.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return Err(VmmError::Io(std::io::Error::last_os_error()));
    }

    // SAFETY: `ifreq` is a C POD; zeroing is a valid initial state.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let bytes = name.as_bytes();
    if bytes.len() >= ifr.ifr_name.len() {
        // SAFETY: `fd` is the descriptor we just opened.
        unsafe { libc::close(fd) };
        return Err(VmmError::Device(format!("tap name too long: {name}")));
    }
    for (slot, &b) in ifr.ifr_name.iter_mut().zip(bytes) {
        *slot = b as libc::c_char;
    }
    // Writing a union field (no read) is safe; this selects TAP mode without a
    // packet-info prefix so the device exchanges raw Ethernet frames.
    ifr.ifr_ifru.ifru_flags = IFF_TAP | IFF_NO_PI;

    // SAFETY: `fd` is a valid /dev/net/tun fd and `ifr` is sized for TUNSETIFF.
    let rc = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        // SAFETY: closing the fd we own before returning the error.
        unsafe { libc::close(fd) };
        return Err(VmmError::Io(err));
    }

    // SAFETY: `fd` is an open descriptor we now hand exclusive ownership of to File.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// Parse an `aa:bb:cc:dd:ee:ff` MAC string into 6 bytes.
fn parse_mac(mac: &str) -> Result<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut count = 0;
    for (i, part) in mac.split(':').enumerate() {
        if i >= 6 {
            return Err(VmmError::Device(format!(
                "invalid MAC (too many octets): {mac}"
            )));
        }
        out[i] = u8::from_str_radix(part, 16)
            .map_err(|_| VmmError::Device(format!("invalid MAC octet {part:?} in {mac}")))?;
        count += 1;
    }
    if count != 6 {
        return Err(VmmError::Device(format!(
            "invalid MAC (need 6 octets): {mac}"
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mac_accepts_canonical_form() {
        assert_eq!(
            parse_mac("02:00:00:12:34:56").unwrap(),
            [0x02, 0x00, 0x00, 0x12, 0x34, 0x56]
        );
    }

    #[test]
    fn parse_mac_rejects_malformed() {
        assert!(parse_mac("02:00:00:12:34").is_err(), "too few octets");
        assert!(parse_mac("zz:00:00:12:34:56").is_err(), "non-hex octet");
        assert!(
            parse_mac("02:00:00:12:34:56:78").is_err(),
            "too many octets"
        );
    }
}
