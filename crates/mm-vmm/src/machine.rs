//! KVM machine: device-independent VM setup — the `/dev/kvm` handle, guest RAM,
//! the in-kernel interrupt controller + PIT, and vCPU creation (SPEC-1 FR-1).
//!
//! It builds the VM, maps guest memory into KVM, creates the vCPUs, and — via
//! [`Machine::boot`] — wires the device model ([`crate::devices`]), loads the
//! kernel ([`crate::boot`]), configures the vCPUs for the boot protocol, and runs
//! them. [`Machine::wait_for_ready`] blocks on the guest's vsock readiness signal.
use std::fmt::Write as _;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use kvm_bindings::{kvm_pit_config, kvm_userspace_memory_region, KVM_PIT_SPEAKER_DUMMY};
use kvm_ioctls::{Kvm, VmFd};
use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};
use vmm_sys_util::eventfd::EventFd;

use crate::config::{ConfigError, VirtioDevice as ConfigDevice, VmConfig};
use crate::devices::{
    Balloon, Block, Bus, Interrupt, MmioTransport, Net, SerialDevice, VirtioDevice, Vsock,
    VsockReady, COM1_IRQ,
};
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
    /// Set by `shutdown` to ask the vCPU threads to stop.
    vcpu_stop: Arc<AtomicBool>,
    /// pthread ids of the running vCPU threads, so `shutdown` can signal them out
    /// of a halted KVM_RUN.
    vcpu_tids: Arc<Mutex<Vec<libc::pthread_t>>>,
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

        let guest_memory = Self::allocate_guest_memory(config.memory_mib)?;
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
            vcpu_stop: Arc::new(AtomicBool::new(false)),
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

    /// Boot using resources opened by a privileged parent: an inherited `/dev/kvm`
    /// fd and one inherited TAP fd per configured net device (in config order).
    /// This is the entry point for the jailed worker, which has already been
    /// confined (namespaces/chroot/cgroup/uid-drop) and therefore cannot open these
    /// itself. `vcpu_hook` installs the per-thread seccomp filter before guest code.
    ///
    /// # Safety
    /// `kvm_fd` and each entry of `tap_fds` must be valid, open file descriptors
    /// that ownership is transferred to this call.
    pub fn boot_jailed(
        config: &VmConfig,
        kvm_fd: RawFd,
        tap_fds: Vec<RawFd>,
        vcpu_hook: Option<VcpuHook>,
    ) -> Result<Self> {
        // SAFETY: the caller guarantees `kvm_fd` is an open /dev/kvm fd we now own.
        let kvm = unsafe { Kvm::from_raw_fd(kvm_fd) };
        let mut machine = Self::with_resources(config, kvm, tap_fds)?;
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
        eprintln!("mm-vmm: start: serial eventfd"); // DIAG(jail-einval): remove
        let serial_irq = EventFd::new(libc::EFD_NONBLOCK).map_err(VmmError::Io)?;
        eprintln!("mm-vmm: start: serial irqfd"); // DIAG(jail-einval): remove
        self.vm.register_irqfd(&serial_irq, COM1_IRQ)?;
        // Wrap stdout so every guest console byte is flushed immediately — block
        // buffering (stdout -> pipe) otherwise swallows early kernel messages.
        let serial = Arc::new(Mutex::new(SerialDevice::new(
            serial_irq,
            Box::new(AutoFlush(std::io::stdout())),
        )));
        bus.set_serial(serial);

        // Rootfs block device (always present).
        eprintln!(
            "mm-vmm: start: block open {}",
            self.config.rootfs.path.display()
        ); // DIAG(jail-einval): remove
        let block = Block::new(&self.config.rootfs.path, self.config.rootfs.read_only)?;
        self.attach_virtio(
            &mut bus,
            &mut mmio_cmdline,
            &mut next_mmio,
            &mut next_gsi,
            Box::new(block),
        )?;

        // Boot vsock channel (always present): carries the guest "ready" signal.
        eprintln!("mm-vmm: start: vsock new"); // DIAG(jail-einval): remove
        let vsock = Vsock::new(DEFAULT_GUEST_CID)?;
        self.ready = Some(vsock.ready_signal());
        self.attach_virtio(
            &mut bus,
            &mut mmio_cmdline,
            &mut next_mmio,
            &mut next_gsi,
            Box::new(vsock),
        )?;

        // Pre-opened TAP fds (jailed boot) are consumed in net-device order; an
        // empty queue means the in-process boot opens the TAP by name itself.
        let mut tap_fds = std::mem::take(&mut self.tap_fds).into_iter();

        // Configured devices: net (attach to its TAP). The boot vsock above already
        // covers M1's single vsock use; balloon is a tracked M1 TODO, so a config
        // that asks for it fails loudly rather than being silently dropped.
        for device in &self.config.devices {
            match device {
                ConfigDevice::Net { tap_name, mac } => {
                    let tap = match tap_fds.next() {
                        // SAFETY: the parent passed us this open TAP fd via fd
                        // inheritance; we take exclusive ownership of it here.
                        Some(fd) => unsafe { std::fs::File::from_raw_fd(fd) },
                        None => open_tap(tap_name)?,
                    };
                    let net = Net::new(tap, parse_mac(mac)?);
                    self.attach_virtio(
                        &mut bus,
                        &mut mmio_cmdline,
                        &mut next_mmio,
                        &mut next_gsi,
                        Box::new(net),
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
        eprintln!(
            "mm-vmm: start: kernel load {}",
            self.config.kernel.display()
        ); // DIAG(jail-einval): remove
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
        eprintln!("mm-vmm: start: spawn vcpu threads"); // DIAG(jail-einval): remove
        let bus = Arc::new(bus);
        self.bus = Some(bus.clone());
        let dispatch: Arc<dyn IoDispatch> = bus;
        for mut vcpu in std::mem::take(&mut self.vcpus) {
            let dispatch = dispatch.clone();
            let hook = self.vcpu_hook.clone();
            let stop = self.vcpu_stop.clone();
            let tids = self.vcpu_tids.clone();
            let handle = std::thread::Builder::new()
                .name(format!("mm-vcpu-{}", vcpu.index()))
                .spawn(move || {
                    // Register this thread so `shutdown` can signal it out of KVM_RUN.
                    // SAFETY: `pthread_self` is always safe and returns this thread.
                    let tid = unsafe { libc::pthread_self() };
                    if let Ok(mut guard) = tids.lock() {
                        guard.push(tid);
                    }
                    // Run the pre-run hook (e.g. seccomp install) on this thread,
                    // after the VMM's opens, before any guest code executes.
                    if let Some(hook) = &hook {
                        hook(vcpu.index())?;
                    }
                    vcpu.run(&dispatch, &stop)
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
    ) -> Result<()> {
        let base = *next_mmio;
        let gsi = *next_gsi;

        let irq = EventFd::new(libc::EFD_NONBLOCK).map_err(VmmError::Io)?;
        self.vm.register_irqfd(&irq, gsi)?;
        let interrupt = Arc::new(Interrupt::new(irq));

        let transport = MmioTransport::new(device, self.guest_memory.clone(), interrupt)?;
        bus.add_mmio_device(base, MMIO_DEVICE_SIZE, Arc::new(Mutex::new(transport)));

        // e.g. " virtio_mmio.device=4K@0xd0000000:5"
        let _ = write!(cmdline, " virtio_mmio.device=4K@0x{base:x}:{gsi}");

        *next_mmio += MMIO_DEVICE_SIZE;
        *next_gsi += 1;
        Ok(())
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
