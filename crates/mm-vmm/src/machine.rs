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
    kvm_clock_data, kvm_pit_config, kvm_userspace_memory_region, KVM_PIT_SPEAKER_DUMMY,
};
use kvm_ioctls::{Kvm, VmFd};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};
use vmm_sys_util::eventfd::EventFd;

use crate::config::{ConfigError, VirtioDevice as ConfigDevice, VmConfig};
use crate::devices::{
    Balloon, Block, Bus, DevicePause, Interrupt, MmioTransport, Net, SerialDevice, VirtioDevice,
    Vsock, VsockReady, COM1_IRQ,
};
use crate::snapshot::state::{DeviceState, QueueCursor, VcpuState};
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
    /// Set by `pause_and_capture_vcpus` to ask the vCPU threads to capture their
    /// state and freeze (snapshot, SPEC-1 FR-14), distinct from the teardown stop.
    vcpu_pause: Arc<AtomicBool>,
    /// Per-vCPU capture slots, filled when the threads observe `vcpu_pause`, then
    /// drained by `pause_and_capture_vcpus`. One per vCPU, in index order.
    vcpu_states: Vec<Arc<Mutex<Option<VcpuState>>>>,
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
            vsock_listener: None,
            vcpu_stop: Arc::new(AtomicBool::new(false)),
            vcpu_pause: Arc::new(AtomicBool::new(false)),
            vcpu_states: Vec::new(),
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
                    if let Some(hook) = &hook {
                        hook(vcpu.index())?;
                    }
                    vcpu.run(&dispatch, &stop, &pause, &pause_out)
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

    /// Create a snapshot pause handle, give one end to `device`, and record the other
    /// for [`pause_devices`](Self::pause_devices). Call once per snapshottable device
    /// before it is activated.
    fn install_device_pause(&mut self, device: &mut Box<dyn VirtioDevice>) -> Result<()> {
        let evt = EventFd::new(libc::EFD_NONBLOCK).map_err(VmmError::Io)?;
        let slot = Arc::new(Mutex::new(None));
        device.set_pause_handle(DevicePause {
            evt: evt.try_clone().map_err(VmmError::Io)?,
            slot: slot.clone(),
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
