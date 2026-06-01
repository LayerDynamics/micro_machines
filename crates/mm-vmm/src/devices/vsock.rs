//! virtio-vsock — the host<->guest channel (SPEC-1 FR-3 readiness + FR-13 exec).
//!
//! Two jobs:
//!   * **Boot readiness (M1).** The guest's `mm-init` connects to host port 1024;
//!     the device treats that as the "reached userspace" edge, sets a flag, and
//!     signals an eventfd the VMM boot path polls.
//!   * **Sandbox exec (M3).** When constructed with a host Unix-domain-socket
//!     listener ([`Vsock::with_host_bridge`]), the device runs a full vsock muxer:
//!     a host process connects to the UDS, speaks the firecracker-style hybrid
//!     handshake (`CONNECT <port>\n` -> `OK <port>\n`), and is then byte-bridged to
//!     a guest vsock port (the exec agent listens on 1025). Flow control follows the
//!     virtio-vsock credit scheme via [`crate::vsock_proto::CreditTracker`] in both
//!     directions, so neither side can overrun the other (a missing host-side
//!     receive window is the classic stdout-stall bug, so we advertise a bounded one
//!     and emit `CREDIT_UPDATE` as we drain to the UDS).
//!
//! The activated worker owns its rx/tx queues exclusively, so it is a single
//! threaded `poll(2)` reactor over the queue-notify eventfds, the UDS listener, and
//! each live connection's socket — no locks on the hot path.
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use virtio_queue::{Queue, QueueT};
use vm_memory::{Bytes, GuestMemoryMmap};
use vmm_sys_util::eventfd::EventFd;

use super::{DevicePause, Interrupt, VirtioDevice, QUEUE_SIZE, TYPE_VSOCK, VIRTIO_F_VERSION_1};
use crate::machine::{Result, VmmError};
use crate::vsock_proto::{
    CreditTracker, VsockHeader, HOST_CID, OP_CREDIT_REQUEST, OP_CREDIT_UPDATE, OP_REQUEST,
    OP_RESPONSE, OP_RST, OP_RW, OP_SHUTDOWN, TYPE_STREAM, VSOCK_HDR_LEN,
};

const RX_QUEUE_INDEX: usize = 0;
const TX_QUEUE_INDEX: usize = 1;
const EVENT_QUEUE_INDEX: usize = 2;

/// Guest connects here (to `VMADDR_CID_HOST`) to signal boot readiness.
const BOOT_PORT: u32 = 1024;
/// Receive window we advertise to the guest per connection. Bounded on purpose: it
/// is what makes the guest throttle its stdout instead of overrunning us.
const HOST_BUF_ALLOC: u32 = 256 * 1024;
/// Host-side source ports allocated for outbound (host-initiated) connections; kept
/// out of the low/reserved range so they never collide with guest service ports.
const FIRST_HOST_PORT: u32 = 0x4000_0000;
/// Cap on host->guest packets buffered while the guest has posted no rx buffers.
const RX_BACKLOG_MAX: usize = 256;
/// Largest payload we put in one OP_RW packet (keeps a packet inside one rx buffer).
const MAX_RW_PAYLOAD: usize = 4096;

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

/// virtio-vsock device. Holds the readiness signal, the guest context id, and —
/// when exec is enabled — the host UDS listener handed to the worker on activation.
pub struct Vsock {
    cid: u64,
    ready: Arc<VsockReady>,
    listener: Option<UnixListener>,
    queue_max_sizes: [u16; 3],
    /// Snapshot pause handle (SPEC-1 FR-14); the worker captures its rx/tx queue
    /// cursors here when signalled.
    pause: Option<DevicePause>,
}

impl Vsock {
    /// Create a readiness-only vsock device with guest context id `cid` (M1 boot).
    pub fn new(cid: u64) -> Result<Self> {
        Ok(Self {
            cid,
            ready: Arc::new(VsockReady::new()?),
            listener: None,
            // rx, tx, event queues.
            queue_max_sizes: [QUEUE_SIZE, QUEUE_SIZE, QUEUE_SIZE],
            pause: None,
        })
    }

    /// Create an exec-enabled device: in addition to the readiness signal, the
    /// worker bridges host connections arriving on `listener` to guest vsock ports
    /// (SPEC-1 FR-13). `listener` must already be bound to a path the host side can
    /// reach (for a jailed VMM, bound outside the chroot and its fd passed in).
    pub fn with_host_bridge(cid: u64, listener: UnixListener) -> Result<Self> {
        let mut v = Self::new(cid)?;
        v.listener = Some(listener);
        Ok(v)
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

    fn set_pause_handle(&mut self, pause: DevicePause) {
        self.pause = Some(pause);
    }

    fn activate(
        &mut self,
        mem: Arc<GuestMemoryMmap>,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
        interrupt: Arc<Interrupt>,
    ) -> Result<()> {
        if queues.len() <= EVENT_QUEUE_INDEX || queue_evts.len() <= EVENT_QUEUE_INDEX {
            return Err(VmmError::Device(
                "vsock: expected rx, tx, event queues".to_string(),
            ));
        }
        // Drop the (unused) event queue, then take tx and rx. swap_remove the highest
        // index first so the lower indices stay valid.
        let _ = queues.swap_remove(EVENT_QUEUE_INDEX);
        let _ = queue_evts.swap_remove(EVENT_QUEUE_INDEX);
        let tx_queue = queues.swap_remove(TX_QUEUE_INDEX);
        let rx_queue = queues.swap_remove(RX_QUEUE_INDEX);
        let tx_evt = queue_evts.swap_remove(TX_QUEUE_INDEX);
        let rx_evt = queue_evts.swap_remove(RX_QUEUE_INDEX);

        if let Some(l) = self.listener.as_ref() {
            l.set_nonblocking(true).map_err(VmmError::Io)?;
        }

        let worker = VsockWorker {
            cid: self.cid,
            rx_queue,
            tx_queue,
            rx_evt,
            tx_evt,
            mem,
            interrupt,
            ready: self.ready.clone(),
            listener: self.listener.take(),
            pause: self.pause.take(),
            pending: Vec::new(),
            conns: HashMap::new(),
            next_port: FIRST_HOST_PORT,
            rx_backlog: VecDeque::new(),
        };

        std::thread::Builder::new()
            .name("mm-vsock".to_string())
            .spawn(move || worker.run())
            .map_err(VmmError::Io)?;
        Ok(())
    }
}

/// A connection's lifecycle on the host side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnState {
    /// Host sent OP_REQUEST, awaiting the guest's OP_RESPONSE.
    Connecting,
    /// Guest accepted; bytes flow both ways.
    Established,
}

/// A live host<->guest bridged connection.
struct Conn {
    /// Host-side (source) port; the key the guest addresses replies to.
    local_port: u32,
    /// Guest-side (destination) service port, e.g. the exec agent's 1025.
    guest_port: u32,
    /// The host UDS socket this connection bridges to (non-blocking).
    uds: UnixStream,
    state: ConnState,
    /// Flow control for bytes we send *to* the guest.
    credit: CreditTracker,
    /// Bytes we have delivered to the UDS (our receive `fwd_cnt`, advertised so the
    /// guest knows how much of its stream we have consumed).
    rx_fwd_cnt: u32,
    /// `rx_fwd_cnt` at the last CREDIT_UPDATE we sent (so we only update on advance).
    last_credit_sent: u32,
    /// Guest->host bytes accepted from the guest but not yet written to the UDS
    /// (the UDS would have blocked); drained when the socket is writable.
    to_uds: VecDeque<u8>,
}

impl Conn {
    /// Build an outgoing (host->guest) header for this connection carrying our
    /// current receive-credit advertisement.
    fn header(&self, guest_cid: u64, op: u16, len: u32) -> VsockHeader {
        VsockHeader {
            src_cid: HOST_CID,
            dst_cid: guest_cid,
            src_port: self.local_port,
            dst_port: self.guest_port,
            len,
            type_: TYPE_STREAM,
            op,
            flags: 0,
            buf_alloc: HOST_BUF_ALLOC,
            fwd_cnt: self.rx_fwd_cnt,
        }
    }
}

/// A just-accepted UDS connection still reading its `CONNECT <port>\n` line.
struct Pending {
    uds: UnixStream,
    inbuf: Vec<u8>,
}

/// Parse a firecracker-style hybrid handshake line. Returns `Some((consumed, port))`
/// once a full `CONNECT <port>\n` line is present at the front of `buf`, where
/// `consumed` is the byte length of the line (including the newline). `None` means
/// "need more bytes". Returns `Some((consumed, 0))`-style is avoided: a malformed
/// complete line yields `Err`-like via the caller treating port 0 as invalid.
fn parse_connect(buf: &[u8]) -> Option<(usize, Option<u32>)> {
    let nl = buf.iter().position(|&b| b == b'\n')?;
    let line = &buf[..nl];
    let consumed = nl + 1;
    // Trim a trailing CR (CRLF tolerance).
    let line = if line.last() == Some(&b'\r') {
        &line[..line.len() - 1]
    } else {
        line
    };
    let text = std::str::from_utf8(line).ok()?;
    let mut it = text.split_ascii_whitespace();
    let verb = it.next()?;
    if !verb.eq_ignore_ascii_case("connect") {
        return Some((consumed, None));
    }
    let port = it.next().and_then(|p| p.parse::<u32>().ok());
    Some((consumed, port))
}

/// What a poll iteration found readable/writable, paired with its source.
enum Source {
    RxEvt,
    TxEvt,
    Listener,
    Pending(usize),
    Conn(u32),
    /// Snapshot pause requested: capture rx/tx cursors and exit.
    PauseEvt,
}

/// The single-threaded reactor owning the vsock device's queues and connections.
struct VsockWorker {
    cid: u64,
    rx_queue: Queue,
    tx_queue: Queue,
    rx_evt: EventFd,
    tx_evt: EventFd,
    mem: Arc<GuestMemoryMmap>,
    interrupt: Arc<Interrupt>,
    ready: Arc<VsockReady>,
    listener: Option<UnixListener>,
    /// Snapshot pause handle; on signal the reactor captures rx/tx cursors + exits.
    pause: Option<DevicePause>,
    pending: Vec<Pending>,
    conns: HashMap<u32, Conn>,
    next_port: u32,
    /// host->guest packets buffered while the guest had no rx buffer posted.
    rx_backlog: VecDeque<Vec<u8>>,
}

impl VsockWorker {
    /// The poll(2) reactor. Runs until the queue-notify eventfds are closed at
    /// teardown (a closed eventfd makes `read` fail, which ends the loop).
    fn run(mut self) {
        loop {
            // Build the pollfd set fresh each iteration (the connection set changes).
            let mut fds: Vec<libc::pollfd> = Vec::new();
            let mut sources: Vec<Source> = Vec::new();
            let mut push = |fd: RawFd, events: i16, src: Source| {
                fds.push(libc::pollfd {
                    fd,
                    events,
                    revents: 0,
                });
                sources.push(src);
            };
            push(self.rx_evt.as_raw_fd(), libc::POLLIN, Source::RxEvt);
            push(self.tx_evt.as_raw_fd(), libc::POLLIN, Source::TxEvt);
            if let Some(l) = self.listener.as_ref() {
                push(l.as_raw_fd(), libc::POLLIN, Source::Listener);
            }
            if let Some(p) = self.pause.as_ref() {
                push(p.evt.as_raw_fd(), libc::POLLIN, Source::PauseEvt);
            }
            for (i, p) in self.pending.iter().enumerate() {
                push(p.uds.as_raw_fd(), libc::POLLIN, Source::Pending(i));
            }
            for (&port, c) in self.conns.iter() {
                let mut events = 0i16;
                // Want guest-bound data only when the guest has credit to receive it.
                if c.state == ConnState::Established && c.credit.available() > 0 {
                    events |= libc::POLLIN;
                }
                // Want writability when we still owe the UDS buffered guest output.
                if !c.to_uds.is_empty() {
                    events |= libc::POLLOUT;
                }
                if events != 0 {
                    push(c.uds.as_raw_fd(), events, Source::Conn(port));
                }
            }

            // SAFETY: `fds` is a valid, initialized slice of pollfds for the duration
            // of the call; len fits the nfds_t range for our small fd set.
            let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                tracing::error!("vsock: poll failed: {err}");
                break;
            }

            let mut dirty = false;
            let mut stop = false;
            for (i, pfd) in fds.iter().enumerate() {
                if pfd.revents == 0 {
                    continue;
                }
                match sources[i] {
                    Source::RxEvt => {
                        if self.rx_evt.read().is_err() {
                            stop = true;
                            break;
                        }
                        // Guest posted rx buffers: flush whatever we backlogged.
                        match self.drain_rx_backlog() {
                            Ok(true) => dirty = true,
                            Ok(false) => {}
                            Err(e) => tracing::error!("vsock: rx backlog drain: {e}"),
                        }
                    }
                    Source::TxEvt => {
                        if self.tx_evt.read().is_err() {
                            stop = true;
                            break;
                        }
                        match self.process_tx() {
                            Ok(d) => dirty |= d,
                            Err(e) => tracing::error!("vsock: tx process: {e}"),
                        }
                    }
                    Source::Listener => self.accept_uds(),
                    Source::Pending(idx) => {
                        // The pending vec may have shrunk if an earlier event removed
                        // an entry; guard the index.
                        if idx < self.pending.len() && (pfd.revents & libc::POLLIN) != 0 {
                            match self.poll_pending(idx) {
                                Ok(d) => dirty |= d,
                                Err(e) => tracing::error!("vsock: pending connect: {e}"),
                            }
                        }
                    }
                    Source::Conn(port) => {
                        if (pfd.revents & libc::POLLOUT) != 0 {
                            match self.flush_to_uds(port) {
                                Ok(d) => dirty |= d,
                                Err(e) => tracing::error!("vsock: uds flush: {e}"),
                            }
                        }
                        if (pfd.revents & libc::POLLIN) != 0 {
                            match self.pump_to_guest(port) {
                                Ok(d) => dirty |= d,
                                Err(e) => tracing::error!("vsock: uds->guest: {e}"),
                            }
                        }
                        if (pfd.revents & (libc::POLLHUP | libc::POLLERR)) != 0 {
                            if let Err(e) = self.close_conn(port, true) {
                                tracing::error!("vsock: close: {e}");
                            } else {
                                dirty = true;
                            }
                        }
                    }
                    Source::PauseEvt => {
                        // Snapshot: capture the rx/tx queue cursors and exit (the VM
                        // is already frozen, so the queues are stable).
                        if let Some(p) = self.pause.as_ref() {
                            let _ = p.evt.read();
                            let cursors =
                                vec![self.rx_queue.state().into(), self.tx_queue.state().into()];
                            if let Ok(mut slot) = p.slot.lock() {
                                *slot = Some(cursors);
                            }
                        }
                        stop = true;
                        break;
                    }
                }
            }

            if dirty {
                if let Err(e) = self.interrupt.signal_used_queue() {
                    tracing::error!("vsock: interrupt: {e}");
                }
            }
            if stop {
                break;
            }
        }
    }

    /// Drain the guest transmit queue, dispatching each fully-assembled packet.
    /// Returns whether any rx used-ring entry was produced (so the caller signals).
    fn process_tx(&mut self) -> Result<bool> {
        let mut dirty = false;
        loop {
            let Some(chain) = self.tx_queue.pop_descriptor_chain(self.mem.clone()) else {
                break;
            };
            let head = chain.head_index();
            let mut pkt = Vec::with_capacity(VSOCK_HDR_LEN + 256);
            for desc in chain {
                let mut buf = vec![0u8; desc.len() as usize];
                self.mem
                    .read_slice(&mut buf, desc.addr())
                    .map_err(|e| VmmError::Device(format!("vsock tx read: {e}")))?;
                pkt.extend_from_slice(&buf);
            }
            self.tx_queue
                .add_used(self.mem.as_ref(), head, 0)
                .map_err(|e| VmmError::Device(format!("vsock tx add_used: {e}")))?;

            if let Some(hdr) = VsockHeader::parse(&pkt) {
                let payload = &pkt[VSOCK_HDR_LEN..];
                let n = (hdr.len as usize).min(payload.len());
                if self.handle_guest_packet(&hdr, &payload[..n])? {
                    dirty = true;
                }
            }
        }
        Ok(dirty)
    }

    /// Act on one guest->host packet. Returns whether it queued an rx packet.
    fn handle_guest_packet(&mut self, hdr: &VsockHeader, payload: &[u8]) -> Result<bool> {
        // The guest addresses the host port in dst_port; our connection key.
        let port = hdr.dst_port;

        // Boot readiness: the guest connecting to BOOT_PORT is the M1 "ready" edge.
        // There is no host listener there, so reset it (so the guest connect() ends
        // promptly) after recording readiness.
        if hdr.op == OP_REQUEST && port == BOOT_PORT {
            self.ready.mark_ready();
            return self.send_rst(hdr);
        }

        match hdr.op {
            OP_REQUEST => {
                // No host service listens on guest-initiated ports (other than the
                // boot ping handled above) — refuse cleanly.
                self.send_rst(hdr)
            }
            OP_RESPONSE => {
                if let Some(c) = self.conns.get_mut(&port) {
                    if c.state == ConnState::Connecting {
                        c.state = ConnState::Established;
                        c.credit.update_peer(hdr.buf_alloc, hdr.fwd_cnt);
                        // Complete the hybrid handshake to the host side.
                        let _ = c.uds.write_all(format!("OK {}\n", c.local_port).as_bytes());
                    }
                }
                Ok(false)
            }
            OP_RW => {
                if let Some(c) = self.conns.get_mut(&port) {
                    c.credit.update_peer(hdr.buf_alloc, hdr.fwd_cnt);
                    // Accept the bytes; whatever the UDS can't take stays buffered.
                    c.to_uds.extend(payload.iter().copied());
                } else {
                    return Ok(false);
                }
                // Flush to the UDS (advances rx_fwd_cnt) and emit credit if we made room.
                self.flush_to_uds(port)
            }
            OP_CREDIT_UPDATE => {
                if let Some(c) = self.conns.get_mut(&port) {
                    c.credit.update_peer(hdr.buf_alloc, hdr.fwd_cnt);
                }
                Ok(false)
            }
            OP_CREDIT_REQUEST => {
                // Reply with our current receive credit.
                if self.conns.contains_key(&port) {
                    self.send_control(port, OP_CREDIT_UPDATE)
                } else {
                    Ok(false)
                }
            }
            OP_SHUTDOWN => {
                // Peer is done; reset and tear the connection down.
                let _ = self.send_rst(hdr);
                self.close_conn(port, false)?;
                Ok(true)
            }
            OP_RST => {
                self.close_conn(port, false)?;
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    /// Accept all currently-pending host UDS connections (non-blocking listener).
    fn accept_uds(&mut self) {
        let Some(listener) = self.listener.as_ref() else {
            return;
        };
        loop {
            match listener.accept() {
                Ok((uds, _)) => {
                    if uds.set_nonblocking(true).is_err() {
                        continue;
                    }
                    self.pending.push(Pending {
                        uds,
                        inbuf: Vec::new(),
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    tracing::warn!("vsock: uds accept failed: {e}");
                    break;
                }
            }
        }
    }

    /// Read from a pending UDS until its `CONNECT <port>\n` line completes, then
    /// promote it to a Connecting connection and send OP_REQUEST to the guest.
    /// Returns whether an rx packet was queued.
    fn poll_pending(&mut self, idx: usize) -> Result<bool> {
        let mut buf = [0u8; 256];
        let n = match self.pending[idx].uds.read(&mut buf) {
            Ok(0) => {
                // Peer closed before completing the handshake.
                self.pending.swap_remove(idx);
                return Ok(false);
            }
            Ok(n) => n,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) => {
                self.pending.swap_remove(idx);
                return Err(VmmError::Io(e));
            }
        };
        self.pending[idx].inbuf.extend_from_slice(&buf[..n]);

        let Some((consumed, port_opt)) = parse_connect(&self.pending[idx].inbuf) else {
            // Need more bytes; bound the buffer so a misbehaving client can't grow it.
            if self.pending[idx].inbuf.len() > 1024 {
                self.pending.swap_remove(idx);
            }
            return Ok(false);
        };
        let pending = self.pending.swap_remove(idx);
        let Some(guest_port) = port_opt else {
            // Malformed CONNECT line — drop it (socket closes on drop).
            let _ = consumed;
            return Ok(false);
        };

        let local_port = self.alloc_port();
        let conn = Conn {
            local_port,
            guest_port,
            uds: pending.uds,
            state: ConnState::Connecting,
            credit: CreditTracker::new(),
            rx_fwd_cnt: 0,
            last_credit_sent: 0,
            to_uds: VecDeque::new(),
        };
        self.conns.insert(local_port, conn);
        self.send_control(local_port, OP_REQUEST)
    }

    /// Pull bytes from the connection's UDS and forward them to the guest as OP_RW
    /// packets, bounded by the guest's advertised credit. On UDS EOF, send SHUTDOWN.
    fn pump_to_guest(&mut self, port: u32) -> Result<bool> {
        let mut dirty = false;
        loop {
            let avail = match self.conns.get(&port) {
                Some(c) if c.state == ConnState::Established => {
                    c.credit.available().min(MAX_RW_PAYLOAD as u32) as usize
                }
                _ => break,
            };
            if avail == 0 {
                break;
            }
            let mut buf = vec![0u8; avail];
            let read = {
                let c = self.conns.get_mut(&port).unwrap();
                c.uds.read(&mut buf)
            };
            match read {
                Ok(0) => {
                    // Host closed the connection: tell the guest, then tear down.
                    let _ = self.send_control(port, OP_SHUTDOWN);
                    self.close_conn(port, false)?;
                    dirty = true;
                    break;
                }
                Ok(n) => {
                    if self.send_rw(port, &buf[..n])? {
                        dirty = true;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    tracing::warn!("vsock: uds read on port {port}: {e}");
                    let _ = self.send_control(port, OP_SHUTDOWN);
                    self.close_conn(port, false)?;
                    dirty = true;
                    break;
                }
            }
        }
        Ok(dirty)
    }

    /// Flush the connection's buffered guest output to its UDS, advancing our receive
    /// `fwd_cnt`; emit a CREDIT_UPDATE to the guest when that advances so it may send
    /// more. Returns whether an rx packet (the credit update) was queued.
    fn flush_to_uds(&mut self, port: u32) -> Result<bool> {
        let mut advanced = false;
        loop {
            let front = match self.conns.get(&port) {
                Some(c) if !c.to_uds.is_empty() => {
                    let (a, _) = c.to_uds.as_slices();
                    a.to_vec()
                }
                _ => break,
            };
            let written = {
                let c = self.conns.get_mut(&port).unwrap();
                c.uds.write(&front)
            };
            match written {
                Ok(0) => break,
                Ok(n) => {
                    let c = self.conns.get_mut(&port).unwrap();
                    for _ in 0..n {
                        c.to_uds.pop_front();
                    }
                    c.rx_fwd_cnt = c.rx_fwd_cnt.wrapping_add(n as u32);
                    advanced = true;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    tracing::warn!("vsock: uds write on port {port}: {e}");
                    let _ = self.send_control(port, OP_RST);
                    self.close_conn(port, false)?;
                    return Ok(false);
                }
            }
        }
        // Tell the guest we consumed some of its stream (recovers its send credit).
        if advanced {
            let needs_update = self
                .conns
                .get(&port)
                .map(|c| c.rx_fwd_cnt != c.last_credit_sent)
                .unwrap_or(false);
            if needs_update {
                return self.send_control(port, OP_CREDIT_UPDATE);
            }
        }
        Ok(false)
    }

    /// Send a header-only control packet (REQUEST/RESPONSE/CREDIT_UPDATE/...) for a
    /// connection to the guest. Returns whether it was placed in the rx queue.
    fn send_control(&mut self, port: u32, op: u16) -> Result<bool> {
        let guest_cid = self.cid;
        let Some(c) = self.conns.get_mut(&port) else {
            return Ok(false);
        };
        if op == OP_CREDIT_UPDATE {
            c.last_credit_sent = c.rx_fwd_cnt;
        }
        let hdr = c.header(guest_cid, op, 0);
        self.push_to_guest(&hdr.to_bytes())
    }

    /// Send an OP_RW data packet for `port` carrying `data`, accounting the bytes
    /// against the guest's receive credit.
    fn send_rw(&mut self, port: u32, data: &[u8]) -> Result<bool> {
        let guest_cid = self.cid;
        let Some(c) = self.conns.get_mut(&port) else {
            return Ok(false);
        };
        let hdr = c.header(guest_cid, OP_RW, data.len() as u32);
        c.credit.record_sent(data.len() as u32);
        let mut pkt = hdr.to_bytes().to_vec();
        pkt.extend_from_slice(data);
        self.push_to_guest(&pkt)
    }

    /// Reply to a guest packet with an OP_RST (swap src/dst so it reaches the sender).
    fn send_rst(&mut self, incoming: &VsockHeader) -> Result<bool> {
        let rst = VsockHeader {
            src_cid: HOST_CID,
            dst_cid: incoming.src_cid,
            src_port: incoming.dst_port,
            dst_port: incoming.src_port,
            len: 0,
            type_: TYPE_STREAM,
            op: OP_RST,
            flags: 0,
            buf_alloc: 0,
            fwd_cnt: 0,
        };
        self.push_to_guest(&rst.to_bytes())
    }

    /// Place a fully-formed host->guest packet into a guest rx descriptor chain, or
    /// buffer it if the guest has posted no rx buffer. Returns whether it was placed
    /// directly (so the caller knows an interrupt is warranted).
    fn push_to_guest(&mut self, pkt: &[u8]) -> Result<bool> {
        // Preserve ordering: if a backlog exists, append rather than overtake it.
        if !self.rx_backlog.is_empty() {
            self.enqueue_backlog(pkt);
            return Ok(false);
        }
        if self.write_rx(pkt)? {
            Ok(true)
        } else {
            self.enqueue_backlog(pkt);
            Ok(false)
        }
    }

    /// Try to copy one packet into the next available guest rx chain. Returns
    /// `Ok(false)` if no rx buffer is available.
    fn write_rx(&mut self, pkt: &[u8]) -> Result<bool> {
        let Some(chain) = self.rx_queue.pop_descriptor_chain(self.mem.clone()) else {
            return Ok(false);
        };
        let head = chain.head_index();
        let mut copied = 0usize;
        for desc in chain {
            if copied >= pkt.len() {
                break;
            }
            let want = (desc.len() as usize).min(pkt.len() - copied);
            self.mem
                .write_slice(&pkt[copied..copied + want], desc.addr())
                .map_err(|e| VmmError::Device(format!("vsock rx write: {e}")))?;
            copied += want;
        }
        self.rx_queue
            .add_used(self.mem.as_ref(), head, copied as u32)
            .map_err(|e| VmmError::Device(format!("vsock rx add_used: {e}")))?;
        Ok(true)
    }

    /// Flush as many backlogged host->guest packets as the guest now has buffers for.
    /// Returns whether any were delivered.
    fn drain_rx_backlog(&mut self) -> Result<bool> {
        let mut delivered = false;
        while let Some(pkt) = self.rx_backlog.pop_front() {
            if self.write_rx(&pkt)? {
                delivered = true;
            } else {
                self.rx_backlog.push_front(pkt);
                break;
            }
        }
        Ok(delivered)
    }

    /// Buffer a host->guest packet, dropping the oldest if the bound is hit.
    fn enqueue_backlog(&mut self, pkt: &[u8]) {
        if self.rx_backlog.len() >= RX_BACKLOG_MAX {
            self.rx_backlog.pop_front();
            tracing::warn!("vsock: rx backlog full ({RX_BACKLOG_MAX}); dropped oldest packet");
        }
        self.rx_backlog.push_back(pkt.to_vec());
    }

    /// Allocate the next host-side source port, wrapping within the high range.
    fn alloc_port(&mut self) -> u32 {
        loop {
            let p = self.next_port;
            self.next_port = self.next_port.checked_add(1).unwrap_or(FIRST_HOST_PORT);
            if !self.conns.contains_key(&p) && p != BOOT_PORT {
                return p;
            }
        }
    }

    /// Remove a connection and drop its UDS. When `reset`, also send an OP_RST so the
    /// guest tears its side down (used for host-side errors/hangups).
    fn close_conn(&mut self, port: u32, reset: bool) -> Result<bool> {
        if let Some(c) = self.conns.remove(&port) {
            if reset {
                let rst = VsockHeader {
                    src_cid: HOST_CID,
                    dst_cid: self.cid,
                    src_port: c.local_port,
                    dst_port: c.guest_port,
                    len: 0,
                    type_: TYPE_STREAM,
                    op: OP_RST,
                    flags: 0,
                    buf_alloc: 0,
                    fwd_cnt: 0,
                };
                return self.push_to_guest(&rst.to_bytes());
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use virtio_queue::desc::split::Descriptor as SplitDescriptor;
    use virtio_queue::desc::RawDescriptor;
    use virtio_queue::mock::MockSplitQueue;
    use vm_memory::GuestAddress;

    use super::*;
    use crate::devices::Interrupt;

    /// virtio descriptor flag: buffer is device-writable (the rx direction). Defined
    /// locally to avoid a direct virtio-bindings dependency.
    const VRING_DESC_F_WRITE: u16 = 2;

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

    #[test]
    fn parse_connect_needs_full_line() {
        assert_eq!(parse_connect(b"CONN"), None);
        assert_eq!(parse_connect(b"CONNECT 1025"), None, "no newline yet");
        assert_eq!(parse_connect(b"CONNECT 1025\n"), Some((13, Some(1025))));
        assert_eq!(parse_connect(b"connect 22\r\n"), Some((12, Some(22))));
        // A complete but malformed line is consumed with no port.
        assert_eq!(parse_connect(b"HELLO\n"), Some((6, None)));
        assert_eq!(parse_connect(b"CONNECT abc\n"), Some((12, None)));
    }

    /// A worker with a memory + a real rx queue holding `rx_bufs` writable buffers,
    /// and an empty tx queue. Used to inspect what the worker pushes to the guest.
    /// Returns the worker plus the host end of the UDS socketpair for a seeded conn.
    fn worker_with_rx(mem: Arc<GuestMemoryMmap>, rx_bufs: u16) -> VsockWorker {
        // Build an rx queue with `rx_bufs` single-descriptor device-writable chains.
        // Each is its own chain (no NEXT flag), with a distinct buffer well above the
        // ring memory. The rx and tx mocks MUST sit at different guest-physical bases:
        // each MockSplitQueue constructor zeroes its avail-ring idx, so two mocks at
        // the same default base (gpa 0) would alias and the second would wipe the rx
        // avail idx we just populated — leaving nothing to pop.
        let rxq = MockSplitQueue::create(mem.as_ref(), GuestAddress(0), 256);
        let descs: Vec<RawDescriptor> = (0..rx_bufs)
            .map(|i| {
                RawDescriptor::from(SplitDescriptor::new(
                    0x10_0000 + u64::from(i) * 0x1000,
                    0x1000,
                    VRING_DESC_F_WRITE,
                    0,
                ))
            })
            .collect();
        if !descs.is_empty() {
            rxq.add_desc_chains(&descs, 0).unwrap();
        }
        let rx_queue = rxq.create_queue::<Queue>().unwrap();
        // tx queue at a separate base (8 MiB), clear of the rx rings + rx buffers.
        let tx_queue = MockSplitQueue::create(mem.as_ref(), GuestAddress(0x80_0000), 256)
            .create_queue::<Queue>()
            .unwrap();
        let interrupt = Arc::new(Interrupt::new(EventFd::new(0).unwrap()));
        VsockWorker {
            cid: 3,
            rx_queue,
            tx_queue,
            rx_evt: EventFd::new(0).unwrap(),
            tx_evt: EventFd::new(0).unwrap(),
            mem,
            interrupt,
            ready: Arc::new(VsockReady::new().unwrap()),
            listener: None,
            pause: None,
            pending: Vec::new(),
            conns: HashMap::new(),
            next_port: FIRST_HOST_PORT,
            rx_backlog: VecDeque::new(),
        }
    }

    fn new_mem() -> Arc<GuestMemoryMmap> {
        Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x400_0000)]).unwrap())
    }

    #[test]
    fn host_connect_emits_request_to_guest() {
        let mem = new_mem();
        let mut w = worker_with_rx(mem.clone(), 4);
        let (host, _guest_side) = UnixStream::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        // Seed a pending UDS that has already sent its CONNECT line.
        w.pending.push(Pending {
            uds: host,
            inbuf: b"CONNECT 1025\n".to_vec(),
        });
        // Re-run the same parse path poll_pending uses, but feed the buffered line.
        // poll_pending reads from the socket; instead exercise the promotion directly.
        let (consumed, port) = parse_connect(&w.pending[0].inbuf).unwrap();
        assert_eq!(consumed, 13);
        let guest_port = port.unwrap();
        let local = w.alloc_port();
        let pend = w.pending.swap_remove(0);
        w.conns.insert(
            local,
            Conn {
                local_port: local,
                guest_port,
                uds: pend.uds,
                state: ConnState::Connecting,
                credit: CreditTracker::new(),
                rx_fwd_cnt: 0,
                last_credit_sent: 0,
                to_uds: VecDeque::new(),
            },
        );
        let placed = w.send_control(local, OP_REQUEST).unwrap();
        assert!(placed, "OP_REQUEST should land in an rx buffer");
    }

    #[test]
    fn guest_rw_is_delivered_to_uds_and_credits_back() {
        let mem = new_mem();
        let mut w = worker_with_rx(mem.clone(), 4);
        let (host, mut guest_side) = UnixStream::pair().unwrap();
        host.set_nonblocking(true).unwrap();
        let local = 0x4000_0000;
        w.conns.insert(
            local,
            Conn {
                local_port: local,
                guest_port: 1025,
                uds: host,
                state: ConnState::Established,
                credit: CreditTracker::new(),
                rx_fwd_cnt: 0,
                last_credit_sent: 0,
                to_uds: VecDeque::new(),
            },
        );
        // Guest sends "hi\n" to host port `local`.
        let hdr = VsockHeader {
            src_cid: 3,
            dst_cid: HOST_CID,
            src_port: 1025,
            dst_port: local,
            len: 3,
            type_: TYPE_STREAM,
            op: OP_RW,
            flags: 0,
            buf_alloc: 65536,
            fwd_cnt: 0,
        };
        let produced = w.handle_guest_packet(&hdr, b"hi\n").unwrap();
        // The payload reached the host UDS end.
        let mut got = [0u8; 3];
        guest_side.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"hi\n");
        // And we advertised that we consumed 3 bytes (credit recovery) — i.e. a
        // CREDIT_UPDATE was queued to the guest.
        assert!(produced, "consuming guest RW must emit a CREDIT_UPDATE");
        assert_eq!(w.conns[&local].rx_fwd_cnt, 3);
    }

    #[test]
    fn boot_port_request_marks_ready_and_resets() {
        let mem = new_mem();
        let mut w = worker_with_rx(mem.clone(), 4);
        assert!(!w.ready.is_ready());
        let hdr = VsockHeader {
            src_cid: 3,
            dst_cid: HOST_CID,
            src_port: 5555,
            dst_port: BOOT_PORT,
            len: 0,
            type_: TYPE_STREAM,
            op: OP_REQUEST,
            flags: 0,
            buf_alloc: 0,
            fwd_cnt: 0,
        };
        let produced = w.handle_guest_packet(&hdr, &[]).unwrap();
        assert!(w.ready.is_ready(), "boot-port connect signals readiness");
        assert!(produced, "an RST is queued back to the guest");
    }

    #[test]
    fn no_guest_buffer_backlogs_without_dropping() {
        let mem = new_mem();
        // Zero rx buffers: every push must be backlogged, not lost.
        let mut w = worker_with_rx(mem.clone(), 0);
        let local = w.alloc_port();
        let (host, _g) = UnixStream::pair().unwrap();
        w.conns.insert(
            local,
            Conn {
                local_port: local,
                guest_port: 1025,
                uds: host,
                state: ConnState::Connecting,
                credit: CreditTracker::new(),
                rx_fwd_cnt: 0,
                last_credit_sent: 0,
                to_uds: VecDeque::new(),
            },
        );
        let placed = w.send_control(local, OP_REQUEST).unwrap();
        assert!(!placed, "no rx buffer → not placed directly");
        assert_eq!(w.rx_backlog.len(), 1, "packet is backlogged, not dropped");
    }
}
