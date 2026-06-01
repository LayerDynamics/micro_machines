//! Pure virtio-vsock protocol primitives (SPEC: virtio-v1.1 §5.10), shared by the
//! Linux vsock device.
//!
//! The packet header framing and the connection **credit** (flow-control) accounting
//! are the subtle, error-prone parts of a vsock implementation, so they live here as
//! pure, cross-platform, unit-tested code. The device's queue/UDS plumbing drives
//! them.

/// `virtio_vsock_hdr` length (all fields little-endian).
pub const VSOCK_HDR_LEN: usize = 44;

/// Connection-oriented stream socket type.
pub const TYPE_STREAM: u16 = 1;
/// Host context id (`VMADDR_CID_HOST`).
pub const HOST_CID: u64 = 2;

/// virtio-vsock operation types (the connection state machine).
pub const OP_REQUEST: u16 = 1;
pub const OP_RESPONSE: u16 = 2;
pub const OP_RST: u16 = 3;
pub const OP_SHUTDOWN: u16 = 4;
pub const OP_RW: u16 = 5;
pub const OP_CREDIT_UPDATE: u16 = 6;
pub const OP_CREDIT_REQUEST: u16 = 7;

/// A parsed/serializable `virtio_vsock_hdr`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VsockHeader {
    pub src_cid: u64,
    pub dst_cid: u64,
    pub src_port: u32,
    pub dst_port: u32,
    /// Length of the data payload following the header.
    pub len: u32,
    pub type_: u16,
    pub op: u16,
    pub flags: u32,
    /// Sender's receive-buffer size (for the peer's flow control).
    pub buf_alloc: u32,
    /// Bytes the sender has consumed from its receive stream (flow control).
    pub fwd_cnt: u32,
}

impl VsockHeader {
    /// Parse a header from the front of `b`, or `None` if too short.
    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() < VSOCK_HDR_LEN {
            return None;
        }
        let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let u16_at = |o: usize| u16::from_le_bytes(b[o..o + 2].try_into().unwrap());
        Some(Self {
            src_cid: u64_at(0),
            dst_cid: u64_at(8),
            src_port: u32_at(16),
            dst_port: u32_at(20),
            len: u32_at(24),
            type_: u16_at(28),
            op: u16_at(30),
            flags: u32_at(32),
            buf_alloc: u32_at(36),
            fwd_cnt: u32_at(40),
        })
    }

    /// Serialize to the 44-byte wire form.
    pub fn to_bytes(&self) -> [u8; VSOCK_HDR_LEN] {
        let mut b = [0u8; VSOCK_HDR_LEN];
        b[0..8].copy_from_slice(&self.src_cid.to_le_bytes());
        b[8..16].copy_from_slice(&self.dst_cid.to_le_bytes());
        b[16..20].copy_from_slice(&self.src_port.to_le_bytes());
        b[20..24].copy_from_slice(&self.dst_port.to_le_bytes());
        b[24..28].copy_from_slice(&self.len.to_le_bytes());
        b[28..30].copy_from_slice(&self.type_.to_le_bytes());
        b[30..32].copy_from_slice(&self.op.to_le_bytes());
        b[32..36].copy_from_slice(&self.flags.to_le_bytes());
        b[36..40].copy_from_slice(&self.buf_alloc.to_le_bytes());
        b[40..44].copy_from_slice(&self.fwd_cnt.to_le_bytes());
        b
    }
}

/// Per-connection flow-control accounting (virtio-vsock credit).
///
/// The peer advertises a receive buffer of `peer_buf_alloc` bytes and reports how
/// many it has consumed (`peer_fwd_cnt`). We track how many we have sent (`tx_cnt`).
/// In-flight (unconsumed) bytes are `tx_cnt - peer_fwd_cnt` (wrapping u32 per spec),
/// so we may send up to `peer_buf_alloc - in_flight` more before the peer's buffer
/// would overflow — sending beyond that would stall the connection.
#[derive(Clone, Copy, Debug, Default)]
pub struct CreditTracker {
    peer_buf_alloc: u32,
    peer_fwd_cnt: u32,
    tx_cnt: u32,
}

impl CreditTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Update the peer's advertised credit from an incoming packet header.
    pub fn update_peer(&mut self, buf_alloc: u32, fwd_cnt: u32) {
        self.peer_buf_alloc = buf_alloc;
        self.peer_fwd_cnt = fwd_cnt;
    }

    /// Record that we sent `n` payload bytes to the peer.
    pub fn record_sent(&mut self, n: u32) {
        self.tx_cnt = self.tx_cnt.wrapping_add(n);
    }

    /// Our running tx count (placed in the `fwd_cnt`/header of packets we send).
    pub fn tx_cnt(&self) -> u32 {
        self.tx_cnt
    }

    /// How many more payload bytes we may send before the peer's receive buffer is
    /// full (0 means wait for the peer to drain / send a credit update).
    pub fn available(&self) -> u32 {
        let in_flight = self.tx_cnt.wrapping_sub(self.peer_fwd_cnt);
        self.peer_buf_alloc.saturating_sub(in_flight)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips_little_endian() {
        let h = VsockHeader {
            src_cid: HOST_CID,
            dst_cid: 3,
            src_port: 1024,
            dst_port: 1025,
            len: 7,
            type_: TYPE_STREAM,
            op: OP_RW,
            flags: 0,
            buf_alloc: 65536,
            fwd_cnt: 42,
        };
        let bytes = h.to_bytes();
        assert_eq!(bytes.len(), VSOCK_HDR_LEN);
        assert_eq!(&bytes[16..20], &1024u32.to_le_bytes()); // src_port offset
        assert_eq!(&bytes[30..32], &OP_RW.to_le_bytes()); // op offset
        assert_eq!(VsockHeader::parse(&bytes), Some(h));
    }

    #[test]
    fn parse_rejects_short_buffer() {
        assert_eq!(VsockHeader::parse(&[0u8; VSOCK_HDR_LEN - 1]), None);
    }

    #[test]
    fn credit_tracks_in_flight_and_available() {
        let mut c = CreditTracker::new();
        c.update_peer(1000, 0); // peer can hold 1000 bytes, has consumed 0
        assert_eq!(c.available(), 1000);

        c.record_sent(400);
        assert_eq!(c.available(), 600, "400 in flight");

        c.update_peer(1000, 400); // peer consumed all 400
        assert_eq!(c.available(), 1000, "credit recovers as peer drains");

        c.record_sent(1000);
        assert_eq!(c.available(), 0, "buffer full → throttled");
    }

    #[test]
    fn credit_wraps_u32_correctly() {
        let mut c = CreditTracker::new();
        c.tx_cnt = u32::MAX; // near wrap
        c.update_peer(100, u32::MAX); // peer consumed up to the same point
        assert_eq!(c.available(), 100);
        c.record_sent(10); // wraps past u32::MAX
        assert_eq!(c.available(), 90, "wrapping in-flight math stays correct");
    }
}
