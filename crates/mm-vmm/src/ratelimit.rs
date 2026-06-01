//! Token-bucket rate limiter for virtio devices (SPEC-1 FR-28).
//!
//! A fair-sharing primitive for multi-tenant hosts: each rate-limited virtio device
//! (block, net) holds buckets that are charged per operation and per byte, and a
//! queue is throttled when its bucket runs dry until time refills it. Pure and
//! deterministic (time is passed in), so the policy is unit-testable without a VM;
//! the Linux device workers drive it with real elapsed time.
pub struct TokenBucket {
    capacity: u64,
    tokens: u64,
    refill_per_ms: u64,
}

impl TokenBucket {
    /// A full bucket of `capacity` tokens that refills `refill_per_ms` tokens per ms.
    pub fn new(capacity: u64, refill_per_ms: u64) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_per_ms,
        }
    }

    /// Advance time by `ms`, refilling tokens up to capacity (saturating).
    pub fn refill(&mut self, ms: u64) {
        let added = ms.saturating_mul(self.refill_per_ms);
        self.tokens = self.tokens.saturating_add(added).min(self.capacity);
    }

    /// Try to consume `n` tokens; returns `false` (throttle) if insufficient,
    /// leaving the bucket unchanged so the caller can retry after a [`refill`].
    pub fn consume(&mut self, n: u64) -> bool {
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }

    /// Currently available tokens (for diagnostics/metrics).
    pub fn available(&self) -> u64 {
        self.tokens
    }
}

/// A virtio device's request gate: an ops bucket + a bytes bucket, refilled from
/// elapsed wall-clock time. Built from a [`crate::config::RateLimit`]; `None` config
/// means no limiter (unlimited). The device worker calls [`wait_admit`] before
/// servicing each request, which blocks (briefly) until the request fits in budget
/// — so requests are throttled but never dropped or deadlocked.
///
/// [`wait_admit`]: DeviceRateLimiter::wait_admit
pub struct DeviceRateLimiter {
    ops: TokenBucket,
    ops_capacity: u64,
    bytes: TokenBucket,
    bytes_capacity: u64,
    last: std::time::Instant,
}

impl DeviceRateLimiter {
    /// Build a limiter from config, or `None` when unlimited. A zero-capacity bucket
    /// disables that dimension.
    pub fn from_config(rl: Option<&crate::config::RateLimit>) -> Option<Self> {
        let rl = rl?;
        Some(Self {
            ops: TokenBucket::new(rl.ops_capacity, rl.ops_refill_per_ms),
            ops_capacity: rl.ops_capacity,
            bytes: TokenBucket::new(rl.bytes_capacity, rl.bytes_refill_per_ms),
            bytes_capacity: rl.bytes_capacity,
            last: std::time::Instant::now(),
        })
    }

    /// Refill from elapsed time, then try to admit a request needing `ops` + `bytes`
    /// tokens. A request larger than a bucket's capacity is clamped to capacity (so
    /// it waits for a full bucket, then proceeds — never starves). Returns whether it
    /// was admitted (tokens consumed) this instant.
    pub fn try_admit(&mut self, ops: u64, bytes: u64) -> bool {
        let now = std::time::Instant::now();
        let ms = now.saturating_duration_since(self.last).as_millis() as u64;
        if ms > 0 {
            self.ops.refill(ms);
            self.bytes.refill(ms);
            self.last = now;
        }
        let need_ops = ops.min(self.ops_capacity);
        let need_bytes = bytes.min(self.bytes_capacity);
        if self.ops.available() >= need_ops && self.bytes.available() >= need_bytes {
            self.ops.consume(need_ops);
            self.bytes.consume(need_bytes);
            true
        } else {
            false
        }
    }

    /// Block (sleeping briefly) until a request needing `ops` + `bytes` tokens is
    /// admitted. Bounded by `max_wait` so a misconfigured limiter can't hang a worker
    /// forever; returns `true` if admitted, `false` if it gave up (and admits anyway,
    /// charging what it can, so the request still proceeds).
    pub fn wait_admit(&mut self, ops: u64, bytes: u64, max_wait: std::time::Duration) {
        let deadline = std::time::Instant::now() + max_wait;
        while !self.try_admit(ops, bytes) {
            if std::time::Instant::now() >= deadline {
                // Give up waiting but still charge available tokens so we don't spin.
                let need_ops = ops.min(self.ops_capacity);
                let need_bytes = bytes.min(self.bytes_capacity);
                self.ops.consume(need_ops.min(self.ops.available()));
                self.bytes.consume(need_bytes.min(self.bytes.available()));
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RateLimit;

    #[test]
    fn throttles_then_refills() {
        let mut b = TokenBucket::new(100, 10);
        assert!(b.consume(100));
        assert!(!b.consume(1), "empty -> throttled");
        b.refill(5); // +50 tokens
        assert!(b.consume(50));
        assert!(!b.consume(1));
    }

    #[test]
    fn refill_caps_at_capacity() {
        let mut b = TokenBucket::new(100, 10);
        b.refill(1_000_000);
        assert!(b.consume(100) && !b.consume(1));
    }

    #[test]
    fn rejected_consume_leaves_tokens_intact() {
        let mut b = TokenBucket::new(10, 1);
        assert!(!b.consume(11));
        assert_eq!(
            b.available(),
            10,
            "a throttled consume must not partially drain"
        );
        assert!(b.consume(10));
    }

    #[test]
    fn no_config_means_no_limiter() {
        assert!(DeviceRateLimiter::from_config(None).is_none());
    }

    #[test]
    fn device_limiter_admits_until_a_bucket_is_dry() {
        // No refill (refill_per_ms = 0) → deterministic regardless of wall-clock.
        let rl = RateLimit {
            ops_capacity: 3,
            ops_refill_per_ms: 0,
            bytes_capacity: 10_000,
            bytes_refill_per_ms: 0,
        };
        let mut l = DeviceRateLimiter::from_config(Some(&rl)).unwrap();
        assert!(l.try_admit(1, 100));
        assert!(l.try_admit(1, 100));
        assert!(l.try_admit(1, 100));
        assert!(!l.try_admit(1, 100), "ops bucket dry → throttled");
    }

    #[test]
    fn oversized_request_is_clamped_to_capacity_not_starved() {
        let rl = RateLimit {
            ops_capacity: 100,
            ops_refill_per_ms: 0,
            bytes_capacity: 500,
            bytes_refill_per_ms: 0,
        };
        let mut l = DeviceRateLimiter::from_config(Some(&rl)).unwrap();
        // A 9000-byte request exceeds the 500-byte bucket; it is clamped to capacity
        // and admitted from a full bucket rather than starving forever.
        assert!(l.try_admit(1, 9000));
    }
}
