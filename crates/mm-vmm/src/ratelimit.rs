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

#[cfg(test)]
mod tests {
    use super::*;

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
}
