//! API request-latency metrics (SPEC-1 NFR-P4: API p95 < 200 ms, tracked).
//!
//! Every REST request's wall-clock duration is recorded into an HdrHistogram; the
//! `/metrics` endpoint exposes the resulting percentiles (p50/p95/p99) in Prometheus
//! text format, so operators can track and alert on API latency.
use std::sync::Mutex;

use hdrhistogram::Histogram;

/// Thread-safe latency recorder. Cheap to clone the `Arc` wrapping it; recording is
/// a single locked histogram update.
pub struct Metrics {
    latency_ms: Mutex<Histogram<u64>>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    /// A histogram covering 1 ms … 60 s with 3 significant figures of precision.
    pub fn new() -> Self {
        Self {
            latency_ms: Mutex::new(
                Histogram::new_with_bounds(1, 60_000, 3).expect("valid histogram bounds"),
            ),
        }
    }

    /// Record one request's latency in milliseconds (clamped into the histogram's
    /// `[1, 60000]` range).
    pub fn record_ms(&self, ms: u64) {
        if let Ok(mut h) = self.latency_ms.lock() {
            h.saturating_record(ms.clamp(1, 60_000));
        }
    }

    /// p95 latency in ms (0 if nothing has been recorded yet).
    pub fn p95_ms(&self) -> u64 {
        self.with(|h| h.value_at_quantile(0.95))
    }

    /// Render the recorded latency distribution as Prometheus summary text.
    pub fn prometheus(&self) -> String {
        let (p50, p95, p99, count, max) = self.with(|h| {
            (
                h.value_at_quantile(0.50),
                h.value_at_quantile(0.95),
                h.value_at_quantile(0.99),
                h.len(),
                h.max(),
            )
        });
        format!(
            "# HELP mm_api_request_duration_ms API request latency in milliseconds.\n\
             # TYPE mm_api_request_duration_ms summary\n\
             mm_api_request_duration_ms{{quantile=\"0.5\"}} {p50}\n\
             mm_api_request_duration_ms{{quantile=\"0.95\"}} {p95}\n\
             mm_api_request_duration_ms{{quantile=\"0.99\"}} {p99}\n\
             mm_api_request_duration_ms_count {count}\n\
             mm_api_request_duration_ms_max {max}\n"
        )
    }

    fn with<T>(&self, f: impl FnOnce(&Histogram<u64>) -> T) -> T {
        let guard = self.latency_ms.lock().unwrap_or_else(|e| e.into_inner());
        f(&guard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_reflect_recorded_latencies() {
        let m = Metrics::new();
        for ms in 1..=100 {
            m.record_ms(ms);
        }
        // 100 samples 1..=100 → p95 ≈ 95 (within the histogram's precision).
        let p95 = m.p95_ms();
        assert!((93..=97).contains(&p95), "p95 was {p95}, expected ~95");

        let text = m.prometheus();
        assert!(
            text.contains("mm_api_request_duration_ms_count 100"),
            "{text}"
        );
        assert!(text.contains("quantile=\"0.95\""), "{text}");
    }

    #[test]
    fn empty_metrics_render_without_panicking() {
        let text = Metrics::new().prometheus();
        assert!(text.contains("mm_api_request_duration_ms_count 0"));
    }

    #[test]
    fn out_of_range_latencies_are_clamped() {
        let m = Metrics::new();
        m.record_ms(0); // below low bound → clamped to 1
        m.record_ms(10_000_000); // above high bound → clamped to 60000
        assert_eq!(m.with(|h| h.len()), 2);
    }
}
