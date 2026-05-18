//! Report shape (stable; `bench/compare.py` parses this).

use std::time::Duration;

use hdrhistogram::Histogram;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Report {
    pub scenario: String,
    pub subject: String,
    pub target: String,
    /// Free-form parameters (packet_size, flows, etc.) recorded verbatim so
    /// the comparison report has full context.
    pub params: serde_json::Map<String, serde_json::Value>,
    pub stats: Stats,
    pub ts_start_unix_ms: u128,
    pub ts_end_unix_ms: u128,
}

#[derive(Debug, Default, Serialize)]
pub struct Stats {
    pub duration_s: f64,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub errors: u64,
    pub loss_pct: f64,
    pub pps_tx: f64,
    pub pps_rx: f64,
    pub bytes_per_sec_tx: f64,
    pub bytes_per_sec_rx: f64,
    pub latency_us: Option<LatencySummary>,
}

#[derive(Debug, Default, Serialize)]
pub struct LatencySummary {
    pub samples: u64,
    pub min: u64,
    pub p50: u64,
    pub p90: u64,
    pub p99: u64,
    pub p999: u64,
    pub max: u64,
    pub mean: f64,
}

impl LatencySummary {
    pub fn from_hist(h: &Histogram<u64>) -> Self {
        if h.is_empty() {
            return Self::default();
        }
        Self {
            samples: h.len(),
            min: h.min(),
            p50: h.value_at_quantile(0.50),
            p90: h.value_at_quantile(0.90),
            p99: h.value_at_quantile(0.99),
            p999: h.value_at_quantile(0.999),
            max: h.max(),
            mean: h.mean(),
        }
    }
}

pub fn unix_ms_now() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

pub fn build_report(
    scenario: &str,
    subject: &str,
    target: &str,
    params: serde_json::Map<String, serde_json::Value>,
    stats: Stats,
    ts_start_unix_ms: u128,
    ts_end_unix_ms: u128,
) -> Report {
    Report {
        scenario: scenario.into(),
        subject: subject.into(),
        target: target.into(),
        params,
        stats,
        ts_start_unix_ms,
        ts_end_unix_ms,
    }
}

/// Derive throughput rates from raw counts and a duration.
pub fn finalize_stats(stats: &mut Stats, duration: Duration) {
    let secs = duration.as_secs_f64().max(f64::EPSILON);
    stats.duration_s = secs;
    stats.pps_tx = stats.tx_packets as f64 / secs;
    stats.pps_rx = stats.rx_packets as f64 / secs;
    stats.bytes_per_sec_tx = stats.tx_bytes as f64 / secs;
    stats.bytes_per_sec_rx = stats.rx_bytes as f64 / secs;
    stats.loss_pct = if stats.tx_packets > 0 {
        ((stats.tx_packets.saturating_sub(stats.rx_packets)) as f64 / stats.tx_packets as f64)
            * 100.0
    } else {
        0.0
    };
}
