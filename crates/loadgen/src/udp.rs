//! UDP load generators.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use hdrhistogram::Histogram;
use serde_json::json;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::report::{build_report, finalize_stats, unix_ms_now, LatencySummary, Report, Stats};
use crate::{UdpArgs, UdpChurnArgs};

/// Echo-RTT loadgen: open N flows, send packets at the target aggregate pps,
/// expect the proxy/echo to bounce them back, capture round-trip latency.
pub async fn run_udp(subject: &str, args: UdpArgs) -> Result<Report> {
    let target: SocketAddr = args
        .target
        .parse()
        .with_context(|| format!("parse target {}", args.target))?;
    let UdpArgs {
        target: _,
        flows,
        pps,
        packet_size,
        duration,
        warmup,
    } = args;

    // Per-flow socket + send-time map.
    let mut flow_socks: Vec<Arc<UdpSocket>> = Vec::with_capacity(flows as usize);
    for _ in 0..flows {
        let sock = UdpSocket::bind("0.0.0.0:0").await.context("bind UDP flow")?;
        sock.connect(target).await.context("connect UDP flow")?;
        flow_socks.push(Arc::new(sock));
    }

    let hist: Arc<Mutex<Histogram<u64>>> =
        Arc::new(Mutex::new(Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap()));
    let tx_packets = Arc::new(AtomicU64::new(0));
    let rx_packets = Arc::new(AtomicU64::new(0));
    let tx_bytes = Arc::new(AtomicU64::new(0));
    let rx_bytes = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));

    // Receivers, one per flow. Each receiver reads echoes and computes RTT
    // from the embedded send timestamp.
    let recv_handles: Vec<_> = flow_socks
        .iter()
        .cloned()
        .map(|sock| {
            let hist = hist.clone();
            let rx_packets = rx_packets.clone();
            let rx_bytes = rx_bytes.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65_535];
                loop {
                    match sock.recv(&mut buf).await {
                        Ok(n) => {
                            if n < 8 {
                                continue;
                            }
                            let sent_ns = u64::from_le_bytes(buf[..8].try_into().unwrap());
                            let now_ns = now_ns();
                            let rtt_us = (now_ns.saturating_sub(sent_ns)) / 1_000;
                            hist.lock().await.saturating_record(rtt_us.max(1));
                            rx_packets.fetch_add(1, Ordering::Relaxed);
                            rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                        }
                        Err(_) => return,
                    }
                }
            })
        })
        .collect();

    // Compute the per-flow send interval that aggregates to the target pps.
    let per_flow_pps = (pps as f64 / flows as f64).max(1.0);
    let interval = Duration::from_secs_f64(1.0 / per_flow_pps);

    // Warmup loop — same logic but stats aren't counted.
    if !warmup.is_zero() {
        run_send_loop(
            &flow_socks,
            packet_size,
            interval,
            warmup,
            None,
            None,
            errors.clone(),
        )
        .await;
        // Drain echoes from warmup so they don't pollute hist.
        hist.lock().await.reset();
        rx_packets.store(0, Ordering::Relaxed);
        rx_bytes.store(0, Ordering::Relaxed);
    }

    let ts_start = unix_ms_now();
    let started = Instant::now();
    run_send_loop(
        &flow_socks,
        packet_size,
        interval,
        duration,
        Some(tx_packets.clone()),
        Some(tx_bytes.clone()),
        errors.clone(),
    )
    .await;
    // Allow the last echoes to land before tearing down.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let elapsed = started.elapsed();
    let ts_end = unix_ms_now();

    for h in recv_handles {
        h.abort();
    }

    let mut stats = Stats {
        tx_packets: tx_packets.load(Ordering::Relaxed),
        rx_packets: rx_packets.load(Ordering::Relaxed),
        tx_bytes: tx_bytes.load(Ordering::Relaxed),
        rx_bytes: rx_bytes.load(Ordering::Relaxed),
        errors: errors.load(Ordering::Relaxed),
        ..Stats::default()
    };
    finalize_stats(&mut stats, elapsed);
    stats.latency_us = Some(LatencySummary::from_hist(&*hist.lock().await));

    let mut params = serde_json::Map::new();
    params.insert("flows".into(), json!(flows));
    params.insert("pps".into(), json!(pps));
    params.insert("packet_size".into(), json!(packet_size));
    params.insert("warmup_s".into(), json!(warmup.as_secs_f64()));
    Ok(build_report(
        "udp",
        subject,
        &target.to_string(),
        params,
        stats,
        ts_start,
        ts_end,
    ))
}

async fn run_send_loop(
    flow_socks: &[Arc<UdpSocket>],
    packet_size: usize,
    interval: Duration,
    duration: Duration,
    tx_packets: Option<Arc<AtomicU64>>,
    tx_bytes: Option<Arc<AtomicU64>>,
    errors: Arc<AtomicU64>,
) {
    let deadline = Instant::now() + duration;
    let mut buf = vec![0u8; packet_size];

    // Each iteration: send one packet on each flow, sleep interval.
    while Instant::now() < deadline {
        let send_at = Instant::now();
        for sock in flow_socks {
            // Embed the send timestamp at the front of the payload so the
            // receiver can compute RTT.
            let ts = now_ns().to_le_bytes();
            let n = ts.len().min(buf.len());
            buf[..n].copy_from_slice(&ts[..n]);
            match sock.try_send(&buf) {
                Ok(sent) => {
                    if let Some(tp) = &tx_packets {
                        tp.fetch_add(1, Ordering::Relaxed);
                    }
                    if let Some(tb) = &tx_bytes {
                        tb.fetch_add(sent as u64, Ordering::Relaxed);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Kernel send buffer full; skip this tick.
                    errors.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        // Sleep, but not past the deadline.
        let now = Instant::now();
        let wakeup = send_at + interval;
        if wakeup > now && wakeup <= deadline {
            tokio::time::sleep_until(wakeup.into()).await;
        }
    }
}

/// Open new UDP flows at the target rate, send one packet on each, close.
/// Measures the flow-table churn capacity.
pub async fn run_udp_churn(subject: &str, args: UdpChurnArgs) -> Result<Report> {
    let target: SocketAddr = args
        .target
        .parse()
        .with_context(|| format!("parse target {}", args.target))?;
    let UdpChurnArgs {
        target: _,
        rate,
        duration,
    } = args;

    let interval = Duration::from_secs_f64(1.0 / rate as f64);
    let payload = b"loadgen-churn";
    let tx_packets = AtomicU64::new(0);
    let rx_packets = AtomicU64::new(0);
    let errors = AtomicU64::new(0);

    let ts_start = unix_ms_now();
    let started = Instant::now();
    let deadline = started + duration;
    while Instant::now() < deadline {
        let send_at = Instant::now();
        match UdpSocket::bind("0.0.0.0:0").await {
            Ok(sock) => match sock.connect(target).await {
                Ok(()) => match sock.send(payload).await {
                    Ok(_) => {
                        tx_packets.fetch_add(1, Ordering::Relaxed);
                        // Try to read one echo so we can also measure
                        // whether the proxy actually responded. Use a tight
                        // budget so churn rate is the dominant signal.
                        let mut buf = [0u8; 64];
                        if tokio::time::timeout(
                            Duration::from_millis(20),
                            sock.recv(&mut buf),
                        )
                        .await
                        .ok()
                        .and_then(|r| r.ok())
                        .is_some()
                        {
                            rx_packets.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                },
                Err(_) => {
                    errors.fetch_add(1, Ordering::Relaxed);
                }
            },
            Err(_) => {
                errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        let wakeup = send_at + interval;
        let now = Instant::now();
        if wakeup > now && wakeup <= deadline {
            tokio::time::sleep_until(wakeup.into()).await;
        }
    }
    let elapsed = started.elapsed();
    let ts_end = unix_ms_now();

    let mut stats = Stats {
        tx_packets: tx_packets.load(Ordering::Relaxed),
        rx_packets: rx_packets.load(Ordering::Relaxed),
        tx_bytes: tx_packets.load(Ordering::Relaxed) * payload.len() as u64,
        rx_bytes: rx_packets.load(Ordering::Relaxed) * payload.len() as u64,
        errors: errors.load(Ordering::Relaxed),
        ..Stats::default()
    };
    finalize_stats(&mut stats, elapsed);

    let mut params = serde_json::Map::new();
    params.insert("target_rate".into(), json!(rate));
    Ok(build_report(
        "udp-churn",
        subject,
        &target.to_string(),
        params,
        stats,
        ts_start,
        ts_end,
    ))
}

fn now_ns() -> u64 {
    // Monotonic; safe to compare against itself within one process.
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
