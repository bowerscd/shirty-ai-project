//! TCP load generators.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use hdrhistogram::Histogram;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};

use crate::report::{build_report, finalize_stats, unix_ms_now, LatencySummary, Report, Stats};
use crate::{TcpArgs, TcpConnrateArgs, TcpIdleArgs, TcpThroughputArgs};

/// Ping-pong fixed-size messages on N TCP connections, capture RTT.
pub async fn run_tcp(subject: &str, args: TcpArgs) -> Result<Report> {
    let target: SocketAddr = args
        .target
        .parse()
        .with_context(|| format!("parse target {}", args.target))?;
    let TcpArgs {
        target: _,
        connections,
        message_size,
        duration,
        warmup,
    } = args;

    let total_duration = warmup + duration;
    let hist: Arc<Mutex<Histogram<u64>>> = Arc::new(Mutex::new(
        Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap(),
    ));
    let tx_packets = Arc::new(AtomicU64::new(0));
    let rx_packets = Arc::new(AtomicU64::new(0));
    let tx_bytes = Arc::new(AtomicU64::new(0));
    let rx_bytes = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));

    let ts_start = unix_ms_now();
    let started = Instant::now();
    let measure_start = started + warmup;
    let deadline = started + total_duration;

    let mut handles = Vec::with_capacity(connections as usize);
    for _ in 0..connections {
        let hist = hist.clone();
        let tx_packets = tx_packets.clone();
        let rx_packets = rx_packets.clone();
        let tx_bytes = tx_bytes.clone();
        let rx_bytes = rx_bytes.clone();
        let errors = errors.clone();
        handles.push(tokio::spawn(async move {
            let mut stream = match TcpStream::connect(target).await {
                Ok(s) => s,
                Err(_) => {
                    errors.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };
            let _ = stream.set_nodelay(true);
            let mut send_buf = vec![0u8; message_size];
            let mut recv_buf = vec![0u8; message_size];
            while Instant::now() < deadline {
                let ts = now_ns().to_le_bytes();
                let n = ts.len().min(send_buf.len());
                send_buf[..n].copy_from_slice(&ts[..n]);
                if stream.write_all(&send_buf).await.is_err() {
                    errors.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                if Instant::now() >= measure_start {
                    tx_packets.fetch_add(1, Ordering::Relaxed);
                    tx_bytes.fetch_add(message_size as u64, Ordering::Relaxed);
                }
                if stream.read_exact(&mut recv_buf).await.is_err() {
                    errors.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                if Instant::now() >= measure_start {
                    let sent_ns = u64::from_le_bytes(recv_buf[..8].try_into().unwrap());
                    let rtt_us = now_ns().saturating_sub(sent_ns) / 1_000;
                    hist.lock().await.saturating_record(rtt_us.max(1));
                    rx_packets.fetch_add(1, Ordering::Relaxed);
                    rx_bytes.fetch_add(message_size as u64, Ordering::Relaxed);
                }
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }
    let elapsed = Instant::now().duration_since(measure_start);
    let ts_end = unix_ms_now();

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
    params.insert("connections".into(), json!(connections));
    params.insert("message_size".into(), json!(message_size));
    params.insert("warmup_s".into(), json!(warmup.as_secs_f64()));
    Ok(build_report(
        "tcp",
        subject,
        &target.to_string(),
        params,
        stats,
        ts_start,
        ts_end,
    ))
}

/// Sustained bulk throughput: open N TCP streams, fill each with a continuous
/// write pipeline, measure aggregate bytes/sec.
pub async fn run_tcp_throughput(subject: &str, args: TcpThroughputArgs) -> Result<Report> {
    let target: SocketAddr = args
        .target
        .parse()
        .with_context(|| format!("parse target {}", args.target))?;
    let TcpThroughputArgs {
        target: _,
        streams,
        buffer_size,
        duration,
    } = args;

    let tx_bytes = Arc::new(AtomicU64::new(0));
    let rx_bytes = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));

    let ts_start = unix_ms_now();
    let started = Instant::now();
    let deadline = started + duration;

    let mut handles = Vec::with_capacity(streams as usize);
    for _ in 0..streams {
        let tx_bytes = tx_bytes.clone();
        let rx_bytes = rx_bytes.clone();
        let errors = errors.clone();
        handles.push(tokio::spawn(async move {
            let stream = match TcpStream::connect(target).await {
                Ok(s) => s,
                Err(_) => {
                    errors.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };
            let _ = stream.set_nodelay(true);
            let (mut rd, mut wr) = stream.into_split();
            let send_buf = vec![0xAAu8; buffer_size];
            let tx_bytes_w = tx_bytes.clone();
            let errors_w = errors.clone();
            // Pump writes.
            let w_task = tokio::spawn(async move {
                while Instant::now() < deadline {
                    match wr.write_all(&send_buf).await {
                        Ok(()) => {
                            tx_bytes_w.fetch_add(buffer_size as u64, Ordering::Relaxed);
                        }
                        Err(_) => {
                            errors_w.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                    }
                }
            });
            // Drain reads (echo bytes coming back from the upstream).
            let r_task = tokio::spawn(async move {
                let mut recv_buf = vec![0u8; buffer_size];
                while Instant::now() < deadline {
                    match rd.read(&mut recv_buf).await {
                        Ok(0) => return,
                        Ok(n) => {
                            rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                        }
                        Err(_) => return,
                    }
                }
            });
            let _ = tokio::join!(w_task, r_task);
        }));
    }
    for h in handles {
        let _ = h.await;
    }

    let elapsed = started.elapsed();
    let ts_end = unix_ms_now();
    let mut stats = Stats {
        tx_bytes: tx_bytes.load(Ordering::Relaxed),
        rx_bytes: rx_bytes.load(Ordering::Relaxed),
        errors: errors.load(Ordering::Relaxed),
        ..Stats::default()
    };
    finalize_stats(&mut stats, elapsed);

    let mut params = serde_json::Map::new();
    params.insert("streams".into(), json!(streams));
    params.insert("buffer_size".into(), json!(buffer_size));
    Ok(build_report(
        "tcp-throughput",
        subject,
        &target.to_string(),
        params,
        stats,
        ts_start,
        ts_end,
    ))
}

/// Repeatedly open + close short-lived TCP connections. Caps concurrency so
/// the kernel's accept queue doesn't pile up arbitrarily.
pub async fn run_tcp_connrate(subject: &str, args: TcpConnrateArgs) -> Result<Report> {
    let target: SocketAddr = args
        .target
        .parse()
        .with_context(|| format!("parse target {}", args.target))?;
    let TcpConnrateArgs {
        target: _,
        concurrency,
        duration,
    } = args;

    let sem = Arc::new(Semaphore::new(concurrency as usize));
    let connects = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));

    let ts_start = unix_ms_now();
    let started = Instant::now();
    let deadline = started + duration;

    let mut handles = Vec::new();
    while Instant::now() < deadline {
        let permit = match sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break,
        };
        let connects = connects.clone();
        let errors = errors.clone();
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            match TcpStream::connect(target).await {
                Ok(s) => {
                    drop(s); // immediate close.
                    connects.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    // Drain in-flight attempts.
    for h in handles {
        let _ = h.await;
    }

    let elapsed = started.elapsed();
    let ts_end = unix_ms_now();
    let mut stats = Stats {
        tx_packets: connects.load(Ordering::Relaxed),
        rx_packets: connects.load(Ordering::Relaxed),
        errors: errors.load(Ordering::Relaxed),
        ..Stats::default()
    };
    finalize_stats(&mut stats, elapsed);

    let mut params = serde_json::Map::new();
    params.insert("concurrency".into(), json!(concurrency));
    Ok(build_report(
        "tcp-connrate",
        subject,
        &target.to_string(),
        params,
        stats,
        ts_start,
        ts_end,
    ))
}

fn now_ns() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Open `connections` TCP connections at bounded ramp-up parallelism,
/// hold every one idle for `hold`, then close. The semaphore bounds
/// only the connect phase — each task drops its permit as soon as the
/// socket is established, so the steady-state simultaneously-open
/// count converges to `connections` (modulo connect errors). Records
/// the per-connect latency histogram. `tx_packets` and `rx_packets`
/// report the established count (one successful TCP handshake = one
/// of each).
pub async fn run_tcp_idle(subject: &str, args: TcpIdleArgs) -> Result<Report> {
    let target: SocketAddr = args
        .target
        .parse()
        .with_context(|| format!("parse target {}", args.target))?;
    let TcpIdleArgs {
        target: _,
        connections,
        concurrency,
        hold,
    } = args;

    let sem = Arc::new(Semaphore::new(concurrency.max(1) as usize));
    let hist: Arc<Mutex<Histogram<u64>>> = Arc::new(Mutex::new(
        Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).unwrap(),
    ));
    let established = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));

    let ts_start = unix_ms_now();
    let started = Instant::now();

    let mut handles = Vec::with_capacity(connections as usize);
    for _ in 0..connections {
        let permit = match sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break,
        };
        let hist = hist.clone();
        let established = established.clone();
        let errors = errors.clone();
        handles.push(tokio::spawn(async move {
            let connect_start = Instant::now();
            let stream = match TcpStream::connect(target).await {
                Ok(s) => s,
                Err(_) => {
                    errors.fetch_add(1, Ordering::Relaxed);
                    drop(permit);
                    return;
                }
            };
            let connect_us = connect_start.elapsed().as_micros() as u64;
            hist.lock().await.saturating_record(connect_us.max(1));
            established.fetch_add(1, Ordering::Relaxed);
            drop(permit);
            tokio::time::sleep(hold).await;
            drop(stream);
        }));
    }
    for h in handles {
        let _ = h.await;
    }

    let elapsed = started.elapsed();
    let ts_end = unix_ms_now();

    let conns = established.load(Ordering::Relaxed);
    let mut stats = Stats {
        tx_packets: conns,
        rx_packets: conns,
        errors: errors.load(Ordering::Relaxed),
        ..Stats::default()
    };
    finalize_stats(&mut stats, elapsed);
    stats.latency_us = Some(LatencySummary::from_hist(&*hist.lock().await));

    let mut params = serde_json::Map::new();
    params.insert("connections".into(), json!(connections));
    params.insert("concurrency".into(), json!(concurrency));
    params.insert("hold_s".into(), json!(hold.as_secs_f64()));
    Ok(build_report(
        "tcp-idle",
        subject,
        &target.to_string(),
        params,
        stats,
        ts_start,
        ts_end,
    ))
}
