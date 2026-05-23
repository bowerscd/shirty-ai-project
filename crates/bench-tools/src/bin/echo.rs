//! `bench-echo` — native TCP/UDP echo backend for the yggdrasil bench harness.
//!
//! Replaces the original `bench/lib/echo_{tcp,udp}.py` scripts. Those were
//! single-threaded blocking-loop Python servers that capped loopback echo
//! at ~150 k pps and injected GIL/scheduler-induced p99 noise, so both
//! the yggdrasil and nginx legs of pps/throughput scenarios flat-lined
//! at the *backend's* ceiling rather than the proxy's. The result was
//! artificially low and artificially convergent numbers — the harness
//! could not tell the proxy under test from the echo behind it.
//!
//! This implementation:
//!
//! * Uses a multi-threaded tokio runtime.
//! * Spawns `--workers` independent listener sockets, each bound to the
//!   same address with `SO_REUSEADDR + SO_REUSEPORT`. The kernel then
//!   load-balances incoming connections (TCP) or datagrams (UDP) across
//!   workers, giving the echo plenty of headroom on a multi-core host.
//! * Sets `TCP_NODELAY` per connection and bumps UDP socket buffers so
//!   transient bursts don't cause drops.
//!
//! Defaults match the old Python scripts' bind (`127.0.0.1:<port>`); the
//! one new knob, `--workers`, defaults to available_parallelism so the
//! echo is never the bottleneck without the operator opting into it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

#[derive(Debug, Parser)]
#[command(
    name = "bench-echo",
    version,
    about = "TCP/UDP echo backend for the yggdrasil bench harness"
)]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Debug, Subcommand)]
enum Mode {
    /// Echo TCP byte streams.
    Tcp(CommonArgs),
    /// Echo UDP datagrams to their sender, optionally also pushing an
    /// independent server-originated stream.
    Udp(UdpArgs),
}

#[derive(Debug, clap::Args)]
struct CommonArgs {
    /// Port to bind on `--bind`.
    port: u16,
    /// Bind host. Defaults to loopback for parity with the old Python echo.
    #[arg(long, default_value = "127.0.0.1")]
    bind: String,
    /// Number of independent listener sockets bound via `SO_REUSEPORT`.
    /// Defaults to available_parallelism so the echo can scale across
    /// cores and not bottleneck the proxy under test.
    #[arg(long, default_value_t = default_workers())]
    workers: usize,
}

#[derive(Debug, clap::Args)]
struct UdpArgs {
    #[command(flatten)]
    common: CommonArgs,
    /// Per-source-address rate (packets/second) at which the echo also
    /// originates **unsolicited** datagrams back to whichever sources
    /// have contacted it. Default `0` keeps the legacy pure-echo behaviour.
    ///
    /// Set this together with `--originate-bytes` to simulate workloads
    /// where the upstream pushes a server-driven stream concurrently with
    /// echoing client requests — game state broadcasts, voice/video
    /// frames, push notifications. Exercises both directions of the
    /// proxy's data plane (handle_inbound + upstream_to_client_loop)
    /// under independent rate control.
    #[arg(long, default_value_t = 0)]
    originate_pps: u32,
    /// Payload size of originated datagrams. First 9 bytes are reserved
    /// for a (type, timestamp) header the matching loadgen reads.
    #[arg(long, default_value_t = 64)]
    originate_bytes: usize,
    /// Cap on concurrent per-source origination tasks. Sources beyond
    /// this cap still get their datagrams echoed but no originated
    /// stream — guards against unbounded resource growth in adversarial
    /// scenarios.
    #[arg(long, default_value_t = 4096)]
    originate_max_sources: usize,
}

fn default_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;
    runtime.block_on(async move {
        match cli.mode {
            Mode::Tcp(args) => run_tcp(args).await,
            Mode::Udp(args) => run_udp(args).await,
        }
    })
}

fn resolve_bind(args: &CommonArgs) -> Result<SocketAddr> {
    let s = format!("{}:{}", args.bind, args.port);
    s.parse().with_context(|| format!("parse bind address {s}"))
}

fn make_reuseport_socket(addr: SocketAddr, udp: bool) -> Result<Socket> {
    let domain = Domain::for_address(addr);
    let (ty, proto) = if udp {
        (Type::DGRAM, Protocol::UDP)
    } else {
        (Type::STREAM, Protocol::TCP)
    };
    let sock = Socket::new(domain, ty, Some(proto)).context("socket(2)")?;
    sock.set_reuse_address(true)
        .context("setsockopt SO_REUSEADDR")?;
    sock.set_reuse_port(true)
        .context("setsockopt SO_REUSEPORT")?;
    sock.set_nonblocking(true)
        .context("set socket non-blocking")?;
    if udp {
        let _ = sock.set_recv_buffer_size(4 * 1024 * 1024);
        let _ = sock.set_send_buffer_size(4 * 1024 * 1024);
    }
    sock.bind(&addr.into())
        .with_context(|| format!("bind {addr}"))?;
    if !udp {
        sock.listen(4096).context("listen")?;
    }
    Ok(sock)
}

async fn run_tcp(args: CommonArgs) -> Result<()> {
    let addr = resolve_bind(&args)?;
    let workers = args.workers.max(1);
    let mut handles = Vec::with_capacity(workers);
    for worker_id in 0..workers {
        let sock = make_reuseport_socket(addr, false)?;
        let std_listener: std::net::TcpListener = sock.into();
        let listener = TcpListener::from_std(std_listener)
            .with_context(|| format!("adopt TCP listener (worker {worker_id})"))?;
        handles.push(tokio::spawn(async move {
            accept_tcp_loop(listener).await;
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    Ok(())
}

async fn accept_tcp_loop(listener: TcpListener) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                tokio::spawn(serve_tcp(stream));
            }
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }
}

async fn serve_tcp(mut stream: TcpStream) {
    let _ = stream.set_nodelay(true);
    let (mut rd, mut wr) = stream.split();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match rd.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        if wr.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
}

async fn run_udp(args: UdpArgs) -> Result<()> {
    let addr = resolve_bind(&args.common)?;
    let workers = args.common.workers.max(1);
    let originate_pps = args.originate_pps;
    let originate_bytes = args.originate_bytes.max(9);
    let originate_max_sources = args.originate_max_sources;

    // Shared registry of sources we already spawned an originator for.
    // Keeps the per-source originate task count bounded so a hostile
    // client can't OOM us by sending from millions of source ports.
    let originators: Arc<dashmap::DashMap<SocketAddr, ()>> = Arc::new(dashmap::DashMap::new());

    let mut handles = Vec::with_capacity(workers);
    for worker_id in 0..workers {
        let sock = make_reuseport_socket(addr, true)?;
        let std_sock: std::net::UdpSocket = sock.into();
        let udp = UdpSocket::from_std(std_sock)
            .with_context(|| format!("adopt UDP socket (worker {worker_id})"))?;
        let udp = Arc::new(udp);
        let originators = Arc::clone(&originators);
        handles.push(tokio::spawn(async move {
            udp_recv_loop(
                udp,
                originate_pps,
                originate_bytes,
                originate_max_sources,
                originators,
            )
            .await;
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    Ok(())
}

async fn udp_recv_loop(
    udp: Arc<UdpSocket>,
    originate_pps: u32,
    originate_bytes: usize,
    originate_max_sources: usize,
    originators: Arc<dashmap::DashMap<SocketAddr, ()>>,
) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match udp.recv_from(&mut buf).await {
            Ok((n, peer)) => {
                // Echo first (matches legacy behaviour).
                let _ = udp.send_to(&buf[..n], peer).await;
                // Then, if origination is on and we haven't seen this
                // source yet, spawn its dedicated send loop.
                if originate_pps > 0
                    && originators.len() < originate_max_sources
                    && originators.insert(peer, ()).is_none()
                {
                    let send_sock = Arc::clone(&udp);
                    tokio::spawn(originate_loop(
                        send_sock,
                        peer,
                        originate_pps,
                        originate_bytes,
                    ));
                }
            }
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }
}

async fn originate_loop(sock: Arc<UdpSocket>, dst: SocketAddr, pps: u32, bytes: usize) {
    let interval = Duration::from_secs_f64(1.0 / f64::from(pps).max(1.0));
    let mut payload = vec![0u8; bytes.max(9)];
    // Type byte: 1 = server-originated. The matching loadgen distinguishes
    // these from echoes (type 0) so it can attribute one-way latency
    // separately from RTT.
    payload[0] = 1;
    loop {
        let ts = now_ns().to_le_bytes();
        payload[1..9].copy_from_slice(&ts);
        if sock.send_to(&payload, dst).await.is_err() {
            // The destination went away; keep trying anyway. The
            // matching client may have reconnected from a fresh port,
            // which will register a NEW originator. We don't tear this
            // task down on a single failure — short ICMP unreach
            // storms shouldn't kill long-lived broadcasts.
        }
        tokio::time::sleep(interval).await;
    }
}

fn now_ns() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
