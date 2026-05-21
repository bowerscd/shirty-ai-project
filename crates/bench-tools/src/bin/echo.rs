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
    /// Echo UDP datagrams to their sender.
    Udp(CommonArgs),
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

async fn run_udp(args: CommonArgs) -> Result<()> {
    let addr = resolve_bind(&args)?;
    let workers = args.workers.max(1);
    let mut handles = Vec::with_capacity(workers);
    for worker_id in 0..workers {
        let sock = make_reuseport_socket(addr, true)?;
        let std_sock: std::net::UdpSocket = sock.into();
        let udp = UdpSocket::from_std(std_sock)
            .with_context(|| format!("adopt UDP socket (worker {worker_id})"))?;
        let udp = Arc::new(udp);
        handles.push(tokio::spawn(async move {
            udp_recv_loop(udp).await;
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    Ok(())
}

async fn udp_recv_loop(udp: Arc<UdpSocket>) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match udp.recv_from(&mut buf).await {
            Ok((n, peer)) => {
                let _ = udp.send_to(&buf[..n], peer).await;
            }
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }
}
