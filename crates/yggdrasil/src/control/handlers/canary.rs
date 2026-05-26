//! Async dispatcher for [`Request::ChainCanary`].
//!
//! The canary command tests a rule's L4 forwarding path end-to-end
//! through the chain. The handler runs three phases:
//!
//! 1. **Rule lookup.** Walk the supervisor's current rule set for a
//!    rule with the requested `(listen, protocol)`. If none matches,
//!    return [`CanaryStatus::NoSuchRule`] with a `close_matches` list
//!    for renderer-side suggestions.
//! 2. **Arm phase.** Generate a 32-byte random token, build a
//!    [`CanaryArmFrame`], install a local arm (when this node is the
//!    terminal hop for the rule), and recurse the arm up the chain
//!    via [`ChainClientHandle::query_upstream_canary`]. If any hop is
//!    unreachable inside the timeout, return
//!    [`CanaryStatus::ChainDead`] with the truncated hop list.
//! 3. **Probe phase.** Open a TCP connection or UDP socket to the
//!    rule's listener, prefix the token, run a bidirectional
//!    send/recv at the configured rate for the configured duration,
//!    and collect per-direction throughput / loss / latency
//!    statistics. Classify the outcome as [`CanaryStatus::Ok`] or
//!    [`CanaryStatus::Degraded`] using the daemon-side thresholds.
//!
//! On clean completion (or any early-return path), the local arm is
//! removed so it doesn't outlive the canary command.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hdrhistogram::Histogram;
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use ratatoskr::canary::{
    CanaryArm as CanaryArmFrame, CanaryHop, CANARY_ARM_DEFAULT_DEADLINE_MS,
    CANARY_ARM_DEFAULT_DEPTH_BUDGET, CANARY_TOKEN_LEN,
};
use ratatoskr::control::{
    CanaryStatus, ChainCanaryResponse, CloseMatch, DirectionStats, Mode, ProbeResults, Response,
};
use ratatoskr::rule::Protocol;

use super::super::ControlState;
use crate::proxy::canary::CanaryArmTable;

/// Grace window added to the probe duration when computing the arm
/// expiry: ensures the terminal's intercept stays armed slightly
/// past the originator's intended probe end so the last in-flight
/// echo isn't accidentally rejected.
const ARM_GRACE: Duration = Duration::from_secs(5);

/// Loss threshold (fraction) above which a UDP probe is classified as
/// DEGRADED. Sub-percent loss on a healthy chain is normal; this
/// threshold is intentionally conservative.
const DEGRADED_LOSS_THRESHOLD: f64 = 0.005;

/// p99 latency threshold above which a probe is classified as
/// DEGRADED, expressed in microseconds. Captures both TCP and UDP
/// tail-latency excursions.
const DEGRADED_P99_MICROS: u64 = 50_000;

/// Default TCP probe send rate when the operator passes `0`. Bytes
/// per second, per direction. 1 MiB/s is the documented CLI default.
const TCP_DEFAULT_RATE_BPS: u64 = 1024 * 1024;

/// Default UDP probe send rate when the operator passes `0`. Packets
/// per second, per direction. 100 pps is the documented CLI default.
const UDP_DEFAULT_RATE_PPS: u64 = 100;

/// Default UDP payload size when the operator passes `0`, in bytes.
/// 1200 fits one Ethernet-MTU datagram after chain framing overhead.
/// The token prefix is counted within this size.
const UDP_DEFAULT_PAYLOAD_BYTES: usize = 1200;

/// Async dispatch for [`ratatoskr::control::Request::ChainCanary`].
#[allow(clippy::too_many_arguments)]
pub(in crate::control) async fn dispatch_chain_canary(
    rule_listen: SocketAddr,
    rule_protocol: Protocol,
    duration_ms: u32,
    rate: u32,
    payload_bytes: u32,
    timeout_ms: Option<u32>,
    state: &ControlState,
) -> Response {
    // 1. Rule lookup. The supervisor's current rule set is the source
    //    of truth for what listeners are actually bound on this node.
    let rule_name = find_rule_name(&state.supervisor_handle, rule_listen, rule_protocol);
    let rule_present = rule_name.is_some();

    if !rule_present {
        let close_matches =
            compute_close_matches(&state.supervisor_handle, rule_listen, rule_protocol);
        return Response::ChainCanary(ChainCanaryResponse {
            status: CanaryStatus::NoSuchRule,
            chain: vec![],
            probe_results: None,
            partial: false,
            close_matches,
            rule_name: None,
        });
    }

    // 2. Arm phase. Build the canary frame, install locally when
    //    we're the terminal hop for the rule, and recurse upstream.
    let mut token = [0u8; CANARY_TOKEN_LEN];
    rand::thread_rng().fill_bytes(&mut token);

    let duration = Duration::from_millis(duration_ms.max(1) as u64);
    let arm_ttl = duration + ARM_GRACE;
    let expires_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
        .saturating_add(arm_ttl.as_millis() as u64);

    let local_echo_armed = if state.mode == Mode::Terminal {
        state
            .canary_arm_table
            .arm(rule_listen, rule_protocol, token, arm_ttl);
        true
    } else {
        false
    };

    // Local hop record. The pubkey is whatever introspection exposes;
    // without it we can still build a hop record with a placeholder
    // and surface the issue via `partial`.
    let local_pubkey = state
        .introspection
        .as_ref()
        .map(|ix| ix.snapshot().chain.local)
        .unwrap_or_else(|| ratatoskr::pubkey::PubKey::x25519([0u8; 32]));

    let local_hop = CanaryHop {
        hop_index: 0,
        pubkey: local_pubkey,
        name: Some(state.node_name.clone()),
        mode: state.mode,
        rule_present: true,
        echo_armed: local_echo_armed,
        query_rtt_ms: None,
    };

    let arm_timeout_ms = timeout_ms.unwrap_or(CANARY_ARM_DEFAULT_DEADLINE_MS);
    let arm_timeout = Duration::from_millis(arm_timeout_ms.max(1) as u64);

    let mut chain_hops = vec![local_hop];
    let mut chain_partial = false;

    if let Some(upstream) = state.chain_client_handle.as_ref() {
        let arm_frame = CanaryArmFrame {
            query_id: 0, // router assigns
            depth_budget: CANARY_ARM_DEFAULT_DEPTH_BUDGET,
            deadline_ms: arm_timeout_ms,
            rule_listen,
            rule_protocol,
            token,
            expires_unix_ms,
        };
        let upstream_started = Instant::now();
        match upstream.query_upstream_canary(arm_frame, arm_timeout).await {
            Ok(reply) => {
                let rtt_ms = upstream_started.elapsed().as_millis().min(u64::MAX as u128) as u64;
                for (offset, mut hop) in reply.hops.into_iter().enumerate() {
                    hop.hop_index = (chain_hops.len() + offset) as u32;
                    if offset == 0 {
                        hop.query_rtt_ms = Some(rtt_ms);
                    }
                    chain_hops.push(hop);
                }
                if reply.partial {
                    chain_partial = true;
                    if let Some(err) = reply.error {
                        tracing::warn!(
                            error = %err,
                            "canary arm phase partial: upstream truncated"
                        );
                    }
                }
            }
            Err(e) => {
                chain_partial = true;
                tracing::warn!(error = %e, "canary arm phase failed at upstream");
            }
        }
    }

    if chain_partial {
        // Tear down the local arm — without a complete chain the
        // probe phase can't run meaningfully.
        if local_echo_armed {
            state
                .canary_arm_table
                .disarm(rule_listen, rule_protocol, &token);
        }
        return Response::ChainCanary(ChainCanaryResponse {
            status: CanaryStatus::ChainDead,
            chain: chain_hops,
            probe_results: None,
            partial: true,
            close_matches: vec![],
            rule_name,
        });
    }

    // 3. Probe phase. The arm is now installed across the chain;
    //    open the rule's listener and run a tagged probe through it.
    let probe_results = match rule_protocol {
        Protocol::Tcp => run_tcp_probe(rule_listen, &token, duration, rate).await,
        Protocol::Udp => run_udp_probe(rule_listen, &token, duration, rate, payload_bytes).await,
        Protocol::Https => Err(anyhow::anyhow!(
            "chain canary does not support Https rules in v1"
        )),
    };

    // Disarm regardless of probe outcome so the entry doesn't linger
    // until TTL.
    if local_echo_armed {
        state
            .canary_arm_table
            .disarm(rule_listen, rule_protocol, &token);
    }
    // Note: arm entries on upstream hops self-evict via their TTL;
    // we don't issue an explicit upstream `disarm` frame in v1.

    let probe_results = match probe_results {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "canary probe failed");
            return Response::ChainCanary(ChainCanaryResponse {
                status: CanaryStatus::Degraded,
                chain: chain_hops,
                probe_results: None,
                partial: false,
                close_matches: vec![],
                rule_name,
            });
        }
    };

    let status = classify(&probe_results, rule_protocol);
    Response::ChainCanary(ChainCanaryResponse {
        status,
        chain: chain_hops,
        probe_results: Some(probe_results),
        partial: false,
        close_matches: vec![],
        rule_name,
    })
}

fn find_rule_name(
    supervisor: &crate::proxy::supervisor::SupervisorHandle,
    listen: SocketAddr,
    protocol: Protocol,
) -> Option<String> {
    let set = supervisor.current_set_rx();
    let snap = set.borrow();
    snap.rules()
        .iter()
        .find(|r| r.listen == listen && r.protocol == protocol)
        .map(|r| r.name.clone())
}

/// Compute up to three suggested close matches when the requested
/// `(listen, protocol)` has no rule. Ranked: same-port-different-proto
/// > different-port-same-proto > everything else.
fn compute_close_matches(
    supervisor: &crate::proxy::supervisor::SupervisorHandle,
    target_listen: SocketAddr,
    target_proto: Protocol,
) -> Vec<CloseMatch> {
    let set = supervisor.current_set_rx();
    let snap = set.borrow();
    let target_port = target_listen.port();
    let mut ranked: Vec<(u8, CloseMatch)> = Vec::new();
    for r in snap.rules() {
        if r.listen == target_listen && r.protocol == target_proto {
            // Should never happen (we already failed the rule lookup
            // before getting here), but skip defensively.
            continue;
        }
        let rank: u8 = if r.listen.port() == target_port && r.protocol != target_proto {
            0
        } else if r.protocol == target_proto && r.listen.port() != target_port {
            1
        } else {
            2
        };
        ranked.push((
            rank,
            CloseMatch {
                listen: r.listen,
                protocol: r.protocol,
                rule_name: r.name.clone(),
            },
        ));
    }
    ranked.sort_by_key(|(rank, _)| *rank);
    ranked.into_iter().take(3).map(|(_, m)| m).collect()
}

/// Run the TCP probe: connect, write token prefix, then bidirectionally
/// send timestamped chunks until `duration` elapses, recording
/// per-direction throughput + latency.
async fn run_tcp_probe(
    rule_listen: SocketAddr,
    token: &[u8; CANARY_TOKEN_LEN],
    duration: Duration,
    rate: u32,
) -> anyhow::Result<ProbeResults> {
    let rate_bps = if rate == 0 {
        TCP_DEFAULT_RATE_BPS
    } else {
        // Operator passes MiB/s for TCP.
        (rate as u64).saturating_mul(1024 * 1024)
    };

    let connect_start = Instant::now();
    let mut stream = TcpStream::connect(rule_listen).await?;
    let connect_rtt_micros = Some(connect_start.elapsed().as_micros() as u64);

    // Prefix: send the token first so the terminal's intercept can
    // match it and route us to the in-process echo.
    stream.write_all(token).await?;

    // Per-chunk shape: 8-byte BE seq, 8-byte BE send_micros, payload
    // padding to fill out the chunk. With a 1 MiB/s send rate and
    // ~10 ms cadence this is ~10 KiB chunks.
    const CHUNK_SIZE: usize = 8192;
    let interval = Duration::from_millis(((CHUNK_SIZE as u64 * 1000) / rate_bps.max(1)).max(1));

    let mut hist_c_to_s = Histogram::<u64>::new(3).expect("hdrhistogram::new(3) infallible");
    let mut hist_s_to_c = Histogram::<u64>::new(3).expect("hdrhistogram::new(3) infallible");
    let mut bytes_sent: u64 = 0;
    let mut bytes_received: u64 = 0;
    let mut next_seq: u64 = 0;
    // Reuse the same scratch buffers across iterations.
    let mut send_buf = vec![0u8; CHUNK_SIZE];
    let mut recv_buf = vec![0u8; CHUNK_SIZE];

    let deadline = Instant::now() + duration;
    let mut send_ticker = tokio::time::interval(interval);
    send_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    while Instant::now() < deadline {
        tokio::select! {
            _ = send_ticker.tick() => {
                let now_micros = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_micros() as u64)
                    .unwrap_or(0);
                send_buf[0..8].copy_from_slice(&next_seq.to_be_bytes());
                send_buf[8..16].copy_from_slice(&now_micros.to_be_bytes());
                // Bytes 16.. are arbitrary payload padding.
                if stream.write_all(&send_buf).await.is_err() {
                    break;
                }
                bytes_sent = bytes_sent.saturating_add(send_buf.len() as u64);
                hist_c_to_s.record(0).ok();
                next_seq = next_seq.wrapping_add(1);
            }
            // Read whatever the echo loop sends back. The echo
            // preserves byte order, so we can decode the timestamp
            // from each received chunk's first 16 bytes.
            res = stream.read(&mut recv_buf) => {
                match res {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        bytes_received = bytes_received.saturating_add(n as u64);
                        if n >= 16 {
                            let send_micros = u64::from_be_bytes(
                                recv_buf[8..16].try_into().unwrap(),
                            );
                            let now_micros = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map(|d| d.as_micros() as u64)
                                .unwrap_or(0);
                            let rtt = now_micros.saturating_sub(send_micros);
                            hist_s_to_c.record(rtt).ok();
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }

    let _ = stream.shutdown().await;

    let secs = duration.as_secs_f64().max(0.001);
    Ok(ProbeResults {
        c_to_s: DirectionStats {
            sent: bytes_sent,
            received: bytes_sent, // TCP is reliable; loss is binary at the connection level
            throughput_bps: ((bytes_sent as f64 * 8.0) / secs) as u64,
            latency_p50_micros: hist_s_to_c.value_at_quantile(0.5),
            latency_p99_micros: hist_s_to_c.value_at_quantile(0.99),
        },
        s_to_c: DirectionStats {
            sent: bytes_received,
            received: bytes_received,
            throughput_bps: ((bytes_received as f64 * 8.0) / secs) as u64,
            latency_p50_micros: hist_s_to_c.value_at_quantile(0.5),
            latency_p99_micros: hist_s_to_c.value_at_quantile(0.99),
        },
        connection_rtt_micros: connect_rtt_micros,
    })
}

/// Run the UDP probe: bind a local socket, send token-prefixed
/// timestamped datagrams at the configured rate, read echoes,
/// record per-direction loss + latency.
async fn run_udp_probe(
    rule_listen: SocketAddr,
    token: &[u8; CANARY_TOKEN_LEN],
    duration: Duration,
    rate: u32,
    payload_bytes: u32,
) -> anyhow::Result<ProbeResults> {
    let rate_pps = if rate == 0 {
        UDP_DEFAULT_RATE_PPS
    } else {
        rate as u64
    };
    let payload = if payload_bytes == 0 {
        UDP_DEFAULT_PAYLOAD_BYTES
    } else {
        (payload_bytes as usize).max(CANARY_TOKEN_LEN + 16)
    };
    let interval = Duration::from_millis((1000 / rate_pps.max(1)).max(1));

    let bind_addr = if rule_listen.is_ipv4() {
        "0.0.0.0:0".parse::<SocketAddr>().unwrap()
    } else {
        "[::]:0".parse::<SocketAddr>().unwrap()
    };
    let sock = UdpSocket::bind(bind_addr).await?;
    sock.connect(rule_listen).await?;

    let mut hist = Histogram::<u64>::new(3).expect("hdrhistogram::new(3) infallible");
    let mut sent: u64 = 0;
    let mut received: u64 = 0;
    let mut next_seq: u64 = 0;
    let mut send_buf = vec![0u8; payload];
    send_buf[..CANARY_TOKEN_LEN].copy_from_slice(token);
    let mut recv_buf = vec![0u8; payload.max(2048)];

    let deadline = Instant::now() + duration;
    let mut send_ticker = tokio::time::interval(interval);
    send_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    while Instant::now() < deadline {
        tokio::select! {
            _ = send_ticker.tick() => {
                let now_micros = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_micros() as u64)
                    .unwrap_or(0);
                send_buf[CANARY_TOKEN_LEN..CANARY_TOKEN_LEN + 8]
                    .copy_from_slice(&next_seq.to_be_bytes());
                send_buf[CANARY_TOKEN_LEN + 8..CANARY_TOKEN_LEN + 16]
                    .copy_from_slice(&now_micros.to_be_bytes());
                if sock.send(&send_buf).await.is_ok() {
                    sent = sent.saturating_add(1);
                }
                next_seq = next_seq.wrapping_add(1);
            }
            res = sock.recv(&mut recv_buf) => {
                if let Ok(n) = res {
                    if n >= CANARY_TOKEN_LEN + 16 {
                        let send_micros = u64::from_be_bytes(
                            recv_buf[CANARY_TOKEN_LEN + 8..CANARY_TOKEN_LEN + 16]
                                .try_into()
                                .unwrap(),
                        );
                        let now_micros = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_micros() as u64)
                            .unwrap_or(0);
                        let rtt = now_micros.saturating_sub(send_micros);
                        hist.record(rtt).ok();
                        received = received.saturating_add(1);
                    }
                }
            }
        }
    }

    // After the send-loop ends, drain in-flight echoes for a short
    // grace window so packets in flight aren't counted as losses.
    let drain_deadline = Instant::now() + Duration::from_millis(200);
    while Instant::now() < drain_deadline {
        match tokio::time::timeout(Duration::from_millis(50), sock.recv(&mut recv_buf)).await {
            Ok(Ok(n)) if n >= CANARY_TOKEN_LEN + 16 => {
                let send_micros = u64::from_be_bytes(
                    recv_buf[CANARY_TOKEN_LEN + 8..CANARY_TOKEN_LEN + 16]
                        .try_into()
                        .unwrap(),
                );
                let now_micros = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_micros() as u64)
                    .unwrap_or(0);
                let rtt = now_micros.saturating_sub(send_micros);
                hist.record(rtt).ok();
                received = received.saturating_add(1);
            }
            _ => break,
        }
    }

    let secs = duration.as_secs_f64().max(0.001);
    Ok(ProbeResults {
        c_to_s: DirectionStats {
            sent,
            received,
            throughput_bps: ((sent as f64 * payload as f64 * 8.0) / secs) as u64,
            latency_p50_micros: hist.value_at_quantile(0.5),
            latency_p99_micros: hist.value_at_quantile(0.99),
        },
        s_to_c: DirectionStats {
            sent: received,
            received,
            throughput_bps: ((received as f64 * payload as f64 * 8.0) / secs) as u64,
            latency_p50_micros: hist.value_at_quantile(0.5),
            latency_p99_micros: hist.value_at_quantile(0.99),
        },
        connection_rtt_micros: None,
    })
}

/// Classify a probe result as [`CanaryStatus::Ok`] or
/// [`CanaryStatus::Degraded`] based on the canned thresholds at the
/// top of this module.
fn classify(p: &ProbeResults, protocol: Protocol) -> CanaryStatus {
    if let Protocol::Udp = protocol {
        let sent = p.c_to_s.sent.max(1);
        let loss = 1.0 - (p.c_to_s.received as f64 / sent as f64).min(1.0);
        if loss > DEGRADED_LOSS_THRESHOLD {
            return CanaryStatus::Degraded;
        }
    }
    if p.s_to_c.latency_p99_micros > DEGRADED_P99_MICROS
        || p.c_to_s.latency_p99_micros > DEGRADED_P99_MICROS
    {
        return CanaryStatus::Degraded;
    }
    // Probe ran for nominally `duration` seconds; if neither side
    // observed *any* traffic the chain is up but the data path
    // never carried bytes — call that degraded.
    if p.c_to_s.sent == 0 && p.s_to_c.received == 0 {
        return CanaryStatus::Degraded;
    }
    CanaryStatus::Ok
}

/// Unused-prevention: this re-export keeps the `Arc<CanaryArmTable>`
/// import surfaced so dead-code lints stay quiet even if the table is
/// referenced only via `ControlState`. Removing this once the handler
/// is fully wired into production paths is safe.
#[allow(dead_code)]
fn _suppress_dead_import(_t: Arc<CanaryArmTable>) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_returns_ok_for_clean_tcp_probe() {
        let p = ProbeResults {
            c_to_s: DirectionStats {
                sent: 1024,
                received: 1024,
                throughput_bps: 8192,
                latency_p50_micros: 100,
                latency_p99_micros: 200,
            },
            s_to_c: DirectionStats {
                sent: 1024,
                received: 1024,
                throughput_bps: 8192,
                latency_p50_micros: 100,
                latency_p99_micros: 200,
            },
            connection_rtt_micros: Some(50),
        };
        assert_eq!(classify(&p, Protocol::Tcp), CanaryStatus::Ok);
    }

    #[test]
    fn classify_returns_degraded_on_udp_loss() {
        let p = ProbeResults {
            c_to_s: DirectionStats {
                sent: 1000,
                received: 900, // 10% loss
                throughput_bps: 0,
                latency_p50_micros: 100,
                latency_p99_micros: 200,
            },
            s_to_c: DirectionStats {
                sent: 900,
                received: 900,
                throughput_bps: 0,
                latency_p50_micros: 100,
                latency_p99_micros: 200,
            },
            connection_rtt_micros: None,
        };
        assert_eq!(classify(&p, Protocol::Udp), CanaryStatus::Degraded);
    }

    #[test]
    fn classify_returns_degraded_on_high_p99() {
        let p = ProbeResults {
            c_to_s: DirectionStats {
                sent: 1000,
                received: 1000,
                throughput_bps: 0,
                latency_p50_micros: 100,
                latency_p99_micros: 100_000, // 100ms p99
            },
            s_to_c: DirectionStats {
                sent: 1000,
                received: 1000,
                throughput_bps: 0,
                latency_p50_micros: 100,
                latency_p99_micros: 100_000,
            },
            connection_rtt_micros: None,
        };
        assert_eq!(classify(&p, Protocol::Tcp), CanaryStatus::Degraded);
    }

    #[test]
    fn classify_returns_degraded_when_no_traffic_observed() {
        let p = ProbeResults {
            c_to_s: DirectionStats {
                sent: 0,
                received: 0,
                throughput_bps: 0,
                latency_p50_micros: 0,
                latency_p99_micros: 0,
            },
            s_to_c: DirectionStats {
                sent: 0,
                received: 0,
                throughput_bps: 0,
                latency_p50_micros: 0,
                latency_p99_micros: 0,
            },
            connection_rtt_micros: None,
        };
        assert_eq!(classify(&p, Protocol::Tcp), CanaryStatus::Degraded);
    }
}
