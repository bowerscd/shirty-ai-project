//! The session run loop: `run_session_once`, `heartbeat_loop`, and
//! per-envelope body dispatch.
//!
//! Split out from the original monolithic `client.rs` (Phase B6).

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use tokio::net::UdpSocket;

use ratatoskr::auth::Session;
use ratatoskr::control_frame::{AckStatus, ControlAck};
use ratatoskr::wire::{self, PacketType};

use crate::chain::reliability::{ControlChannel, InboundDisposition};

use super::backoff::ACK_DEADLINE_MULTIPLIER;
use super::body_handler::BodyHandler;
use super::handshake::resolve_endpoint;
use super::ChainClient;

pub(super) enum SessionExit {
    Rekey,
    Cancelled,
}

impl ChainClient {
    pub(super) async fn run_session_once(&mut self) -> Result<SessionExit> {
        let target_addr = resolve_endpoint(&self.config.endpoint).await?;
        let bind_addr: SocketAddr = match (self.config.local_bind, target_addr) {
            (Some(ip @ IpAddr::V4(_)), SocketAddr::V4(_))
            | (Some(ip @ IpAddr::V6(_)), SocketAddr::V6(_)) => SocketAddr::new(ip, 0),
            (_, SocketAddr::V4(_)) => "0.0.0.0:0".parse().unwrap(),
            (_, SocketAddr::V6(_)) => "[::]:0".parse().unwrap(),
        };
        let socket = UdpSocket::bind(bind_addr)
            .await
            .with_context(|| format!("bind UDP socket toward {target_addr}"))?;
        socket
            .connect(target_addr)
            .await
            .with_context(|| format!("connect UDP socket to {target_addr}"))?;
        tracing::info!(
            upstream = %target_addr,
            local    = %socket.local_addr().map(|a| a.to_string()).unwrap_or_default(),
            "udp socket ready"
        );

        let session = self.handshake(&socket).await?;
        self.heartbeat_loop(socket, session).await
    }

    pub(super) async fn heartbeat_loop(
        &mut self,
        socket: UdpSocket,
        mut session: Session,
    ) -> Result<SessionExit> {
        let session_started = Instant::now();
        let mut ticker = tokio::time::interval(self.config.heartbeat_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let mut last_ack_at: Option<Instant> = None;
        let mut heartbeats_sent: u64 = 0;
        let mut acks_received: u64 = 0;
        let mut buf = [0u8; ratatoskr::wire::MAX_PACKET_LEN];

        let ack_deadline = self.config.heartbeat_interval * ACK_DEADLINE_MULTIPLIER;

        // Per-session control reliability state. Drop-aborts every pending
        // send with `SendError::ChannelClosed` when this function returns
        // (rekey, cancel, or fatal session error), so callers awaiting on a
        // completion receiver always make progress.
        let mut channel = ControlChannel::new();

        loop {
            if session_started.elapsed() >= self.config.rekey_interval {
                tracing::info!(heartbeats_sent, acks_received, "rekey deadline reached");
                return Ok(SessionExit::Rekey);
            }
            if let Some(last) = last_ack_at {
                if last.elapsed() > ack_deadline {
                    bail!(
                        "no ACK in {:?} (sent={}, acked={}); presuming session dead",
                        last.elapsed(),
                        heartbeats_sent,
                        acks_received
                    );
                }
            } else if heartbeats_sent > 0 && session_started.elapsed() > ack_deadline {
                bail!(
                    "no ACK ever received (sent={}, deadline={:?})",
                    heartbeats_sent,
                    ack_deadline
                );
            }

            // Compute the next control-channel retransmit deadline. If the
            // outbound queue is empty, sleep for a long interval (we'll be
            // woken by any of the other select arms first).
            let retx_at = channel
                .next_tick_at()
                .map(tokio::time::Instant::from_std)
                .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(3600));

            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => return Ok(SessionExit::Cancelled),
                // Drain inbound before anything else: heartbeat acks must
                // arrive promptly, and an unbounded outbound `control_rx`
                // burst would otherwise starve this arm and bail the
                // session on the no-ack deadline.
                res = socket.recv(&mut buf) => {
                    let n = res.context("recv from upstream")?;
                    tracing::trace!(n, "chain client: recv UDP packet");
                    let view = match wire::parse(&buf[..n]) {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::debug!(error = %e, "ignoring unparseable packet");
                            continue;
                        }
                    };
                    match view.packet_type {
                        PacketType::HeartbeatAck => {
                            match session.decode_heartbeat_ack(&view) {
                                Ok(ack) => {
                                    acks_received += 1;
                                    last_ack_at = Some(Instant::now());
                                    tracing::trace!(
                                        echoed_counter = ack.echoed_counter,
                                        server_ts_ms  = ack.server_ts_ms,
                                        "heartbeat ack"
                                    );
                                }
                                Err(e) => {
                                    tracing::debug!(error = %e, "ignoring malformed ack");
                                }
                            }
                        }
                        PacketType::Control => {
                            match session.decode_control(&view) {
                                Ok(env) => {
                                    let seq = env.seq;
                                    let status = match channel.on_inbound(env) {
                                        InboundDisposition::Deliver(env) => {
                                            dispatch_body(
                                                self.config.body_handler.as_ref(),
                                                env.body_type,
                                                &env.body,
                                            )
                                        }
                                        InboundDisposition::Duplicate => AckStatus::Ok,
                                    };
                                    let ack = ControlAck { seq, status };
                                    match session.encode_control_ack(&ack) {
                                        Ok((_, packet)) => {
                                            if let Err(e) = socket.send(&packet).await {
                                                tracing::warn!(seq, error = %e, "send ControlAck failed");
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(seq, error = %e, "encode ControlAck failed");
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::debug!(error = %e, "ignoring malformed Control");
                                }
                            }
                        }
                        PacketType::ControlAck => {
                            match session.decode_control_ack(&view) {
                                Ok(ack) => {
                                    let seq = ack.seq;
                                    let resolved = channel.on_ack(&ack);
                                    if resolved {
                                        tracing::trace!(seq, "control ack resolved waiter");
                                    } else {
                                        tracing::debug!(seq, "control ack for unknown seq");
                                    }
                                }
                                Err(e) => {
                                    tracing::debug!(error = %e, "ignoring malformed ControlAck");
                                }
                            }
                        }
                        PacketType::Handshake2 => {
                            tracing::debug!("ignoring late Handshake2");
                        }
                        other => {
                            tracing::debug!(?other, "ignoring unexpected packet from upstream");
                        }
                    }
                }
                _ = ticker.tick() => {
                    let ts = current_unix_millis();
                    let (counter, packet) = session
                        .encode_heartbeat(ts, 0)
                        .context("encode heartbeat")?;
                    socket.send(&packet).await.context("send heartbeat")?;
                    heartbeats_sent += 1;
                    tracing::trace!(counter, ts, "heartbeat sent");
                }
                Some(op) = self.control_rx.recv() => {
                    let env = channel.enqueue(
                        op.body_type,
                        op.body,
                        op.completion,
                        Instant::now(),
                    );
                    let seq = env.seq;
                    match session.encode_control(&env) {
                        Ok((counter, packet)) => {
                            if let Err(e) = socket.send(&packet).await {
                                tracing::warn!(seq, counter, error = %e, "send control failed");
                            } else {
                                tracing::trace!(seq, counter, "control envelope sent");
                            }
                        }
                        Err(e) => {
                            tracing::warn!(seq, error = %e, "encode control failed");
                        }
                    }
                }
                _ = tokio::time::sleep_until(retx_at) => {
                    let due = channel.next_due(Instant::now());
                    for env in due {
                        let seq = env.seq;
                        match session.encode_control(&env) {
                            Ok((counter, packet)) => {
                                if let Err(e) = socket.send(&packet).await {
                                    tracing::warn!(seq, counter, error = %e, "retransmit control failed");
                                } else {
                                    tracing::trace!(seq, counter, "control envelope retransmitted");
                                }
                            }
                            Err(e) => {
                                tracing::warn!(seq, error = %e, "encode control retransmit failed");
                            }
                        }
                    }
                }
            }
        }
    }
}

fn dispatch_body(handler: Option<&BodyHandler>, body_type: u8, body: &[u8]) -> AckStatus {
    let res = match handler {
        Some(h) => h(body_type, body),
        None => AckStatus::Unknown,
    };
    tracing::trace!(
        body_type,
        body_len = body.len(),
        ?res,
        "chain client: dispatch_body"
    );
    res
}

fn current_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
