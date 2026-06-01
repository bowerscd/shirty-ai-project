//! Noise_IK handshake driver and endpoint resolution.
//!

use std::net::SocketAddr;

use anyhow::{anyhow, bail, Context, Result};
use tokio::net::UdpSocket;

use ratatoskr::auth::{Initiator, Session};
use ratatoskr::wire::{self, PacketType, SessionId};

use super::backoff::HANDSHAKE_TIMEOUT;
use super::ChainClient;

pub(super) async fn resolve_endpoint(endpoint: &str) -> Result<SocketAddr> {
    let mut addrs = tokio::net::lookup_host(endpoint)
        .await
        .with_context(|| format!("resolve {endpoint}"))?;
    addrs
        .next()
        .ok_or_else(|| anyhow!("no addresses returned for {endpoint}"))
}

impl ChainClient {
    pub(super) async fn handshake(&self, socket: &UdpSocket) -> Result<Session> {
        let session_id = SessionId::random();
        let (initiator, hs1) = Initiator::start(
            &self.config.local_keys,
            &self.config.upstream_pubkey,
            session_id,
        )
        .context("build handshake1")?;
        tracing::debug!(
            session_id = %session_id,
            bytes = hs1.len(),
            "sending handshake1"
        );
        socket.send(&hs1).await.context("send handshake1")?;

        let mut buf = [0u8; ratatoskr::wire::MAX_PACKET_LEN];
        let n = match tokio::time::timeout(HANDSHAKE_TIMEOUT, socket.recv(&mut buf)).await {
            Ok(r) => r.context("recv handshake2")?,
            Err(_) => bail!("handshake2 timeout after {:?}", HANDSHAKE_TIMEOUT),
        };
        let view = wire::parse(&buf[..n]).context("parse handshake2")?;
        if view.packet_type != PacketType::Handshake2 {
            bail!(
                "expected Handshake2, got {:?} (session_id={})",
                view.packet_type,
                view.session_id
            );
        }
        let session = initiator.complete(&view).context("complete handshake")?;
        tracing::info!(session_id = %session_id, "handshake complete");
        Ok(session)
    }
}
