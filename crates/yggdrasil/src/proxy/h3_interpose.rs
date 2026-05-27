//! `quinn::AsyncUdpSocket` wrapper that intercepts PROXY-v2 first-datagrams
//! emitted by the chain relay for HTTPS / HTTP-3 traffic.
//!
//! ## What this exists for
//!
//! The chain relay forwards client UDP datagrams to the terminal over a
//! direct UDP path (the chain control link is control-only — it doesn't
//! carry forwarded bytes). On every new (relay → terminal) UDP flow, the
//! relay emits a standalone PROXY-v2 datagram describing
//! `(client_addr → relay_listen_addr)` before forwarding the client's
//! first application datagram (the QUIC Initial). The terminal needs to
//! pluck those PROXY datagrams off the wire before they reach quinn,
//! because quinn would reject them as malformed QUIC.
//!
//! ## Where it sits
//!
//! Between the OS UDP socket and quinn:
//!
//! ```text
//!  relay --UDP--> [ tokio UdpSocket ] --> [ ProxyV2InterposeSocket ] --> quinn::Endpoint
//!                                              |
//!                                              v
//!                                       InterposeMap (5-tuple → real client)
//!                                              ^
//!                                              |
//!                                       h3 request handler reads here
//! ```
//!
//! Quinn's `Endpoint::new_with_abstract_socket` takes an
//! `Arc<dyn AsyncUdpSocket>` — we wrap the real socket in our type and
//! pass that. On `poll_recv`, we walk the batch of datagrams the kernel
//! handed up:
//! * Datagrams whose first 12 bytes match the v2 magic are decoded.
//!   On success, we upsert `(meta.addr → endpoints.client)` into the
//!   shared map and *skip* the datagram (do not surface it to quinn).
//! * Datagrams whose first byte is incompatible with the v2 magic
//!   pass through unchanged. By construction (see
//!   `decode_v2_from_datagram` tests) no valid QUIC packet can match
//!   the v2 magic, so quinn never sees a stripped legit datagram.
//! * Datagrams that *almost* look like v2 (magic present but
//!   malformed payload) also pass through. Quinn will then drop them
//!   as malformed QUIC; we'd rather let quinn's logging handle that
//!   than silently swallow a bug.
//!
//! When an entire kernel batch is PROXY datagrams the wrapper loops
//! and re-polls the inner socket so it never returns `Ready(0)` from a
//! non-empty `poll_recv` (which quinn could misinterpret as EOF).
//!
//! ## TTL
//!
//! Map entries live `MAP_TTL` after the most recent PROXY datagram for
//! that 5-tuple. Quinn's default `max_idle_timeout` is 30 s, so picking
//! the same TTL means map entries die roughly when the corresponding
//! QUIC connection times out. A reaper task in `h3_frontend` periodically
//! evicts expired entries.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

use crate::proxy::proxy_protocol;

/// How long after the most recent PROXY-v2 observation a map entry
/// remains looked-up-able. Matches quinn's default `max_idle_timeout`
/// so map entries die roughly when the corresponding QUIC connection
/// reaches its idle limit.
pub(crate) const MAP_TTL: Duration = Duration::from_secs(30);

/// One mapping: which real client `(ip, port)` the relay told us a
/// given `(relay-source-ip, relay-source-port)` is forwarding for, and
/// when we last heard that.
#[derive(Debug, Clone, Copy)]
struct MapEntry {
    real_client: SocketAddr,
    last_seen: Instant,
}

/// Shared `relay-source-5-tuple → real-client-addr` lookup table.
///
/// Cloned into the interpose socket (writer; called from quinn's recv
/// path) and the h3 accept path (reader; called when stamping
/// forwarded headers). Both sides hold an `Arc<DashMap>` clone.
#[derive(Clone, Default)]
pub(crate) struct InterposeMap {
    inner: Arc<DashMap<SocketAddr, MapEntry>>,
}

impl InterposeMap {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record a fresh PROXY-v2 observation. Called from the interpose
    /// socket's recv path on every successful v2 decode.
    fn upsert(&self, relay_peer: SocketAddr, real_client: SocketAddr) {
        self.inner.insert(
            relay_peer,
            MapEntry {
                real_client,
                last_seen: Instant::now(),
            },
        );
    }

    /// Look up the real client behind a `relay_peer` address. Returns
    /// `None` if we haven't observed a PROXY-v2 datagram for this
    /// 5-tuple within `MAP_TTL` (e.g. direct LAN clients that bypass
    /// the relay entirely).
    pub(crate) fn lookup(&self, relay_peer: SocketAddr) -> Option<SocketAddr> {
        let entry = self.inner.get(&relay_peer)?;
        if entry.last_seen.elapsed() > MAP_TTL {
            return None;
        }
        Some(entry.real_client)
    }

    /// Evict entries with `last_seen` older than `MAP_TTL`. Called by
    /// the periodic reaper task spawned by the h3 frontend.
    pub(crate) fn reap(&self) {
        let now = Instant::now();
        self.inner
            .retain(|_, e| now.duration_since(e.last_seen) <= MAP_TTL);
    }

    /// For tests / metrics.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner.len()
    }
}

impl fmt::Debug for InterposeMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InterposeMap")
            .field("entries", &self.inner.len())
            .finish()
    }
}

/// `AsyncUdpSocket` wrapper that strips PROXY-v2 first-datagrams.
///
/// See module-level docs for the full contract. The send path is a
/// straight pass-through to the inner socket; only the recv path does
/// any work.
pub(crate) struct ProxyV2InterposeSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    map: InterposeMap,
}

impl ProxyV2InterposeSocket {
    pub(crate) fn new(inner: Arc<dyn AsyncUdpSocket>, map: InterposeMap) -> Self {
        Self { inner, map }
    }
}

impl fmt::Debug for ProxyV2InterposeSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyV2InterposeSocket")
            .field("inner", &self.inner)
            .field("map", &self.map)
            .finish()
    }
}

impl AsyncUdpSocket for ProxyV2InterposeSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // Loop in case an entire batch is PROXY datagrams. We must not
        // return `Ready(0)` from a non-empty batch; quinn's accept loop
        // treats that as EOF.
        loop {
            let n = match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(n)) => n,
            };
            if n == 0 {
                return Poll::Ready(Ok(0));
            }

            // Walk in place, compacting non-PROXY datagrams down to the
            // front of `bufs` / `meta`. `write_idx <= read_idx` always.
            let mut write_idx: usize = 0;
            for read_idx in 0..n {
                let m = meta[read_idx];
                let datagram_bytes: &[u8] = &bufs[read_idx][..m.len];
                if let Some(endpoints) = proxy_protocol::decode_v2_from_datagram(datagram_bytes) {
                    // Stripping this datagram: record the mapping but
                    // do not surface to quinn. The relay's `meta.addr`
                    // is the per-flow ephemeral socket the relay's UDP
                    // worker bound for this client; subsequent QUIC
                    // datagrams in the same flow will land with this
                    // same `meta.addr`.
                    self.map.upsert(m.addr, endpoints.client);
                    continue;
                }
                if read_idx != write_idx {
                    // Copy contents and meta down. We split bufs at
                    // `read_idx` to satisfy the borrow checker — `left`
                    // covers `[0, read_idx)`, `right` covers
                    // `[read_idx, n)`, and `write_idx < read_idx` puts
                    // the destination strictly in `left`.
                    let len = m.len;
                    let (left, right) = bufs.split_at_mut(read_idx);
                    let src: &[u8] = &right[0][..len];
                    let dst: &mut [u8] = &mut left[write_idx].deref_mut()[..len];
                    dst.copy_from_slice(src);
                    meta[write_idx] = m;
                }
                write_idx += 1;
            }
            if write_idx > 0 {
                return Poll::Ready(Ok(write_idx));
            }
            // Entire batch was PROXY datagrams — loop and re-poll
            // inner. Inner re-registers our waker on Pending paths so
            // looping doesn't busy-spin: we either drain another batch
            // here or return Pending from inner.
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn sa(a: &str) -> SocketAddr {
        a.parse().unwrap()
    }

    #[test]
    fn map_upsert_and_lookup_round_trip() {
        let m = InterposeMap::new();
        let relay = sa("198.51.100.1:50001");
        let real = sa("203.0.113.7:54321");
        assert_eq!(m.lookup(relay), None);
        m.upsert(relay, real);
        assert_eq!(m.lookup(relay), Some(real));
    }

    #[test]
    fn map_upsert_replaces_previous_real_client() {
        // Connection migration: a relay-side flow reaped + recreated
        // under a new client `(ip, port)` will fire a fresh PROXY
        // datagram from the same relay 5-tuple. The map must replace
        // the previous real-client mapping.
        let m = InterposeMap::new();
        let relay = sa("198.51.100.1:50001");
        let real_a = sa("203.0.113.7:54321");
        let real_b = sa("203.0.113.8:65530");
        m.upsert(relay, real_a);
        m.upsert(relay, real_b);
        assert_eq!(m.lookup(relay), Some(real_b));
    }

    #[test]
    fn map_lookup_misses_on_expired_entry() {
        // We can't easily fast-forward time without injecting a clock,
        // but we can verify the freshness gate by upserting then
        // manually mutating last_seen. The DashMap value is `Copy`, so
        // we just call the public path here.
        let m = InterposeMap::new();
        let relay = sa("198.51.100.1:50001");
        let real = sa("203.0.113.7:54321");
        m.upsert(relay, real);
        // Mutate last_seen to long-past via the inner DashMap.
        {
            let mut entry = m.inner.get_mut(&relay).unwrap();
            entry.last_seen = Instant::now() - (MAP_TTL + Duration::from_secs(5));
        }
        assert_eq!(m.lookup(relay), None);
    }

    #[test]
    fn reap_drops_expired_entries() {
        let m = InterposeMap::new();
        let fresh = sa("198.51.100.2:50002");
        let stale = sa("198.51.100.3:50003");
        m.upsert(fresh, sa("203.0.113.10:5000"));
        m.upsert(stale, sa("203.0.113.11:5001"));
        // Age out only the stale entry.
        {
            let mut entry = m.inner.get_mut(&stale).unwrap();
            entry.last_seen = Instant::now() - (MAP_TTL + Duration::from_secs(5));
        }
        assert_eq!(m.len(), 2);
        m.reap();
        assert_eq!(m.len(), 1);
        assert!(m.lookup(fresh).is_some());
        assert!(m.lookup(stale).is_none());
    }

    #[test]
    fn map_lookup_keys_on_full_socket_addr_not_ip_only() {
        // Two relay flows from the same source IP but different ports
        // are distinct mappings (matches the relay's per-(client_ip,
        // client_port) flow keying).
        let m = InterposeMap::new();
        let port_a = SocketAddr::new(Ipv4Addr::new(198, 51, 100, 1).into(), 50001);
        let port_b = SocketAddr::new(Ipv4Addr::new(198, 51, 100, 1).into(), 50002);
        m.upsert(port_a, sa("203.0.113.7:54321"));
        m.upsert(port_b, sa("203.0.113.8:55555"));
        assert_eq!(m.lookup(port_a), Some(sa("203.0.113.7:54321")));
        assert_eq!(m.lookup(port_b), Some(sa("203.0.113.8:55555")));
    }
}
