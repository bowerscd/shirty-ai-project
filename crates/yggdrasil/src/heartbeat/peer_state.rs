//! Shared peer state: current IP, last heartbeat timestamp, configured pubkey.
//!
//! Cheap to clone via `Arc`. The `watch::Sender` inside is the *only*
//! mechanism through which heartbeat events disturb the data plane — proxy
//! tasks call [`PeerState::watch`] to get a receiver and react only to
//! genuine IP changes.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use tokio::sync::watch;

use ratatoskr::auth::{public_key_fingerprint, PUBLIC_KEY_LEN};

/// Sentinel value meaning "no peer enrolled yet". X25519 rejects the all-zeros
/// point as a public key (low-order), so this is unambiguously distinct from
/// any real peer key.
pub const UNENROLLED_PEER_KEY: [u8; PUBLIC_KEY_LEN] = [0u8; PUBLIC_KEY_LEN];

/// What happened when the heartbeat server accepted an authenticated
/// heartbeat. Used by [`HeartbeatServer`](super::HeartbeatServer) to decide
/// what to log and what metrics to bump; downstream proxies see only the
/// resulting watch-channel update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatEffect {
    /// Peer IP is unchanged. **Data plane is not touched.**
    SameIp(IpAddr),
    /// First successful heartbeat ever (or first since startup). The watch
    /// receivers are woken so proxies can establish upstream sockets.
    FirstHeartbeat(IpAddr),
    /// Peer's residential IP has changed since the last heartbeat. The
    /// watch receivers are woken so proxies drain their flow tables.
    IpChanged { old: IpAddr, new: IpAddr },
}

impl HeartbeatEffect {
    pub fn is_data_plane_change(&self) -> bool {
        !matches!(self, HeartbeatEffect::SameIp(_))
    }
}

/// Single, process-wide peer state. Constructed at startup with the
/// configured peer pubkey; shared by `Arc` clone across the heartbeat server,
/// proxy supervisors, control socket, and metrics exporter.
///
/// The peer's static public key is held behind a `RwLock` so it can be
/// live-replaced by the TOFU approval flow without restarting the daemon.
/// Reads are taken on every `Handshake1`; writes happen only via
/// `yggdrasilctl peer approve`.
pub struct PeerState {
    peer_static_key: RwLock<[u8; PUBLIC_KEY_LEN]>,
    current_ip_tx: watch::Sender<Option<IpAddr>>,
    /// Last accepted-heartbeat timestamp in milliseconds since `UNIX_EPOCH`.
    /// `0` means "no heartbeat ever received in this process lifetime".
    last_heartbeat_ms: AtomicU64,
}

impl PeerState {
    /// Construct from the enrolled peer's static public key. Pass
    /// [`UNENROLLED_PEER_KEY`] when no peer has been enrolled yet — in that
    /// case the heartbeat server stages incoming handshakes to the pending
    /// store instead of rejecting them.
    pub fn new(peer_static_key: [u8; PUBLIC_KEY_LEN]) -> Arc<Self> {
        let (tx, _rx) = watch::channel::<Option<IpAddr>>(None);
        Arc::new(Self {
            peer_static_key: RwLock::new(peer_static_key),
            current_ip_tx: tx,
            last_heartbeat_ms: AtomicU64::new(0),
        })
    }

    /// Whether a real peer is currently enrolled (key is not the all-zeros
    /// sentinel).
    pub fn is_peer_enrolled(&self) -> bool {
        *self.peer_static_key.read().unwrap() != UNENROLLED_PEER_KEY
    }

    /// Replace the configured peer public key. Called by the TOFU approve
    /// flow after writing the new key to disk. Subsequent `Handshake1`s
    /// from the just-approved peer will be accepted immediately.
    pub fn set_peer_static_key(&self, new_key: [u8; PUBLIC_KEY_LEN]) {
        *self.peer_static_key.write().unwrap() = new_key;
    }

    /// Subscribe to peer-IP changes. The initial `borrow()` yields whatever
    /// the current value is (typically `None` until the first heartbeat).
    pub fn watch(&self) -> watch::Receiver<Option<IpAddr>> {
        self.current_ip_tx.subscribe()
    }

    /// Snapshot the current peer IP without subscribing.
    pub fn current_ip(&self) -> Option<IpAddr> {
        *self.current_ip_tx.borrow()
    }

    /// Last heartbeat timestamp (ms since UNIX_EPOCH). `None` until the first
    /// authenticated heartbeat is recorded.
    pub fn last_heartbeat_ms(&self) -> Option<u64> {
        match self.last_heartbeat_ms.load(Ordering::Relaxed) {
            0 => None,
            v => Some(v),
        }
    }

    /// Snapshot the currently-configured peer public key. Returns the
    /// all-zeros [`UNENROLLED_PEER_KEY`] sentinel if no peer is enrolled.
    pub fn peer_static_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        *self.peer_static_key.read().unwrap()
    }

    pub fn fingerprint(&self) -> String {
        public_key_fingerprint(&self.peer_static_key.read().unwrap())
    }

    /// Record an authenticated heartbeat from `peer_addr`. Returns the
    /// resulting [`HeartbeatEffect`] for logging/metrics.
    ///
    /// This is the **only** function that may move `current_ip`. It is
    /// `&self` and lock-free for the same-IP fast path: the
    /// [`watch::Sender::send_if_modified`] closure only briefly takes the
    /// channel's internal lock, and for `SameIp` it returns `false` so no
    /// receiver is woken.
    pub fn record_heartbeat(&self, peer_addr: SocketAddr) -> HeartbeatEffect {
        let now_ms = current_unix_millis();
        self.last_heartbeat_ms.store(now_ms, Ordering::Relaxed);

        let new_ip = peer_addr.ip();
        // Default placeholder; the closure below always overwrites it.
        let mut effect = HeartbeatEffect::SameIp(new_ip);
        self.current_ip_tx.send_if_modified(|cur| match *cur {
            Some(old) if old == new_ip => {
                effect = HeartbeatEffect::SameIp(new_ip);
                false
            }
            Some(old) => {
                effect = HeartbeatEffect::IpChanged { old, new: new_ip };
                *cur = Some(new_ip);
                true
            }
            None => {
                effect = HeartbeatEffect::FirstHeartbeat(new_ip);
                *cur = Some(new_ip);
                true
            }
        });
        effect
    }
}

impl std::fmt::Debug for PeerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerState")
            .field("peer_fingerprint", &self.fingerprint())
            .field("current_ip", &self.current_ip())
            .field("last_heartbeat_ms", &self.last_heartbeat_ms())
            .finish()
    }
}

fn current_unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn starts_empty() {
        let p = PeerState::new([7u8; 32]);
        assert_eq!(p.current_ip(), None);
        assert_eq!(p.last_heartbeat_ms(), None);
        assert_eq!(p.peer_static_key(), [7u8; 32]);
        assert!(p.is_peer_enrolled());
    }

    #[test]
    fn unenrolled_sentinel_is_recognised() {
        let p = PeerState::new(UNENROLLED_PEER_KEY);
        assert!(!p.is_peer_enrolled());
        p.set_peer_static_key([9u8; 32]);
        assert!(p.is_peer_enrolled());
        assert_eq!(p.peer_static_key(), [9u8; 32]);
    }

    #[test]
    fn first_heartbeat_is_classified_as_first() {
        let p = PeerState::new([0u8; 32]);
        let eff = p.record_heartbeat(addr("203.0.113.7:1234"));
        assert!(
            matches!(eff, HeartbeatEffect::FirstHeartbeat(ip) if ip.to_string() == "203.0.113.7")
        );
        assert_eq!(p.current_ip().unwrap().to_string(), "203.0.113.7");
        assert!(p.last_heartbeat_ms().is_some());
        assert!(eff.is_data_plane_change());
    }

    #[test]
    fn repeat_same_ip_does_not_fire_watch() {
        let p = PeerState::new([0u8; 32]);
        let mut rx = p.watch();
        // Initial subscribe: current value is None.
        assert_eq!(*rx.borrow_and_update(), None);

        // First heartbeat → watch fires.
        let _ = p.record_heartbeat(addr("198.51.100.1:1111"));
        assert!(rx.has_changed().unwrap());
        let val = *rx.borrow_and_update();
        assert_eq!(val.unwrap().to_string(), "198.51.100.1");

        // 1000 more heartbeats from the same IP, different ports.
        for port in 2000..3000u16 {
            let eff = p.record_heartbeat(addr(&format!("198.51.100.1:{port}")));
            assert!(matches!(eff, HeartbeatEffect::SameIp(_)));
            assert!(!eff.is_data_plane_change());
        }
        // Watch must NOT have fired since the IP didn't change. This is the
        // critical "heartbeat invariance" property the data plane relies on.
        assert!(!rx.has_changed().unwrap());
    }

    #[test]
    fn changed_ip_fires_watch_with_old_and_new() {
        let p = PeerState::new([0u8; 32]);
        let mut rx = p.watch();
        let _ = rx.borrow_and_update();

        let _ = p.record_heartbeat(addr("198.51.100.1:1111"));
        let _ = rx.borrow_and_update();

        let eff = p.record_heartbeat(addr("198.51.100.2:1111"));
        match eff {
            HeartbeatEffect::IpChanged { old, new } => {
                assert_eq!(old.to_string(), "198.51.100.1");
                assert_eq!(new.to_string(), "198.51.100.2");
            }
            other => panic!("expected IpChanged, got {other:?}"),
        }
        assert!(rx.has_changed().unwrap());
        assert_eq!(rx.borrow_and_update().unwrap().to_string(), "198.51.100.2");
    }

    #[test]
    fn last_heartbeat_ms_monotonic() {
        let p = PeerState::new([0u8; 32]);
        let _ = p.record_heartbeat(addr("198.51.100.1:1111"));
        let first = p.last_heartbeat_ms().unwrap();
        // No sleep — but a second call should produce ms >= first (system clock).
        let _ = p.record_heartbeat(addr("198.51.100.1:1112"));
        let second = p.last_heartbeat_ms().unwrap();
        assert!(second >= first, "timestamps should be non-decreasing");
    }

    #[test]
    fn fingerprint_is_stable() {
        let key = [0xABu8; 32];
        let p = PeerState::new(key);
        let f1 = p.fingerprint();
        let f2 = p.fingerprint();
        assert_eq!(f1, f2);
        assert_eq!(f1.len(), 32);
    }
}
