//! Upstream resolver — the abstraction between L4 listeners and their dial
//! target.
//!
//! Three shapes:
//! * [`UpstreamResolver::Dynamic`] — relay mode. The target IP is supplied by
//!   the heartbeat-discovered peer at runtime; this resolver pairs it with
//!   a fixed port from the rule.
//! * [`UpstreamResolver::Static`] — terminal mode. A fixed LAN socket address
//!   dialed verbatim. The resolver's [`watch_ip_changes`](UpstreamResolver::watch_ip_changes)
//!   handle returns [`WatchHandle::NeverFires`] so the per-rule UDP
//!   `ipchange_loop` can be skipped entirely (kept as an abstraction for
//!   forward-compat with a future authenticated-tunnel mode that might
//!   re-introduce dynamic semantics on the terminal side — see plan
//!   decisions §L).
//! * [`UpstreamResolver::Dns`] — terminal mode. A `host:port` resolved at
//!   startup via [`tokio::net::lookup_host`] and re-resolved every 30s by a
//!   tokio task whose lifetime is bound to the resolver (the task exits
//!   when all `watch::Receiver` clones are dropped). `watch_ip_changes`
//!   also returns `NeverFires` here — a DNS rebind takes effect for *new*
//!   flows only; in-flight flows continue to the previously-resolved
//!   address until they close. This matches nginx / haproxy semantics and
//!   keeps the UDP flow table out of the resolver's blast radius.
//!
//! Built by [`ResolverFactory`], which enforces the per-mode rule-shape
//! invariant: relay-mode rules must carry `upstream_port`; terminal-mode
//! rules must carry `upstream_addr` or `upstream_host`. Construction
//! failures bubble up to the supervisor's per-rule-failure policy
//! (log + skip).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::MissedTickBehavior;

use ratatoskr::rule::{Rule, UpstreamHost};

use crate::config::Mode;
use crate::heartbeat::PeerState;

/// How often the DNS-backed resolver re-queries the OS resolver. 30s is
/// short enough to follow DHCP-driven LAN reshuffles within an SLA
/// operators tolerate, and long enough that an unreachable resolver
/// doesn't burn CPU.
const DNS_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Where a proxy listener should dial. Snapshot-style: `current_target` is
/// called per accept / per UDP datagram, and resolvers internally hold any
/// state they need to answer cheaply (Dynamic reads from `PeerState`'s
/// `watch` cell; Static is constant; Dns reads from a `watch` cell that a
/// background task updates).
#[derive(Debug, Clone)]
pub enum UpstreamResolver {
    /// Relay mode. The peer IP comes from a heartbeat watch channel; the
    /// rule contributes the port.
    Dynamic {
        peer_state: Arc<PeerState>,
        port: u16,
    },
    /// Terminal mode. The whole socket address is fixed at rule-load time.
    Static { addr: SocketAddr },
    /// Terminal mode. A `host:port` re-resolved periodically by a tokio
    /// background task. `current` is a `watch::Receiver<Option<SocketAddr>>`
    /// updated by the task each successful resolution; failed resolutions
    /// keep the previous value (or `None` if no resolution has ever
    /// succeeded).
    Dns {
        host: String,
        port: u16,
        current: watch::Receiver<Option<SocketAddr>>,
    },
}

impl UpstreamResolver {
    /// Current dial target, or `None` if no target is available (relay mode
    /// before the first successful heartbeat; DNS mode before the first
    /// successful resolution). Static resolvers always return `Some`.
    pub fn current_target(&self) -> Option<SocketAddr> {
        match self {
            Self::Dynamic { peer_state, port } => {
                peer_state.current_ip().map(|ip| SocketAddr::new(ip, *port))
            }
            Self::Static { addr } => Some(*addr),
            Self::Dns { current, .. } => *current.borrow(),
        }
    }

    /// Handle for observing dial-target changes. Static and Dns resolvers
    /// return [`WatchHandle::NeverFires`], letting consumers skip per-flow
    /// watcher tasks entirely. Dns is intentionally treated as static from
    /// the UDP-ipchange-loop's perspective: a DNS rebind takes effect for
    /// new flows only.
    pub fn watch_ip_changes(&self) -> WatchHandle {
        match self {
            Self::Dynamic { peer_state, .. } => WatchHandle::Dynamic(peer_state.watch()),
            Self::Static { .. } | Self::Dns { .. } => WatchHandle::NeverFires,
        }
    }

    /// Human-readable description for tracing fields and `yggdrasilctl rules
    /// list` output. Stable shape; not a parse target.
    pub fn describe(&self) -> String {
        match self {
            Self::Dynamic { port, .. } => format!("dynamic:peer:{port}"),
            Self::Static { addr } => format!("static:{addr}"),
            Self::Dns { host, port, .. } => format!("dns:{host}:{port}"),
        }
    }

    /// `true` if the resolver may change its dial target over time *in a
    /// way that should drain in-flight UDP flows*. Only `Dynamic` qualifies.
    /// DNS resolvers do change targets but operate at "new flows only"
    /// semantics; the per-rule `ipchange_loop` should not be spawned for
    /// them.
    pub fn is_dynamic(&self) -> bool {
        matches!(self, Self::Dynamic { .. })
    }
}

/// Spawn the periodic re-resolution task for an [`UpstreamResolver::Dns`].
///
/// Performs the first resolution immediately (so `current_target()`
/// converges within ~tens of ms of construction), then re-resolves every
/// [`DNS_REFRESH_INTERVAL`]. The task exits cleanly when all
/// `watch::Receiver` clones of `tx` are dropped — i.e. when the resolver
/// (and any clones held by listener tasks) goes away.
///
/// On lookup failure or an empty result set, the previous value in the
/// watch is retained — transient resolver outages don't blip the rule
/// offline.
fn spawn_dns_refresh(
    host: String,
    port: u16,
    tx: watch::Sender<Option<SocketAddr>>,
) {
    tokio::spawn(async move {
        let target = format!("{host}:{port}");
        let mut ticker = tokio::time::interval(DNS_REFRESH_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // First tick fires immediately; we throw it away so the loop's
        // shape is "resolve, then tick".
        ticker.tick().await;
        loop {
            match tokio::net::lookup_host(&target).await {
                Ok(mut iter) => match iter.next() {
                    Some(addr) => {
                        if tx.send(Some(addr)).is_err() {
                            // Receiver dropped; resolver is gone.
                            return;
                        }
                    }
                    None => {
                        tracing::warn!(
                            %host, %port,
                            "DNS resolution returned no addresses; retaining previous target"
                        );
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        %host, %port,
                        error = %e,
                        "DNS resolution failed; retaining previous target"
                    );
                }
            }
            // If the receiver was dropped while we were resolving, exit.
            if tx.is_closed() {
                return;
            }
            ticker.tick().await;
        }
    });
}

/// Receiver-side abstraction for IP-change watches. The `Dynamic` variant
/// wraps a tokio `watch::Receiver<Option<IpAddr>>`; the `NeverFires` variant
/// is the static resolver's no-op — its `changed()` future is pending
/// forever, so consumers tasked with "wake on IP change" simply park.
#[derive(Debug)]
pub enum WatchHandle {
    Dynamic(watch::Receiver<Option<IpAddr>>),
    NeverFires,
}

impl WatchHandle {
    /// Resolve when the dial target changes. For [`WatchHandle::Dynamic`]
    /// this delegates to tokio's `watch::Receiver::changed`. For
    /// [`WatchHandle::NeverFires`] this future is pending forever — callers
    /// `tokio::select!` it alongside a cancellation token to unblock on
    /// shutdown.
    pub async fn changed(&mut self) -> Result<(), watch::error::RecvError> {
        match self {
            Self::Dynamic(rx) => rx.changed().await,
            Self::NeverFires => std::future::pending().await,
        }
    }
}

/// Builds [`UpstreamResolver`]s for the supervisor. Carries the daemon's
/// mode and (in relay mode) the shared peer state; in terminal mode the
/// `peer_state` is `None`.
#[derive(Debug, Clone)]
pub struct ResolverFactory {
    pub mode: Mode,
    pub peer_state: Option<Arc<PeerState>>,
}

impl ResolverFactory {
    pub fn new_relay(peer_state: Arc<PeerState>) -> Self {
        Self {
            mode: Mode::Relay,
            peer_state: Some(peer_state),
        }
    }

    pub fn new_terminal() -> Self {
        Self {
            mode: Mode::Terminal,
            peer_state: None,
        }
    }

    /// Build a resolver for one rule. Errors when the rule's shape doesn't
    /// match the daemon's mode (relay rule with `upstream_addr` /
    /// `upstream_host`, or terminal rule with `upstream_port`). The
    /// supervisor logs the error and skips that rule per its existing
    /// per-rule-failure policy.
    pub fn build(&self, rule: &Rule) -> Result<UpstreamResolver, ResolverBuildError> {
        // Compress (upstream_port, upstream_addr, upstream_host) into a
        // single enum to keep the match readable. Validation guarantees
        // exactly one is set.
        enum Target<'a> {
            Port(u16),
            Addr(SocketAddr),
            Host(&'a UpstreamHost),
            None,
        }
        let target = match (rule.upstream_port, rule.upstream_addr, rule.upstream_host.as_ref()) {
            (Some(p), None, None) => Target::Port(p),
            (None, Some(a), None) => Target::Addr(a),
            (None, None, Some(h)) => Target::Host(h),
            (None, None, None) => Target::None,
            _ => {
                return Err(ResolverBuildError::Internal(
                    "rule has multiple of upstream_port / upstream_addr / upstream_host \
                     set (validation bug)",
                ))
            }
        };

        match (self.mode, target) {
            (Mode::Relay, Target::Port(port)) => {
                let peer_state = self.peer_state.clone().ok_or(
                    ResolverBuildError::Internal(
                        "relay-mode factory has no peer_state (logic error)",
                    ),
                )?;
                Ok(UpstreamResolver::Dynamic { peer_state, port })
            }
            (Mode::Relay, Target::Addr(_)) => Err(ResolverBuildError::ModeMismatch {
                rule: rule.name.clone(),
                mode: Mode::Relay,
                detail:
                    "rule has upstream_addr (terminal-style) but daemon is in relay mode; \
                     terminal rules cannot run on a relay",
            }),
            (Mode::Relay, Target::Host(_)) => Err(ResolverBuildError::ModeMismatch {
                rule: rule.name.clone(),
                mode: Mode::Relay,
                detail:
                    "rule has upstream_host (terminal-style) but daemon is in relay mode; \
                     terminal rules cannot run on a relay",
            }),
            (Mode::Terminal, Target::Addr(addr)) => Ok(UpstreamResolver::Static { addr }),
            (Mode::Terminal, Target::Host(uh)) => {
                let (tx, rx) = watch::channel(None);
                spawn_dns_refresh(uh.host.clone(), uh.port, tx);
                Ok(UpstreamResolver::Dns {
                    host: uh.host.clone(),
                    port: uh.port,
                    current: rx,
                })
            }
            (Mode::Terminal, Target::Port(_)) => Err(ResolverBuildError::ModeMismatch {
                rule: rule.name.clone(),
                mode: Mode::Terminal,
                detail:
                    "rule has upstream_port (relay-style) but daemon is in terminal mode; \
                     relay rules cannot run on a terminal",
            }),
            (_, Target::None) => Err(ResolverBuildError::Internal(
                "rule has no upstream_port / upstream_addr / upstream_host (validation bug)",
            )),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ResolverBuildError {
    #[error("rule {rule:?}: {detail} (daemon mode = {})", mode.as_str())]
    ModeMismatch {
        rule: String,
        mode: Mode,
        detail: &'static str,
    },
    #[error("internal resolver error: {0}")]
    Internal(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatoskr::rule::{Protocol, Rule, UpstreamHost};

    fn relay_rule(port: u16) -> Rule {
        Rule {
            name: "relay-rule".into(),
            listen: "127.0.0.1:1111".parse().unwrap(),
            protocol: Protocol::Tcp,
            upstream_port: Some(port),
            upstream_addr: None,
            upstream_host: None,
            idle_timeout: None,
            proxy_protocol: None,
            routes: None,
            cert_dir: None,
        }
    }

    fn terminal_rule(addr: &str) -> Rule {
        Rule {
            name: "terminal-rule".into(),
            listen: "127.0.0.1:2222".parse().unwrap(),
            protocol: Protocol::Tcp,
            upstream_port: None,
            upstream_addr: Some(addr.parse().unwrap()),
            upstream_host: None,
            idle_timeout: None,
            proxy_protocol: None,
            routes: None,
            cert_dir: None,
        }
    }

    #[test]
    fn dynamic_resolver_returns_target_when_peer_known() {
        let peer = PeerState::new([1u8; 32]);
        let _ = peer.record_heartbeat("203.0.113.1:9999".parse().unwrap());
        let r = UpstreamResolver::Dynamic {
            peer_state: peer,
            port: 8080,
        };
        assert_eq!(
            r.current_target(),
            Some("203.0.113.1:8080".parse().unwrap())
        );
        assert!(r.is_dynamic());
        assert!(r.describe().contains("dynamic"));
    }

    #[test]
    fn dynamic_resolver_returns_none_when_peer_unknown() {
        let peer = PeerState::new([1u8; 32]);
        let r = UpstreamResolver::Dynamic {
            peer_state: peer,
            port: 8080,
        };
        assert_eq!(r.current_target(), None);
    }

    #[test]
    fn static_resolver_returns_target_always() {
        let r = UpstreamResolver::Static {
            addr: "192.168.1.10:22".parse().unwrap(),
        };
        assert_eq!(r.current_target(), Some("192.168.1.10:22".parse().unwrap()));
        assert!(!r.is_dynamic());
        assert!(r.describe().contains("static"));
    }

    #[test]
    fn factory_relay_mode_builds_dynamic_for_relay_rule() {
        let peer = PeerState::new([1u8; 32]);
        let f = ResolverFactory::new_relay(peer);
        let r = f.build(&relay_rule(22)).unwrap();
        assert!(matches!(r, UpstreamResolver::Dynamic { port: 22, .. }));
    }

    #[test]
    fn factory_relay_mode_rejects_terminal_rule() {
        let peer = PeerState::new([1u8; 32]);
        let f = ResolverFactory::new_relay(peer);
        let err = f.build(&terminal_rule("192.168.1.10:22")).err().unwrap();
        assert!(matches!(
            err,
            ResolverBuildError::ModeMismatch {
                mode: Mode::Relay,
                ..
            }
        ));
    }

    #[test]
    fn factory_terminal_mode_builds_static_for_terminal_rule() {
        let f = ResolverFactory::new_terminal();
        let r = f.build(&terminal_rule("192.168.1.10:22")).unwrap();
        assert!(matches!(r, UpstreamResolver::Static { .. }));
    }

    #[test]
    fn factory_terminal_mode_rejects_relay_rule() {
        let f = ResolverFactory::new_terminal();
        let err = f.build(&relay_rule(22)).err().unwrap();
        assert!(matches!(
            err,
            ResolverBuildError::ModeMismatch {
                mode: Mode::Terminal,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn never_fires_watch_handle_blocks_forever() {
        let mut h = WatchHandle::NeverFires;
        let res = tokio::time::timeout(std::time::Duration::from_millis(50), h.changed()).await;
        assert!(res.is_err(), "NeverFires.changed() must not resolve");
    }

    #[tokio::test]
    async fn dynamic_watch_handle_fires_on_ip_update() {
        let peer = PeerState::new([1u8; 32]);
        let r = UpstreamResolver::Dynamic {
            peer_state: peer.clone(),
            port: 1234,
        };
        let mut h = r.watch_ip_changes();
        // Drive a change from the producer side.
        let peer_clone = peer.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let _ = peer_clone.record_heartbeat("203.0.113.7:9999".parse().unwrap());
        });
        let res = tokio::time::timeout(std::time::Duration::from_secs(1), h.changed()).await;
        assert!(res.is_ok(), "Dynamic.changed() should fire on peer IP set");
    }

    fn dns_rule(host: &str, port: u16) -> Rule {
        Rule {
            name: "dns-rule".into(),
            listen: "127.0.0.1:3333".parse().unwrap(),
            protocol: Protocol::Tcp,
            upstream_port: None,
            upstream_addr: None,
            upstream_host: Some(UpstreamHost {
                host: host.to_string(),
                port,
            }),
            idle_timeout: None,
            proxy_protocol: None,
            routes: None,
            cert_dir: None,
        }
    }

    /// `Dns` resolvers initially have `current_target() == None` because
    /// the refresh task may not have run its first iteration yet. After a
    /// short wait, `localhost` should resolve.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dns_resolver_converges_to_resolved_addr() {
        let f = ResolverFactory::new_terminal();
        let r = f.build(&dns_rule("localhost", 9)).unwrap();
        assert!(matches!(r, UpstreamResolver::Dns { .. }));
        assert!(r.describe().contains("dns:localhost:9"));
        assert!(!r.is_dynamic(), "Dns resolver should not drive ipchange_loop");

        // Wait for the refresh task to land an address.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if let Some(addr) = r.current_target() {
                assert_eq!(addr.port(), 9);
                // localhost resolves to 127.0.0.1 or ::1 depending on OS;
                // both are loopback. Just sanity-check that.
                assert!(addr.ip().is_loopback(), "expected loopback, got {addr}");
                break;
            }
            if std::time::Instant::now() >= deadline {
                panic!("Dns resolver never produced a target for localhost:9");
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    /// `Dns` resolvers report `WatchHandle::NeverFires` so the UDP
    /// ipchange_loop is not spawned for them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dns_resolver_watch_handle_is_never_fires() {
        let f = ResolverFactory::new_terminal();
        let r = f.build(&dns_rule("localhost", 9)).unwrap();
        let mut h = r.watch_ip_changes();
        let res = tokio::time::timeout(std::time::Duration::from_millis(50), h.changed()).await;
        assert!(res.is_err(), "Dns.watch_ip_changes() must not fire");
    }

    /// Relay-mode factory must refuse to build a Dns resolver — DNS-based
    /// upstreams are a terminal-mode-only feature.
    #[test]
    fn factory_relay_mode_rejects_dns_rule() {
        let peer = PeerState::new([1u8; 32]);
        let f = ResolverFactory::new_relay(peer);
        let err = f.build(&dns_rule("example.com", 80)).err().unwrap();
        assert!(
            matches!(
                err,
                ResolverBuildError::ModeMismatch {
                    mode: Mode::Relay,
                    ..
                }
            ),
            "expected ModeMismatch, got: {err:?}"
        );
    }
}
