//! Upstream resolver — the abstraction between L4 listeners and their dial
//! target.
//!
//! Two shapes:
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
//!
//! Built by [`ResolverFactory`], which enforces the per-mode rule-shape
//! invariant: relay-mode rules must carry `upstream_port`; terminal-mode
//! rules must carry `upstream_addr`. Construction failures bubble up to the
//! supervisor's per-rule-failure policy (log + skip).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::sync::watch;

use ratatoskr::rule::Rule;

use crate::config::Mode;
use crate::heartbeat::PeerState;

/// Where a proxy listener should dial. Snapshot-style: `current_target` is
/// called per accept / per UDP datagram, and resolvers internally hold any
/// state they need to answer cheaply (Dynamic reads from `PeerState`'s
/// `watch` cell; Static is constant).
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
}

impl UpstreamResolver {
    /// Current dial target, or `None` if no target is available (relay mode
    /// before the first successful heartbeat). Static resolvers always return
    /// `Some`.
    pub fn current_target(&self) -> Option<SocketAddr> {
        match self {
            Self::Dynamic { peer_state, port } => {
                peer_state.current_ip().map(|ip| SocketAddr::new(ip, *port))
            }
            Self::Static { addr } => Some(*addr),
        }
    }

    /// Handle for observing dial-target changes. Static resolvers return
    /// [`WatchHandle::NeverFires`], letting consumers skip per-flow watcher
    /// tasks entirely.
    pub fn watch_ip_changes(&self) -> WatchHandle {
        match self {
            Self::Dynamic { peer_state, .. } => WatchHandle::Dynamic(peer_state.watch()),
            Self::Static { .. } => WatchHandle::NeverFires,
        }
    }

    /// Human-readable description for tracing fields and `yggdrasilctl rules
    /// list` output. Stable shape; not a parse target.
    pub fn describe(&self) -> String {
        match self {
            Self::Dynamic { port, .. } => format!("dynamic:peer:{port}"),
            Self::Static { addr } => format!("static:{addr}"),
        }
    }

    /// `true` if the resolver may change its dial target over time. Used by
    /// UDP to decide whether the per-rule `ipchange_loop` task is worth
    /// spawning at all.
    pub fn is_dynamic(&self) -> bool {
        matches!(self, Self::Dynamic { .. })
    }
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
    /// match the daemon's mode (relay rule with `upstream_addr`, or terminal
    /// rule with `upstream_port`). The supervisor logs the error and skips
    /// that rule per its existing per-rule-failure policy.
    pub fn build(&self, rule: &Rule) -> Result<UpstreamResolver, ResolverBuildError> {
        match (self.mode, rule.upstream_port, rule.upstream_addr) {
            (Mode::Relay, Some(port), None) => {
                let peer_state = self.peer_state.clone().ok_or(
                    ResolverBuildError::Internal(
                        "relay-mode factory has no peer_state (logic error)",
                    ),
                )?;
                Ok(UpstreamResolver::Dynamic { peer_state, port })
            }
            (Mode::Relay, None, Some(_)) => Err(ResolverBuildError::ModeMismatch {
                rule: rule.name.clone(),
                mode: Mode::Relay,
                detail:
                    "rule has upstream_addr (terminal-style) but daemon is in relay mode; \
                     terminal rules cannot run on a relay",
            }),
            (Mode::Terminal, None, Some(addr)) => Ok(UpstreamResolver::Static { addr }),
            (Mode::Terminal, Some(_), None) => Err(ResolverBuildError::ModeMismatch {
                rule: rule.name.clone(),
                mode: Mode::Terminal,
                detail:
                    "rule has upstream_port (relay-style) but daemon is in terminal mode; \
                     relay rules cannot run on a terminal",
            }),
            // Schema validation in Rule::validate rejects (None, None) and
            // (Some, Some); the patterns below are defensive.
            (_, None, None) => Err(ResolverBuildError::Internal(
                "rule has neither upstream_port nor upstream_addr (validation bug)",
            )),
            (_, Some(_), Some(_)) => Err(ResolverBuildError::Internal(
                "rule has both upstream_port and upstream_addr (validation bug)",
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
    use ratatoskr::rule::{Protocol, Rule};

    fn relay_rule(port: u16) -> Rule {
        Rule {
            name: "relay-rule".into(),
            listen: "127.0.0.1:1111".parse().unwrap(),
            protocol: Protocol::Tcp,
            upstream_port: Some(port),
            upstream_addr: None,
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
}
