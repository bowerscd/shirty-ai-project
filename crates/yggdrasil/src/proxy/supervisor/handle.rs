//! Type-erased per-rule proxy handles.
//!
//! Split out from the original monolithic `supervisor.rs` (Phase B3).
//! All types are `pub(super)` — visible to siblings under `supervisor/`
//! (notably `reconcile.rs`) but not to external callers.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use ratatoskr::rule::Protocol;

use crate::proxy::h3_frontend::H3Frontend;
use crate::proxy::http_frontend::HttpFrontend;
use crate::proxy::tcp::TcpProxy;
use crate::proxy::udp::UdpProxy;

/// Type-erased handle to a running per-rule proxy.
pub(super) enum ProxyHandle {
    Tcp(TcpProxy),
    Udp(UdpProxy),
    Https(Box<HttpsHandle>),
}

/// HTTPS handle bundles the frontend with the hostnames it registered into
/// the per-IP redirect listener, so we can deregister cleanly on stop.
///
/// Post-schema-cleanup: HTTPS is a node-wide concern driven by the
/// top-level `[[route]]` set, not per-rule. `name` is a synthetic
/// identifier (e.g. `"https@0.0.0.0:443"`) used for logging only.
pub(super) struct HttpsHandle {
    pub(super) frontend: HttpFrontend,
    pub(super) h3: Option<H3Frontend>,
    pub(super) redirect_hosts: Vec<String>,
    pub(super) redirect_ip: IpAddr,
    pub(super) listen: SocketAddr,
    pub(super) name: String,
}

impl ProxyHandle {
    pub(super) fn local_addr(&self) -> SocketAddr {
        match self {
            Self::Tcp(p) => p.local_addr(),
            Self::Udp(p) => p.local_addr(),
            Self::Https(h) => h.listen,
        }
    }

    pub(super) fn name(&self) -> &str {
        match self {
            Self::Tcp(p) => &p.rule().name,
            Self::Udp(p) => &p.rule().name,
            Self::Https(h) => &h.name,
        }
    }

    pub(super) fn protocol(&self) -> Protocol {
        match self {
            Self::Tcp(p) => p.rule().protocol,
            Self::Udp(p) => p.rule().protocol,
            Self::Https(_) => Protocol::Https,
        }
    }

    pub(super) async fn stop(self, drain_timeout: Option<Duration>) {
        match self {
            Self::Tcp(p) => p.stop(drain_timeout).await,
            Self::Udp(p) => p.stop().await,
            Self::Https(h) => {
                let HttpsHandle { frontend, h3, .. } = *h;
                if let Some(q) = h3 {
                    q.stop(drain_timeout).await;
                }
                frontend.stop(drain_timeout).await;
            }
        }
    }
}

/// Active record: the running proxy plus the resolver description it was
/// spawned with (snapshotted at spawn time so the control surface doesn't
/// have to re-derive it).
pub(super) struct ActiveProxy {
    pub(super) handle: ProxyHandle,
    pub(super) upstream_description: String,
    /// For HTTPS rules: number of routes that ended up cert-less (no
    /// cert source resolved). Zero for non-HTTPS rules.
    pub(super) cert_less_route_count: usize,
}
