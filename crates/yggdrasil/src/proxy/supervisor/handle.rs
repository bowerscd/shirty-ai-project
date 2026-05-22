//! Type-erased per-rule proxy handles.
//!
//! Split out from the original monolithic `supervisor.rs` (Phase B3).
//! All types are `pub(super)` — visible to siblings under `supervisor/`
//! (notably `reconcile.rs`) but not to external callers.

use std::net::{IpAddr, SocketAddr};

use ratatoskr::rule::Rule;

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
pub(super) struct HttpsHandle {
    pub(super) frontend: HttpFrontend,
    pub(super) h3: Option<H3Frontend>,
    pub(super) redirect_hosts: Vec<String>,
    pub(super) redirect_ip: IpAddr,
    pub(super) listen: SocketAddr,
    pub(super) rule: Rule,
}

impl ProxyHandle {
    pub(super) fn local_addr(&self) -> SocketAddr {
        match self {
            Self::Tcp(p) => p.local_addr(),
            Self::Udp(p) => p.local_addr(),
            Self::Https(h) => h.listen,
        }
    }

    pub(super) fn rule(&self) -> &Rule {
        match self {
            Self::Tcp(p) => p.rule(),
            Self::Udp(p) => p.rule(),
            Self::Https(h) => &h.rule,
        }
    }

    pub(super) async fn stop(self) {
        match self {
            Self::Tcp(p) => p.stop().await,
            Self::Udp(p) => p.stop().await,
            Self::Https(h) => {
                let HttpsHandle { frontend, h3, .. } = *h;
                if let Some(q) = h3 {
                    q.stop().await;
                }
                frontend.stop().await;
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
}
