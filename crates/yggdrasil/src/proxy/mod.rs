//! Proxy supervision.
//!
//! Subsystems:
//!
//! * [`supervisor`] — the diff loop that owns the active proxy table,
//!   reconciles desired-vs-actual on every [`crate::rules`] reload, and
//!   reconciles the node-wide HTTPS frontend against the route set.
//! * [`tcp`] — per-rule TCP proxy. Bidirectional half-close-aware byte
//!   forwarding plus optional PROXY-protocol header emission.
//! * [`udp`] — per-rule UDP proxy. On-demand flow table, per-worker
//!   `SO_REUSEPORT` fan-out, IP-change drain. Heartbeat invariance is the
//!   load-bearing property and is documented in [`udp`]'s module doc.
//! * [`http_frontend`] + [`h3_frontend`] — the node-wide L7 frontends for
//!   HTTP/1.1+2 over TLS and HTTP/3 over QUIC; cert resolution and SNI
//!   dispatch live here.
//! * [`certs`] — three-rung cert store + watcher (per-route convention →
//!   node-wide default → cert-less LAN-only fallback).
//! * [`acme`] — RFC 8555 ACME issuance for HTTP-01 + DNS-01.
//! * [`canary`] — in-process probe arm table used by `chain canary`.
//! * [`forward`] — shared header-rewriting helpers used by both L7
//!   frontends so backends see identical `X-Forwarded-*` regardless of
//!   protocol.
//! * [`proxy_protocol`] — PROXY-v1 / PROXY-v2 codec used to propagate
//!   the real client IP across chain hops and to backends.
//! * [`resolver`] — upstream-target resolution (static literal,
//!   peer-state-driven dynamic, DNS).

pub mod acme;
pub mod canary;
pub mod certs;
pub mod forward;
pub mod h3_frontend;
pub(crate) mod h3_interpose;
pub mod http_frontend;
pub mod proxy_protocol;
pub mod resolver;
pub mod supervisor;
pub mod tcp;
pub mod udp;
