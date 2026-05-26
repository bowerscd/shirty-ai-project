//! Proxy supervision: TCP rules in [`tcp`], PROXY-protocol header writer in
//! [`proxy_protocol`]. UDP support lands in Phase 5.
//!
//! Per-rule listeners are owned by [`tcp::TcpProxy`] handles; the cross-rule
//! supervisor that owns the diff loop comes once Phase 5 is in too.

#![allow(dead_code)] // wired into run() in the supervisor pass

pub mod acme;
pub mod canary;
pub mod certs;
pub mod forward;
pub mod h3_frontend;
pub mod http_frontend;
pub mod proxy_protocol;
pub mod resolver;
pub mod supervisor;
pub mod tcp;
pub mod udp;
