//! Heartbeat control plane.
//!
//! The heartbeat subsystem is split into two pieces:
//!
//! * [`PeerState`] — the single source of truth for "where is the peer right
//!   now?". Owns a [`tokio::sync::watch`] sender that fires only on actual IP
//!   changes; proxy tasks subscribe to it to know when to drain flows. Cheap
//!   to clone (it's `Arc`).
//! * [`HeartbeatServer`] — owns the heartbeat UDP socket and the single
//!   Noise session. Drives handshakes and processes inbound heartbeats. On
//!   every authenticated heartbeat it calls
//!   [`PeerState::record_heartbeat`], which classifies the effect as
//!   `SameIp`, `FirstHeartbeat`, or `IpChanged` — only the latter two fire
//!   the watch channel and disturb the data plane.
//!
//! This split exists to keep the **heartbeat invariance** property obvious
//! and unit-testable: as long as `PeerState::record_heartbeat` does the right
//! thing, no amount of UDP traffic on the heartbeat port can move flows
//! unless the source IP truly changed.

mod peer_state;
mod server;

pub use peer_state::{HeartbeatEffect, PeerState, UNENROLLED_PEER_KEY};
pub use server::{HeartbeatServer, OutboundHandle};
