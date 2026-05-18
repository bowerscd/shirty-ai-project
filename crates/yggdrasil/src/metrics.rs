//! Prometheus metrics registration & exporter wiring.
//!
//! The `metrics` crate gives us a global recorder; we install
//! `metrics_exporter_prometheus` once at startup. Hot-path call sites use the
//! [`metrics::counter!`] / [`metrics::gauge!`] macros directly — no per-call
//! lookup, just a recorder dispatch.
//!
//! ## Metric catalogue
//!
//! All metric names are prefixed with `yggdrasil_` so they're cleanly
//! distinguishable from any sibling services scraped from the same host.
//!
//! Counters (monotonic):
//! - `yggdrasil_heartbeats_received_total{result}` — `result=accepted|rejected`.
//! - `yggdrasil_handshakes_completed_total` — Noise_IK responder completions.
//! - `yggdrasil_peer_ip_changes_total` — observed `peer_ip` transitions.
//! - `yggdrasil_udp_flows_drained_on_ip_change_total{rule}` — flows aborted
//!   when the residential IP changed. **Asserted == 0 by
//!   `heartbeat_invariance.rs`** when no IP change occurs.
//! - `yggdrasil_tcp_connections_accepted_total{rule}` — incoming TCP connects.
//! - `yggdrasil_udp_packets_inbound_total{rule}` — client→upstream datagrams.
//! - `yggdrasil_udp_packets_outbound_total{rule}` — upstream→client datagrams.
//!
//! Gauges:
//! - `yggdrasil_branches_loaded` — number of currently-supervised rules.
//! - `yggdrasil_udp_flows_active{rule}` — current size of a rule's flow table.
//! - `yggdrasil_build_info{version}` — always set to `1`, used to expose the build version
//!   as a label.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use metrics_exporter_prometheus::PrometheusBuilder;

/// Install the prometheus exporter listening on `listen`. Should be called
/// exactly once per process before any metric is emitted (otherwise that
/// metric goes to the no-op recorder).
pub fn init(listen: SocketAddr) -> Result<()> {
    PrometheusBuilder::new()
        .with_http_listener(listen)
        .install()
        .with_context(|| format!("installing prometheus exporter on {listen}"))?;

    // Build info gauge — emit once at startup so scrapes can see the version.
    metrics::gauge!(
        "yggdrasil_build_info",
        "version" => env!("CARGO_PKG_VERSION"),
    )
    .set(1.0);

    tracing::info!(%listen, "prometheus exporter listening");
    Ok(())
}
