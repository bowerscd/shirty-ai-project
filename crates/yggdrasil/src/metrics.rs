//! Prometheus metrics registration.
//!
//! The `metrics` crate gives us a global recorder; we install
//! `metrics_exporter_prometheus`'s recorder once at startup. Hot-path
//! call sites use the [`metrics::counter!`] / [`metrics::gauge!`] macros
//! directly — no per-call lookup, just a recorder dispatch.
//!
//! The text exposition format is served exclusively over the
//! `yggdrasilctl` UDS via [`ratatoskr::control::Request::Metrics`].
//! There is no HTTP listener; operators that scrape via Prometheus run
//! a thin UDS→HTTP adapter sidecar.
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
//! - `yggdrasil_udp_flows_rejected_total{rule,reason}` — new flows that
//!   could not be admitted. `reason=cap` is the only variant today (flow
//!   table at [`crate::proxy::udp::MAX_FLOWS_PER_RULE_DEFAULT`]).
//! - `yggdrasil_tcp_connections_accepted_total{rule}` — incoming TCP connects.
//! - `yggdrasil_udp_packets_inbound_total{rule}` — client→upstream datagrams.
//! - `yggdrasil_udp_packets_outbound_total{rule}` — upstream→client datagrams.
//!
//! Gauges:
//! - `yggdrasil_rules_loaded` — number of currently-supervised rules.
//! - `yggdrasil_udp_flows_active{rule}` — current size of a rule's flow table.
//! - `yggdrasil_build_info{version}` — always set to `1`, used to expose the build version
//!   as a label.
//! - `yggdrasil_mode{mode}` — always `1`, the `mode` label is one of
//!   `"relay"` / `"terminal"`. Cardinality 1 per daemon. Lets dashboards
//!   filter and color by mode without joining against external metadata.
//! - `yggdrasil_last_heartbeat_timestamp_seconds` — wall-clock seconds since
//!   `UNIX_EPOCH` of the last *accepted* heartbeat. Absent in terminal mode
//!   (no heartbeat path) and until the first heartbeat lands in relay mode.
//!   Alert primitive: `time() - yggdrasil_last_heartbeat_timestamp_seconds
//!   > N`.
//!
//! ### NAT traversal (opt-in, `[server].nat_traversal != "off"`)
//!
//! Emitted only when the daemon's NAT mapper is running. When the
//! mapper is off, none of these series appear.
//!
//! Counters:
//! - `yggdrasil_nat_mappings_created_total{protocol,origin,result_code}`
//!   — every initial MAP request the mapper sent. `protocol` is `"pcp"`
//!   or `"natpmp"`. `origin` is one of `"rule:<name>" |
//!   "accept" | "redirect:<ip>" | "http3:<name>"`. `result_code` is
//!   `"success"` on the happy path, otherwise the protocol's error
//!   code stringified (`"network_failure"`, `"no_resources"`, ...).
//! - `yggdrasil_nat_renewals_total{protocol,origin,result_code}` —
//!   the half-lifetime renewal path. Separated from creates so
//!   dashboards can show "are renewals failing while creates succeed?"
//! - `yggdrasil_nat_mappings_released_total{protocol,origin}` —
//!   explicit `lifetime = 0` unmaps issued during reconciliation (a
//!   rule was removed) or shutdown (every mapping released).
//! - `yggdrasil_nat_epoch_resets_total` — gateway epoch went
//!   backwards; every increment means the mapper rebuilt the entire
//!   mapping table from scratch per RFC 6887 §8.5.
//! - `yggdrasil_nat_mapping_skipped_total{reason}` — listener filtered
//!   out before mapping. `reason ∈ {loopback, link_local,
//!   public_internal, ipv6}`. Incremented once per (listener, reason)
//!   tuple for the daemon's lifetime; re-pushes of the same config do
//!   not re-increment.
//!
//! Gauges:
//! - `yggdrasil_nat_active_mappings` — current size of the active
//!   mapping table.
//! - `yggdrasil_nat_state{state}` — set to `1` for the current
//!   mapper state (`"discovering"` / `"active"` / `"backoff"`),
//!   `0` for the others. Useful for alerting: `max by () (
//!   yggdrasil_nat_state{state="backoff"}) == 1` fires when the
//!   gateway has gone unresponsive.
//! - `yggdrasil_nat_external_ip_known` — `1` once the gateway has
//!   told us its external IP, `0` otherwise.

use anyhow::{Context, Result};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

use ratatoskr::control::Mode;

/// Install the prometheus recorder and emit the startup gauges.
///
/// Must be called exactly once per process before any metric is emitted
/// (otherwise that metric goes to the no-op recorder). Returns the
/// [`PrometheusHandle`] so callers can render the text exposition format
/// directly (e.g. for the UDS-served `local metrics` command).
pub fn install_recorder(mode: Mode) -> Result<PrometheusHandle> {
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .with_context(|| "installing prometheus recorder")?;

    // Build info gauge — emit once at startup so scrapes can see the version.
    metrics::gauge!(
        "yggdrasil_build_info",
        "version" => env!("CARGO_PKG_VERSION"),
    )
    .set(1.0);

    // Mode gauge — always 1, the label carries the relay/terminal split.
    // Cardinality is 1 per daemon (a process has exactly one mode).
    metrics::gauge!(
        "yggdrasil_mode",
        "mode" => mode.as_str(),
    )
    .set(1.0);

    Ok(handle)
}

/// Build a fresh, unattached [`PrometheusHandle`] for tests that need
/// to construct a [`crate::control::ControlServer`] without installing
/// a global recorder. The returned handle renders an empty exposition
/// (no metrics will route through it). Production code paths must use
/// [`install_recorder`] instead.
#[doc(hidden)]
pub fn detached_handle_for_tests() -> PrometheusHandle {
    PrometheusBuilder::new().build_recorder().handle()
}
