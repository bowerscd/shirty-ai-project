//! Prometheus metrics registration & HTTP surface.
//!
//! The `metrics` crate gives us a global recorder; we install
//! `metrics_exporter_prometheus`'s recorder once at startup and stand up a
//! tiny hyper server on the configured `[metrics] listen` address. Hot-path
//! call sites use the [`metrics::counter!`] / [`metrics::gauge!`] macros
//! directly — no per-call lookup, just a recorder dispatch.
//!
//! ## HTTP endpoints
//!
//! The listener serves five routes — Prometheus exposition, standard
//! liveness / readiness probes, and a loopback-only chain-introspection
//! endpoint — over a single port:
//!
//! | Path                       | Status               | Body                            |
//! |----------------------------|----------------------|---------------------------------|
//! | `/metrics`                 | 200                  | Prometheus text exposition      |
//! | `/healthz`                 | 200                  | `ok\n` — liveness (process up)  |
//! | `/readyz`                  | 200 or 503           | `ready\n` once [`crate::health::mark_ready`] has been called; `not ready\n` otherwise |
//! | `/`                        | 200                  | Plain-text index of the above   |
//! | `/internal/derived-rules`  | 200 / 403 / 404      | JSON snapshot of the local node's chain-applied predicates + derived rules + chain identity. Loopback-only; non-loopback peers get 403. Returns 404 when [`init`] was called without an [`IntrospectionState`]. See [`crate::chain::introspection`]. |
//! | (other)                    | 404                  | `not found\n`                   |
//!
//! Bundling all routes behind one listener keeps the operator-facing
//! surface to a single port. Kubernetes `readinessProbe.httpGet.path:
//! /readyz`, load-balancer pool members, `docker run --health-cmd="curl
//! -fs .../readyz"`, etc. all work without any extra wiring. The
//! `/internal/*` prefix is reserved for operator-facing introspection
//! that must never be reachable from outside the host.
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

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tokio::net::TcpListener;

use ratatoskr::control::Mode;

use crate::chain::introspection::IntrospectionState;
use crate::health;

/// Late-bound holder for the chain-introspection state. The metrics
/// listener has to come up *before* the proxy supervisor so the
/// supervisor's startup-time gauges hit the real recorder; the
/// [`IntrospectionState`], by contrast, needs the supervisor's handle
/// to read `derived_rules`. We resolve the ordering tension by passing
/// this empty slot into [`init`] and filling it in the orchestration
/// layer ([`crate::run_relay`] / [`crate::run_terminal`]) once the
/// supervisor exists.
///
/// HTTP requests to `/internal/derived-rules` that race the fill
/// observe `None` and receive `503 Service Unavailable` until the slot
/// is populated. In practice this window is a few milliseconds at
/// startup.
pub type IntrospectionSlot = Arc<OnceLock<Arc<IntrospectionState>>>;

/// Construct a fresh [`IntrospectionSlot`]. The caller passes the slot
/// to [`init`] *and* fills it later with [`OnceLock::set`].
pub fn new_introspection_slot() -> IntrospectionSlot {
    Arc::new(OnceLock::new())
}

/// Install the prometheus recorder, emit the startup gauges, and spawn the
/// HTTP listener that serves `/metrics`, `/healthz`, `/readyz`, `/`, and
/// — when `introspection` resolves — the loopback-gated
/// `/internal/derived-rules` chain-introspection endpoint.
///
/// Must be called exactly once per process before any metric is emitted
/// (otherwise that metric goes to the no-op recorder). Returns the actual
/// bound address — primarily useful for tests that pass `127.0.0.1:0`.
pub async fn init(
    listen: SocketAddr,
    mode: Mode,
    introspection: Option<IntrospectionSlot>,
) -> Result<SocketAddr> {
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

    // TcpListener::bind is what gives us EADDRINUSE if the port is taken.
    // Use std then convert so that we get the synchronous error directly.
    let std_listener = std::net::TcpListener::bind(listen)
        .with_context(|| format!("binding metrics listener on {listen}"))?;
    std_listener
        .set_nonblocking(true)
        .context("set_nonblocking on metrics listener")?;
    let bound = std_listener
        .local_addr()
        .context("local_addr on metrics listener")?;
    let listener = TcpListener::from_std(std_listener)
        .context("converting metrics listener to tokio")?;

    tokio::spawn(accept_loop(listener, handle, introspection));

    tracing::info!(
        listen = %bound,
        mode = mode.as_str(),
        "metrics + health listener up (/metrics /healthz /readyz)"
    );
    Ok(bound)
}

async fn accept_loop(
    listener: TcpListener,
    handle: PrometheusHandle,
    introspection: Option<IntrospectionSlot>,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "metrics accept error; retrying");
                continue;
            }
        };
        let handle = handle.clone();
        let introspection = introspection.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req: Request<Incoming>| {
                let handle = handle.clone();
                let introspection = introspection.clone();
                async move {
                    Ok::<_, std::convert::Infallible>(route(
                        req,
                        &handle,
                        introspection.as_ref(),
                        peer,
                    ))
                }
            });
            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                tracing::debug!(peer = %peer, error = %e, "metrics connection error");
            }
        });
    }
}

fn route(
    req: Request<Incoming>,
    handle: &PrometheusHandle,
    introspection: Option<&IntrospectionSlot>,
    peer: SocketAddr,
) -> Response<Full<Bytes>> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => text_response(StatusCode::OK, handle.render()),
        (&Method::GET, "/healthz") => text_response(StatusCode::OK, "ok\n".to_string()),
        (&Method::GET, "/readyz") => {
            if health::is_ready() {
                text_response(StatusCode::OK, "ready\n".to_string())
            } else {
                text_response(StatusCode::SERVICE_UNAVAILABLE, "not ready\n".to_string())
            }
        }
        (&Method::GET, "/") => text_response(
            StatusCode::OK,
            INDEX_BODY.to_string(),
        ),
        (&Method::GET, "/internal/derived-rules") => {
            internal_derived_rules(introspection, peer)
        }
        _ => text_response(StatusCode::NOT_FOUND, "not found\n".to_string()),
    }
}

/// `/internal/derived-rules` handler. Gated to loopback peers — the
/// endpoint exposes the operator's effective rule set (hostnames + ports)
/// and must not leak across the trust boundary. Non-loopback peers see
/// `403 Forbidden`. A 404 is returned when [`init`] was called without an
/// introspection slot (e.g. an operator path that disables the
/// endpoint). `503` is returned when the slot was passed but the
/// orchestration layer has not yet filled it (brief startup window
/// between `metrics::init` and supervisor construction).
fn internal_derived_rules(
    introspection: Option<&IntrospectionSlot>,
    peer: SocketAddr,
) -> Response<Full<Bytes>> {
    if !peer.ip().is_loopback() {
        tracing::warn!(
            peer = %peer,
            "non-loopback peer requested /internal/derived-rules; refusing"
        );
        return text_response(
            StatusCode::FORBIDDEN,
            "forbidden: /internal/* is loopback-only\n".to_string(),
        );
    }
    let Some(slot) = introspection else {
        return text_response(
            StatusCode::NOT_FOUND,
            "not found\n".to_string(),
        );
    };
    let Some(ix) = slot.get() else {
        return text_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "introspection state not yet initialised\n".to_string(),
        );
    };
    match ix.render_json() {
        Ok(body) => Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body)))
            .expect("static response build never fails"),
        Err(e) => {
            tracing::error!(error = %e, "render_json failed");
            text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error\n".to_string(),
            )
        }
    }
}

fn text_response(status: StatusCode, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .expect("static response build never fails")
}

const INDEX_BODY: &str = "\
yggdrasil

/metrics                  Prometheus text exposition
/healthz                  Liveness probe — 200 while the process is responding
/readyz                   Readiness probe — 200 once all subsystems are bound, else 503
/internal/derived-rules   Chain introspection JSON (loopback only)
";

