//! Backend dialer for HTTPS rules — a hyper-util `legacy::Client` that
//! pools connections per `(host, port)`.
//!
//! Split out from the original monolithic `http_frontend.rs` (Phase B4).

use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as LegacyClient;
use hyper_util::rt::TokioExecutor;

/// HTTP/1.1 + HTTP/2 capable client that pools connections per `(host, port)`.
/// One instance per frontend; cloning is cheap (it's an Arc internally).
pub(crate) type BackendClient = LegacyClient<HttpConnector, BoxBody<Bytes, hyper::Error>>;

pub(crate) fn build_backend_client() -> BackendClient {
    let mut http = HttpConnector::new();
    http.set_nodelay(true);
    http.enforce_http(true); // refuse non-http:// upstreams; HTTPS upstreams unsupported in this phase.
    http.set_connect_timeout(Some(Duration::from_secs(5)));
    LegacyClient::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(32)
        .build::<_, BoxBody<Bytes, hyper::Error>>(http)
}
