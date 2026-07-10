//! Microbench: HTTP/3 request rewriting (header strip + inject + URI rewrite).
//!
//! Measures the per-request CPU cost of the steps `proxy::h3_frontend::handle_stream`
//! does before / after the actual network IO. Useful for catching regressions
//! in the shared `proxy::forward` helpers.

use std::net::{IpAddr, Ipv4Addr};

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, Criterion};
use http::{HeaderMap, HeaderValue, Request, Uri, Version};
use std::hint::black_box;
use url::Url;

use yggdrasil::proxy::forward;

fn synth_request_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        "user-agent",
        HeaderValue::from_static("yggdrasil-bench/1.0"),
    );
    h.insert("accept", HeaderValue::from_static("*/*"));
    h.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.7"));
    h.insert("x-forwarded-proto", HeaderValue::from_static("http"));
    h.insert("x-real-ip", HeaderValue::from_static("198.51.100.7"));
    h.insert("connection", HeaderValue::from_static("keep-alive"));
    h
}

fn synth_h3_request() -> Request<Bytes> {
    let uri = Uri::from_static("https://api.example.com/v1/accounts/42?expand=teams");
    Request::builder()
        .method(http::Method::GET)
        .version(http::Version::HTTP_3)
        .uri(uri)
        .header("host", HeaderValue::from_static("api.example.com"))
        .header(
            "user-agent",
            HeaderValue::from_static("yggdrasil-bench/1.0"),
        )
        .header("accept", HeaderValue::from_static("*/*"))
        .header("x-forwarded-for", HeaderValue::from_static("198.51.100.7"))
        .header("x-forwarded-proto", HeaderValue::from_static("http"))
        .header("x-real-ip", HeaderValue::from_static("198.51.100.7"))
        .header("connection", HeaderValue::from_static("keep-alive"))
        .body(Bytes::new())
        .expect("synthetic h3 request builds")
}

fn bench_strip_and_inject(c: &mut Criterion) {
    let client_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
    c.bench_function("h3_strip_and_inject", |b| {
        b.iter(|| {
            let mut h = synth_request_headers();
            forward::strip_untrusted_forwarding(black_box(&mut h));
            forward::strip_hop_by_hop(black_box(&mut h));
            forward::inject_forwarded(
                black_box(&mut h),
                client_ip,
                Some("api.example.com"),
                "https",
            );
            black_box(&h);
        });
    });
}

fn bench_request_rewrite(c: &mut Criterion) {
    let client_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
    let upstream: Url = "http://127.0.0.1:8080/ignored-prefix"
        .parse()
        .expect("synthetic upstream URL parses");
    c.bench_function("h3_request_rewrite", |b| {
        b.iter(|| {
            let req = synth_h3_request();
            let outbound_uri =
                forward::build_upstream_uri(black_box(req.uri()), black_box(&upstream))
                    .expect("synthetic upstream URI builds");
            let (mut parts, body) = req.into_parts();
            forward::strip_untrusted_forwarding(black_box(&mut parts.headers));
            forward::strip_hop_by_hop(black_box(&mut parts.headers));
            forward::inject_forwarded(
                black_box(&mut parts.headers),
                client_ip,
                Some(black_box("api.example.com")),
                "https",
            );
            parts.uri = outbound_uri;
            parts.version = Version::HTTP_11;
            black_box(Request::from_parts(parts, body));
        });
    });
}

fn bench_hsts_inject(c: &mut Criterion) {
    use ratatoskr::rule::{HstsConfig, DEFAULT_HSTS_MAX_AGE};
    let cfg = HstsConfig {
        max_age: DEFAULT_HSTS_MAX_AGE,
        include_subdomains: true,
        preload: false,
    };
    c.bench_function("h3_hsts_inject", |b| {
        b.iter(|| {
            let mut h = HeaderMap::new();
            forward::maybe_inject_hsts(black_box(&mut h), Some(black_box(&cfg)));
            black_box(&h);
        });
    });
}

criterion_group!(
    benches,
    bench_strip_and_inject,
    bench_request_rewrite,
    bench_hsts_inject
);
criterion_main!(benches);
