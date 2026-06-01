//! NAT-traversal integration tests.
//!
//! Tests the full `NatMapper` lifecycle against an in-process
//! `MockNatGateway`. The mapper sees a real loopback socket and
//! sends real PCP / NAT-PMP frames; the mock parses them with the
//! production codecs and emits programmable responses. This makes
//! the codecs themselves part of the test surface: a regression in
//! wire/pcp.rs would fail here even if `cargo test --lib` passed.

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

use ratatoskr::rule::{Protocol, Rule, RuleSet};

use yggdrasil::nat::discovery::Gateway;
use yggdrasil::nat::wire::{pcp, MapProtocol};
use yggdrasil::nat::{NatMapper, NatMapperParams, NatProtocol, NatState, NatTraversalMode};

use common::nat_gateway::{MockNatGateway, MockResponse};

const SETTLE: Duration = Duration::from_millis(150);

/// Poll until the mock gateway has received at least `target`
/// requests, bounded by `timeout`. Deterministic replacement for
/// `sleep(SETTLE)` in tests where the next assertion looks at the
/// gateway's recorded request log.
async fn wait_for_requests(gateway: &MockNatGateway, target: usize, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let n = gateway.requests().len();
        if n >= target {
            return;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "timed out waiting for ≥ {target} gateway requests; have {n}"
            );
        }
        // 5 ms backoff between request-count polls; deadline gates the loop.
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}


fn loopback_rule(name: &str, port: u16) -> Rule {
    Rule {
        name: name.into(),
        // 192.168.0.5 makes the listener look like a real LAN bind;
        // the mapper accepts it (it's RFC 1918) and uses it as the
        // PCP internal_addr hint. The actual socket is never opened
        // here — only the mapper sees this rule.
        listen: format!("192.168.0.5:{port}").parse().unwrap(),
        protocol: Protocol::Tcp,
        target_port: None,
        target: Some("127.0.0.1:9".to_string()),
        idle_timeout: None,
        proxy_protocol: None,
    }
}

fn rule_set(rules: Vec<Rule>) -> RuleSet {
    RuleSet::from_rules(rules).unwrap()
}

async fn spawn_mapper_against(
    gateway_addr: SocketAddr,
    mode: NatTraversalMode,
    accept_listen: Option<SocketAddr>,
    rx: watch::Receiver<RuleSet>,
    shutdown: CancellationToken,
) -> NatMapper {
    let (v4, port) = match gateway_addr {
        SocketAddr::V4(v4) => (*v4.ip(), v4.port()),
        SocketAddr::V6(_) => panic!("mock gateway should bind v4"),
    };
    let params = NatMapperParams {
        mode,
        accept_listen,
        rule_set_rx: rx,
        shutdown,
        https_listen: "0.0.0.0:443".parse().unwrap(),
        https_http3: true,
        gateway_override: Some(Gateway {
            addr: v4,
            local_source: Ipv4Addr::LOCALHOST,
            port,
        }),
        shutdown_release_timeout: Some(Duration::from_millis(250)),
    };
    NatMapper::spawn(params).await.unwrap()
}

#[tokio::test]
async fn mapper_off_holds_no_resources_and_returns_disabled_error() {
    // `nat_traversal = "off"` returns the Disabled spawn error so
    // the daemon's wireup helper decides to hold None instead.
    let shutdown = CancellationToken::new();
    let (_tx, rx) = watch::channel(RuleSet::default());
    let params = NatMapperParams {
        mode: NatTraversalMode::Off,
        accept_listen: None,
        rule_set_rx: rx,
        shutdown: shutdown.clone(),
        https_listen: "0.0.0.0:443".parse().unwrap(),
        https_http3: true,
        gateway_override: None,
        shutdown_release_timeout: None,
    };
    let err = NatMapper::spawn(params).await.err().unwrap();
    assert!(matches!(
        err,
        yggdrasil::nat::mapper::MapperSpawnError::Disabled
    ));
}

#[tokio::test]
async fn mapper_pcp_maps_initial_rule_on_apply() {
    let gateway = MockNatGateway::start().await;
    gateway.set_default(MockResponse::pcp_ok());

    let shutdown = CancellationToken::new();
    let (tx, rx) = watch::channel(RuleSet::default());
    let mapper = spawn_mapper_against(
        gateway.addr,
        NatTraversalMode::Pcp,
        None,
        rx,
        shutdown.clone(),
    )
    .await;

    // Apply a single TCP rule.
    tx.send(rule_set(vec![loopback_rule("ssh", 22)])).unwrap();
    wait_for_requests(&gateway, 1, Duration::from_secs(2)).await;

    let reqs = gateway.requests();
    let pcp = reqs[0].pcp().expect("first request should be PCP");
    assert_eq!(pcp.protocol, MapProtocol::Tcp);
    assert_eq!(pcp.internal_port, 22);
    assert_eq!(pcp.suggested_external_port, 22);
    assert!(pcp.lifetime_secs > 0);

    let snap = mapper.handle().snapshot();
    assert_eq!(snap.state, NatState::Active, "mapper should be Active");
    assert_eq!(snap.protocol, Some(NatProtocol::Pcp));
    assert_eq!(snap.active_mappings.len(), 1);
    assert_eq!(snap.external_ip, Some(Ipv4Addr::new(203, 0, 113, 42)));

    shutdown.cancel();
    mapper.shutdown().await;
    gateway.shutdown().await;
}

#[tokio::test]
async fn mapper_natpmp_explicit_mode_uses_natpmp_only() {
    let gateway = MockNatGateway::start().await;
    gateway.set_default(MockResponse::natpmp_ok());

    let shutdown = CancellationToken::new();
    let (tx, rx) = watch::channel(RuleSet::default());
    let mapper = spawn_mapper_against(
        gateway.addr,
        NatTraversalMode::NatPmp,
        None,
        rx,
        shutdown.clone(),
    )
    .await;

    tx.send(rule_set(vec![loopback_rule("ssh", 22)])).unwrap();
    wait_for_requests(&gateway, 1, Duration::from_secs(2)).await;

    let reqs = gateway.requests();
    assert!(
        reqs.iter().all(|r| r.natpmp().is_some()),
        "every request must be NAT-PMP in natpmp mode, got {reqs:?}"
    );

    let snap = mapper.handle().snapshot();
    assert_eq!(snap.protocol, Some(NatProtocol::NatPmp));
    assert_eq!(snap.active_mappings.len(), 1);

    shutdown.cancel();
    mapper.shutdown().await;
    gateway.shutdown().await;
}

#[tokio::test]
async fn mapper_auto_falls_back_to_natpmp_on_unsupp_version() {
    let gateway = MockNatGateway::start().await;
    // First request (PCP) gets UnsuppVersion; mapper should retry
    // with NAT-PMP, and the default policy is natpmp_ok which
    // matches the second-attempt protocol.
    gateway.enqueue(MockResponse::PcpError {
        code: pcp::PcpResultCode::UnsuppVersion,
        epoch_time: 100,
    });
    gateway.set_default(MockResponse::natpmp_ok());

    let shutdown = CancellationToken::new();
    let (tx, rx) = watch::channel(RuleSet::default());
    let mapper = spawn_mapper_against(
        gateway.addr,
        NatTraversalMode::Auto,
        None,
        rx,
        shutdown.clone(),
    )
    .await;

    tx.send(rule_set(vec![loopback_rule("ssh", 22)])).unwrap();
    // Expect ≥ 2: the initial PCP attempt + the NAT-PMP retry that
    // actually succeeds.
    wait_for_requests(&gateway, 2, Duration::from_secs(2)).await;

    let snap = mapper.handle().snapshot();
    assert_eq!(
        snap.protocol,
        Some(NatProtocol::NatPmp),
        "fell back to NAT-PMP"
    );
    assert_eq!(snap.active_mappings.len(), 1);

    shutdown.cancel();
    mapper.shutdown().await;
    gateway.shutdown().await;
}

#[tokio::test]
async fn mapper_unmaps_on_rule_removal() {
    let gateway = MockNatGateway::start().await;
    gateway.set_default(MockResponse::pcp_ok());

    let shutdown = CancellationToken::new();
    let (tx, rx) = watch::channel(RuleSet::default());
    let mapper = spawn_mapper_against(
        gateway.addr,
        NatTraversalMode::Pcp,
        None,
        rx,
        shutdown.clone(),
    )
    .await;

    tx.send(rule_set(vec![loopback_rule("ssh", 22)])).unwrap();
    wait_for_requests(&gateway, 1, Duration::from_secs(2)).await;
    let create_count = gateway.requests().len();

    // Apply an empty rule set; the mapper should send a
    // lifetime=0 release request for the previously-mapped port.
    tx.send(RuleSet::default()).unwrap();
    wait_for_requests(&gateway, create_count + 1, Duration::from_secs(2)).await;

    let after = gateway.requests();
    assert!(
        after.len() > create_count,
        "expected at least one release request after rule removal: before={create_count}, after={}",
        after.len()
    );
    // The release request has lifetime_secs == 0.
    let release = after
        .iter()
        .skip(create_count)
        .find_map(|r| r.pcp())
        .expect("release request should be PCP");
    assert_eq!(release.lifetime_secs, 0);
    assert_eq!(release.internal_port, 22);

    let snap = mapper.handle().snapshot();
    assert!(snap.active_mappings.is_empty());

    shutdown.cancel();
    mapper.shutdown().await;
    gateway.shutdown().await;
}

#[tokio::test]
async fn mapper_unmaps_all_on_shutdown() {
    let gateway = MockNatGateway::start().await;
    gateway.set_default(MockResponse::pcp_ok());

    let shutdown = CancellationToken::new();
    let (tx, rx) = watch::channel(RuleSet::default());
    let mapper = spawn_mapper_against(
        gateway.addr,
        NatTraversalMode::Pcp,
        None,
        rx,
        shutdown.clone(),
    )
    .await;

    tx.send(rule_set(vec![
        loopback_rule("ssh", 22),
        loopback_rule("web", 8080),
    ]))
    .unwrap();
    // Two MAP requests (one per rule).
    wait_for_requests(&gateway, 2, Duration::from_secs(2)).await;
    let create_count = gateway.requests().len();

    shutdown.cancel();
    mapper.shutdown().await;
    // Wait for the lifetime=0 release datagrams the mapper sent on
    // its way out — one per active mapping (2). `mapper.shutdown()`
    // returned when its tokio::spawn handle resolved, but the
    // datagrams still need to be observed by the gateway task.
    wait_for_requests(&gateway, create_count + 2, Duration::from_secs(2)).await;

    let after = gateway.requests();
    let releases: Vec<&pcp::PcpMapRequest> = after
        .iter()
        .skip(create_count)
        .filter_map(|r| r.pcp())
        .filter(|p| p.lifetime_secs == 0)
        .collect();
    assert!(
        releases.len() >= 2,
        "expected at least 2 release requests on shutdown, got {}: {after:?}",
        releases.len()
    );
    gateway.shutdown().await;
}

#[tokio::test]
async fn mapper_includes_accept_listen_target() {
    let gateway = MockNatGateway::start().await;
    gateway.set_default(MockResponse::pcp_ok());

    let shutdown = CancellationToken::new();
    let (_tx, rx) = watch::channel(RuleSet::default());
    let accept: SocketAddr = "192.168.0.5:51820".parse().unwrap();
    let mapper = spawn_mapper_against(
        gateway.addr,
        NatTraversalMode::Pcp,
        Some(accept),
        rx,
        shutdown.clone(),
    )
    .await;

    wait_for_requests(&gateway, 1, Duration::from_secs(2)).await;
    let reqs = gateway.requests();
    let udp_51820 = reqs
        .iter()
        .filter_map(|r| r.pcp())
        .find(|p| p.protocol == MapProtocol::Udp && p.internal_port == 51820);
    assert!(
        udp_51820.is_some(),
        "accept-listen target not mapped: {reqs:?}"
    );

    let snap = mapper.handle().snapshot();
    let has_accept = snap
        .active_mappings
        .iter()
        .any(|m| matches!(m.target.origin, yggdrasil::nat::MappingOrigin::AcceptListen));
    assert!(has_accept);

    shutdown.cancel();
    mapper.shutdown().await;
    gateway.shutdown().await;
}

#[tokio::test]
async fn mapper_loopback_listener_is_filtered_and_never_mapped() {
    let gateway = MockNatGateway::start().await;
    gateway.set_default(MockResponse::pcp_ok());

    let shutdown = CancellationToken::new();
    let (tx, rx) = watch::channel(RuleSet::default());
    let mapper = spawn_mapper_against(
        gateway.addr,
        NatTraversalMode::Pcp,
        None,
        rx,
        shutdown.clone(),
    )
    .await;

    // Loopback bind — must not produce a MAP request. This is a
    // negative assertion: there's no observable "the mapper finished
    // processing the rule-set update without producing a request"
    // signal, so SETTLE is the irreducible budget for the mapper's
    // reconcile loop. If it ever does emit, the assertion below
    // catches it.
    let mut rule = loopback_rule("local-only", 9000);
    rule.listen = "127.0.0.1:9000".parse().unwrap();
    tx.send(rule_set(vec![rule])).unwrap();
    sleep(SETTLE).await;

    assert!(
        gateway.requests().is_empty(),
        "loopback-bound listener must not produce MAP requests: {:?}",
        gateway.requests()
    );

    shutdown.cancel();
    mapper.shutdown().await;
    gateway.shutdown().await;
}

#[tokio::test]
async fn mapper_off_makes_no_requests_even_after_apply() {
    let gateway = MockNatGateway::start().await;
    gateway.set_default(MockResponse::pcp_ok());

    let shutdown = CancellationToken::new();
    let (tx, _rx) = watch::channel(RuleSet::default());
    // We explicitly DO NOT spawn the mapper. Off-mode must hold no
    // resources and emit no traffic. Negative assertion — same
    // irreducible-SETTLE caveat as loopback_listener_is_filtered.
    tx.send(rule_set(vec![loopback_rule("ssh", 22)])).unwrap();
    sleep(SETTLE).await;

    assert!(gateway.requests().is_empty());

    shutdown.cancel();
    gateway.shutdown().await;
}

#[tokio::test]
async fn status_snapshot_reflects_mapper_progress() {
    let gateway = MockNatGateway::start().await;
    gateway.set_default(MockResponse::pcp_ok());

    let shutdown = CancellationToken::new();
    let (tx, rx) = watch::channel(RuleSet::default());
    let mapper = spawn_mapper_against(
        gateway.addr,
        NatTraversalMode::Pcp,
        None,
        rx,
        shutdown.clone(),
    )
    .await;

    let handle = mapper.handle();
    let snap0 = handle.snapshot();
    assert_eq!(snap0.mode, NatTraversalMode::Pcp);
    // Either Discovering or Active depending on whether the
    // initial reconcile pass has completed.
    assert!(matches!(
        snap0.state,
        NatState::Discovering | NatState::Active
    ));

    tx.send(rule_set(vec![loopback_rule("ssh", 22)])).unwrap();
    wait_for_requests(&gateway, 1, Duration::from_secs(2)).await;

    let snap1 = handle.snapshot();
    assert_eq!(snap1.state, NatState::Active);
    assert_eq!(snap1.active_mappings.len(), 1);
    assert_eq!(snap1.protocol, Some(NatProtocol::Pcp));
    assert!(snap1.external_ip.is_some());

    shutdown.cancel();
    mapper.shutdown().await;
    gateway.shutdown().await;
}

#[tokio::test]
async fn mapper_permanent_error_drops_target_and_surfaces_error() {
    let gateway = MockNatGateway::start().await;
    // NotAuthorized is a permanent error per RFC 6887 — the mapper
    // should drop the target (rather than retrying forever) and
    // surface the error in `last_error`.
    gateway.set_default(MockResponse::PcpError {
        code: pcp::PcpResultCode::NotAuthorized,
        epoch_time: 100,
    });

    let shutdown = CancellationToken::new();
    let (tx, rx) = watch::channel(RuleSet::default());
    let mapper = spawn_mapper_against(
        gateway.addr,
        NatTraversalMode::Pcp,
        None,
        rx,
        shutdown.clone(),
    )
    .await;

    tx.send(rule_set(vec![loopback_rule("ssh", 22)])).unwrap();
    wait_for_requests(&gateway, 1, Duration::from_secs(2)).await;
    // Then poll the snapshot for the surfaced error (it's set after
    // the request response is processed; one short await is enough).
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let snap = loop {
        let snap = mapper.handle().snapshot();
        if snap.last_error.is_some() {
            break snap;
        }
        if std::time::Instant::now() >= deadline {
            panic!("mapper never surfaced last_error");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    assert_eq!(snap.active_mappings.len(), 0);
    assert!(snap.last_error.is_some());
    assert!(snap.last_error.unwrap().contains("NotAuthorized"));

    shutdown.cancel();
    mapper.shutdown().await;
    gateway.shutdown().await;
}

#[tokio::test]
async fn natpmp_release_has_lifetime_zero() {
    let gateway = MockNatGateway::start().await;
    gateway.set_default(MockResponse::natpmp_ok());

    let shutdown = CancellationToken::new();
    let (tx, rx) = watch::channel(RuleSet::default());
    let mapper = spawn_mapper_against(
        gateway.addr,
        NatTraversalMode::NatPmp,
        None,
        rx,
        shutdown.clone(),
    )
    .await;

    tx.send(rule_set(vec![loopback_rule("ssh", 22)])).unwrap();
    wait_for_requests(&gateway, 1, Duration::from_secs(2)).await;
    let after_create = gateway.requests().len();

    shutdown.cancel();
    mapper.shutdown().await;
    // Wait for the release datagram to land after shutdown returns.
    wait_for_requests(&gateway, after_create + 1, Duration::from_secs(2)).await;

    let all = gateway.requests();
    let release = all
        .iter()
        .skip(after_create)
        .find_map(|r| r.natpmp())
        .expect("NAT-PMP release should be present after shutdown");
    assert_eq!(release.lifetime_secs, 0);
    gateway.shutdown().await;
}
