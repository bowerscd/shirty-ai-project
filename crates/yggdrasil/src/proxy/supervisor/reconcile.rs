//! Reconcile loop: turn rule-set updates into start/stop/swap actions
//! against the active proxy table.
//!
//! All entry points are `pub(super)` — only [`super::ProxySupervisor`]
//! drives this code.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use ratatoskr::rule::{HttpRoute, Protocol, ProxyProto, Rule, RuleSet};

use crate::proxy::canary::CanaryArmTable;
use crate::proxy::certs::{load_routes_into_store, CertStore, CertWatcher};
use crate::proxy::h3_frontend::H3Frontend;
use crate::proxy::http_frontend::{HttpFrontend, RedirectListener};
use crate::proxy::resolver::{ResolverFactory, UpstreamResolver};
use crate::proxy::tcp::TcpProxy;
use crate::proxy::udp::{resolve_workers, UdpProxy, MAX_FLOWS_PER_RULE_DEFAULT};
use crate::rules::{RuleUpdate, RuleWatcher};

use super::cert_config::CertConfig;
use super::handle::{ActiveProxy, HttpsHandle, ProxyHandle};
use super::ProxySnapshot;

/// Synthetic rule-name used for the node-wide HTTPS frontend. Used as
/// the cert-watcher / redirect-listener registration key.
const HTTPS_FRONTEND_NAME: &str = "__https__";

#[allow(clippy::too_many_arguments)]
pub(super) async fn supervisor_loop(
    mut watcher: RuleWatcher,
    mut apply_rx: mpsc::Receiver<RuleSet>,
    current_set_tx: watch::Sender<RuleSet>,
    resolver_factory: ResolverFactory,
    default_bind: Option<IpAddr>,
    default_workers: Option<usize>,
    cert_config: CertConfig,
    cert_store: Arc<CertStore>,
    cert_watcher: Arc<CertWatcher>,
    graceful_drain_timeout: Option<Duration>,
    arm_table: Arc<CanaryArmTable>,
    cancel: CancellationToken,
    snapshot_tx: tokio::sync::watch::Sender<Vec<ProxySnapshot>>,
) {
    let mut active: HashMap<String, ActiveProxy> = HashMap::new();
    let mut redirect_listeners: HashMap<IpAddr, RedirectListener> = HashMap::new();
    let mut https_active: Option<ActiveProxy> = None;
    let mut prev_routes: Vec<HttpRoute> = Vec::new();
    // Supervisor-owned source of truth. Both the file watcher and the
    // external apply channel feed RuleSets in; we always compute the diff
    // against this field so the two sources can coexist without their
    // notions of "previous" diverging.
    let mut current_set: RuleSet = RuleSet::default();

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                tracing::info!("supervisor received shutdown signal");
                break;
            }
            update = watcher.recv() => {
                match update {
                    Some(u) => {
                        let RuleUpdate { set, diff: _ } = u;
                        let is_startup_empty = current_set.rules().is_empty()
                            && set.rules().is_empty()
                            && current_set.routes().is_empty()
                            && set.routes().is_empty();
                        if !is_startup_empty {
                            crate::systemd::notify_reloading();
                        }
                        apply_set(
                            &mut active,
                            &mut redirect_listeners,
                            &mut https_active,
                            &mut prev_routes,
                            &mut current_set,
                            set,
                            "file_watcher",
                            &resolver_factory,
                            default_bind,
                            default_workers,
                            &cert_config,
                            &cert_store,
                            &cert_watcher,
                            &arm_table,
                            graceful_drain_timeout,
                            &cancel,
                        )
                        .await;
                        let _ = current_set_tx.send(current_set.clone());
                        publish_snapshot(&active, &https_active, &snapshot_tx, &cert_store);
                        if !is_startup_empty {
                            crate::systemd::notify_ready_after_reload();
                        }
                    }
                    None => {
                        tracing::warn!("rule watcher channel closed; supervisor exiting");
                        break;
                    }
                }
            }
            ext = apply_rx.recv() => {
                if let Some(set) = ext {
                    crate::systemd::notify_reloading();
                    apply_set(
                        &mut active,
                        &mut redirect_listeners,
                        &mut https_active,
                        &mut prev_routes,
                        &mut current_set,
                        set,
                        "external_push",
                        &resolver_factory,
                        default_bind,
                        default_workers,
                        &cert_config,
                        &cert_store,
                        &cert_watcher,
                        &arm_table,
                        graceful_drain_timeout,
                        &cancel,
                    )
                    .await;
                    let _ = current_set_tx.send(current_set.clone());
                    publish_snapshot(&active, &https_active, &snapshot_tx, &cert_store);
                    crate::systemd::notify_ready_after_reload();
                }
            }
        }
    }

    let active_drained: Vec<ActiveProxy> = active.drain().map(|(_, p)| p).collect();
    let stops = active_drained
        .into_iter()
        .map(|p| p.handle.stop(graceful_drain_timeout));
    futures::future::join_all(stops).await;
    if let Some(ap) = https_active.take() {
        ap.handle.stop(graceful_drain_timeout).await;
    }
    let redirect_drained: Vec<RedirectListener> =
        redirect_listeners.drain().map(|(_, l)| l).collect();
    let red_stops = redirect_drained.into_iter().map(|l| l.stop());
    futures::future::join_all(red_stops).await;
    publish_snapshot(&active, &https_active, &snapshot_tx, &cert_store);
    tracing::info!("supervisor shut down");
}

#[allow(clippy::too_many_arguments)]
async fn apply_set(
    active: &mut HashMap<String, ActiveProxy>,
    redirect_listeners: &mut HashMap<IpAddr, RedirectListener>,
    https_active: &mut Option<ActiveProxy>,
    prev_routes: &mut Vec<HttpRoute>,
    current_set: &mut RuleSet,
    new_set: RuleSet,
    source: &'static str,
    resolver_factory: &ResolverFactory,
    default_bind: Option<IpAddr>,
    default_workers: Option<usize>,
    cert_config: &CertConfig,
    cert_store: &Arc<CertStore>,
    cert_watcher: &Arc<CertWatcher>,
    arm_table: &Arc<CanaryArmTable>,
    graceful_drain_timeout: Option<Duration>,
    parent_cancel: &CancellationToken,
) {
    let diff = current_set.diff(&new_set);
    tracing::debug!(
        source = source,
        added = diff.added.len(),
        changed = diff.changed.len(),
        removed = diff.removed.len(),
        unchanged = diff.unchanged.len(),
        routes = new_set.routes().len(),
        "supervisor applying rule set"
    );
    let set = new_set.clone();
    apply_update(
        active,
        redirect_listeners,
        RuleUpdate { set, diff },
        resolver_factory,
        default_bind,
        default_workers,
        cert_config,
        cert_store,
        cert_watcher,
        arm_table,
        graceful_drain_timeout,
        parent_cancel,
    )
    .await;

    reconcile_https(
        https_active,
        prev_routes,
        redirect_listeners,
        new_set.routes(),
        cert_config,
        cert_store,
        cert_watcher,
        graceful_drain_timeout,
        parent_cancel,
    )
    .await;

    // Garbage-collect redirect listeners that no longer have either a
    // registered cert'd host or a plaintext route.
    let dead_ips: Vec<IpAddr> = redirect_listeners
        .iter()
        .filter(|(_, l)| l.is_empty())
        .map(|(ip, _)| *ip)
        .collect();
    for ip in dead_ips {
        if let Some(l) = redirect_listeners.remove(&ip) {
            tracing::info!(ip = %ip, "tearing down idle HTTP→HTTPS redirect listener");
            l.stop().await;
        }
    }

    *current_set = new_set;
}

#[allow(clippy::too_many_arguments)]
async fn apply_update(
    active: &mut HashMap<String, ActiveProxy>,
    redirect_listeners: &mut HashMap<IpAddr, RedirectListener>,
    update: RuleUpdate,
    resolver_factory: &ResolverFactory,
    default_bind: Option<IpAddr>,
    default_workers: Option<usize>,
    cert_config: &CertConfig,
    cert_store: &Arc<CertStore>,
    cert_watcher: &Arc<CertWatcher>,
    arm_table: &Arc<CanaryArmTable>,
    graceful_drain_timeout: Option<Duration>,
    parent_cancel: &CancellationToken,
) {
    let RuleUpdate { set, diff } = update;

    // 1. Remove proxies for removed rules.
    for removed in &diff.removed {
        if let Some(ap) = active.remove(&removed.name) {
            tracing::info!(
                rule = %removed.name,
                listen = %ap.handle.local_addr(),
                "stopping removed rule"
            );
            ap.handle.stop(graceful_drain_timeout).await;
        }
    }

    // 2. Swap proxies for changed rules.
    for change in &diff.changed {
        if let Some(old) = active.remove(&change.old.name) {
            tracing::info!(
                rule = %change.old.name,
                old_listen = %old.handle.local_addr(),
                new_listen = %change.new.listen,
                "swapping changed rule"
            );
            old.handle.stop(graceful_drain_timeout).await;
        }
        match spawn_proxy_for_rule(
            change.new.clone(),
            resolver_factory,
            default_bind,
            default_workers,
            cert_config,
            cert_store,
            cert_watcher,
            redirect_listeners,
            arm_table,
            parent_cancel,
            active,
        )
        .await
        {
            Ok(ap) => {
                active.insert(change.new.name.clone(), ap);
            }
            Err(e) => {
                tracing::error!(
                    rule = %change.new.name,
                    error = %e,
                    "failed to spawn replacement proxy for changed rule; rule is now offline"
                );
            }
        }
    }

    // 3. Spawn proxies for added rules.
    for added in &diff.added {
        match spawn_proxy_for_rule(
            added.clone(),
            resolver_factory,
            default_bind,
            default_workers,
            cert_config,
            cert_store,
            cert_watcher,
            redirect_listeners,
            arm_table,
            parent_cancel,
            active,
        )
        .await
        {
            Ok(ap) => {
                tracing::info!(
                    rule = %added.name,
                    listen = %ap.handle.local_addr(),
                    protocol = added.protocol.as_str(),
                    upstream = %ap.upstream_description,
                    "added rule online"
                );
                active.insert(added.name.clone(), ap);
            }
            Err(e) => {
                tracing::error!(
                    rule = %added.name,
                    error = %e,
                    "failed to spawn proxy for new rule"
                );
            }
        }
    }

    if !diff.unchanged.is_empty() {
        tracing::trace!(
            unchanged = diff.unchanged.len(),
            "unchanged rules left undisturbed"
        );
    }
    let _ = set;
}

/// Reconcile the node-wide HTTPS frontend against the desired route
/// set extracted from `[[route]]` blocks.
///
/// HTTPS is **node-wide**: one frontend on `[server].https_listen`
/// serves every `[[route]]`. Hot reload that changes the route set
/// stops the existing frontend (draining in-flight connections up to
/// `graceful_drain_timeout`, the same budget SIGTERM honours) and
/// respawns it. Per-route diffing — adding or removing a single
/// route without disturbing the others — is deferred to the
/// `route-hot-reload-fix` follow-up.
#[allow(clippy::too_many_arguments)]
async fn reconcile_https(
    https_active: &mut Option<ActiveProxy>,
    prev_routes: &mut Vec<HttpRoute>,
    redirect_listeners: &mut HashMap<IpAddr, RedirectListener>,
    routes: &[HttpRoute],
    cert_config: &CertConfig,
    cert_store: &Arc<CertStore>,
    cert_watcher: &Arc<CertWatcher>,
    graceful_drain_timeout: Option<Duration>,
    parent_cancel: &CancellationToken,
) {
    let desired: Vec<HttpRoute> = routes.to_vec();
    let routes_match = desired == *prev_routes;

    if desired.is_empty() {
        if let Some(old) = https_active.take() {
            tracing::info!("no top-level [[route]] entries remain; tearing down HTTPS frontend");
            if let ProxyHandle::Https(h) = &old.handle {
                if let Some(rl) = redirect_listeners.get(&h.redirect_ip) {
                    for host in &h.redirect_hosts {
                        rl.unregister_host(host);
                    }
                    rl.unregister_plaintext_routes(HTTPS_FRONTEND_NAME);
                }
            }
            for r in prev_routes.iter() {
                let host = r.hostname.to_ascii_lowercase();
                cert_watcher.unregister(&host);
                cert_store.remove(&host);
            }
            old.handle.stop(graceful_drain_timeout).await;
        }
        prev_routes.clear();
        return;
    }

    if https_active.is_some() && routes_match {
        return;
    }

    // Per-route hot reload: if a frontend is alive and only the route
    // set differs (listener config is stable across reconcile calls in
    // a given supervisor lifetime), hot-swap the route tables in
    // place. New TLS handshakes / HTTP requests on EXISTING routes
    // see the same listener — no connection-drop, no rebind. Falls
    // through to the teardown + respawn path on any error (e.g.
    // cert-load failure for a newly-added route).
    if let Some(ap) = https_active.as_mut() {
        if matches!(&ap.handle, ProxyHandle::Https(_)) {
            match try_hot_swap_routes(
                ap,
                prev_routes,
                redirect_listeners,
                &desired,
                cert_config,
                cert_store,
                cert_watcher,
            )
            .await
            {
                Ok(()) => return,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "HTTPS route hot-swap failed; falling back to teardown + respawn"
                    );
                }
            }
        }
    }

    if let Some(old) = https_active.take() {
        if let ProxyHandle::Https(h) = &old.handle {
            if let Some(rl) = redirect_listeners.get(&h.redirect_ip) {
                for host in &h.redirect_hosts {
                    rl.unregister_host(host);
                }
                rl.unregister_plaintext_routes(HTTPS_FRONTEND_NAME);
            }
        }
        for r in prev_routes.iter() {
            let host = r.hostname.to_ascii_lowercase();
            cert_watcher.unregister(&host);
            cert_store.remove(&host);
        }
        old.handle.stop(graceful_drain_timeout).await;
    }

    match spawn_https_frontend(
        &desired,
        cert_config,
        cert_store,
        cert_watcher,
        redirect_listeners,
        parent_cancel,
    )
    .await
    {
        Ok(ap) => {
            tracing::info!(
                listen = %ap.handle.local_addr(),
                routes = desired.len(),
                cert_less = ap.cert_less_route_count,
                "HTTPS frontend online"
            );
            *https_active = Some(ap);
            *prev_routes = desired;
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to spawn HTTPS frontend; node is serving zero routes");
            prev_routes.clear();
        }
    }
}

/// Hot-swap the HTTPS frontend's route set in place. Used when only
/// the route table differs between the previous and desired state —
/// no listener rebind, no TLS-connection drop, no h3 endpoint
/// recreation. Returns `Err` if the hot-swap can't proceed (e.g. a
/// newly-added route's cert failed to load); the caller falls back
/// to teardown + respawn.
///
/// Side effects on success:
///   - cert_store gains entries for newly-added cert'd routes,
///     loses entries for removed routes.
///   - cert_watcher gains registrations for newly-added cert'd
///     routes, loses registrations for removed routes.
///   - redirect listener's host set + cert-less plaintext route
///     table reflect the new state.
///   - `HttpFrontend::update_routes` and `H3Frontend::update_routes`
///     atomically swap their route tables.
///   - `https_active.cert_less_route_count` and
///     `HttpsHandle::redirect_hosts` are updated in place.
///   - `*prev_routes` is replaced with `desired`.
#[allow(clippy::too_many_arguments)]
async fn try_hot_swap_routes(
    https_active: &mut ActiveProxy,
    prev_routes: &mut Vec<HttpRoute>,
    redirect_listeners: &mut HashMap<IpAddr, RedirectListener>,
    desired: &[HttpRoute],
    cert_config: &CertConfig,
    cert_store: &Arc<CertStore>,
    cert_watcher: &Arc<CertWatcher>,
) -> Result<()> {
    // Defensive: only valid for an active HTTPS handle.
    if !matches!(&https_active.handle, ProxyHandle::Https(_)) {
        anyhow::bail!("try_hot_swap_routes called on non-HTTPS handle");
    }

    let old_hosts: HashSet<String> = prev_routes
        .iter()
        .map(|r| r.hostname.to_ascii_lowercase())
        .collect();
    let new_hosts: HashSet<String> = desired
        .iter()
        .map(|r| r.hostname.to_ascii_lowercase())
        .collect();
    let removed: Vec<String> = old_hosts.difference(&new_hosts).cloned().collect();
    let added: Vec<String> = new_hosts.difference(&old_hosts).cloned().collect();

    // 1. Load certs for any newly-added routes through the same
    //    three-rung resolver as the spawn path. Failure to load a
    //    cert is non-fatal at this layer — the new route just ends
    //    up cert-less and is served only on the companion :80 path.
    //    But propagation of a hard error (e.g. invalid PEM in
    //    `default_cert`) bubbles up so the caller falls back to
    //    respawn rather than leaving a half-loaded cert_store.
    let added_routes: Vec<HttpRoute> = desired
        .iter()
        .filter(|r| added.contains(&r.hostname.to_ascii_lowercase()))
        .cloned()
        .collect();
    if !added_routes.is_empty() {
        load_routes_into_store(
            HTTPS_FRONTEND_NAME,
            &added_routes,
            cert_store,
            &cert_config.cert_dir,
            cert_config
                .default_cert
                .as_deref()
                .zip(cert_config.default_key.as_deref()),
        )
        .with_context(|| {
            format!(
                "hot-load certs for {} added top-level [[route]] entries",
                added_routes.len()
            )
        })?;
    }

    // 2. Recompute the cert-less set from the new desired routes. We
    //    consult `cert_store` because load_routes_into_store may have
    //    failed to resolve a cert source for one of the added routes,
    //    in which case it's silently demoted to cert-less. Same logic
    //    as `HttpFrontend::spawn` / `spawn_https_frontend`.
    let cert_less_in_new: Vec<String> = desired
        .iter()
        .filter(|r| !cert_store.contains(&r.hostname))
        .map(|r| r.hostname.clone())
        .collect();

    // 3. cert_watcher: unregister removed, register all currently-
    //    cert'd hosts (no-op on already-registered).
    for host in &removed {
        cert_watcher.unregister(host);
    }
    let mut new_loaded_hosts: Vec<String> = Vec::new();
    for r in desired {
        let host = r.hostname.to_ascii_lowercase();
        if cert_less_in_new
            .iter()
            .any(|c| c.eq_ignore_ascii_case(&host))
        {
            continue;
        }
        let paths = cert_store.watched_paths_for(&host);
        cert_watcher.register(&host, &paths);
        new_loaded_hosts.push(host);
    }

    // 4. Drop certs for removed hosts AFTER cert_watcher unregister
    //    (otherwise a watcher event could race with the remove and
    //    fire `reload_host` on a host we've just dropped).
    for host in &removed {
        cert_store.remove(host);
    }

    // 5. Redirect listener: unregister cert'd hosts that left, register
    //    cert'd hosts that arrived. Reset the cert-less plaintext
    //    route table to the new set (full reset is cheap and matches
    //    the spawn path's idempotent register-after-clear pattern).
    let ProxyHandle::Https(https_handle) = &https_active.handle else {
        unreachable!("https_active is HTTPS per the guard above");
    };
    let rl_ip = https_handle.redirect_ip;
    let rl = redirect_listeners
        .get(&rl_ip)
        .context("redirect listener missing for active HTTPS handle's IP")?;
    let old_loaded_hosts: HashSet<String> = https_handle.redirect_hosts.iter().cloned().collect();
    let new_loaded_set: HashSet<String> = new_loaded_hosts.iter().cloned().collect();
    for host in old_loaded_hosts.difference(&new_loaded_set) {
        rl.unregister_host(host);
    }
    for host in new_loaded_set.difference(&old_loaded_hosts) {
        rl.register_host(host);
    }
    rl.unregister_plaintext_routes(HTTPS_FRONTEND_NAME);
    if !cert_less_in_new.is_empty() {
        let cert_less_routes: Vec<HttpRoute> = desired
            .iter()
            .filter(|r| {
                cert_less_in_new
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(&r.hostname))
            })
            .cloned()
            .collect();
        rl.register_plaintext_routes(&cert_less_routes, HTTPS_FRONTEND_NAME);
    }

    // 6. Atomically hot-swap both frontends' route tables. After this
    //    point, the next request on the listener (h1/h2 or h3) sees
    //    the new route set; in-flight requests on routes that
    //    survived continue to completion against the same backend.
    https_handle.frontend.update_routes(desired, cert_store);
    if let Some(h3) = &https_handle.h3 {
        h3.update_routes(desired, cert_store);
    }

    // 7. Bookkeeping.
    let new_cert_less_count = cert_less_in_new.len();
    if let ProxyHandle::Https(h) = &mut https_active.handle {
        h.redirect_hosts = new_loaded_hosts;
    }
    https_active.cert_less_route_count = new_cert_less_count;
    https_active.upstream_description = format!("https:{} routes", desired.len());
    *prev_routes = desired.to_vec();
    tracing::info!(
        added = added.len(),
        removed = removed.len(),
        total = desired.len(),
        cert_less = new_cert_less_count,
        "HTTPS routes hot-swapped in place (no listener disturbance)"
    );
    Ok(())
}

async fn spawn_https_frontend(
    routes: &[HttpRoute],
    cert_config: &CertConfig,
    cert_store: &Arc<CertStore>,
    cert_watcher: &Arc<CertWatcher>,
    redirect_listeners: &mut HashMap<IpAddr, RedirectListener>,
    parent_cancel: &CancellationToken,
) -> Result<ActiveProxy> {
    // 1. Load each route's cert through the three-rung node-wide
    //    resolver. Cert-less hostnames are returned so we can register
    //    them on the per-IP companion's plaintext-routes table.
    let cert_less_hosts = load_routes_into_store(
        HTTPS_FRONTEND_NAME,
        routes,
        cert_store,
        &cert_config.cert_dir,
        cert_config
            .default_cert
            .as_deref()
            .zip(cert_config.default_key.as_deref()),
    )
    .with_context(|| {
        format!(
            "load certs for {} top-level [[route]] entries",
            routes.len()
        )
    })?;

    for host in &cert_less_hosts {
        tracing::warn!(
            route = %host,
            cert = "none",
            "no cert source resolved; route served as plaintext on :80 to lan_cidrs peers only"
        );
    }

    // Register cert'd hostnames with the cert-watcher (no-op for
    // routes whose cert origin has no watched paths).
    let mut loaded_hosts: Vec<String> = Vec::new();
    for r in routes {
        let host_lower = r.hostname.to_ascii_lowercase();
        if cert_less_hosts
            .iter()
            .any(|c| c.eq_ignore_ascii_case(&r.hostname))
        {
            continue;
        }
        loaded_hosts.push(host_lower.clone());
        let paths = cert_store.watched_paths_for(&host_lower);
        cert_watcher.register(&host_lower, &paths);
        metrics::counter!(
            "yggdrasil_https_cert_reload_total",
            "route" => host_lower,
            "result" => "ok",
        )
        .increment(1);
    }

    // 2. Spawn or look up the per-IP companion (:80) listener.
    let listen = cert_config.https_listen;
    let ip = listen.ip();
    if let std::collections::hash_map::Entry::Vacant(e) = redirect_listeners.entry(ip) {
        let port = cert_config.redirect_port.unwrap_or(80);
        let rl = RedirectListener::spawn(ip, port, parent_cancel.clone())
            .await
            .with_context(|| format!("spawn HTTP→HTTPS redirect listener on {ip}:{port}"))?;
        rl.set_lan_cidrs(Some(Arc::clone(&cert_config.lan_cidrs)));
        e.insert(rl);
    }
    let rl = redirect_listeners.get(&ip).expect("just inserted");
    let redirect_hosts: Vec<String> = loaded_hosts.clone();
    for host in &redirect_hosts {
        rl.register_host(host);
    }
    rl.unregister_plaintext_routes(HTTPS_FRONTEND_NAME);
    if !cert_less_hosts.is_empty() {
        let cert_less_routes: Vec<HttpRoute> = routes
            .iter()
            .filter(|r| {
                cert_less_hosts
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(&r.hostname))
            })
            .cloned()
            .collect();
        let collisions = rl.register_plaintext_routes(&cert_less_routes, HTTPS_FRONTEND_NAME);
        for collided in &collisions {
            tracing::warn!(
                route = %collided,
                "cert-less hostname collided with another rule's route on this IP; \
                 most recent wins"
            );
        }
    }

    // 3. Spawn the HTTPS frontend.
    let emit_alt_svc = cert_config.https_http3 && cert_config.https_alt_svc;
    let frontend = HttpFrontend::spawn(
        HTTPS_FRONTEND_NAME.to_string(),
        listen,
        routes,
        Arc::clone(cert_store),
        emit_alt_svc,
        parent_cancel.clone(),
    )
    .await
    .map_err(|e| {
        for host in &redirect_hosts {
            rl.unregister_host(host);
        }
        for host in &loaded_hosts {
            cert_watcher.unregister(host);
            cert_store.remove(host);
        }
        anyhow::anyhow!(e)
    })?;

    // 4. Optionally bring up HTTP/3 alongside.
    let h3 = if cert_config.https_http3 {
        match H3Frontend::spawn(
            HTTPS_FRONTEND_NAME.to_string(),
            listen,
            routes,
            Arc::clone(cert_store),
            cert_config.https_request_body_limit,
        )
        .await
        {
            Ok(q) => Some(q),
            Err(e) => {
                tracing::warn!(error = %e, "failed to bring up HTTP/3 endpoint; serving TCP HTTPS only");
                None
            }
        }
    } else {
        None
    };

    let bound = frontend.local_addr();
    let handle = ProxyHandle::Https(Box::new(HttpsHandle {
        frontend,
        h3,
        redirect_hosts,
        redirect_ip: ip,
        listen: bound,
        name: format!("{HTTPS_FRONTEND_NAME}@{bound}"),
    }));

    Ok(ActiveProxy {
        handle,
        upstream_description: format!("https:{} routes", routes.len()),
        cert_less_route_count: cert_less_hosts.len(),
    })
}

#[allow(clippy::too_many_arguments)]
async fn spawn_proxy_for_rule(
    rule: Rule,
    resolver_factory: &ResolverFactory,
    default_bind: Option<IpAddr>,
    default_workers: Option<usize>,
    cert_config: &CertConfig,
    cert_store: &Arc<CertStore>,
    cert_watcher: &Arc<CertWatcher>,
    redirect_listeners: &mut HashMap<IpAddr, RedirectListener>,
    arm_table: &Arc<CanaryArmTable>,
    parent_cancel: &CancellationToken,
    active: &HashMap<String, ActiveProxy>,
) -> Result<ActiveProxy> {
    let rule = rule.with_bind_override(default_bind);

    let claimed: HashSet<SocketAddr> = collect_claimed_addrs(active);
    if claimed.contains(&rule.listen) {
        anyhow::bail!(
            "rule {:?}: listen address {} is already claimed by another rule",
            rule.name,
            rule.listen,
        );
    }

    match rule.protocol {
        Protocol::Tcp | Protocol::Udp => {
            let resolver: UpstreamResolver = resolver_factory
                .build(&rule)
                .with_context(|| format!("build resolver for rule {:?}", rule.name))?;
            let upstream_description = resolver.describe();
            let workers = resolve_workers(default_workers);
            // Inbound PROXY-protocol consumption is only meaningful on a
            // mid-chain Relay for chain-derived rules: the upstream
            // Gateway / Relay prepended a PROXY-v2 header on every
            // accepted connection, and we use the decoded client when
            // synthesising our own outbound PROXY emission so a 3+ hop
            // chain preserves the real client IP. Gateways see real
            // internet clients (no PROXY). Terminals don't proxy
            // chain-derived rules (their HTTPS frontend handles PROXY
            // directly via `read_optional_header` in the acceptor).
            let expect_inbound_proxy = matches!(resolver_factory.mode, crate::config::Mode::Relay)
                && matches!(rule.proxy_protocol, Some(ProxyProto::V2));
            let handle = match rule.protocol {
                Protocol::Tcp => ProxyHandle::Tcp(
                    TcpProxy::spawn_with_arm_table(
                        rule,
                        resolver,
                        workers,
                        expect_inbound_proxy,
                        Arc::clone(arm_table),
                    )
                    .await?,
                ),
                Protocol::Udp => ProxyHandle::Udp(
                    UdpProxy::spawn_with_arm_table(
                        rule,
                        resolver,
                        MAX_FLOWS_PER_RULE_DEFAULT,
                        workers,
                        expect_inbound_proxy,
                        Arc::clone(arm_table),
                    )
                    .await?,
                ),
                Protocol::Https => unreachable!(),
            };
            Ok(ActiveProxy {
                handle,
                upstream_description,
                cert_less_route_count: 0,
            })
        }
        Protocol::Https => {
            // Unreachable in practice — Rule::validate rejects Https.
            // The node-wide HTTPS frontend is spawned from
            // `reconcile_https` against `RuleSet::routes()` instead.
            let _ = (
                cert_config,
                cert_store,
                cert_watcher,
                redirect_listeners,
                parent_cancel,
            );
            anyhow::bail!(
                "rule {:?}: protocol = \"https\" is no longer valid on `[[rule]]`; \
                 use top-level `[[route]]` blocks",
                rule.name,
            )
        }
    }
}

/// Walk every active L4 proxy and collect the SocketAddrs it claims.
fn collect_claimed_addrs(active: &HashMap<String, ActiveProxy>) -> HashSet<SocketAddr> {
    let mut out = HashSet::new();
    for ap in active.values() {
        let listen = ap.handle.local_addr();
        out.insert(listen);
        if let ProxyHandle::Https(_) = &ap.handle {
            out.insert(SocketAddr::new(listen.ip(), 80));
        }
    }
    out
}

pub(super) fn publish_snapshot(
    active: &HashMap<String, ActiveProxy>,
    https_active: &Option<ActiveProxy>,
    snapshot_tx: &tokio::sync::watch::Sender<Vec<ProxySnapshot>>,
    cert_store: &Arc<CertStore>,
) {
    let mut snaps: Vec<ProxySnapshot> = active
        .values()
        .chain(https_active.iter())
        .map(|ap| ProxySnapshot {
            name: ap.handle.name().to_string(),
            protocol: ap.handle.protocol(),
            listen: ap.handle.local_addr(),
            upstream_description: ap.upstream_description.clone(),
            cert_less_route_count: ap.cert_less_route_count,
        })
        .collect();
    snaps.sort_by(|a, b| a.name.cmp(&b.name));
    metrics::gauge!("yggdrasil_rules_loaded").set(snaps.len() as f64);
    metrics::gauge!("yggdrasil_https_routes").set(cert_store.len() as f64);
    let _ = snapshot_tx.send(snaps);
}
