//! Reconcile loop: turn rule-set updates into start/stop/swap actions
//! against the active proxy table.
//!
//! Split out from the original monolithic `supervisor.rs` (Phase B3).
//! All entry points are `pub(super)` — only [`super::ProxySupervisor`]
//! drives this code.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use ratatoskr::rule::{Protocol, Rule, RuleSet};

use crate::proxy::certs::{load_rule_into_store, CertStore, CertWatcher};
use crate::proxy::h3_frontend::H3Frontend;
use crate::proxy::http_frontend::{HttpFrontend, RedirectListener};
use crate::proxy::resolver::{ResolverFactory, UpstreamResolver};
use crate::proxy::tcp::TcpProxy;
use crate::proxy::udp::{resolve_workers, UdpProxy, MAX_FLOWS_PER_RULE_DEFAULT};
use crate::rules::{RuleUpdate, RuleWatcher};

use super::cert_config::CertConfig;
use super::handle::{ActiveProxy, HttpsHandle, ProxyHandle};
use super::ProxySnapshot;

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
    cancel: CancellationToken,
    snapshot_tx: tokio::sync::watch::Sender<Vec<ProxySnapshot>>,
) {
    let mut active: HashMap<String, ActiveProxy> = HashMap::new();
    let mut redirect_listeners: HashMap<IpAddr, RedirectListener> = HashMap::new();
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
                        // Watcher emits {set, diff}, but we ignore the diff
                        // and recompute against `current_set` so external
                        // pushes between file events are honoured.
                        let RuleUpdate { set, diff: _ } = u;
                        // Notify systemd that a `Type=notify-reload` reload
                        // cycle is in progress. No-op when not running
                        // under systemd. Skips the very first apply (when
                        // `current_set` is still default-empty AND the
                        // incoming set is empty too) so the initial
                        // startup notification flow isn't conflated with
                        // a reload.
                        let is_startup_empty = current_set.rules().is_empty()
                            && set.rules().is_empty();
                        if !is_startup_empty {
                            crate::systemd::notify_reloading();
                        }
                        apply_set(
                            &mut active,
                            &mut redirect_listeners,
                            &mut current_set,
                            set,
                            "file_watcher",
                            &resolver_factory,
                            default_bind,
                            default_workers,
                            &cert_config,
                            &cert_store,
                            &cert_watcher,
                            &cancel,
                        )
                        .await;
                        let _ = current_set_tx.send(current_set.clone());
                        publish_snapshot(&active, &snapshot_tx, &cert_store);
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
                match ext {
                    Some(set) => {
                        crate::systemd::notify_reloading();
                        apply_set(
                            &mut active,
                            &mut redirect_listeners,
                            &mut current_set,
                            set,
                            "external_push",
                            &resolver_factory,
                            default_bind,
                            default_workers,
                            &cert_config,
                            &cert_store,
                            &cert_watcher,
                            &cancel,
                        )
                        .await;
                        let _ = current_set_tx.send(current_set.clone());
                        publish_snapshot(&active, &snapshot_tx, &cert_store);
                        crate::systemd::notify_ready_after_reload();
                    }
                    None => {
                        // All SupervisorHandle clones dropped. Not an exit
                        // condition by itself — we keep serving the file
                        // watcher — but we won't get any further external
                        // pushes. Continue without `ext` ever firing again.
                    }
                }
            }
        }
    }

    // Shutdown: stop every active proxy concurrently. Drain the snapshot
    // last so observers see the empty set on the way out.
    let active_drained: Vec<ActiveProxy> = active.drain().map(|(_, p)| p).collect();
    let stops = active_drained.into_iter().map(|p| p.handle.stop());
    futures::future::join_all(stops).await;
    // Tear down any leftover redirect listeners.
    let redirect_drained: Vec<RedirectListener> =
        redirect_listeners.drain().map(|(_, l)| l).collect();
    let red_stops = redirect_drained.into_iter().map(|l| l.stop());
    futures::future::join_all(red_stops).await;
    publish_snapshot(&active, &snapshot_tx, &cert_store);
    tracing::info!("supervisor shut down");
}

#[allow(clippy::too_many_arguments)]
async fn apply_set(
    active: &mut HashMap<String, ActiveProxy>,
    redirect_listeners: &mut HashMap<IpAddr, RedirectListener>,
    current_set: &mut RuleSet,
    new_set: RuleSet,
    source: &'static str,
    resolver_factory: &ResolverFactory,
    default_bind: Option<IpAddr>,
    default_workers: Option<usize>,
    cert_config: &CertConfig,
    cert_store: &Arc<CertStore>,
    cert_watcher: &Arc<CertWatcher>,
    parent_cancel: &CancellationToken,
) {
    // Compute the diff against the supervisor-owned current state, not
    // whatever the input source thinks the previous state was. This is
    // what lets file-watch and chain-push coexist on a single supervisor.
    let diff = current_set.diff(&new_set);
    tracing::debug!(
        source = source,
        added = diff.added.len(),
        changed = diff.changed.len(),
        removed = diff.removed.len(),
        unchanged = diff.unchanged.len(),
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
        parent_cancel,
    )
    .await;
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
    parent_cancel: &CancellationToken,
) {
    let RuleUpdate { set, diff } = update;

    // 1. Remove proxies for removed rules. Includes unregistering their
    //    cert routes from the shared store and unhooking from the per-IP
    //    redirect listener.
    for removed in &diff.removed {
        if let Some(ap) = active.remove(&removed.name) {
            tracing::info!(
                rule = %removed.name,
                listen = %ap.handle.local_addr(),
                "stopping removed rule"
            );
            // Unregister redirect-listener hosts before stop (idempotent).
            if let ProxyHandle::Https(h) = &ap.handle {
                if let Some(rl) = redirect_listeners.get(&h.redirect_ip) {
                    for host in &h.redirect_hosts {
                        rl.unregister_host(host);
                    }
                }
            }
            // Unregister this rule's routes from the cert store and the
            // cert watcher's path index.
            unload_rule_from_cert_store(cert_store, cert_watcher, removed);
            ap.handle.stop().await;
        }
    }

    // 2. Swap proxies for changed rules. Stop-then-spawn (not the reverse)
    //    because both bind the same listen address — they can't coexist.
    for change in &diff.changed {
        if let Some(old) = active.remove(&change.old.name) {
            tracing::info!(
                rule = %change.old.name,
                old_listen = %old.handle.local_addr(),
                new_listen = %change.new.listen,
                "swapping changed rule"
            );
            if let ProxyHandle::Https(h) = &old.handle {
                if let Some(rl) = redirect_listeners.get(&h.redirect_ip) {
                    for host in &h.redirect_hosts {
                        rl.unregister_host(host);
                    }
                }
            }
            unload_rule_from_cert_store(cert_store, cert_watcher, &change.old);
            old.handle.stop().await;
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

    // 4. Garbage-collect any redirect listeners whose host set is now empty
    //    (i.e. the last HTTPS rule referring to that IP went away).
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

    // 5. Unchanged rules: do nothing. (Their listeners and any in-flight
    //    flows are preserved.) The trace below is for observability only;
    //    it does not mutate state.
    if !diff.unchanged.is_empty() {
        tracing::trace!(
            unchanged = diff.unchanged.len(),
            "unchanged rules left undisturbed"
        );
    }
    let _ = set; // currently only the diff is needed
}

fn unload_rule_from_cert_store(
    cert_store: &Arc<CertStore>,
    cert_watcher: &Arc<CertWatcher>,
    rule: &Rule,
) {
    if rule.protocol != Protocol::Https {
        return;
    }
    if let Some(routes) = rule.routes.as_ref() {
        for r in routes {
            cert_watcher.unregister(&r.hostname);
            cert_store.remove(&r.hostname);
        }
    }
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
    parent_cancel: &CancellationToken,
    active: &HashMap<String, ActiveProxy>,
) -> Result<ActiveProxy> {
    // Apply server-wide default_bind override before any uniqueness or
    // listener-binding work. The rule itself is left untouched in the
    // RuleSet (so reload diffs work) — we only clone-and-override here.
    let rule = rule.with_bind_override(default_bind);

    // Listen-exclusivity: a single SocketAddr cannot be claimed twice. The
    // OS would reject the second bind anyway, but checking here gives a
    // clearer error and is essential for the implicit `:80` claim made by
    // HTTPS rules.
    let claimed: HashSet<SocketAddr> = collect_claimed_addrs(active);
    if claimed.contains(&rule.listen) {
        anyhow::bail!(
            "rule {:?}: listen address {} is already claimed by another rule",
            rule.name,
            rule.listen,
        );
    }

    // HTTPS rules also implicitly claim `(listen.ip(), 80)` for the
    // redirect listener. Two HTTPS rules on the same IP share the
    // listener (refcounted), so the conflict is only with non-HTTPS rules
    // claiming :80.
    if rule.protocol == Protocol::Https {
        let implicit_80 = SocketAddr::new(rule.listen.ip(), 80);
        if claimed.contains(&implicit_80) {
            anyhow::bail!(
                "rule {:?}: implicit HTTP→HTTPS redirect on {} clashes with \
                 another rule already listening there",
                rule.name,
                implicit_80,
            );
        }
    }

    match rule.protocol {
        Protocol::Tcp | Protocol::Udp => {
            let resolver: UpstreamResolver = resolver_factory
                .build(&rule)
                .with_context(|| format!("build resolver for rule {:?}", rule.name))?;
            let upstream_description = resolver.describe();
            let workers = resolve_workers(default_workers);
            let handle = match rule.protocol {
                Protocol::Tcp => ProxyHandle::Tcp(TcpProxy::spawn(rule, resolver, workers).await?),
                Protocol::Udp => ProxyHandle::Udp(
                    UdpProxy::spawn_with(rule, resolver, MAX_FLOWS_PER_RULE_DEFAULT, workers)
                        .await?,
                ),
                Protocol::Https => unreachable!(),
            };
            Ok(ActiveProxy {
                handle,
                upstream_description,
            })
        }
        Protocol::Https => {
            spawn_https_rule(
                rule,
                cert_config,
                cert_store,
                cert_watcher,
                redirect_listeners,
                parent_cancel,
            )
            .await
        }
    }
}

/// Walk every active proxy and collect the SocketAddrs it claims. For
/// HTTPS rules this includes the implicit `(ip, 80)` redirect claim.
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

async fn spawn_https_rule(
    rule: Rule,
    cert_config: &CertConfig,
    cert_store: &Arc<CertStore>,
    cert_watcher: &Arc<CertWatcher>,
    redirect_listeners: &mut HashMap<IpAddr, RedirectListener>,
    parent_cancel: &CancellationToken,
) -> Result<ActiveProxy> {
    // 1. Load each route's certificate into the shared store. If any route
    //    fails we abort the whole rule and roll back what we loaded so the
    //    store doesn't get a half-applied rule.
    let routes = rule
        .routes
        .as_ref()
        .filter(|r| !r.is_empty())
        .with_context(|| {
            format!(
                "HTTPS rule {:?}: routes list is empty; validator should have rejected this",
                rule.name,
            )
        })?;

    let mut loaded_hosts: Vec<String> = Vec::with_capacity(routes.len());
    let load_result = load_rule_into_store(
        &rule,
        cert_store,
        &cert_config.cert_dir,
        cert_config
            .default_cert
            .as_deref()
            .zip(cert_config.default_key.as_deref()),
    );
    if let Err(e) = load_result {
        // Roll back any entries we did manage to set (load_rule_into_store
        // is best-effort but may have inserted some before failing).
        for host in routes.iter().map(|r| r.hostname.clone()) {
            cert_store.remove(&host);
        }
        // Emit per-route reload-failed counters. We can't know exactly which
        // route hit the error, so we count the rule itself as failing on its
        // first route — this is good enough as an alert signal.
        if let Some(first) = routes.first() {
            metrics::counter!(
                "yggdrasil_https_cert_reload_total",
                "route" => first.hostname.to_ascii_lowercase(),
                "result" => "err",
            )
            .increment(1);
        }
        return Err(e).with_context(|| format!("load certs for HTTPS rule {:?}", rule.name));
    }
    for r in routes {
        let host_lower = r.hostname.to_ascii_lowercase();
        loaded_hosts.push(host_lower.clone());
        // Register the route's disk paths with the cert watcher (a no-op
        // for ephemeral routes, since their `watched_paths()` is empty).
        let paths = cert_store.watched_paths_for(&host_lower);
        cert_watcher.register(&host_lower, &paths);
        metrics::counter!(
            "yggdrasil_https_cert_reload_total",
            "route" => host_lower,
            "result" => "ok",
        )
        .increment(1);
    }

    // 2. Spawn (or look up) the per-IP redirect listener. Attach the
    //    AcmeManager's HTTP-01 responder on first spawn so
    //    `/.well-known/acme-challenge/<token>` requests get answered
    //    in-band instead of being 301'd to HTTPS.
    let ip = rule.listen.ip();
    if let std::collections::hash_map::Entry::Vacant(e) = redirect_listeners.entry(ip) {
        let port = cert_config.redirect_port.unwrap_or(80);
        let rl = RedirectListener::spawn(ip, port, parent_cancel.clone())
            .await
            .with_context(|| format!("spawn HTTP→HTTPS redirect listener on {ip}:{port}"))?;
        if let Some(acme) = cert_config.acme.as_ref() {
            rl.set_acme_responder(acme.responder());
        }
        e.insert(rl);
    }
    let rl = redirect_listeners.get(&ip).expect("just inserted");
    let redirect_hosts: Vec<String> = loaded_hosts.clone();
    for host in &redirect_hosts {
        rl.register_host(host);
    }

    // 2b. Register every `cert = "acme"` route with the AcmeManager so
    //     the renewer can kick off issuance (and schedule subsequent
    //     renewals) in the background. The renewer races against the
    //     ephemeral stand-in served via `CertOrigin::AcmePending`.
    if let Some(acme_mgr) = cert_config.acme.as_ref() {
        for r in routes {
            if matches!(r.cert, Some(ratatoskr::rule::CertSource::Acme(_))) {
                let route_cfg = match &r.cert {
                    Some(ratatoskr::rule::CertSource::Acme(c)) => c,
                    _ => unreachable!("matched above"),
                };
                if let Err(e) = acme_mgr.register(&r.hostname, route_cfg).await {
                    tracing::warn!(
                        rule = %rule.name,
                        host = %r.hostname,
                        error = %e,
                        "ACME registration failed; serving ephemeral \
                         stand-in until issuance succeeds",
                    );
                }
            }
        }
    }

    // 3. Spawn the HTTPS frontend.
    let frontend_res =
        HttpFrontend::spawn(&rule, Arc::clone(cert_store), parent_cancel.clone()).await;
    let frontend = match frontend_res {
        Ok(f) => f,
        Err(e) => {
            // Roll back redirect registration + cert watcher + cert store entries.
            if let Some(rl) = redirect_listeners.get(&ip) {
                for host in &redirect_hosts {
                    rl.unregister_host(host);
                }
            }
            for host in &loaded_hosts {
                cert_watcher.unregister(host);
                cert_store.remove(host);
            }
            return Err(e)
                .with_context(|| format!("spawn HTTPS frontend for rule {:?}", rule.name));
        }
    };

    // 4. Optionally spawn the HTTP/3 endpoint alongside.
    let h3 = if rule.http3 != Some(false) {
        match H3Frontend::spawn(rule.clone(), Arc::clone(cert_store)).await {
            Ok(q) => Some(q),
            Err(e) => {
                tracing::warn!(
                    rule = %rule.name,
                    error = %e,
                    "failed to bring up HTTP/3 endpoint; serving TCP HTTPS only"
                );
                None
            }
        }
    } else {
        None
    };

    let listen = frontend.local_addr();
    let handle = ProxyHandle::Https(Box::new(HttpsHandle {
        frontend,
        h3,
        redirect_hosts,
        redirect_ip: ip,
        listen,
        rule: rule.clone(),
    }));

    Ok(ActiveProxy {
        handle,
        upstream_description: format!("https:{} routes", routes.len()),
    })
}

pub(super) fn publish_snapshot(
    active: &HashMap<String, ActiveProxy>,
    snapshot_tx: &tokio::sync::watch::Sender<Vec<ProxySnapshot>>,
    cert_store: &Arc<CertStore>,
) {
    let mut snaps: Vec<ProxySnapshot> = active
        .values()
        .map(|ap| ProxySnapshot {
            name: ap.handle.rule().name.clone(),
            protocol: ap.handle.rule().protocol,
            listen: ap.handle.local_addr(),
            upstream_description: ap.upstream_description.clone(),
        })
        .collect();
    snaps.sort_by(|a, b| a.name.cmp(&b.name));
    metrics::gauge!("yggdrasil_rules_loaded").set(snaps.len() as f64);
    metrics::gauge!("yggdrasil_https_routes").set(cert_store.len() as f64);
    let _ = snapshot_tx.send(snaps);
}
