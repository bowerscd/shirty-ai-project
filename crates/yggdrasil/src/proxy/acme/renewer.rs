//! Per-host renewal scheduler.
//!
//! For each `cert = "acme"` route the supervisor passes to
//! [`super::AcmeManager::register`], this module spawns one tokio task
//! that:
//!
//! 1. Looks at any existing cert at `{storage_dir}/{host}/fullchain.pem`.
//!    If present, parses `not_after`. If still healthy, sleeps until
//!    `not_after - renew_before ± jitter`. Otherwise issues immediately.
//! 2. On scheduled fire OR an external `KickRequest` (from
//!    `AcmeManager::force_renew`), drives
//!    [`super::client::AcmeClient::issue`], writes via
//!    [`super::storage::write_atomic`], and tells the cert store to
//!    reload-host so the new bytes go live.
//! 3. Updates the per-host `HostState` snapshot the control surface
//!    reads back from.
//! 4. Schedules the next renewal.

use rand::Rng;

use super::client::AcmeClient;
use super::{storage, AcmeError, AcmeManager, AcmeRouteConfig, HostState, HostStatus, KickRequest};

pub(super) async fn register_host(
    manager: &AcmeManager,
    host: &str,
    route_cfg: &AcmeRouteConfig,
) -> Result<(), AcmeError> {
    // 16-deep kick channel: the queue can absorb a handful of operator
    // `local acme renew` invocations without blocking the control
    // socket, but isn't unbounded.
    let (kick_tx, mut kick_rx) = tokio::sync::mpsc::channel::<KickRequest>(16);
    let state = HostState {
        route_cfg: route_cfg.clone(),
        state: HostStatus::Pending,
        last_error: None,
        next_renewal_unix: None,
        not_after_unix: None,
        kick_tx,
    };
    if !manager.install_host(host, state) {
        // Already registered — keep the existing renewer in charge.
        return Ok(());
    }

    let manager = manager.clone();
    let host_s = host.to_string();
    let route_cfg = route_cfg.clone();
    tokio::spawn(async move {
        if let Err(e) = run_loop(manager, host_s.clone(), route_cfg, &mut kick_rx).await {
            tracing::warn!(
                host = %host_s,
                error = %e,
                "ACME renewer task exited with error",
            );
        }
    });
    Ok(())
}

/// Main renewal loop for one host. Lives for the daemon's lifetime
/// (or until the parent cancel token fires).
async fn run_loop(
    manager: AcmeManager,
    host: String,
    route_cfg: AcmeRouteConfig,
    kick_rx: &mut tokio::sync::mpsc::Receiver<KickRequest>,
) -> Result<(), AcmeError> {
    let cancel = manager.cancel();
    loop {
        // Decide whether to issue now or sleep until the next renewal
        // window.
        let (fullchain, _privkey) = storage::paths(manager.storage_dir(), &host);
        let (sleep_for, observed_not_after) = if fullchain.is_file() {
            match read_not_after(&fullchain) {
                Ok(not_after_secs) => (
                    sleep_until_renewal(
                        not_after_secs,
                        manager.renew_before(),
                        manager.renew_jitter(),
                    ),
                    Some(not_after_secs),
                ),
                Err(e) => {
                    tracing::warn!(
                        host,
                        error = %e,
                        "could not parse existing cert; issuing now",
                    );
                    (None, None)
                }
            }
        } else {
            (None, None)
        };

        // Snapshot the schedule into the host-state map so
        // `local acme list` reflects reality.
        let next_renewal_unix = sleep_for.map(|d| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|n| n.as_secs() + d.as_secs())
                .unwrap_or(0)
        });
        manager.with_host_state(&host, |st| {
            st.next_renewal_unix = next_renewal_unix;
            st.not_after_unix = observed_not_after;
            if observed_not_after.is_some() && st.state == HostStatus::Pending {
                st.state = HostStatus::Active;
            }
        });

        // Sleep until the schedule fires OR we get cancelled OR an
        // operator-kick arrives.
        let mut external_reply: Option<tokio::sync::oneshot::Sender<Result<(), AcmeError>>> = None;
        if let Some(dur) = sleep_for {
            tracing::info!(
                host,
                "ACME renewer: sleeping {:?} until next renewal window",
                dur,
            );
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return Ok(()),
                kick = kick_rx.recv() => {
                    if let Some(req) = kick {
                        external_reply = Some(req.reply);
                    } else {
                        // Channel closed by AcmeManager going away.
                        return Ok(());
                    }
                }
                _ = tokio::time::sleep(dur) => {}
            }
        } else {
            // No scheduled sleep: drain any pending kick non-blockingly
            // so an immediate `force_renew()` after registration is
            // honoured.
            if let Ok(req) = kick_rx.try_recv() {
                external_reply = Some(req.reply);
            }
        }

        // Time to issue. The result is reported both back to any
        // external kick reply AND mirrored into HostState. When the
        // host matches the operator-configured wildcard apex, also
        // include `*.<host>` in the SAN list so the issued cert
        // covers the apex + one level of subdomains.
        let client = AcmeClient::new(&manager);
        let extra_sans: Vec<String> = if manager.config().domain == host {
            vec![format!("*.{host}")]
        } else {
            Vec::new()
        };
        let outcome = client.issue(&host, &extra_sans, &route_cfg).await;
        match &outcome {
            Ok(cert) => {
                if let Err(e) = storage::write_atomic(manager.storage_dir(), &host, cert) {
                    tracing::warn!(
                        host,
                        error = %e,
                        "ACME renewer: atomic write failed after successful issuance",
                    );
                    manager.with_host_state(&host, |st| {
                        st.state = HostStatus::Error;
                        st.last_error = Some(e.to_string());
                    });
                    if let Some(r) = external_reply.take() {
                        let _ = r.send(Err(e));
                    }
                    continue;
                }
                let _ = manager.cert_store().reload_host(&host);
                let (fullchain, _) = storage::paths(manager.storage_dir(), &host);
                let new_not_after = read_not_after(&fullchain).ok();
                manager.with_host_state(&host, |st| {
                    st.state = HostStatus::Active;
                    st.last_error = None;
                    st.not_after_unix = new_not_after;
                });
                if let Some(secs) = new_not_after {
                    metrics::gauge!(
                        "yggdrasil_acme_expiry_seconds",
                        "hostname" => host.clone(),
                    )
                    .set(secs as f64);
                }
                metrics::counter!(
                    "yggdrasil_acme_renew_total",
                    "hostname" => host.clone(),
                    "result" => "ok",
                )
                .increment(1);
                tracing::info!(host, "ACME renewer: issuance complete");
                if let Some(r) = external_reply.take() {
                    let _ = r.send(Ok(()));
                }
            }
            Err(e) => {
                manager.with_host_state(&host, |st| {
                    st.state = HostStatus::Error;
                    st.last_error = Some(e.to_string());
                });
                metrics::counter!(
                    "yggdrasil_acme_renew_total",
                    "hostname" => host.clone(),
                    "result" => "err",
                )
                .increment(1);
                tracing::warn!(
                    host,
                    error = %e,
                    "ACME renewer: issuance failed; will retry after backoff",
                );
                if let Some(r) = external_reply.take() {
                    // Clone the error variant so the channel can take
                    // ownership while we continue the loop.
                    let clone = clone_acme_error(e);
                    let _ = r.send(Err(clone));
                }
                let backoff = std::time::Duration::from_secs(300);
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return Ok(()),
                    _ = tokio::time::sleep(backoff) => {}
                }
            }
        }
    }
}

/// `AcmeError` isn't `Clone`; this helper duplicates the variant for
/// the renewer's "report-back" path without forcing all variants to
/// derive Clone.
fn clone_acme_error(e: &AcmeError) -> AcmeError {
    match e {
        AcmeError::UnknownProvider { host, provider } => AcmeError::UnknownProvider {
            host: host.clone(),
            provider: provider.clone(),
        },
        AcmeError::NoHttp01Responder { host } => {
            AcmeError::NoHttp01Responder { host: host.clone() }
        }
        AcmeError::Dns { host, detail } => AcmeError::Dns {
            host: host.clone(),
            detail: detail.clone(),
        },
        AcmeError::Account { host, detail } => AcmeError::Account {
            host: host.clone(),
            detail: detail.clone(),
        },
        AcmeError::Storage { host, detail } => AcmeError::Storage {
            host: host.clone(),
            detail: detail.clone(),
        },
        AcmeError::Client { host, detail } => AcmeError::Client {
            host: host.clone(),
            detail: detail.clone(),
        },
    }
}

/// Compute `not_after - renew_before ± rand(0..renew_jitter)` as a
/// sleep duration relative to now. Returns `None` if the renewal
/// window has already passed (caller should issue immediately).
fn sleep_until_renewal(
    not_after_unix_secs: u64,
    renew_before: std::time::Duration,
    renew_jitter: std::time::Duration,
) -> Option<std::time::Duration> {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    if not_after_unix_secs <= now_secs {
        return None;
    }
    let lifetime = std::time::Duration::from_secs(not_after_unix_secs - now_secs);
    let renew_target = lifetime.checked_sub(renew_before)?;
    let jitter_secs = if renew_jitter.as_secs() == 0 {
        0
    } else {
        rand::thread_rng().gen_range(0..renew_jitter.as_secs())
    };
    renew_target.checked_sub(std::time::Duration::from_secs(jitter_secs))
}

/// Parse `not_after` (Unix seconds) from a PEM-encoded fullchain on disk.
fn read_not_after(path: &std::path::Path) -> Result<u64, AcmeError> {
    let bytes = std::fs::read(path).map_err(|e| AcmeError::Storage {
        host: "<unknown>".into(),
        detail: format!("read {}: {e}", path.display()),
    })?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&bytes).map_err(|e| AcmeError::Storage {
        host: "<unknown>".into(),
        detail: format!("parse PEM at {}: {e}", path.display()),
    })?;
    let (_, cert) =
        x509_parser::parse_x509_certificate(&pem.contents).map_err(|e| AcmeError::Storage {
            host: "<unknown>".into(),
            detail: format!("parse X.509 at {}: {e}", path.display()),
        })?;
    Ok(cert.validity().not_after.timestamp() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sleep_until_renewal_returns_none_when_already_expired() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let in_the_past = now.saturating_sub(60);
        let res = sleep_until_renewal(
            in_the_past,
            std::time::Duration::from_secs(30 * 86_400),
            std::time::Duration::from_secs(0),
        );
        assert!(res.is_none());
    }

    #[test]
    fn sleep_until_renewal_returns_some_when_far_out() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let dur = sleep_until_renewal(
            now + 90 * 86_400,
            std::time::Duration::from_secs(30 * 86_400),
            std::time::Duration::from_secs(0),
        )
        .expect("should return Some");
        let secs = dur.as_secs();
        assert!(secs > 59 * 86_400, "expected ~60d, got {secs}s");
        assert!(secs <= 60 * 86_400, "expected ~60d, got {secs}s");
    }

    #[test]
    fn sleep_until_renewal_applies_jitter() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let target_secs = now + 90 * 86_400;
        let renew_before = std::time::Duration::from_secs(30 * 86_400);
        let jitter = std::time::Duration::from_secs(3600);
        let mut samples = Vec::with_capacity(8);
        for _ in 0..8 {
            samples.push(
                sleep_until_renewal(target_secs, renew_before, jitter)
                    .unwrap()
                    .as_secs(),
            );
        }
        let min = *samples.iter().min().unwrap();
        let max = *samples.iter().max().unwrap();
        assert!(max - min > 1, "expected jitter spread, got {samples:?}");
    }
}
