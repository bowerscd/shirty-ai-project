//! `CertStore`: hostname-keyed map implementing `rustls::server::ResolvesServerCert`.
//!
//! Split out from the original monolithic `certs.rs` (Phase B5). Holds
//! the runtime cert table plus per-host `ReloadSpec` entries; mutation
//! is serialised through a single `RwLock` so reads (every TLS
//! handshake) and writes (rare hot reloads) cannot tear.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::RwLock;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use super::loader::{load_route_cert, CertContext};
use super::origin::{CertEntry, CertError, CertOrigin, ReloadSpec};

/// Hostname → cert map. Implements [`ResolvesServerCert`] so it plugs
/// straight into a rustls `ServerConfig`. Stored behind an internal
/// `RwLock` to support runtime hot-reload (write under load, read on
/// every TLS handshake).
pub struct CertStore {
    inner: RwLock<CertStoreInner>,
}

/// Internal state guarded by [`CertStore`]'s `RwLock`. Held as a single
/// struct so reads and writes can atomically observe both the live
/// certificate map and the reload-spec table without taking two locks in
/// sequence (which would race against `reload_host`).
#[derive(Default)]
struct CertStoreInner {
    entries: HashMap<String, CertEntry>,
    /// Reload specs for hosts whose certs come from disk (every origin
    /// except [`CertOrigin::Ephemeral`]). Used by
    /// [`CertStore::reload_host`] to re-resolve the cert without any
    /// extra context from the caller. Ephemeral hosts are *not* recorded
    /// here — they have no disk paths to watch.
    reload_specs: HashMap<String, ReloadSpec>,
}

impl CertStore {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(CertStoreInner::default()),
        }
    }

    /// Insert or replace the entry for `hostname`. Hostnames are stored
    /// lowercased so SNI lookup is case-insensitive (per RFC 6066 §3).
    ///
    /// Does *not* touch the host's reload spec — callers that want hot
    /// reload to be possible must also call [`CertStore::record_reload_spec`].
    /// [`super::loader::load_rule_into_store`] does both as a unit.
    pub fn insert(&self, hostname: &str, entry: CertEntry) {
        self.inner
            .write()
            .entries
            .insert(hostname.to_ascii_lowercase(), entry);
    }

    /// Remove the entry for `hostname`, if present. Also drops any
    /// associated reload spec so a subsequent rule re-add starts from a
    /// clean slate.
    pub fn remove(&self, hostname: &str) -> Option<CertEntry> {
        let key = hostname.to_ascii_lowercase();
        let mut g = self.inner.write();
        g.reload_specs.remove(&key);
        g.entries.remove(&key)
    }

    /// Record (or replace) the [`ReloadSpec`] for `hostname`. Ephemeral
    /// hosts must not be recorded — they have no disk paths.
    pub fn record_reload_spec(&self, hostname: &str, spec: ReloadSpec) {
        self.inner
            .write()
            .reload_specs
            .insert(hostname.to_ascii_lowercase(), spec);
    }

    /// Return a copy of the reload spec for `hostname`, if one is
    /// recorded. Used by [`super::watcher::CertWatcher::register`] to
    /// retrieve watch paths without taking a long-lived borrow into the
    /// store.
    pub fn reload_spec(&self, hostname: &str) -> Option<ReloadSpec> {
        self.inner
            .read()
            .reload_specs
            .get(&hostname.to_ascii_lowercase())
            .cloned()
    }

    /// Re-resolve `hostname` using its recorded [`ReloadSpec`]. On
    /// success the entry is replaced atomically and the success metric
    /// is emitted. On failure the old entry is kept in service and the
    /// failure metric is emitted; the error is returned to the caller
    /// for logging.
    ///
    /// Returns `Ok(())` and skips the metric if no spec is recorded
    /// (e.g. the host was concurrently removed by a rule reload): there
    /// is nothing to reload and the absence is not an error.
    pub fn reload_host(&self, hostname: &str) -> Result<(), CertError> {
        let key = hostname.to_ascii_lowercase();
        let spec = match self.inner.read().reload_specs.get(&key).cloned() {
            Some(s) => s,
            None => return Ok(()),
        };
        let server_default = spec
            .server_default
            .as_ref()
            .map(|(c, k)| (c.as_path(), k.as_path()));
        let ctx = CertContext {
            rule_name: &spec.rule_name,
            rule_cert_dir: spec.rule_cert_dir.as_deref(),
            server_cert_dir: &spec.server_cert_dir,
            server_default,
        };
        match load_route_cert(&spec.route, &ctx) {
            Ok(Some(entry)) => {
                self.inner.write().entries.insert(key.clone(), entry);
                metrics::counter!(
                    "yggdrasil_https_cert_reload_total",
                    "route"  => key,
                    "result" => "ok",
                )
                .increment(1);
                Ok(())
            }
            Ok(None) => {
                // Reload spec exists for this hostname, but the cert source
                // no longer resolves — the route has effectively become
                // cert-less. Remove it from the store; the supervisor's
                // next reload cycle will pick up the new shape and route
                // the hostname onto the companion listener instead.
                self.inner.write().entries.remove(&key);
                metrics::counter!(
                    "yggdrasil_https_cert_reload_total",
                    "route"  => key,
                    "result" => "cert_less",
                )
                .increment(1);
                Ok(())
            }
            Err(e) => {
                metrics::counter!(
                    "yggdrasil_https_cert_reload_total",
                    "route"  => key,
                    "result" => "err",
                )
                .increment(1);
                Err(e)
            }
        }
    }

    /// Snapshot every loaded `(hostname, origin)` pair for inspection.
    pub fn list(&self) -> Vec<(String, CertOrigin)> {
        let g = self.inner.read();
        let mut out: Vec<_> = g
            .entries
            .iter()
            .map(|(h, e)| (h.clone(), e.origin.clone()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Disk paths backing `hostname`, derived from its `CertOrigin`.
    /// Returns an empty vec when the host is unknown or its origin is
    /// `Ephemeral` (nothing on disk to watch). Used by
    /// [`super::watcher::CertWatcher::register`] to hook the right files.
    pub fn watched_paths_for(&self, hostname: &str) -> Vec<PathBuf> {
        self.inner
            .read()
            .entries
            .get(&hostname.to_ascii_lowercase())
            .map(|e| e.origin.watched_paths())
            .unwrap_or_default()
    }

    /// Snapshot every loaded entry's full operator-relevant metadata:
    /// `(hostname, origin, loaded_at_unix_ms)`. Used by the
    /// control-plane `Request::Status` handler to render the cert
    /// summary in `yggdrasilctl local status`.
    pub fn list_full(&self) -> Vec<(String, CertOrigin, u64)> {
        let g = self.inner.read();
        let mut out: Vec<_> = g
            .entries
            .iter()
            .map(|(h, e)| (h.clone(), e.origin.clone(), e.loaded_at_unix_ms))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Number of loaded hostnames.
    pub fn len(&self) -> usize {
        self.inner.read().entries.len()
    }

    /// True if no hostnames are loaded.
    pub fn is_empty(&self) -> bool {
        self.inner.read().entries.is_empty()
    }

    /// True if a cert for `hostname` is loaded. Used by the HTTPS
    /// frontend to filter cert-less routes out of the `:443` SNI
    /// table — a route whose hostname is not in the store will not be
    /// bound on TLS.
    pub fn contains(&self, hostname: &str) -> bool {
        self.inner
            .read()
            .entries
            .contains_key(&hostname.to_ascii_lowercase())
    }

    /// SNI lookup helper. `pub(super)` so the cert-module tests can call
    /// it; external callers go through [`ResolvesServerCert::resolve`].
    pub(super) fn lookup(&self, hostname: &str) -> Option<Arc<CertifiedKey>> {
        self.inner
            .read()
            .entries
            .get(&hostname.to_ascii_lowercase())
            .map(|e| Arc::clone(&e.key))
    }
}

impl Default for CertStore {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for CertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertStore")
            .field("entries", &self.len())
            .finish()
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // No SNI → rustls already rejected the handshake at TLS 1.3 if there's
        // a SNI extension policy; otherwise `server_name()` is None and we
        // return None (handshake fails with unrecognized_name).
        let sni = client_hello.server_name()?;
        self.lookup(sni)
    }
}
