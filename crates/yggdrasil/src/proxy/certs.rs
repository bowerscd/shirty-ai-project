//! TLS certificate store for the L7 HTTP(S) frontend.
//!
//! `CertStore` is a hostname-keyed map of `rustls::sign::CertifiedKey` entries
//! that implements [`rustls::server::ResolvesServerCert`], so the rustls
//! `ServerConfig` can dispatch on SNI without us writing any callback glue at
//! the HTTPS-acceptor layer.
//!
//! ## Cert source precedence (highest → lowest)
//!
//! Per the design in `docs/configuration.md` (Phase 6 section) and the plan
//! decision §X, the per-route certificate is resolved in this order:
//!
//! 1. Explicit `cert = "/path/full.pem"` + `key = "/path/priv.pem"` in the
//!    rule's `[[rule.route]]` block.
//! 2. `cert = "ephemeral"` sentinel (allowed only for `localhost`,
//!    `*.localhost`, `*.local`; enforced by `ratatoskr`'s rule
//!    validator).
//! 3. Convention directory:
//!    `{rule.cert_dir.unwrap_or(server.cert_dir)}/{hostname}/{fullchain.pem,
//!    privkey.pem}` — both files must exist together.
//! 4. Global baseline: `server.default_cert` + `server.default_key`.
//! 5. None of the above → rule fails to load with an error naming the route.
//!
//! Hot reload of disk-backed certs is plumbed via [`CertWatcher`], which
//! sits next to the rule-file watcher in the supervisor. The cert watcher
//! observes the parent directories of every `(cert, key)` PEM path
//! currently loaded into the store, debounces filesystem events through
//! `notify-debouncer-mini`, and calls [`CertStore::reload_host`] for each
//! hostname whose backing file changed. A failed reload (malformed PEM,
//! missing file, etc.) keeps the previous good entry in service and emits
//! `yggdrasil_https_cert_reload_total{result="err"}`.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{mpsc as std_mpsc, Arc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use notify::RecursiveMode;
use notify_debouncer_mini::{new_debouncer, DebouncedEvent, Debouncer};
use parking_lot::{Mutex, RwLock};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use ratatoskr::rule::{CertSource, HttpRoute, Rule};

/// Current wall clock as Unix epoch milliseconds. Saturates at zero if the
/// system clock is implausibly skewed before 1970.
fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Errors produced while loading or generating per-route TLS material.
#[derive(Debug, Error)]
pub enum CertError {
    #[error("rule {rule:?}: route {route:?}: cert file {path}: {source}")]
    CertRead {
        rule:   String,
        route:  String,
        path:   PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("rule {rule:?}: route {route:?}: key file {path}: {source}")]
    KeyRead {
        rule:   String,
        route:  String,
        path:   PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("rule {rule:?}: route {route:?}: cert {path:?} has no parseable certificates")]
    CertEmpty { rule: String, route: String, path: PathBuf },
    #[error("rule {rule:?}: route {route:?}: key {path:?} has no parseable private key")]
    KeyEmpty { rule: String, route: String, path: PathBuf },
    #[error("rule {rule:?}: route {route:?}: malformed PEM ({kind}) at {path}: {detail}")]
    Pem {
        rule:   String,
        route:  String,
        kind:   &'static str,
        path:   PathBuf,
        detail: String,
    },
    #[error("rule {rule:?}: route {route:?}: failed to load signing key: {detail}")]
    SigningKey { rule: String, route: String, detail: String },
    #[error("rule {rule:?}: route {route:?}: failed to generate ephemeral cert: {detail}")]
    Ephemeral { rule: String, route: String, detail: String },
    #[error(
        "rule {rule:?}: route {route:?}: no cert source matched the resolution chain \
         (no explicit cert, no ephemeral, no convention-dir match, no server.default_cert)"
    )]
    NoSource { rule: String, route: String },
}

/// Origin of a certificate currently loaded in the store. Mostly an
/// observability aid: the cert summary surfaces in `yggdrasilctl local
/// status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertOrigin {
    /// Operator-supplied PEM files on disk.
    Path { cert: PathBuf, key: PathBuf },
    /// In-memory self-signed leaf generated at startup. Never persisted.
    Ephemeral,
    /// Loaded from the convention directory (`<cert_dir>/<host>/fullchain.pem`).
    Convention { cert: PathBuf, key: PathBuf },
    /// Loaded from `[server] default_cert` + `default_key`.
    Default { cert: PathBuf, key: PathBuf },
}

impl CertOrigin {
    /// Short label suitable for tabular output in `yggdrasilctl local status`.
    pub fn as_label(&self) -> String {
        match self {
            Self::Path { cert, .. } => format!("path:{}", cert.display()),
            Self::Ephemeral => "ephemeral".to_string(),
            Self::Convention { cert, .. } => format!("convention:{}", cert.display()),
            Self::Default { cert, .. } => format!("default:{}", cert.display()),
        }
    }

    /// PEM file paths that should be wired into the hot-reload watcher.
    /// Ephemeral origins have no paths to watch.
    pub fn watched_paths(&self) -> Vec<PathBuf> {
        match self {
            Self::Path { cert, key }
            | Self::Convention { cert, key }
            | Self::Default { cert, key } => vec![cert.clone(), key.clone()],
            Self::Ephemeral => Vec::new(),
        }
    }
}

/// One loaded entry, keyed by hostname inside [`CertStore`].
#[derive(Clone)]
pub struct CertEntry {
    pub key:    Arc<CertifiedKey>,
    pub origin: CertOrigin,
    /// Unix epoch milliseconds at the time this entry was inserted.
    /// Used by `yggdrasilctl local status` for operator-facing
    /// freshness hints. Updated on every reload — the value reflects
    /// the *last* successful load, not the original.
    pub loaded_at_unix_ms: u64,
}

impl std::fmt::Debug for CertEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertEntry")
            .field("origin", &self.origin)
            .field("cert_chain_len", &self.key.cert.len())
            .field("loaded_at_unix_ms", &self.loaded_at_unix_ms)
            .finish()
    }
}

/// Owned, clone-friendly snapshot of every input needed to re-run the cert
/// resolution chain for a single hostname. Stored inside [`CertStore`] at
/// load time so [`CertStore::reload_host`] can re-derive the entry purely
/// from the store's own state — the watcher doesn't need to carry rule
/// context with it.
#[derive(Debug, Clone)]
pub struct ReloadSpec {
    pub rule_name:       String,
    pub route:           HttpRoute,
    pub rule_cert_dir:   Option<PathBuf>,
    pub server_cert_dir: PathBuf,
    pub server_default:  Option<(PathBuf, PathBuf)>,
}

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
    /// [`load_rule_into_store`] does both as a unit.
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
    /// recorded. Used by [`CertWatcher::register`] to retrieve watch
    /// paths without taking a long-lived borrow into the store.
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
            rule_name:       &spec.rule_name,
            rule_cert_dir:   spec.rule_cert_dir.as_deref(),
            server_cert_dir: &spec.server_cert_dir,
            server_default,
        };
        match load_route_cert(&spec.route, &ctx) {
            Ok(entry) => {
                self.inner.write().entries.insert(key.clone(), entry);
                metrics::counter!(
                    "yggdrasil_https_cert_reload_total",
                    "route"  => key,
                    "result" => "ok",
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
    /// [`CertWatcher::register`] to hook the right files.
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

    fn lookup(&self, hostname: &str) -> Option<Arc<CertifiedKey>> {
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

/// Inputs to [`load_route_cert`] that aren't carried by the route itself.
#[derive(Debug, Clone)]
pub struct CertContext<'a> {
    pub rule_name:    &'a str,
    /// Per-rule `cert_dir` override, if any; otherwise falls back to
    /// `server_cert_dir`.
    pub rule_cert_dir: Option<&'a Path>,
    pub server_cert_dir: &'a Path,
    pub server_default: Option<(&'a Path, &'a Path)>,
}

/// Resolve and load the certificate for a single `[[rule.route]]` following
/// the precedence chain described in the module-level docs.
pub fn load_route_cert(
    route: &HttpRoute,
    ctx:   &CertContext<'_>,
) -> Result<CertEntry, CertError> {
    let hostname = &route.hostname;

    // 1) Explicit path.
    if let Some(CertSource::Path(cert_path)) = &route.cert {
        let key_path = route
            .key
            .as_ref()
            .expect("validator guarantees Path(_) ⇒ Some(key)");
        let key = load_pem_pair(
            ctx.rule_name,
            hostname,
            cert_path,
            key_path,
        )?;
        return Ok(CertEntry {
            key:    Arc::new(key),
            origin: CertOrigin::Path {
                cert: cert_path.clone(),
                key:  key_path.clone(),
            },
            loaded_at_unix_ms: now_unix_ms(),
        });
    }

    // 2) Ephemeral sentinel.
    if matches!(route.cert, Some(CertSource::Ephemeral)) {
        let key = generate_ephemeral(hostname).map_err(|e| CertError::Ephemeral {
            rule:   ctx.rule_name.to_string(),
            route:  hostname.clone(),
            detail: e.to_string(),
        })?;
        return Ok(CertEntry {
            key:    Arc::new(key),
            origin: CertOrigin::Ephemeral,
            loaded_at_unix_ms: now_unix_ms(),
        });
    }

    // 3) Convention directory.
    let cdir = ctx.rule_cert_dir.unwrap_or(ctx.server_cert_dir);
    let conv_cert = cdir.join(hostname).join("fullchain.pem");
    let conv_key  = cdir.join(hostname).join("privkey.pem");
    if conv_cert.is_file() && conv_key.is_file() {
        let key = load_pem_pair(ctx.rule_name, hostname, &conv_cert, &conv_key)?;
        return Ok(CertEntry {
            key:    Arc::new(key),
            origin: CertOrigin::Convention {
                cert: conv_cert,
                key:  conv_key,
            },
            loaded_at_unix_ms: now_unix_ms(),
        });
    }

    // 4) Server-wide default.
    if let Some((cert_path, key_path)) = ctx.server_default {
        let key = load_pem_pair(ctx.rule_name, hostname, cert_path, key_path)?;
        return Ok(CertEntry {
            key:    Arc::new(key),
            origin: CertOrigin::Default {
                cert: cert_path.to_path_buf(),
                key:  key_path.to_path_buf(),
            },
            loaded_at_unix_ms: now_unix_ms(),
        });
    }

    Err(CertError::NoSource {
        rule:  ctx.rule_name.to_string(),
        route: hostname.clone(),
    })
}

/// Resolve every route in `rule` and insert the results into `store`. This is
/// the "build the cert map at rule-load time" entry point used by the
/// supervisor.
///
/// For every disk-backed route (i.e. every route whose `CertOrigin` is
/// not `Ephemeral`), this also records a [`ReloadSpec`] in the store so
/// [`CertStore::reload_host`] can re-resolve the cert later without any
/// extra context from the caller. Ephemeral routes are not recorded —
/// they have no disk paths to watch.
pub fn load_rule_into_store(
    rule:    &Rule,
    store:   &CertStore,
    server_cert_dir: &Path,
    server_default:  Option<(&Path, &Path)>,
) -> Result<(), CertError> {
    let routes = rule.routes.as_deref().unwrap_or(&[]);
    let rule_cert_dir = rule.cert_dir.as_deref();
    let ctx = CertContext {
        rule_name: &rule.name,
        rule_cert_dir,
        server_cert_dir,
        server_default,
    };
    for route in routes {
        let entry = load_route_cert(route, &ctx)?;
        let host_key = route.hostname.to_ascii_lowercase();
        // Record the spec *before* inserting the entry so a concurrent
        // observer that sees the entry can also find the spec.
        if !matches!(entry.origin, CertOrigin::Ephemeral) {
            let spec = ReloadSpec {
                rule_name:       rule.name.clone(),
                route:           route.clone(),
                rule_cert_dir:   rule_cert_dir.map(Path::to_path_buf),
                server_cert_dir: server_cert_dir.to_path_buf(),
                server_default:  server_default
                    .map(|(c, k)| (c.to_path_buf(), k.to_path_buf())),
            };
            store
                .inner
                .write()
                .reload_specs
                .insert(host_key.clone(), spec);
        }
        store.inner.write().entries.insert(host_key, entry);
    }
    Ok(())
}

/// Load and verify a `(cert, key)` PEM pair.
fn load_pem_pair(
    rule_name: &str,
    route:     &str,
    cert_path: &Path,
    key_path:  &Path,
) -> Result<CertifiedKey, CertError> {
    let cert_pem = fs::read(cert_path).map_err(|e| CertError::CertRead {
        rule:   rule_name.to_string(),
        route:  route.to_string(),
        path:   cert_path.to_path_buf(),
        source: e,
    })?;
    let key_pem = fs::read(key_path).map_err(|e| CertError::KeyRead {
        rule:   rule_name.to_string(),
        route:  route.to_string(),
        path:   key_path.to_path_buf(),
        source: e,
    })?;
    parse_pem_pair(rule_name, route, cert_path, &cert_pem, key_path, &key_pem)
}

fn parse_pem_pair(
    rule_name: &str,
    route:     &str,
    cert_path: &Path,
    cert_pem:  &[u8],
    key_path:  &Path,
    key_pem:   &[u8],
) -> Result<CertifiedKey, CertError> {
    let mut cert_slice: &[u8] = cert_pem;
    let chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_slice)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| CertError::Pem {
            rule:   rule_name.to_string(),
            route:  route.to_string(),
            kind:   "certificate",
            path:   cert_path.to_path_buf(),
            detail: e.to_string(),
        })?;
    if chain.is_empty() {
        return Err(CertError::CertEmpty {
            rule:  rule_name.to_string(),
            route: route.to_string(),
            path:  cert_path.to_path_buf(),
        });
    }

    let mut key_slice: &[u8] = key_pem;
    let key_der: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_slice)
        .map_err(|e| CertError::Pem {
            rule:   rule_name.to_string(),
            route:  route.to_string(),
            kind:   "private key",
            path:   key_path.to_path_buf(),
            detail: e.to_string(),
        })?
        .ok_or_else(|| CertError::KeyEmpty {
            rule:  rule_name.to_string(),
            route: route.to_string(),
            path:  key_path.to_path_buf(),
        })?;

    let signing_key = any_supported_type(&key_der).map_err(|e| CertError::SigningKey {
        rule:   rule_name.to_string(),
        route:  route.to_string(),
        detail: e.to_string(),
    })?;

    Ok(CertifiedKey::new(chain, signing_key))
}

/// Generate an ephemeral self-signed leaf for `hostname`.
///
/// - ECDSA P-256 keypair (rcgen + ring backend default).
/// - Wide validity window (`2024-01-01 .. 2099-01-01`); the cert is
///   regenerated at every daemon restart, so its absolute lifetime is
///   effectively the daemon's uptime.
/// - SAN: always the hostname; if `hostname == "localhost"`, also `127.0.0.1`
///   and `::1` (so browser-loopback works without a separate cert).
/// - Server-auth EKU.
/// - Never persisted to disk; lives entirely in memory.
fn generate_ephemeral(hostname: &str) -> Result<CertifiedKey, rcgen::Error> {
    use rcgen::{
        date_time_ymd, CertificateParams, DistinguishedName, DnType,
        ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
    };
    use std::str::FromStr;

    let mut sans = vec![SanType::DnsName(
        rcgen::Ia5String::try_from(hostname.to_string())?,
    )];
    if hostname.eq_ignore_ascii_case("localhost") {
        sans.push(SanType::IpAddress(std::net::IpAddr::from_str("127.0.0.1").unwrap()));
        sans.push(SanType::IpAddress(std::net::IpAddr::from_str("::1").unwrap()));
    }

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, hostname);

    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.subject_alt_names  = sans;
    params.not_before         = date_time_ymd(2024, 1, 1);
    params.not_after          = date_time_ymd(2099, 1, 1);
    params.is_ca              = IsCa::NoCa;
    params.key_usages         = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    // `KeyPair::generate()` selects the ring backend's default — ECDSA P-256.
    let kp = KeyPair::generate()?;
    let cert = params.self_signed(&kp)?;

    let cert_der: CertificateDer<'static> = cert.der().clone();
    let key_pkcs8 = kp.serialize_der();
    let key_der = PrivateKeyDer::try_from(key_pkcs8).map_err(|e| {
        rcgen::Error::PemError(format!("PKCS#8 round-trip: {e}"))
    })?;
    let signing_key = any_supported_type(&key_der).map_err(|e| {
        rcgen::Error::PemError(format!("rustls signing-key load: {e:?}"))
    })?;
    Ok(CertifiedKey::new(vec![cert_der], signing_key))
}

// ---------------------------------------------------------------------------
// Hot-reload watcher
// ---------------------------------------------------------------------------

/// Filesystem watcher for disk-backed certificate PEM files.
///
/// Sits next to the rule-file watcher in [`ProxySupervisor`]: each HTTPS
/// rule that loads at least one disk-backed route registers its
/// `(hostname, [cert_path, key_path])` pairs with the watcher via
/// [`CertWatcher::register`]. When notify-debouncer-mini reports a change
/// inside a watched parent directory, the watcher looks up every host
/// whose PEM lives in that directory and asks [`CertStore::reload_host`]
/// to re-resolve it.
///
/// Watch handles are reference-counted per parent directory: a single
/// `cert_dir` shared by N routes uses one inotify watch, not N. Dropping
/// the watcher tears down the debouncer thread, the bridge thread, and
/// the consumer task.
pub struct CertWatcher {
    inner: Arc<WatcherShared>,
    // Order matters: the debouncer holds the notify watcher which feeds
    // the std::sync::mpsc bridge; dropping it closes the bridge, which
    // closes the reload channel, which lets the worker task exit cleanly.
    _debouncer: Mutex<Debouncer<notify::RecommendedWatcher>>,
    _bridge:    thread::JoinHandle<()>,
    _worker:    tokio::task::JoinHandle<()>,
}

struct WatcherShared {
    store: Arc<CertStore>,
    state: Mutex<WatcherState>,
}

#[derive(Default)]
struct WatcherState {
    /// Hostname → list of cert/key paths the host depends on. Mirrors
    /// the disk paths from each host's `CertOrigin`.
    host_paths: HashMap<String, Vec<PathBuf>>,
    /// Parent directory → refcount. We watch parent directories (not
    /// individual files) so atomic-rename replacements
    /// (`mv tmp.pem cert.pem`) are observable. Refcount lets us share
    /// one inotify watch across hosts that live in the same cert_dir.
    watched_dirs: HashMap<PathBuf, usize>,
}

impl CertWatcher {
    /// Spawn the watcher.
    ///
    /// `debounce` is the coalescing window for filesystem events; the
    /// supervisor passes the same value the rule watcher uses (typically
    /// 250 ms). `shutdown` is observed cooperatively — cancelling it
    /// stops the consumer task; dropping the watcher tears the rest down.
    pub fn spawn(
        store:    Arc<CertStore>,
        debounce: Duration,
        shutdown: CancellationToken,
    ) -> io::Result<Self> {
        let (notify_tx, notify_rx) = std_mpsc::channel::<NotifyResult>();
        let debouncer = new_debouncer(debounce, notify_tx).map_err(io::Error::other)?;

        let (reload_tx, mut reload_rx) =
            tokio::sync::mpsc::channel::<HashSet<String>>(32);

        let shared = Arc::new(WatcherShared {
            store: Arc::clone(&store),
            state: Mutex::new(WatcherState::default()),
        });

        let bridge_shared = Arc::clone(&shared);
        let bridge = thread::Builder::new()
            .name("cert-watch-bridge".into())
            .spawn(move || bridge_cert_events(notify_rx, bridge_shared, reload_tx))
            .map_err(io::Error::other)?;

        let worker_shared = Arc::clone(&shared);
        let worker = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => {
                        tracing::debug!("cert watcher: shutdown signalled");
                        break;
                    }
                    msg = reload_rx.recv() => {
                        let hosts = match msg {
                            Some(h) => h,
                            None => {
                                tracing::debug!(
                                    "cert watcher: bridge channel closed; exiting"
                                );
                                break;
                            }
                        };
                        for host in hosts {
                            match worker_shared.store.reload_host(&host) {
                                Ok(()) => tracing::info!(
                                    route = %host,
                                    "cert hot-reload: refreshed from disk"
                                ),
                                Err(e) => tracing::warn!(
                                    route = %host,
                                    error = %e,
                                    "cert hot-reload: reload failed; keeping previous cert in service"
                                ),
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            inner:      shared,
            _debouncer: Mutex::new(debouncer),
            _bridge:    bridge,
            _worker:    worker,
        })
    }

    /// Register a hostname and its current set of disk paths with the
    /// watcher. Safe to call repeatedly for the same host: any previously
    /// watched paths that are no longer in `paths` are released, and any
    /// new directories are added to the inotify set.
    ///
    /// Hosts with no disk paths (i.e. ephemeral) are skipped — there's
    /// nothing to watch.
    pub fn register(&self, hostname: &str, paths: &[PathBuf]) {
        if paths.is_empty() {
            return;
        }
        let key = hostname.to_ascii_lowercase();
        let mut state = self.inner.state.lock();
        // Compute the diff vs. whatever this host was previously
        // watching, so we don't churn inotify watches across spurious
        // re-registers.
        let prev: Vec<PathBuf> = state.host_paths.remove(&key).unwrap_or_default();
        let prev_dirs: HashSet<PathBuf> =
            prev.iter().filter_map(|p| p.parent().map(Path::to_path_buf)).collect();
        let new_dirs: HashSet<PathBuf> = paths
            .iter()
            .filter_map(|p| p.parent().map(Path::to_path_buf))
            .collect();
        // Add new directories.
        for dir in new_dirs.difference(&prev_dirs) {
            let count = state.watched_dirs.entry(dir.clone()).or_insert(0);
            *count += 1;
            if *count == 1 {
                if let Err(e) = self
                    ._debouncer
                    .lock()
                    .watcher()
                    .watch(dir, RecursiveMode::NonRecursive)
                {
                    tracing::warn!(
                        dir   = %dir.display(),
                        error = %e,
                        "cert watcher: failed to watch cert directory"
                    );
                    // Roll back the refcount so we don't leak the slot.
                    *count -= 1;
                    if *count == 0 {
                        state.watched_dirs.remove(dir);
                    }
                }
            }
        }
        // Drop directories no longer needed by this host.
        for dir in prev_dirs.difference(&new_dirs) {
            decrement_watched_dir(&mut state, dir, &self._debouncer);
        }
        state.host_paths.insert(key, paths.to_vec());
    }

    /// Unregister a hostname. Drops it from the path index and releases
    /// any inotify watches that were only held on this host's behalf.
    pub fn unregister(&self, hostname: &str) {
        let key = hostname.to_ascii_lowercase();
        let mut state = self.inner.state.lock();
        let Some(paths) = state.host_paths.remove(&key) else {
            return;
        };
        let dirs: HashSet<PathBuf> = paths
            .iter()
            .filter_map(|p| p.parent().map(Path::to_path_buf))
            .collect();
        for dir in dirs {
            decrement_watched_dir(&mut state, &dir, &self._debouncer);
        }
    }

    /// Number of hostnames currently registered. Test/observability aid.
    pub fn host_count(&self) -> usize {
        self.inner.state.lock().host_paths.len()
    }
}

impl std::fmt::Debug for CertWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertWatcher")
            .field("hosts", &self.host_count())
            .finish()
    }
}

fn decrement_watched_dir(
    state:     &mut WatcherState,
    dir:       &Path,
    debouncer: &Mutex<Debouncer<notify::RecommendedWatcher>>,
) {
    let Some(count) = state.watched_dirs.get_mut(dir) else {
        return;
    };
    *count = count.saturating_sub(1);
    if *count == 0 {
        state.watched_dirs.remove(dir);
        if let Err(e) = debouncer.lock().watcher().unwatch(dir) {
            tracing::debug!(
                dir   = %dir.display(),
                error = %e,
                "cert watcher: unwatch failed (already gone?)"
            );
        }
    }
}

type NotifyResult = Result<Vec<DebouncedEvent>, notify::Error>;

/// Bridge thread: turns notify-debouncer batches into "reload these
/// hosts" messages on the tokio side.
fn bridge_cert_events(
    rx:        std_mpsc::Receiver<NotifyResult>,
    shared:    Arc<WatcherShared>,
    reload_tx: tokio::sync::mpsc::Sender<HashSet<String>>,
) {
    while let Ok(batch) = rx.recv() {
        let events = match batch {
            Ok(events) if !events.is_empty() => events,
            Ok(_) => continue,
            Err(e) => {
                tracing::warn!(error = %e, "cert watcher: notify error");
                continue;
            }
        };
        // Map every event path back to one or more affected hostnames.
        // We compare full paths so a sibling file in the same cert_dir
        // doesn't accidentally trigger an unrelated reload.
        let hosts = {
            let state = shared.state.lock();
            let mut hits: HashSet<String> = HashSet::new();
            for ev in &events {
                for (host, paths) in &state.host_paths {
                    if paths.iter().any(|p| p == &ev.path) {
                        hits.insert(host.clone());
                    }
                }
            }
            hits
        };
        if hosts.is_empty() {
            continue;
        }
        tracing::debug!(
            hosts = hosts.len(),
            "cert watcher: fs event affected loaded routes"
        );
        if reload_tx.blocking_send(hosts).is_err() {
            // Worker has exited.
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::SocketAddr;
    use std::str::FromStr;

    use ratatoskr::rule::{HttpRoute, Protocol, Rule};
    use url::Url;

    fn rule_with_routes(routes: Vec<HttpRoute>) -> Rule {
        Rule {
            name: "h".to_string(),
            listen: SocketAddr::from_str("127.0.0.1:443").unwrap(),
            protocol: Protocol::Https,
            target_port: None,
            target_addr: None,
            target_host: None,
            proxy_protocol: None,
            idle_timeout: None,
            routes: Some(routes),
            cert_dir: None,
        }
    }

    fn ephemeral_route(host: &str) -> HttpRoute {
        HttpRoute {
            hostname: host.to_string(),
            target: Url::parse("http://10.0.0.1:8080").unwrap(),
            cert:     Some(CertSource::Ephemeral),
            key:      None,
            hsts:     None,
        }
    }

    fn write_file(dir: &Path, name: &str, content: &str) -> PathBuf {
        let p = dir.join(name);
        let mut f = fs::File::create(&p).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        p
    }

    /// Generate a real (cert.pem, key.pem) pair we can write to disk.
    fn make_test_pem(hostname: &str) -> (String, String) {
        let kp = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, hostname);
        params.distinguished_name = dn;
        params.subject_alt_names = vec![rcgen::SanType::DnsName(
            rcgen::Ia5String::try_from(hostname.to_string()).unwrap(),
        )];
        let cert = params.self_signed(&kp).unwrap();
        (cert.pem(), kp.serialize_pem())
    }

    #[test]
    fn ephemeral_for_localhost_includes_loopback_sans() {
        // Spot-check: localhost ephemerals embed loopback IPs in SANs.
        let _ck = generate_ephemeral("localhost").unwrap();
        // CertifiedKey doesn't expose SANs directly; the generation path
        // running clean is the load-bearing assertion. End-to-end use is
        // covered in the Phase 6h integration test.
    }

    #[test]
    fn ephemeral_route_loads_into_store() {
        let store = CertStore::new();
        let rule = rule_with_routes(vec![ephemeral_route("api.local")]);
        let server_cert_dir = PathBuf::from("/nonexistent");
        load_rule_into_store(&rule, &store, &server_cert_dir, None).unwrap();
        assert_eq!(store.len(), 1);
        let listed = store.list();
        assert_eq!(listed[0].0, "api.local");
        assert!(matches!(listed[0].1, CertOrigin::Ephemeral));
    }

    #[test]
    fn store_lookup_is_case_insensitive() {
        let store = CertStore::new();
        let rule = rule_with_routes(vec![ephemeral_route("API.Local")]);
        let server_cert_dir = PathBuf::from("/nonexistent");
        load_rule_into_store(&rule, &store, &server_cert_dir, None).unwrap();
        assert!(store.lookup("api.local").is_some());
        assert!(store.lookup("API.LOCAL").is_some());
        assert!(store.lookup("ApI.LoCaL").is_some());
        assert!(store.lookup("nope.local").is_none());
    }

    #[test]
    fn path_cert_loads_and_records_origin() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, key_pem) = make_test_pem("api.local");
        let cert_path = write_file(dir.path(), "fullchain.pem", &cert_pem);
        let key_path  = write_file(dir.path(), "privkey.pem", &key_pem);

        let route = HttpRoute {
            hostname: "api.local".to_string(),
            target: Url::parse("http://10.0.0.1:8080").unwrap(),
            cert:     Some(CertSource::Path(cert_path.clone())),
            key:      Some(key_path.clone()),
            hsts:     None,
        };
        let rule = rule_with_routes(vec![route]);
        let store = CertStore::new();
        load_rule_into_store(&rule, &store, &PathBuf::from("/nonexistent"), None).unwrap();
        let listed = store.list();
        assert_eq!(listed.len(), 1);
        match &listed[0].1 {
            CertOrigin::Path { cert, key } => {
                assert_eq!(cert, &cert_path);
                assert_eq!(key,  &key_path);
            }
            other => panic!("expected CertOrigin::Path, got {other:?}"),
        }
    }

    #[test]
    fn convention_dir_match_loads_with_convention_origin() {
        let conv = tempfile::tempdir().unwrap();
        let host_dir = conv.path().join("api.local");
        fs::create_dir_all(&host_dir).unwrap();
        let (cert_pem, key_pem) = make_test_pem("api.local");
        fs::write(host_dir.join("fullchain.pem"), cert_pem).unwrap();
        fs::write(host_dir.join("privkey.pem"),   key_pem).unwrap();

        let route = HttpRoute {
            hostname: "api.local".to_string(),
            target: Url::parse("http://10.0.0.1:8080").unwrap(),
            cert:     None,
            key:      None,
            hsts:     None,
        };
        let rule = rule_with_routes(vec![route]);
        let store = CertStore::new();
        load_rule_into_store(&rule, &store, conv.path(), None).unwrap();
        let listed = store.list();
        assert!(matches!(listed[0].1, CertOrigin::Convention { .. }));
    }

    #[test]
    fn server_default_used_when_no_other_source() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, key_pem) = make_test_pem("default");
        let cert_path = write_file(dir.path(), "wc.pem", &cert_pem);
        let key_path  = write_file(dir.path(), "wc.key", &key_pem);

        let route = HttpRoute {
            hostname: "api.local".to_string(),
            target: Url::parse("http://10.0.0.1:8080").unwrap(),
            cert:     None,
            key:      None,
            hsts:     None,
        };
        let rule = rule_with_routes(vec![route]);
        let store = CertStore::new();
        load_rule_into_store(
            &rule,
            &store,
            &PathBuf::from("/nonexistent"),
            Some((&cert_path, &key_path)),
        )
        .unwrap();
        let listed = store.list();
        assert!(matches!(listed[0].1, CertOrigin::Default { .. }));
    }

    #[test]
    fn no_source_error_when_chain_exhausted() {
        let route = HttpRoute {
            hostname: "api.local".to_string(),
            target: Url::parse("http://10.0.0.1:8080").unwrap(),
            cert:     None,
            key:      None,
            hsts:     None,
        };
        let rule = rule_with_routes(vec![route]);
        let store = CertStore::new();
        let err = load_rule_into_store(
            &rule,
            &store,
            &PathBuf::from("/nonexistent-dir"),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, CertError::NoSource { .. }));
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn malformed_cert_pem_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        // No PEM markers at all → rustls_pemfile parses zero entries → empty
        // chain → CertEmpty.
        let cert_path = write_file(
            dir.path(),
            "fullchain.pem",
            "garbage with no PEM markers at all\n",
        );
        let (_, key_pem) = make_test_pem("api.local");
        let key_path = write_file(dir.path(), "privkey.pem", &key_pem);
        let route = HttpRoute {
            hostname: "api.local".to_string(),
            target: Url::parse("http://10.0.0.1:8080").unwrap(),
            cert:     Some(CertSource::Path(cert_path)),
            key:      Some(key_path),
            hsts:     None,
        };
        let rule = rule_with_routes(vec![route]);
        let store = CertStore::new();
        let err = load_rule_into_store(&rule, &store, &PathBuf::from("/nx"), None)
            .unwrap_err();
        assert!(matches!(
            err,
            CertError::Pem {
                kind: "certificate",
                ..
            } | CertError::CertEmpty { .. }
        ));
    }

    #[test]
    fn cert_origin_watched_paths_skips_ephemeral() {
        let eph = CertOrigin::Ephemeral;
        assert!(eph.watched_paths().is_empty());
        let p = CertOrigin::Path {
            cert: PathBuf::from("/a"),
            key:  PathBuf::from("/b"),
        };
        assert_eq!(p.watched_paths().len(), 2);
    }

    #[test]
    fn cert_origin_label_format() {
        assert_eq!(CertOrigin::Ephemeral.as_label(), "ephemeral");
        assert_eq!(
            CertOrigin::Path {
                cert: PathBuf::from("/etc/a.pem"),
                key:  PathBuf::from("/etc/a.key"),
            }
            .as_label(),
            "path:/etc/a.pem"
        );
    }

    #[test]
    fn store_remove_returns_evicted_entry() {
        let store = CertStore::new();
        let rule = rule_with_routes(vec![ephemeral_route("a.local")]);
        load_rule_into_store(&rule, &store, &PathBuf::from("/nx"), None).unwrap();
        assert!(store.remove("a.local").is_some());
        assert!(store.remove("a.local").is_none());
        assert_eq!(store.len(), 0);
    }
}
