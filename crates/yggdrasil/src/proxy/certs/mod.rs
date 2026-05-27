//! TLS certificate store for the L7 HTTP(S) frontend.
//!
//! `CertStore` is a hostname-keyed map of `rustls::sign::CertifiedKey` entries
//! that implements [`rustls::server::ResolvesServerCert`], so the rustls
//! `ServerConfig` can dispatch on SNI without us writing any callback glue at
//! the HTTPS-acceptor layer.
//!
//! ## Cert source precedence (highest → lowest)
//!
//! Cert resolution is node-wide; routes carry no cert source of their own.
//! Per hostname:
//!
//! 1. Convention directory:
//!    `{server.cert_dir}/{hostname}/{fullchain.pem, privkey.pem}` — both
//!    files must exist together.
//! 2. Global baseline: `server.default_cert` + `server.default_key`.
//! 3. None of the above → cert-less route, served as plain HTTP on `:80`
//!    to peers in `[server].lan_cidrs`.
//!
//! Hot reload of disk-backed certs is plumbed via [`CertWatcher`], which
//! sits next to the rule-file watcher in the supervisor. The cert watcher
//! observes the parent directories of every `(cert, key)` PEM path
//! currently loaded into the store, debounces filesystem events through
//! `notify-debouncer-mini`, and calls [`CertStore::reload_host`] for each
//! hostname whose backing file changed. A failed reload (malformed PEM,
//! missing file, etc.) keeps the previous good entry in service and emits
//! `yggdrasil_https_cert_reload_total{result="err"}`.
//!
//! ## Module layout (Phase B5 split)
//!
//! - [`origin`] — `CertError`, `CertOrigin`, `CertEntry`, `ReloadSpec`.
//! - [`store`] — `CertStore` and its `RwLock`-guarded inner state.
//! - [`loader`] — `load_route_cert`, `load_routes_into_store`, PEM parsing,
//!   `CertContext`.
//! - [`watcher`] — `CertWatcher`, debouncer integration, reload task.

pub mod loader;
pub mod origin;
pub mod store;
pub mod watcher;

pub use loader::{load_route_cert, load_routes_into_store, CertContext};
pub use origin::{CertEntry, CertError, CertOrigin, ReloadSpec};
pub use store::CertStore;
pub use watcher::CertWatcher;
