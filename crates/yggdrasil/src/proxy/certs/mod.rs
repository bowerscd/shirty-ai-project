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
//!
//! ## Module layout (Phase B5 split)
//!
//! - [`origin`] — `CertError`, `CertOrigin`, `CertEntry`, `ReloadSpec`.
//! - [`store`] — `CertStore` and its `RwLock`-guarded inner state.
//! - [`loader`] — `load_route_cert`, `load_rule_into_store`, PEM parsing,
//!   ephemeral leaf generation, `CertContext`.
//! - [`watcher`] — `CertWatcher`, debouncer integration, reload task.

pub mod loader;
pub mod origin;
pub mod store;
pub mod watcher;

pub use loader::{load_route_cert, load_rule_into_store, CertContext};
pub use origin::{CertEntry, CertError, CertOrigin, ReloadSpec};
pub use store::CertStore;
pub use watcher::CertWatcher;
