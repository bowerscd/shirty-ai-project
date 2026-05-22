//! Cert-store data types: errors, origin labels, loaded-entry struct,
//! reload-spec snapshot.
//!
//! Split out from the original monolithic `certs.rs` (Phase B5). No
//! behavioural change — the types and their impls move verbatim.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use rustls::sign::CertifiedKey;
use thiserror::Error;

use ratatoskr::rule::HttpRoute;

/// Errors produced while loading or generating per-route TLS material.
#[derive(Debug, Error)]
pub enum CertError {
    #[error("rule {rule:?}: route {route:?}: cert file {path}: {source}")]
    CertRead {
        rule: String,
        route: String,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("rule {rule:?}: route {route:?}: key file {path}: {source}")]
    KeyRead {
        rule: String,
        route: String,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("rule {rule:?}: route {route:?}: cert {path:?} has no parseable certificates")]
    CertEmpty {
        rule: String,
        route: String,
        path: PathBuf,
    },
    #[error("rule {rule:?}: route {route:?}: key {path:?} has no parseable private key")]
    KeyEmpty {
        rule: String,
        route: String,
        path: PathBuf,
    },
    #[error("rule {rule:?}: route {route:?}: malformed PEM ({kind}) at {path}: {detail}")]
    Pem {
        rule: String,
        route: String,
        kind: &'static str,
        path: PathBuf,
        detail: String,
    },
    #[error("rule {rule:?}: route {route:?}: failed to load signing key: {detail}")]
    SigningKey {
        rule: String,
        route: String,
        detail: String,
    },
    #[error("rule {rule:?}: route {route:?}: failed to generate ephemeral cert: {detail}")]
    Ephemeral {
        rule: String,
        route: String,
        detail: String,
    },
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
    /// ACME-issued and -managed: PEM files live at the convention path
    /// but their lifecycle (issue, renew, atomic replace) is owned by
    /// the daemon's `AcmeManager`.
    Acme { cert: PathBuf, key: PathBuf },
    /// ACME route whose first issuance hasn't completed yet. The cert
    /// served is the same in-memory ephemeral as the `Ephemeral`
    /// variant, but its presence is a signal to the operator and the
    /// renewer that a real cert is pending at the recorded paths.
    AcmePending { cert: PathBuf, key: PathBuf },
}

impl CertOrigin {
    /// Short label suitable for tabular output in `yggdrasilctl local status`.
    pub fn as_label(&self) -> String {
        match self {
            Self::Path { cert, .. } => format!("path:{}", cert.display()),
            Self::Ephemeral => "ephemeral".to_string(),
            Self::Convention { cert, .. } => format!("convention:{}", cert.display()),
            Self::Default { cert, .. } => format!("default:{}", cert.display()),
            Self::Acme { cert, .. } => format!("acme:{}", cert.display()),
            Self::AcmePending { cert, .. } => format!("acme-pending:{}", cert.display()),
        }
    }

    /// PEM file paths that should be wired into the hot-reload watcher.
    /// `Ephemeral` and `AcmePending` have no on-disk paths (yet); the
    /// pending variant relies on the AcmeManager driving an explicit
    /// `reload_host` once it writes the first issuance.
    pub fn watched_paths(&self) -> Vec<PathBuf> {
        match self {
            Self::Path { cert, key }
            | Self::Convention { cert, key }
            | Self::Default { cert, key }
            | Self::Acme { cert, key } => vec![cert.clone(), key.clone()],
            Self::Ephemeral | Self::AcmePending { .. } => Vec::new(),
        }
    }
}

/// One loaded entry, keyed by hostname inside `CertStore`.
#[derive(Clone)]
pub struct CertEntry {
    pub key: Arc<CertifiedKey>,
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
/// resolution chain for a single hostname. Stored inside `CertStore` at
/// load time so `CertStore::reload_host` can re-derive the entry purely
/// from the store's own state — the watcher doesn't need to carry rule
/// context with it.
#[derive(Debug, Clone)]
pub struct ReloadSpec {
    pub rule_name: String,
    pub route: HttpRoute,
    pub rule_cert_dir: Option<PathBuf>,
    pub server_cert_dir: PathBuf,
    pub server_default: Option<(PathBuf, PathBuf)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_origin_watched_paths_skips_ephemeral() {
        let eph = CertOrigin::Ephemeral;
        assert!(eph.watched_paths().is_empty());
        let p = CertOrigin::Path {
            cert: PathBuf::from("/a"),
            key: PathBuf::from("/b"),
        };
        assert_eq!(p.watched_paths().len(), 2);
    }

    #[test]
    fn cert_origin_label_format() {
        assert_eq!(CertOrigin::Ephemeral.as_label(), "ephemeral");
        assert_eq!(
            CertOrigin::Path {
                cert: PathBuf::from("/etc/a.pem"),
                key: PathBuf::from("/etc/a.key"),
            }
            .as_label(),
            "path:/etc/a.pem"
        );
    }
}
