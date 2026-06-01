//! Certificate loading: the node-wide three-rung resolution chain plus
//! PEM parsing.
//!
//!
//! Cert resolution is **node-wide**, not per-route. The resolver chain is:
//!
//! 1. **`[server].default_cert` + `default_key`** — operator-managed
//!    wildcard PEM. Serves every SNI whose hostname matches a SAN.
//! 2. **`<server_cert_dir>/<hostname>/{fullchain,privkey}.pem`** —
//!    per-hostname file convention.
//! 3. **Cert-less LAN route** — the hostname is not bound on `:443`
//!    SNI; the per-IP companion listener serves it as plain HTTP on
//!    `:80` to peers in `[server].lan_cidrs`.

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;

use ratatoskr::rule::HttpRoute;

use super::origin::{CertEntry, CertError, CertOrigin};
use super::store::CertStore;

/// Current wall clock as Unix epoch milliseconds. Saturates at zero if the
/// system clock is implausibly skewed before 1970.
pub(super) fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Inputs to [`load_route_cert`] that aren't carried by the route itself.
#[derive(Debug, Clone)]
pub struct CertContext<'a> {
    pub rule_name: &'a str,
    pub server_cert_dir: &'a Path,
    pub server_default: Option<(&'a Path, &'a Path)>,
}

/// Resolve and load the certificate for a single HTTPS route following
/// the three-rung node-wide chain.
///
/// Returns `Ok(None)` when no cert source matches — that signals a
/// **cert-less route** which lives only on the per-IP companion
/// listener's `:80` plaintext path (see
/// [`crate::proxy::http_frontend::redirect`]). Cert-less routes are
/// intentionally not entered into the cert store; the HTTPS frontend
/// will not register their hostnames in the SNI table.
pub fn load_route_cert(
    route: &HttpRoute,
    ctx: &CertContext<'_>,
) -> Result<Option<CertEntry>, CertError> {
    let hostname = &route.hostname;

    // 1) Convention directory: <server_cert_dir>/<hostname>/{fullchain,privkey}.pem.
    let conv_cert = ctx.server_cert_dir.join(hostname).join("fullchain.pem");
    let conv_key = ctx.server_cert_dir.join(hostname).join("privkey.pem");
    if conv_cert.is_file() && conv_key.is_file() {
        let key = load_pem_pair(ctx.rule_name, hostname, &conv_cert, &conv_key)?;
        return Ok(Some(CertEntry {
            key: Arc::new(key),
            origin: CertOrigin::Convention {
                cert: conv_cert,
                key: conv_key,
            },
            loaded_at_unix_ms: now_unix_ms(),
        }));
    }

    // 2) Server-wide default (wildcard).
    if let Some((cert_path, key_path)) = ctx.server_default {
        let key = load_pem_pair(ctx.rule_name, hostname, cert_path, key_path)?;
        return Ok(Some(CertEntry {
            key: Arc::new(key),
            origin: CertOrigin::Default {
                cert: cert_path.to_path_buf(),
                key: key_path.to_path_buf(),
            },
            loaded_at_unix_ms: now_unix_ms(),
        }));
    }

    // 3) Cert-less route — lives on :80 to lan_cidrs peers only.
    Ok(None)
}

/// Resolve every route in `routes` and insert the results into `store`. This is
/// the "build the cert map at rule-load time" entry point used by the
/// supervisor.
///
/// Cert-less routes (`load_route_cert` returning `Ok(None)`) are
/// **skipped entirely**: they are not inserted into the store and no
/// reload spec is recorded for them. The supervisor's route-partition
/// step is responsible for forwarding cert-less routes to the per-IP
/// companion listener's `plaintext_routes` table. The collected
/// cert-less hostnames are returned so the caller can emit a load-time
/// `WARN` per hostname and wire the routes onto the companion listener
/// atomically with the cert store update.
pub fn load_routes_into_store(
    rule_name: &str,
    routes: &[HttpRoute],
    store: &CertStore,
    server_cert_dir: &Path,
    server_default: Option<(&Path, &Path)>,
) -> Result<Vec<String>, CertError> {
    let ctx = CertContext {
        rule_name,
        server_cert_dir,
        server_default,
    };
    let mut cert_less: Vec<String> = Vec::new();
    for route in routes {
        let Some(entry) = load_route_cert(route, &ctx)? else {
            cert_less.push(route.hostname.clone());
            continue;
        };
        let spec = super::origin::ReloadSpec {
            rule_name: rule_name.to_string(),
            route: route.clone(),
            server_cert_dir: server_cert_dir.to_path_buf(),
            server_default: server_default.map(|(c, k)| (c.to_path_buf(), k.to_path_buf())),
        };
        store.record_reload_spec(&route.hostname, spec);
        store.insert(&route.hostname, entry);
    }
    Ok(cert_less)
}

/// Load and verify a `(cert, key)` PEM pair.
fn load_pem_pair(
    rule_name: &str,
    route: &str,
    cert_path: &Path,
    key_path: &Path,
) -> Result<CertifiedKey, CertError> {
    let cert_pem = fs::read(cert_path).map_err(|e| CertError::CertRead {
        rule: rule_name.to_string(),
        route: route.to_string(),
        path: cert_path.to_path_buf(),
        source: e,
    })?;
    let key_pem = fs::read(key_path).map_err(|e| CertError::KeyRead {
        rule: rule_name.to_string(),
        route: route.to_string(),
        path: key_path.to_path_buf(),
        source: e,
    })?;
    parse_pem_pair(rule_name, route, cert_path, &cert_pem, key_path, &key_pem)
}

fn parse_pem_pair(
    rule_name: &str,
    route: &str,
    cert_path: &Path,
    cert_pem: &[u8],
    key_path: &Path,
    key_pem: &[u8],
) -> Result<CertifiedKey, CertError> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| CertError::Pem {
            rule: rule_name.to_string(),
            route: route.to_string(),
            kind: "certificate",
            path: cert_path.to_path_buf(),
            detail: e.to_string(),
        })?;
    if chain.is_empty() {
        return Err(CertError::CertEmpty {
            rule: rule_name.to_string(),
            route: route.to_string(),
            path: cert_path.to_path_buf(),
        });
    }

    let key_der: PrivateKeyDer<'static> = match PrivateKeyDer::from_pem_slice(key_pem) {
        Ok(k) => k,
        Err(rustls::pki_types::pem::Error::NoItemsFound) => {
            return Err(CertError::KeyEmpty {
                rule: rule_name.to_string(),
                route: route.to_string(),
                path: key_path.to_path_buf(),
            });
        }
        Err(e) => {
            return Err(CertError::Pem {
                rule: rule_name.to_string(),
                route: route.to_string(),
                kind: "private key",
                path: key_path.to_path_buf(),
                detail: e.to_string(),
            });
        }
    };

    let signing_key = any_supported_type(&key_der).map_err(|e| CertError::SigningKey {
        rule: rule_name.to_string(),
        route: route.to_string(),
        detail: e.to_string(),
    })?;

    Ok(CertifiedKey::new(chain, signing_key))
}
