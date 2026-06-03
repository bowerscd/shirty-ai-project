//! Certificate loading: the node-wide three-rung resolution chain plus
//! PEM parsing.
//!
//!
//! Cert resolution is **node-wide**, not per-route. The resolver chain is:
//!
//! 1. **`<server_cert_dir>/<hostname>/{fullchain,privkey}.pem`** —
//!    per-hostname file convention.
//! 2. **`[server].default_cert` + `default_key`** — operator-managed
//!    wildcard PEM. Serves a route only when the cert's Subject
//!    Alternative Names actually cover the route's hostname (exact
//!    match or `*.parent` wildcard, RFC 6125). Routes outside that
//!    coverage fall through to rung 3 — the cert is not picked up
//!    as a misleading fallback that the TLS client would reject.
//! 3. **Cert-less LAN route** — the hostname is not bound on `:443`
//!    SNI; the per-IP companion listener serves it as plain HTTP on
//!    `:80` to peers in `[server].lan_cidrs`.

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use x509_parser::extensions::GeneralName;

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
    /// Pre-parsed lowercase DNS SANs of the leaf cert at
    /// `server_default.0` (if any). When present, `load_route_cert`
    /// uses this to decide whether the default cert legitimately
    /// covers a given route's hostname before treating it as a
    /// fallback. `None` means "default cert SANs are not available
    /// (no default cert configured, or parse failed)" — in that
    /// case the default-cert rung is skipped entirely and routes
    /// without convention-dir certs fall through to cert-less.
    pub server_default_sans: Option<Vec<String>>,
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

    // 2) Server-wide default. Only treat the cert as a covering
    //    fallback when its SANs actually include this hostname —
    //    otherwise a strict TLS client would reject the served cert
    //    at hostname-verification time, and the route would be
    //    better off as cert-less (rung 3) where it can be served as
    //    plain HTTP on the companion :80 listener to lan_cidrs
    //    peers. The SAN list is pre-parsed by the caller into
    //    `ctx.server_default_sans` so we don't reparse the PEM per
    //    route.
    if let Some((cert_path, key_path)) = ctx.server_default {
        let covers = ctx
            .server_default_sans
            .as_deref()
            .is_some_and(|sans| any_san_covers(sans, hostname));
        if covers {
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
    }

    // 3) Cert-less route — lives on :80 to lan_cidrs peers only.
    Ok(None)
}

/// Extract the leaf certificate's DNS Subject Alternative Names from
/// a PEM-encoded fullchain on disk. Returns lowercase names so the
/// coverage check is case-insensitive.
///
/// PEM/X.509 parse failures propagate as `CertError` — callers must
/// surface these, NOT silently treat the cert as missing. A
/// parse-failure on the default cert means "the operator's cert is
/// in a bad state right now"; collapsing that to cert-less would
/// pull every covered route off the SNI table and serve them plain
/// on :80, which is a security-affecting transition the operator
/// did NOT request. The reload-loop caller (`CertStore::reload_host`)
/// already treats `CertError` as "keep the previously-loaded
/// state", which is the correct posture for malformed-cert
/// resilience.
///
/// `Ok(vec![])` is distinct: the cert parsed cleanly but has no DNS
/// SAN entries (no `subjectAltName` extension at all, or a non-DNS
/// one). That's a legit "the default cert covers no hostnames"
/// state — routes correctly drop to cert-less.
pub(super) fn read_default_cert_sans(cert_path: &Path) -> Result<Vec<String>, CertError> {
    let pem = fs::read(cert_path).map_err(|e| CertError::CertRead {
        rule: "<default>".to_string(),
        route: "<default>".to_string(),
        path: cert_path.to_path_buf(),
        source: e,
    })?;
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| CertError::Pem {
            rule: "<default>".to_string(),
            route: "<default>".to_string(),
            kind: "certificate",
            path: cert_path.to_path_buf(),
            detail: e.to_string(),
        })?;
    if chain.is_empty() {
        return Err(CertError::CertEmpty {
            rule: "<default>".to_string(),
            route: "<default>".to_string(),
            path: cert_path.to_path_buf(),
        });
    }
    let leaf_der = chain[0].as_ref();
    let (_, cert) = x509_parser::parse_x509_certificate(leaf_der).map_err(|e| CertError::Pem {
        rule: "<default>".to_string(),
        route: "<default>".to_string(),
        kind: "x509",
        path: cert_path.to_path_buf(),
        detail: e.to_string(),
    })?;
    let sans = match cert.subject_alternative_name() {
        Ok(Some(ext)) => ext
            .value
            .general_names
            .iter()
            .filter_map(|gn| match gn {
                GeneralName::DNSName(name) => Some(name.to_ascii_lowercase()),
                _ => None,
            })
            .collect::<Vec<_>>(),
        Ok(None) => {
            tracing::info!(
                path = %cert_path.display(),
                "default cert: no Subject Alternative Name extension; \
                 cert won't cover any route by hostname"
            );
            Vec::new()
        }
        Err(e) => {
            return Err(CertError::Pem {
                rule: "<default>".to_string(),
                route: "<default>".to_string(),
                kind: "x509-sans",
                path: cert_path.to_path_buf(),
                detail: e.to_string(),
            });
        }
    };
    // Dedup so the per-route lookup is O(unique SANs).
    let mut deduped: HashSet<String> = HashSet::with_capacity(sans.len());
    for s in sans {
        deduped.insert(s);
    }
    Ok(deduped.into_iter().collect())
}

/// Returns true iff any SAN in `sans` covers `hostname` per RFC 6125:
/// either an exact case-insensitive match, or a single-label wildcard
/// at the leftmost position (`*.parent` covers `child.parent` but not
/// `parent` alone and not `a.b.parent`).
pub(super) fn any_san_covers(sans: &[String], hostname: &str) -> bool {
    let host = hostname.to_ascii_lowercase();
    sans.iter().any(|san| san_covers(san, &host))
}

fn san_covers(san: &str, host: &str) -> bool {
    if san == host {
        return true;
    }
    // Wildcard: `*.parent` matches one and only one DNS label at the
    // leftmost position. Per RFC 6125, the wildcard must be the
    // entire leftmost label; not `*foo.bar.com` or `foo*.bar.com`.
    if let Some(rest) = san.strip_prefix("*.") {
        if !rest.contains('*') {
            // host must have exactly one extra leading label.
            if let Some((leftmost, host_rest)) = host.split_once('.') {
                if !leftmost.is_empty() && host_rest == rest {
                    return true;
                }
            }
        }
    }
    false
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
    // Pre-parse SANs once for the whole batch. Parse failure on the
    // default cert is propagated as `CertError` so the supervisor
    // can refuse the load and keep the previous good state, matching
    // the malformed-cert resilience semantic; we do not silently
    // demote every route to cert-less on a transient bad cert.
    let server_default_sans = match server_default {
        Some((cert, _)) => Some(read_default_cert_sans(cert)?),
        None => None,
    };
    let ctx = CertContext {
        rule_name,
        server_cert_dir,
        server_default,
        server_default_sans,
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

#[cfg(test)]
mod tests {
    use super::*;
    use ratatoskr::rule::HttpRoute;
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    /// Mint a self-signed cert + key with the given DNS SANs.
    fn mint_cert_with_sans(sans: &[&str]) -> (String, String) {
        let mut params =
            rcgen::CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn write_default_cert(
        dir: &TempDir,
        sans: &[&str],
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let (cert_pem, key_pem) = mint_cert_with_sans(sans);
        let cert_path = dir.path().join("server.pem");
        let key_path = dir.path().join("server.key");
        std::fs::write(&cert_path, cert_pem).unwrap();
        std::fs::write(&key_path, key_pem).unwrap();
        (cert_path, key_path)
    }

    fn route(hostname: &str) -> HttpRoute {
        HttpRoute {
            hostname: hostname.to_string(),
            target: format!("http://backend-{}:80", hostname.replace('.', "-"))
                .parse()
                .unwrap(),
            hsts: None,
            headers: BTreeMap::new(),
        }
    }

    // ---- san_covers / any_san_covers ----

    #[test]
    fn san_exact_match_covers() {
        assert!(san_covers("app.test.local", "app.test.local"));
    }

    #[test]
    fn san_match_is_case_insensitive() {
        // any_san_covers lower-cases the host; san_covers expects
        // both inputs already lowercased.
        assert!(any_san_covers(
            &["app.test.local".to_string()],
            "App.Test.Local"
        ));
    }

    #[test]
    fn san_no_match_returns_false() {
        assert!(!san_covers("app.test.local", "other.test.local"));
        assert!(!san_covers("app.test.local", "test.local"));
    }

    #[test]
    fn san_wildcard_covers_one_label() {
        assert!(san_covers("*.test.local", "foo.test.local"));
        assert!(san_covers("*.test.local", "bar.test.local"));
    }

    #[test]
    fn san_wildcard_rejects_two_labels() {
        // RFC 6125: wildcard matches exactly one DNS label.
        assert!(!san_covers("*.test.local", "a.b.test.local"));
    }

    #[test]
    fn san_wildcard_rejects_bare_parent() {
        // `*.test.local` must not cover the parent `test.local`.
        assert!(!san_covers("*.test.local", "test.local"));
    }

    #[test]
    fn san_wildcard_rejects_embedded_asterisk() {
        // Per RFC 6125, the wildcard must be the entire leftmost
        // label. `app*.test.local` is not a valid wildcard pattern.
        assert!(!san_covers("app*.test.local", "appfoo.test.local"));
    }

    #[test]
    fn any_san_finds_match_across_list() {
        let sans = vec!["app.test.local".to_string(), "alt.test.local".to_string()];
        assert!(any_san_covers(&sans, "alt.test.local"));
        assert!(!any_san_covers(&sans, "internal.test.local"));
    }

    // ---- read_default_cert_sans ----

    #[test]
    fn read_sans_extracts_dns_names_lowercase() {
        let dir = TempDir::new().unwrap();
        let (cert_path, _) = write_default_cert(&dir, &["App.Test.Local", "alt.test.local"]);
        let sans = read_default_cert_sans(&cert_path).expect("SANs parsed");
        // Lowercased + deduped (order undefined since HashSet).
        let mut s = sans;
        s.sort();
        assert_eq!(s, vec!["alt.test.local", "app.test.local"]);
    }

    #[test]
    fn read_sans_returns_err_on_missing_file() {
        let result = read_default_cert_sans(std::path::Path::new("/no/such/file.pem"));
        assert!(
            result.is_err(),
            "missing file must propagate as CertError so the malformed-cert resilience \
             path in CertStore::reload_host keeps the previously-loaded cert in place"
        );
    }

    #[test]
    fn read_sans_returns_err_on_garbage_pem() {
        let dir = TempDir::new().unwrap();
        let garbage = dir.path().join("garbage.pem");
        std::fs::write(&garbage, b"this is not a PEM file").unwrap();
        let result = read_default_cert_sans(&garbage);
        assert!(
            result.is_err(),
            "garbage PEM must propagate as CertError (CertEmpty / Pem) for the same \
             reason: never silently demote covered routes to cert-less"
        );
    }

    // ---- load_route_cert: the actual bug ----

    /// Pre-fix: a route for `internal.test.local` would have been
    /// loaded with the default cert (which doesn't cover it) and
    /// shown up in the SNI table — strict TLS clients would then
    /// reject the cert at hostname verification. Post-fix: the route
    /// drops to rung 3 (cert-less) so it's served plain on :80 to
    /// lan_cidrs peers, or simply not served if lan_cidrs check
    /// fails. Either way, never served TLS with a wrong cert.
    #[test]
    fn route_not_covered_by_default_cert_falls_through_to_cert_less() {
        let dir = TempDir::new().unwrap();
        let (cert_path, key_path) = write_default_cert(&dir, &["app.test.local"]);
        let ctx = CertContext {
            rule_name: "test",
            server_cert_dir: dir.path(),
            server_default: Some((&cert_path, &key_path)),
            server_default_sans: Some(read_default_cert_sans(&cert_path).unwrap()),
        };
        let r = route("internal.test.local");
        let result = load_route_cert(&r, &ctx).unwrap();
        assert!(
            result.is_none(),
            "uncovered route must fall through to cert-less, not pick up the default cert"
        );
    }

    #[test]
    fn route_covered_by_default_cert_picks_it_up() {
        let dir = TempDir::new().unwrap();
        let (cert_path, key_path) = write_default_cert(&dir, &["app.test.local"]);
        let ctx = CertContext {
            rule_name: "test",
            server_cert_dir: dir.path(),
            server_default: Some((&cert_path, &key_path)),
            server_default_sans: Some(read_default_cert_sans(&cert_path).unwrap()),
        };
        let r = route("app.test.local");
        let result = load_route_cert(&r, &ctx).unwrap();
        let entry = result.expect("covered route must use default cert");
        assert!(matches!(entry.origin, CertOrigin::Default { .. }));
    }

    #[test]
    fn convention_dir_cert_wins_even_when_default_does_not_cover() {
        let dir = TempDir::new().unwrap();
        let (default_cert, default_key) = write_default_cert(&dir, &["app.test.local"]);
        // Convention-dir cert for a totally different hostname.
        let convdir = TempDir::new().unwrap();
        let (cert_pem, key_pem) = mint_cert_with_sans(&["internal.test.local"]);
        let host_dir = convdir.path().join("internal.test.local");
        std::fs::create_dir_all(&host_dir).unwrap();
        std::fs::write(host_dir.join("fullchain.pem"), cert_pem).unwrap();
        std::fs::write(host_dir.join("privkey.pem"), key_pem).unwrap();

        let ctx = CertContext {
            rule_name: "test",
            server_cert_dir: convdir.path(),
            server_default: Some((&default_cert, &default_key)),
            server_default_sans: Some(read_default_cert_sans(&default_cert).unwrap()),
        };
        let r = route("internal.test.local");
        let entry = load_route_cert(&r, &ctx)
            .unwrap()
            .expect("convention-dir cert covers the route");
        assert!(matches!(entry.origin, CertOrigin::Convention { .. }));
    }

    #[test]
    fn route_covered_by_wildcard_default_picks_it_up() {
        let dir = TempDir::new().unwrap();
        let (cert_path, key_path) = write_default_cert(&dir, &["*.test.local"]);
        let ctx = CertContext {
            rule_name: "test",
            server_cert_dir: dir.path(),
            server_default: Some((&cert_path, &key_path)),
            server_default_sans: Some(read_default_cert_sans(&cert_path).unwrap()),
        };
        let entry = load_route_cert(&route("foo.test.local"), &ctx)
            .unwrap()
            .expect("wildcard SAN must cover foo.test.local");
        assert!(matches!(entry.origin, CertOrigin::Default { .. }));
        // But not the bare parent.
        let none = load_route_cert(&route("test.local"), &ctx).unwrap();
        assert!(
            none.is_none(),
            "wildcard *.test.local must NOT cover bare test.local"
        );
    }

    /// Malformed-cert resilience: when the default cert is broken,
    /// `load_routes_into_store` must propagate the error so the
    /// caller (CertStore::reload_host) keeps the previously-loaded
    /// state. This is the regression that
    /// `default-cert-bypasses-cert-less`'s first naive fix
    /// introduced — silently demoting every route to cert-less on
    /// a transient bad cert.
    #[test]
    fn load_routes_into_store_propagates_malformed_default_cert() {
        let dir = TempDir::new().unwrap();
        let garbage = dir.path().join("server.pem");
        let garbage_key = dir.path().join("server.key");
        std::fs::write(&garbage, b"not actually a PEM").unwrap();
        // Key path won't be read because we fail at SAN extraction
        // first.
        std::fs::write(&garbage_key, b"also not a PEM").unwrap();

        let store = CertStore::new();
        let routes = vec![route("app.test.local")];
        let result = load_routes_into_store(
            "test",
            &routes,
            &store,
            dir.path(),
            Some((&garbage, &garbage_key)),
        );
        assert!(
            result.is_err(),
            "malformed default cert must propagate, not silently demote routes to cert-less"
        );
    }
}
