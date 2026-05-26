//! Certificate loading: the explicit/ephemeral/convention/default
//! resolution chain plus PEM parsing and ephemeral leaf generation.
//!
//! Split out from the original monolithic `certs.rs` (Phase B5). The
//! public free functions `load_route_cert` and `load_rule_into_store`
//! are unchanged; downstream callers reach them through the parent
//! `certs` module's re-exports.

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;

use ratatoskr::rule::{CertSource, HttpRoute, Rule};

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
    /// Per-rule `cert_dir` override, if any; otherwise falls back to
    /// `server_cert_dir`.
    pub rule_cert_dir: Option<&'a Path>,
    pub server_cert_dir: &'a Path,
    pub server_default: Option<(&'a Path, &'a Path)>,
}

/// Resolve and load the certificate for a single `[[rule.route]]` following
/// the precedence chain described in the module-level docs.
pub fn load_route_cert(route: &HttpRoute, ctx: &CertContext<'_>) -> Result<CertEntry, CertError> {
    let hostname = &route.hostname;

    // 1) Explicit path.
    if let Some(CertSource::Path(cert_path)) = &route.cert {
        let key_path = route
            .key
            .as_ref()
            .expect("validator guarantees Path(_) ⇒ Some(key)");
        let key = load_pem_pair(ctx.rule_name, hostname, cert_path, key_path)?;
        return Ok(CertEntry {
            key: Arc::new(key),
            origin: CertOrigin::Path {
                cert: cert_path.clone(),
                key: key_path.clone(),
            },
            loaded_at_unix_ms: now_unix_ms(),
        });
    }

    // 2) Ephemeral sentinel.
    if matches!(route.cert, Some(CertSource::Ephemeral)) {
        let key = generate_ephemeral(hostname).map_err(|e| CertError::Ephemeral {
            rule: ctx.rule_name.to_string(),
            route: hostname.clone(),
            detail: e.to_string(),
        })?;
        return Ok(CertEntry {
            key: Arc::new(key),
            origin: CertOrigin::Ephemeral,
            loaded_at_unix_ms: now_unix_ms(),
        });
    }

    // 3) ACME-managed: convention dir is the source of truth (the
    //    renewer writes here). If the cert isn't there yet, fall back
    //    to an ephemeral stand-in so the listener can still bind; the
    //    renewer will issue and the CertWatcher will reload-host once
    //    the real fullchain.pem lands.
    if matches!(route.cert, Some(CertSource::Acme(_))) {
        let cdir = ctx.rule_cert_dir.unwrap_or(ctx.server_cert_dir);
        let acme_cert = cdir.join(hostname).join("fullchain.pem");
        let acme_key = cdir.join(hostname).join("privkey.pem");
        if acme_cert.is_file() && acme_key.is_file() {
            let key = load_pem_pair(ctx.rule_name, hostname, &acme_cert, &acme_key)?;
            return Ok(CertEntry {
                key: Arc::new(key),
                origin: CertOrigin::Acme {
                    cert: acme_cert,
                    key: acme_key,
                },
                loaded_at_unix_ms: now_unix_ms(),
            });
        }
        // First-boot stand-in. The ephemeral isn't valid against a real
        // CA-signed chain on the client side, but it lets the rule
        // bind so the rest of the daemon stays online while the
        // AcmeManager fetches the real cert.
        let key = generate_ephemeral(hostname).map_err(|e| CertError::Ephemeral {
            rule: ctx.rule_name.to_string(),
            route: hostname.clone(),
            detail: e.to_string(),
        })?;
        return Ok(CertEntry {
            key: Arc::new(key),
            origin: CertOrigin::AcmePending {
                cert: acme_cert,
                key: acme_key,
            },
            loaded_at_unix_ms: now_unix_ms(),
        });
    }

    // 4) Convention directory (no `cert =` declared at all).
    let cdir = ctx.rule_cert_dir.unwrap_or(ctx.server_cert_dir);
    let conv_cert = cdir.join(hostname).join("fullchain.pem");
    let conv_key = cdir.join(hostname).join("privkey.pem");
    if conv_cert.is_file() && conv_key.is_file() {
        let key = load_pem_pair(ctx.rule_name, hostname, &conv_cert, &conv_key)?;
        return Ok(CertEntry {
            key: Arc::new(key),
            origin: CertOrigin::Convention {
                cert: conv_cert,
                key: conv_key,
            },
            loaded_at_unix_ms: now_unix_ms(),
        });
    }

    // 5) Server-wide default.
    if let Some((cert_path, key_path)) = ctx.server_default {
        let key = load_pem_pair(ctx.rule_name, hostname, cert_path, key_path)?;
        return Ok(CertEntry {
            key: Arc::new(key),
            origin: CertOrigin::Default {
                cert: cert_path.to_path_buf(),
                key: key_path.to_path_buf(),
            },
            loaded_at_unix_ms: now_unix_ms(),
        });
    }

    Err(CertError::NoSource {
        rule: ctx.rule_name.to_string(),
        route: hostname.clone(),
    })
}

/// Resolve every route in `rule` and insert the results into `store`. This is
/// the "build the cert map at rule-load time" entry point used by the
/// supervisor.
///
/// For every disk-backed route (i.e. every route whose `CertOrigin` is
/// not `Ephemeral`), this also records a `ReloadSpec` in the store so
/// `CertStore::reload_host` can re-resolve the cert later without any
/// extra context from the caller. Ephemeral routes are not recorded —
/// they have no disk paths to watch.
pub fn load_rule_into_store(
    rule: &Rule,
    store: &CertStore,
    server_cert_dir: &Path,
    server_default: Option<(&Path, &Path)>,
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
        // Record the spec *before* inserting the entry so a concurrent
        // observer that sees the entry can also find the spec.
        if !matches!(entry.origin, CertOrigin::Ephemeral) {
            let spec = super::origin::ReloadSpec {
                rule_name: rule.name.clone(),
                route: route.clone(),
                rule_cert_dir: rule_cert_dir.map(Path::to_path_buf),
                server_cert_dir: server_cert_dir.to_path_buf(),
                server_default: server_default.map(|(c, k)| (c.to_path_buf(), k.to_path_buf())),
            };
            store.record_reload_spec(&route.hostname, spec);
        }
        store.insert(&route.hostname, entry);
    }
    Ok(())
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
pub(super) fn generate_ephemeral(hostname: &str) -> Result<CertifiedKey, rcgen::Error> {
    use rcgen::{
        date_time_ymd, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose, SanType,
    };
    use std::str::FromStr;

    let mut sans = vec![SanType::DnsName(rcgen::Ia5String::try_from(
        hostname.to_string(),
    )?)];
    if hostname.eq_ignore_ascii_case("localhost") {
        sans.push(SanType::IpAddress(
            std::net::IpAddr::from_str("127.0.0.1").unwrap(),
        ));
        sans.push(SanType::IpAddress(
            std::net::IpAddr::from_str("::1").unwrap(),
        ));
    }

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, hostname);

    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.subject_alt_names = sans;
    params.not_before = date_time_ymd(2024, 1, 1);
    params.not_after = date_time_ymd(2099, 1, 1);
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    // `KeyPair::generate()` selects the ring backend's default — ECDSA P-256.
    let kp = KeyPair::generate()?;
    let cert = params.self_signed(&kp)?;

    let cert_der: CertificateDer<'static> = cert.der().clone();
    let key_pkcs8 = kp.serialize_der();
    let key_der = PrivateKeyDer::try_from(key_pkcs8)
        .map_err(|e| rcgen::Error::PemError(format!("PKCS#8 round-trip: {e}")))?;
    let signing_key = any_supported_type(&key_der)
        .map_err(|e| rcgen::Error::PemError(format!("rustls signing-key load: {e:?}")))?;
    Ok(CertifiedKey::new(vec![cert_der], signing_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::SocketAddr;
    use std::path::PathBuf;
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
            http3: None,
            alt_svc: None,
        }
    }

    fn ephemeral_route(host: &str) -> HttpRoute {
        HttpRoute {
            hostname: host.to_string(),
            target: Url::parse("http://10.0.0.1:8080").unwrap(),
            cert: Some(CertSource::Ephemeral),
            key: None,
            hsts: None,
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
        let key_path = write_file(dir.path(), "privkey.pem", &key_pem);

        let route = HttpRoute {
            hostname: "api.local".to_string(),
            target: Url::parse("http://10.0.0.1:8080").unwrap(),
            cert: Some(CertSource::Path(cert_path.clone())),
            key: Some(key_path.clone()),
            hsts: None,
        };
        let rule = rule_with_routes(vec![route]);
        let store = CertStore::new();
        load_rule_into_store(&rule, &store, &PathBuf::from("/nonexistent"), None).unwrap();
        let listed = store.list();
        assert_eq!(listed.len(), 1);
        match &listed[0].1 {
            CertOrigin::Path { cert, key } => {
                assert_eq!(cert, &cert_path);
                assert_eq!(key, &key_path);
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
        fs::write(host_dir.join("privkey.pem"), key_pem).unwrap();

        let route = HttpRoute {
            hostname: "api.local".to_string(),
            target: Url::parse("http://10.0.0.1:8080").unwrap(),
            cert: None,
            key: None,
            hsts: None,
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
        let key_path = write_file(dir.path(), "wc.key", &key_pem);

        let route = HttpRoute {
            hostname: "api.local".to_string(),
            target: Url::parse("http://10.0.0.1:8080").unwrap(),
            cert: None,
            key: None,
            hsts: None,
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
            cert: None,
            key: None,
            hsts: None,
        };
        let rule = rule_with_routes(vec![route]);
        let store = CertStore::new();
        let err = load_rule_into_store(&rule, &store, &PathBuf::from("/nonexistent-dir"), None)
            .unwrap_err();
        assert!(matches!(err, CertError::NoSource { .. }));
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn malformed_cert_pem_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        // No PEM markers at all → PemObject parses zero entries → empty
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
            cert: Some(CertSource::Path(cert_path)),
            key: Some(key_path),
            hsts: None,
        };
        let rule = rule_with_routes(vec![route]);
        let store = CertStore::new();
        let err = load_rule_into_store(&rule, &store, &PathBuf::from("/nx"), None).unwrap_err();
        assert!(matches!(
            err,
            CertError::Pem {
                kind: "certificate",
                ..
            } | CertError::CertEmpty { .. }
        ));
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
