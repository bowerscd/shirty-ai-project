//! `DnsProvider` trait + `ProviderRegistry`.
//!
//! Operators declare DNS-01 providers under `[acme.dns.<name>]`. Each
//! implementation knows how to add a temporary `_acme-challenge.<host>`
//! `TXT` record, poll the authoritative resolver until the record is
//! visible, then remove the record after the CA has validated.
//!
//! The trait is `async`-friendly; implementations are expected to use
//! `reqwest`/`hyper`/whatever to talk to their respective provider APIs.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::config::AcmeDnsProviderConfig;

use super::providers::cloudflare::CloudflareProvider;
use super::AcmeError;

/// Opaque handle returned by [`DnsProvider::add_txt`] and consumed by
/// [`DnsProvider::remove_txt`]. Providers stash whatever they need
/// (e.g. Cloudflare's `record_id`) inside.
#[derive(Debug, Clone)]
pub struct TxtHandle {
    pub fqdn: String,
    pub provider_record_id: String,
}

/// DNS-provider abstraction. Operations are async because every real
/// provider talks to an HTTP API.
pub trait DnsProvider: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &'static str;

    /// Insert a `TXT` record at `fqdn` with `value`. The returned
    /// `TxtHandle` is opaque to the caller; pass it back into
    /// [`DnsProvider::remove_txt`] when the CA has finished validating.
    fn add_txt<'a>(
        &'a self,
        fqdn: &'a str,
        value: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<TxtHandle, AcmeError>> + Send + 'a>>;

    /// Remove a `TXT` record previously inserted by `add_txt`.
    /// Idempotent: removing an already-removed record is not an error.
    fn remove_txt<'a>(
        &'a self,
        handle: TxtHandle,
    ) -> Pin<Box<dyn Future<Output = Result<(), AcmeError>> + Send + 'a>>;

    /// Block until the authoritative resolver returns `value` as a
    /// `TXT` value at `fqdn`, or until the provider's internal deadline
    /// elapses (typically a few minutes). Implementations are expected
    /// to back off between polls.
    fn wait_for_propagation<'a>(
        &'a self,
        fqdn: &'a str,
        value: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), AcmeError>> + Send + 'a>>;
}

/// Lookup map from `[acme.dns.<name>]` key to a built provider. The
/// registry takes ownership of provider configs at startup; the only
/// dynamic dispatch happens via the `DnsProvider` trait object inside.
#[derive(Debug, Clone, Default)]
pub struct ProviderRegistry {
    by_name: BTreeMap<String, Arc<dyn DnsProvider>>,
}

impl ProviderRegistry {
    /// Build a registry from the `[acme.dns.*]` config tables. Returns
    /// the canonical [`AcmeError`] when a config block names an
    /// unknown provider or has missing credentials.
    pub fn from_config(dns: &BTreeMap<String, AcmeDnsProviderConfig>) -> Result<Self, AcmeError> {
        let mut by_name: BTreeMap<String, Arc<dyn DnsProvider>> = BTreeMap::new();
        for (name, cfg) in dns {
            let provider: Arc<dyn DnsProvider> = match name.as_str() {
                "cloudflare" => Arc::new(CloudflareProvider::from_config(cfg)?),
                other => {
                    return Err(AcmeError::UnknownProvider {
                        host: "<config>".to_string(),
                        provider: other.to_string(),
                    });
                }
            };
            by_name.insert(name.clone(), provider);
        }
        Ok(Self { by_name })
    }

    /// Look up a provider by name (e.g. `"cloudflare"`). Returns
    /// `UnknownProvider` when the name is not registered.
    pub fn get(&self, host: &str, name: &str) -> Result<Arc<dyn DnsProvider>, AcmeError> {
        self.by_name
            .get(name)
            .cloned()
            .ok_or_else(|| AcmeError::UnknownProvider {
                host: host.to_string(),
                provider: name.to_string(),
            })
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.by_name.keys().map(|s| s.as_str())
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_registry_is_empty() {
        let dns = BTreeMap::new();
        let reg = ProviderRegistry::from_config(&dns).unwrap();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn unknown_provider_name_is_rejected() {
        let mut dns = BTreeMap::new();
        dns.insert(
            "no-such-provider".to_string(),
            AcmeDnsProviderConfig {
                api_token: Some("x".into()),
                api_token_env: None,
            },
        );
        let err = ProviderRegistry::from_config(&dns).unwrap_err();
        assert!(matches!(err, AcmeError::UnknownProvider { .. }));
    }

    #[test]
    fn cloudflare_provider_registers() {
        let mut dns = BTreeMap::new();
        dns.insert(
            "cloudflare".to_string(),
            AcmeDnsProviderConfig {
                api_token: Some("cf-token".into()),
                api_token_env: None,
            },
        );
        let reg = ProviderRegistry::from_config(&dns).unwrap();
        assert_eq!(reg.len(), 1);
        let p = reg.get("api.example.com", "cloudflare").unwrap();
        assert_eq!(p.name(), "cloudflare");
    }
}
