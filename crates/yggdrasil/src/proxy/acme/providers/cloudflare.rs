//! Cloudflare DNS provider for DNS-01 challenges.
//!
//! Talks to <https://api.cloudflare.com/client/v4/> using an
//! operator-supplied API token (scoped to `Zone.DNS:Edit`).
//! Propagation is verified by querying Cloudflare's authoritative
//! nameservers directly via `hickory-resolver`, so we don't depend on
//! the daemon host's recursive DNS cache being TTL-coherent.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::config::AcmeDnsProviderConfig;
use crate::proxy::acme::provider::{DnsProvider, TxtHandle};
use crate::proxy::acme::AcmeError;

const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";
const PROPAGATION_DEADLINE: Duration = Duration::from_secs(300);
const PROPAGATION_POLL_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct CloudflareProvider {
    api_token: String,
    http: Client,
}

impl CloudflareProvider {
    pub fn from_config(cfg: &AcmeDnsProviderConfig) -> Result<Self, AcmeError> {
        let api_token = match (&cfg.api_token, &cfg.api_token_env) {
            (Some(t), None) => t.clone(),
            (None, Some(env_name)) => std::env::var(env_name).map_err(|_| AcmeError::Dns {
                host: "<config>".into(),
                detail: format!(
                    "[acme.dns.cloudflare]: api_token_env = {env_name:?} \
                     is not set in the daemon's environment",
                ),
            })?,
            (Some(_), Some(_)) => {
                return Err(AcmeError::Dns {
                    host: "<config>".into(),
                    detail: "[acme.dns.cloudflare]: api_token and \
                             api_token_env are mutually exclusive"
                        .into(),
                });
            }
            (None, None) => {
                return Err(AcmeError::Dns {
                    host: "<config>".into(),
                    detail: "[acme.dns.cloudflare]: one of api_token or \
                             api_token_env must be set"
                        .into(),
                });
            }
        };
        if api_token.trim().is_empty() {
            return Err(AcmeError::Dns {
                host: "<config>".into(),
                detail: "[acme.dns.cloudflare]: api_token is empty".into(),
            });
        }

        let http = Client::builder()
            .user_agent(concat!("yggdrasil/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| AcmeError::Dns {
                host: "<config>".into(),
                detail: format!("build reqwest client: {e}"),
            })?;

        Ok(Self { api_token, http })
    }

    #[allow(dead_code)]
    pub(crate) fn api_token(&self) -> &str {
        &self.api_token
    }

    /// Locate the zone ID for an apex domain. Cloudflare scopes records
    /// under zones, so for `_acme-challenge.api.example.com` we need
    /// the `example.com` zone id.
    async fn find_zone_id(&self, fqdn: &str) -> Result<String, AcmeError> {
        // Walk leaf → root looking for the longest registered zone the
        // token has access to.
        let mut name = fqdn.trim_end_matches('.').to_string();
        loop {
            if let Some(id) = self.query_zone_by_name(&name).await? {
                return Ok(id);
            }
            match name.split_once('.') {
                Some((_, rest)) if !rest.is_empty() && rest.contains('.') => {
                    name = rest.to_string();
                }
                _ => break,
            }
        }
        Err(AcmeError::Dns {
            host: fqdn.into(),
            detail: format!("no Cloudflare zone covers {fqdn:?} (token scope?)"),
        })
    }

    async fn query_zone_by_name(&self, name: &str) -> Result<Option<String>, AcmeError> {
        let url = format!("{CF_API_BASE}/zones?name={name}");
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| AcmeError::Dns {
                host: name.into(),
                detail: format!("GET {url}: {e}"),
            })?;
        let status = resp.status();
        let body: CfListZonesResponse = resp.json().await.map_err(|e| AcmeError::Dns {
            host: name.into(),
            detail: format!("decode {url}: {e}"),
        })?;
        if !status.is_success() || !body.success {
            return Err(AcmeError::Dns {
                host: name.into(),
                detail: format!(
                    "Cloudflare zone lookup failed (status={status}, errors={:?})",
                    body.errors
                ),
            });
        }
        Ok(body.result.into_iter().next().map(|z| z.id))
    }
}

impl DnsProvider for CloudflareProvider {
    fn name(&self) -> &'static str {
        "cloudflare"
    }

    fn add_txt<'a>(
        &'a self,
        fqdn: &'a str,
        value: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<TxtHandle, AcmeError>> + Send + 'a>> {
        Box::pin(async move {
            let zone_id = self.find_zone_id(fqdn).await?;
            let url = format!("{CF_API_BASE}/zones/{zone_id}/dns_records");
            let body = CfCreateTxt {
                kind: "TXT",
                name: fqdn,
                content: value,
                ttl: 60,
            };
            let resp = self
                .http
                .post(&url)
                .bearer_auth(&self.api_token)
                .json(&body)
                .send()
                .await
                .map_err(|e| AcmeError::Dns {
                    host: fqdn.into(),
                    detail: format!("POST {url}: {e}"),
                })?;
            let status = resp.status();
            let decoded: CfRecordResponse = resp.json().await.map_err(|e| AcmeError::Dns {
                host: fqdn.into(),
                detail: format!("decode POST {url}: {e}"),
            })?;
            if !status.is_success() || !decoded.success {
                return Err(AcmeError::Dns {
                    host: fqdn.into(),
                    detail: format!(
                        "Cloudflare TXT add failed (status={status}, errors={:?})",
                        decoded.errors
                    ),
                });
            }
            let record_id = decoded
                .result
                .ok_or_else(|| AcmeError::Dns {
                    host: fqdn.into(),
                    detail: "Cloudflare returned success without result body".into(),
                })?
                .id;
            Ok(TxtHandle {
                fqdn: fqdn.to_string(),
                provider_record_id: format!("{zone_id}/{record_id}"),
            })
        })
    }

    fn remove_txt<'a>(
        &'a self,
        handle: TxtHandle,
    ) -> Pin<Box<dyn Future<Output = Result<(), AcmeError>> + Send + 'a>> {
        Box::pin(async move {
            let (zone_id, record_id) =
                handle
                    .provider_record_id
                    .split_once('/')
                    .ok_or_else(|| AcmeError::Dns {
                        host: handle.fqdn.clone(),
                        detail: "malformed Cloudflare TxtHandle (expected `<zone>/<record>`)"
                            .into(),
                    })?;
            let url = format!("{CF_API_BASE}/zones/{zone_id}/dns_records/{record_id}");
            let resp = self
                .http
                .delete(&url)
                .bearer_auth(&self.api_token)
                .send()
                .await
                .map_err(|e| AcmeError::Dns {
                    host: handle.fqdn.clone(),
                    detail: format!("DELETE {url}: {e}"),
                })?;
            let status = resp.status();
            // 404 means the record was already gone; idempotent.
            if status == reqwest::StatusCode::NOT_FOUND {
                return Ok(());
            }
            if !status.is_success() {
                let detail = resp
                    .text()
                    .await
                    .unwrap_or_else(|e| format!("(decode error: {e})"));
                return Err(AcmeError::Dns {
                    host: handle.fqdn.clone(),
                    detail: format!("Cloudflare TXT delete failed: status={status} body={detail}"),
                });
            }
            Ok(())
        })
    }

    fn wait_for_propagation<'a>(
        &'a self,
        fqdn: &'a str,
        value: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), AcmeError>> + Send + 'a>> {
        Box::pin(async move {
            // Cloudflare's anycasted authoritative resolvers, queried
            // directly so we bypass any recursive cache's TTL.
            let cf_ns = NameServerConfigGroup::cloudflare();
            let cfg = ResolverConfig::from_parts(None, vec![], cf_ns);
            let opts = ResolverOpts::default();
            let resolver = Arc::new(TokioAsyncResolver::tokio(cfg, opts));

            let started = std::time::Instant::now();
            while started.elapsed() < PROPAGATION_DEADLINE {
                if let Ok(txt) = resolver.txt_lookup(fqdn).await {
                    for record in txt.iter() {
                        for chunk in record.txt_data() {
                            if let Ok(s) = std::str::from_utf8(chunk) {
                                if s == value {
                                    return Ok(());
                                }
                            }
                        }
                    }
                }
                tokio::time::sleep(PROPAGATION_POLL_INTERVAL).await;
            }
            Err(AcmeError::Dns {
                host: fqdn.into(),
                detail: format!(
                    "TXT propagation poll timed out after {PROPAGATION_DEADLINE:?} \
                     (no record matched {value:?})",
                ),
            })
        })
    }
}

// ---- Cloudflare REST DTOs ----

#[derive(Debug, Deserialize)]
struct CfListZonesResponse {
    success: bool,
    #[serde(default)]
    errors: Vec<CfErrorEntry>,
    #[serde(default)]
    result: Vec<CfZone>,
}

#[derive(Debug, Deserialize)]
struct CfZone {
    id: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // populated by CF; kept for debug output
struct CfErrorEntry {
    code: u64,
    message: String,
}

#[derive(Debug, Serialize)]
struct CfCreateTxt<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    name: &'a str,
    content: &'a str,
    ttl: u32,
}

#[derive(Debug, Deserialize)]
struct CfRecordResponse {
    success: bool,
    #[serde(default)]
    errors: Vec<CfErrorEntry>,
    #[serde(default)]
    result: Option<CfRecord>,
}

#[derive(Debug, Deserialize)]
struct CfRecord {
    id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_token_loads_clean() {
        let p = CloudflareProvider::from_config(&AcmeDnsProviderConfig {
            api_token: Some("inline-token".into()),
            api_token_env: None,
        })
        .unwrap();
        assert_eq!(p.api_token(), "inline-token");
    }

    #[test]
    fn env_token_loads_from_process_env() {
        // SAFETY: this test binary uses unique env-var names so it
        // doesn't race other tests in the same binary.
        unsafe { std::env::set_var("YGGDRASIL_TEST_CF_TOKEN_XYZ", "env-token") };
        let p = CloudflareProvider::from_config(&AcmeDnsProviderConfig {
            api_token: None,
            api_token_env: Some("YGGDRASIL_TEST_CF_TOKEN_XYZ".into()),
        })
        .unwrap();
        assert_eq!(p.api_token(), "env-token");
        unsafe { std::env::remove_var("YGGDRASIL_TEST_CF_TOKEN_XYZ") };
    }

    #[test]
    fn missing_env_var_is_rejected() {
        let err = CloudflareProvider::from_config(&AcmeDnsProviderConfig {
            api_token: None,
            api_token_env: Some("YGGDRASIL_TEST_DEFINITELY_UNSET_XYZ".into()),
        })
        .unwrap_err();
        assert!(matches!(err, AcmeError::Dns { .. }));
    }

    #[test]
    fn empty_token_is_rejected() {
        let err = CloudflareProvider::from_config(&AcmeDnsProviderConfig {
            api_token: Some("   ".into()),
            api_token_env: None,
        })
        .unwrap_err();
        assert!(matches!(err, AcmeError::Dns { .. }));
    }

    #[test]
    fn txt_handle_round_trips_zone_and_record() {
        let handle = TxtHandle {
            fqdn: "_acme-challenge.api.example.com".into(),
            provider_record_id: "zone-abc/rec-xyz".into(),
        };
        let (zone, record) = handle.provider_record_id.split_once('/').unwrap();
        assert_eq!(zone, "zone-abc");
        assert_eq!(record, "rec-xyz");
    }
}
