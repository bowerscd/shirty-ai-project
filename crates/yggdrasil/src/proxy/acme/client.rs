//! ACME directory client.
//!
//! Drives the RFC 8555 order/finalise/poll flow against any ACME
//! directory via `instant-acme`. The renewer calls
//! [`AcmeClient::issue`] per `(host, challenge_type)` pair; this
//! module wires up HTTP-01 (via the shared [`super::AcmeResponder`])
//! or DNS-01 (via the resolved [`super::DnsProvider`]).

use std::time::Duration;

use instant_acme::{ChallengeType, Identifier, KeyAuthorization, NewOrder, OrderStatus};
use ratatoskr::rule::{AcmeChallenge, AcmeRouteConfig};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

use super::account::AccountKey;
use super::{dns01, AcmeError, AcmeManager};

/// Outcome of a successful issuance: the cert chain and matching
/// private key, both as PEM bytes ready to write to disk.
#[derive(Debug)]
pub struct IssuedCert {
    pub fullchain_pem: Vec<u8>,
    pub privkey_pem: Vec<u8>,
}

#[derive(Debug)]
pub struct AcmeClient<'a> {
    manager: &'a AcmeManager,
}

const ORDER_POLL_INTERVAL: Duration = Duration::from_secs(2);
const ORDER_POLL_DEADLINE: Duration = Duration::from_secs(120);

impl<'a> AcmeClient<'a> {
    pub fn new(manager: &'a AcmeManager) -> Self {
        Self { manager }
    }

    /// Run the full ACME flow for `host` using the challenge type and
    /// optional DNS provider from `route_cfg`. Returns the issued cert
    /// chain + private key as PEM bytes.
    pub async fn issue(
        &self,
        host: &str,
        route_cfg: &AcmeRouteConfig,
    ) -> Result<IssuedCert, AcmeError> {
        let cfg = self.manager.config();
        let account_key = AccountKey::new(cfg.account_key_path.clone());
        let account = account_key
            .load_or_register(
                &cfg.directory_url,
                &cfg.contact_email,
                cfg.terms_of_service_agreed,
            )
            .await?;

        // Submit the order.
        let identifier = Identifier::Dns(host.to_string());
        let mut order = account
            .new_order(&NewOrder {
                identifiers: &[identifier],
            })
            .await
            .map_err(|e| AcmeError::Client {
                host: host.to_string(),
                detail: format!("new_order: {e}"),
            })?;

        // Pick the matching challenge type for each pending authorization
        // and arm it. We collect the URLs to mark ready after every
        // challenge is registered, so the CA doesn't start validating
        // before we've placed all the records.
        let mut authorizations = order
            .authorizations()
            .await
            .map_err(|e| AcmeError::Client {
                host: host.to_string(),
                detail: format!("order.authorizations: {e}"),
            })?;

        let want_type = match route_cfg.challenge {
            AcmeChallenge::Http01 => ChallengeType::Http01,
            AcmeChallenge::Dns01 => ChallengeType::Dns01,
        };
        let mut ready_urls: Vec<String> = Vec::new();
        let mut dns_handles: Vec<(std::sync::Arc<dyn super::DnsProvider>, super::TxtHandle)> =
            Vec::new();
        let mut http_tokens: Vec<String> = Vec::new();

        for authz in authorizations.iter_mut() {
            let Identifier::Dns(authz_host) = &authz.identifier;
            let challenge = authz
                .challenges
                .iter()
                .find(|c| c.r#type == want_type)
                .ok_or_else(|| AcmeError::Client {
                    host: host.to_string(),
                    detail: format!(
                        "authorization for {authz_host:?} has no matching {want_type:?} challenge"
                    ),
                })?;
            let key_auth: KeyAuthorization = order.key_authorization(challenge);
            match route_cfg.challenge {
                AcmeChallenge::Http01 => {
                    self.manager
                        .responder()
                        .register(&challenge.token, key_auth.as_str());
                    http_tokens.push(challenge.token.clone());
                }
                AcmeChallenge::Dns01 => {
                    let provider_name =
                        route_cfg
                            .provider
                            .as_deref()
                            .ok_or_else(|| AcmeError::Client {
                                host: host.to_string(),
                                detail: "dns-01 challenge requested but no provider configured"
                                    .into(),
                            })?;
                    let provider = self.manager.providers().get(host, provider_name)?;
                    let txt_handle = dns01::place_challenge(
                        &provider,
                        authz_host,
                        key_auth.dns_value().as_str(),
                    )
                    .await?;
                    dns01::wait_for_propagation(
                        &provider,
                        authz_host,
                        key_auth.dns_value().as_str(),
                    )
                    .await?;
                    dns_handles.push((provider, txt_handle));
                }
            }
            ready_urls.push(challenge.url.clone());
        }

        // Mark every challenge ready in one pass.
        for url in &ready_urls {
            order
                .set_challenge_ready(url)
                .await
                .map_err(|e| AcmeError::Client {
                    host: host.to_string(),
                    detail: format!("set_challenge_ready {url}: {e}"),
                })?;
        }

        // Poll the order state until validation finishes.
        let started = std::time::Instant::now();
        let outcome: Result<(), AcmeError> = loop {
            if started.elapsed() > ORDER_POLL_DEADLINE {
                break Err(AcmeError::Client {
                    host: host.to_string(),
                    detail: format!("order did not reach Ready within {ORDER_POLL_DEADLINE:?}",),
                });
            }
            let state = order.refresh().await.map_err(|e| AcmeError::Client {
                host: host.to_string(),
                detail: format!("order.refresh: {e}"),
            })?;
            match state.status {
                OrderStatus::Pending | OrderStatus::Processing => {
                    tokio::time::sleep(ORDER_POLL_INTERVAL).await;
                }
                OrderStatus::Ready => break Ok(()),
                OrderStatus::Valid => break Ok(()),
                OrderStatus::Invalid => {
                    break Err(AcmeError::Client {
                        host: host.to_string(),
                        detail: "order entered Invalid state during validation".into(),
                    });
                }
            }
        };

        // Always tear challenges down — success or fail.
        for tok in &http_tokens {
            self.manager.responder().deregister(tok);
        }
        for (provider, handle) in dns_handles {
            if let Err(e) = dns01::remove_challenge(&provider, handle).await {
                tracing::warn!(host, error = %e, "dns-01 TXT cleanup failed; record may linger");
            }
        }

        outcome?;

        // Build CSR + key. ECDSA P-256 is the default rcgen keypair.
        let mut params =
            CertificateParams::new(vec![host.to_string()]).map_err(|e| AcmeError::Client {
                host: host.to_string(),
                detail: format!("CertificateParams::new: {e}"),
            })?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;
        let key_pair = KeyPair::generate().map_err(|e| AcmeError::Client {
            host: host.to_string(),
            detail: format!("KeyPair::generate: {e}"),
        })?;
        let csr = params
            .serialize_request(&key_pair)
            .map_err(|e| AcmeError::Client {
                host: host.to_string(),
                detail: format!("serialize_request: {e}"),
            })?;

        order
            .finalize(csr.der())
            .await
            .map_err(|e| AcmeError::Client {
                host: host.to_string(),
                detail: format!("order.finalize: {e}"),
            })?;

        // Poll for the certificate chain.
        let started = std::time::Instant::now();
        let cert_pem = loop {
            if started.elapsed() > ORDER_POLL_DEADLINE {
                return Err(AcmeError::Client {
                    host: host.to_string(),
                    detail: format!(
                        "certificate did not materialise within {ORDER_POLL_DEADLINE:?}",
                    ),
                });
            }
            match order.certificate().await.map_err(|e| AcmeError::Client {
                host: host.to_string(),
                detail: format!("order.certificate: {e}"),
            })? {
                Some(chain) => break chain,
                None => tokio::time::sleep(ORDER_POLL_INTERVAL).await,
            }
        };

        Ok(IssuedCert {
            fullchain_pem: cert_pem.into_bytes(),
            privkey_pem: key_pair.serialize_pem().into_bytes(),
        })
    }
}
