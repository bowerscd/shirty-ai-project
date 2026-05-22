//! DNS-01 challenge driver.
//!
//! Generic wrapper around any [`super::provider::DnsProvider`] that
//! handles the three phases:
//!
//! 1. Insert the `TXT` record with the ACME-supplied key-authorization
//!    digest.
//! 2. Poll the authoritative resolver until the value is visible
//!    (provider-specific; defers to the provider's own implementation).
//! 3. After the CA finishes validating, remove the record.
//!
//! Step (3) runs even on validation failure so we don't leak `TXT`
//! records.

use std::sync::Arc;

use super::provider::DnsProvider;
use super::AcmeError;

/// Phase-1: insert. Returns the opaque handle the driver later passes
/// to `remove`.
pub async fn place_challenge(
    provider: &Arc<dyn DnsProvider>,
    host: &str,
    value: &str,
) -> Result<super::provider::TxtHandle, AcmeError> {
    let fqdn = format!("_acme-challenge.{host}");
    provider.add_txt(&fqdn, value).await
}

/// Phase-2: wait for the authoritative resolver to return `value`.
/// Errors propagate from the provider's own propagation poll.
pub async fn wait_for_propagation(
    provider: &Arc<dyn DnsProvider>,
    host: &str,
    value: &str,
) -> Result<(), AcmeError> {
    let fqdn = format!("_acme-challenge.{host}");
    provider.wait_for_propagation(&fqdn, value).await
}

/// Phase-3: tear the record down. Idempotent — providers may return
/// 404 from the underlying delete; that's not an error.
pub async fn remove_challenge(
    provider: &Arc<dyn DnsProvider>,
    handle: super::provider::TxtHandle,
) -> Result<(), AcmeError> {
    provider.remove_txt(handle).await
}
