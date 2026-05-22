//! DNS-provider implementations.
//!
//! Each provider lives in its own submodule and is wired into
//! [`super::provider::ProviderRegistry`] by name. Adding a new provider
//! is a localized change: implement [`super::provider::DnsProvider`] +
//! register the name in `ProviderRegistry::from_config`.

pub mod cloudflare;
