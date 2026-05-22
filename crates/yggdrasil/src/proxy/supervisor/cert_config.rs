//! Certificate-loading configuration extracted from `ServerSection`.
//!
//! Split out from the original monolithic `supervisor.rs` (Phase B3).
//! Held by [`super::ProxySupervisor`] and consulted whenever an HTTPS
//! rule's routes need to be reified into the shared [`CertStore`].
//!
//! [`CertStore`]: crate::proxy::certs::CertStore

use std::path::PathBuf;

use crate::proxy::acme::AcmeManager;

/// Certificate-loading configuration extracted from `ServerSection`. Held
/// by the supervisor and consulted whenever an HTTPS rule's routes need to
/// be reified into the shared `CertStore`.
#[derive(Debug, Clone, Default)]
pub struct CertConfig {
    pub cert_dir: PathBuf,
    pub default_cert: Option<PathBuf>,
    pub default_key: Option<PathBuf>,
    /// Port for the HTTP→HTTPS redirect listener. `None` (default) uses
    /// the standard `:80`. Tests and operators without privileged-port
    /// access can set this to any other value (including `0` for an
    /// ephemeral port).
    pub redirect_port: Option<u16>,
    /// ACME manager (when `[acme]` is configured). When set, the
    /// supervisor:
    ///   * attaches the manager's HTTP-01 responder to every per-IP
    ///     redirect listener it spawns, and
    ///   * calls `AcmeManager::register(host, route_cfg)` for each
    ///     route whose `cert = "acme"` once the rule loads.
    pub acme: Option<AcmeManager>,
}

impl CertConfig {
    pub fn from_server_section(
        cert_dir: PathBuf,
        default_cert: Option<PathBuf>,
        default_key: Option<PathBuf>,
    ) -> Self {
        Self {
            cert_dir,
            default_cert,
            default_key,
            redirect_port: None,
            acme: None,
        }
    }

    /// Builder-style: attach an `AcmeManager`. The manager is shared
    /// across all HTTPS rules; only routes whose `cert = "acme"` ever
    /// reach it.
    pub fn with_acme(mut self, acme: AcmeManager) -> Self {
        self.acme = Some(acme);
        self
    }
}
