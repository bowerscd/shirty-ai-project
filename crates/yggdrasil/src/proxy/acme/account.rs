//! Long-lived ACME account-key persistence.
//!
//! The account credentials are an `instant_acme::AccountCredentials`
//! JSON blob. We persist them at `[acme].account_key_path` (default
//! `/var/lib/yggdrasil/acme/account.key`) with mode `0600`. On first
//! use the file is created by registering a fresh account against the
//! configured ACME directory.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use instant_acme::{Account, AccountCredentials, NewAccount};

use super::AcmeError;

/// Persistent handle to the daemon's ACME account credentials.
#[derive(Debug, Clone)]
pub struct AccountKey {
    path: PathBuf,
}

impl AccountKey {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load the persisted credentials and reconstruct an `Account`, or
    /// register a fresh account against `directory_url` (using
    /// `contact_email`) when no key is on disk yet. The newly-issued
    /// credentials are persisted at `0600` before returning.
    pub async fn load_or_register(
        &self,
        directory_url: &str,
        contact_email: &str,
        terms_of_service_agreed: bool,
    ) -> Result<Account, AcmeError> {
        if self.path.exists() {
            let bytes = std::fs::read(&self.path).map_err(|e| AcmeError::Account {
                host: "<global>".into(),
                detail: format!("read {}: {e}", self.path.display()),
            })?;
            let creds: AccountCredentials =
                serde_json::from_slice(&bytes).map_err(|e| AcmeError::Account {
                    host: "<global>".into(),
                    detail: format!("decode {}: {e}", self.path.display()),
                })?;
            let account =
                Account::from_credentials(creds)
                    .await
                    .map_err(|e| AcmeError::Account {
                        host: "<global>".into(),
                        detail: format!("reconstruct account from {}: {e}", self.path.display()),
                    })?;
            return Ok(account);
        }

        let contact = format!("mailto:{contact_email}");
        let new_account = NewAccount {
            contact: &[&contact],
            terms_of_service_agreed,
            only_return_existing: false,
        };
        let (account, creds) = Account::create(&new_account, directory_url, None)
            .await
            .map_err(|e| AcmeError::Account {
                host: "<global>".into(),
                detail: format!("Account::create against {directory_url:?}: {e}"),
            })?;
        let serialised = serde_json::to_vec(&creds).map_err(|e| AcmeError::Account {
            host: "<global>".into(),
            detail: format!("serialise account credentials: {e}"),
        })?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| AcmeError::Account {
                host: "<global>".into(),
                detail: format!("mkdir -p {}: {e}", parent.display()),
            })?;
        }
        let tmp = self.path.with_extension("key.tmp");
        std::fs::write(&tmp, &serialised).map_err(|e| AcmeError::Account {
            host: "<global>".into(),
            detail: format!("write {}: {e}", tmp.display()),
        })?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
            AcmeError::Account {
                host: "<global>".into(),
                detail: format!("chmod 0600 {}: {e}", tmp.display()),
            }
        })?;
        std::fs::rename(&tmp, &self.path).map_err(|e| AcmeError::Account {
            host: "<global>".into(),
            detail: format!("rename {} -> {}: {e}", tmp.display(), self.path.display()),
        })?;
        tracing::info!(path = %self.path.display(), "ACME: registered new account with CA");
        Ok(account)
    }
}
