//! Atomic on-disk writeout of issued cert material.
//!
//! Writes `{storage_dir}/{host}/{fullchain.pem,privkey.pem}` via
//! tempfile + rename so the `CertWatcher` sees a single atomic
//! filesystem event rather than a torn read. Permissions on the
//! private key file are tightened to `0600`.

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::client::IssuedCert;
use super::AcmeError;

/// Resolve the `(fullchain, privkey)` PEM paths for `host` under the
/// given storage directory.
pub fn paths(storage_dir: &Path, host: &str) -> (PathBuf, PathBuf) {
    let host_dir = storage_dir.join(host);
    let fullchain = host_dir.join("fullchain.pem");
    let privkey = host_dir.join("privkey.pem");
    (fullchain, privkey)
}

/// Atomic, mode-`0600`-on-the-key write of an issued cert pair to
/// `{storage_dir}/{host}/`.
pub fn write_atomic(storage_dir: &Path, host: &str, cert: &IssuedCert) -> Result<(), AcmeError> {
    let host_dir = storage_dir.join(host);
    std::fs::create_dir_all(&host_dir).map_err(|e| AcmeError::Storage {
        host: host.to_string(),
        detail: format!("create_dir_all {}: {e}", host_dir.display()),
    })?;
    write_one(&host_dir, host, "fullchain.pem", &cert.fullchain_pem, 0o644)?;
    write_one(&host_dir, host, "privkey.pem", &cert.privkey_pem, 0o600)?;
    Ok(())
}

fn write_one(
    host_dir: &Path,
    host: &str,
    name: &str,
    bytes: &[u8],
    mode: u32,
) -> Result<(), AcmeError> {
    let final_path = host_dir.join(name);
    let tmp_path = host_dir.join(format!("{name}.tmp"));
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp_path)
            .map_err(|e| AcmeError::Storage {
                host: host.to_string(),
                detail: format!("open {}: {e}", tmp_path.display()),
            })?;
        f.write_all(bytes).map_err(|e| AcmeError::Storage {
            host: host.to_string(),
            detail: format!("write {}: {e}", tmp_path.display()),
        })?;
        f.set_permissions(std::fs::Permissions::from_mode(mode))
            .map_err(|e| AcmeError::Storage {
                host: host.to_string(),
                detail: format!("chmod {} {mode:o}: {e}", tmp_path.display()),
            })?;
        f.sync_all().map_err(|e| AcmeError::Storage {
            host: host.to_string(),
            detail: format!("fsync {}: {e}", tmp_path.display()),
        })?;
    }
    std::fs::rename(&tmp_path, &final_path).map_err(|e| AcmeError::Storage {
        host: host.to_string(),
        detail: format!(
            "rename {} -> {}: {e}",
            tmp_path.display(),
            final_path.display()
        ),
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_lay_out_under_host_directory() {
        let (fc, pk) = paths(Path::new("/etc/yggdrasil/certs"), "api.example.com");
        assert_eq!(
            fc,
            PathBuf::from("/etc/yggdrasil/certs/api.example.com/fullchain.pem"),
        );
        assert_eq!(
            pk,
            PathBuf::from("/etc/yggdrasil/certs/api.example.com/privkey.pem"),
        );
    }

    #[test]
    fn write_atomic_creates_files_with_correct_perms() {
        let tmp = tempfile::tempdir().unwrap();
        let cert = IssuedCert {
            fullchain_pem: b"FULLCHAIN\n".to_vec(),
            privkey_pem: b"PRIVKEY\n".to_vec(),
        };
        write_atomic(tmp.path(), "api.local", &cert).unwrap();
        let (fc, pk) = paths(tmp.path(), "api.local");
        assert!(fc.is_file());
        assert!(pk.is_file());
        let pk_mode = std::fs::metadata(&pk).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            pk_mode, 0o600,
            "privkey perms must be 0600, got {pk_mode:o}"
        );
        let fc_mode = std::fs::metadata(&fc).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            fc_mode, 0o644,
            "fullchain perms must be 0644, got {fc_mode:o}"
        );
        assert_eq!(std::fs::read(&fc).unwrap(), b"FULLCHAIN\n");
        assert_eq!(std::fs::read(&pk).unwrap(), b"PRIVKEY\n");
    }
}
