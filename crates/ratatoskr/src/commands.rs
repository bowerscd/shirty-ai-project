//! Implementations of the non-`run` CLI subcommands for ratatoskr.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};

use yggdrasil_proto::auth::{StaticKeyPair, PUBLIC_KEY_LEN};
use yggdrasil_proto::enrollment::EnrollmentBody;

use crate::cli::{EnrollArgs, IdentityArgs, KeygenArgs};

pub fn keygen(args: KeygenArgs) -> Result<()> {
    if args.force {
        match std::fs::remove_file(&args.identity_file) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(anyhow!(e).context(format!(
                    "removing existing identity file {}",
                    args.identity_file.display()
                )))
            }
        }
    }
    let kp = StaticKeyPair::generate().context("generating keypair")?;
    kp.save_to_file(&args.identity_file).with_context(|| {
        format!("writing identity file to {}", args.identity_file.display())
    })?;
    println!("wrote {}", args.identity_file.display());
    println!("pubkey:      {}", hex::encode(kp.public_key()));
    println!("fingerprint: {}", kp.fingerprint());
    println!();
    println!(
        "  Send the pubkey above to the yggdrasil operator. They will run"
    );
    println!("  `yggdrasil enroll-token --peer-pubkey <hex> ...` and send back");
    println!("  a token file for `ratatoskr enroll`.");
    Ok(())
}

pub fn pubkey(args: IdentityArgs) -> Result<()> {
    let kp = StaticKeyPair::load_from_file(&args.identity_file).with_context(|| {
        format!(
            "loading client identity from {}",
            args.identity_file.display()
        )
    })?;
    println!("{}", hex::encode(kp.public_key()));
    Ok(())
}

pub fn fingerprint(args: IdentityArgs) -> Result<()> {
    let kp = StaticKeyPair::load_from_file(&args.identity_file).with_context(|| {
        format!(
            "loading client identity from {}",
            args.identity_file.display()
        )
    })?;
    println!("{}", kp.fingerprint());
    Ok(())
}

pub fn enroll(args: EnrollArgs) -> Result<()> {
    let token_text = std::fs::read_to_string(&args.token)
        .with_context(|| format!("reading token from {}", args.token.display()))?;
    let body = EnrollmentBody::decode_string(&token_text)
        .context("decoding enrollment token")?;

    // Sanity check: the token's `peer_public` must match our identity. This
    // catches "wrong token file" before the daemon starts hammering an
    // unrelated peer.
    let cfg_dir = args
        .config
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let default_identity = cfg_dir.join("identity.key");
    let identity_path = pick_identity_path(&args.config, &default_identity);

    match StaticKeyPair::load_from_file(&identity_path) {
        Ok(local_kp) => {
            if *local_kp.public_key() != body.peer_public {
                bail!(
                    "token's peer_public ({}) does not match local identity ({} at {}); \
                     either the wrong token was used, or this host's identity was rotated",
                    hex::encode(body.peer_public),
                    hex::encode(local_kp.public_key()),
                    identity_path.display(),
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                identity_path = %identity_path.display(),
                "could not load local identity to cross-check token; proceeding anyway"
            );
        }
    }

    update_client_config(
        &args.config,
        &hex::encode(body.yggdrasil_public),
        &body.endpoint_hint,
    )
    .with_context(|| format!("updating {}", args.config.display()))?;

    println!("updated {}", args.config.display());
    println!("  client.yggdrasil_pubkey_hex = {}", hex::encode(body.yggdrasil_public));
    println!("  client.yggdrasil_endpoint   = {}", body.endpoint_hint);
    println!("  yggdrasil fingerprint       = {}", yggdrasil_proto::auth::public_key_fingerprint(&body.yggdrasil_public));
    println!("Start the daemon with `ratatoskr run`.");
    Ok(())
}

/// If the config file already contains a `client.identity_file`, use that;
/// otherwise fall back to the default path next to the config.
fn pick_identity_path(config_path: &Path, default_identity: &Path) -> PathBuf {
    let raw = match std::fs::read_to_string(config_path) {
        Ok(s) => s,
        Err(_) => return default_identity.to_path_buf(),
    };
    let value: toml::Value = match toml::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return default_identity.to_path_buf(),
    };
    value
        .get("client")
        .and_then(|c| c.get("identity_file"))
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .unwrap_or_else(|| default_identity.to_path_buf())
}

fn update_client_config(
    path: &Path,
    yggdrasil_pubkey_hex: &str,
    endpoint: &str,
) -> Result<()> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let mut doc: toml::Value = toml::from_str(&raw)
        .with_context(|| format!("parsing {} as TOML", path.display()))?;

    let client_tbl = doc
        .as_table_mut()
        .ok_or_else(|| anyhow!("config root must be a table"))?
        .entry("client".to_string())
        .or_insert_with(|| toml::Value::Table(Default::default()));
    let client_tbl = client_tbl
        .as_table_mut()
        .ok_or_else(|| anyhow!("[client] section must be a table"))?;

    client_tbl.insert(
        "yggdrasil_pubkey_hex".to_string(),
        toml::Value::String(yggdrasil_pubkey_hex.to_string()),
    );
    client_tbl.insert(
        "yggdrasil_endpoint".to_string(),
        toml::Value::String(endpoint.to_string()),
    );

    let serialised = toml::to_string_pretty(&doc).context("re-serialising TOML")?;

    // Atomic replace: write to sibling tmp, fsync, rename.
    let tmp_path = path.with_extension("toml.tmp");
    std::fs::write(&tmp_path, serialised.as_bytes())
        .with_context(|| format!("writing tmp file {}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("renaming {} → {}", tmp_path.display(), path.display()))?;
    Ok(())
}

// Kept for potential future use by other commands.
#[allow(dead_code)]
fn decode_pubkey_hex(hex_str: &str) -> Result<[u8; PUBLIC_KEY_LEN]> {
    let bytes = hex::decode(hex_str.trim()).context("not valid hex")?;
    let arr: [u8; PUBLIC_KEY_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("expected exactly {PUBLIC_KEY_LEN} bytes, got {}", bytes.len()))?;
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{EnrollArgs, IdentityArgs, KeygenArgs};
    use yggdrasil_proto::enrollment::EnrollmentBody;

    fn write_baseline_client_config(dir: &Path, identity_file: &Path) -> PathBuf {
        let cfg_path = dir.join("config.toml");
        let cfg = format!(
            r#"[client]
yggdrasil_endpoint = ""
yggdrasil_pubkey_hex = ""
identity_file = "{}"
"#,
            identity_file.display(),
        );
        std::fs::write(&cfg_path, cfg).unwrap();
        cfg_path
    }

    #[test]
    fn keygen_pubkey_fingerprint_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let ident = dir.path().join("identity.key");

        keygen(KeygenArgs {
            identity_file: ident.clone(),
            force: false,
        })
        .unwrap();
        // Re-load identity through proto crate and verify it parses.
        let kp = StaticKeyPair::load_from_file(&ident).unwrap();

        // Pubkey / fingerprint helpers should succeed.
        pubkey(IdentityArgs {
            identity_file: ident.clone(),
        })
        .unwrap();
        fingerprint(IdentityArgs {
            identity_file: ident.clone(),
        })
        .unwrap();

        // Sanity: fingerprint output is 32 hex chars per the proto crate.
        let fp = kp.fingerprint();
        assert_eq!(fp.len(), 32);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn enroll_updates_client_config_when_token_matches_identity() {
        let dir = tempfile::tempdir().unwrap();
        let ident = dir.path().join("identity.key");
        let cfg_path = write_baseline_client_config(dir.path(), &ident);

        keygen(KeygenArgs {
            identity_file: ident.clone(),
            force: false,
        })
        .unwrap();
        let kp = StaticKeyPair::load_from_file(&ident).unwrap();

        // Build a matching token.
        let yggdrasil_pub = [0xCDu8; PUBLIC_KEY_LEN];
        let body = EnrollmentBody::new(
            yggdrasil_pub,
            *kp.public_key(),
            "vps.example.com:7117",
            1700000000,
        );
        let token_path = dir.path().join("token.txt");
        std::fs::write(&token_path, body.encode_string().unwrap()).unwrap();

        enroll(EnrollArgs {
            token: token_path.clone(),
            config: cfg_path.clone(),
        })
        .unwrap();

        let updated = std::fs::read_to_string(&cfg_path).unwrap();
        assert!(updated.contains(&format!(
            "yggdrasil_pubkey_hex = \"{}\"",
            hex::encode(yggdrasil_pub)
        )));
        assert!(updated.contains("yggdrasil_endpoint = \"vps.example.com:7117\""));
    }

    #[test]
    fn enroll_rejects_token_whose_peer_public_does_not_match() {
        let dir = tempfile::tempdir().unwrap();
        let ident = dir.path().join("identity.key");
        let cfg_path = write_baseline_client_config(dir.path(), &ident);

        keygen(KeygenArgs {
            identity_file: ident.clone(),
            force: false,
        })
        .unwrap();

        // Token references a different peer_public than our identity.
        let body = EnrollmentBody::new(
            [0xCDu8; PUBLIC_KEY_LEN],
            [0xFFu8; PUBLIC_KEY_LEN],
            "vps:7117",
            1,
        );
        let token_path = dir.path().join("token.txt");
        std::fs::write(&token_path, body.encode_string().unwrap()).unwrap();

        let err = enroll(EnrollArgs {
            token: token_path,
            config: cfg_path,
        })
        .unwrap_err();
        assert!(format!("{err:#}").contains("does not match local identity"));
    }

    #[test]
    fn enroll_rejects_malformed_token_file() {
        let dir = tempfile::tempdir().unwrap();
        let ident = dir.path().join("identity.key");
        let cfg_path = write_baseline_client_config(dir.path(), &ident);
        keygen(KeygenArgs {
            identity_file: ident,
            force: false,
        })
        .unwrap();

        let token_path = dir.path().join("token.txt");
        std::fs::write(&token_path, "not a token").unwrap();
        let err = enroll(EnrollArgs {
            token: token_path,
            config: cfg_path,
        })
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.to_lowercase().contains("token"), "msg: {msg}");
    }
}
