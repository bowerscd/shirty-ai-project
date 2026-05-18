//! Implementations of the non-`run` CLI subcommands.

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};

use ratatoskr::auth::{self, StaticKeyPair, PUBLIC_KEY_LEN};
use ratatoskr::enrollment::EnrollmentBody;

use crate::cli::{EnrollTokenArgs, KeygenArgs};
use crate::config::ServerConfig;

pub fn keygen(args: KeygenArgs) -> Result<()> {
    if args.force {
        // Best-effort delete; ignore NotFound. `save_to_file` uses
        // create_new(true) so anything else would race anyway.
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
    Ok(())
}

pub fn enroll_token(args: EnrollTokenArgs) -> Result<()> {
    let cfg = ServerConfig::load(&args.config)
        .with_context(|| format!("loading server config from {}", args.config.display()))?;

    let local_kp = StaticKeyPair::load_from_file(&cfg.server.identity_file)
        .with_context(|| {
            format!(
                "loading server identity from {}",
                cfg.server.identity_file.display()
            )
        })?;

    let peer_public = decode_pubkey_hex(&args.peer_pubkey)
        .context("decoding --peer-pubkey")?;

    if args.endpoint.trim().is_empty() {
        bail!("--endpoint must not be empty");
    }
    // Sanity-check parse — we don't *use* the parsed addr; resolution happens
    // on the client side. We just refuse obviously-bad input.
    if !args.endpoint.contains(':') {
        bail!("--endpoint must be host:port (got {:?})", args.endpoint);
    }

    // Refuse to overwrite a different already-enrolled peer unless --force.
    if !cfg.peer.public_key_hex.is_empty() {
        let existing = decode_pubkey_hex(&cfg.peer.public_key_hex)
            .context("decoding existing peer.public_key_hex in config")?;
        if existing != peer_public && !args.force {
            bail!(
                "config already has a different peer enrolled ({}); pass --force to overwrite",
                hex::encode(existing),
            );
        }
    }

    let issued_at = current_unix_seconds();
    let body = EnrollmentBody::new(
        *local_kp.public_key(),
        peer_public,
        args.endpoint.clone(),
        issued_at,
    );
    let token_string = body.encode_string().context("encode enrollment token")?;

    write_secret_file(&args.output, token_string.as_bytes())
        .with_context(|| format!("writing token to {}", args.output.display()))?;

    update_server_peer(&args.config, &args.peer_pubkey)
        .with_context(|| format!("updating {}", args.config.display()))?;

    println!("wrote {}", args.output.display());
    println!("yggdrasil_pubkey: {}", hex::encode(local_kp.public_key()));
    println!(
        "yggdrasil_fingerprint: {}",
        auth::public_key_fingerprint(local_kp.public_key())
    );
    println!("peer_pubkey:      {}", args.peer_pubkey);
    println!("endpoint:         {}", args.endpoint);
    println!();
    println!("Recorded peer.public_key_hex in {}.", args.config.display());
    println!(
        "  Transfer {} to the huginn host over a trusted channel,",
        args.output.display()
    );
    println!("  then run `huginn enroll <token-file>` there.");
    Ok(())
}

/// Read-modify-write the server config file, setting `peer.public_key_hex`.
/// Atomic on the same filesystem (write tmp → rename).
fn update_server_peer(config_path: &Path, peer_pubkey_hex: &str) -> Result<()> {
    let raw = std::fs::read_to_string(config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;
    let mut doc: toml::Value = toml::from_str(&raw)
        .with_context(|| format!("parsing {} as TOML", config_path.display()))?;

    let root = doc
        .as_table_mut()
        .ok_or_else(|| anyhow!("config root must be a table"))?;
    let peer_tbl = root
        .entry("peer".to_string())
        .or_insert_with(|| toml::Value::Table(Default::default()))
        .as_table_mut()
        .ok_or_else(|| anyhow!("[peer] section must be a table"))?;
    peer_tbl.insert(
        "public_key_hex".to_string(),
        toml::Value::String(peer_pubkey_hex.to_string()),
    );

    let serialised = toml::to_string_pretty(&doc).context("re-serialising TOML")?;
    let tmp_path = config_path.with_extension("toml.tmp");
    std::fs::write(&tmp_path, serialised.as_bytes())
        .with_context(|| format!("writing tmp file {}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, config_path)
        .with_context(|| format!("renaming {} → {}", tmp_path.display(), config_path.display()))?;
    Ok(())
}

fn decode_pubkey_hex(hex_str: &str) -> Result<[u8; PUBLIC_KEY_LEN]> {
    let bytes = hex::decode(hex_str.trim()).context("not valid hex")?;
    let arr: [u8; PUBLIC_KEY_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("expected exactly {PUBLIC_KEY_LEN} bytes, got {}", bytes.len()))?;
    Ok(arr)
}

fn current_unix_seconds() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Write `data` to `path` with mode 0600, refusing to overwrite.
fn write_secret_file(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(data)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{EnrollTokenArgs, KeygenArgs};
    use std::path::PathBuf;

    fn write_minimal_server_config(dir: &Path, identity_file: &Path) -> PathBuf {
        let cfg_path = dir.join("config.toml");
        let cfg = format!(
            r#"
[server]
heartbeat_listen = "127.0.0.1:0"
rules_dir = "{}"
identity_file = "{}"

[peer]
public_key_hex = ""
"#,
            dir.display(),
            identity_file.display(),
        );
        std::fs::write(&cfg_path, cfg).unwrap();
        cfg_path
    }

    #[test]
    fn keygen_writes_identity_file_and_force_reissues() {
        let dir = tempfile::tempdir().unwrap();
        let ident = dir.path().join("identity.key");

        keygen(KeygenArgs {
            identity_file: ident.clone(),
            force: false,
        })
        .unwrap();
        assert!(ident.exists());

        // Non-force refuses to overwrite.
        let err = keygen(KeygenArgs {
            identity_file: ident.clone(),
            force: false,
        })
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.to_lowercase().contains("exists") || msg.to_lowercase().contains("write"),
            "unexpected error: {msg}"
        );

        // With --force we can rotate it.
        keygen(KeygenArgs {
            identity_file: ident.clone(),
            force: true,
        })
        .unwrap();
        assert!(ident.exists());
    }

    #[test]
    fn enroll_token_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let ident = dir.path().join("identity.key");
        let cfg_path = write_minimal_server_config(dir.path(), &ident);

        // Generate the server's identity first.
        keygen(KeygenArgs {
            identity_file: ident.clone(),
            force: false,
        })
        .unwrap();

        // Peer pubkey: any 32-byte value, hex-encoded.
        let peer_pub_bytes = [0xABu8; PUBLIC_KEY_LEN];
        let peer_pub_hex = hex::encode(peer_pub_bytes);

        let token_path = dir.path().join("token.txt");
        enroll_token(EnrollTokenArgs {
            peer_pubkey: peer_pub_hex.clone(),
            endpoint: "vps.example.com:7117".to_string(),
            output: token_path.clone(),
            config: cfg_path.clone(),
            force: false,
        })
        .unwrap();

        let token = std::fs::read_to_string(&token_path).unwrap();
        assert!(token.starts_with("YGG1-v1."));

        let body = EnrollmentBody::decode_string(&token).unwrap();
        let local_kp = StaticKeyPair::load_from_file(&ident).unwrap();
        assert_eq!(body.yggdrasil_public, *local_kp.public_key());
        assert_eq!(body.peer_public, peer_pub_bytes);
        assert_eq!(body.endpoint_hint, "vps.example.com:7117");

        // Side effect: config file now has the peer recorded.
        let updated = std::fs::read_to_string(&cfg_path).unwrap();
        assert!(
            updated.contains(&format!("public_key_hex = \"{peer_pub_hex}\"")),
            "config not updated:\n{updated}"
        );
    }

    #[test]
    fn enroll_token_rejects_bad_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let ident = dir.path().join("identity.key");
        let cfg_path = write_minimal_server_config(dir.path(), &ident);
        keygen(KeygenArgs {
            identity_file: ident.clone(),
            force: false,
        })
        .unwrap();

        let err = enroll_token(EnrollTokenArgs {
            peer_pubkey: hex::encode([0u8; PUBLIC_KEY_LEN]),
            endpoint: "no-colon-here".to_string(),
            output: dir.path().join("token.txt"),
            config: cfg_path,
            force: false,
        })
        .unwrap_err();
        assert!(format!("{err:#}").contains("host:port"));
    }

    #[test]
    fn enroll_token_rejects_bad_peer_pubkey() {
        let dir = tempfile::tempdir().unwrap();
        let ident = dir.path().join("identity.key");
        let cfg_path = write_minimal_server_config(dir.path(), &ident);
        keygen(KeygenArgs {
            identity_file: ident.clone(),
            force: false,
        })
        .unwrap();

        let err = enroll_token(EnrollTokenArgs {
            peer_pubkey: "nothex!!".to_string(),
            endpoint: "host:1".to_string(),
            output: dir.path().join("token.txt"),
            config: cfg_path,
            force: false,
        })
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("hex") || msg.contains("decoding"), "msg: {msg}");
    }

    #[test]
    fn enroll_token_refuses_to_overwrite_different_existing_peer_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let ident = dir.path().join("identity.key");
        let cfg_path = write_minimal_server_config(dir.path(), &ident);
        keygen(KeygenArgs {
            identity_file: ident.clone(),
            force: false,
        })
        .unwrap();

        // Pre-enroll one peer.
        let first_peer = hex::encode([0x11u8; PUBLIC_KEY_LEN]);
        enroll_token(EnrollTokenArgs {
            peer_pubkey: first_peer.clone(),
            endpoint: "host:1".to_string(),
            output: dir.path().join("token-1.txt"),
            config: cfg_path.clone(),
            force: false,
        })
        .unwrap();

        // Idempotent re-enroll (same peer) — should succeed.
        enroll_token(EnrollTokenArgs {
            peer_pubkey: first_peer.clone(),
            endpoint: "host:1".to_string(),
            output: dir.path().join("token-1b.txt"),
            config: cfg_path.clone(),
            force: false,
        })
        .unwrap();

        // Different peer without --force → refuse.
        let second_peer = hex::encode([0x22u8; PUBLIC_KEY_LEN]);
        let err = enroll_token(EnrollTokenArgs {
            peer_pubkey: second_peer.clone(),
            endpoint: "host:1".to_string(),
            output: dir.path().join("token-2.txt"),
            config: cfg_path.clone(),
            force: false,
        })
        .unwrap_err();
        assert!(format!("{err:#}").contains("--force"));

        // With --force, it goes through.
        enroll_token(EnrollTokenArgs {
            peer_pubkey: second_peer.clone(),
            endpoint: "host:1".to_string(),
            output: dir.path().join("token-2b.txt"),
            config: cfg_path.clone(),
            force: true,
        })
        .unwrap();
        let updated = std::fs::read_to_string(&cfg_path).unwrap();
        assert!(
            updated.contains(&format!("public_key_hex = \"{second_peer}\"")),
            "config not updated:\n{updated}"
        );
    }
}
