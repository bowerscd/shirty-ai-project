//! `identity` scope — offline operations on this node's identity file and
//! the daemon's config TOML.
//!
//! All commands here are file-based and run without contacting the daemon.
//! Changes to `[dial]` / `[accept]` sections take effect on the next
//! daemon restart (chain endpoints are wired at startup; there is no
//! hot-reload path for them yet).
//!
//! ## Files involved
//!
//! * Identity file: 64 raw bytes (32-byte X25519 secret ++ 32-byte X25519
//!   public). Mode `0600`. Default location `/etc/yggdrasil/identity.key`;
//!   overridable with `--identity-file`, or, when not given, resolved from
//!   `[server].identity_file` in `--config`.
//! * Config file: standard yggdrasil TOML. We mutate the `[dial]`
//!   and `[accept]` sections atomically (tmp + rename); other
//!   sections are preserved.
//! * Intro file (`intro.txt` by convention): emitted by a node that wants to
//!   advertise itself as a downstream candidate. Contains this node's
//!   tagged pubkey and a self-fingerprint.
//! * Invite file (`invite.txt` by convention): emitted by an upstream after
//!   accepting an intro. Contains both pubkeys + the upstream's reachable
//!   endpoint. Hand-delivered back to the downstream (the issuer of the
//!   original intro), which feeds it to `identity add-upstream`.
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};

use ratatoskr::auth::StaticKeyPair;
use ratatoskr::intro::{IntroFile, InviteFile};
use ratatoskr::pubkey::PubKey;

/// Fallback identity-file path when neither `--identity-file` nor the
/// config's `[server].identity_file` is available.
const DEFAULT_IDENTITY_FILE: &str = "/etc/yggdrasil/identity.key";

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Print this node's pubkey and fingerprint from the identity file.
    Show(ShowArgs),

    /// Generate a fresh identity key. Refuses to overwrite an existing file
    /// unless `--force` is given.
    Rotate(RotateArgs),

    /// Write an intro file (this node advertising itself as a downstream
    /// candidate).
    #[command(name = "export-intro")]
    ExportIntro(ExportIntroArgs),

    /// Apply an invite file: verify it targets this node and write
    /// `[dial]` into the daemon config.
    #[command(name = "add-upstream")]
    AddUpstream(AddUpstreamArgs),

    /// Apply an intro file: mint an invite for the introducer, and write
    /// `[accept]` into the daemon config.
    #[command(name = "add-downstream")]
    AddDownstream(AddDownstreamArgs),

    /// Remove `[dial]` from the daemon config.
    #[command(name = "remove-upstream")]
    RemoveUpstream,

    /// Remove `[accept]` from the daemon config.
    #[command(name = "remove-downstream")]
    RemoveDownstream,
}

#[derive(Debug, Args)]
pub struct ShowArgs {
    /// Override the identity file path. If unset, read from `[server].identity_file`
    /// in `--config`, falling back to `/etc/yggdrasil/identity.key`.
    #[arg(long)]
    identity_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct RotateArgs {
    /// Override the identity file path.
    #[arg(long)]
    identity_file: Option<PathBuf>,

    /// Overwrite an existing identity file. Without this flag, `rotate`
    /// refuses to clobber an existing key.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
pub struct ExportIntroArgs {
    /// Override the identity file path.
    #[arg(long)]
    identity_file: Option<PathBuf>,

    /// Where to write the intro file. Defaults to `intro.txt` in the current
    /// working directory.
    #[arg(short = 'o', long = "out", default_value = "intro.txt")]
    out: PathBuf,

    /// Free-form note included in the intro file (operator hint).
    #[arg(long, default_value = "")]
    note: String,
}

#[derive(Debug, Args)]
pub struct AddUpstreamArgs {
    /// Path to the invite file emitted by the upstream.
    #[arg(long = "from")]
    from: PathBuf,

    /// Override the identity file path (used to verify the invite targets us).
    #[arg(long)]
    identity_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct AddDownstreamArgs {
    /// Path to the intro file received from the prospective downstream.
    #[arg(long = "from")]
    from: PathBuf,

    /// The endpoint string (`host:port`) this node advertises as its
    /// upstream-facing address. Written into both the invite file and the
    /// `[dial].endpoint` field that the downstream will paste in.
    #[arg(long = "my-endpoint")]
    my_endpoint: String,

    /// Where to write the resulting invite file. Defaults to `invite.txt`.
    #[arg(short = 'o', long = "out", default_value = "invite.txt")]
    out: PathBuf,

    /// Override the identity file path (used to populate the invite's
    /// `upstream_pubkey`).
    #[arg(long)]
    identity_file: Option<PathBuf>,

    /// Free-form note included in the invite file.
    #[arg(long, default_value = "")]
    note: String,
}

pub async fn run(cmd: Cmd, config_path: &Path, json: bool) -> Result<()> {
    match cmd {
        Cmd::Show(a) => show(a, config_path, json),
        Cmd::Rotate(a) => rotate(a, config_path, json),
        Cmd::ExportIntro(a) => export_intro(a, config_path, json),
        Cmd::AddUpstream(a) => add_upstream(a, config_path, json),
        Cmd::AddDownstream(a) => add_downstream(a, config_path, json),
        Cmd::RemoveUpstream => remove_upstream(config_path, json),
        Cmd::RemoveDownstream => remove_downstream(config_path, json),
    }
}

// ---------- helpers ----------

/// Resolve the effective identity-file path:
///
/// 1. Explicit `--identity-file` flag wins.
/// 2. Else read `[server].identity_file` from `--config` if it exists and parses.
/// 3. Else fall back to `/etc/yggdrasil/identity.key`.
fn resolve_identity_file(explicit: Option<PathBuf>, config_path: &Path) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    if config_path.exists() {
        let text = std::fs::read_to_string(config_path)
            .with_context(|| format!("read {}", config_path.display()))?;
        if let Ok(doc) = text.parse::<toml::Value>() {
            if let Some(p) = doc
                .get("server")
                .and_then(|s| s.get("identity_file"))
                .and_then(|v| v.as_str())
            {
                return Ok(PathBuf::from(p));
            }
        }
    }
    Ok(PathBuf::from(DEFAULT_IDENTITY_FILE))
}

/// Load the config TOML for mutation. Returns the parsed `toml::Value` and
/// the path it was read from. If `path` does not exist, returns an empty
/// table so `add-upstream`/`add-downstream` can bootstrap a new file.
fn load_config_doc(path: &Path) -> Result<toml::Value> {
    if !path.exists() {
        return Ok(toml::Value::Table(toml::value::Table::new()));
    }
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    text.parse::<toml::Value>()
        .with_context(|| format!("parse {}", path.display()))
}

/// Atomically write `doc` back to `path` (tmp + rename). Creates parent
/// directories if needed.
fn save_config_doc(path: &Path, doc: &toml::Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    let serialised = toml::to_string_pretty(doc).context("serialise config TOML")?;
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, serialised).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

fn top_table_mut(doc: &mut toml::Value) -> Result<&mut toml::value::Table> {
    doc.as_table_mut()
        .ok_or_else(|| anyhow!("config is not a TOML table"))
}

fn print_kv(json: bool, kvs: &[(&str, &str)]) -> Result<()> {
    if json {
        let obj: serde_json::Map<String, serde_json::Value> = kvs
            .iter()
            .map(|(k, v)| ((*k).to_string(), serde_json::Value::String((*v).to_string())))
            .collect();
        println!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        for (k, v) in kvs {
            println!("{k:<18} {v}");
        }
    }
    Ok(())
}

// ---------- show ----------

fn show(args: ShowArgs, config_path: &Path, json: bool) -> Result<()> {
    let identity_file = resolve_identity_file(args.identity_file, config_path)?;
    if !identity_file.exists() {
        bail!(
            "no identity file at {}. Run `yggdrasilctl identity rotate` to \
             generate one, or start the yggdrasil daemon and it will be \
             auto-generated.",
            identity_file.display()
        );
    }
    let kp = StaticKeyPair::load_from_file(&identity_file)
        .with_context(|| format!("load {}", identity_file.display()))?;
    let pubkey = PubKey::X25519(*kp.public_key()).to_string();
    let fingerprint = kp.fingerprint();
    let path_str = identity_file.display().to_string();
    print_kv(
        json,
        &[
            ("identity_file:", path_str.as_str()),
            ("pubkey:", pubkey.as_str()),
            ("fingerprint:", fingerprint.as_str()),
        ],
    )
}

// ---------- rotate ----------

fn rotate(args: RotateArgs, config_path: &Path, json: bool) -> Result<()> {
    let identity_file = resolve_identity_file(args.identity_file, config_path)?;
    if identity_file.exists() && !args.force {
        bail!(
            "identity file already exists at {}. Re-run with `--force` to \
             rotate (the existing key will be permanently overwritten).",
            identity_file.display()
        );
    }
    // If --force, remove the old file so save_to_file's `create_new(true)`
    // semantics still apply (we always want exclusive create).
    if identity_file.exists() {
        std::fs::remove_file(&identity_file)
            .with_context(|| format!("removing old identity {}", identity_file.display()))?;
    }
    let kp = StaticKeyPair::generate().context("generate keypair")?;
    kp.save_to_file(&identity_file)
        .with_context(|| format!("write {}", identity_file.display()))?;
    let pubkey = PubKey::X25519(*kp.public_key()).to_string();
    let fingerprint = kp.fingerprint();
    let path_str = identity_file.display().to_string();
    print_kv(
        json,
        &[
            ("identity_file:", path_str.as_str()),
            ("pubkey:", pubkey.as_str()),
            ("fingerprint:", fingerprint.as_str()),
            ("action:", "generated"),
        ],
    )
}

// ---------- export-intro ----------

fn export_intro(args: ExportIntroArgs, config_path: &Path, json: bool) -> Result<()> {
    let identity_file = resolve_identity_file(args.identity_file, config_path)?;
    if !identity_file.exists() {
        bail!(
            "no identity file at {}. Run `yggdrasilctl identity rotate` first.",
            identity_file.display()
        );
    }
    let kp = StaticKeyPair::load_from_file(&identity_file)
        .with_context(|| format!("load {}", identity_file.display()))?;
    let pubkey = PubKey::X25519(*kp.public_key());
    let intro = IntroFile::new(pubkey, now_unix_secs(), args.note.clone());
    let toml_str = intro.to_toml().context("serialise intro file")?;
    write_file_secret(&args.out, toml_str.as_bytes())
        .with_context(|| format!("write {}", args.out.display()))?;
    let out_str = args.out.display().to_string();
    let fingerprint = kp.fingerprint();
    let pubkey_str = intro.intro.pubkey.to_string();
    print_kv(
        json,
        &[
            ("intro_file:", out_str.as_str()),
            ("pubkey:", pubkey_str.as_str()),
            ("fingerprint:", fingerprint.as_str()),
            ("note:", intro.intro.note.as_str()),
        ],
    )
}

// ---------- add-upstream ----------

fn add_upstream(args: AddUpstreamArgs, config_path: &Path, json: bool) -> Result<()> {
    let identity_file = resolve_identity_file(args.identity_file, config_path)?;
    if !identity_file.exists() {
        bail!(
            "no identity file at {}. Run `yggdrasilctl identity rotate` first.",
            identity_file.display()
        );
    }
    let kp = StaticKeyPair::load_from_file(&identity_file)
        .with_context(|| format!("load {}", identity_file.display()))?;
    let local_pubkey = PubKey::X25519(*kp.public_key());

    let invite = InviteFile::read(&args.from)
        .with_context(|| format!("read invite {}", args.from.display()))?;

    if invite.invite.downstream_pubkey != local_pubkey {
        bail!(
            "invite at {} targets pubkey {} (fp {}), but our identity is \
             {} (fp {}). Refusing to apply.",
            args.from.display(),
            invite.invite.downstream_pubkey,
            invite.invite.downstream_fingerprint,
            local_pubkey,
            kp.fingerprint(),
        );
    }

    let mut doc = load_config_doc(config_path)?;
    let top = top_table_mut(&mut doc)?;
    let dial_table = top
        .entry("dial".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()))
        .as_table_mut()
        .ok_or_else(|| anyhow!("`dial` is not a table"))?;
    dial_table.insert(
        "pubkey".to_string(),
        toml::Value::String(invite.invite.upstream_pubkey.to_string()),
    );
    dial_table.insert(
        "endpoint".to_string(),
        toml::Value::String(invite.invite.upstream_endpoint.clone()),
    );
    save_config_doc(config_path, &doc)?;

    let cfg_str = config_path.display().to_string();
    let upstream_pubkey_str = invite.invite.upstream_pubkey.to_string();
    print_kv(
        json,
        &[
            ("config:", cfg_str.as_str()),
            ("upstream_pubkey:", upstream_pubkey_str.as_str()),
            ("upstream_fingerprint:", invite.invite.upstream_fingerprint.as_str()),
            ("upstream_endpoint:", invite.invite.upstream_endpoint.as_str()),
            ("action:", "wrote_[dial]"),
        ],
    )?;
    eprintln!(
        "note: chain endpoints are wired at daemon startup; restart yggdrasil \
         to pick up the new [dial] section."
    );
    Ok(())
}

// ---------- add-downstream ----------

fn add_downstream(args: AddDownstreamArgs, config_path: &Path, json: bool) -> Result<()> {
    let identity_file = resolve_identity_file(args.identity_file, config_path)?;
    if !identity_file.exists() {
        bail!(
            "no identity file at {}. Run `yggdrasilctl identity rotate` first.",
            identity_file.display()
        );
    }
    let kp = StaticKeyPair::load_from_file(&identity_file)
        .with_context(|| format!("load {}", identity_file.display()))?;
    let upstream_pubkey = PubKey::X25519(*kp.public_key());

    // Validate endpoint shape: must contain a ':' (host:port). We don't
    // resolve DNS or check reachability here — that's the daemon's job at
    // startup.
    if !args.my_endpoint.contains(':') {
        bail!(
            "--my-endpoint must be a `host:port` string (got {:?})",
            args.my_endpoint
        );
    }

    let intro = IntroFile::read(&args.from)
        .with_context(|| format!("read intro {}", args.from.display()))?;
    let downstream_pubkey = intro.intro.pubkey;

    // Mint the invite.
    let invite = InviteFile::new(
        &intro,
        upstream_pubkey,
        args.my_endpoint.clone(),
        now_unix_secs(),
        args.note.clone(),
    );
    let invite_toml = invite.to_toml().context("serialise invite file")?;
    write_file_secret(&args.out, invite_toml.as_bytes())
        .with_context(|| format!("write {}", args.out.display()))?;

    // Mutate config: write `[accept].pubkey`. `listen` is left for the
    // operator to fill in (the daemon validator will surface a missing
    // `listen` field on the next restart).
    let mut doc = load_config_doc(config_path)?;
    let top = top_table_mut(&mut doc)?;
    let accept_table = top
        .entry("accept".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()))
        .as_table_mut()
        .ok_or_else(|| anyhow!("`accept` is not a table"))?;
    accept_table.insert(
        "pubkey".to_string(),
        toml::Value::String(downstream_pubkey.to_string()),
    );
    save_config_doc(config_path, &doc)?;

    let cfg_str = config_path.display().to_string();
    let out_str = args.out.display().to_string();
    let downstream_pubkey_str = downstream_pubkey.to_string();
    print_kv(
        json,
        &[
            ("config:", cfg_str.as_str()),
            ("invite_file:", out_str.as_str()),
            ("downstream_pubkey:", downstream_pubkey_str.as_str()),
            ("downstream_fingerprint:", invite.invite.downstream_fingerprint.as_str()),
            ("upstream_endpoint:", args.my_endpoint.as_str()),
            ("action:", "wrote_[accept]_and_invite"),
        ],
    )?;
    eprintln!(
        "note: chain endpoints are wired at daemon startup; restart yggdrasil \
         to pick up the new [accept] section. Ensure [accept].listen is also \
         configured."
    );
    Ok(())
}

// ---------- remove-upstream / remove-downstream ----------

fn remove_upstream(config_path: &Path, json: bool) -> Result<()> {
    remove_top_section(config_path, "dial", json)
}

fn remove_downstream(config_path: &Path, json: bool) -> Result<()> {
    remove_top_section(config_path, "accept", json)
}

fn remove_top_section(config_path: &Path, section: &str, json: bool) -> Result<()> {
    if !config_path.exists() {
        bail!(
            "no config file at {} — nothing to remove.",
            config_path.display()
        );
    }
    let mut doc = load_config_doc(config_path)?;
    let removed = {
        let top = top_table_mut(&mut doc)?;
        top.remove(section).is_some()
    };
    if !removed {
        bail!("no `[{section}]` section in {}", config_path.display());
    }
    save_config_doc(config_path, &doc)?;
    let cfg_str = config_path.display().to_string();
    let section_label = format!("[{section}]");
    print_kv(
        json,
        &[
            ("config:", cfg_str.as_str()),
            ("removed:", section_label.as_str()),
        ],
    )
}

// ---------- file helper ----------

/// Current UTC wall time in seconds since the Unix epoch. Used for intro /
/// invite `issued_at` stamps.
fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Write `bytes` to `path` with mode `0600`. Refuses to overwrite an
/// existing file (no `--force` flag for intro/invite output; callers should
/// pick a fresh path).
fn write_file_secret(path: &Path, bytes: &[u8]) -> Result<()> {
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
        .with_context(|| format!("create {}", path.display()))?;
    use std::io::Write;
    f.write_all(bytes)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}
