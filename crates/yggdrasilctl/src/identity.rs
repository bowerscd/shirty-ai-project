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
//! * Request file (`request.txt` by convention): emitted by a node that
//!   wants to be enrolled as a `dial`-side peer. Contains this node's
//!   tagged pubkey and a self-fingerprint.
//! * Grant file (`grant.txt` by convention): emitted by an accept-side
//!   peer after consuming a request. Contains both pubkeys + the
//!   accept-side's reachable endpoint. Hand-delivered back to the
//!   requester (the issuer of the original request), which feeds it to
//!   `identity add-dial`.
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};

use ratatoskr::auth::StaticKeyPair;
use ratatoskr::enrollment::{GrantFile, RequestFile};
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

    /// Write a request file (this node asking to be enrolled as a
    /// `dial`-side peer).
    #[command(name = "export-request")]
    ExportRequest(ExportRequestArgs),

    /// Apply a grant file: verify it targets this node and write
    /// `[dial]` into the daemon config.
    #[command(name = "add-dial")]
    AddDial(AddDialArgs),

    /// Apply a request file: mint a grant for the requester, and write
    /// `[accept]` into the daemon config.
    #[command(name = "add-accept")]
    AddAccept(AddAcceptArgs),

    /// Remove `[dial]` from the daemon config.
    #[command(name = "remove-dial")]
    RemoveDial,

    /// Remove `[accept]` from the daemon config.
    #[command(name = "remove-accept")]
    RemoveAccept,
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
    /// refuses to clobber an existing key. When the identity file is
    /// absent (fresh install), `--force` is a no-op.
    #[arg(long)]
    force: bool,

    /// Skip the interactive fingerprint-confirmation prompt. Required for
    /// non-interactive overwrite of an existing identity. Use only when
    /// you have already audited the chain enrollments that this rotation
    /// will break (`identity show` lists the breakage). Pair with
    /// `--force`.
    #[arg(long = "yes-i-understand-this-breaks-existing-chains")]
    yes_i_understand_this_breaks_existing_chains: bool,
}

#[derive(Debug, Args)]
pub struct ExportRequestArgs {
    /// Override the identity file path.
    #[arg(long)]
    identity_file: Option<PathBuf>,

    /// Where to write the request file. When omitted, the request TOML
    /// is printed to stdout (operators can pipe it directly or redirect
    /// to a file). When supplied, the file is written with 0600 perms.
    #[arg(short = 'o', long = "out")]
    out: Option<PathBuf>,

    /// Free-form note included in the request file (operator hint).
    #[arg(long, default_value = "")]
    note: String,
}

#[derive(Debug, Args)]
pub struct AddDialArgs {
    /// Path to the grant file emitted by the accept-side.
    #[arg(long = "from")]
    from: PathBuf,

    /// Override the identity file path (used to verify the grant targets us).
    #[arg(long)]
    identity_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct AddAcceptArgs {
    /// Path to the request file received from the prospective dial-side peer.
    #[arg(long = "from")]
    from: PathBuf,

    /// The endpoint string (`host:port`) this node advertises as its
    /// accept-side reachable address. Written into both the grant file
    /// and the `[dial].endpoint` field that the requester will paste in.
    #[arg(long = "my-endpoint")]
    my_endpoint: String,

    /// Where to write the resulting grant file. Defaults to `grant.txt`.
    #[arg(short = 'o', long = "out", default_value = "grant.txt")]
    out: PathBuf,

    /// Override the identity file path (used to populate the grant's
    /// `accept_pubkey`).
    #[arg(long)]
    identity_file: Option<PathBuf>,

    /// Free-form note included in the grant file.
    #[arg(long, default_value = "")]
    note: String,
}

pub async fn run(cmd: Cmd, config_path: &Path, json: bool) -> Result<()> {
    match cmd {
        Cmd::Show(a) => show(a, config_path, json),
        Cmd::Rotate(a) => rotate(a, config_path, json),
        Cmd::ExportRequest(a) => export_request(a, config_path, json),
        Cmd::AddDial(a) => add_dial(a, config_path, json),
        Cmd::AddAccept(a) => add_accept(a, config_path, json),
        Cmd::RemoveDial => remove_dial(config_path, json),
        Cmd::RemoveAccept => remove_accept(config_path, json),
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
/// table so `add-dial`/`add-accept` can bootstrap a new file.
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

    // Existing identity → must confirm before clobbering.
    if identity_file.exists() {
        if !args.force {
            bail!(
                "identity file already exists at {}. Re-run with `--force` to \
                 rotate (the existing key will be permanently overwritten). \
                 Rotation invalidates every chain enrollment that pins this \
                 node's pubkey, so audit `identity show` first.",
                identity_file.display()
            );
        }

        // Load the current keypair so we know which fingerprint operators
        // must type to confirm.
        let current_kp = StaticKeyPair::load_from_file(&identity_file)
            .with_context(|| format!("load {}", identity_file.display()))?;
        let current_fp = current_kp.fingerprint();
        let current_short = &current_fp[..8];

        // Enumerate breakage from the daemon config (if it exists).
        let enrollments = list_chain_enrollments(config_path);

        eprintln!(
            "Rotating identity at {} (current fingerprint {}).",
            identity_file.display(),
            current_fp
        );
        eprintln!(
            "After rotation, peers that pin this node's pubkey must be \
             re-enrolled (issue a fresh invite/intro pair)."
        );
        if enrollments.is_empty() {
            eprintln!(
                "  No `[dial]` or `[accept]` enrollments are configured in {}.",
                config_path.display()
            );
        } else {
            eprintln!(
                "Chain enrollments in {} that will break:",
                config_path.display()
            );
            for e in &enrollments {
                eprintln!("  - [{}] peer={} {}", e.section, e.peer_pubkey, e.endpoint_label);
            }
        }

        if !args.yes_i_understand_this_breaks_existing_chains {
            // Interactive confirmation: must type the short fingerprint of
            // the *current* (about-to-be-replaced) identity.
            use std::io::{IsTerminal, Write};
            let stdin = std::io::stdin();
            if !stdin.is_terminal() {
                bail!(
                    "rotation of an existing identity requires interactive \
                     confirmation (stdin is not a TTY). Re-run with \
                     `--yes-i-understand-this-breaks-existing-chains` to \
                     skip the prompt for scripted use."
                );
            }
            eprintln!(
                "\nType the current identity's short fingerprint ({} hex chars) to confirm:",
                current_short.len()
            );
            eprint!("> ");
            std::io::stderr().flush().ok();
            let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .context("read confirmation from stdin")?;
            let typed = line.trim().to_ascii_lowercase();
            if typed != current_short.to_ascii_lowercase() {
                bail!(
                    "fingerprint mismatch (expected `{}`, got `{}`). Aborting \
                     rotation; identity file unchanged.",
                    current_short,
                    typed
                );
            }
        }

        // Confirmed — remove the old file so save_to_file's `create_new(true)`
        // semantics still apply (we always want exclusive create).
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

/// One enumerated chain enrollment that pins this node's identity. Used to
/// list breakage before a `rotate`.
struct EnrollmentEntry {
    /// `"dial"` or `"accept"`.
    section: &'static str,
    /// Peer's tagged pubkey (`x25519:<hex>`).
    peer_pubkey: String,
    /// Human-readable endpoint hint (`endpoint=...` for dial, `listen=...`
    /// for accept).
    endpoint_label: String,
}

/// Read `config_path` and return the `[dial]` / `[accept]` enrollments
/// declared there. Tolerant of a missing or unparseable config (returns an
/// empty list); enumeration is best-effort and only ever displayed to the
/// operator as breakage hints.
fn list_chain_enrollments(config_path: &Path) -> Vec<EnrollmentEntry> {
    let mut out = Vec::new();
    let Ok(text) = std::fs::read_to_string(config_path) else {
        return out;
    };
    let Ok(doc) = text.parse::<toml::Value>() else {
        return out;
    };
    if let Some(dial) = doc.get("dial").and_then(|v| v.as_table()) {
        let pk = dial
            .get("pubkey")
            .and_then(|v| v.as_str())
            .unwrap_or("<unset>")
            .to_string();
        let ep = dial
            .get("endpoint")
            .and_then(|v| v.as_str())
            .unwrap_or("<unset>");
        out.push(EnrollmentEntry {
            section: "dial",
            peer_pubkey: pk,
            endpoint_label: format!("endpoint={ep}"),
        });
    }
    if let Some(accept) = doc.get("accept").and_then(|v| v.as_table()) {
        let pk = accept
            .get("pubkey")
            .and_then(|v| v.as_str())
            .unwrap_or("<unset>")
            .to_string();
        let listen = accept
            .get("listen")
            .and_then(|v| v.as_str())
            .unwrap_or("<unset>");
        out.push(EnrollmentEntry {
            section: "accept",
            peer_pubkey: pk,
            endpoint_label: format!("listen={listen}"),
        });
    }
    out
}

// ---------- export-request ----------

fn export_request(args: ExportRequestArgs, config_path: &Path, json: bool) -> Result<()> {
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
    let req = RequestFile::new(pubkey, now_unix_secs(), args.note.clone());
    let toml_str = req.to_toml().context("serialise request file")?;

    let fingerprint = kp.fingerprint();
    let pubkey_str = req.request.pubkey.to_string();

    match args.out.as_ref() {
        Some(path) => {
            write_file_secret(path, toml_str.as_bytes())
                .with_context(|| format!("write {}", path.display()))?;
            let out_str = path.display().to_string();
            print_kv(
                json,
                &[
                    ("request_file:", out_str.as_str()),
                    ("pubkey:", pubkey_str.as_str()),
                    ("fingerprint:", fingerprint.as_str()),
                    ("note:", req.request.note.as_str()),
                ],
            )
        }
        None => {
            // Stdout default: emit only the request TOML body so the
            // output can be piped directly into the accept-side's
            // `identity add-accept --from -` workflow without
            // any text-mode chrome to strip first. Diagnostic
            // metadata (pubkey/fingerprint/note) goes to stderr so
            // pipelines stay clean while the operator still sees
            // what was emitted.
            print!("{toml_str}");
            if !json {
                eprintln!("pubkey:      {pubkey_str}");
                eprintln!("fingerprint: {fingerprint}");
                if !req.request.note.is_empty() {
                    eprintln!("note:        {}", req.request.note);
                }
            }
            Ok(())
        }
    }
}

// ---------- add-dial ----------

fn add_dial(args: AddDialArgs, config_path: &Path, json: bool) -> Result<()> {
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

    let grant = GrantFile::read(&args.from)
        .with_context(|| format!("read grant {}", args.from.display()))?;

    if grant.grant.dial_pubkey != local_pubkey {
        bail!(
            "grant at {} targets pubkey {} (fp {}), but our identity is \
             {} (fp {}). Refusing to apply.",
            args.from.display(),
            grant.grant.dial_pubkey,
            grant.grant.dial_fingerprint,
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
        toml::Value::String(grant.grant.accept_pubkey.to_string()),
    );
    dial_table.insert(
        "endpoint".to_string(),
        toml::Value::String(grant.grant.accept_endpoint.clone()),
    );
    save_config_doc(config_path, &doc)?;

    let cfg_str = config_path.display().to_string();
    let accept_pubkey_str = grant.grant.accept_pubkey.to_string();
    print_kv(
        json,
        &[
            ("config:", cfg_str.as_str()),
            ("accept_pubkey:", accept_pubkey_str.as_str()),
            ("accept_fingerprint:", grant.grant.accept_fingerprint.as_str()),
            ("accept_endpoint:", grant.grant.accept_endpoint.as_str()),
            ("action:", "wrote_[dial]"),
        ],
    )?;
    eprintln!(
        "note: chain endpoints are wired at daemon startup; restart yggdrasil \
         to pick up the new [dial] section."
    );
    Ok(())
}

// ---------- add-accept ----------

fn add_accept(args: AddAcceptArgs, config_path: &Path, json: bool) -> Result<()> {
    let identity_file = resolve_identity_file(args.identity_file, config_path)?;
    if !identity_file.exists() {
        bail!(
            "no identity file at {}. Run `yggdrasilctl identity rotate` first.",
            identity_file.display()
        );
    }
    let kp = StaticKeyPair::load_from_file(&identity_file)
        .with_context(|| format!("load {}", identity_file.display()))?;
    let accept_pubkey = PubKey::X25519(*kp.public_key());

    // Validate endpoint shape: must contain a ':' (host:port). We don't
    // resolve DNS or check reachability here — that's the daemon's job at
    // startup.
    if !args.my_endpoint.contains(':') {
        bail!(
            "--my-endpoint must be a `host:port` string (got {:?})",
            args.my_endpoint
        );
    }

    let req = RequestFile::read(&args.from)
        .with_context(|| format!("read request {}", args.from.display()))?;
    let dial_pubkey = req.request.pubkey;

    // Mint the grant.
    let grant = GrantFile::new(
        &req,
        accept_pubkey,
        args.my_endpoint.clone(),
        now_unix_secs(),
        args.note.clone(),
    );
    let grant_toml = grant.to_toml().context("serialise grant file")?;
    write_file_secret(&args.out, grant_toml.as_bytes())
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
        toml::Value::String(dial_pubkey.to_string()),
    );
    save_config_doc(config_path, &doc)?;

    let cfg_str = config_path.display().to_string();
    let out_str = args.out.display().to_string();
    let dial_pubkey_str = dial_pubkey.to_string();
    print_kv(
        json,
        &[
            ("config:", cfg_str.as_str()),
            ("grant_file:", out_str.as_str()),
            ("dial_pubkey:", dial_pubkey_str.as_str()),
            ("dial_fingerprint:", grant.grant.dial_fingerprint.as_str()),
            ("accept_endpoint:", args.my_endpoint.as_str()),
            ("action:", "wrote_[accept]_and_grant"),
        ],
    )?;
    eprintln!(
        "note: chain endpoints are wired at daemon startup; restart yggdrasil \
         to pick up the new [accept] section. Ensure [accept].listen is also \
         configured."
    );
    Ok(())
}

// ---------- remove-dial / remove-accept ----------

fn remove_dial(config_path: &Path, json: bool) -> Result<()> {
    remove_top_section(config_path, "dial", json)
}

fn remove_accept(config_path: &Path, json: bool) -> Result<()> {
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
