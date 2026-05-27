//! Server configuration schema (`/etc/yggdrasil/config.toml`).
//!
//! The config is organised into a small number of named tables:
//!
//! * `[server]` — paths and defaults.
//! * `[control]` — `yggdrasilctl` Unix-domain socket path.
//! * `[dial]` (optional) — this node's outbound chain client: who to
//!   dial, what to pin, how often to heartbeat. Drives both relay- and
//!   terminal-mode nodes when set.
//! * `[accept]` (optional) — single enrolled inbound chain peer plus its
//!   listener socket. When present and `pubkey` is set, the node listens
//!   for inbound chain traffic on `listen` and accepts only from `pubkey`.
//!
//! All public keys use the tagged textual form `<algo>:<hex>`; bare hex is
//! rejected.

use std::net::{IpAddr, SocketAddr};

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use ratatoskr::pubkey::PubKey;
use ratatoskr::Error as ProtoError;

/// Top-level server config file. Validated on load.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub server: ServerSection,
    #[serde(default)]
    pub control: ControlSection,
    /// Outbound chain client. When set, this node dials the configured
    /// upstream and sends heartbeats. Terminal-mode nodes with no upstream
    /// link omit this entirely.
    #[serde(default)]
    pub dial: Option<DialSection>,
    /// Inbound chain peer. When set, the node accepts inbound chain
    /// traffic on `listen` only from `pubkey`. v1 supports exactly one
    /// inbound peer per node.
    #[serde(default)]
    pub accept: Option<AcceptSection>,
    /// ACME (Let's Encrypt / RFC 8555) configuration for routes that
    /// declare `cert = "acme"`. Only meaningful on terminal-mode nodes
    /// (relays don't terminate TLS). The presence of this section also
    /// gates the daemon's per-host renewer task.
    #[serde(default)]
    pub acme: Option<AcmeSection>,
}

/// Effective runtime mode, derived from top-level chain section presence.
///
/// | mode       | `[dial]` | `[accept]` |
/// |------------|----------|------------|
/// | `Gateway`  | absent   | present    |
/// | `Relay`    | present  | present    |
/// | `Terminal` | present  | absent     |
///
/// (Both absent is rejected at config-load time.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Gateway,
    Relay,
    Terminal,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gateway => "gateway",
            Self::Relay => "relay",
            Self::Terminal => "terminal",
        }
    }
}

impl From<Mode> for ratatoskr::control::Mode {
    fn from(m: Mode) -> Self {
        match m {
            Mode::Gateway => Self::Gateway,
            Mode::Relay => Self::Relay,
            Mode::Terminal => Self::Terminal,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    /// Human-readable label for this node. Surfaced in `chain summary`,
    /// `chain ping`, `chain diff`, `chain health`, and `chain canary`
    /// outputs in place of the long X25519 pubkey. Falls back to
    /// `gethostname(3)` when unset. Free-form UTF-8, ≤ 32 bytes, no
    /// control characters, no embedded whitespace. Empty strings are
    /// treated as if the field were absent.
    #[serde(default)]
    pub name: Option<String>,
    /// Directory containing `*.toml` rule files. Defaults to `/etc/yggdrasil/conf.d`.
    #[serde(default = "default_rules_dir")]
    pub rules_dir: PathBuf,
    /// Hard-override for every rule's `listen` IP. When set, each rule binds on
    /// `(default_bind, rule.listen.port())` regardless of what the rule's TOML
    /// `listen` field specifies (the port is preserved). Use to share one
    /// config across hosts with different network interfaces.
    #[serde(default)]
    pub default_bind: Option<IpAddr>,
    /// Per-host default frontend worker count for SO_REUSEPORT fan-out
    /// across the daemon's accept paths (TCP listeners and UDP frontend
    /// sockets alike). `None` means resolve to
    /// `std::thread::available_parallelism()` when a proxy is spawned;
    /// `Some(n)` overrides that. `Some(0)` is rejected during validation.
    /// Applies daemon-wide — fan-out is a kernel-level concern (the
    /// kernel hash-distributes incoming SYNs / datagrams across the
    /// workers sharing an `addr:port`), so a per-rule override would
    /// not buy anything that a global default doesn't already provide.
    #[serde(default)]
    pub workers: Option<usize>,
    /// Per-host state directory (TOFU staging, runtime markers).
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    /// Path to the node's static X25519 identity. Auto-generated on first
    /// start if the file does not exist.
    #[serde(default = "default_identity_file")]
    pub identity_file: PathBuf,
    /// Root directory under which per-rule TLS material lives by convention.
    #[serde(default = "default_cert_dir")]
    pub cert_dir: PathBuf,
    /// Default TLS certificate (full chain, PEM) used by L7 `https` rules
    /// whose routes do not specify their own `cert`. Must be set together
    /// with `default_key` (XOR-validated on load).
    #[serde(default)]
    pub default_cert: Option<PathBuf>,
    /// Default TLS private key (PEM) paired with `default_cert`.
    #[serde(default)]
    pub default_key: Option<PathBuf>,
    /// Port for the per-IP HTTP→HTTPS redirect listener that the daemon
    /// auto-spawns for every `protocol = "https"` rule. Defaults to
    /// 80 (the standard). Set to a non-privileged port when the
    /// daemon is run without `CAP_NET_BIND_SERVICE` (typical for
    /// dev / bench / containerised deployments where binding to
    /// 80 isn't desired or possible). Set to `0` for an ephemeral
    /// (kernel-assigned) port — useful for integration tests.
    #[serde(default)]
    pub http_redirect_port: Option<u16>,
    /// Listener address for the node-wide HTTPS frontend. Routes
    /// declared via top-level `[[route]]` blocks attach here.
    /// Defaults to `0.0.0.0:443` (the standard).
    #[serde(default = "default_https_listen")]
    pub https_listen: SocketAddr,
    /// Node-wide HTTP/3 enable for the HTTPS frontend. `true` (default)
    /// makes the daemon bind UDP `https_listen` for QUIC in addition to
    /// the TCP HTTPS listener; `false` suppresses the UDP listener
    /// and the `Alt-Svc: h3=...` advertising header.
    #[serde(default = "default_true")]
    pub https_http3: bool,
    /// Node-wide `Alt-Svc: h3=...` header enable on TCP HTTPS responses.
    /// `true` (default) lets capable clients upgrade to HTTP/3 on the
    /// next request; `false` suppresses the header. Rejected at load
    /// when `https_http3 = false` (advertising a non-existent listener
    /// is a footgun).
    #[serde(default = "default_true")]
    pub https_alt_svc: bool,
    /// Maximum wall-clock time the daemon will wait, after receiving
    /// `SIGTERM`, for in-flight TCP connections / HTTPS requests to
    /// complete naturally before letting the tokio runtime abort
    /// them. UDP is per-datagram and not subject to drain.
    ///
    /// Default unset (`None`) preserves the historical behaviour:
    /// accept loops cancel immediately, in-flight tasks die when the
    /// runtime drops them. Set to a positive humantime value (e.g.
    /// `"30s"`) when you've drained external traffic out of yggdrasil
    /// at an upstream layer (DNS rotation, load-balancer health
    /// check) and want the daemon to finish whatever's still in
    /// flight before exiting — zero-downtime rolling restarts.
    ///
    /// Cooperates with systemd: while draining, the daemon emits
    /// `STOPPING=1` + `STATUS=Draining (...)` via `sd_notify` so
    /// `systemctl status` reflects what's happening. systemd's own
    /// `TimeoutStopSec=` is the outer bound — if it expires first
    /// the daemon is `SIGKILL`-ed regardless of this setting.
    #[serde(default, with = "humantime_serde::option")]
    pub graceful_drain_timeout: Option<Duration>,
    /// Opt-in NAT port-mapping for rule listeners, `[accept].listen`,
    /// HTTPS redirect, and HTTP/3 endpoints. `"auto"` tries PCP
    /// (RFC 6887) and falls back to NAT-PMP (RFC 6886) on
    /// unsupported-version / timeout. UPnP-IGD is intentionally not
    /// supported (SSDP multicast + SOAP/XML is a values mismatch).
    /// IPv4 only. Default `"off"` keeps zero-config deployments
    /// unaffected. See `docs/configuration.md` for the operator-
    /// facing behaviour matrix and CGNAT caveat.
    #[serde(default)]
    pub nat_traversal: crate::nat::NatTraversalMode,
    /// Override the default "private peer" CIDR set used by the per-IP
    /// companion listener to gate cert-less HTTPS route serving on
    /// `:80`. When `None` (the default), the hard-coded set in
    /// [`crate::lan_cidrs::DEFAULT_LAN_CIDR_STRINGS`] is used —
    /// loopback + RFC 1918 + RFC 4193, which on a typical home network
    /// is exactly the set of peers an operator wants to call "LAN".
    /// When `Some(list)`, the operator's list **replaces** the default
    /// entirely. `Some([])` means "no peer is local" — cert-less route
    /// serving is effectively disabled. Each entry must parse as a
    /// CIDR (e.g. `"192.168.1.0/24"`, `"::1/128"`); malformed entries
    /// are rejected at config-load time.
    ///
    /// This field only takes effect when at least one HTTPS rule has a
    /// cert-less route loaded — on daemons without any cert-less
    /// routes, the value is parsed and validated but never consulted.
    #[serde(default)]
    pub lan_cidrs: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlSection {
    /// Unix domain socket for `yggdrasilctl`. Should be group-readable by the
    /// admin group only.
    pub socket: PathBuf,
}

impl Default for ControlSection {
    fn default() -> Self {
        Self {
            socket: PathBuf::from("/run/yggdrasil/control.sock"),
        }
    }
}

/// `[dial]` — outbound chain client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DialSection {
    /// Tagged pubkey (`x25519:<hex>`) of the upstream node we dial.
    pub pubkey: PubKey,
    /// Endpoint to dial: `host:port` or `[ipv6]:port`. Re-resolved on
    /// every reconnection attempt; DNS rebinds during the lifetime of the
    /// daemon are honoured.
    pub endpoint: String,
    /// How often to send heartbeats. Default 5 s.
    #[serde(default = "default_heartbeat_interval", with = "humantime_serde")]
    pub heartbeat_interval: Duration,
    /// Re-handshake after at most this much time (default 1h).
    #[serde(default = "default_rekey_interval", with = "humantime_serde")]
    pub rekey_interval: Duration,
}

/// `[accept]` — single enrolled inbound chain peer plus its listener socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptSection {
    /// Tagged pubkey (`x25519:<hex>`) of the enrolled inbound peer.
    pub pubkey: PubKey,
    /// UDP socket to bind on. Required.
    pub listen: SocketAddr,
    /// Re-handshake after at most this much time (default 1h).
    #[serde(default = "default_rekey_interval", with = "humantime_serde")]
    pub rekey_interval: Duration,
}

/// `[acme]` — ACME (RFC 8555) configuration for the node-wide
/// wildcard cert. Only meaningful on terminal-mode nodes (relays
/// passthrough TLS bytes without terminating). When this section is
/// absent, the daemon doesn't try to issue any cert; HTTPS routes
/// fall through to the convention dir, then to `default_cert`, then
/// to the cert-less LAN path.
///
/// One terminal holds one wildcard cert covering the apex + a single
/// star: SAN list `["<domain>", "*.<domain>"]`. Wildcards force
/// DNS-01, so the daemon picks the (single) provider sub-table
/// `[acme.dns.<name>]`. Zero or 2+ provider sub-tables are rejected
/// at load.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeSection {
    /// ACME directory URL. Defaults to Let's Encrypt production.
    /// Override with the LE staging endpoint
    /// (`https://acme-staging-v02.api.letsencrypt.org/directory`) when
    /// shaking out the renewer.
    #[serde(default = "default_acme_directory_url")]
    pub directory_url: String,
    /// Contact email registered with the ACME account. Used by the CA
    /// to notify the operator about impending expirations or account
    /// problems.
    pub contact_email: String,
    /// Apex domain to issue against. Expands at issuance time to the
    /// SAN list `["<domain>", "*.<domain>"]` so the resulting cert
    /// covers the apex and one level of subdomains.
    pub domain: String,
    /// Where to persist the long-lived ACME account key. Auto-generated
    /// on first use; mode `0600`.
    #[serde(default = "default_acme_account_key_path")]
    pub account_key_path: PathBuf,
    /// Where renewed certs land on disk. Defaults to
    /// `[server].cert_dir` so the existing `CertWatcher` reload
    /// pipeline picks them up automatically.
    #[serde(default)]
    pub storage_dir: Option<PathBuf>,
    /// Operator must explicitly opt in to the ACME directory's ToS.
    /// Rejected at config load if `false` or absent.
    #[serde(default)]
    pub terms_of_service_agreed: bool,
    /// Renew certs this far in advance of `not_after`. Default 30 days.
    #[serde(default = "default_acme_renew_before", with = "humantime_serde")]
    pub renew_before: Duration,
    /// Random jitter added to the renewal time to spread load. Default
    /// 12 hours; the actual schedule is `not_after - renew_before -
    /// rand(0..renew_jitter)`.
    #[serde(default = "default_acme_renew_jitter", with = "humantime_serde")]
    pub renew_jitter: Duration,
    /// DNS provider sub-tables keyed by provider name. Exactly one
    /// sub-table is required. Names recognized today: `cloudflare`.
    #[serde(default)]
    pub dns: std::collections::BTreeMap<String, AcmeDnsProviderConfig>,
}

/// Catch-all DNS-provider credentials block. Each provider implementation
/// knows how to interpret its own fields; the schema here is intentionally
/// loose so adding a new provider doesn't require touching the schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeDnsProviderConfig {
    /// Inline API token (string). Mutually exclusive with `api_token_env`;
    /// at least one must be set for the Cloudflare provider.
    #[serde(default)]
    pub api_token: Option<String>,
    /// Name of an environment variable holding the API token.
    /// Operator-facing best practice — keeps secrets out of the config
    /// file. Mutually exclusive with `api_token`.
    #[serde(default)]
    pub api_token_env: Option<String>,
}

fn default_state_dir() -> PathBuf {
    PathBuf::from("/var/lib/yggdrasil")
}
fn default_identity_file() -> PathBuf {
    PathBuf::from("/etc/yggdrasil/identity.key")
}
fn default_rules_dir() -> PathBuf {
    PathBuf::from("/etc/yggdrasil/conf.d")
}
fn default_cert_dir() -> PathBuf {
    PathBuf::from("/etc/yggdrasil/certs")
}
fn default_https_listen() -> SocketAddr {
    "0.0.0.0:443".parse().unwrap()
}
fn default_true() -> bool {
    true
}
fn default_rekey_interval() -> Duration {
    Duration::from_secs(3600)
}
fn default_heartbeat_interval() -> Duration {
    Duration::from_secs(5)
}
fn default_acme_directory_url() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}
fn default_acme_account_key_path() -> PathBuf {
    PathBuf::from("/var/lib/yggdrasil/acme/account.key")
}
fn default_acme_renew_before() -> Duration {
    Duration::from_secs(30 * 86_400)
}
fn default_acme_renew_jitter() -> Duration {
    Duration::from_secs(12 * 3600)
}

/// Maximum byte length of `[server].name`. Keeps wire propagation
/// through `ChainHop` cheap and renderers predictable.
pub const SERVER_NAME_MAX_BYTES: usize = 32;

/// Validate `[server].name` shape. Rejects names that exceed
/// [`SERVER_NAME_MAX_BYTES`], contain control characters, or contain
/// any ASCII whitespace (including embedded spaces).
fn validate_server_name(name: &str) -> Result<(), ConfigError> {
    if name.is_empty() {
        // Empty string is treated identically to "absent" by callers;
        // it is not an error in itself, but the resolver will fall
        // back to gethostname(3) for an empty value too.
        return Ok(());
    }
    if name.len() > SERVER_NAME_MAX_BYTES {
        return Err(ConfigError::Invalid(format!(
            "[server].name must be <= {SERVER_NAME_MAX_BYTES} bytes (got {} bytes)",
            name.len(),
        )));
    }
    if name.chars().any(|c| c.is_control()) {
        return Err(ConfigError::Invalid(
            "[server].name must not contain control characters".into(),
        ));
    }
    if name.chars().any(|c| c.is_whitespace()) {
        return Err(ConfigError::Invalid(
            "[server].name must not contain whitespace".into(),
        ));
    }
    Ok(())
}

/// Read the kernel's hostname via `gethostname(3)`. Used as the
/// fallback for `[server].name` when the operator hasn't set one.
/// On any failure (extremely rare — kernel always provides one) the
/// fallback returns `"unknown"` so renderers always have something
/// non-empty to display.
fn read_hostname_or_unknown() -> String {
    // SAFETY: gethostname is async-signal-safe and writes at most
    // `buf.len()` bytes plus a trailing NUL. We allocate
    // HOST_NAME_MAX + 1 = 65 bytes and locate the NUL terminator
    // ourselves; if gethostname returns -1 we fall back to "unknown".
    const BUFLEN: usize = 65;
    let mut buf = [0u8; BUFLEN];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, BUFLEN) };
    if rc != 0 {
        return "unknown".to_string();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(BUFLEN);
    let name = std::str::from_utf8(&buf[..end]).unwrap_or("unknown");
    // Apply the same shape constraints as a user-configured name:
    // a hostname containing whitespace, control characters, or being
    // longer than SERVER_NAME_MAX_BYTES gets truncated and sanitised
    // so the renderer never sees a malformed string. This is a
    // last-resort fallback; operators wanting a controlled value
    // should set `[server].name` explicitly.
    let mut sanitised: String = name
        .chars()
        .filter(|c| !c.is_control() && !c.is_whitespace())
        .collect();
    if sanitised.is_empty() {
        return "unknown".to_string();
    }
    if sanitised.len() > SERVER_NAME_MAX_BYTES {
        // Truncate on a char boundary to keep UTF-8 valid.
        sanitised.truncate(
            sanitised
                .char_indices()
                .take_while(|(idx, _)| *idx <= SERVER_NAME_MAX_BYTES)
                .last()
                .map(|(idx, _)| idx)
                .unwrap_or(SERVER_NAME_MAX_BYTES),
        );
    }
    sanitised
}

/// Resolve the effective node label for this daemon. Returns the
/// configured `[server].name` when non-empty, otherwise the kernel
/// hostname (sanitised; falls back to `"unknown"` if hostname lookup
/// fails). Always non-empty.
pub fn resolve_server_name(configured: Option<&str>) -> String {
    match configured {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => read_hostname_or_unknown(),
    }
}

impl ServerConfig {
    /// Load and validate a config file from disk.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
            path: path.to_path_buf(),
            source: e,
        })?;
        let cfg: ServerConfig = toml::from_str(&raw).map_err(|e| {
            ConfigError::Proto(ProtoError::TomlParse {
                path: path.to_path_buf(),
                source: e,
            })
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Derive effective runtime mode from section presence.
    pub fn derived_mode(&self) -> Result<Mode, ConfigError> {
        match (self.dial.is_some(), self.accept.is_some()) {
            (false, true) => Ok(Mode::Gateway),
            (true, true) => Ok(Mode::Relay),
            (true, false) => Ok(Mode::Terminal),
            (false, false) => Err(ConfigError::Invalid(
                "config must define at least one of [dial] or [accept]".into(),
            )),
        }
    }

    /// Resolve the effective node label. See [`resolve_server_name`] for
    /// the resolution rules. Always non-empty, suitable for direct
    /// embedding in `ChainHop.name` and CLI renderers.
    pub fn resolved_name(&self) -> String {
        resolve_server_name(self.server.name.as_deref())
    }

    /// Validate the in-memory config.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // ---- Derived mode shape ----
        let _ = self.derived_mode()?;

        // ---- [server] sanity ----
        if matches!(self.server.workers, Some(0)) {
            return Err(ConfigError::Invalid(
                "[server].workers must be >= 1 when set".into(),
            ));
        }
        if let Some(name) = &self.server.name {
            validate_server_name(name)?;
        }

        // ---- [dial] sanity ----
        if let Some(up) = &self.dial {
            if up.endpoint.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "[dial].endpoint must not be empty".into(),
                ));
            }
            if !up.endpoint.contains(':') {
                return Err(ConfigError::Invalid(format!(
                    "[dial].endpoint must be host:port (got {:?})",
                    up.endpoint
                )));
            }
            if up.heartbeat_interval.is_zero() {
                return Err(ConfigError::Invalid(
                    "[dial].heartbeat_interval must be > 0".into(),
                ));
            }
            if up.rekey_interval.is_zero() {
                return Err(ConfigError::Invalid(
                    "[dial].rekey_interval must be > 0".into(),
                ));
            }
        }

        // ---- [accept] sanity ----
        if let Some(acc) = &self.accept {
            if acc.rekey_interval.is_zero() {
                return Err(ConfigError::Invalid(
                    "[accept].rekey_interval must be > 0".into(),
                ));
            }
        }

        // ---- TLS default cert/key XOR ----
        match (&self.server.default_cert, &self.server.default_key) {
            (Some(_), None) => {
                return Err(ConfigError::Invalid(
                    "server.default_cert is set but server.default_key is not; \
                     both must be set together or both omitted"
                        .into(),
                ));
            }
            (None, Some(_)) => {
                return Err(ConfigError::Invalid(
                    "server.default_key is set but server.default_cert is not; \
                     both must be set together or both omitted"
                        .into(),
                ));
            }
            _ => {}
        }

        // ---- [server].lan_cidrs parse check ----
        // Only validate the strings here; resolution into the runtime
        // `LanCidrs` snapshot happens in the supervisor at rule-load
        // time. We pre-check syntax so a malformed entry fails fast at
        // config load rather than at first cert-less request.
        if let Some(list) = &self.server.lan_cidrs {
            for s in list {
                if let Err(e) = crate::lan_cidrs::IpCidr::parse(s) {
                    return Err(ConfigError::Invalid(format!("[server].lan_cidrs: {}", e)));
                }
            }
        }

        // ---- HTTPS knob sanity ----
        if self.server.https_alt_svc && !self.server.https_http3 {
            return Err(ConfigError::Invalid(
                "[server].https_alt_svc = true is incompatible with \
                 [server].https_http3 = false — an Alt-Svc header would \
                 advertise a non-existent listener"
                    .into(),
            ));
        }
        if self.server.https_listen.port() == 0 {
            return Err(ConfigError::Invalid(
                "[server].https_listen must have a non-zero port".into(),
            ));
        }

        // ---- [acme] sanity ----
        if let Some(acme) = &self.acme {
            if !acme.terms_of_service_agreed {
                return Err(ConfigError::Invalid(
                    "[acme].terms_of_service_agreed = true must be set explicitly \
                     to acknowledge the ACME directory's terms of service"
                        .into(),
                ));
            }
            if acme.contact_email.trim().is_empty() || !acme.contact_email.contains('@') {
                return Err(ConfigError::Invalid(format!(
                    "[acme].contact_email must be a valid address (got {:?})",
                    acme.contact_email
                )));
            }
            if acme.domain.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "[acme].domain must not be empty".into(),
                ));
            }
            if acme.directory_url.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "[acme].directory_url must not be empty".into(),
                ));
            }
            if acme.renew_before.is_zero() {
                return Err(ConfigError::Invalid(
                    "[acme].renew_before must be > 0".into(),
                ));
            }
            // Wildcards force DNS-01, so exactly one [acme.dns.<name>]
            // sub-table is required. Zero or 2+ is rejected — the
            // operator must declare the provider unambiguously.
            match acme.dns.len() {
                0 => {
                    return Err(ConfigError::Invalid(
                        "[acme] requires exactly one [acme.dns.<provider>] \
                         sub-table; got none"
                            .into(),
                    ));
                }
                1 => {}
                n => {
                    let names: Vec<&str> = acme.dns.keys().map(String::as_str).collect();
                    return Err(ConfigError::Invalid(format!(
                        "[acme] requires exactly one [acme.dns.<provider>] \
                         sub-table; got {n}: {names:?}",
                    )));
                }
            }
            for (name, prov) in &acme.dns {
                match (&prov.api_token, &prov.api_token_env) {
                    (Some(_), Some(_)) => {
                        return Err(ConfigError::Invalid(format!(
                            "[acme.dns.{name}]: api_token and api_token_env \
                             are mutually exclusive",
                        )));
                    }
                    (None, None) => {
                        return Err(ConfigError::Invalid(format!(
                            "[acme.dns.{name}]: one of api_token or \
                             api_token_env must be set",
                        )));
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Convenience: return the SAN list the ACME wildcard should be
    /// issued against — apex plus a single `*.<apex>` star.
    pub fn acme_sans(&self) -> Option<Vec<String>> {
        self.acme
            .as_ref()
            .map(|a| vec![a.domain.clone(), format!("*.{}", a.domain)])
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(transparent)]
    Proto(#[from] ProtoError),
    #[error("invalid config: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<ServerConfig, ConfigError> {
        let cfg: ServerConfig = toml::from_str(s).map_err(|e| {
            ConfigError::Proto(ProtoError::TomlParse {
                path: PathBuf::from("test.toml"),
                source: e,
            })
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn relay_minimal_toml() -> &'static str {
        r#"
        [server]

        [accept]
        pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        listen = "0.0.0.0:51820"
        "#
    }

    fn terminal_minimal_toml() -> &'static str {
        r#"
        [server]

        [dial]
        pubkey   = "x25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        endpoint = "u.example.com:7117"
        "#
    }

    #[test]
    fn derived_mode_is_gateway_when_accept_only() {
        let cfg = parse(relay_minimal_toml()).unwrap();
        assert_eq!(cfg.derived_mode().unwrap(), Mode::Gateway);
    }

    #[test]
    fn derived_mode_is_terminal_when_dial_only() {
        let cfg = parse(terminal_minimal_toml()).unwrap();
        assert_eq!(cfg.derived_mode().unwrap(), Mode::Terminal);
    }

    #[test]
    fn derived_mode_is_relay_when_dial_and_accept_present() {
        let cfg = parse(
            r#"
            [server]

            [dial]
            pubkey   = "x25519:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            endpoint = "u.example.com:7117"

            [accept]
            pubkey = "x25519:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            listen = "0.0.0.0:51820"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.derived_mode().unwrap(), Mode::Relay);
    }

    #[test]
    fn missing_dial_and_accept_is_rejected() {
        let err = parse(
            r#"
            [server]
            "#,
        )
        .err()
        .unwrap();
        assert!(
            matches!(err, ConfigError::Invalid(s) if s.contains("at least one of [dial] or [accept]"))
        );
    }

    #[test]
    fn rules_dir_defaults_to_conf_d() {
        let cfg = parse(relay_minimal_toml()).unwrap();
        assert_eq!(cfg.server.rules_dir, PathBuf::from("/etc/yggdrasil/conf.d"));
    }

    #[test]
    fn rules_dir_override_parses() {
        let cfg = parse(
            r#"
            [server]
            rules_dir = "/srv/yggdrasil/rules"

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.server.rules_dir, PathBuf::from("/srv/yggdrasil/rules"));
    }

    #[test]
    fn default_bind_parses() {
        let cfg = parse(
            r#"
            [server]
            default_bind = "192.168.1.5"

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
            "#,
        )
        .unwrap();
        assert_eq!(
            cfg.server.default_bind,
            Some("192.168.1.5".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn workers_defaults_to_none() {
        let cfg = parse(relay_minimal_toml()).unwrap();
        assert_eq!(cfg.server.workers, None);
    }

    #[test]
    fn workers_override_parses() {
        let cfg = parse(
            r#"
            [server]
            workers = 4

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.server.workers, Some(4));
    }

    #[test]
    fn workers_zero_is_rejected() {
        let err = parse(
            r#"
            [server]
            workers = 0

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
            "#,
        )
        .err()
        .unwrap();
        assert!(matches!(err, ConfigError::Invalid(s)
                if s.contains("[server].workers must be >= 1 when set")));
    }

    // ---- [server].name ----

    #[test]
    fn name_defaults_to_none() {
        let cfg = parse(relay_minimal_toml()).unwrap();
        assert_eq!(cfg.server.name, None);
    }

    #[test]
    fn name_parses_when_set() {
        let cfg = parse(
            r#"
            [server]
            name = "vps"

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.server.name.as_deref(), Some("vps"));
    }

    #[test]
    fn name_empty_string_is_accepted_but_resolves_to_hostname() {
        let cfg = parse(
            r#"
            [server]
            name = ""

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.server.name.as_deref(), Some(""));
        // resolved_name falls through to the hostname for empty values.
        assert!(!cfg.resolved_name().is_empty());
    }

    #[test]
    fn name_too_long_is_rejected() {
        let too_long = "a".repeat(SERVER_NAME_MAX_BYTES + 1);
        let toml = format!(
            r#"
            [server]
            name = "{too_long}"

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
            "#,
        );
        let err = parse(&toml).err().unwrap();
        assert!(
            matches!(err, ConfigError::Invalid(ref s) if s.contains("[server].name must be <=")),
            "expected size rejection, got: {err:?}"
        );
    }

    #[test]
    fn name_with_whitespace_is_rejected() {
        let err = parse(
            r#"
            [server]
            name = "vps prod"

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
            "#,
        )
        .err()
        .unwrap();
        assert!(
            matches!(err, ConfigError::Invalid(ref s) if s.contains("must not contain whitespace")),
            "expected whitespace rejection, got: {err:?}"
        );
    }

    #[test]
    fn name_with_control_char_is_rejected() {
        let err = parse(
            "
            [server]
            name = \"vps\\n\"

            [accept]
            pubkey = \"x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"
            listen = \"0.0.0.0:51820\"
            ",
        )
        .err()
        .unwrap();
        // `\n` is both whitespace and a control char; whichever check
        // fires first is acceptable. We assert that a control-or-
        // whitespace error path was taken.
        assert!(
            matches!(err, ConfigError::Invalid(ref s)
                if s.contains("must not contain control characters")
                    || s.contains("must not contain whitespace")),
            "expected control/whitespace rejection, got: {err:?}"
        );
    }

    #[test]
    fn resolved_name_uses_configured_value_when_set() {
        let cfg = parse(
            r#"
            [server]
            name = "vps"

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.resolved_name(), "vps");
    }

    #[test]
    fn resolved_name_falls_back_to_hostname_when_unset() {
        let cfg = parse(relay_minimal_toml()).unwrap();
        // gethostname always returns *something* on Linux; the
        // resolver guarantees non-empty.
        let resolved = cfg.resolved_name();
        assert!(!resolved.is_empty());
        assert!(resolved.len() <= SERVER_NAME_MAX_BYTES);
    }

    // ---- [server].nat_traversal ----

    #[test]
    fn nat_traversal_defaults_to_off_when_absent() {
        let cfg = parse(relay_minimal_toml()).unwrap();
        assert_eq!(cfg.server.nat_traversal, crate::nat::NatTraversalMode::Off);
    }

    #[test]
    fn nat_traversal_parses_off() {
        let cfg = parse(
            r#"
            [server]
            nat_traversal = "off"

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.server.nat_traversal, crate::nat::NatTraversalMode::Off);
    }

    #[test]
    fn nat_traversal_parses_pcp() {
        let cfg = parse(
            r#"
            [server]
            nat_traversal = "pcp"

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.server.nat_traversal, crate::nat::NatTraversalMode::Pcp);
    }

    #[test]
    fn nat_traversal_parses_natpmp() {
        let cfg = parse(
            r#"
            [server]
            nat_traversal = "natpmp"

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
            "#,
        )
        .unwrap();
        assert_eq!(
            cfg.server.nat_traversal,
            crate::nat::NatTraversalMode::NatPmp
        );
    }

    #[test]
    fn nat_traversal_parses_auto() {
        let cfg = parse(
            r#"
            [server]
            nat_traversal = "auto"

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.server.nat_traversal, crate::nat::NatTraversalMode::Auto);
    }

    #[test]
    fn nat_traversal_rejects_unknown_variant() {
        // UPnP is intentionally not a valid variant; we want misuse
        // to fail loudly at config-load time rather than silently
        // disable the feature.
        let err = parse(
            r#"
            [server]
            nat_traversal = "upnp"

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
            "#,
        )
        .err()
        .unwrap();
        assert!(matches!(err, ConfigError::Proto(_)));
    }

    #[test]
    fn nat_traversal_is_case_sensitive() {
        // serde rename_all = "lowercase" — uppercase must be rejected.
        let err = parse(
            r#"
            [server]
            nat_traversal = "Off"

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
            "#,
        )
        .err()
        .unwrap();
        assert!(matches!(err, ConfigError::Proto(_)));
    }

    #[test]
    fn unknown_field_is_rejected() {
        let err = parse(
            r#"
            [server]
            branches_dir = "/etc/yggdrasil/branches"
            "#,
        )
        .err()
        .unwrap();
        assert!(matches!(err, ConfigError::Proto(_)));
    }

    #[test]
    fn cert_dir_defaults_to_etc_yggdrasil_certs() {
        let cfg = parse(relay_minimal_toml()).unwrap();
        assert_eq!(cfg.server.cert_dir, PathBuf::from("/etc/yggdrasil/certs"));
    }

    #[test]
    fn default_cert_and_key_set_together_parses() {
        let cfg = parse(
            r#"
            [server]
            default_cert = "/etc/yggdrasil/certs/wildcard.pem"
            default_key  = "/etc/yggdrasil/certs/wildcard.key"

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
            "#,
        )
        .unwrap();
        assert!(cfg.server.default_cert.is_some());
        assert!(cfg.server.default_key.is_some());
    }

    #[test]
    fn default_cert_without_key_is_rejected() {
        let err = parse(
            r#"
            [server]
            default_cert = "/etc/yggdrasil/certs/wildcard.pem"

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
            "#,
        )
        .err()
        .unwrap();
        assert!(matches!(err, ConfigError::Invalid(s)
                if s.contains("default_cert is set but server.default_key is not")));
    }

    #[test]
    fn default_key_without_cert_is_rejected() {
        let err = parse(
            r#"
            [server]
            default_key = "/etc/yggdrasil/certs/wildcard.key"

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
            "#,
        )
        .err()
        .unwrap();
        assert!(matches!(err, ConfigError::Invalid(s)
                if s.contains("default_key is set but server.default_cert is not")));
    }

    // ---- [server].lan_cidrs ----

    #[test]
    fn lan_cidrs_absent_parses_as_none() {
        let cfg = parse(
            r#"
            [server]

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
            "#,
        )
        .unwrap();
        assert!(cfg.server.lan_cidrs.is_none());
    }

    #[test]
    fn lan_cidrs_parses_v4_and_v6_mixed() {
        let cfg = parse(
            r#"
            [server]
            lan_cidrs = ["192.168.1.0/24", "fc00::/7"]

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
            "#,
        )
        .unwrap();
        let list = cfg.server.lan_cidrs.as_ref().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0], "192.168.1.0/24");
        assert_eq!(list[1], "fc00::/7");
    }

    #[test]
    fn lan_cidrs_empty_array_parses() {
        // [] is the "no peer is local" opt-out, distinct from absent.
        let cfg = parse(
            r#"
            [server]
            lan_cidrs = []

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
            "#,
        )
        .unwrap();
        let list = cfg.server.lan_cidrs.as_ref().unwrap();
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn lan_cidrs_malformed_entry_rejected() {
        let err = parse(
            r#"
            [server]
            lan_cidrs = ["not-a-cidr"]

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
            "#,
        )
        .err()
        .unwrap();
        assert!(
            matches!(&err, ConfigError::Invalid(s) if s.contains("lan_cidrs")),
            "expected lan_cidrs parse error, got {:?}",
            err
        );
    }

    #[test]
    fn lan_cidrs_oversized_prefix_rejected() {
        let err = parse(
            r#"
            [server]
            lan_cidrs = ["10.0.0.0/40"]

            [accept]
            pubkey = "x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            listen = "0.0.0.0:51820"
            "#,
        )
        .err()
        .unwrap();
        assert!(
            matches!(&err, ConfigError::Invalid(s) if s.contains("lan_cidrs")),
            "expected lan_cidrs prefix-too-large error, got {:?}",
            err
        );
    }

    // ---- [dial] ----

    #[test]
    fn parses_dial_section() {
        let cfg = parse(
            r#"
            [server]

            [dial]
            pubkey   = "x25519:1111111111111111111111111111111111111111111111111111111111111111"
            endpoint = "u.example.com:7117"
            "#,
        )
        .unwrap();
        let up = cfg.dial.expect("dial parsed");
        assert_eq!(up.endpoint, "u.example.com:7117");
        assert_eq!(up.heartbeat_interval, Duration::from_secs(5));
        assert_eq!(up.rekey_interval, Duration::from_secs(3600));
        assert_eq!(
            up.pubkey,
            PubKey::X25519([0x11; ratatoskr::auth::PUBLIC_KEY_LEN])
        );
    }

    #[test]
    fn dial_rejects_untagged_pubkey() {
        let err = parse(
            r#"
            [server]

            [dial]
            pubkey   = "1111111111111111111111111111111111111111111111111111111111111111"
            endpoint = "host:1"
            "#,
        )
        .err()
        .unwrap();
        assert!(matches!(err, ConfigError::Proto(_)));
    }

    #[test]
    fn dial_rejects_empty_endpoint() {
        let err = parse(
            r#"
            [server]

            [dial]
            pubkey   = "x25519:1111111111111111111111111111111111111111111111111111111111111111"
            endpoint = ""
            "#,
        )
        .err()
        .unwrap();
        assert!(matches!(err, ConfigError::Invalid(s) if s.contains("endpoint must not be empty")));
    }

    #[test]
    fn dial_rejects_endpoint_without_port() {
        let err = parse(
            r#"
            [server]

            [dial]
            pubkey   = "x25519:1111111111111111111111111111111111111111111111111111111111111111"
            endpoint = "host-no-port"
            "#,
        )
        .err()
        .unwrap();
        assert!(matches!(err, ConfigError::Invalid(s) if s.contains("host:port")));
    }

    #[test]
    fn dial_parses_humantime_intervals() {
        let cfg = parse(
            r#"
            [server]

            [dial]
            pubkey             = "x25519:2222222222222222222222222222222222222222222222222222222222222222"
            endpoint           = "host:1"
            heartbeat_interval = "2s"
            rekey_interval     = "30m"
            "#,
        )
        .unwrap();
        let up = cfg.dial.unwrap();
        assert_eq!(up.heartbeat_interval, Duration::from_secs(2));
        assert_eq!(up.rekey_interval, Duration::from_secs(30 * 60));
    }

    // ---- [accept] ----

    #[test]
    fn relay_with_accept_section_parses() {
        let cfg = parse(
            r#"
            [server]

            [accept]
            pubkey = "x25519:3333333333333333333333333333333333333333333333333333333333333333"
            listen = "0.0.0.0:51820"
            "#,
        )
        .unwrap();
        let acc = cfg.accept.expect("accept parsed");
        assert_eq!(
            acc.pubkey,
            PubKey::X25519([0x33; ratatoskr::auth::PUBLIC_KEY_LEN])
        );
        assert_eq!(acc.listen, "0.0.0.0:51820".parse::<SocketAddr>().unwrap());
        assert_eq!(acc.rekey_interval, Duration::from_secs(3600));
    }

    #[test]
    fn accept_missing_listen_is_rejected() {
        let err = parse(
            r#"
            [server]

            [accept]
            pubkey = "x25519:4444444444444444444444444444444444444444444444444444444444444444"
            "#,
        )
        .err()
        .unwrap();
        // Missing required `listen` is a TOML / serde deserialisation error,
        // surfaced through ConfigError::Proto.
        assert!(matches!(err, ConfigError::Proto(_)));
    }

    #[test]
    fn accept_missing_pubkey_is_rejected() {
        let err = parse(
            r#"
            [server]

            [accept]
            listen = "0.0.0.0:51820"
            "#,
        )
        .err()
        .unwrap();
        assert!(matches!(err, ConfigError::Proto(_)));
    }

    #[test]
    fn terminal_mode_accepts_only_dial() {
        let cfg = parse(
            r#"
            [server]

            [dial]
            pubkey   = "x25519:6666666666666666666666666666666666666666666666666666666666666666"
            endpoint = "u.example.com:7117"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.derived_mode().unwrap(), Mode::Terminal);
        assert!(cfg.dial.is_some());
        assert!(cfg.accept.is_none());
    }

    #[test]
    fn relay_with_both_dial_and_accept_parses() {
        let cfg = parse(
            r#"
            [server]

            [dial]
            pubkey   = "x25519:7777777777777777777777777777777777777777777777777777777777777777"
            endpoint = "uu.example.com:7117"

            [accept]
            pubkey = "x25519:8888888888888888888888888888888888888888888888888888888888888888"
            listen = "0.0.0.0:51820"
            "#,
        )
        .unwrap();
        assert!(cfg.dial.is_some());
        assert!(cfg.accept.is_some());
    }

    #[test]
    fn empty_chain_sections_are_invalid() {
        let err = parse(
            r#"
            [server]
            "#,
        )
        .err()
        .unwrap();
        assert!(
            matches!(err, ConfigError::Invalid(s) if s.contains("at least one of [dial] or [accept]"))
        );
    }

    #[test]
    fn https_listen_defaults_to_443() {
        let cfg = parse(
            r#"
            [server]
            [accept]
            listen = "0.0.0.0:51820"
            pubkey = "x25519:0000000000000000000000000000000000000000000000000000000000000000"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.server.https_listen.port(), 443);
        assert!(cfg.server.https_http3);
        assert!(cfg.server.https_alt_svc);
    }

    #[test]
    fn https_alt_svc_true_with_http3_false_is_rejected() {
        let err = parse(
            r#"
            [server]
            https_http3   = false
            https_alt_svc = true
            [accept]
            listen = "0.0.0.0:51820"
            pubkey = "x25519:0000000000000000000000000000000000000000000000000000000000000000"
            "#,
        )
        .err()
        .unwrap();
        assert!(matches!(
            err,
            ConfigError::Invalid(s) if s.contains("https_alt_svc = true") && s.contains("https_http3 = false")
        ));
    }

    #[test]
    fn acme_with_one_dns_provider_parses() {
        let cfg = parse(
            r#"
            [server]
            [dial]
            pubkey   = "x25519:0000000000000000000000000000000000000000000000000000000000000000"
            endpoint = "vps.example.com:51820"
            [acme]
            contact_email           = "ops@example.com"
            terms_of_service_agreed = true
            domain                  = "example.com"
              [acme.dns.cloudflare]
              api_token_env = "CLOUDFLARE_API_TOKEN"
            "#,
        )
        .unwrap();
        let acme = cfg.acme.as_ref().expect("acme present");
        assert_eq!(acme.domain, "example.com");
        assert_eq!(
            cfg.acme_sans(),
            Some(vec!["example.com".to_string(), "*.example.com".to_string()])
        );
    }

    #[test]
    fn acme_without_domain_is_rejected() {
        let err = parse(
            r#"
            [server]
            [dial]
            pubkey   = "x25519:0000000000000000000000000000000000000000000000000000000000000000"
            endpoint = "vps.example.com:51820"
            [acme]
            contact_email           = "ops@example.com"
            terms_of_service_agreed = true
              [acme.dns.cloudflare]
              api_token_env = "CLOUDFLARE_API_TOKEN"
            "#,
        )
        .err()
        .unwrap();
        // Missing `domain` is a parse error (it's required, no default).
        assert!(matches!(
            err,
            ConfigError::Proto(_) | ConfigError::Invalid(_)
        ));
    }

    #[test]
    fn acme_without_dns_subtable_is_rejected() {
        let err = parse(
            r#"
            [server]
            [dial]
            pubkey   = "x25519:0000000000000000000000000000000000000000000000000000000000000000"
            endpoint = "vps.example.com:51820"
            [acme]
            contact_email           = "ops@example.com"
            terms_of_service_agreed = true
            domain                  = "example.com"
            "#,
        )
        .err()
        .unwrap();
        assert!(matches!(
            err,
            ConfigError::Invalid(s) if s.contains("[acme.dns.<provider>]") && s.contains("got none")
        ));
    }

    #[test]
    fn acme_with_two_dns_subtables_is_rejected() {
        let err = parse(
            r#"
            [server]
            [dial]
            pubkey   = "x25519:0000000000000000000000000000000000000000000000000000000000000000"
            endpoint = "vps.example.com:51820"
            [acme]
            contact_email           = "ops@example.com"
            terms_of_service_agreed = true
            domain                  = "example.com"
              [acme.dns.cloudflare]
              api_token_env = "CF_TOKEN"
              [acme.dns.route53]
              api_token_env = "AWS_TOKEN"
            "#,
        )
        .err()
        .unwrap();
        assert!(matches!(
            err,
            ConfigError::Invalid(s) if s.contains("got 2")
        ));
    }
}
