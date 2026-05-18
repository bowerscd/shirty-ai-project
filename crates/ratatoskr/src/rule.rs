//! Rule (proxy-rule) schema and TOML deserialisation.
//!
//! A *rule file* lives at `/etc/yggdrasil/conf.d/<name>.toml` and contains
//! one or more `[[rule]]` blocks. Splitting rules across files is purely an
//! operator convenience — the runtime semantics are determined by the
//! aggregated rule set across the whole directory.
//!
//! Example (relay-mode rules — dial the heartbeat-discovered peer IP):
//!
//! ```toml
//! [[rule]]
//! name           = "minecraft-survival"
//! listen         = "0.0.0.0:25565"
//! protocol       = "tcp"
//! upstream_port  = 25565
//! proxy_protocol = "v2"          # optional, off by default
//!
//! [[rule]]
//! name           = "minecraft-bedrock"
//! listen         = "0.0.0.0:19132"
//! protocol       = "udp"
//! upstream_port  = 19132
//! idle_timeout   = "30s"          # optional, defaults to 60s for udp
//! ```
//!
//! Example (terminal-mode rules — dial a fixed LAN address):
//!
//! ```toml
//! [[rule]]
//! name          = "home-ssh"
//! listen        = "0.0.0.0:2222"
//! protocol      = "tcp"
//! upstream_addr = "192.168.1.10:22"
//!
//! [[rule]]
//! name          = "home-dns"
//! listen        = "0.0.0.0:53"
//! protocol      = "udp"
//! upstream_addr = "192.168.1.1:53"
//! idle_timeout  = "30s"
//! ```
//!
//! Example (HTTPS L7 frontend — terminal-mode only, terminates TLS and
//! reverse-proxies to multiple LAN backends by hostname):
//!
//! ```toml
//! [[rule]]
//! name     = "home-https"
//! listen   = "0.0.0.0:443"
//! protocol = "https"
//!
//!   [[rule.route]]
//!   hostname = "api.home.example"
//!   upstream = "http://192.168.1.10:8080"
//!   cert     = "/etc/yggdrasil/certs/api.home.example/fullchain.pem"
//!   key      = "/etc/yggdrasil/certs/api.home.example/privkey.pem"
//!   hsts     = true
//!
//!   [[rule.route]]
//!   hostname = "app.local"
//!   upstream = "http://192.168.1.11:3000"
//!   cert     = "ephemeral"          # self-signed, in-memory, 10y validity
//! ```
//!
//! ## Validation
//!
//! Per-rule:
//! * `name` is non-empty and contains no whitespace or control characters.
//! * `idle_timeout` is only meaningful for UDP; setting it on a TCP or
//!   HTTPS rule is rejected.
//! * `proxy_protocol` is only meaningful for TCP; setting it on a UDP or
//!   HTTPS rule is rejected.
//! * `listen` port must be non-zero (binding to port 0 makes no sense for a
//!   fixed-listener proxy).
//! * For `protocol = "tcp" | "udp"`: exactly one of `upstream_port` /
//!   `upstream_addr` is set (XOR). `upstream_port`, when set, must be
//!   non-zero; `upstream_addr`, when set, must have a non-zero port.
//! * `proxy_protocol` is rejected when `upstream_addr` is set — terminal
//!   rules cannot emit headers (the relay's header passes through verbatim).
//! * For `protocol = "https"`: `routes` is present and non-empty;
//!   `upstream_port` / `upstream_addr` / `proxy_protocol` / `idle_timeout`
//!   are all absent. Per-route invariants: hostname is a syntactically
//!   valid DNS name (no duplicates within the rule); `upstream` URL scheme
//!   is `"http"` with explicit host + port; `cert` as a path requires `key`
//!   alongside; `cert = "ephemeral"` requires the hostname to match
//!   `localhost`, `*.localhost`, or `*.local`.
//!
//! Cross-file:
//! * `name` must be globally unique.
//! * `listen` socket address must be globally unique (no two rules can claim
//!   the same `(ip, port, protocol)` triple — different protocols *can* share
//!   `(ip, port)`).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use url::Url;

use crate::error::{Error, Result};

/// Transport protocol selected per-rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    /// HTTPS L7 frontend (terminal mode only): terminates TLS and reverse-
    /// proxies to per-hostname HTTP backends. The set of backends lives in
    /// the per-rule `routes` array; see [`HttpRoute`].
    Https,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Https => "https",
        }
    }
}

/// HAProxy PROXY-protocol version selector for TCP rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProto {
    V1,
    V2,
}

/// HTTP Strict-Transport-Security policy attached to a single HTTPS route.
///
/// TOML accepts two shapes:
/// * `hsts = true` shorthand — equivalent to
///   `[rule.route.hsts] max_age = 31536000 include_subdomains = false
///   preload = false`.
/// * Explicit block `[rule.route.hsts]` with any subset of the three fields
///   (missing fields default the same way).
///
/// `hsts = false` and absence both mean "no `Strict-Transport-Security`
/// header" — they are normalised to `Option::None` at the [`HttpRoute`]
/// level by [`HstsConfig::deserialize`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct HstsConfig {
    /// `max-age` in seconds. Default: one year (31_536_000).
    pub max_age: u32,
    /// Emit `includeSubDomains`.
    pub include_subdomains: bool,
    /// Emit `preload`. Setting this without going through the browser-vendor
    /// preload-list submission process is a deployment footgun; the field
    /// exists for operators who know what they're doing.
    pub preload: bool,
}

/// Default `max-age` for an HSTS shorthand (`hsts = true`): one year.
pub const DEFAULT_HSTS_MAX_AGE: u32 = 31_536_000;

impl Default for HstsConfig {
    fn default() -> Self {
        Self {
            max_age: DEFAULT_HSTS_MAX_AGE,
            include_subdomains: false,
            preload: false,
        }
    }
}

impl<'de> Deserialize<'de> for HstsConfig {
    fn deserialize<D>(de: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{Error as _, Unexpected, Visitor};
        use std::fmt;

        struct HstsVisitor;

        impl<'de> Visitor<'de> for HstsVisitor {
            type Value = HstsConfig;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    "either `true` (shorthand for one-year HSTS) or a table \
                     with `max_age`, `include_subdomains`, `preload`",
                )
            }

            fn visit_bool<E: serde::de::Error>(self, v: bool) -> std::result::Result<HstsConfig, E> {
                if v {
                    Ok(HstsConfig::default())
                } else {
                    // `hsts = false` is consumed at the HttpRoute layer
                    // (see Option<HstsConfig>'s custom deserialise). Hitting
                    // this branch here means an operator placed a bare
                    // `false` outside the Option context; surface that as an
                    // error rather than silently producing the default.
                    Err(E::invalid_value(
                        Unexpected::Bool(false),
                        &"`hsts = false` or omit the field entirely",
                    ))
                }
            }

            fn visit_map<M>(self, mut map: M) -> std::result::Result<HstsConfig, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                let mut max_age: Option<u32> = None;
                let mut include_subdomains: Option<bool> = None;
                let mut preload: Option<bool> = None;
                while let Some(k) = map.next_key::<String>()? {
                    match k.as_str() {
                        "max_age" => {
                            if max_age.is_some() {
                                return Err(M::Error::custom("duplicate field `max_age`"));
                            }
                            max_age = Some(map.next_value()?);
                        }
                        "include_subdomains" => {
                            if include_subdomains.is_some() {
                                return Err(M::Error::custom(
                                    "duplicate field `include_subdomains`",
                                ));
                            }
                            include_subdomains = Some(map.next_value()?);
                        }
                        "preload" => {
                            if preload.is_some() {
                                return Err(M::Error::custom("duplicate field `preload`"));
                            }
                            preload = Some(map.next_value()?);
                        }
                        other => {
                            return Err(M::Error::unknown_field(
                                other,
                                &["max_age", "include_subdomains", "preload"],
                            ));
                        }
                    }
                }
                Ok(HstsConfig {
                    max_age: max_age.unwrap_or(DEFAULT_HSTS_MAX_AGE),
                    include_subdomains: include_subdomains.unwrap_or(false),
                    preload: preload.unwrap_or(false),
                })
            }
        }

        de.deserialize_any(HstsVisitor)
    }
}

/// Source of the certificate served for a route's hostname.
///
/// * `Path` — a fully-qualified file path on disk. Must be accompanied by
///   `HttpRoute.key`.
/// * `Ephemeral` — sentinel telling the daemon to generate a self-signed
///   keypair in memory at startup, valid for ten years. Local-dev only;
///   browsers will warn.
///
/// TOML deserialisation is bespoke: the literal string `"ephemeral"` maps
/// to [`CertSource::Ephemeral`] and any other string maps to
/// [`CertSource::Path`]. A table is rejected — paths must be inline strings,
/// not nested structures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertSource {
    Path(PathBuf),
    Ephemeral,
}

impl Serialize for CertSource {
    fn serialize<S>(&self, ser: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Ephemeral => ser.serialize_str("ephemeral"),
            Self::Path(p) => ser.serialize_str(&p.to_string_lossy()),
        }
    }
}

impl<'de> Deserialize<'de> for CertSource {
    fn deserialize<D>(de: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Visitor;
        use std::fmt;

        struct CertSourceVisitor;

        impl Visitor<'_> for CertSourceVisitor {
            type Value = CertSource;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(r#"either the literal string "ephemeral" or a path string"#)
            }

            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> std::result::Result<CertSource, E> {
                if v == "ephemeral" {
                    Ok(CertSource::Ephemeral)
                } else if v.is_empty() {
                    Err(E::custom("cert: empty string is not a valid path"))
                } else {
                    Ok(CertSource::Path(PathBuf::from(v)))
                }
            }
        }

        de.deserialize_str(CertSourceVisitor)
    }
}

/// A single HTTPS route attached to a `Protocol::Https` rule.
///
/// Routes are matched by exact `Host` header against the inbound request
/// (after SNI). All fields beyond `hostname` and `upstream` are optional.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRoute {
    /// DNS hostname the route is served as. Matched as an exact, case-
    /// insensitive string against both SNI and the `Host` header.
    pub hostname: String,
    /// Plaintext HTTP upstream URL — must use scheme `http` and include an
    /// explicit host + port (path/query are ignored; only the authority is
    /// used to dial the backend).
    pub upstream: Url,
    /// Certificate source for this hostname. Precedence when resolving
    /// effective cert at load time:
    /// 1. `cert == Some(Path(p))` plus `key` → load `p` + `key` from disk.
    /// 2. `cert == Some(Ephemeral)` → generate in memory.
    /// 3. Convention dir `{rule.cert_dir | server.cert_dir}/{hostname}/`
    ///    containing `fullchain.pem` + `privkey.pem`.
    /// 4. Global `[server].default_cert` / `default_key`.
    ///
    /// See the per-rule schema (`Rule::validate`) and `CertStore` (in the
    /// `yggdrasil` crate) for the actual lookup loop. This proto-level
    /// schema only enforces local-shape invariants.
    #[serde(default)]
    pub cert: Option<CertSource>,
    /// Private-key file alongside `cert = Path(...)`. Rejected if `cert` is
    /// `Ephemeral` or absent.
    #[serde(default)]
    pub key: Option<PathBuf>,
    /// HTTP Strict-Transport-Security policy. See [`HstsConfig`] for the
    /// shorthand-vs-table TOML shapes. `None` means no header is emitted.
    #[serde(default, deserialize_with = "deserialize_optional_hsts")]
    pub hsts: Option<HstsConfig>,
}

/// `hsts = false` and absence both deserialise to `None`. Any other value
/// is delegated to [`HstsConfig::deserialize`].
fn deserialize_optional_hsts<'de, D>(de: D) -> std::result::Result<Option<HstsConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Visitor;
    use std::fmt;

    struct OptHstsVisitor;

    impl<'de> Visitor<'de> for OptHstsVisitor {
        type Value = Option<HstsConfig>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(
                "either `true`, `false`, or a table with `max_age`, \
                 `include_subdomains`, `preload`",
            )
        }

        fn visit_bool<E: serde::de::Error>(self, v: bool) -> std::result::Result<Self::Value, E> {
            Ok(if v { Some(HstsConfig::default()) } else { None })
        }

        fn visit_map<M>(self, map: M) -> std::result::Result<Self::Value, M::Error>
        where
            M: serde::de::MapAccess<'de>,
        {
            // Delegate the map shape to HstsConfig's own deserialiser.
            HstsConfig::deserialize(serde::de::value::MapAccessDeserializer::new(map)).map(Some)
        }

        fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_none<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D: Deserializer<'de>>(
            self,
            de: D,
        ) -> std::result::Result<Self::Value, D::Error> {
            de.deserialize_any(OptHstsVisitor)
        }
    }

    de.deserialize_any(OptHstsVisitor)
}

/// A single proxy rule as deserialised from a `[[rule]]` table.
///
/// Exactly one of `upstream_port` / `upstream_addr` is set for L4
/// (`protocol = "tcp" | "udp"`):
/// * `upstream_port` — relay mode. The destination IP is supplied by the
///   heartbeat-discovered peer at runtime; this field selects the port.
/// * `upstream_addr` — terminal mode. A fixed LAN socket dialed verbatim.
///
/// For L7 (`protocol = "https"`) the dial targets live inside the per-rule
/// `routes` array; neither `upstream_port` nor `upstream_addr` may be set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Human-friendly identifier. Must be globally unique across all rule files.
    pub name: String,
    /// Local socket on which yggdrasil listens for client connections / datagrams.
    pub listen: SocketAddr,
    /// `"tcp"`, `"udp"`, or `"https"`.
    pub protocol: Protocol,
    /// Relay mode: destination port on the upstream peer (the residential host's
    /// IP comes from the heartbeat, not from this file). XOR with `upstream_addr`.
    /// Forbidden when `protocol = "https"`.
    #[serde(default)]
    pub upstream_port: Option<u16>,
    /// Terminal mode: fixed LAN socket address dialed verbatim. XOR with
    /// `upstream_port`. Forbidden when `protocol = "https"`.
    #[serde(default)]
    pub upstream_addr: Option<SocketAddr>,
    /// UDP only: time without activity before a flow is evicted from the flow table.
    /// Default applied at load time (see [`Rule::resolved_idle_timeout`]).
    #[serde(default, with = "humantime_serde::option")]
    pub idle_timeout: Option<Duration>,
    /// TCP only: emit a PROXY-protocol header to the upstream before forwarding.
    /// Rejected when `upstream_addr` is set (terminal rules must not synthesise
    /// PROXY-protocol headers; relay-written headers pass through verbatim).
    #[serde(default)]
    pub proxy_protocol: Option<ProxyProto>,
    /// HTTPS only: required, non-empty list of per-hostname routes. See
    /// [`HttpRoute`]. Forbidden when `protocol = "tcp" | "udp"`.
    #[serde(default, rename = "route")]
    pub routes: Option<Vec<HttpRoute>>,
    /// HTTPS only: override of the convention cert directory for this
    /// rule's routes. Absent → fall back to `[server].cert_dir`.
    #[serde(default)]
    pub cert_dir: Option<PathBuf>,
}

/// Default UDP idle timeout if a rule does not specify one.
pub const DEFAULT_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

impl Rule {
    /// Validate per-rule invariants. Returns `Error::InvalidRule` with a
    /// human-readable message on failure.
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(Error::InvalidRule("rule name is empty".into()));
        }
        if self.name.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(Error::InvalidRule(format!(
                "rule name {:?} contains whitespace or control characters",
                self.name
            )));
        }
        if self.listen.port() == 0 {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: listen port must be non-zero",
                self.name
            )));
        }
        match self.protocol {
            Protocol::Tcp | Protocol::Udp => self.validate_l4(),
            Protocol::Https => self.validate_l7(),
        }
    }

    /// Per-protocol checks for TCP/UDP rules.
    fn validate_l4(&self) -> Result<()> {
        // HTTPS-only fields must be absent.
        if self.routes.is_some() {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: `route` blocks are only valid for protocol = \"https\"",
                self.name
            )));
        }
        if self.cert_dir.is_some() {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: `cert_dir` is only valid for protocol = \"https\"",
                self.name
            )));
        }

        match (self.upstream_port, self.upstream_addr) {
            (Some(_), Some(_)) => {
                return Err(Error::InvalidRule(format!(
                    "rule {:?}: set exactly one of upstream_port (relay) or \
                     upstream_addr (terminal), not both",
                    self.name
                )));
            }
            (None, None) => {
                return Err(Error::InvalidRule(format!(
                    "rule {:?}: must set exactly one of upstream_port (relay) \
                     or upstream_addr (terminal)",
                    self.name
                )));
            }
            (Some(0), _) => {
                return Err(Error::InvalidRule(format!(
                    "rule {:?}: upstream_port must be non-zero",
                    self.name
                )));
            }
            (_, Some(addr)) if addr.port() == 0 => {
                return Err(Error::InvalidRule(format!(
                    "rule {:?}: upstream_addr port must be non-zero",
                    self.name
                )));
            }
            _ => {}
        }
        if self.upstream_addr.is_some() && self.proxy_protocol.is_some() {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: proxy_protocol is invalid on terminal rules \
                 (upstream_addr is set); relay-written headers pass through verbatim",
                self.name
            )));
        }
        match self.protocol {
            Protocol::Tcp => {
                if self.idle_timeout.is_some() {
                    return Err(Error::InvalidRule(format!(
                        "rule {:?}: idle_timeout is only valid for udp rules",
                        self.name
                    )));
                }
            }
            Protocol::Udp => {
                if self.proxy_protocol.is_some() {
                    return Err(Error::InvalidRule(format!(
                        "rule {:?}: proxy_protocol is only valid for tcp rules",
                        self.name
                    )));
                }
            }
            Protocol::Https => unreachable!("dispatched in validate()"),
        }
        Ok(())
    }

    /// Per-protocol checks for HTTPS rules.
    fn validate_l7(&self) -> Result<()> {
        // L4 dial-target fields must all be absent.
        if self.upstream_port.is_some() {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: `upstream_port` is not valid for protocol = \
                 \"https\" (dial targets live in [[rule.route]])",
                self.name
            )));
        }
        if self.upstream_addr.is_some() {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: `upstream_addr` is not valid for protocol = \
                 \"https\" (dial targets live in [[rule.route]])",
                self.name
            )));
        }
        if self.proxy_protocol.is_some() {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: `proxy_protocol` is not valid for protocol = \
                 \"https\" (terminal consumes inbound PROXY-protocol headers)",
                self.name
            )));
        }
        if self.idle_timeout.is_some() {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: `idle_timeout` is only valid for udp rules",
                self.name
            )));
        }

        // `routes` required and non-empty.
        let routes = self.routes.as_deref().unwrap_or(&[]);
        if routes.is_empty() {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: protocol = \"https\" requires at least one \
                 [[rule.route]] block",
                self.name
            )));
        }

        // Per-route validation + within-rule duplicate-hostname detection.
        let mut seen_hostnames = std::collections::HashSet::<String>::new();
        for route in routes {
            validate_http_route(&self.name, route)?;
            let lc = route.hostname.to_ascii_lowercase();
            if !seen_hostnames.insert(lc) {
                return Err(Error::InvalidRule(format!(
                    "rule {:?}: duplicate route hostname {:?}",
                    self.name, route.hostname
                )));
            }
        }
        Ok(())
    }

    /// Idle timeout to apply at runtime — supplied value or
    /// [`DEFAULT_UDP_IDLE_TIMEOUT`] for UDP, irrelevant for TCP.
    pub fn resolved_idle_timeout(&self) -> Duration {
        self.idle_timeout.unwrap_or(DEFAULT_UDP_IDLE_TIMEOUT)
    }

    /// Return a copy of this rule with the listen IP replaced by `bind_ip`
    /// if one is provided AND the rule's listen address is the wildcard
    /// (`0.0.0.0` or `::`). Rules with an explicit non-wildcard listen IP
    /// are returned unchanged — operator intent always wins over the
    /// server-wide default.
    ///
    /// Port is preserved. `bind_ip = None` is a no-op (rule returned
    /// unchanged). The override is a v4 vs v6 match: a v4 default does not
    /// rewrite a `::` listen and vice versa.
    pub fn with_bind_override(&self, bind_ip: Option<std::net::IpAddr>) -> Rule {
        let Some(ip) = bind_ip else {
            return self.clone();
        };
        let cur_ip = self.listen.ip();
        let is_wildcard = cur_ip.is_unspecified();
        let same_family = matches!(
            (cur_ip, ip),
            (std::net::IpAddr::V4(_), std::net::IpAddr::V4(_))
                | (std::net::IpAddr::V6(_), std::net::IpAddr::V6(_))
        );
        if !is_wildcard || !same_family {
            return self.clone();
        }
        let mut out = self.clone();
        out.listen = std::net::SocketAddr::new(ip, self.listen.port());
        out
    }
}

/// Validate a single [`HttpRoute`] block belonging to `rule_name`.
///
/// Checks:
/// * `hostname` non-empty and a syntactically valid DNS label sequence.
/// * `upstream` scheme is exactly `"http"`; host and explicit port present.
/// * `cert = Path(_)` requires `key = Some(_)`; XOR.
/// * `cert = Ephemeral` restricts `hostname` to local-only patterns
///   (`localhost`, `*.localhost`, `*.local`).
/// * `key` set without a `Path` `cert` is rejected.
fn validate_http_route(rule_name: &str, route: &HttpRoute) -> Result<()> {
    if route.hostname.is_empty() {
        return Err(Error::InvalidRule(format!(
            "rule {:?}: route hostname is empty",
            rule_name
        )));
    }
    if !is_valid_dns_hostname(&route.hostname) {
        return Err(Error::InvalidRule(format!(
            "rule {:?}: route hostname {:?} is not a valid DNS name",
            rule_name, route.hostname
        )));
    }

    if route.upstream.scheme() != "http" {
        return Err(Error::InvalidRule(format!(
            "rule {:?}: route {:?}: upstream URL scheme must be \"http\" \
             (got {:?})",
            rule_name,
            route.hostname,
            route.upstream.scheme()
        )));
    }
    if route.upstream.host_str().is_none() {
        return Err(Error::InvalidRule(format!(
            "rule {:?}: route {:?}: upstream URL is missing a host",
            rule_name, route.hostname
        )));
    }
    if route.upstream.port_or_known_default().is_none() {
        return Err(Error::InvalidRule(format!(
            "rule {:?}: route {:?}: upstream URL has no port and no known \
             default for its scheme",
            rule_name, route.hostname
        )));
    }

    match (&route.cert, &route.key) {
        (Some(CertSource::Path(_)), None) => {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: route {:?}: cert is a file path; `key` must also \
                 be supplied",
                rule_name, route.hostname
            )));
        }
        (Some(CertSource::Ephemeral), Some(_)) => {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: route {:?}: cert = \"ephemeral\" does not take a \
                 separate `key` (the keypair is generated in-process)",
                rule_name, route.hostname
            )));
        }
        (None, Some(_)) => {
            return Err(Error::InvalidRule(format!(
                "rule {:?}: route {:?}: `key` is set but no `cert` is \
                 provided",
                rule_name, route.hostname
            )));
        }
        _ => {}
    }

    if matches!(route.cert, Some(CertSource::Ephemeral))
        && !is_local_only_hostname(&route.hostname)
    {
        return Err(Error::InvalidRule(format!(
            "rule {:?}: route {:?}: cert = \"ephemeral\" is only allowed for \
             `localhost`, `*.localhost`, or `*.local` hostnames",
            rule_name, route.hostname
        )));
    }

    Ok(())
}

/// Loose RFC-1123 DNS-name validator. Accepts:
/// * length 1..=253 octets total;
/// * labels of length 1..=63;
/// * labels matching `[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?`;
/// * a single optional trailing dot.
///
/// Wildcard (`*.example.com`) and underscore labels are rejected: a route
/// hostname must be a concrete DNS name, not a pattern. (Per-hostname
/// SNI/Host matching is exact at runtime.)
fn is_valid_dns_hostname(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.split('.').all(|label| {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        let bytes = label.as_bytes();
        if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
            return false;
        }
        bytes
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// True if `host` is one of the allowed `cert = "ephemeral"` hostnames:
/// `localhost`, anything ending in `.localhost`, or anything ending in
/// `.local` (the mDNS suffix; common on home LANs).
fn is_local_only_hostname(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    let h = h.strip_suffix('.').unwrap_or(&h);
    h == "localhost" || h.ends_with(".localhost") || h.ends_with(".local")
}

/// A single rule file (`/etc/yggdrasil/conf.d/*.toml`) deserialised from TOML.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleFile {
    #[serde(default)]
    pub rule: Vec<Rule>,
}

impl RuleFile {
    /// Parse a TOML string into a [`RuleFile`], attaching `path` to any parse
    /// error so the operator gets line context.
    pub fn from_toml(path: impl Into<std::path::PathBuf>, s: &str) -> Result<Self> {
        let path = path.into();
        toml::from_str(s).map_err(|source| Error::TomlParse {
            path,
            source,
        })
    }

    /// Validate every rule in the file. Cross-file uniqueness is enforced by
    /// [`RuleSet::from_files`].
    pub fn validate_each(&self) -> Result<()> {
        for r in &self.rule {
            r.validate()?;
        }
        Ok(())
    }
}

/// Aggregated, cross-file-validated set of rules ready for use by the runtime.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    /// Build a [`RuleSet`] from one or more parsed rule files, performing
    /// cross-file uniqueness validation. Per-rule validation runs first.
    pub fn from_files(files: impl IntoIterator<Item = RuleFile>) -> Result<Self> {
        let mut rules: Vec<Rule> = Vec::new();
        for f in files {
            f.validate_each()?;
            rules.extend(f.rule);
        }

        // Duplicate name check.
        {
            let mut seen = std::collections::HashSet::<&str>::new();
            for r in &rules {
                if !seen.insert(r.name.as_str()) {
                    return Err(Error::InvalidRule(format!(
                        "duplicate rule name {:?} across rule files",
                        r.name
                    )));
                }
            }
        }

        // Duplicate listen-addr+protocol check.
        {
            let mut seen = std::collections::HashSet::<(SocketAddr, Protocol)>::new();
            for r in &rules {
                if !seen.insert((r.listen, r.protocol)) {
                    return Err(Error::InvalidRule(format!(
                        "duplicate listen address {} for protocol {} (rule {:?})",
                        r.listen,
                        r.protocol.as_str(),
                        r.name
                    )));
                }
            }
        }

        Ok(Self { rules })
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn find(&self, name: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.name == name)
    }

    /// Compute a name-keyed diff against a new set. Used by the hot-reload
    /// watcher to figure out which listeners to add, remove, or restart.
    pub fn diff(&self, new: &RuleSet) -> RuleDiff {
        use std::collections::HashMap;

        let mut old_by_name: HashMap<&str, &Rule> =
            self.rules.iter().map(|r| (r.name.as_str(), r)).collect();
        let mut diff = RuleDiff::default();

        for new_rule in &new.rules {
            match old_by_name.remove(new_rule.name.as_str()) {
                Some(old) if old == new_rule => diff.unchanged.push(new_rule.name.clone()),
                Some(old) => diff.changed.push(RuleChange {
                    old: old.clone(),
                    new: new_rule.clone(),
                }),
                None => diff.added.push(new_rule.clone()),
            }
        }

        // Anything left in old_by_name was removed in the new set.
        for (_, r) in old_by_name {
            diff.removed.push(r.clone());
        }
        // Sort removed by name for determinism (HashMap iteration is randomised).
        diff.removed.sort_by(|a, b| a.name.cmp(&b.name));
        diff
    }

    /// Diff treating the previous set as empty — used to emit the initial
    /// "everything is new" event when the watcher first starts.
    pub fn as_initial_diff(&self) -> RuleDiff {
        RuleDiff {
            added: self.rules.clone(),
            ..Default::default()
        }
    }
}

/// A rule whose contents changed across a reload (same `name`, different fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleChange {
    pub old: Rule,
    pub new: Rule,
}

/// Result of [`RuleSet::diff`]: a partition of the new rule set into
/// added / removed / changed / unchanged, keyed by rule `name`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleDiff {
    pub added: Vec<Rule>,
    pub removed: Vec<Rule>,
    pub changed: Vec<RuleChange>,
    /// Rule names that exist with identical contents in both sets.
    pub unchanged: Vec<String>,
}

impl RuleDiff {
    /// `true` if the diff represents no actual change.
    pub fn is_noop(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }

    /// Number of rules touched (added + removed + changed).
    pub fn touched(&self) -> usize {
        self.added.len() + self.removed.len() + self.changed.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<RuleFile> {
        RuleFile::from_toml("test.toml", s)
    }

    #[test]
    fn parses_minimal_tcp_rule() {
        let f = parse(
            r#"
            [[rule]]
            name = "ssh"
            listen = "0.0.0.0:2222"
            protocol = "tcp"
            upstream_port = 22
            "#,
        )
        .unwrap();
        assert_eq!(f.rule.len(), 1);
        let r = &f.rule[0];
        assert_eq!(r.name, "ssh");
        assert_eq!(r.protocol, Protocol::Tcp);
        assert_eq!(r.upstream_port, Some(22));
        assert_eq!(r.upstream_addr, None);
        assert_eq!(r.idle_timeout, None);
        assert_eq!(r.proxy_protocol, None);
        f.validate_each().unwrap();
    }

    #[test]
    fn parses_terminal_style_tcp_rule() {
        let f = parse(
            r#"
            [[rule]]
            name = "home-ssh"
            listen = "0.0.0.0:2222"
            protocol = "tcp"
            upstream_addr = "192.168.1.10:22"
            "#,
        )
        .unwrap();
        let r = &f.rule[0];
        assert_eq!(r.upstream_port, None);
        assert_eq!(
            r.upstream_addr,
            Some("192.168.1.10:22".parse::<SocketAddr>().unwrap())
        );
        f.validate_each().unwrap();
    }

    #[test]
    fn parses_terminal_style_udp_rule() {
        let f = parse(
            r#"
            [[rule]]
            name = "home-dns"
            listen = "0.0.0.0:53"
            protocol = "udp"
            upstream_addr = "192.168.1.1:53"
            idle_timeout = "30s"
            "#,
        )
        .unwrap();
        let r = &f.rule[0];
        assert_eq!(r.protocol, Protocol::Udp);
        assert_eq!(
            r.upstream_addr,
            Some("192.168.1.1:53".parse::<SocketAddr>().unwrap())
        );
        assert_eq!(r.idle_timeout, Some(Duration::from_secs(30)));
        f.validate_each().unwrap();
    }

    #[test]
    fn parses_udp_rule_with_idle_timeout() {
        let f = parse(
            r#"
            [[rule]]
            name = "minecraft-bedrock"
            listen = "0.0.0.0:19132"
            protocol = "udp"
            upstream_port = 19132
            idle_timeout = "30s"
            "#,
        )
        .unwrap();
        let r = &f.rule[0];
        assert_eq!(r.protocol, Protocol::Udp);
        assert_eq!(r.idle_timeout, Some(Duration::from_secs(30)));
        assert_eq!(r.resolved_idle_timeout(), Duration::from_secs(30));
        f.validate_each().unwrap();
    }

    #[test]
    fn parses_tcp_rule_with_proxy_protocol() {
        let f = parse(
            r#"
            [[rule]]
            name = "http"
            listen = "0.0.0.0:80"
            protocol = "tcp"
            upstream_port = 8080
            proxy_protocol = "v2"
            "#,
        )
        .unwrap();
        assert_eq!(f.rule[0].proxy_protocol, Some(ProxyProto::V2));
        f.validate_each().unwrap();
    }

    #[test]
    fn rejects_idle_timeout_on_tcp_rule() {
        let f = parse(
            r#"
            [[rule]]
            name = "ssh"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            upstream_port = 22
            idle_timeout = "30s"
            "#,
        )
        .unwrap();
        let err = f.validate_each().err();
        assert!(matches!(err, Some(Error::InvalidRule(s)) if s.contains("idle_timeout")));
    }

    #[test]
    fn rejects_proxy_protocol_on_udp_rule() {
        let f = parse(
            r#"
            [[rule]]
            name = "dns"
            listen = "0.0.0.0:53"
            protocol = "udp"
            upstream_port = 53
            proxy_protocol = "v1"
            "#,
        )
        .unwrap();
        let err = f.validate_each().err();
        assert!(matches!(err, Some(Error::InvalidRule(s)) if s.contains("proxy_protocol")));
    }

    #[test]
    fn rejects_zero_listen_port() {
        let f = parse(
            r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:0"
            protocol = "tcp"
            upstream_port = 22
            "#,
        )
        .unwrap();
        let err = f.validate_each().err();
        assert!(matches!(err, Some(Error::InvalidRule(s)) if s.contains("listen port")));
    }

    #[test]
    fn rejects_zero_upstream_port() {
        let f = parse(
            r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            upstream_port = 0
            "#,
        )
        .unwrap();
        let err = f.validate_each().err();
        assert!(matches!(err, Some(Error::InvalidRule(s)) if s.contains("upstream_port")));
    }

    #[test]
    fn rejects_both_upstream_port_and_upstream_addr() {
        let f = parse(
            r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            upstream_port = 22
            upstream_addr = "192.168.1.1:22"
            "#,
        )
        .unwrap();
        let err = f.validate_each().err();
        assert!(matches!(
            err,
            Some(Error::InvalidRule(s)) if s.contains("exactly one of upstream_port")
        ));
    }

    #[test]
    fn rejects_neither_upstream_port_nor_upstream_addr() {
        let f = parse(
            r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            "#,
        )
        .unwrap();
        let err = f.validate_each().err();
        assert!(matches!(
            err,
            Some(Error::InvalidRule(s)) if s.contains("must set exactly one")
        ));
    }

    #[test]
    fn rejects_upstream_addr_with_zero_port() {
        let f = parse(
            r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            upstream_addr = "192.168.1.1:0"
            "#,
        )
        .unwrap();
        let err = f.validate_each().err();
        assert!(matches!(
            err,
            Some(Error::InvalidRule(s)) if s.contains("upstream_addr port")
        ));
    }

    #[test]
    fn rejects_proxy_protocol_with_upstream_addr() {
        let f = parse(
            r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            upstream_addr = "192.168.1.1:22"
            proxy_protocol = "v2"
            "#,
        )
        .unwrap();
        let err = f.validate_each().err();
        assert!(matches!(
            err,
            Some(Error::InvalidRule(s)) if s.contains("proxy_protocol is invalid on terminal rules")
        ));
    }

    #[test]
    fn rejects_empty_name() {
        let f = parse(
            r#"
            [[rule]]
            name = ""
            listen = "0.0.0.0:22"
            protocol = "tcp"
            upstream_port = 22
            "#,
        )
        .unwrap();
        let err = f.validate_each().err();
        assert!(matches!(err, Some(Error::InvalidRule(s)) if s.contains("empty")));
    }

    #[test]
    fn rejects_name_with_whitespace() {
        let f = parse(
            r#"
            [[rule]]
            name = "bad name"
            listen = "0.0.0.0:22"
            protocol = "tcp"
            upstream_port = 22
            "#,
        )
        .unwrap();
        let err = f.validate_each().err();
        assert!(matches!(err, Some(Error::InvalidRule(s)) if s.contains("whitespace")));
    }

    #[test]
    fn rejects_malformed_toml() {
        let err = parse("[[rule\nname=oops").err();
        assert!(matches!(err, Some(Error::TomlParse { .. })));
    }

    #[test]
    fn allows_empty_rule_file() {
        let f = parse("").unwrap();
        assert!(f.rule.is_empty());
        f.validate_each().unwrap();
    }

    #[test]
    fn rule_set_aggregates_multiple_files() {
        let a = parse(
            r#"
            [[rule]]
            name = "a"
            listen = "0.0.0.0:1111"
            protocol = "tcp"
            upstream_port = 1
            "#,
        )
        .unwrap();
        let b = parse(
            r#"
            [[rule]]
            name = "b"
            listen = "0.0.0.0:2222"
            protocol = "udp"
            upstream_port = 2
            "#,
        )
        .unwrap();
        let set = RuleSet::from_files([a, b]).unwrap();
        assert_eq!(set.len(), 2);
        assert!(set.find("a").is_some());
        assert!(set.find("b").is_some());
        assert!(set.find("nope").is_none());
    }

    #[test]
    fn rule_set_rejects_duplicate_names() {
        let a = parse(
            r#"
            [[rule]]
            name = "dup"
            listen = "0.0.0.0:1111"
            protocol = "tcp"
            upstream_port = 1
            "#,
        )
        .unwrap();
        let b = parse(
            r#"
            [[rule]]
            name = "dup"
            listen = "0.0.0.0:2222"
            protocol = "tcp"
            upstream_port = 2
            "#,
        )
        .unwrap();
        let err = RuleSet::from_files([a, b]).err();
        assert!(matches!(err, Some(Error::InvalidRule(s)) if s.contains("duplicate rule name")));
    }

    #[test]
    fn rule_set_rejects_duplicate_listen_within_protocol() {
        let a = parse(
            r#"
            [[rule]]
            name = "x"
            listen = "0.0.0.0:1111"
            protocol = "tcp"
            upstream_port = 1
            "#,
        )
        .unwrap();
        let b = parse(
            r#"
            [[rule]]
            name = "y"
            listen = "0.0.0.0:1111"
            protocol = "tcp"
            upstream_port = 2
            "#,
        )
        .unwrap();
        let err = RuleSet::from_files([a, b]).err();
        assert!(matches!(err, Some(Error::InvalidRule(s)) if s.contains("duplicate listen")));
    }

    #[test]
    fn rule_set_allows_same_listen_addr_across_different_protocols() {
        // tcp and udp can share `(ip, port)` — different sockets entirely.
        let a = parse(
            r#"
            [[rule]]
            name = "x-tcp"
            listen = "0.0.0.0:53"
            protocol = "tcp"
            upstream_port = 53
            "#,
        )
        .unwrap();
        let b = parse(
            r#"
            [[rule]]
            name = "x-udp"
            listen = "0.0.0.0:53"
            protocol = "udp"
            upstream_port = 53
            "#,
        )
        .unwrap();
        let set = RuleSet::from_files([a, b]).unwrap();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn unknown_protocol_string_fails_to_deserialise() {
        let err = parse(
            r#"
            [[rule]]
            name = "bad"
            listen = "0.0.0.0:22"
            protocol = "sctp"
            upstream_port = 22
            "#,
        )
        .err();
        assert!(matches!(err, Some(Error::TomlParse { .. })));
    }

    #[test]
    fn idle_timeout_default_for_udp() {
        let f = parse(
            r#"
            [[rule]]
            name = "udp"
            listen = "0.0.0.0:1234"
            protocol = "udp"
            upstream_port = 1234
            "#,
        )
        .unwrap();
        assert_eq!(f.rule[0].idle_timeout, None);
        assert_eq!(
            f.rule[0].resolved_idle_timeout(),
            DEFAULT_UDP_IDLE_TIMEOUT
        );
    }

    // ---- diff tests ----

    fn rule(name: &str, port: u16, proto: Protocol, upstream: u16) -> Rule {
        let f = parse(&format!(
            r#"
            [[rule]]
            name = "{name}"
            listen = "0.0.0.0:{port}"
            protocol = "{}"
            upstream_port = {upstream}
            "#,
            proto.as_str()
        ))
        .unwrap();
        f.rule.into_iter().next().unwrap()
    }

    fn set(rules: Vec<Rule>) -> RuleSet {
        RuleSet::from_files([RuleFile { rule: rules }]).unwrap()
    }

    #[test]
    fn diff_empty_to_empty_is_noop() {
        let d = RuleSet::default().diff(&RuleSet::default());
        assert!(d.is_noop());
        assert_eq!(d.touched(), 0);
    }

    #[test]
    fn diff_initial_treats_everything_as_added() {
        let s = set(vec![rule("a", 1111, Protocol::Tcp, 22)]);
        let d = s.as_initial_diff();
        assert_eq!(d.added.len(), 1);
        assert_eq!(d.added[0].name, "a");
        assert!(d.removed.is_empty());
        assert!(d.changed.is_empty());
        assert!(d.unchanged.is_empty());
    }

    #[test]
    fn diff_classifies_added_removed_changed_unchanged() {
        let old = set(vec![
            rule("keep", 1000, Protocol::Tcp, 22),
            rule("gone", 2000, Protocol::Tcp, 23),
            rule("mod",  3000, Protocol::Tcp, 24),
        ]);
        // "keep" unchanged, "gone" removed, "mod" upstream port changed, "new" added.
        let new = set(vec![
            rule("keep", 1000, Protocol::Tcp, 22),
            rule("mod",  3000, Protocol::Tcp, 99),
            rule("new",  4000, Protocol::Udp, 53),
        ]);
        let d = old.diff(&new);
        assert_eq!(d.added.len(), 1);
        assert_eq!(d.added[0].name, "new");
        assert_eq!(d.removed.len(), 1);
        assert_eq!(d.removed[0].name, "gone");
        assert_eq!(d.changed.len(), 1);
        assert_eq!(d.changed[0].old.name, "mod");
        assert_eq!(d.changed[0].old.upstream_port, Some(24));
        assert_eq!(d.changed[0].new.upstream_port, Some(99));
        assert_eq!(d.unchanged, vec!["keep".to_string()]);
        assert_eq!(d.touched(), 3);
        assert!(!d.is_noop());
    }

    #[test]
    fn diff_same_set_is_noop_but_marks_unchanged() {
        let s = set(vec![
            rule("a", 1, Protocol::Tcp, 1),
            rule("b", 2, Protocol::Udp, 2),
        ]);
        let d = s.diff(&s);
        assert!(d.is_noop());
        assert_eq!(d.unchanged.len(), 2);
    }

    // ---- with_bind_override ----

    fn relay_rule_with_listen(listen: &str) -> Rule {
        let mut r = rule("test", 0, Protocol::Tcp, 22);
        r.listen = listen.parse().unwrap();
        r
    }

    #[test]
    fn with_bind_override_none_is_noop() {
        let r = relay_rule_with_listen("0.0.0.0:1234");
        let out = r.with_bind_override(None);
        assert_eq!(out.listen, r.listen);
    }

    #[test]
    fn with_bind_override_rewrites_wildcard_v4_listen() {
        let r = relay_rule_with_listen("0.0.0.0:1234");
        let out = r.with_bind_override(Some("10.0.0.5".parse().unwrap()));
        assert_eq!(out.listen, "10.0.0.5:1234".parse().unwrap());
    }

    #[test]
    fn with_bind_override_rewrites_wildcard_v6_listen() {
        let r = relay_rule_with_listen("[::]:1234");
        let out = r.with_bind_override(Some("fd00::1".parse().unwrap()));
        assert_eq!(out.listen, "[fd00::1]:1234".parse().unwrap());
    }

    #[test]
    fn with_bind_override_preserves_explicit_v4_listen() {
        let r = relay_rule_with_listen("127.0.0.1:1234");
        let out = r.with_bind_override(Some("10.0.0.5".parse().unwrap()));
        assert_eq!(
            out.listen,
            "127.0.0.1:1234".parse().unwrap(),
            "explicit operator listen IP must win over default_bind"
        );
    }

    #[test]
    fn with_bind_override_does_not_cross_address_families() {
        let r = relay_rule_with_listen("0.0.0.0:1234");
        let out = r.with_bind_override(Some("fd00::1".parse().unwrap()));
        assert_eq!(
            out.listen,
            "0.0.0.0:1234".parse().unwrap(),
            "v6 default_bind must not rewrite a v4 wildcard listen"
        );
    }

    // ===== L7 (HTTPS) schema tests =====

    fn parse_one(s: &str) -> Result<Rule> {
        let f = parse(s)?;
        assert_eq!(f.rule.len(), 1);
        Ok(f.rule.into_iter().next().unwrap())
    }

    #[test]
    fn parses_minimal_https_rule_with_ephemeral_cert() {
        let r = parse_one(
            r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"

              [[rule.route]]
              hostname = "app.localhost"
              upstream = "http://127.0.0.1:8080"
              cert     = "ephemeral"
            "#,
        )
        .unwrap();
        assert_eq!(r.protocol, Protocol::Https);
        let routes = r.routes.as_ref().expect("routes present");
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].hostname, "app.localhost");
        assert_eq!(routes[0].upstream.scheme(), "http");
        assert_eq!(routes[0].upstream.port(), Some(8080));
        assert_eq!(routes[0].cert, Some(CertSource::Ephemeral));
        assert_eq!(routes[0].key, None);
        assert_eq!(routes[0].hsts, None);
        r.validate().expect("schema-valid");
    }

    #[test]
    fn parses_https_rule_with_path_cert_and_key() {
        let r = parse_one(
            r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"

              [[rule.route]]
              hostname = "api.home.example"
              upstream = "http://192.168.1.10:8080"
              cert     = "/tls/api/fullchain.pem"
              key      = "/tls/api/privkey.pem"
            "#,
        )
        .unwrap();
        let route = &r.routes.as_ref().unwrap()[0];
        assert_eq!(
            route.cert,
            Some(CertSource::Path(PathBuf::from("/tls/api/fullchain.pem")))
        );
        assert_eq!(route.key, Some(PathBuf::from("/tls/api/privkey.pem")));
        r.validate().unwrap();
    }

    #[test]
    fn https_rule_accepts_multiple_routes_and_distinct_hosts() {
        let r = parse_one(
            r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"

              [[rule.route]]
              hostname = "a.local"
              upstream = "http://10.0.0.1:80"
              cert     = "ephemeral"

              [[rule.route]]
              hostname = "b.local"
              upstream = "http://10.0.0.2:80"
              cert     = "ephemeral"
            "#,
        )
        .unwrap();
        assert_eq!(r.routes.as_ref().unwrap().len(), 2);
        r.validate().unwrap();
    }

    #[test]
    fn https_rule_rejects_duplicate_route_hostnames_case_insensitive() {
        let err = parse_one(
            r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"

              [[rule.route]]
              hostname = "App.local"
              upstream = "http://10.0.0.1:80"
              cert     = "ephemeral"

              [[rule.route]]
              hostname = "app.LOCAL"
              upstream = "http://10.0.0.2:80"
              cert     = "ephemeral"
            "#,
        )
        .unwrap()
        .validate()
        .unwrap_err();
        assert!(matches!(err, Error::InvalidRule(s) if s.contains("duplicate route hostname")));
    }

    #[test]
    fn https_rule_requires_non_empty_routes() {
        let err = parse_one(
            r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"
            "#,
        )
        .unwrap()
        .validate()
        .unwrap_err();
        assert!(
            matches!(err, Error::InvalidRule(s) if s.contains("requires at least one")),
            "expected 'requires at least one' error"
        );
    }

    #[test]
    fn https_rule_rejects_upstream_port() {
        let err = parse_one(
            r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"
            upstream_port = 80

              [[rule.route]]
              hostname = "x.local"
              upstream = "http://127.0.0.1:80"
              cert     = "ephemeral"
            "#,
        )
        .unwrap()
        .validate()
        .unwrap_err();
        assert!(
            matches!(err, Error::InvalidRule(s) if s.contains("`upstream_port` is not valid")),
        );
    }

    #[test]
    fn https_rule_rejects_upstream_addr() {
        let err = parse_one(
            r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"
            upstream_addr = "127.0.0.1:80"

              [[rule.route]]
              hostname = "x.local"
              upstream = "http://127.0.0.1:80"
              cert     = "ephemeral"
            "#,
        )
        .unwrap()
        .validate()
        .unwrap_err();
        assert!(
            matches!(err, Error::InvalidRule(s) if s.contains("`upstream_addr` is not valid")),
        );
    }

    #[test]
    fn https_rule_rejects_proxy_protocol() {
        let err = parse_one(
            r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"
            proxy_protocol = "v2"

              [[rule.route]]
              hostname = "x.local"
              upstream = "http://127.0.0.1:80"
              cert     = "ephemeral"
            "#,
        )
        .unwrap()
        .validate()
        .unwrap_err();
        assert!(
            matches!(err, Error::InvalidRule(s) if s.contains("`proxy_protocol` is not valid")),
        );
    }

    #[test]
    fn https_rule_rejects_idle_timeout() {
        let err = parse_one(
            r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"
            idle_timeout = "30s"

              [[rule.route]]
              hostname = "x.local"
              upstream = "http://127.0.0.1:80"
              cert     = "ephemeral"
            "#,
        )
        .unwrap()
        .validate()
        .unwrap_err();
        assert!(matches!(err, Error::InvalidRule(s) if s.contains("`idle_timeout`")));
    }

    #[test]
    fn tcp_rule_rejects_route_blocks() {
        let err = parse(
            r#"
            [[rule]]
            name = "x"
            listen = "0.0.0.0:1234"
            protocol = "tcp"
            upstream_port = 22

              [[rule.route]]
              hostname = "x.local"
              upstream = "http://127.0.0.1:80"
              cert     = "ephemeral"
            "#,
        )
        .unwrap()
        .validate_each()
        .unwrap_err();
        assert!(matches!(err, Error::InvalidRule(s) if s.contains("`route` blocks are only valid")));
    }

    #[test]
    fn tcp_rule_rejects_cert_dir() {
        let err = parse(
            r#"
            [[rule]]
            name = "x"
            listen = "0.0.0.0:1234"
            protocol = "tcp"
            upstream_port = 22
            cert_dir = "/tls"
            "#,
        )
        .unwrap()
        .validate_each()
        .unwrap_err();
        assert!(matches!(err, Error::InvalidRule(s) if s.contains("`cert_dir` is only valid")));
    }

    #[test]
    fn https_rule_rejects_non_http_upstream_scheme() {
        let err = parse_one(
            r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"

              [[rule.route]]
              hostname = "x.local"
              upstream = "https://10.0.0.1:443"
              cert     = "ephemeral"
            "#,
        )
        .unwrap()
        .validate()
        .unwrap_err();
        assert!(
            matches!(err, Error::InvalidRule(s) if s.contains("upstream URL scheme")),
        );
    }

    #[test]
    fn https_rule_accepts_upstream_with_default_http_port() {
        // http://10.0.0.1 (no explicit port) → url crate sets known default
        // port 80; we accept it. Adopting the URL semantics avoids forcing
        // operators to write `:80` redundantly.
        let r = parse_one(
            r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"

              [[rule.route]]
              hostname = "x.local"
              upstream = "http://10.0.0.1"
              cert     = "ephemeral"
            "#,
        )
        .unwrap();
        r.validate().unwrap();
        assert_eq!(
            r.routes.as_ref().unwrap()[0]
                .upstream
                .port_or_known_default(),
            Some(80)
        );
    }

    #[test]
    fn https_rule_rejects_path_cert_without_key() {
        let err = parse_one(
            r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"

              [[rule.route]]
              hostname = "api.home.example"
              upstream = "http://10.0.0.1:80"
              cert     = "/tls/cert.pem"
            "#,
        )
        .unwrap()
        .validate()
        .unwrap_err();
        assert!(matches!(err, Error::InvalidRule(s) if s.contains("`key` must also")));
    }

    #[test]
    fn https_rule_rejects_ephemeral_cert_with_key() {
        let err = parse_one(
            r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"

              [[rule.route]]
              hostname = "x.local"
              upstream = "http://10.0.0.1:80"
              cert     = "ephemeral"
              key      = "/tls/k.pem"
            "#,
        )
        .unwrap()
        .validate()
        .unwrap_err();
        assert!(matches!(err, Error::InvalidRule(s) if s.contains("does not take a separate")));
    }

    #[test]
    fn https_rule_rejects_key_without_cert() {
        let err = parse_one(
            r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"

              [[rule.route]]
              hostname = "x.local"
              upstream = "http://10.0.0.1:80"
              key      = "/tls/k.pem"
            "#,
        )
        .unwrap()
        .validate()
        .unwrap_err();
        assert!(matches!(err, Error::InvalidRule(s) if s.contains("but no `cert` is provided")));
    }

    #[test]
    fn https_rule_ephemeral_allows_localhost_pattern_hostnames() {
        for host in [
            "localhost",
            "app.localhost",
            "deep.nested.localhost",
            "thing.local",
            "raspberrypi.local",
        ] {
            let r = parse_one(&format!(
                r#"
                [[rule]]
                name = "h"
                listen = "0.0.0.0:443"
                protocol = "https"

                  [[rule.route]]
                  hostname = "{host}"
                  upstream = "http://127.0.0.1:8080"
                  cert     = "ephemeral"
                "#
            ))
            .unwrap();
            r.validate()
                .unwrap_or_else(|e| panic!("hostname {host:?} unexpectedly rejected: {e:?}"));
        }
    }

    #[test]
    fn https_rule_ephemeral_rejects_public_hostnames() {
        let err = parse_one(
            r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"

              [[rule.route]]
              hostname = "api.example.com"
              upstream = "http://127.0.0.1:8080"
              cert     = "ephemeral"
            "#,
        )
        .unwrap()
        .validate()
        .unwrap_err();
        assert!(matches!(err, Error::InvalidRule(s) if s.contains("only allowed for")));
    }

    #[test]
    fn https_rule_rejects_invalid_dns_hostname() {
        for bad in [
            "-leading-dash.local",
            "trailing-dash-.local",
            "label..double-dot.local",
            "white space.local",
        ] {
            let err = parse_one(&format!(
                r#"
                [[rule]]
                name = "h"
                listen = "0.0.0.0:443"
                protocol = "https"

                  [[rule.route]]
                  hostname = "{bad}"
                  upstream = "http://127.0.0.1:8080"
                  cert     = "ephemeral"
                "#
            ))
            .unwrap()
            .validate()
            .unwrap_err();
            assert!(
                matches!(err, Error::InvalidRule(s) if s.contains("not a valid DNS name")),
                "hostname {bad:?} should have been rejected as malformed"
            );
        }
    }

    #[test]
    fn https_rule_hsts_shorthand_true_yields_defaults() {
        let r = parse_one(
            r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"

              [[rule.route]]
              hostname = "x.local"
              upstream = "http://10.0.0.1:80"
              cert     = "ephemeral"
              hsts     = true
            "#,
        )
        .unwrap();
        let hsts = r.routes.as_ref().unwrap()[0]
            .hsts
            .expect("hsts shorthand parsed");
        assert_eq!(hsts.max_age, DEFAULT_HSTS_MAX_AGE);
        assert!(!hsts.include_subdomains);
        assert!(!hsts.preload);
    }

    #[test]
    fn https_rule_hsts_shorthand_false_yields_none() {
        let r = parse_one(
            r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"

              [[rule.route]]
              hostname = "x.local"
              upstream = "http://10.0.0.1:80"
              cert     = "ephemeral"
              hsts     = false
            "#,
        )
        .unwrap();
        assert_eq!(r.routes.as_ref().unwrap()[0].hsts, None);
    }

    #[test]
    fn https_rule_hsts_explicit_table_overrides_defaults() {
        let r = parse_one(
            r#"
            [[rule]]
            name = "h"
            listen = "0.0.0.0:443"
            protocol = "https"

              [[rule.route]]
              hostname = "x.local"
              upstream = "http://10.0.0.1:80"
              cert     = "ephemeral"

              [rule.route.hsts]
              max_age = 600
              include_subdomains = true
              preload = true
            "#,
        )
        .unwrap();
        let hsts = r.routes.as_ref().unwrap()[0].hsts.unwrap();
        assert_eq!(hsts.max_age, 600);
        assert!(hsts.include_subdomains);
        assert!(hsts.preload);
    }

    #[test]
    fn cert_source_deserialises_ephemeral_string() {
        let cs: CertSource =
            toml::from_str("v = \"ephemeral\"\n").map(|t: toml::Table| {
                t["v"].clone().try_into::<CertSource>().unwrap()
            }).unwrap();
        assert_eq!(cs, CertSource::Ephemeral);
    }

    #[test]
    fn cert_source_deserialises_path_string() {
        let cs: CertSource = toml::from_str("v = \"/tls/x.pem\"\n")
            .map(|t: toml::Table| t["v"].clone().try_into::<CertSource>().unwrap())
            .unwrap();
        assert_eq!(cs, CertSource::Path(PathBuf::from("/tls/x.pem")));
    }

    #[test]
    fn cert_source_rejects_empty_string() {
        let err: Result<CertSource> = toml::from_str("v = \"\"\n")
            .map(|t: toml::Table| {
                t["v"].clone().try_into::<CertSource>().map_err(|e| {
                    // Box the toml::de::Error into Error::InvalidRule for
                    // uniform handling in the assertion below.
                    Error::InvalidRule(e.to_string())
                })
            })
            .unwrap();
        assert!(err.is_err());
    }

    #[test]
    fn https_protocol_serialises_as_lowercase() {
        let p = Protocol::Https;
        let v = serde_json::to_string(&p).unwrap();
        assert_eq!(v, "\"https\"");
        assert_eq!(p.as_str(), "https");
    }
}
