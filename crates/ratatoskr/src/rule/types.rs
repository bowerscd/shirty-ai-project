//! Small leaf types shared across the rule module: `Protocol`,
//! `ProxyProto`, `TargetHost`, `HstsConfig`.
//!
//! Split out from the original monolithic `rule.rs` (Phase B1).

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::validate::is_valid_dns_hostname;

/// Transport protocol selected per-rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    /// HTTPS L7 frontend (terminal mode only): terminates TLS and reverse-
    /// proxies to per-hostname HTTP backends. The set of backends lives in
    /// the per-rule `routes` array; see [`super::HttpRoute`].
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

/// Terminal-mode upstream specified as a DNS hostname plus port. Parsed
/// from a single TOML string of the form `"hostname:port"`.
///
/// The host portion is validated against the same DNS-label rules as
/// `[[rule.route]] hostname` (RFC-1123 LDH labels, no wildcards, no
/// underscores, optional trailing dot tolerated). The port portion must be
/// a non-zero u16.
///
/// Resolution is performed at runtime by the yggdrasil daemon (see
/// `yggdrasil::proxy::resolver::UpstreamResolver::Dns`), refreshed
/// periodically; the rule itself only carries the (host, port) tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetHost {
    pub host: String,
    pub port: u16,
}

impl std::fmt::Display for TargetHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

impl std::str::FromStr for TargetHost {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        // Split on the *last* `:` so `host` may contain colons in IPv6
        // literal form — though IPv6 literals are not valid DNS hostnames
        // and will be caught by the validator below. Splitting on the last
        // colon keeps the error message focused on the hostname rather
        // than producing a confusing "port not a number" message.
        let (host, port_str) = s
            .rsplit_once(':')
            .ok_or_else(|| format!("target_host {s:?}: expected \"hostname:port\""))?;
        if host.is_empty() {
            return Err(format!("target_host {s:?}: empty hostname"));
        }
        let port: u16 = port_str
            .parse()
            .map_err(|_| format!("target_host {s:?}: port {port_str:?} is not a u16"))?;
        if port == 0 {
            return Err(format!("target_host {s:?}: port must be non-zero"));
        }
        if !is_valid_dns_hostname(host) {
            return Err(format!(
                "target_host {s:?}: hostname {host:?} is not a valid DNS \
                 name (LDH labels, no wildcards, no underscores)"
            ));
        }
        Ok(TargetHost {
            host: host.to_string(),
            port,
        })
    }
}

impl Serialize for TargetHost {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for TargetHost {
    fn deserialize<D>(de: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error as _;
        let s = String::deserialize(de)?;
        s.parse::<TargetHost>().map_err(D::Error::custom)
    }
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
/// header" — they are normalised to `Option::None` at the
/// [`super::HttpRoute`] level by [`HstsConfig::deserialize`].
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

            fn visit_bool<E: serde::de::Error>(
                self,
                v: bool,
            ) -> std::result::Result<HstsConfig, E> {
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
