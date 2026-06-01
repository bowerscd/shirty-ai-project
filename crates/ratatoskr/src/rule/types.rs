//! Small leaf types shared across the rule module: `Protocol`,
//! `ProxyProto`, `HstsConfig`.
//!

use serde::{Deserialize, Deserializer, Serialize};

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
