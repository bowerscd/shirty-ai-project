//! [`CertSource`] enum and its bespoke (de)serialisation.
//!
//! Split out from the original monolithic `rule.rs` (Phase B1).

use std::path::PathBuf;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Source of the certificate served for a route's hostname.
///
/// * `Path` — a fully-qualified file path on disk. Must be accompanied by
///   `HttpRoute.key`.
/// * `Ephemeral` — sentinel telling the daemon to generate a self-signed
///   keypair in memory at startup, valid for ten years. Local-dev only;
///   browsers will warn.
/// * `Acme(AcmeRouteConfig)` — the daemon obtains and rotates the cert
///   automatically via the ACME protocol. The actual issuance + renewal
///   pipeline lives in `crate::proxy::acme` (in the `yggdrasil` crate);
///   this schema only encodes the per-route challenge selection.
///
/// TOML deserialisation accepts three string shorthands and one explicit
/// table form:
///
/// ```toml
/// # path:
/// cert = "/etc/yggdrasil/certs/api.example.com/fullchain.pem"
///
/// # ephemeral:
/// cert = "ephemeral"
///
/// # ACME / HTTP-01 (shorthand):
/// cert = "acme"
///
/// # ACME / DNS-01 with a specific provider (explicit table):
/// [rule.route.cert.acme]
/// challenge = "dns01"
/// provider  = "cloudflare"
/// ```
///
/// A bare empty string is rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertSource {
    Path(PathBuf),
    Ephemeral,
    Acme(AcmeRouteConfig),
}

/// Per-route ACME configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeRouteConfig {
    /// Which challenge type to use. Defaults to HTTP-01 (the
    /// shorthand `cert = "acme"` form picks this).
    #[serde(default)]
    pub challenge: AcmeChallenge,
    /// DNS provider name (must be registered in `[acme.dns.<name>]`
    /// in the server config). Required iff `challenge = "dns01"`,
    /// rejected otherwise.
    #[serde(default)]
    pub provider: Option<String>,
}

impl AcmeRouteConfig {
    /// HTTP-01 with no DNS provider — the shorthand `cert = "acme"`.
    pub fn http01() -> Self {
        Self {
            challenge: AcmeChallenge::Http01,
            provider: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AcmeChallenge {
    #[default]
    Http01,
    Dns01,
}

impl Serialize for CertSource {
    fn serialize<S>(&self, ser: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;
        match self {
            Self::Ephemeral => ser.serialize_str("ephemeral"),
            Self::Path(p) => ser.serialize_str(&p.to_string_lossy()),
            Self::Acme(cfg) if cfg.challenge == AcmeChallenge::Http01 && cfg.provider.is_none() => {
                // Round-trip the shorthand form for the trivial HTTP-01
                // case so configs don't bloat when they don't need to.
                ser.serialize_str("acme")
            }
            Self::Acme(cfg) => {
                let mut m = ser.serialize_map(Some(1))?;
                m.serialize_entry("acme", cfg)?;
                m.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for CertSource {
    fn deserialize<D>(de: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{MapAccess, Visitor};
        use std::fmt;

        struct CertSourceVisitor;

        impl<'de> Visitor<'de> for CertSourceVisitor {
            type Value = CertSource;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    r#"either "ephemeral", "acme", a path string, or a table `{ acme = { ... } }`"#,
                )
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<CertSource, E> {
                match v {
                    "ephemeral" => Ok(CertSource::Ephemeral),
                    "acme" => Ok(CertSource::Acme(AcmeRouteConfig::http01())),
                    "" => Err(E::custom("cert: empty string is not a valid path")),
                    other => Ok(CertSource::Path(PathBuf::from(other))),
                }
            }

            fn visit_map<M>(self, mut map: M) -> std::result::Result<CertSource, M::Error>
            where
                M: MapAccess<'de>,
            {
                use serde::de::Error as _;
                let mut acme: Option<AcmeRouteConfig> = None;
                while let Some(k) = map.next_key::<String>()? {
                    match k.as_str() {
                        "acme" => {
                            if acme.is_some() {
                                return Err(M::Error::custom("duplicate `acme` table"));
                            }
                            acme = Some(map.next_value()?);
                        }
                        other => {
                            return Err(M::Error::unknown_field(other, &["acme"]));
                        }
                    }
                }
                let cfg = acme.ok_or_else(|| {
                    M::Error::custom("cert table must contain an `acme` subtable")
                })?;
                Ok(CertSource::Acme(cfg))
            }
        }

        de.deserialize_any(CertSourceVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    fn parse(v: toml::Value) -> Result<CertSource, toml::de::Error> {
        CertSource::deserialize(v)
    }

    #[test]
    fn acme_shorthand_string_maps_to_http01() {
        let cs = parse(toml::Value::String("acme".into())).unwrap();
        assert_eq!(
            cs,
            CertSource::Acme(AcmeRouteConfig {
                challenge: AcmeChallenge::Http01,
                provider: None,
            }),
        );
    }

    #[test]
    fn acme_table_form_carries_dns01_provider() {
        let v: toml::Value =
            toml::from_str("v = { acme = { challenge = \"dns01\", provider = \"cloudflare\" } }\n")
                .unwrap();
        let cs: CertSource = v["v"].clone().try_into().unwrap();
        assert_eq!(
            cs,
            CertSource::Acme(AcmeRouteConfig {
                challenge: AcmeChallenge::Dns01,
                provider: Some("cloudflare".into()),
            }),
        );
    }

    #[test]
    fn acme_table_form_defaults_to_http01() {
        let v: toml::Value = toml::from_str("v = { acme = {} }\n").unwrap();
        let cs: CertSource = v["v"].clone().try_into().unwrap();
        assert_eq!(
            cs,
            CertSource::Acme(AcmeRouteConfig {
                challenge: AcmeChallenge::Http01,
                provider: None,
            }),
        );
    }

    #[test]
    fn unknown_field_in_acme_table_is_rejected() {
        let v: toml::Value =
            toml::from_str("v = { acme = { challenge = \"http01\", unknown = \"x\" } }\n").unwrap();
        let res: Result<CertSource, _> = v["v"].clone().try_into();
        assert!(res.is_err(), "expected unknown-field rejection");
    }

    #[test]
    fn ephemeral_path_string_forms_unchanged() {
        assert_eq!(
            parse(toml::Value::String("ephemeral".into())).unwrap(),
            CertSource::Ephemeral
        );
        assert_eq!(
            parse(toml::Value::String("/etc/x.pem".into())).unwrap(),
            CertSource::Path(PathBuf::from("/etc/x.pem"))
        );
    }
}
