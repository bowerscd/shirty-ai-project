//! `HttpRoute`: a single per-hostname HTTPS route attached to a
//! `Protocol::Https` rule, plus its bespoke HSTS deserialisation.
//!
//! Split out from the original monolithic `rule.rs` (Phase B1).

use std::path::PathBuf;

use serde::{Deserialize, Deserializer, Serialize};
use url::Url;

use super::cert_source::CertSource;
use super::types::HstsConfig;

/// A single HTTPS route attached to a `Protocol::Https` rule.
///
/// Routes are matched by exact `Host` header against the inbound request
/// (after SNI). All fields beyond `hostname` and `target` are optional.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRoute {
    /// DNS hostname the route is served as. Matched as an exact, case-
    /// insensitive string against both SNI and the `Host` header.
    pub hostname: String,
    /// Plaintext HTTP target URL — must use scheme `http` and include an
    /// explicit host + port (path/query are ignored; only the authority is
    /// used to dial the backend).
    pub target: Url,
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
