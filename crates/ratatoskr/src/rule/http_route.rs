//! `HttpRoute`: a single per-hostname HTTPS route attached to a
//! `Protocol::Https` rule, plus its bespoke HSTS deserialisation.
//!

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};
use url::Url;

use super::types::HstsConfig;

/// A single HTTPS route attached to a `Protocol::Https` rule.
///
/// Routes are matched by exact `Host` header against the inbound request
/// (after SNI). All fields beyond `hostname` and `target` are optional.
///
/// Certificate resolution is **node-wide**, not per-route — the daemon
/// serves whichever cert covers a given SNI hostname via the three-rung
/// resolver (`[server].default_cert+default_key` → ACME-managed wildcard
/// → cert-less LAN). Routes whose hostname is not covered by any cert
/// fall through to the cert-less LAN path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRoute {
    /// DNS hostname the route is served as. Matched as an exact, case-
    /// insensitive string against both SNI and the `Host` header.
    pub hostname: String,
    /// Plaintext HTTP target URL — must use scheme `http` and include an
    /// explicit host + port (path/query are ignored; only the authority is
    /// used to dial the backend).
    pub target: Url,
    /// HTTP Strict-Transport-Security policy. See [`HstsConfig`] for the
    /// shorthand-vs-table TOML shapes. `None` means no header is emitted.
    #[serde(default, deserialize_with = "deserialize_optional_hsts")]
    pub hsts: Option<HstsConfig>,
    /// Static response headers stamped onto every response the route
    /// produces — proxied or proxy-generated alike. Operator-set values
    /// OVERRIDE any header of the same name returned by the backend, so
    /// the configured policy always wins (matches nginx's `add_header
    /// ... always` semantics).
    ///
    /// The header **name** is validated at config load: hop-by-hop
    /// names, the request-forwarding names yggdrasil owns
    /// (`X-Forwarded-*`, `X-Real-IP`, `Forwarded`), and
    /// `Strict-Transport-Security` (use `hsts` instead) are rejected.
    /// Empty map means no extra headers (default).
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
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
