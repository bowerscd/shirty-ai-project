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
//! target_port  = 25565
//! proxy_protocol = "v2"          # optional, off by default
//!
//! [[rule]]
//! name           = "minecraft-bedrock"
//! listen         = "0.0.0.0:19132"
//! protocol       = "udp"
//! target_port  = 19132
//! idle_timeout   = "30s"          # optional, defaults to 60s for udp
//! ```
//!
//! Example (terminal-mode rules — dial a `host:port` LAN target;
//! `host` may be an IP literal for a static target, or a DNS name for
//! periodic re-resolution):
//!
//! ```toml
//! [[rule]]
//! name     = "home-ssh"
//! listen   = "0.0.0.0:2222"
//! protocol = "tcp"
//! target   = "192.168.1.10:22"      # IP literal: static
//!
//! [[rule]]
//! name     = "home-dns"
//! listen   = "0.0.0.0:53"
//! protocol = "udp"
//! target   = "192.168.1.1:53"
//! idle_timeout = "30s"
//!
//! [[rule]]
//! name     = "home-printer"
//! listen   = "0.0.0.0:9100"
//! protocol = "tcp"
//! target   = "printer.lan:9100"     # DNS name: re-resolved every 30s
//! ```
//!
//! The loader picks the resolver shape based on whether the host portion
//! of `target` parses as an IP literal. IP literals become a static
//! resolver; DNS names become a re-resolving resolver. Picking exactly
//! one of `target_port` (relay) and `target` (terminal) is a per-rule
//! validation requirement.
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
//!   target = "http://192.168.1.10:8080"
//!   cert     = "/etc/yggdrasil/certs/api.home.example/fullchain.pem"
//!   key      = "/etc/yggdrasil/certs/api.home.example/privkey.pem"
//!   hsts     = true
//!
//!   [[rule.route]]
//!   hostname = "app.local"
//!   target = "http://192.168.1.11:3000"
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
//! * `http3` and `alt_svc` are only meaningful for HTTPS; setting either on
//!   TCP or UDP is rejected. `alt_svc = true` with `http3 = false` is rejected.
//! * `listen` port must be non-zero (binding to port 0 makes no sense for a
//!   fixed-listener proxy).
//! * For `protocol = "tcp" | "udp"`: exactly one of `target_port` and
//!   `target` is set (2-way XOR). `target_port`, when set, must be
//!   non-zero; `target`, when set, must parse as `host:port` with a
//!   non-zero port and a host that is either an IP literal or a valid
//!   DNS name.
//! * `proxy_protocol` is rejected when `target` is set — terminal rules
//!   cannot emit headers (the relay's header passes through verbatim).
//! * For `protocol = "https"`: `routes` is present and non-empty;
//!   `target_port` / `target` / `proxy_protocol` / `idle_timeout` are
//!   all absent. Per-route invariants:
//!   hostname is a syntactically valid DNS name (no duplicates within the rule); `target` URL scheme
//!   is `"http"` with explicit host + port; `cert` as a path requires `key`
//!   alongside; `cert = "ephemeral"` requires the hostname to match
//!   `localhost`, `*.localhost`, or `*.local`.
//!
//! Cross-file:
//! * `name` must be globally unique.
//! * `listen` socket claims must be globally unique: no two rules can claim
//!   the same `(ip, port, protocol)` triple. TCP and UDP may share `(ip, port)`,
//!   but HTTPS claims both TCP and UDP on its `(ip, port)` for HTTP/3.
//!
//! ## Module layout (Phase B1 split)
//!
//! - `types` — `Protocol`, `ProxyProto`, `HstsConfig`,
//!   `DEFAULT_HSTS_MAX_AGE`.
//! - `http_route` — `HttpRoute` with the HSTS shorthand handling.
//! - `target` — `Target` parsed from the L4 `target` field (static vs DNS).
//! - `rule_def` — `Rule` struct + per-rule validation,
//!   `DEFAULT_UDP_IDLE_TIMEOUT`, `with_bind_override`,
//!   `resolved_idle_timeout`.
//! - `validate` — shared validation helpers (`validate_http_route`,
//!   `is_valid_dns_hostname`).
//! - `file` — `RuleFile` and the per-file TOML parser/validator.
//! - `set` — `RuleSet`, `RuleChange`, `RuleDiff`.

mod file;
mod http_route;
mod rule_def;
mod set;
mod target;
mod types;
mod validate;

#[cfg(test)]
mod tests;

pub use file::RuleFile;
pub use http_route::HttpRoute;
pub use rule_def::{Rule, DEFAULT_UDP_IDLE_TIMEOUT};
pub use set::{RuleChange, RuleDiff, RuleSet};
pub use target::Target;
pub use types::{HstsConfig, Protocol, ProxyProto, DEFAULT_HSTS_MAX_AGE};
