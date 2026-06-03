# Configuration reference

There are two config artefacts; both are TOML. `config.toml` is strict:
`[server]`, `[control]`, `[dial]`, `[accept]`, and `[acme]` all carry
`#[serde(deny_unknown_fields)]`, so a typo at the top level is a hard
parse error. The rule files in `conf.d/*.toml` are more permissive at
the parse layer — unknown keys are silently dropped — but the post-parse
validator rejects any rule that ends up missing a required field (e.g.
neither `target` nor `target_port` set), so a typo'd key name (`target_addr`
instead of `target`, say) surfaces at validation rather than parse.

| File                                  | Owner                | Purpose                                  |
| ------------------------------------- | -------------------- | ---------------------------------------- |
| `/etc/yggdrasil/config.toml`          | every node           | Top-level yggdrasil daemon config.       |
| `/etc/yggdrasil/conf.d/*.toml`        | terminal nodes       | One or more files defining proxy rules.  |

Relay nodes derive their rule set from a downstream terminal's published
predicate set; they do not normally hold `conf.d/*.toml` files. (The
relay's `[server].rules_dir` still has to be a valid path — pointing at
an empty directory is fine.)

Defaults below are what you get when a field is omitted. `humantime`
values accept the usual `1h`, `30s`, `250ms`, etc. Public keys use the
tagged textual form `<algo>:<hex>` everywhere (`x25519:6c5a…0ff1`); bare
hex is rejected on parse.

## `/etc/yggdrasil/config.toml`

### `[server]` — required

| Key                | Type                   | Default                          | Notes                                                                                          |
| ------------------ | ---------------------- | -------------------------------- | ---------------------------------------------------------------------------------------------- |
| `name`             | string (≤ 32 bytes, no whitespace / control chars) | `gethostname(3)` | Human-readable label propagated through every `chain {summary,ping,diff,health}` response. Lets `yggdrasilctl` render hops as e.g. `vps` / `midbox` / `home` instead of pubkey soup. Falls back to the kernel hostname when unset; empty string is treated as unset. Captured at startup; not hot-reloadable. |
| `rules_dir`        | path                   | `/etc/yggdrasil/conf.d`          | Watched for `*.toml`. Non-recursive. Missing dir is a hard error at startup.                   |
| `default_bind`     | IP                     | unset                            | If set, hard-rewrites every rule's `listen` IP to this address (the port is preserved). Used to share one config across hosts with different network interfaces. |
| `workers`          | optional positive integer | unset (`None` → `available_parallelism()` at proxy spawn) | Daemon-wide default for SO_REUSEPORT accept-loop fan-out across the proxy's TCP listeners and UDP frontend sockets. `0` is rejected. Per-rule overrides aren't exposed — fan-out is a kernel-level concern (the kernel hash-distributes incoming SYNs / datagrams across the workers sharing an `addr:port`), so a per-rule knob would buy nothing a global default doesn't already provide. |
| `state_dir`        | path                   | `/var/lib/yggdrasil`             | Per-host state — TOFU candidates, runtime markers.                                             |
| `identity_file`    | path                   | `/etc/yggdrasil/identity.key`    | Long-term identity in the tagged on-disk format (5-byte `b"YGGID"` magic + 1-byte version + 1-byte algorithm discriminator + algorithm-specific payload; X25519 payload is 32 secret ++ 32 public = 64 bytes, for a 71-byte file). Mode 0600. Auto-generated on first start if missing. |
| `cert_dir`         | path                   | `/etc/yggdrasil/certs`           | HTTPS only. Directory consulted by the **convention** cert-source rung (`<cert_dir>/<hostname>/{fullchain,privkey}.pem`). Rung 1: takes precedence over `default_cert` when present. |
| `default_cert`     | path                   | unset                            | HTTPS only. **Fallback** certificate PEM, served only for routes whose hostname is actually covered by a Subject Alternative Name in the cert (exact match or single-label `*.parent` wildcard per RFC 6125). Routes outside that SAN coverage fall through to rung 3 (cert-less LAN serving on `:80`) rather than being served the wrong cert. Must be set together with `default_key`. The ACME wildcard issuance pipeline (when `[acme]` is configured) writes its renewed PEMs to `<storage_dir>/<domain>/{fullchain,privkey}.pem`; operators point `default_cert`/`default_key` at those files so the renewer's writes are picked up by the cert watcher without further wiring. |
| `default_key`      | path                   | unset                            | HTTPS only. Private key PEM matching `default_cert`. Must be set together with it.              |
| `https_listen`     | `host:port`            | `0.0.0.0:443`                    | HTTPS only. Node-wide HTTPS listener address. Every top-level `[[route]]` lands on this socket; per-route `listen` overrides aren't supported in v1. Set to e.g. `0.0.0.0:8443` when running unprivileged. |
| `https_http3`      | bool                   | `true`                           | HTTPS only. Whether the node binds the HTTP/3 UDP companion on the same `(ip, port)` as `https_listen`. Set `false` to opt out of HTTP/3 — saves a UDP socket plus a NAT mapping. The `Alt-Svc: h3=":<port>"` advertisement is suppressed automatically when this is `false`. |
| `https_alt_svc`    | bool                   | `true`                           | HTTPS only. Whether HTTPS responses include the `Alt-Svc: h3=":<port>"; ma=86400` header that advertises the HTTP/3 alternative. Set `false` to suppress the header while still serving HTTP/3 (useful when a CDN in front of the terminal would re-write the advertisement). `https_alt_svc = true` combined with `https_http3 = false` is rejected at config load — there's no h3 listener to advertise. |
| `https_request_body_limit` | bytes (usize)  | `16777216` (16 MiB)              | HTTPS only. Maximum buffered inbound HTTP/3 request body. Oversized requests get `413 Payload Too Large` before any backend dial. Raise when a backend expects larger uploads (e.g. Jellyfin recommends `client_max_body_size 20M` for poster uploads — set this to `20971520`). Applies to the HTTP/3 path only; the HTTP/1.1 + HTTP/2 path streams uncapped. Note: setting `[server].https_http3 = false` disables HTTP/3 daemon-wide, so raising this knob is the right knob for the body-size case where you still want h3. |
| `http_redirect_port` | optional u16         | unset (`None` → `80`)            | HTTPS only. Port for the per-IP HTTP→HTTPS redirect listener the supervisor auto-spawns. Default `80`. Set to a non-privileged port when running unprivileged (no `CAP_NET_BIND_SERVICE`), or to `0` for an ephemeral kernel-assigned port (useful in containers / dev / bench harnesses). |
| `graceful_drain_timeout` | optional humantime duration | unset                            | When set, on `SIGTERM` the daemon stops accepting new TCP / HTTPS connections immediately but waits up to this duration for in-flight conversations to finish naturally before cancelling them. UDP is per-datagram and unaffected. systemd users should pair this with a matching `TimeoutStopSec=` in the unit file. Default unset = preserve the historical abrupt-cancel behaviour (in-flight conns die when the runtime drops them). |
| `nat_traversal`    | enum (`off` / `pcp` / `natpmp` / `auto`) | `off`                  | Opt-in NAT port-mapping for home-hosted gateways / relays / standalone terminals. See [NAT traversal](#nat-traversal) below. |

Mode is derived from section presence:

* `[dial]` only => `terminal`
* `[accept]` only => `gateway` (root-of-chain VPS)
* `[dial]` + `[accept]` => `relay` (mid-chain hop)
* neither => invalid config

There is no `[metrics]` section. Prometheus text, `/healthz`-equivalent
status, and derived-rule snapshots are served on the control UDS via
`yggdrasilctl local metrics` / `local health` / `local derived-rules`.
Operators who scrape Prometheus over TCP run a thin UDS→HTTP scrape
adapter sidecar (`socat UNIX-CONNECT:/run/yggdrasil/control.sock …` is
enough).

### `[control]` — optional

| Key      | Type | Default                         | Notes                                                                                            |
| -------- | ---- | ------------------------------- | ------------------------------------------------------------------------------------------------ |
| `socket` | path | `/run/yggdrasil/control.sock`   | Unix domain socket for `yggdrasilctl`. Restrict to an admin group via filesystem permissions.    |

### `[dial]` — optional

Configures this node as a chain client (terminal- and mid-chain-relay
nodes). When set, the daemon dials `endpoint`, performs Noise_IK against
`pubkey`, and sends heartbeats + control frames. Terminal nodes require
this section; pure root relays omit it.

| Key                  | Type           | Default | Notes                                                                                          |
| -------------------- | -------------- | ------- | ---------------------------------------------------------------------------------------------- |
| `pubkey`             | tagged pubkey  | **required** | `x25519:<hex>` of the upstream node. Pinned; the handshake fails if the responder's static key doesn't match. |
| `endpoint`           | `host:port`    | **required** | DNS hostname **or** literal IP. Re-resolved on every reconnection attempt — dynamic DNS for the upstream's address works. |
| `heartbeat_interval` | `humantime`    | `5s`    | How often to emit a heartbeat. Lower = faster IP-change reaction; higher = fewer wakeups.       |
| `rekey_interval`     | `humantime`    | `1h`    | Force a fresh Noise handshake at most this often, regardless of traffic.                       |

### `[accept]` — optional

Pins the single enrolled downstream identity. When set, this node accepts
inbound chain traffic only from `pubkey` and binds UDP `listen` for that
session. Presence of `[accept]` makes the effective mode `gateway`
(`[accept]`-only, root-of-chain VPS) or `relay` (when `[dial]` is also
set, mid-chain hop).

| Key                  | Type           | Default | Notes                                                                  |
| -------------------- | -------------- | ------- | ---------------------------------------------------------------------- |
| `pubkey`             | tagged pubkey  | **required** | `x25519:<hex>` of the downstream node. Written by `yggdrasilctl identity add-accept` or `local accept approve`. |
| `listen`             | `host:port`    | **required** | UDP socket to bind. Public-facing on the root relay.                  |
| `rekey_interval`     | `humantime`    | `1h`    | Force a fresh Noise handshake at most this often.                      |

### `[acme]` — optional (terminal mode only)

> **Implementation status.** The renewer / storage / DNS-01 client are
> unit-tested but no end-to-end test in tree has ever issued a cert
> against a live (or local pebble) CA. Treat the issuance pipeline
> documented below as "implemented but operationally unverified" until
> an e2e harness lands.

Configures ACME (RFC 8555) issuance + renewal of a **single wildcard
certificate** for the terminal's apex domain. Only meaningful on
terminal nodes — relays passthrough TLS without terminating. When
this section is absent, the daemon serves whichever PEMs are on disk
(via `[server].default_cert` / cert-dir convention) and never talks
to a CA.

Issuance is **DNS-01 only** — wildcards (`*.example.com`) require it
per RFC 8555 §7.1.3, so HTTP-01 isn't offered. The renewer issues
one cert with SANs `[<domain>, *.<domain>]` covering both the apex
and every immediate subdomain. Operators point
`[server].default_cert` / `default_key` at the renewer's output path
(`<storage_dir>/<domain>/{fullchain,privkey}.pem`) so the existing
`CertWatcher` reload pipeline picks up renewals automatically.

| Key                          | Type        | Default                                              | Notes                                                                                                            |
| ---------------------------- | ----------- | ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `domain`                     | DNS name    | **required**                                         | The apex domain the wildcard covers. SANs are derived as `[<domain>, *.<domain>]`. Must be a valid hostname.   |
| `directory_url`              | string URL  | `https://acme-v02.api.letsencrypt.org/directory`    | LE staging is `https://acme-staging-v02.api.letsencrypt.org/directory`; flip while shaking out a deployment.    |
| `contact_email`              | string      | **required**                                         | Registered with the CA so it can notify you about impending expiries or account problems.                       |
| `account_key_path`           | path        | `/var/lib/yggdrasil/acme/account.key`                | Long-lived ACME account credentials. Auto-generated on first run; mode `0600`.                                  |
| `storage_dir`                | path        | (`[server].cert_dir`)                                | Where renewed PEMs land. Defaults to the cert dir so the existing `CertWatcher` reload pipeline picks them up. |
| `terms_of_service_agreed`    | bool        | **required, must be `true`**                          | Operator must explicitly opt in to the directory's ToS.                                                          |
| `renew_before`               | `humantime` | `30d`                                                | Renew this far in advance of `not_after`.                                                                       |
| `renew_jitter`               | `humantime` | `12h`                                                | Random jitter added to spread renewal load.                                                                     |

The DNS-01 provider is **derived from the (single) `[acme.dns.<name>]`
sub-table** present in the config. Exactly one sub-table is required;
zero is rejected ("no DNS-01 provider configured") and two-or-more
is rejected ("multiple DNS-01 providers — pick one"). The only
provider implemented today is `cloudflare`:

| Key             | Type        | Notes                                                                                                |
| --------------- | ----------- | ---------------------------------------------------------------------------------------------------- |
| `api_token`     | string      | Inline Cloudflare API token (scope: `Zone.DNS:Edit`). Mutually exclusive with `api_token_env`.       |
| `api_token_env` | string      | Name of an environment variable holding the token. Preferred — keeps the secret out of the config.  |

Example:

```toml
[acme]
domain                  = "example.com"
contact_email           = "ops@example.com"
terms_of_service_agreed = true

[acme.dns.cloudflare]
api_token_env = "CLOUDFLARE_API_TOKEN"
```

At startup the daemon kicks off a `start_wildcard()` issuance against
the apex domain (driven through the same renewer machinery that
schedules subsequent renewals). While issuance is in flight, the
daemon serves whatever cert is already on disk via the three-rung
resolver (typically the previous renewed wildcard, if any). Browsers
see `ERR_CERT_AUTHORITY_INVALID` only on the very first startup with
no prior PEM — once the renewer writes the real cert,
`CertWatcher::reload_host` swaps it in without restart.

### NAT traversal

When the daemon is hosted behind a consumer router (home gateway,
home-hosted standalone terminal, home-hosted mid-chain relay), every
listener it spawns — `[[rule]]` L4 listeners, the chain
`[accept].listen` socket, the node-wide HTTPS listener on
`[server].https_listen`, its HTTP/3 UDP companion (when
`[server].https_http3 = true`), and the HTTP→HTTPS redirect listener
on `[server].http_redirect_port` — needs an inbound port forward on
the router. Setting `[server].nat_traversal` opts the daemon into
asking the router for those forwards automatically via the standard
IETF binary protocols:

| Value      | Behaviour                                                                    |
| ---------- | ---------------------------------------------------------------------------- |
| `"off"`    | Default. No port-mapping requests are emitted. The operator forwards ports manually in their router admin UI. |
| `"pcp"`    | RFC 6887 PCP only. Use when you know the router speaks PCP and want to avoid leaking NAT-PMP probes on networks that don't. |
| `"natpmp"` | RFC 6886 NAT-PMP only. Use for older routers that don't speak PCP. |
| `"auto"`   | Try PCP first; on `UnsuppVersion` or socket timeout per RFC 6887 §9, retry with NAT-PMP. Recommended default for unknown networks. |

**What gets mapped.** Every TCP / UDP rule's `listen.port()`; for
HTTPS, the node-wide `[server].https_listen` socket, plus the
`Alt-Svc` h3 UDP companion on the same port when
`[server].https_http3 = true`, plus the HTTP→HTTPS redirect listener
on `[server].http_redirect_port` (default `80`); plus the
`[accept].listen` port on relay / gateway nodes. HTTPS mappings only
fire when the live rule set has at least one top-level `[[route]]`
— a terminal with no routes doesn't bind the HTTPS socket and
nothing is mapped. Listeners bound to loopback, link-local, or a
publicly-routable address are filtered out (they don't need NAT, and
mapping a public IP confuses CGNAT-traversal routers).

**Lifetime and renewal.** The daemon asks for a 2-hour mapping;
consumer routers typically clamp this to 1 hour. The daemon renews
each mapping at half the gateway-assigned lifetime and tracks the
gateway's `epoch_time` (PCP §8.5): a backwards jump means the
router rebooted or factory-reset, and the daemon re-establishes
every mapping immediately.

**Shutdown.** On `SIGTERM`, the daemon sends a `lifetime = 0`
release for each active mapping, bounded by a 3-second internal
deadline so a dead gateway can't hold up the process exit.
Mappings that don't get cleanly released expire naturally on the
router within the assigned lifetime.

**IPv4 only.** NAT-PMP is v4-only by protocol; IPv6 generally
doesn't need NAT in the first place (firewalls do "pinholing"
but the residential firewall stories vary so much that v1 punts).
IPv6 listeners are filtered out and counted under
`yggdrasil_nat_mapping_skipped_total{reason="ipv6"}`.

**CGNAT.** If your ISP gives you a 100.64.0.0/10 address, *no*
NAT-mapping protocol can punch out — your router cannot map a port
on an IP it doesn't own. Use a VPS for the public-facing role and
let `[dial]` connect outward from home.

**Observability.** `yggdrasilctl local status` prints a "NAT
traversal:" block with the current state, gateway IP, external IP,
and per-mapping detail. Prometheus series under `yggdrasil_nat_*`
expose counters for mapping creation / renewal / release / failure
and gauges for the current mapper state and active mapping count.
See `docs/operations.md` for the alert primitives.

UPnP-IGD is intentionally **not** supported: SSDP multicast +
SOAP/XML is a values mismatch with the project's `#![forbid(unsafe_
code)]` and minimum-attack-surface posture. PCP and NAT-PMP cover
every consumer router worth supporting; for routers that speak
neither, manual port forwarding remains the path.

### Complete example (root relay)

```toml
[server]

[accept]
listen = "0.0.0.0:51820"
pubkey = "x25519:9d2f04a3...4b7c"
```

### Complete example (terminal home box with HTTPS + ACME)

```toml
[server]
default_cert  = "/var/lib/yggdrasil/acme/example.com/fullchain.pem"
default_key   = "/var/lib/yggdrasil/acme/example.com/privkey.pem"
nat_traversal = "auto"

[dial]
pubkey   = "x25519:6c5a30bb...0ff1"
endpoint = "vps.example.net:51820"

[acme]
domain                  = "example.com"
contact_email           = "ops@example.com"
terms_of_service_agreed = true

[acme.dns.cloudflare]
api_token_env = "CLOUDFLARE_API_TOKEN"
```

### Complete example (mid-chain relay)

Same as a root relay, plus `[dial]` pointing at the next-hop
relay. Mode is `"relay"` because the node still accepts inbound chain
traffic from its downstream.

```toml
[server]

[dial]
pubkey   = "x25519:0123abcd...ef"
endpoint = "next-hop.example.net:51820"

[accept]
listen = "0.0.0.0:51820"
pubkey = "x25519:9d2f04a3...4b7c"
```

## Rule files

Rule files describe proxy rules. They live as `*.toml` files in the
daemon's `[server].rules_dir`. Files are loaded sorted by filename,
non-recursive. A `*.toml` extension is required; anything else is ignored.

Rules normally live on the **terminal** node. On a relay running in
single-hop mode, the proxy supervisor is fed exclusively from the
predicate-derived rule set; manual `conf.d` files there would be
overwritten on the next downstream push. (Pushing a candidate rule set
directly without writing to disk is `yggdrasilctl chain apply --file
rules.toml`.)

A rule file contains two kinds of top-level table:

* **`[[rule]]`** — an L4 listener (TCP or UDP). One rule per listener.
* **`[[route]]`** — an HTTPS virtual host. Routes are merged across
  every file in `rules_dir`; the daemon binds a single node-wide HTTPS
  listener on `[server].https_listen` and dispatches by SNI / `Host:`.

Splitting rules and routes across multiple files is cosmetic — yggdrasil
aggregates them all into one unified set with global uniqueness checks
(rule `name`s and `(ip, port, protocol)` tuples are unique across files;
route `hostname`s are unique across files).

### `[[rule]]` — repeatable

| Key              | Type                       | TCP | UDP | Default       | Notes                                                                                                              |
| ---------------- | -------------------------- | --- | --- | ------------- | ------------------------------------------------------------------------------------------------------------------ |
| `name`           | string                     | ✓   | ✓   | **required**  | Globally unique across all rule files. No whitespace or control characters.                                        |
| `listen`         | `host:port`                | ✓   | ✓   | **required**  | Listen socket. `port` must be non-zero. Globally unique by `(ip, port, protocol)`.                                 |
| `protocol`       | `"tcp"`/`"udp"`            | ✓   | ✓   | **required**  | Determines whether this is a TCP listener or a UDP receiver. `protocol = "https"` was removed in the L7 schema cleanup — use top-level `[[route]]` blocks instead. |
| `target_port`    | u16                        | ✓   | ✓   | one of these  | Relay mode. Port on the residential host. The IP comes from the heartbeat. Mutually exclusive with `target`.       |
| `target`         | `host:port`                | ✓   | ✓   | one of these  | Terminal mode. Upstream socket. If the host portion parses as an IP, the daemon dials directly (static); otherwise it's a DNS hostname that the daemon re-resolves periodically. On lookup failure the previously-resolved address is retained. New connections pick up the current resolution; existing flows are **not** rebound. Mutually exclusive with `target_port`. |
| `idle_timeout`   | `humantime`                | —   | ✓   | `60s`         | UDP only. Drop a flow if no datagrams in either direction for this long. Rejected on TCP rules.                    |
| `proxy_protocol` | `"v1"`/`"v2"`              | ✓   | —   | absent        | TCP relay rules only. Prepend a PROXY-protocol header so the upstream sees the real client IP. Rejected on UDP rules and on terminal-mode rules (rules with `target` set). |

Validation runs at load time. A malformed rule file fails the **whole**
reload — yggdrasil keeps serving the previous rule set rather than
half-applying a broken update.

### Examples (terminal mode)

```toml
# /etc/yggdrasil/conf.d/ssh.toml — TCP rule pointing at the local sshd.
[[rule]]
name     = "ssh"
listen   = "0.0.0.0:2222"
protocol = "tcp"
target   = "127.0.0.1:22"
```

```toml
# /etc/yggdrasil/conf.d/games.toml — mixed TCP + UDP. The Java rule
# uses a DNS-resolved upstream (periodic re-resolution); the others
# dial a literal IP.
[[rule]]
name     = "minecraft-java"
listen   = "0.0.0.0:25565"
protocol = "tcp"
target   = "minecraft.lan:25565"

[[rule]]
name         = "minecraft-bedrock"
listen       = "0.0.0.0:19132"
protocol     = "udp"
target       = "192.168.1.20:19132"
idle_timeout = "120s"

[[rule]]
name         = "wireguard"
listen       = "0.0.0.0:51821"
protocol     = "udp"
target       = "127.0.0.1:51820"
idle_timeout = "300s"
```

### Relay-mode rules

Relay-mode rules are normally produced by the predicate publisher on the
downstream terminal and applied to the relay's supervisor via the chain
plane — operators do not hand-author them. They look the same in
TOML, with `target_port` (no host; the IP is filled in at runtime from
the heartbeat):

```toml
# What a derived rule on a single-hop relay would look like if you dumped it.
[[rule]]
name        = "ssh"
listen      = "0.0.0.0:2222"
protocol    = "tcp"
target_port = 22
```

### `[[route]]` — HTTPS virtual hosts (terminal mode)

A `[[route]]` block declares one HTTPS virtual host served by the
terminal's node-wide HTTPS frontend. The frontend binds
`[server].https_listen` (default `0.0.0.0:443`) once, terminates TLS
for HTTP/1.1 / HTTP/2 (and QUIC/TLS for HTTP/3 when
`[server].https_http3 = true`), performs SNI / `Host:` virtual-host
routing, and forwards each request as cleartext HTTP to the
per-route `target`.

When the terminal publishes its predicate set through the chain, the
relay derives one TCP listener (HTTPS over TLS) and — when HTTP/3 is
enabled — one UDP listener (QUIC with a 30 s idle timeout) for the
configured `https_listen.port()`. Certificate resolution remains
terminal-only; the relay is L4 passthrough on both transports.

**Real client IP propagation through the chain is automatic.** On the
TCP HTTPS leg, the relay prepends a PROXY-v2 header to each new chain
connection before any TLS bytes; the terminal's accept path consumes
it before the rustls handshake. On the UDP/QUIC leg, the relay sends a
PROXY-v2 header as a standalone first datagram on each new flow; the
terminal's HTTP/3 endpoint interposes on its UDP socket
(`proxy/h3_interpose.rs`) to strip these and recover the real client
addr for `X-Forwarded-For` / `X-Real-IP` / `X-Forwarded-Proto` (and
its `X-Forwarded-Protocol` synonym, for backends that read the older
spelling) / `X-Forwarded-Host` stamping.
Operators do not configure this — there is no `proxy_protocol` field on
`[[route]]`, no `[server]` knob, and no `[[rule]]` opt-in for the
HTTPS path. The L4 `[[rule]] proxy_protocol = "v1"|"v2"` knob remains
operator-controlled because non-yggdrasil TCP backends may not speak
PROXY; HTTPS is different because both ends of the chain HTTPS leg are
yggdrasil and always agree.

| Key        | Type        | Default        | Notes                                                                                                       |
| ---------- | ----------- | -------------- | ----------------------------------------------------------------------------------------------------------- |
| `hostname` | DNS name    | **required**   | SNI / `Host:` value. Case-insensitive. Globally unique across all routes in all files.                       |
| `target`   | `http://…`  | **required**   | Backend URL. Cleartext HTTP only — the encrypted leg ends at the terminal's HTTPS frontend.                |
| `hsts`     | bool/table  | `false`        | `true` ⇒ default `Strict-Transport-Security` header. Table form (`max_age`, `include_subdomains`, `preload`) gives fine control. Cert-less routes reject `hsts`. |
| `headers`  | table       | `{}`           | Static response headers stamped onto every response from this route (proxied OR proxy-generated). Operator-set values **override** any header of the same name returned by the backend — mirrors nginx's `add_header NAME VALUE always` posture. Configure as a TOML table: `[route.headers]\n"X-Robots-Tag" = "noindex"`. Reserved names (hop-by-hop, `Strict-Transport-Security`, `Alt-Svc`, every `X-Forwarded-*` / `X-Real-IP` / `Forwarded`) are rejected at config load — use the `hsts` field for HSTS, and the request-forwarding headers are owned by the daemon. |

**Cert resolution is node-wide, not per-route.** Routes do not carry
a `cert` / `key` field. The supervisor walks a three-rung chain per
incoming SNI hostname:

1. **`[server].default_cert` + `default_key`** — wildcard / fallback
   PEM. Served whenever its SANs cover the SNI hostname. When
   `[acme]` is configured the renewer writes the wildcard cert into
   `<storage_dir>/<domain>/{fullchain,privkey}.pem`; operators
   typically point `default_cert` / `default_key` at those files so
   the watcher picks up renewals automatically.
2. **`<cert_dir>/<hostname>/{fullchain,privkey}.pem` convention** —
   a per-hostname PEM pair on disk. Useful for one-off certs sitting
   alongside an ACME wildcard.
3. **Cert-less route** — no source resolved. The hostname is **not**
   bound to the `:443` SNI table; the per-IP companion listener
   serves it as plain HTTP on `:80` to peers in
   [`[server].lan_cidrs`](#server-lan_cidrs-private-peer-set). This
   is the mechanism for LAN-only hostnames that can't get a
   public-CA cert (`*.local`, internal `*.lan`, etc.). Operators
   see a `WARN` log line per cert-less route at startup naming the
   consequence; the `yggdrasil_certless_routes` gauge tracks the
   live count.

```toml
# /etc/yggdrasil/conf.d/web.toml — three virtual hosts on one terminal.

[[route]]
hostname = "api.example.com"
target   = "http://10.0.0.10:8080"
hsts     = true
# Cert comes from `[server].default_cert` (the wildcard *.example.com).
# Stamp a few static response headers on every response — equivalent
# to nginx `add_header NAME VALUE always`.
[route.headers]
"X-Robots-Tag"            = "noindex, nofollow, nosnippet, noarchive"
"X-Frame-Options"         = "DENY"
"X-Content-Type-Options"  = "nosniff"
"Content-Security-Policy" = "default-src 'self'"

[[route]]
hostname = "app.example.com"
target   = "http://10.0.0.11:3000"
# Same — covered by the wildcard.

[[route]]
hostname = "internal.lan"
target   = "http://192.168.1.50:8080"
# Intentionally cert-less: served on :80 plaintext to LAN peers only
# (no SNI match on :443). `hsts` would be rejected by the validator.
```

### `[server].lan_cidrs` (private-peer set)

Optional list of CIDR strings that define which peer IPs are
considered "local" by the per-IP companion listener's cert-less route
branch. When unset (the default), yggdrasil uses a hard-coded set
matching the well-known private-addressing ranges:

| CIDR              | RFC                  |
| ----------------- | -------------------- |
| `127.0.0.0/8`     | RFC 1122 §3.2.1.3    |
| `10.0.0.0/8`      | RFC 1918             |
| `172.16.0.0/12`   | RFC 1918             |
| `192.168.0.0/16`  | RFC 1918             |
| `::1/128`         | RFC 4291 §2.5.3      |
| `fc00::/7`        | RFC 4193 (ULA)       |

Setting `lan_cidrs` replaces the default set entirely:

```toml
[server]
# Narrow to just the home LAN (excludes loopback, docker bridges, ULA, etc.)
lan_cidrs = ["192.168.1.0/24"]

# Or widen to include Tailscale's CGNAT range (RFC 6598):
lan_cidrs = ["192.168.0.0/16", "100.64.0.0/10"]

# Or explicitly disable cert-less route serving:
lan_cidrs = []

# Or expose cert-less routes publicly (explicit footgun):
lan_cidrs = ["0.0.0.0/0", "::/0"]
```

The resolved set + source (`default` vs `override`) is logged at
startup and surfaced by `yggdrasilctl local status` whenever the
daemon has at least one cert-less route loaded.

## Environment variables

Most CLI flags also bind to environment variables, listed here for
completeness:

| Variable                    | Equivalent flag                             | Used by         |
| --------------------------- | ------------------------------------------- | --------------- |
| `YGGDRASIL_LOG_FORMAT`      | `--log-format`                              | `yggdrasil`     |
| `YGGDRASIL_LOG`             | (`tracing-subscriber` env-filter)           | `yggdrasil`     |
| `YGGDRASIL_CONFIG`          | `--config` (default for `yggdrasil run`, and `yggdrasilctl identity`) | `yggdrasil`, `yggdrasilctl` |
| `YGGDRASIL_RULES_DIR`       | `--rules-dir` (overrides `[server].rules_dir`) | `yggdrasil`    |
| `YGGDRASIL_CONTROL_SOCKET`  | `--socket`                                  | `yggdrasilctl`  |

## Hot reload semantics

* The rules watcher uses `inotify` with a 250 ms debounce. Drop a new file,
  rename it into place, or `vim` it — within ~250 ms the diff is applied.
* A reload that fails validation is **rejected as a unit**. The previous
  rule set keeps serving traffic; the error is logged.
* `[[rule]]` (L4 listener) changes are reconciled per-rule: unchanged
  rules' listeners and in-flight flows survive the reload untouched;
  added rules spawn fresh listeners; removed rules stop instantly;
  changed rules swap on the same `listen` address.
* `[[route]]` (HTTPS virtual host) changes currently trigger a full
  stop+respawn of the node-wide HTTPS frontend on `[server].https_listen`.
  In-flight HTTPS connections are cancelled at the swap boundary (no
  grace period). Per-route diffing is a deferred follow-up; L4 rules
  are unaffected.
* Changes to **`/etc/yggdrasil/config.toml`** itself are not hot-reloaded;
  restart the daemon (`systemctl restart yggdrasil`). Only `conf.d/*.toml`
  files are picked up live. In particular, the `[dial]`, `[accept]`, `[acme]`,
  and HTTPS-related `[server]` knobs (`https_listen`, `https_http3`,
  `https_alt_svc`, `https_request_body_limit`, `default_cert`,
  `default_key`, `cert_dir`) are read
  once at startup — `yggdrasilctl identity add-dial` / `add-accept` /
  `remove-*` mutations require a restart to take effect.
* `yggdrasilctl local rules reload` forces a re-scan in case you suspect
  the inotify event was missed (NFS, container bind mounts with cached
  metadata, etc.).
* `yggdrasilctl chain apply --file rules.toml` pushes a pre-validated
  rule vector into the running terminal daemon's supervisor without
  touching `rules_dir`. The daemon re-validates server-side and rejects
  the apply as a unit on any cross-rule conflict.
