# Configuration reference

There are two config artefacts. Both are TOML with
`#[serde(deny_unknown_fields)]`, so a typo is a hard parse error — there
are no silently-ignored keys.

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
| `rules_dir`        | path                   | `/etc/yggdrasil/conf.d`          | Watched for `*.toml`. Non-recursive. Missing dir is a hard error at startup.                   |
| `default_bind`     | IP                     | unset                            | If set, hard-rewrites every rule's `listen` IP to this address (the port is preserved). Used to share one config across hosts with different network interfaces. |
| `udp_workers`      | optional positive integer | unset (`None` → `available_parallelism()` at proxy spawn) | Per-host default for every UDP rule unless the rule sets `udp_workers`; `0` is rejected. |
| `state_dir`        | path                   | `/var/lib/yggdrasil`             | Per-host state — TOFU candidates, runtime markers.                                             |
| `identity_file`    | path                   | `/etc/yggdrasil/identity.key`    | Long-term X25519 identity (64 bytes: 32 secret ++ 32 public). Mode 0600. Auto-generated on first start if missing. |
| `cert_dir`         | path                   | `/etc/yggdrasil/certs`           | HTTPS only. Directory consulted by the convention cert-source rung (`<cert_dir>/<hostname>/{fullchain,privkey}.pem`). |
| `default_cert`     | path                   | unset                            | HTTPS only. Wildcard / fallback certificate PEM. Must be set together with `default_key`.       |
| `default_key`      | path                   | unset                            | HTTPS only. Private key PEM matching `default_cert`. Must be set together with it.              |

Mode is derived from section presence:

* `[dial]` only => `terminal`
* `[accept]` only => `relay` (root relay)
* `[dial]` + `[accept]` => `relay` (mid-chain relay)
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
session. Presence of `[accept]` makes the effective mode `relay`.

| Key                  | Type           | Default | Notes                                                                  |
| -------------------- | -------------- | ------- | ---------------------------------------------------------------------- |
| `pubkey`             | tagged pubkey  | **required** | `x25519:<hex>` of the downstream node. Written by `yggdrasilctl identity add-accept` or `local accept approve`. |
| `listen`             | `host:port`    | **required** | UDP socket to bind. Public-facing on the root relay.                  |
| `rekey_interval`     | `humantime`    | `1h`    | Force a fresh Noise handshake at most this often.                      |

### Complete example (root relay)

```toml
[server]

[accept]
listen = "0.0.0.0:51820"
pubkey = "x25519:9d2f04a3...4b7c"
```

### Complete example (terminal home box)

```toml
[server]

[dial]
pubkey   = "x25519:6c5a30bb...0ff1"
endpoint = "vps.example.net:51820"
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

Each file contains zero or more `[[rule]]` tables. Splitting rules into
multiple files is purely cosmetic — yggdrasil aggregates them all into
one unified rule set with global uniqueness checks.

### `[[rule]]` — repeatable

| Key              | Type                       | TCP | UDP | HTTPS | Default       | Notes                                                                                                              |
| ---------------- | -------------------------- | --- | --- | ----- | ------------- | ------------------------------------------------------------------------------------------------------------------ |
| `name`           | string                     | ✓   | ✓   | ✓     | **required**  | Globally unique across all rule files. No whitespace or control characters.                                        |
| `listen`         | `host:port`                | ✓   | ✓   | ✓     | **required**  | Listen socket. `port` must be non-zero. Globally unique by `(ip, port, protocol)`.                                 |
| `protocol`       | `"tcp"`/`"udp"`/`"https"`  | ✓   | ✓   | ✓     | **required**  | Determines whether this is a TCP listener, a UDP receiver, or the HTTPS L7 frontend.                                |
| `target_port`  | u16                        | ✓   | ✓   | —     | one of these  | Relay mode. Port on the residential host. The IP comes from the heartbeat. Mutually exclusive with `target_addr` and `target_host`. |
| `target_addr`  | `host:port`                | ✓   | ✓   | —     | one of these  | Terminal mode. Literal upstream socket address. Mutually exclusive with `target_port` and `target_host`.       |
| `target_host`  | `host:port`                | ✓   | ✓   | —     | one of these  | Terminal mode. DNS-resolved upstream. Re-resolves periodically; on lookup failure, retains the previously-resolved address. New connections pick up the current resolution; existing flows are **not** rebound. Mutually exclusive with `target_port` and `target_addr`. |
| `idle_timeout`   | `humantime`                | —   | ✓   | —     | `60s`         | UDP only. Drop a flow if no datagrams in either direction for this long. Rejected on TCP / HTTPS rules.            |
| `udp_workers`    | optional positive integer  | —   | ✓   | —     | inherits from `[server]` | UDP only. Overrides `[server].udp_workers` for this rule; `0` is rejected. Rejected on TCP / HTTPS rules. |
| `proxy_protocol` | `"v1"`/`"v2"`              | ✓   | —   | —     | absent        | TCP relay rules only. Prepend a PROXY-protocol header so the upstream sees the real client IP. Rejected on UDP / HTTPS rules and on terminal-mode rules (`target_addr` / `target_host`). |
| `cert_dir`       | path                       | —   | —   | ✓     | inherits from `[server]` | HTTPS only. Per-rule override of the convention cert directory.                                          |
| `http3`          | `Option<bool>`             | —   | —   | ✓     | `true`        | HTTPS only. Enables HTTP/3 over UDP / QUIC on the same `(ip, port)` as TCP HTTPS. Set `http3 = false` to opt out and derive / listen TCP only. |
| `alt_svc`        | `Option<bool>`             | —   | —   | ✓     | `true` when `http3` is on | HTTPS only. Controls the TCP HTTPS `Alt-Svc: h3=":<port>"; ma=86400` response header that advertises HTTP/3. Set `alt_svc = false` to suppress it. `alt_svc = true` with `http3 = false` is rejected. |
| `[[rule.route]]` | table                      | —   | —   | ✓     | **required**  | HTTPS only. One entry per virtual host — see the HTTPS section below.                                              |

Validation runs at load time. A malformed rule file fails the **whole**
reload — yggdrasil keeps serving the previous rule set rather than half-
applying a broken update.

### Examples (terminal mode)

```toml
# /etc/yggdrasil/conf.d/ssh.toml — TCP rule pointing at the local sshd.
[[rule]]
name          = "ssh"
listen        = "0.0.0.0:2222"
protocol      = "tcp"
target_addr = "127.0.0.1:22"
```

```toml
# /etc/yggdrasil/conf.d/games.toml — mixed TCP + UDP, DNS-resolved upstream.
[[rule]]
name          = "minecraft-java"
listen        = "0.0.0.0:25565"
protocol      = "tcp"
target_host = "minecraft.lan:25565"

[[rule]]
name          = "minecraft-bedrock"
listen        = "0.0.0.0:19132"
protocol      = "udp"
target_addr = "192.168.1.20:19132"
idle_timeout  = "120s"

[[rule]]
name          = "wireguard"
listen        = "0.0.0.0:51821"
protocol      = "udp"
target_addr = "127.0.0.1:51820"
idle_timeout  = "300s"
```

```toml
# /etc/yggdrasil/conf.d/printer.toml — DNS hostname, periodically re-resolved.
# Rebinds apply to *new* flows only — long-lived TCP sessions and UDP flows
# are not torn down when the address changes (matching nginx / haproxy
# semantics).
[[rule]]
name          = "printer"
listen        = "0.0.0.0:9100"
protocol      = "tcp"
target_host = "printer.lan:9100"
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
name          = "ssh"
listen        = "0.0.0.0:2222"
protocol      = "tcp"
target_port = 22
```

### HTTPS rules

An `https` rule on the terminal is the L7 frontend. It terminates TLS for
HTTP/1.1 and HTTP/2, terminates QUIC/TLS for HTTP/3 unless `http3 = false`,
performs SNI-based virtual-host routing, and forwards each request as
cleartext HTTP to a per-route backend URL. Each `[[rule.route]]` table is
one virtual host.

HTTPS rules with `http3` enabled (the default) automatically listen on both
TCP and UDP `(ip, port)`. The QUIC listener shares the rule's cert
resolution and route table with the TCP path.

When the terminal publishes the rule through the chain, operators no longer
need to manually create matching TCP/443 plus UDP/443 passthrough rules on
the relay. A terminal HTTPS rule publishes one HTTPS predicate; the relay
derives TCP for the TLS listener and, when HTTP/3 is enabled, UDP with a
30s idle timeout for QUIC datagrams. Certificate resolution remains
terminal-only; the relay is L4 passthrough on both transports.

| Key              | Type        | Default              | Notes                                                                                                       |
| ---------------- | ----------- | -------------------- | ----------------------------------------------------------------------------------------------------------- |
| `hostname`       | DNS name    | **required**         | SNI / `Host:` value. Case-insensitive. Globally unique across all https routes.                             |
| `target`         | `http://…`  | **required**         | Backend URL. Cleartext HTTP only — the encrypted leg ends at the terminal HTTPS frontend.                   |
| `cert`           | path or `"ephemeral"` | unset      | Per-route certificate. A path PEM pairs with `key`. The literal string `"ephemeral"` generates a self-signed cert in memory — only valid for localhost-shaped hostnames (testing). |
| `key`            | path        | unset                | Per-route private key PEM. Must accompany a path-style `cert`; forbidden with `cert = "ephemeral"`.         |
| `hsts`           | bool/table  | `false`              | `true` ⇒ default `Strict-Transport-Security` header. Table form (`max_age`, `include_subdomains`, `preload`) gives fine control. |

Cert source precedence (per route): explicit `cert` + `key` paths →
`cert = "ephemeral"` → `<cert_dir>/<hostname>/{fullchain,privkey}.pem`
convention → `server.default_cert` + `server.default_key` → hard error at
load time.

```toml
# /etc/yggdrasil/conf.d/web.toml
[[rule]]
name     = "public-https"
listen   = "0.0.0.0:443"
protocol = "https"

  [[rule.route]]
  hostname = "api.example.com"
  target   = "http://10.0.0.10:8080"
  cert     = "/etc/yggdrasil/certs/api.example.com.crt"
  key      = "/etc/yggdrasil/certs/api.example.com.key"
  hsts     = true

  [[rule.route]]
  hostname = "app.example.com"
  target   = "http://10.0.0.11:3000"
  # No explicit cert — falls through to the cert_dir convention or the default cert.
```

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
* Changes to **`/etc/yggdrasil/config.toml`** itself are not hot-reloaded;
  restart the daemon (`systemctl restart yggdrasil`). Only `conf.d/*.toml`
  files are picked up live. In particular, the `[dial]` and `[accept]` tables are
  read once at startup — `yggdrasilctl identity add-dial` /
  `add-accept` / `remove-*` mutations require a restart to take
  effect.
* `yggdrasilctl local rules reload` forces a re-scan in case you suspect
  the inotify event was missed (NFS, container bind mounts with cached
  metadata, etc.).
* `yggdrasilctl chain apply --file rules.toml` pushes a pre-validated
  rule vector into the running terminal daemon's supervisor without
  touching `rules_dir`. The daemon re-validates server-side and rejects
  the apply as a unit on any cross-rule conflict.
