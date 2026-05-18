# Configuration reference

There are three config artefacts. All are TOML with `#[serde(deny_unknown_fields)]`,
so a typo is a hard parse error — there are no silently-ignored keys.

| File                                  | Owner   | Purpose                                |
| ------------------------------------- | ------- | -------------------------------------- |
| `/etc/yggdrasil/config.toml`          | VPS     | Top-level yggdrasil daemon config.     |
| `/etc/yggdrasil/conf.d/*.toml`      | VPS     | One or more files defining proxy rules.|
| `/etc/huginn/config.toml`          | Home    | huginn heartbeat client config.     |

The defaults below are what you get when a field is omitted entirely.
`humantime` values accept the usual `1h`, `30s`, `250ms`, etc.

## `/etc/yggdrasil/config.toml`

### `[server]` — required

| Key                | Type                | Default                          | Notes                                                                                          |
| ------------------ | ------------------- | -------------------------------- | ---------------------------------------------------------------------------------------------- |
| `mode`             | `"relay"`/`"terminal"` | `relay`                      | `relay` runs heartbeats + forwards traffic to a huginn peer. `terminal` skips heartbeats and forwards to literal `upstream_addr` targets (useful for the home-side leg of a two-hop chain). |
| `heartbeat_listen` | `host:port`         | **required for relay**           | UDP only. The single socket huginn talks to. Public-facing. Must be omitted in terminal mode. |
| `rules_dir`        | path                | `/etc/yggdrasil/conf.d`          | Watched for `*.toml`. Non-recursive. Missing dir is a hard error at startup.                   |
| `default_bind`     | IP                  | unset                            | If set, rewrites a rule’s wildcard `0.0.0.0`/`[::]` listen to this address. Explicit rule listens are untouched. |
| `state_dir`        | path                | `/var/lib/yggdrasil`             | Persistent per-host state — TOFU candidates, last-known peer IP cache.                         |
| `identity_file`    | path                | `/etc/yggdrasil/identity.key`    | Long-term X25519 secret. Mode 0600.                                                            |
| `cert_dir`         | path                | `/etc/yggdrasil/certs`           | HTTPS only. Directory consulted by the “convention” cert-source rung (`<cert_dir>/<hostname>.{crt,key}`). |
| `default_cert`     | path                | unset                            | HTTPS only. Wildcard / fallback certificate PEM. Must be set together with `default_key`.       |
| `default_key`      | path                | unset                            | HTTPS only. Private key PEM matching `default_cert`. Must be set together with it.              |

### `[metrics]` — optional

| Key      | Type        | Default            | Notes                                                                                |
| -------- | ----------- | ------------------ | ------------------------------------------------------------------------------------ |
| `listen` | `host:port` | `127.0.0.1:9090`   | Prometheus `/metrics` endpoint. Bind to loopback and front with whatever scraper you trust. |

### `[control]` — optional

| Key      | Type | Default                         | Notes                                                                                            |
| -------- | ---- | ------------------------------- | ------------------------------------------------------------------------------------------------ |
| `socket` | path | `/run/yggdrasil/control.sock`   | Unix domain socket for `yggdrasilctl`. Restrict to an admin group via filesystem permissions.    |

### `[peer]` — optional, but you'll have one once enrolled

| Key                | Type             | Default | Notes                                                                                              |
| ------------------ | ---------------- | ------- | -------------------------------------------------------------------------------------------------- |
| `public_key_hex`   | 64-char hex      | `""`    | X25519 pubkey of the enrolled huginn. Empty until you run `yggdrasil enroll-token`. **TOFU** approval (via `yggdrasilctl peer approve`) can populate this instead. |
| `rekey_interval`   | `humantime`      | `1h`    | Force a fresh Noise handshake at most this often, regardless of traffic.                           |

Complete example:

```toml
[server]
mode             = "relay"
heartbeat_listen = "0.0.0.0:51820"
rules_dir        = "/etc/yggdrasil/conf.d"
state_dir        = "/var/lib/yggdrasil"
identity_file    = "/etc/yggdrasil/identity.key"
# Optional HTTPS knobs (omit if you don’t run https rules):
# cert_dir       = "/etc/yggdrasil/certs"
# default_cert   = "/etc/yggdrasil/certs/wildcard.pem"
# default_key    = "/etc/yggdrasil/certs/wildcard.key"

[metrics]
listen = "127.0.0.1:9090"

[control]
socket = "/run/yggdrasil/control.sock"

[peer]
public_key_hex = "9d2f...4b7c"
rekey_interval = "1h"
```

## `/etc/huginn/config.toml`

### `[client]` — required

| Key                    | Type             | Default                          | Notes                                                                                          |
| ---------------------- | ---------------- | -------------------------------- | ---------------------------------------------------------------------------------------------- |
| `yggdrasil_endpoint`   | `host:port`      | **required**                     | DNS hostname **or** literal IP. Re-resolved on each handshake attempt, so dynamic DNS for the VPS works too. |
| `yggdrasil_pubkey_hex` | 64-char hex      | **required**                     | Server's pubkey. Filled in by `huginn enroll`.                                              |
| `identity_file`        | path             | `/etc/huginn/identity.key`    | Long-term X25519 secret. Mode 0600.                                                            |
| `heartbeat_interval`   | `humantime`      | `5s`                             | How often to emit a heartbeat. Lower = faster IP-change reaction; higher = less wakeups.       |
| `rekey_interval`       | `humantime`      | `1h`                             | Force re-handshake at most this often.                                                         |

Complete example:

```toml
[client]
yggdrasil_endpoint   = "vps.example.net:51820"
yggdrasil_pubkey_hex = "6c5a...0ff1"
identity_file        = "/etc/huginn/identity.key"
heartbeat_interval   = "5s"
rekey_interval       = "1h"
```

## Rule files

Rule files describe proxy rules. They live as `*.toml` files in the
yggdrasil server’s `rules_dir`. Files are loaded sorted by filename,
non-recursive. A `*.toml` extension is required; anything else is ignored.

Each file contains zero or more `[[rule]]` tables. Splitting rules into
multiple files is purely cosmetic — yggdrasil aggregates them all into one
unified rule set with global uniqueness checks.

### `[[rule]]` — repeatable

| Key              | Type                       | TCP | UDP | HTTPS | Default       | Notes                                                                                                  |
| ---------------- | -------------------------- | --- | --- | ----- | ------------- | ------------------------------------------------------------------------------------------------------ |
| `name`           | string                     | ✓   | ✓   | ✓     | **required**  | Globally unique across all rule files. No whitespace or control characters.                            |
| `listen`         | `host:port`                | ✓   | ✓   | ✓     | **required**  | Listen socket on the VPS. `port` must be non-zero. Globally unique by `(ip, port, protocol)`.          |
| `protocol`       | `"tcp"`/`"udp"`/`"https"` | ✓   | ✓   | ✓     | **required**  | Determines whether this is a TCP listener, a UDP receiver, or the HTTPS frontend.                      |
| `upstream_port`  | u16                        | ✓   | ✓   | —     | one of these  | Port on the home box. The IP comes from the heartbeat. Mutually exclusive with `upstream_addr`.        |
| `upstream_addr`  | `host:port`                | ✓   | ✓   | —     | one of these  | Literal upstream socket address — used by terminal-mode rules and tests. Mutually exclusive with `upstream_port`. |
| `idle_timeout`   | `humantime`                | —   | ✓   | —     | `60s`         | UDP only. Drop a flow if no datagrams in either direction for this long. Rejected on TCP / HTTPS rules. |
| `proxy_protocol` | `"v1"`/`"v2"`             | ✓   | —   | —     | absent        | TCP only. Prepend a PROXY-protocol header so the upstream sees the real client IP. Rejected on UDP / HTTPS rules and when `upstream_addr` is set. |
| `cert_dir`       | path                       | —   | —   | ✓     | inherits from `[server]` | HTTPS only. Per-rule override of the convention cert directory.                                       |
| `[[rule.route]]` | table                      | —   | —   | ✓     | **required**  | HTTPS only. One entry per virtual host — see the HTTPS section below.                                  |

Validation runs at load time. A malformed rule file fails the **whole**
reload — yggdrasil keeps serving the previous rule set rather than half-
applying a broken update.

### Examples

```toml
# /etc/yggdrasil/conf.d/ssh.toml — a single TCP rule
[[rule]]
name          = "ssh"
listen        = "0.0.0.0:2222"
protocol      = "tcp"
upstream_port = 22
```

```toml
# /etc/yggdrasil/conf.d/games.toml — multiple rules, mixed protocols
[[rule]]
name          = "minecraft-java"
listen        = "0.0.0.0:25565"
protocol      = "tcp"
upstream_port = 25565

[[rule]]
name          = "minecraft-bedrock"
listen        = "0.0.0.0:19132"
protocol      = "udp"
upstream_port = 19132
idle_timeout  = "120s"

[[rule]]
name          = "wireguard"
listen        = "0.0.0.0:51821"
protocol      = "udp"
upstream_port = 51820
idle_timeout  = "300s"
```

```toml
# A TCP rule with PROXY protocol so the home-side service sees the real client IP.
[[rule]]
name           = "nginx-public"
listen         = "0.0.0.0:443"
protocol       = "tcp"
upstream_port  = 443
proxy_protocol = "v2"
```

```toml
# A terminal-mode rule that forwards to a literal upstream socket. No huginn
# heartbeat is involved; this shape is normally used on the home-side leg of a
# two-hop chain.
[[rule]]
name          = "ssh-local"
listen        = "127.0.0.1:2222"
protocol      = "tcp"
upstream_addr = "192.168.1.10:22"
```

### HTTPS rules

An `https` rule terminates TLS on the VPS, performs SNI-based virtual-host
routing, and forwards each request as cleartext HTTP to a per-route
backend URL. Each `[[rule.route]]` table is one virtual host.

| Key              | Type        | Default              | Notes                                                                                                       |
| ---------------- | ----------- | -------------------- | ----------------------------------------------------------------------------------------------------------- |
| `hostname`       | DNS name    | **required**         | SNI / `Host:` value. Case-insensitive. Globally unique across all https routes.                             |
| `upstream`       | `http://…`  | **required**         | Backend URL. Cleartext HTTP only — the encrypted leg ends at the VPS.                                       |
| `cert`           | path or `"ephemeral"` | unset      | Per-route certificate. A path PEM pairs with `key`. The literal string `"ephemeral"` generates a self-signed cert in memory — only valid for localhost-shaped hostnames (testing). |
| `key`            | path        | unset                | Per-route private key PEM. Must accompany a path-style `cert`; forbidden with `cert = "ephemeral"`.         |
| `hsts`           | bool/table  | `false`              | `true` ⇒ default `Strict-Transport-Security` header. Table form (`max_age`, `include_subdomains`, `preload`) gives fine control. |

Cert source precedence (per route): explicit `cert` + `key` paths →
`cert = "ephemeral"` → `<cert_dir>/<hostname>.{crt,key}` convention →
`server.default_cert` + `server.default_key` → hard error at load time.

```toml
# /etc/yggdrasil/conf.d/web.toml
[[rule]]
name     = "public-https"
listen   = "0.0.0.0:443"
protocol = "https"

  [[rule.route]]
  hostname = "api.example.com"
  upstream = "http://10.0.0.10:8080"
  cert     = "/etc/yggdrasil/certs/api.example.com.crt"
  key      = "/etc/yggdrasil/certs/api.example.com.key"
  hsts     = true

  [[rule.route]]
  hostname = "app.example.com"
  upstream = "http://10.0.0.11:3000"
  # No explicit cert — falls through to the cert_dir convention or the default cert.
```

## Environment variables

Most CLI flags also bind to environment variables, listed here for completeness:

| Variable                    | Equivalent flag                             | Used by         |
| --------------------------- | ------------------------------------------- | --------------- |
| `YGGDRASIL_LOG_FORMAT`      | `--log-format`                              | `yggdrasil`     |
| `YGGDRASIL_CONFIG`          | `--config` (default for `yggdrasil run`)    | `yggdrasil`     |
| `YGGDRASIL_RULES_DIR`    | `--rules-dir` (overrides `server.rules_dir`) | `yggdrasil`     |
| `YGGDRASIL_CONTROL_SOCKET`  | `--socket`                                  | `yggdrasilctl`  |
| `HUGINN_LOG_FORMAT`      | `--log-format`                              | `huginn`     |
| `HUGINN_CONFIG`          | `--config` (default for `huginn run`)    | `huginn`     |

## Hot reload semantics

- The rules watcher uses `inotify` with a 250 ms debounce. Drop a new file,
  rename it into place, or `vim` it — within ~250 ms the diff is applied.
- A reload that fails validation is **rejected as a unit**. The previous
  rule set keeps serving traffic; the error is logged.
- Changes to **`/etc/yggdrasil/config.toml`** itself are not hot-reloaded;
  restart the daemon (`systemctl restart yggdrasil`). Only `conf.d/*.toml`
  are picked up live.
- `yggdrasilctl rules reload` forces a re-scan in case you suspect the
  inotify event was missed (e.g. NFS, container bind mounts with cached metadata).
