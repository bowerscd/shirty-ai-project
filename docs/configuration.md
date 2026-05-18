# Configuration reference

There are three config artefacts. All are TOML with `#[serde(deny_unknown_fields)]`,
so a typo is a hard parse error — there are no silently-ignored keys.

| File                                  | Owner   | Purpose                                |
| ------------------------------------- | ------- | -------------------------------------- |
| `/etc/yggdrasil/config.toml`          | VPS     | Top-level yggdrasil daemon config.     |
| `/etc/yggdrasil/branches/*.toml`      | VPS     | One or more files defining proxy rules.|
| `/etc/ratatoskr/config.toml`          | Home    | ratatoskr heartbeat client config.     |

The defaults below are what you get when a field is omitted entirely.
`humantime` values accept the usual `1h`, `30s`, `250ms`, etc.

## `/etc/yggdrasil/config.toml`

### `[server]` — required

| Key                | Type           | Default                          | Notes                                                                                          |
| ------------------ | -------------- | -------------------------------- | ---------------------------------------------------------------------------------------------- |
| `heartbeat_listen` | `host:port`    | **required**                     | UDP only. The single socket ratatoskr talks to. Public-facing.                                 |
| `branches_dir`     | path           | **required**                     | Watched for `*.toml`. Non-recursive. Missing dir is a hard error at startup.                   |
| `state_dir`        | path           | `/var/lib/yggdrasil`             | Persistent per-host state — TOFU candidates, last-known peer IP cache.                         |
| `identity_file`    | path           | `/etc/yggdrasil/identity.key`    | Long-term X25519 secret. Mode 0600.                                                            |

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
| `public_key_hex`   | 64-char hex      | `""`    | X25519 pubkey of the enrolled ratatoskr. Empty until you run `yggdrasil enroll-token`. **TOFU** approval (via `yggdrasilctl peer approve`) can populate this instead. |
| `rekey_interval`   | `humantime`      | `1h`    | Force a fresh Noise handshake at most this often, regardless of traffic.                           |

Complete example:

```toml
[server]
heartbeat_listen = "0.0.0.0:51820"
branches_dir     = "/etc/yggdrasil/branches"
state_dir        = "/var/lib/yggdrasil"
identity_file    = "/etc/yggdrasil/identity.key"

[metrics]
listen = "127.0.0.1:9090"

[control]
socket = "/run/yggdrasil/control.sock"

[peer]
public_key_hex = "9d2f...4b7c"
rekey_interval = "1h"
```

## `/etc/ratatoskr/config.toml`

### `[client]` — required

| Key                    | Type             | Default                          | Notes                                                                                          |
| ---------------------- | ---------------- | -------------------------------- | ---------------------------------------------------------------------------------------------- |
| `yggdrasil_endpoint`   | `host:port`      | **required**                     | DNS hostname **or** literal IP. Re-resolved on each handshake attempt, so dynamic DNS for the VPS works too. |
| `yggdrasil_pubkey_hex` | 64-char hex      | **required**                     | Server's pubkey. Filled in by `ratatoskr enroll`.                                              |
| `identity_file`        | path             | `/etc/ratatoskr/identity.key`    | Long-term X25519 secret. Mode 0600.                                                            |
| `heartbeat_interval`   | `humantime`      | `5s`                             | How often to emit a heartbeat. Lower = faster IP-change reaction; higher = less wakeups.       |
| `rekey_interval`       | `humantime`      | `1h`                             | Force re-handshake at most this often.                                                         |

Complete example:

```toml
[client]
yggdrasil_endpoint   = "vps.example.net:51820"
yggdrasil_pubkey_hex = "6c5a...0ff1"
identity_file        = "/etc/ratatoskr/identity.key"
heartbeat_interval   = "5s"
rekey_interval       = "1h"
```

## Branch files

Branch files describe proxy rules. They live as `*.toml` files in the
yggdrasil server's `branches_dir`. Files are loaded sorted by filename,
non-recursive. A `*.toml` extension is required; anything else is ignored.

Each file contains zero or more `[[rule]]` tables. Splitting rules into
multiple files is purely cosmetic — yggdrasil aggregates them all into one
unified rule set with global uniqueness checks.

### `[[rule]]` — repeatable

| Key              | Type            | TCP | UDP | Default       | Notes                                                                                                  |
| ---------------- | --------------- | --- | --- | ------------- | ------------------------------------------------------------------------------------------------------ |
| `name`           | string          | ✓   | ✓   | **required**  | Globally unique across all branch files. No whitespace or control characters.                          |
| `listen`         | `host:port`     | ✓   | ✓   | **required**  | Listen socket on the VPS. `port` must be non-zero. Globally unique by `(ip, port, protocol)`.          |
| `protocol`       | `"tcp"`/`"udp"` | ✓   | ✓   | **required**  | Determines whether this is a TCP listener or a UDP receiver.                                           |
| `upstream_port`  | u16             | ✓   | ✓   | **required**  | Port on the home box. The IP comes from the heartbeat, not from here. Must be non-zero.                |
| `idle_timeout`   | `humantime`     | —   | ✓   | `60s`         | UDP only. Drop a flow if no datagrams in either direction for this long. Rejected on TCP rules.        |
| `proxy_protocol` | `"v1"`/`"v2"`   | ✓   | —   | absent        | TCP only. Prepend a PROXY-protocol header so the upstream sees the real client IP. Rejected on UDP rules. |

Validation runs at load time. A malformed branch file fails the **whole**
reload — yggdrasil keeps serving the previous rule set rather than half-
applying a broken update.

### Examples

```toml
# /etc/yggdrasil/branches/ssh.toml — a single TCP rule
[[rule]]
name          = "ssh"
listen        = "0.0.0.0:2222"
protocol      = "tcp"
upstream_port = 22
```

```toml
# /etc/yggdrasil/branches/games.toml — multiple rules, mixed protocols
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

## Environment variables

Most CLI flags also bind to environment variables, listed here for completeness:

| Variable                    | Equivalent flag                             | Used by         |
| --------------------------- | ------------------------------------------- | --------------- |
| `YGGDRASIL_LOG_FORMAT`      | `--log-format`                              | `yggdrasil`     |
| `YGGDRASIL_CONFIG`          | `--config` (default for `yggdrasil run`)    | `yggdrasil`     |
| `YGGDRASIL_BRANCHES_DIR`    | `--branches-dir` (overrides `server.branches_dir`) | `yggdrasil`     |
| `YGGDRASIL_CONTROL_SOCKET`  | `--socket`                                  | `yggdrasilctl`  |
| `RATATOSKR_LOG_FORMAT`      | `--log-format`                              | `ratatoskr`     |
| `RATATOSKR_CONFIG`          | `--config` (default for `ratatoskr run`)    | `ratatoskr`     |

## Hot reload semantics

- The branches watcher uses `inotify` with a 250 ms debounce. Drop a new file,
  rename it into place, or `vim` it — within ~250 ms the diff is applied.
- A reload that fails validation is **rejected as a unit**. The previous
  rule set keeps serving traffic; the error is logged.
- Changes to **`/etc/yggdrasil/config.toml`** itself are not hot-reloaded;
  restart the daemon (`systemctl restart yggdrasil`). Only `branches/*.toml`
  are picked up live.
- `yggdrasilctl branches reload` forces a re-scan in case you suspect the
  inotify event was missed (e.g. NFS, container bind mounts with cached metadata).
