# CLI reference

Every subcommand exposed by the three binaries, with its real flags and
defaults. Where a flag also reads from an environment variable, that's
called out.

Conventions:

- All three binaries accept `--help` / `-h` and `--version`.
- Log format selectors are **global** flags (`--log-format json|pretty`)
  available on every subcommand; the daemons default to `json`.
- Paths default to the `/etc/...` layout from [install.md](install.md). Override
  with `--config` or `--identity-file` for non-standard layouts.

---

## `yggdrasil`

The reverse-proxy daemon. Runs on the VPS.

### `yggdrasil run`

Start the daemon. The foreground process you'll wire into systemd.

| Flag                | Env var                  | Default                              | Notes                                                                  |
| ------------------- | ------------------------ | ------------------------------------ | ---------------------------------------------------------------------- |
| `--config`          | `YGGDRASIL_CONFIG`       | `/etc/yggdrasil/config.toml`         | Path to the server config file.                                        |
| `--branches-dir`    | `YGGDRASIL_BRANCHES_DIR` | (value from `config.toml`)           | Override `server.branches_dir` without editing the config — useful for tests. |

Exits 0 on SIGTERM/SIGINT, non-zero on startup error (bad config, key not
loadable, port already in use).

### `yggdrasil keygen`

Generate the server's long-term X25519 identity.

| Flag              | Default                          | Notes                                                                |
| ----------------- | -------------------------------- | -------------------------------------------------------------------- |
| `--identity-file` | `/etc/yggdrasil/identity.key`    | Output path. Written with mode 0600.                                 |
| `--force`         | (off)                            | Overwrite an existing file. Default refuses to clobber.              |

Prints the pubkey (hex) and short fingerprint to stdout. The secret never
leaves the file.

### `yggdrasil enroll-token`

Mint an out-of-band enrollment token for a ratatoskr peer. Also stamps
`peer.public_key_hex` into the yggdrasil config so the peer is "official"
right away.

| Flag              | Default                          | Notes                                                                                                  |
| ----------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `--peer-pubkey`   | **required**                     | Hex-encoded X25519 pubkey of the ratatoskr peer (64 chars).                                            |
| `--endpoint`      | **required**                     | `host:port` ratatoskr should heartbeat to. Embedded in the token.                                      |
| `-o, --output`    | `ratatoskr-enrollment.token`     | Where to write the binary token.                                                                       |
| `--config`        | `/etc/yggdrasil/config.toml`     | Server config; used to look up the local identity and to write back `peer.public_key_hex`.             |
| `--force`         | (off)                            | Overwrite `peer.public_key_hex` even if a different peer is already enrolled.                          |

The token is **not** a secret — see [security.md](security.md#enrollment-token-format).

### `yggdrasil version`

Print the build version. Identical to `yggdrasil --version`.

---

## `ratatoskr`

The heartbeat client daemon. Runs on the home box.

### `ratatoskr run`

Start the daemon. Connects to the configured `yggdrasil_endpoint`, performs
the Noise_IK handshake, then sends a heartbeat every `heartbeat_interval`.

| Flag        | Env var               | Default                          | Notes                       |
| ----------- | --------------------- | -------------------------------- | --------------------------- |
| `--config`  | `RATATOSKR_CONFIG`    | `/etc/ratatoskr/config.toml`     | Client config path.         |

Exits on SIGTERM/SIGINT; restarts handshake transparently if the server
moves or rejects the session.

### `ratatoskr keygen`

Generate the client's long-term X25519 identity.

| Flag              | Default                          | Notes                                                                |
| ----------------- | -------------------------------- | -------------------------------------------------------------------- |
| `--identity-file` | `/etc/ratatoskr/identity.key`    | Output path, mode 0600.                                              |
| `--force`         | (off)                            | Overwrite an existing file.                                          |

Prints the pubkey and short fingerprint. You'll paste the pubkey into the
VPS operator's `yggdrasil enroll-token --peer-pubkey` invocation.

### `ratatoskr pubkey`

Print the local pubkey (hex). Reads `--identity-file` if you haven't enrolled yet.

| Flag              | Default                          | Notes                            |
| ----------------- | -------------------------------- | -------------------------------- |
| `--identity-file` | `/etc/ratatoskr/identity.key`    |                                  |

### `ratatoskr fingerprint`

Print the local short fingerprint (BLAKE2s-128 of the pubkey). Useful for
out-of-band verification.

| Flag              | Default                          |
| ----------------- | -------------------------------- |
| `--identity-file` | `/etc/ratatoskr/identity.key`    |

### `ratatoskr enroll <token>`

Apply an enrollment token. Reads the token, cross-checks the embedded
`peer_public` against the local identity (catches "wrong token file"
mistakes), and writes `client.yggdrasil_pubkey_hex` + `client.yggdrasil_endpoint`
into the config.

| Positional / flag    | Default                          | Notes                                                                                              |
| -------------------- | -------------------------------- | -------------------------------------------------------------------------------------------------- |
| `<token>` (positional) | **required**                   | Path to the token file produced by `yggdrasil enroll-token`.                                       |
| `--config`           | `/etc/ratatoskr/config.toml`     | Config file to update in place.                                                                    |

The config file must already exist with at least `[client]` and an `identity_file`
key. `enroll` updates only two fields; placeholders in the other fields are
preserved.

### `ratatoskr version`

Print the build version.

---

## `yggdrasilctl`

Admin CLI. Talks to a running `yggdrasil` over its Unix control socket. All
subcommands are read-only by default — the only mutating one is `peer approve`.

### Global flags

| Flag       | Env var                   | Default                          | Notes                                                              |
| ---------- | ------------------------- | -------------------------------- | ------------------------------------------------------------------ |
| `--socket` | `YGGDRASIL_CONTROL_SOCKET`| `/run/yggdrasil/control.sock`    | Path to the daemon's control socket.                               |
| `--json`   | —                         | (off)                            | Emit raw JSON responses. Otherwise human-readable text.            |

### `yggdrasilctl status`

High-level server status. Shows the current peer IP (from the most recent
authenticated heartbeat), milliseconds since that heartbeat, branch count,
uptime, and whether a peer is enrolled.

### `yggdrasilctl branches list`

Print loaded branch rules with their listen sockets and upstream ports.

### `yggdrasilctl branches reload`

Force a re-scan of `branches_dir`. The inotify watcher already handles most
cases — use this when the filesystem stack doesn't deliver events
(NFS, some FUSE filesystems, container bind mounts on macOS).

### `yggdrasilctl peer show`

Print the currently-enrolled peer's pubkey and fingerprint.

### `yggdrasilctl peer pending`

List staged TOFU candidates — peers that have attempted a handshake but
aren't yet enrolled in `config.toml`. See
[operations.md → TOFU peer enrolment](operations.md#tofu-peer-enrolment).

### `yggdrasilctl peer approve <fingerprint>`

Approve a staged TOFU candidate. After approval the candidate is written
into `config.toml` and the next heartbeat from that key will be accepted.

| Positional        | Notes                                                                                |
| ----------------- | ------------------------------------------------------------------------------------ |
| `<fingerprint>`   | Short BLAKE2s-128 fingerprint (32 hex chars) shown by `peer pending`.                |

### Exit codes

| Exit | Meaning                                                                            |
| ---- | ---------------------------------------------------------------------------------- |
| 0    | Success.                                                                           |
| 1    | Local error — couldn't connect to the socket, timeout, malformed response.          |
| 2    | Server returned a `Response::Error { code, message }`. Both are printed to stderr. |

---

## `loadgen`

Workspace-internal benchmark tool. See [bench/README.md](../bench/README.md)
for end-to-end usage; the per-subcommand surface is documented inline via
`loadgen --help`.

Subcommands:

- `udp` — steady-rate UDP RTT measurement (`--target`, `--flows`, `--pps`,
  `--packet-size`, `--duration`, `--warmup`).
- `udp-churn` — sustained new-flow rate (`--target`, `--rate`, `--duration`).
- `tcp` — TCP ping-pong RTT (`--target`, `--connections`, `--message-size`,
  `--duration`, `--warmup`).
- `tcp-throughput` — bulk TCP MB/s (`--target`, `--streams`, `--buffer-size`,
  `--duration`).
- `tcp-connrate` — TCP connect/close rate (`--target`, `--concurrency`,
  `--duration`).

All modes emit a stable JSON report to stdout, or to `--report-json <path>`.
