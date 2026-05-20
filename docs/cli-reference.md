# CLI reference

Every subcommand exposed by the two binaries, with its real flags and
defaults. Where a flag also reads from an environment variable, that's
called out.

Conventions:

* Both binaries accept `--help` / `-h` and `--version`.
* Log-format selectors are global flags (`--log-format json|pretty`); the
  daemon defaults to `json`.
* Paths default to the `/etc/...` layout from [install.md](install.md).
  Override with `--config` or `--identity-file` for non-standard layouts.

---

## `yggdrasil`

The chain daemon. Same binary in relay and terminal modes; the mode is
derived from config shape: `[dial]` only => terminal, `[accept]` only
or both => relay.

### `yggdrasil run`

Start the daemon. The foreground process you'll wire into systemd.

| Flag                | Env var                  | Default                              | Notes                                                                  |
| ------------------- | ------------------------ | ------------------------------------ | ---------------------------------------------------------------------- |
| `--config`          | `YGGDRASIL_CONFIG`       | `/etc/yggdrasil/config.toml`         | Path to the server config file.                                        |
| `--rules-dir`       | `YGGDRASIL_RULES_DIR`    | (value from config)                  | Override `[server].rules_dir` without editing the config — useful for tests. |
| `--require-mode`    | —                        | (unset)                              | Assert derived mode is `relay` or `terminal`; exit non-zero if it doesn't match. |
| `--bind`            | —                        | (value from config)                  | Override `[server].default_bind`. Hard-rewrites every rule's `listen` IP to this address. |

The daemon exits 0 on SIGTERM/SIGINT, non-zero on startup error (bad
config, identity not loadable, port already in use). Identity files at
`[server].identity_file` are auto-generated on first start if missing.

### `yggdrasil version`

Print the build version. Identical to `yggdrasil --version`.

---

## `yggdrasilctl`

Admin CLI. Four scopes — `local`, `chain`, `identity`, `validate` —
selected as the first positional argument.

### Global flags

| Flag       | Env var                   | Default                          | Notes                                                                                                |
| ---------- | ------------------------- | -------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `--config` | `YGGDRASIL_CONFIG`        | `/etc/yggdrasil/config.toml`     | Path to the daemon's config file. Used by `identity` (mutates `[dial]` / `[accept]` and resolves `identity_file`) and `validate`. |
| `--json`   | —                         | (off)                            | Emit raw JSON responses where possible. Otherwise human-readable text.                                |

### Per-scope flags

| Flag       | Env var                   | Default                          | Scopes               |
| ---------- | ------------------------- | -------------------------------- | -------------------- |
| `--socket` | `YGGDRASIL_CONTROL_SOCKET`| `/run/yggdrasil/control.sock`    | `local`, `chain` only |

`--socket` is **not** accepted by `identity` or `validate` (those scopes
never contact the daemon). It must appear after the scope keyword, e.g.
`yggdrasilctl local --socket /tmp/x.sock status`.

### Exit codes

| Exit | Meaning                                                                            |
| ---- | ---------------------------------------------------------------------------------- |
| 0    | Success.                                                                           |
| 1    | Local error — couldn't connect to the socket, timeout, malformed response. For `chain diff`, this is also the "drift detected" exit code. |
| 2    | Server returned a `Response::Error { code, message }`. Both are printed to stderr. |

---

## `yggdrasilctl local <cmd>` — daemon-local UDS commands

### `local status`

High-level server status. Shows the daemon's mode, currently-known
downstream IP (relay mode only), milliseconds since the last accepted
heartbeat, rule count, uptime, and downstream-enrolment flag. In terminal
mode the heartbeat- and downstream-related fields are suppressed.

### `local rules list`

Print loaded rules with their listen sockets and resolved upstream
targets.

### `local rules reload`

Force a re-scan of `[server].rules_dir`. The inotify watcher already
handles most cases — use this when the filesystem stack doesn't deliver
events (NFS, some FUSE filesystems, container bind mounts on macOS).

### `local certs list`

Removed. Cert-store summary is now folded into `local status`: when at
least one HTTPS rule is loaded, `status` prints a single
`cert: <path> (loaded Xs ago); ephemeral certs: N` line.

### `local downstream show`

Print the currently-enrolled downstream's tagged pubkey and fingerprint.

### `local downstream pending`

List staged TOFU candidates — peers that have attempted a handshake but
aren't yet enrolled in `[accept]`.

### `local downstream approve <fingerprint>`

Approve a staged TOFU candidate. After approval the candidate is written
into `[accept].pubkey` and the next heartbeat from that key is
accepted.

| Positional        | Notes                                                                                |
| ----------------- | ------------------------------------------------------------------------------------ |
| `<fingerprint>`   | Full BLAKE2s-128 fingerprint (32 hex chars) shown by `downstream pending`, or any unique 8+-hex-char prefix. The daemon disambiguates against the staged queue; ambiguous prefixes return `error_codes::AMBIGUOUS_FINGERPRINT` listing every match. |

---

## `yggdrasilctl chain <cmd>` — chain-control plane commands

### `chain tunnel open --pubkey <PK> --dest <HOST:PORT>`

Open a one-shot bidirectional chain tunnel to `dest` at `pubkey`, then
splice it against this process's stdin/stdout. Exits when either stdin
closes or the peer closes the tunnel.

| Flag        | Type           | Notes                                                                                                       |
| ----------- | -------------- | ----------------------------------------------------------------------------------------------------------- |
| `--pubkey`  | tagged pubkey  | Target node where the tunnel terminates. May be any node along the chain — the daemon's tunnel forwarder routes onward until the pubkey matches. |
| `--dest`    | `host:port`    | Destination socket the terminator should dial after the tunnel arrives. In v1, tunnel destination policy is loopback-only. |

Useful for `ssh -o ProxyCommand='yggdrasilctl chain tunnel open --pubkey
… --dest …'` style wiring, or for one-shot pipelines like `echo PAYLOAD
| yggdrasilctl chain tunnel open …`.

### `chain apply --file <PATH>`

Push a candidate `rules.toml` file into the running **terminal** daemon
without writing to `[server].rules_dir` on disk. The CLI parses the file
locally for early error messages with line context; the daemon
re-validates server-side (per-rule + cross-rule uniqueness, listen /
protocol conflicts) and rejects the apply as a unit on any conflict.

Terminal mode only. Relay-mode daemons return
`not_supported_in_relay_mode`.

| Flag       | Type | Notes                                                                                              |
| ---------- | ---- | -------------------------------------------------------------------------------------------------- |
| `--file`   | path | Candidate rule file. Parsed via `ratatoskr::rule::RuleFile::from_toml` before shipping.            |

On success, the predicate publisher emits a fresh `PredicateSetUpdate`
on its next tick (if `[dial]` is set).

### `chain diff`

Walk the chain upward from the local node and surface drift between
each terminal's published predicate set and what each upstream hop
actually accepted. Each hop is reached over a chain tunnel to its
loopback `/internal/derived-rules` HTTP endpoint.

| Flag                | Type        | Default | Notes                                                                                                                   |
| ------------------- | ----------- | ------- | ----------------------------------------------------------------------------------------------------------------------- |
| `--metrics-port`    | u16         | `9090`  | Port on each node's loopback where the metrics listener is bound. Assumed identical on every hop.                       |
| `--max-hops`        | usize       | `8`     | Walk depth cap. A chain deeper than 8 is unusual; tune up only if you've explicitly designed one.                       |
| `--per-hop-timeout` | `humantime` | `5s`    | Per-fetch deadline. Overall walk time is bounded by `max_hops * per_hop_timeout`.                                       |

Exit codes: `0` if every hop is in sync (or all `Predicates::None` /
origin-mismatch sentinels are documented expected drift), `1` if drift
is detected on at least one hop, `2` for protocol-level errors.

Human-readable output:

```
hop 0 (local x25519:abc…): predicates=2 v=12 origin=x25519:abc…
  derived_rules: 2 active
hop 1 (upstream x25519:def…): predicates=2 v=12 origin=x25519:abc…
  in sync with hop 0
hop 2 (upstream x25519:fff…): predicates=0
  no predicates on this hop (under v1 only the immediate upstream of a
  terminal carries the pushed set; deeper hops are reported for chain
  identity only)

in sync across 3 hop(s).
```

With `--json`, the same data is emitted as a structured `DiffReport`
suitable for piping into `jq`.

---

## `yggdrasilctl identity <cmd>` — offline identity & enrollment

All `identity` commands are file-based and run without contacting the
daemon. Changes to `[dial]` / `[accept]` take effect on the next daemon restart
(chain endpoints are wired at startup; there is no hot-reload path for
them).

Identity-file resolution order:

1. Explicit `--identity-file <PATH>` flag.
2. `[server].identity_file` in `--config`, if the config file exists.
3. Fallback `/etc/yggdrasil/identity.key`.

### `identity show [--identity-file <PATH>]`

Print this node's tagged pubkey and fingerprint.

### `identity rotate [--identity-file <PATH>] [--force] [--yes-i-understand-this-breaks-existing-chains]`

Generate a fresh X25519 keypair and write it to the identity file with
mode 0600.

* **Fresh install** (no identity file present): writes the new key
  unconditionally; `--force` is a no-op.
* **Existing identity**: refuses without `--force`. Rotation invalidates
  every chain enrollment that pins this node's pubkey, so before clobbering
  the on-disk key `rotate` lists the `[dial]` / `[accept]` entries that
  will break and prompts the operator to type the *current* identity's
  short fingerprint (8 hex chars). Pass
  `--yes-i-understand-this-breaks-existing-chains` to skip the prompt
  for scripted use; without it, a non-interactive stdin is rejected.

### `identity export-intro [--identity-file <PATH>] [--out PATH] [--note STR]`

Emit an intro file (this node advertising itself as a downstream
candidate). Defaults to `./intro.txt`. The intro contains the local
pubkey + fingerprint + operator note. Not a secret.

### `identity add-downstream --from <INTRO> --my-endpoint <HOST:PORT> [--out PATH] [--note STR] [--identity-file <PATH>]`

Apply an intro file received from a prospective downstream. Writes
`[accept].pubkey = <downstream-pubkey>` into the daemon
config and emits an invite file (default `./invite.txt`) containing
both pubkeys plus `my_endpoint`. Hand-deliver the invite back to the
downstream.

### `identity add-upstream --from <INVITE> [--identity-file <PATH>]`

Apply an invite file received from an upstream. Verifies the invite's
`downstream_pubkey` matches the local identity (catches "wrong invite
file" mistakes), then writes `[dial]` into the daemon config:
the upstream's pubkey + endpoint.

### `identity remove-upstream`

Remove `[dial]` from the daemon config. Useful for re-enrolling
against a new upstream.

### `identity remove-downstream`

Remove `[accept]` from the daemon config. The next downstream
that handshakes lands in the pending-peer TOFU store.

---

## `loadgen`

Workspace-internal benchmark tool. See [bench/README.md](../bench/README.md)
for end-to-end usage; the per-subcommand surface is documented inline via
`loadgen --help`.

Subcommands:

* `udp` — steady-rate UDP RTT measurement (`--target`, `--flows`, `--pps`,
  `--packet-size`, `--duration`, `--warmup`).
* `udp-churn` — sustained new-flow rate (`--target`, `--rate`, `--duration`).
* `tcp` — TCP ping-pong RTT (`--target`, `--connections`, `--message-size`,
  `--duration`, `--warmup`).
* `tcp-throughput` — bulk TCP MB/s (`--target`, `--streams`, `--buffer-size`,
  `--duration`).
* `tcp-connrate` — TCP connect/close rate (`--target`, `--concurrency`,
  `--duration`).

All modes emit a stable JSON report to stdout, or to `--report-json <path>`.
