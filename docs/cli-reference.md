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

Print loaded rules with their listen sockets and resolved target
targets.

### `local rules reload`

Force a re-scan of `[server].rules_dir`. The inotify watcher already
handles most cases — use this when the filesystem stack doesn't deliver
events (NFS, some FUSE filesystems, container bind mounts on macOS).
Blocks until the rule supervisor has swapped in the new set and returns
the post-swap rule count; subsequent `local rules list` / `local status`
calls observe the new ruleset without a follow-up RTT.

### `local metrics`

Emit the Prometheus text-format scrape body (`# HELP … / # TYPE … / …`)
over the UDS. Operators who scrape over TCP run a thin UDS→HTTP scrape
adapter sidecar.

### `local health`

Three-tier liveness/readiness summary (`healthy` / `degraded` /
`down` / `starting`). With `--json`, returns the structured report; without,
a one-line summary. Exit codes: `0` healthy/starting, `1` degraded,
`2` down, `3` RPC error. Suitable for `systemd` HEALTHCHECK / k8s exec
probes.

### `local derived-rules`

JSON snapshot of the daemon's current derived rule set plus the chain
identity / predicate version that produced it. Equivalent to the data
that backs `chain diff` per hop. Loopback-only by virtue of running over
the UDS.

### `local trace <DIRECTIVE> | --reset`

Hot-reload the daemon's `tracing` filter directive (the same syntax
accepted by `RUST_LOG`). Exactly one of `<DIRECTIVE>` or `--reset`
must be supplied; clap enforces XOR. The daemon stores its boot-time
default and `--reset` restores it. The active and default directives
are echoed in the response so scripts can confirm what's now in force.

### `local accept show`

Print the currently-enrolled downstream's tagged pubkey and fingerprint.

### `local accept pending`

List staged TOFU candidates — peers that have attempted a handshake but
aren't yet enrolled in `[accept]`.

### `local accept approve <fingerprint>`

Approve a staged TOFU candidate. After approval the candidate is written
into `[accept].pubkey` and the next heartbeat from that key is
accepted.

| Positional        | Notes                                                                                |
| ----------------- | ------------------------------------------------------------------------------------ |
| `<fingerprint>`   | Tagged fingerprint (e.g. `x25519:<32 hex chars>` for X25519) shown by `accept pending`, or any unique 8+-hex-char prefix of the hash tail (the algorithm prefix is optional). The daemon disambiguates against the staged queue; ambiguous prefixes return `error_codes::AMBIGUOUS_FINGERPRINT` listing every match. |

### `local acme list`

After the L7 schema cleanup the renewer manages a **single wildcard
cert** per terminal, not per-route entries. The command prints one
row covering the apex domain from `[acme].domain` with its renewer
state (`idle` / `pending` / `failed`), challenge (`dns01` — the
provider derived from the `[acme.dns.<name>]` sub-table), next
scheduled renewal (absolute Unix epoch plus a relative "in 3 d" /
"<expired>" hint), and the last error when one is recorded.
Returns `error_codes::ACME_NOT_CONFIGURED` if `[acme]` is absent
from the daemon config.

### `local acme renew <hostname>`

Force an immediate ACME issuance, bypassing the renewer's schedule.
`<hostname>` must be the apex domain configured in `[acme].domain`
(there's only one cert to renew per terminal post-schema-cleanup);
any other value returns `error_codes::ACME_UNKNOWN_HOST`. The CLI
blocks until issuance completes (typically 5-60 s) or the daemon's
5-minute deadline expires. On success, the freshly-issued PEM is
written under `[acme].storage_dir` and `CertStore::reload_host`
swaps it in atomically — clients see no connection interruption.
Returns `error_codes::ACME_RENEW_FAILED` (with the underlying CA
error) on issuance failure, or `error_codes::ACME_NOT_CONFIGURED`
if `[acme]` is absent.

---

## `yggdrasilctl chain <cmd>` — chain-control plane commands

Every `chain` subcommand walks the chain via a single
`Request::ChainSummary` RPC over the control UDS; the daemon fans out
upstream via the chain control plane, aggregates per-hop replies, and
returns them in one response. All commands accept `--timeout <DURATION>`
(default `5s`) as the end-to-end deadline for the walk; local-only
replies (no `[dial]`) return synchronously and effectively ignore it.

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

### `chain summary`

One-line-per-hop overview of the chain (index, role, pubkey, uptime,
rule count, predicate count, predicate version). "What's my chain?"

| Flag        | Type        | Default | Notes                                                                                            |
| ----------- | ----------- | ------- | ------------------------------------------------------------------------------------------------ |
| `--timeout` | `humantime` | `5s`    | End-to-end deadline for the upstream walk. Partial replies are flagged with a trailing `note:`. |

With `--json`, the same data is emitted as a structured `SummaryReport`.

### `chain health`

Per-hop health tier (`healthy` / `degraded` / `down` / `starting`),
aggregated to a chain-wide worst-of-hops verdict. Exit code reflects the
worst hop: `0` healthy/starting, `1` degraded, `2` down, `3` RPC error.

| Flag        | Type        | Default | Notes                                              |
| ----------- | ----------- | ------- | -------------------------------------------------- |
| `--timeout` | `humantime` | `5s`    | End-to-end deadline for the upstream walk.        |

### `chain ping [--hop <PUBKEY>]`

Per-hop control-plane round-trip time. Re-uses the `ChainSummary` RPC
and projects each hop's `query_rtt_ms`. The local hop reports `rtt=-`
(no RTT applies — it's the responder itself); every upstream hop is
RTT-stamped by its parent as the recursive query bubbles back. Useful
for isolating "slow link" vs. "unreachable hop" during a chain incident.

| Flag        | Type           | Default | Notes                                                                                |
| ----------- | -------------- | ------- | ------------------------------------------------------------------------------------ |
| `--timeout` | `humantime`    | `5s`    | End-to-end deadline for the upstream walk.                                          |
| `--hop`     | tagged pubkey  | unset   | If set, restrict rendered output to the single hop matching this `x25519:<hex>`. The whole chain is still walked. |

### `chain diff`

Walk the chain upward from the local node and surface drift between
each terminal's published predicate set and what each upstream hop
actually accepted.

| Flag        | Type        | Default | Notes                                              |
| ----------- | ----------- | ------- | -------------------------------------------------- |
| `--timeout` | `humantime` | `5s`    | End-to-end deadline for the upstream walk.        |

Exit codes: `0` if every hop is in sync (transient skipped comparisons —
neither side has predicates yet, or origin mismatch while a terminal
rotation propagates — do not count as drift), `1` if drift is detected
on at least one hop, `2` for protocol-level errors.

Human-readable output:

```
hop 0 (local x25519:abc…): predicates=2 v=12 origin=x25519:abc…
  derived_rules: 2 active
hop 1 (upstream x25519:def…): predicates=2 v=12 origin=x25519:abc…
  in sync with hop 0
hop 2 (upstream x25519:fff…): predicates=2 v=12 origin=x25519:abc…
  in sync with hop 1

in sync across 3 hop(s).
```

Mid-chain relays forward the original push bytes verbatim upstream, so
every settled hop reports the same origin + version + predicate content
as the terminal at hop 0.

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

### `identity export-request [--identity-file <PATH>] [--out PATH] [--note STR]`

Emit a request file (this node advertising itself as a downstream
candidate). When `--out` is supplied, writes there; when omitted, the
TOML body is written to stdout and the metadata header to stderr
(metadata is silenced under `--json`). The request contains the local
pubkey + fingerprint + operator note. Not a secret.

### `identity add-accept --from <REQUEST> --my-endpoint <HOST:PORT> [--out PATH] [--note STR] [--identity-file <PATH>]`

Apply a request file received from a prospective downstream. Writes
`[accept].pubkey = <downstream-pubkey>` into the daemon
config and emits a grant file (default `./grant.txt`) containing
both pubkeys plus `my_endpoint`. Hand-deliver the grant back to the
downstream.

### `identity add-dial --from <GRANT> [--identity-file <PATH>]`

Apply a grant file received from an upstream. Verifies the grant's
`dial_pubkey` matches the local identity (catches "wrong grant
file" mistakes), then writes `[dial]` into the daemon config:
the upstream's pubkey + endpoint.

### `identity remove-dial`

Remove `[dial]` from the daemon config. Useful for re-enrolling
against a new upstream.

### `identity remove-accept`

Remove `[accept]` from the daemon config. The next downstream
that handshakes lands in the pending-peer TOFU store.

---

## `yggdrasilctl validate` — offline config + rule validation

Parse `--config` and load every `*.toml` under `--rules-dir` (overrides
`[server].rules_dir` from the config), running the daemon's own loaders
and validators. Does not contact a running daemon. Suitable for CI
pipelines and pre-deploy smoke checks.

| Flag           | Default                      | Notes                                                                                  |
| -------------- | ---------------------------- | -------------------------------------------------------------------------------------- |
| `--config`     | `/etc/yggdrasil/config.toml` | (global flag) Path to the server config to parse.                                      |
| `--rules-dir`  | (value from config)          | Override `[server].rules_dir` for the validation pass. Useful when validating a candidate rules tree without touching the deployed config. |

Exit codes:

| Exit | Meaning                                                                          |
| ---- | -------------------------------------------------------------------------------- |
| 0    | Config + rules both parse and validate cleanly.                                  |
| 2    | Config parse or validation error. Path + line context written to stderr.        |
| 3    | One or more rule files failed to parse or validate. Each error names the file. |

---

## `loadgen`

Workspace-internal benchmark tool (shipped in the `bench-tools` crate).
See [bench/README.md](../bench/README.md) for end-to-end usage; the
per-subcommand surface is documented inline via `loadgen --help`.

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

---

## `bench-echo`

Workspace-internal echo backend (shipped in the `bench-tools` crate). The
bench harness spawns it on a loopback port as the upstream for direct /
yggdrasil / nginx legs. A native tokio implementation with `SO_REUSEPORT`
fan-out, so the echo backend never becomes the bottleneck above the
proxy under test.

Subcommands:

* `tcp <port>` — accept TCP connections and echo bytes back.
* `udp <port>` — echo each datagram to its sender.

Shared flags:

* `--bind <host>` (default `127.0.0.1`).
* `--workers <N>` — number of independent listener sockets bound via
  `SO_REUSEPORT`. Defaults to available_parallelism so the kernel can
  spread load across cores.

---

## Complete auto-generated reference

The curated prose above documents the verbs operators reach for most
often. For the exhaustive command tree — every subcommand, every flag,
every default value — see the auto-generated docs. They're regenerated
from the live clap definitions on every `cargo build` and committed
alongside the code, so they cannot drift from the binaries.

* [`docs/cli-reference/yggdrasil.md`](cli-reference/yggdrasil.md) —
  the daemon (`yggdrasil`).
* [`docs/cli-reference/yggdrasilctl.md`](cli-reference/yggdrasilctl.md)
  — the admin CLI (`yggdrasilctl`).

Both binaries also ship `completions <shell>` subcommands that print
shell-completion scripts for `bash`, `zsh`, `fish`, `elvish`, and
`powershell`. The install one-liner is:

```bash
yggdrasilctl completions bash | sudo tee /etc/bash_completion.d/yggdrasilctl
yggdrasil    completions bash | sudo tee /etc/bash_completion.d/yggdrasil
```
