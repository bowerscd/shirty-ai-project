# Command-Line Help for `yggdrasilctl`

This document contains the help content for the `yggdrasilctl` command-line program.

**Command Overview:**

* [`yggdrasilctl`↴](#yggdrasilctl)
* [`yggdrasilctl local`↴](#yggdrasilctl-local)
* [`yggdrasilctl local status`↴](#yggdrasilctl-local-status)
* [`yggdrasilctl local rules`↴](#yggdrasilctl-local-rules)
* [`yggdrasilctl local rules list`↴](#yggdrasilctl-local-rules-list)
* [`yggdrasilctl local rules reload`↴](#yggdrasilctl-local-rules-reload)
* [`yggdrasilctl local accept`↴](#yggdrasilctl-local-accept)
* [`yggdrasilctl local accept show`↴](#yggdrasilctl-local-accept-show)
* [`yggdrasilctl local accept pending`↴](#yggdrasilctl-local-accept-pending)
* [`yggdrasilctl local accept approve`↴](#yggdrasilctl-local-accept-approve)
* [`yggdrasilctl local metrics`↴](#yggdrasilctl-local-metrics)
* [`yggdrasilctl local health`↴](#yggdrasilctl-local-health)
* [`yggdrasilctl local derived-rules`↴](#yggdrasilctl-local-derived-rules)
* [`yggdrasilctl local trace`↴](#yggdrasilctl-local-trace)
* [`yggdrasilctl local acme`↴](#yggdrasilctl-local-acme)
* [`yggdrasilctl local acme list`↴](#yggdrasilctl-local-acme-list)
* [`yggdrasilctl local acme renew`↴](#yggdrasilctl-local-acme-renew)
* [`yggdrasilctl chain`↴](#yggdrasilctl-chain)
* [`yggdrasilctl chain apply`↴](#yggdrasilctl-chain-apply)
* [`yggdrasilctl chain diff`↴](#yggdrasilctl-chain-diff)
* [`yggdrasilctl chain summary`↴](#yggdrasilctl-chain-summary)
* [`yggdrasilctl chain health`↴](#yggdrasilctl-chain-health)
* [`yggdrasilctl chain ping`↴](#yggdrasilctl-chain-ping)
* [`yggdrasilctl chain canary`↴](#yggdrasilctl-chain-canary)
* [`yggdrasilctl identity`↴](#yggdrasilctl-identity)
* [`yggdrasilctl identity show`↴](#yggdrasilctl-identity-show)
* [`yggdrasilctl identity rotate`↴](#yggdrasilctl-identity-rotate)
* [`yggdrasilctl identity export-request`↴](#yggdrasilctl-identity-export-request)
* [`yggdrasilctl identity add-dial`↴](#yggdrasilctl-identity-add-dial)
* [`yggdrasilctl identity add-accept`↴](#yggdrasilctl-identity-add-accept)
* [`yggdrasilctl identity remove-dial`↴](#yggdrasilctl-identity-remove-dial)
* [`yggdrasilctl identity remove-accept`↴](#yggdrasilctl-identity-remove-accept)
* [`yggdrasilctl validate`↴](#yggdrasilctl-validate)
* [`yggdrasilctl completions`↴](#yggdrasilctl-completions)

## `yggdrasilctl`

Admin CLI for yggdrasil; speaks JSON over a Unix domain socket

**Usage:** `yggdrasilctl [OPTIONS] <COMMAND>`

###### **Subcommands:**

* `local` — Daemon-local operations over the control socket
* `chain` — Chain-control plane operations
* `identity` — Identity and enrollment (offline; mutates config file)
* `validate` — Validate the daemon's config file and rules directory offline
* `completions` — Print a shell-completion script for `yggdrasilctl` to stdout

###### **Options:**

* `--config <CONFIG>` — Path to the yggdrasil config file. Used by the `identity` and `validate` scopes; `local` and `chain` ignore it

  Default value: `/etc/yggdrasil/config.toml`
* `--json` — Emit responses as raw JSON instead of human-readable text



## `yggdrasilctl local`

Daemon-local operations over the control socket

**Usage:** `yggdrasilctl local [OPTIONS] <COMMAND>`

###### **Subcommands:**

* `status` — Show high-level server status (mode, downstream IP, last heartbeat, rule count, uptime)
* `rules` — Inspect or manage terminal-loaded rules
* `accept` — Inspect or manage the enrolled accept-side peer (the inbound chain peer pinned by `[accept]` — for relay-mode this is the downstream terminal node)
* `metrics` — Render the daemon's Prometheus metrics in text exposition format, retrieved over the control socket
* `health` — Liveness/readiness probe served over the control socket. Exit status: 0 if ready, 1 if not yet ready, 2 on RPC error
* `derived-rules` — Snapshot of this node's chain-applied predicates, derived rule set, and chain identity. Pretty-printed JSON to stdout
* `trace` — Adjust the daemon's tracing-subscriber filter at runtime. Pass a directive (`debug`, `yggdrasil::heartbeat=trace,info`, etc.) or `--reset` to revert to the startup filter. With no args, prints the current and default directives without changing anything
* `acme` — Inspect or manage terminal ACME-managed certs

###### **Options:**

* `--socket <SOCKET>` — Path to the yggdrasil control socket

  Default value: `/run/yggdrasil/control.sock`



## `yggdrasilctl local status`

Show high-level server status (mode, downstream IP, last heartbeat, rule count, uptime)

**Usage:** `yggdrasilctl local status`



## `yggdrasilctl local rules`

Inspect or manage terminal-loaded rules

**Usage:** `yggdrasilctl local rules <COMMAND>`

###### **Subcommands:**

* `list` — List terminal-loaded rules
* `reload` — Force a reload of the terminal rules directory (in addition to inotify)



## `yggdrasilctl local rules list`

List terminal-loaded rules

**Usage:** `yggdrasilctl local rules list`



## `yggdrasilctl local rules reload`

Force a reload of the terminal rules directory (in addition to inotify)

**Usage:** `yggdrasilctl local rules reload`



## `yggdrasilctl local accept`

Inspect or manage the enrolled accept-side peer (the inbound chain peer pinned by `[accept]` — for relay-mode this is the downstream terminal node)

**Usage:** `yggdrasilctl local accept <COMMAND>`

###### **Subcommands:**

* `show` — Show the currently enrolled accept-side pubkey and fingerprint
* `pending` — List staged TOFU candidates awaiting approval
* `approve` — Approve a staged candidate by its fingerprint or any unique 8+-hex-char prefix



## `yggdrasilctl local accept show`

Show the currently enrolled accept-side pubkey and fingerprint

**Usage:** `yggdrasilctl local accept show`



## `yggdrasilctl local accept pending`

List staged TOFU candidates awaiting approval

**Usage:** `yggdrasilctl local accept pending`



## `yggdrasilctl local accept approve`

Approve a staged candidate by its fingerprint or any unique 8+-hex-char prefix

**Usage:** `yggdrasilctl local accept approve <FINGERPRINT>`

###### **Arguments:**

* `<FINGERPRINT>` — Tagged fingerprint (e.g. `x25519:<32 hex chars>` for X25519) of the accept-side peer to approve, or any unique prefix of at least 8 hex chars of the hash tail (the algorithm prefix is optional). The daemon disambiguates against the staged queue; ambiguous prefixes return an error listing every match



## `yggdrasilctl local metrics`

Render the daemon's Prometheus metrics in text exposition format, retrieved over the control socket

**Usage:** `yggdrasilctl local metrics`



## `yggdrasilctl local health`

Liveness/readiness probe served over the control socket. Exit status: 0 if ready, 1 if not yet ready, 2 on RPC error

**Usage:** `yggdrasilctl local health`



## `yggdrasilctl local derived-rules`

Snapshot of this node's chain-applied predicates, derived rule set, and chain identity. Pretty-printed JSON to stdout

**Usage:** `yggdrasilctl local derived-rules`



## `yggdrasilctl local trace`

Adjust the daemon's tracing-subscriber filter at runtime. Pass a directive (`debug`, `yggdrasil::heartbeat=trace,info`, etc.) or `--reset` to revert to the startup filter. With no args, prints the current and default directives without changing anything

**Usage:** `yggdrasilctl local trace [OPTIONS] [DIRECTIVE]`

###### **Arguments:**

* `<DIRECTIVE>` — New EnvFilter directive to install. Required unless `--reset` is set

###### **Options:**

* `--reset` — Restore the directive the daemon was launched with



## `yggdrasilctl local acme`

Inspect or manage terminal ACME-managed certs

**Usage:** `yggdrasilctl local acme <COMMAND>`

###### **Subcommands:**

* `list` — List ACME-managed hostnames with their renewer state, next renewal time, and last error (if any)
* `renew` — Force an immediate ACME issuance for `<hostname>`. Bypasses the renewer's schedule. Blocks until issuance completes (typically 5-60 seconds) or the daemon's 5-minute deadline expires



## `yggdrasilctl local acme list`

List ACME-managed hostnames with their renewer state, next renewal time, and last error (if any)

**Usage:** `yggdrasilctl local acme list`



## `yggdrasilctl local acme renew`

Force an immediate ACME issuance for `<hostname>`. Bypasses the renewer's schedule. Blocks until issuance completes (typically 5-60 seconds) or the daemon's 5-minute deadline expires

**Usage:** `yggdrasilctl local acme renew <HOSTNAME>`

###### **Arguments:**

* `<HOSTNAME>` — The route hostname to renew. Case-insensitive



## `yggdrasilctl chain`

Chain-control plane operations

**Usage:** `yggdrasilctl chain [OPTIONS] <COMMAND>`

###### **Subcommands:**

* `apply` — Push a candidate rule set from a TOML file into the running terminal daemon without touching its rules directory on disk. The daemon validates the candidate, projects its predicate set, and (if a chain upstream is configured) publishes the projection on its next push tick
* `diff` — Compare the local terminal's published predicate set with what each upstream node believes it accepted
* `summary` — One-line-per-hop overview of the chain (pubkey, role, uptime, rule count, predicate count). Pure projection of the same `Request::ChainSummary` RPC that backs `chain diff`; no extra daemon plumbing
* `health` — Per-hop health (healthy / degraded / down / starting), aggregated to a chain-wide worst-of-hops verdict. Exit code reflects the worst hop: 0=healthy/starting, 1=degraded, 2=down, 3=RPC error
* `ping` — Per-hop control-plane round-trip time. Walks the chain via the same `Request::ChainSummary` RPC and prints each hop's measured query→reply RTT (or `-` for the local hop, which has no RTT to report). Useful for isolating "slow link" vs. "unreachable hop" during a chain incident
* `canary` — Probe a rule's L4 forwarding path end-to-end through the chain and report per-direction throughput, loss, and latency. Routes a token-prefixed probe through the rule's listener so the terminal hop short-circuits to an in-process echo — testing the chain without depending on the rule's configured backend being reachable

###### **Options:**

* `--socket <SOCKET>` — Path to the yggdrasil control socket

  Default value: `/run/yggdrasil/control.sock`



## `yggdrasilctl chain apply`

Push a candidate rule set from a TOML file into the running terminal daemon without touching its rules directory on disk. The daemon validates the candidate, projects its predicate set, and (if a chain upstream is configured) publishes the projection on its next push tick

**Usage:** `yggdrasilctl chain apply --file <PATH>`

###### **Options:**

* `--file <PATH>` — Path to a candidate `rules.toml` file. Parsed locally for early schema errors with line context, then shipped to the daemon as a pre-parsed rule vector. The daemon performs defensive re-validation (per-rule + cross-rule) before applying



## `yggdrasilctl chain diff`

Compare the local terminal's published predicate set with what each upstream node believes it accepted

**Usage:** `yggdrasilctl chain diff [OPTIONS]`

###### **Options:**

* `--timeout <DURATION>` — Overall budget for assembling the chain summary across all hops. Terminals with no `[dial]` upstream return synchronously and effectively ignore this value

  Default value: `5s`



## `yggdrasilctl chain summary`

One-line-per-hop overview of the chain (pubkey, role, uptime, rule count, predicate count). Pure projection of the same `Request::ChainSummary` RPC that backs `chain diff`; no extra daemon plumbing

**Usage:** `yggdrasilctl chain summary [OPTIONS]`

###### **Options:**

* `--timeout <DURATION>` — Overall budget for assembling the chain summary across all hops. Terminals with no `[dial]` upstream return synchronously and effectively ignore this value

  Default value: `5s`



## `yggdrasilctl chain health`

Per-hop health (healthy / degraded / down / starting), aggregated to a chain-wide worst-of-hops verdict. Exit code reflects the worst hop: 0=healthy/starting, 1=degraded, 2=down, 3=RPC error

**Usage:** `yggdrasilctl chain health [OPTIONS]`

###### **Options:**

* `--timeout <DURATION>` — Overall budget for assembling the chain summary across all hops. Terminals with no `[dial]` upstream return synchronously and effectively ignore this value

  Default value: `5s`



## `yggdrasilctl chain ping`

Per-hop control-plane round-trip time. Walks the chain via the same `Request::ChainSummary` RPC and prints each hop's measured query→reply RTT (or `-` for the local hop, which has no RTT to report). Useful for isolating "slow link" vs. "unreachable hop" during a chain incident

**Usage:** `yggdrasilctl chain ping [OPTIONS]`

###### **Options:**

* `--timeout <DURATION>` — Overall budget for assembling the chain summary across all hops. Terminals with no `[dial]` upstream return synchronously and effectively ignore this value

  Default value: `5s`
* `--hop <PUBKEY>` — If set, restrict the rendered output to a single hop matching this tagged x25519 pubkey (`x25519:<hex>`). The whole chain is still walked — only the rendering is filtered. Useful in scripts that probe a specific hop without needing to compute its index



## `yggdrasilctl chain canary`

Probe a rule's L4 forwarding path end-to-end through the chain and report per-direction throughput, loss, and latency. Routes a token-prefixed probe through the rule's listener so the terminal hop short-circuits to an in-process echo — testing the chain without depending on the rule's configured backend being reachable.

Exit code: 0=OK, 1=DEGRADED, 2=NO_SUCH_RULE, 3=CHAIN_DEAD, 4=RPC error.

**Usage:** `yggdrasilctl chain canary [OPTIONS] --port <PORT>`

###### **Options:**

* `--port <PORT>` — Port the rule listens on. Required
* `--proto <PROTO>` — Transport. Required only when the local node has more than one rule binding `--port` (one TCP, one UDP); inferred from the rule set otherwise

  Possible values: `tcp`, `udp`

* `--timeout <DURATION>` — Overall budget for the chain to walk and assemble the arming reply. Matches the `--timeout` shape of the other `chain` subcommands. Caps how long we wait before giving up with `CHAIN_DEAD`; the data probe runs for a fixed daemon-side duration regardless

  Default value: `5s`



## `yggdrasilctl identity`

Identity and enrollment (offline; mutates config file)

**Usage:** `yggdrasilctl identity <COMMAND>`

###### **Subcommands:**

* `show` — Print this node's pubkey and fingerprint from the identity file
* `rotate` — Generate a fresh identity key. Refuses to overwrite an existing file unless `--force` is given
* `export-request` — Write a request file (this node asking to be enrolled as a `dial`-side peer)
* `add-dial` — Apply a grant file: verify it targets this node and write `[dial]` into the daemon config
* `add-accept` — Apply a request file: mint a grant for the requester, and write `[accept]` into the daemon config
* `remove-dial` — Remove `[dial]` from the daemon config
* `remove-accept` — Remove `[accept]` from the daemon config



## `yggdrasilctl identity show`

Print this node's pubkey and fingerprint from the identity file

**Usage:** `yggdrasilctl identity show [OPTIONS]`

###### **Options:**

* `--identity-file <IDENTITY_FILE>` — Override the identity file path. If unset, read from `[server].identity_file` in `--config`, falling back to `/etc/yggdrasil/identity.key`



## `yggdrasilctl identity rotate`

Generate a fresh identity key. Refuses to overwrite an existing file unless `--force` is given

**Usage:** `yggdrasilctl identity rotate [OPTIONS]`

###### **Options:**

* `--identity-file <IDENTITY_FILE>` — Override the identity file path
* `--force` — Overwrite an existing identity file. Without this flag, `rotate` refuses to clobber an existing key. When the identity file is absent (fresh install), `--force` is a no-op
* `--yes-i-understand-this-breaks-existing-chains` — Skip the interactive fingerprint-confirmation prompt. Required for non-interactive overwrite of an existing identity. Use only when you have already audited the chain enrollments that this rotation will break (`identity show` lists the breakage). Pair with `--force`



## `yggdrasilctl identity export-request`

Write a request file (this node asking to be enrolled as a `dial`-side peer)

**Usage:** `yggdrasilctl identity export-request [OPTIONS]`

###### **Options:**

* `--identity-file <IDENTITY_FILE>` — Override the identity file path
* `-o`, `--out <OUT>` — Where to write the request file. When omitted, the request TOML is printed to stdout (operators can pipe it directly or redirect to a file). When supplied, the file is written with 0600 perms
* `--note <NOTE>` — Free-form note included in the request file (operator hint)

  Default value: ``



## `yggdrasilctl identity add-dial`

Apply a grant file: verify it targets this node and write `[dial]` into the daemon config

**Usage:** `yggdrasilctl identity add-dial [OPTIONS] --from <FROM>`

###### **Options:**

* `--from <FROM>` — Path to the grant file emitted by the accept-side
* `--identity-file <IDENTITY_FILE>` — Override the identity file path (used to verify the grant targets us)



## `yggdrasilctl identity add-accept`

Apply a request file: mint a grant for the requester, and write `[accept]` into the daemon config

**Usage:** `yggdrasilctl identity add-accept [OPTIONS] --from <FROM> --my-endpoint <MY_ENDPOINT>`

###### **Options:**

* `--from <FROM>` — Path to the request file received from the prospective dial-side peer
* `--my-endpoint <MY_ENDPOINT>` — The endpoint string (`host:port`) this node advertises as its accept-side reachable address. Written into both the grant file and the `[dial].endpoint` field that the requester will paste in
* `-o`, `--out <OUT>` — Where to write the resulting grant file. Defaults to `grant.txt`

  Default value: `grant.txt`
* `--identity-file <IDENTITY_FILE>` — Override the identity file path (used to populate the grant's `accept_pubkey`)
* `--note <NOTE>` — Free-form note included in the grant file

  Default value: ``



## `yggdrasilctl identity remove-dial`

Remove `[dial]` from the daemon config

**Usage:** `yggdrasilctl identity remove-dial`



## `yggdrasilctl identity remove-accept`

Remove `[accept]` from the daemon config

**Usage:** `yggdrasilctl identity remove-accept`



## `yggdrasilctl validate`

Validate the daemon's config file and rules directory offline

**Usage:** `yggdrasilctl validate [OPTIONS]`

###### **Options:**

* `--rules-dir <RULES_DIR>` — Override the rules directory. When omitted, uses `[server].rules_dir` from the loaded config (default `/etc/yggdrasil/conf.d`)



## `yggdrasilctl completions`

Print a shell-completion script for `yggdrasilctl` to stdout

**Usage:** `yggdrasilctl completions <SHELL>`

###### **Arguments:**

* `<SHELL>` — Target shell. The completion script is printed to stdout

  Possible values: `bash`, `elvish`, `fish`, `powershell`, `zsh`




<hr/>

<small><i>
    This document was generated automatically by
    <a href="https://crates.io/crates/clap-markdown"><code>clap-markdown</code></a>.
</i></small>
