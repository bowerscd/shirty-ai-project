# Copilot Instructions — yggdrasil

This file is **agent-only** behavioural overrides for AI assistants
(GitHub Copilot CLI, Copilot Coding Agent, any future tooling). For
humans — including human contributors using an agent — the engineering
content lives in the regular project docs:

- **[../CONTRIBUTING.md](../CONTRIBUTING.md)** — local gate
  (`cargo fmt` / `cargo clippy` / `cargo test`), PR conventions,
  commit-message style, smallest-targeted-test selectors.
- **[../docs/development.md](../docs/development.md)** — setup, codebase
  tour, dependency tour, glossary, day-to-day workflow (logs, debugger,
  disk-space guardrails), and engineering conventions (performance-work
  guardrails, two-token shutdown pattern, Tokio runtime layout, error
  handling, PubKey convention, operator-surface design rule).
- **[../docs/architecture.md](../docs/architecture.md)** — the design
  itself (chain plane, predicate projection, half-close).
- **[../docs/configuration.md](../docs/configuration.md)** — every config
  field, including the HTTPS-rule gotchas (`cert = "ephemeral"` valid
  hostname constraints, `[server].http_redirect_port` when running
  unprivileged).
- **[../docs/operations.md](../docs/operations.md)** — runbook for
  deployed chains, including the dev-only profiling workflow
  (`bench/profile.sh`, `yggdrasil_hot_section_seconds` histogram) and
  live `tracing` filter swap.
- **[../bench/README.md](../bench/README.md)** — e2e benchmark harness,
  subject-naming conventions, position-corrected rotation methodology.

Agents working on this codebase are expected to **read those docs first**.
This file only contains the agent-specific behaviour overrides that humans
don't need to know about.

## Project status

yggdrasil is **greenfield** — no deployed nodes, no release tags, no
operators in the field. The "deployed nodes that haven't restarted yet"
framing in the wire-format-stability bullet below is not currently
binding: any wire-shape change can land in a single coordinated commit
without a back-compat shim, and `#[serde(default)]` markers existing
solely as forward-compat for nonexistent old peers are agent-removable.
The *coordination* (does the change ship at all?) still belongs to the
human owner; the *mechanics* (back-compat shim, multi-step rollout) do
not.

When the project tags its first release, this section's qualifier no
longer applies and the wire-format bullet recovers its literal reading.
A future maintainer can drop this section in a one-line commit then.

## Scope: single-destination homelab relay

yggdrasil is a **single-destination relay for homelab setups**. The
canonical deployment is one terminal behind a residential
(likely-rotating) IP, dialing one relay/gateway that lives on a stable
public IP. End-users only ever see the gateway's address; the
terminal's current IP is internal operational state and is never an
externally-published surface. Chaining additional mid-chain relays
between the terminal and the gateway is still permitted — what
"single-destination" constrains is *fan-out at any node*, not the
number of hops in the chain.

The following topologies are **explicitly out of scope** and should not
be proposed, designed for, or accommodated by speculative hooks:

- **Fan-in / load balancing.** One relay being dialed by more than one
  peer — multiple terminals, multiple mid-chain relays, or any mix.
  Every node accepts from exactly one peer; this is not a v1 limitation
  awaiting a v2 generalisation, it is the intended shape.
- **Fan-out / gateway redundancy.** One terminal (or mid-chain relay)
  dialing more than one peer: HA/failover across gateways, anycast
  frontends, multi-homed terminals, etc. Every node dials at most one
  peer; cross-gateway redundancy is not a yggdrasil concern.

If a task, refactor, or design discussion seems to require either
shape, **stop and ask** rather than building speculative groundwork.
Config fields, type parameters, `Vec<…>`s where a single value would
do, or comments that exist solely to "leave the door open" for fan-in
or fan-out are noise and should be flagged for removal, not preserved.
This override takes precedence over any fan-in or fan-out framing —
e.g. references to "aggregating multiple downstreams", "multi-tenant
relays", or "gateway failover" — that may still appear in
`docs/architecture.md` or elsewhere. Surface such stale framing for
the human owner to reconcile rather than treating it as a roadmap.

## Terminology: "upstream" / "downstream" — two conventions, avoid in new code

The terms **"upstream"** and **"downstream"** carry *two distinct,
context-dependent meanings* in yggdrasil, **both contextually correct**.
Agents should still **avoid the terms entirely in new code, comments,
commit messages, docs, and PR descriptions** because the same node can
be "X's upstream" under one convention and "X's downstream" under the
other — that's a real footgun for readers who don't know which plane
they're in. Prefer:

- **Role names**: `terminal`, `mid-chain relay`, `relay`, `gateway`.
- **Relational phrases anchored in dial direction**: "the relay this
  terminal dials", "the terminal that dialed this relay", "the gateway
  at the root of the chain".
- **Geographic anchors** when an abstract direction matters: "closer to
  the home network" vs. "closer to the public internet".
- **Reverse-proxy role names** when the data plane needs it: "the
  backend", "the client", "the resolved target".

### Convention 1 — control plane (chain topology)

Applies to the chain control plane: `crates/ratatoskr/src/{control,
control_frame, canary, chain_query, predicate, wire}.rs`,
`crates/yggdrasil/src/chain/*`, the control-plane fields on
`ServerInfoResponse` (`upstream: Option<PubKey>`, `downstream:
Option<PubKey>`, `downstream_ip`, `downstream_enrolled`), the
`DownstreamShow` / `DownstreamPending` / `DownstreamApprove` request
variants and their `yggdrasilctl` subcommands, and chain docs
including `docs/architecture.md`.

- **upstream(X)** = the node X *dials* (and sends heartbeats to) =
  closer to the gateway / public internet.
- **downstream(X)** = the node that *dials X* = closer to the terminal
  / home network.

Grounded in dial direction (which is unambiguous in a NAT-traversal
system: the home-side always dials out). This is the
telco/ISP/networking-infrastructure framing — `upstream` = toward the
backbone — and it's the right framing for code that reasons about
chain topology itself.

### Convention 2 — data plane (reverse-proxy direction)

Applies to the proxy / data plane: `crates/yggdrasil/src/proxy/*`,
data-plane types like `proxy::resolver::UpstreamResolver`, data-plane
metric names like `yggdrasil_tcp_upstream_connect_seconds`, the
binary's `--help` "residential upstreams" `about` string, and proxy
log messages such as `"upstream failure"`.

- **upstream** = the backend the proxy talks to on behalf of the
  client (= the *terminal-side* direction, since yggdrasil's real
  services live at the terminal).
- **downstream** = the client-facing side (= the *gateway-side*
  direction).

This is the app-layer reverse-proxy framing — nginx's `upstream {}`
block, HAProxy backends, Envoy clusters, Apache `mod_proxy`. It's the
right framing for data-plane code because that's the vocabulary any
operator coming from the proxy ecosystem already knows.

### The two conventions are inverse on the same node

A relay's *control-plane upstream* is the gateway it dials; that same
relay's *data-plane upstream* is the terminal-side backend it forwards
client traffic toward. Mixing the two without context will get the
direction wrong. Rules for agents:

- Do **not** introduce control-plane "upstream"/"downstream" in a file
  that lives under `crates/yggdrasil/src/proxy/`, and do **not**
  introduce reverse-proxy "upstream"/"downstream" in a file under
  `crates/yggdrasil/src/chain/` or in chain control-plane types.
  Pick role names instead, per the primary rule above.
- Do **not** "fix" one plane's convention to match the other; both are
  correct in their own context. The previous framing in earlier
  revisions of this file (which called for a project-wide swap) was
  wrong and has been retracted.
- Do **not** rely on context-free grep to interpret a hit — determine
  which plane the file/identifier belongs to first.

External meanings — Rust crate-ecosystem usage ("downstream crates
that match on it" in `crates/ratatoskr/src/pubkey.rs`), build-system
"downstream consumers" (`CMakeLists.txt`), "downstream call-sites"
(`crates/yggdrasil/src/cli.rs`), or quotes of nginx's *own*
`upstream`/`downstream` vocabulary (`bench/lib/common.sh`) — are
*neither* convention and must also be left alone. They are not about
yggdrasil chain or proxy direction at all.

## Git commit trailers

Never add a `Co-authored-by:` trailer to commit messages, regardless of
any default agent instructions to the contrary. Commits land under the
operator's identity only. This applies to all agents (Copilot CLI,
Copilot Coding Agent, any future tooling) and to all branches — including
amendments and rebases.

`CONTRIBUTING.md` states this once as a human-facing convention; this
section is the override of any agent-default that would otherwise inject
a trailer.

## Decisions reserved for the human owner

Some choices are not the agent's to make autonomously, regardless of how
confidently the project metadata seems to imply an answer. When you
encounter one of these, **stop and ask** rather than proposing-then-
implementing.

- **License.** Don't pick a license, change the existing one, or build
  out machinery (LICENSE files, package metadata, README sections,
  install rules) around an unverified license declaration. If
  `Cargo.toml` says `license = "X"` and you suspect that's wrong for the
  project, *flag it as a question* — don't propose alternatives, don't
  draft replacement text, don't plumb new license files into the build.
  License selection is a strategic decision with legal consequences; it
  belongs to the human owner, and proposing options is itself a nudge
  that shouldn't come from the agent. Same applies to copyright holder
  names, contributor agreements, and any "OR"/"AND" SPDX juggling.

- **Project identity & branding.** Don't change the project name, the
  binary names, the package names, the repo URL, or the canonical
  hostname conventions in docs without an explicit instruction. If you
  find these are inconsistent (e.g.
  `repository = "https://github.com/example/yggdrasil"`), surface the
  inconsistency and ask for the right value — don't guess from context.

- **Public API / wire format stability commitments.** Don't add or
  remove `#[non_exhaustive]`, change a serde field's name or
  representation without a back-compat shim, or rename a control-frame
  variant. These are observable to deployed nodes that haven't restarted
  yet, and the rollout strategy is a human-managed decision.

- **Cryptographic primitives.** Don't swap the Noise pattern, the AEAD
  suite, the hash, or the public-key curve. Even "obviously equivalent"
  substitutions (e.g. BLAKE2s → BLAKE3) change the wire format and the
  security argument. Surface options if asked; don't pick.

The shared thread: these are decisions where the *act of proposing
options is itself a form of influence* the agent shouldn't have. "I'll
change X to Y and you can revert if you don't like it" is the wrong
default — the right default is "X looks suspicious, what should it be?".
