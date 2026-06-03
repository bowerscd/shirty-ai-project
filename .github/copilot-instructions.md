# Copilot Instructions — yggdrasil

Treat this file as your **agent-only behavioural overrides**. For
engineering content (which humans also read), read the regular
project docs first:

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

Read those docs first when working on this codebase. Treat this file
as containing only the agent-specific behaviour overrides that humans
don't need to know about; do not duplicate engineering content from
the project docs into this file.

## Project status

Treat the project as **greenfield**: no deployed nodes, no release
tags, no operators in the field. Apply these consequences:

- **Land wire-shape changes as single coordinated commits without
  back-compat shims.** Wire-format stability is not a reserved
  decision while the project is greenfield. The *coordination*
  (does the change ship at all?) still belongs to the human owner
  via the normal task-authorization flow; the *mechanics*
  (back-compat shim, multi-step rollout) do not.
- **Remove `#[serde(default)]` markers** that exist solely as
  forward-compat for nonexistent old peers when you encounter them.
- **Never add migration logic, back-compat shims, orphan-file
  detection, "warn if old config field set" code, or any other
  machinery whose only purpose is to ease the transition for
  deployments that don't exist.** When the schema changes, operators
  who configured the old shape get a clear parse-time error;
  treat that error as the migration signal and add nothing more.

When the project tags its first release, restore the following
bullet to the "Decisions reserved for the human owner" list below
and delete this whole "Project status" section:

> - **Public API / wire format stability commitments.** Don't add or
>   remove `#[non_exhaustive]`, change a serde field's name or
>   representation without a back-compat shim, or rename a control-frame
>   variant. These are observable to deployed nodes that haven't restarted
>   yet, and the rollout strategy is a human-managed decision.

## Scope: single-destination homelab relay

Treat yggdrasil as a **single-destination relay for homelab setups**.
The canonical deployment is one terminal behind a residential
(likely-rotating) IP, dialing one relay/gateway that lives on a stable
public IP. End-users only ever see the gateway's address; the
terminal's current IP is internal operational state and is never an
externally-published surface. Permit chaining of additional mid-chain
relays between the terminal and the gateway — "single-destination"
constrains *fan-out at any node*, not the number of hops in the chain.

Treat the following topologies as **explicitly out of scope**. Do not
propose them, design for them, or accommodate them with speculative
hooks:

- **Fan-in / load balancing.** One relay being dialed by more than one
  peer — multiple terminals, multiple mid-chain relays, or any mix.
  Every node accepts from exactly one peer; this is not a v1 limitation
  awaiting a v2 generalisation, it is the intended shape.
- **Fan-out / gateway redundancy.** One terminal (or mid-chain relay)
  dialing more than one peer: HA/failover across gateways, anycast
  frontends, multi-homed terminals, etc. Every node dials at most one
  peer; cross-gateway redundancy is not a yggdrasil concern.

When a task, refactor, or design discussion seems to require either
shape, **stop and ask** rather than building speculative groundwork.

Flag for removal any **exposed surface** that exists to support
fan-in or fan-out: config fields that take multiple `[[dial]]` or
`[[accept]]` entries, CLI flags or subcommands that imply multi-peer
selection, documented operator features framed as multi-tenant or
load-balanced, or comments that exist solely to "leave the door open"
for either shape.

Do **not** flag internal data structures (`HashMap<PubKey, _>`,
`Vec<…>`, etc.) for collapse on this basis alone. A map that holds
exactly one entry under single-destination but happens to be a map
in the type system costs nothing today and would help a hypothetical
fork that wants to lift the constraint. This rule targets exposed
surfaces; the internal-shape question is a separate implementation
concern that this rule does not auto-trigger.

This override takes precedence over any fan-in or fan-out framing —
e.g. references to "aggregating multiple downstreams", "multi-tenant
relays", or "gateway failover" — that may still appear in
`docs/architecture.md` or elsewhere. Surface such stale framing for
the human owner to reconcile; do not treat it as a roadmap.

## Terminal is authority, intermediaries are transport

Apply this architectural invariant to every design decision about
state, persistence, and authority on the chain plane:

1. **Treat the terminal as the configuration node.** It owns
   `identity.key`, `config.toml`, the rules dir, the cert dir, and
   ACME state. Everything operator-meaningful lives at the terminal.

2. **Treat intermediaries (mid-chain relay, gateway) as pure
   transport.** They exist to bridge NAT and provide a stable
   public-IP presence. They derive their behaviour from what the
   terminal pushes them. Their on-disk surface is `identity.key` +
   `config.toml` and **nothing else**. When a gateway loses its disk
   and the operator restores those two files, the next terminal
   heartbeat must re-establish everything.

3. **Treat mutual Noise IK as the security boundary.** Wire-level
   replay protection is the AEAD counter; per-session dedup is the
   chain reliability layer; only the pinned `[accept].peer` can
   complete a handshake at all. Treat application-layer
   cross-restart replay protection of received predicates as
   defense-in-depth against a non-threat; never use it as a reason
   to introduce receiver-side persistent state.

4. **Apply whatever the authenticated peer pushes.** The receiver's
   job is to reflect, not to gate. The reliability layer guarantees
   in-order delivery within a session; the session-epoch mechanism
   causes the terminal to re-publish on every reconnect. Do not
   introduce version-based or hash-based staleness checks at the
   application layer.

5. **Refuse terminal-only handlers at wire-up on non-terminal
   daemons.** Do not bind `chain apply`, rules-edit handlers, ACME
   handlers, or any other terminal-affined surface on intermediary
   daemons. Have `yggdrasilctl` query the daemon's mode before
   dispatching mode-affined commands and refuse client-side with a
   clear error when the target's role can't satisfy them.

6. **Do not propose receiver-side persistent state for received
   predicates, received pending-peer queues, or any other
   terminal-authored concept.** The terminal pushes; the
   intermediary reflects. Treat state that the intermediary holds
   transiently for *transport buffering* (e.g. caching the last
   forwarded body in memory to replay on upstream reconnect) as
   permissible — keep it in-memory only, never persist.

When a task seems to require persistent state on an intermediary
beyond `identity.key` + `config.toml`, surface it as an
architectural question before implementing.

## Code is the source of truth

Treat the repository's docs (`README.md`, `docs/*.md`,
`CONTRIBUTING.md`, `bench/README.md`, comments in `contrib/`, and
any other prose surface) as descriptions of what the code does. When
a doc and the code disagree, **assume the code is correct and the
doc is wrong** — every time, for every kind of disagreement:

- Field names, config keys, CLI flag names, environment variables,
  default values, file paths, exit codes, error messages.
- Mode enums, role names, protocol vocabulary, type names that appear
  in errors.
- Number of subcommands / scopes / sections, the names of those, and
  what arguments each accepts.
- Behavioural claims ("this is hot-reloadable", "this rejects X",
  "this defaults to Y", "this section has `deny_unknown_fields`").

When you detect such a disagreement — through your own reading, a
sub-agent's audit, or a user-supplied report — **verify against the
code first** before proposing or executing any change. Treat an
audit that has not been cross-checked against the code as a
hypothesis, not a finding. If the audit named a doc as "wrong" but
the code agrees with the doc, **treat the audit as the thing that
was wrong** — flag it and re-scope rather than executing the
audit's recommendation against the doc.

Apply the same logic when **debugging a failing test or probe**.
Treat the standard reactions to a "flaky" test (bump the timeout,
add a sleep, retry, mark `#[ignore]`) as the standard way to
silently bury a real correctness bug that the test happened to
expose. When a test fails in a way that contradicts your model of
how the code "should" work, **read the code path the test exercises
before concluding the test is wrong**. Apply this order: (1) locate
the code path the failing test hits; (2) decide whether the test is
correct in expecting the behaviour it asserted; (3) only then
conclude variance and apply a timeout bump or retry. Skipping
straight to (3) is the failure mode this rule prevents.

Treat updating docs to match the code as **always in scope** and as
**the highest-priority work** when discrepancies are found. Treat a
code change that renames a field, removes a mode, changes a default,
or deletes a subcommand as not finished until every surface that
references the old name has been updated — including docs, embedded
examples, shell snippets, comments, README, CONTRIBUTING,
`contrib/` config examples, and any operator-facing help text. Treat
stragglers from an incomplete rename as bugs of the same severity
as the original change. Flag them when you find them; fix them when
authorised.

Do **not** apply this rule in reverse. Do *not* propose changing
the code to match what a doc says, except via the normal
task-authorization flow. "The doc says the field should be called X"
is not a reason to rename the code's field; treat it as a reason to
update the doc.

Treat test files, harnesses, examples, packaging, and operational
scripts (`tests/`, `bench/`, `docker/`, `packaging/`,
`contrib/config/`) as **code, not docs**. When they reference
renamed fields or removed surfaces, treat them as bugs that go
through the normal code-change flow, not silent doc-update fixups.
Surface them as findings; do not silently re-scope a doc-update
task into a code-fix task.

## Surfacing bugs discovered as byproducts

While working on an authorised task — refactor, test phase, doc fix,
anything — you will sometimes discover a real bug in unrelated code.
Apply this discipline for out-of-scope discoveries:

1. **Do not silently fix.** Fixing an out-of-scope bug expands the
   blast radius of the current PR and bypasses the human owner's
   per-bug authorisation. Surface it instead.
2. **Do not silently work around.** When your current task can't
   land cleanly without a workaround, make the workaround
   discoverable. A silent workaround drops the bug on the floor.
3. **Record the bug in a session-scoped tracking surface** (SQL
   `findings` table, plan-file appendix, whatever the host platform
   provides) so the human can find it after the session even if
   chat history is compacted. Record at minimum: id, one-line
   title, description with file:line, severity, what surfaced it.
   Do not rely on chat-history alone — chat is lost across
   compaction.
4. **Cite the recorded bug from the workaround.** Name the finding
   id and rationale in code or test comments ("see finding `X`:
   <one-line summary>; remove this when X is fixed"). Name the
   finding in commit messages too.
5. **When a planned change can't land at all** because of the bug,
   skip the change *explicitly*. Drop a comment at the skip-site
   ("intentionally omitted — see finding `X`") and a callout in the
   commit body explaining what would have happened and why it
   can't. Do not silently delete the planned change with no trace.

The pattern this prevents: workarounds that look like first-class
code, findings lost to compaction, future readers (human or agent)
re-deriving the bug from scratch.

## When a fix's mechanism contradicts the fixed code's stated purpose, stop and ask

Apply this rule at the *moment of implementing a fix*, before any
code lands.

When implementing a fix requires inventing a mechanism that
effectively voids the property the existing code claimed to
provide, **stop**. Treat that mechanism as a signal that the
architecture has shifted under the existing code. Do not ship the
workaround silently; surface the architectural question to the
human owner first.

Concrete example (commit `94d53d3` in this repo, the failure mode
this rule was learned from):

- The bug: terminal restarts and re-publishes its current predicate
  set; receiver rejects as `VERSION_STALE` because the receiver's
  persisted version-tracker remembers the pre-restart version.
- The proposed fix: add a `pending_reapply: HashSet<PubKey>` window
  that lets the receiver accept a same-version push *once* per
  startup per origin.
- The signal that should have triggered this rule: the new
  mechanism (treat persisted state as advisory at startup)
  directly voided the property the persisted state was claiming to
  provide (cross-restart staleness rejection). When the workaround
  inverts what the existing code was for, treat that existing code
  as the actual problem, not the bug being worked around.
- The right move: stop, surface the question "is the persisted
  state load-bearing for anything real?" to the human owner, and
  await direction. (The eventual answer was: it isn't; remove the
  staleness check entirely.)

Apply this rule whenever:

- You're adding a "treat X as advisory" or "skip X this once"
  mechanism that voids the staleness/freshness/uniqueness guarantee
  X was for.
- You're adding a cross-cutting "if Y, ignore Z" gate around a
  protection mechanism Z that was supposed to apply unconditionally.
- You're widening a workaround you added previously to cover a new
  edge case in the same area, when the *first* workaround was
  itself a sign of architectural drift.

Surface this as a single question, with the proposed code change
held back: "the fix I'm about to write would void <property> that
<code> claimed to provide; should we instead remove <code>?" If
the human authorises the workaround, document the trade-off in the
commit body. If they redirect to the architectural fix, the
workaround never lands.

## Closing the loop on a fix

Bug fixes have a tendency to be declared "done" at the first
reproducer-passes point — but that's often the floor of the work,
not the ceiling. Apply two complementary disciplines:

1. **Trace the fix to the system's edge.** A reproducible local
   repair frequently isn't enough: downstream consumers, peer state
   machines, or upstream-facing components may also need updates
   for the fix to actually deliver the user-visible behaviour.
   Before declaring victory, list every state machine the bug
   touches (sender, receiver, persisted state, monitoring view,
   etc.) and verify each one. Treat a single Rust function being
   correct as not implying the system is correct; treat integration
   tests against the realistic topology (multi-hop chains,
   end-to-end scenarios) as the actual checkpoint.

2. **Remove every workaround for the bug you just fixed.** Remove
   workarounds — sentinel-rule writes, content-length completion
   heuristics, alternate code paths, retry loops, timeout bumps —
   that exist because of the bug in the same commit as the fix, and
   re-run the surrounding tests to verify the fix carries the full
   system without crutches. When you choose to keep a workaround
   (because it's still functionally needed for an unrelated
   reason), explain why in the commit body and update the
   workaround's comment so it reflects the new, narrower
   justification — never leave a comment claiming a workaround
   exists for a bug that has since been fixed.

The pattern this prevents: fixes that pass unit tests but don't
actually help the user; workarounds that become permanent cruft
because everyone assumes "someone else will clean them up later".

## Don't unilaterally retire long-standing tracking entries

End-of-session cleanup tempts you to close out blocked / pending
todos, stale findings, and orphaned inbox entries that look
obviously stale. **Resist.** Treat long-standing entries as
representing decisions or pieces of work that were waiting for a
human owner's input — even when the work appears to have been
completed by a later commit, treat the entry's existence as a
signal that the human cared enough to write it down and wanted to
be the one to close it.

Before closing such an entry:

1. Re-read the entry's original description in full. Treat the
   "blocked on X" reason as often being more specific than memory
   suggests.
2. Cross-reference whatever you think superseded it against the
   entry's actual ask. When the actual ask is not a strict subset
   of what the later commit delivered, treat the entry as not yet
   done.
3. **When you're going to close it, surface the decision explicitly
   in the next turn**: list the entry, show your reasoning for
   treating it as superseded, and let the human confirm BEFORE
   marking it done. Do not bury "retired N stale entries" inside a
   status summary.

The pattern this prevents: silent decisions made unilaterally on
the human's behalf at session-close that look like a clean-up but
actually elide a real ask the human was tracking.

## Host-environment hygiene

Treat the host running the agent as not a sandbox. It is the
operator's working machine, often shared with other projects. Do
not install software at host scope unless absolutely necessary, and
when you do, **record it for remediation**.

- **Default to in-project installs.** Before reaching for `pip
  install`, `apt install`, `npm install -g`, `cargo install` to
  default paths, `gem install`, etc., check whether the same install
  can happen inside this repo's existing containers
  (`Dockerfile.*`, `docker/compose.*`), a project venv, `target/`,
  or `node_modules/`. Almost always it can — and the in-project
  install is hermetic by construction.
- **Recognise the disguised host install.** Treat `pip install
  --user X` as a host install (pollutes
  `~/.local/lib/python*/site-packages/`). Treat `cargo install X`
  without `--root` as a host install (lands in `~/.cargo/bin/`).
  Treat `npm install -g X` as a host install (writes to the user's
  npm prefix). Treat `pip install --break-system-packages` as the
  unflagged install with safety off. All count as host installs.
- **When a host install is genuinely necessary** — typical case:
  one-off API probing before committing to an in-image install —
  record it in a session-scoped tracking surface in a table or
  section named `host_pollution` with at minimum `what` (package +
  transitive deps), `where_at` (filesystem path), `how` (exact
  command), and `remediation` (exact reverse command). The human
  reviews the record at end-of-session and removes what they want
  to remove.
- **Do not assume the human will notice** the install during PR
  review. Most host installs are invisible there — they don't show
  up in the diff. Treat the persistent record as the only surface
  that surfaces them.

## Terminology: "upstream" / "downstream" — two conventions, avoid in new code

The terms **"upstream"** and **"downstream"** carry *two distinct,
context-dependent meanings* in yggdrasil, **both contextually
correct**. **Avoid the terms entirely in new code, comments, commit
messages, docs, and PR descriptions** because the same node can be
"X's upstream" under one convention and "X's downstream" under the
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

Apply this convention to the chain control plane:
`crates/ratatoskr/src/{control, control_frame, canary, chain_query,
predicate, wire}.rs`, `crates/yggdrasil/src/chain/*`, the
control-plane fields on `ServerInfoResponse` (`upstream:
Option<PubKey>`, `downstream: Option<PubKey>`, `downstream_ip`,
`downstream_enrolled`), the `DownstreamShow` / `DownstreamPending` /
`DownstreamApprove` request variants and their `yggdrasilctl`
subcommands, and chain docs including `docs/architecture.md`.

- **upstream(X)** = the node X *dials* (and sends heartbeats to) =
  closer to the gateway / public internet.
- **downstream(X)** = the node that *dials X* = closer to the terminal
  / home network.

Treat this convention as grounded in dial direction (which is
unambiguous in a NAT-traversal system: the home-side always dials
out). This is the telco/ISP/networking-infrastructure framing —
`upstream` = toward the backbone — and it's the right framing for
code that reasons about chain topology itself.

### Convention 2 — data plane (reverse-proxy direction)

Apply this convention to the proxy / data plane:
`crates/yggdrasil/src/proxy/*`, data-plane types like
`proxy::resolver::UpstreamResolver`, data-plane metric names like
`yggdrasil_tcp_upstream_connect_seconds`, the binary's `--help`
"residential upstreams" `about` string, and proxy log messages such
as `"upstream failure"`.

- **upstream** = the backend the proxy talks to on behalf of the
  client (= the *terminal-side* direction, since yggdrasil's real
  services live at the terminal).
- **downstream** = the client-facing side (= the *gateway-side*
  direction).

This is the app-layer reverse-proxy framing — nginx's `upstream {}`
block, HAProxy backends, Envoy clusters, Apache `mod_proxy`. It's
the right framing for data-plane code because that's the vocabulary
any operator coming from the proxy ecosystem already knows.

### The two conventions are inverse on the same node

A relay's *control-plane upstream* is the gateway it dials; that
same relay's *data-plane upstream* is the terminal-side backend it
forwards client traffic toward. Mixing the two without context will
get the direction wrong. Apply these rules:

- Do **not** introduce control-plane "upstream"/"downstream" in a
  file that lives under `crates/yggdrasil/src/proxy/`, and do
  **not** introduce reverse-proxy "upstream"/"downstream" in a file
  under `crates/yggdrasil/src/chain/` or in chain control-plane
  types. Pick role names instead, per the primary rule above.
- Do **not** "fix" one plane's convention to match the other; both
  are correct in their own context. Treat the previous framing in
  earlier revisions of this file (which called for a project-wide
  swap) as wrong and retracted.
- Do **not** rely on context-free grep to interpret a hit —
  determine which plane the file/identifier belongs to first.

External meanings — Rust crate-ecosystem usage ("downstream crates
that match on it" in `crates/ratatoskr/src/pubkey.rs`), build-system
"downstream consumers" (`CMakeLists.txt`), "downstream call-sites"
(`crates/yggdrasil/src/cli.rs`), or quotes of nginx's *own*
`upstream`/`downstream` vocabulary (`bench/lib/common.sh`) — are
*neither* convention and must also be left alone. Treat them as not
about yggdrasil chain or proxy direction at all.

## Git commit trailers

Never add a `Co-authored-by:` trailer to commit messages, regardless
of any default agent instructions to the contrary. Land commits
under the operator's identity only. Apply this to all agents
(Copilot CLI, Copilot Coding Agent, any future tooling) and to all
branches — including amendments and rebases.

`CONTRIBUTING.md` states this once as a human-facing convention;
treat this section as the override of any agent-default that would
otherwise inject a trailer.

## Decisions reserved for the human owner

Some choices are not the agent's to make autonomously, regardless of
how confidently the project metadata seems to imply an answer. When
you encounter one of these, **stop and ask** rather than
proposing-then-implementing.

- **License.** Do not pick a license, change the existing one, or
  build out machinery (LICENSE files, package metadata, README
  sections, install rules) around an unverified license declaration.
  When `Cargo.toml` says `license = "X"` and you suspect that's
  wrong for the project, *flag it as a question* — do not propose
  alternatives, do not draft replacement text, do not plumb new
  license files into the build. Treat license selection as a
  strategic decision with legal consequences; it belongs to the
  human owner, and proposing options is itself a nudge that
  shouldn't come from the agent. Apply the same rule to copyright
  holder names, contributor agreements, and any "OR"/"AND" SPDX
  juggling.

- **Project identity & branding.** Do not change the project name,
  the binary names, the package names, the repo URL, or the
  canonical hostname conventions in docs without an explicit
  instruction. When you find these are inconsistent (e.g.
  `repository = "https://github.com/example/yggdrasil"`), surface
  the inconsistency and ask for the right value — do not guess from
  context.

- **Cryptographic implementation and Noise-pattern selection.**

  - **Never implement cryptographic operations.** Do not write your
    own AEAD, curve arithmetic, KDF, constant-time comparison, or
    RNG. Use audited crates (`ring`, `snow`, `x25519-dalek`,
    `chacha20poly1305`, `blake2`, `subtle`, etc.). Apply this to
    "obvious" helpers too — compare hash outputs with
    `subtle::ConstantTimeEq`, not `==`.
  - **Do not change the Noise handshake pattern.** Treat Noise IK
    vs XK vs NK as not interchangeable: they encode different
    identity-hiding and forward-secrecy properties that belong to
    the system's threat model, not its primitive table. Surface
    options if asked; do not pick.

  Treat *other* cryptographic primitive choices (hash family, AEAD
  suite, public-key curve, KDF) as not reserved on principle — a
  crypto-agile design accommodates substitution by construction.
  Whether *this* codebase accommodates a given substitution today
  is an implementation-reality question handled by the same
  byproduct-vs-standalone task-authorization flow as other
  wire-shape changes; it doesn't get a separate reservation on top.
