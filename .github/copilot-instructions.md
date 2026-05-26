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
