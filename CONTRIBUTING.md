# Contributing to yggdrasil

Thanks for considering a contribution. This file covers the **mechanics** of
landing a PR: the local gate you run before pushing, what reviewers look
for, and how to format commits.

If you're new to the codebase, read [docs/development.md](docs/development.md)
first — that's the full onboarding (setup, codebase tour, dependency tour,
glossary, engineering conventions). This file assumes you've done that.

## The local gate

Run these three commands before pushing. CI runs the same commands with
`RUSTFLAGS="-D warnings"`, so matching them locally is the cheapest way to
avoid a red CI:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --benches -- -D warnings
cargo test  --workspace --all-targets
```

For changes touching CLI surfaces (anything under `crates/cli-defs/`),
also confirm the auto-generated reference didn't drift:

```bash
cargo build --workspace --locked          # build.rs regenerates docs/cli-reference/
git diff --exit-code -- docs/cli-reference/
```

CI's `docs-cli-drift` job will fail if you change a flag and forget to
commit the regenerated docs.

## Smallest targeted selectors

While iterating, narrow to one test for fast feedback. The gate above is
the *push gate*, not the iteration loop:

```bash
# One integration test by file name (file = crates/yggdrasil/tests/hot_reload.rs)
cargo test --package yggdrasil --test hot_reload

# One unit test by module path
cargo test --package ratatoskr -- wire::tests::round_trip

# With test output visible
cargo test --package yggdrasil --test hot_reload -- --nocapture
```

See [docs/development.md § Day-to-day workflow](docs/development.md#5-day-to-day-workflow)
for the broader development loop, including `RUST_LOG` patterns and the
disk-space guardrails for repeated bench/profile builds.

## What reviewers look for

In rough priority order:

1. **Correctness** — does the change do what it claims? Is the test
   coverage proportional to the risk?
2. **Surgical scope** — does the change modify only what it needs to? See
   [docs/development.md § Engineering conventions](docs/development.md#6-engineering-conventions)
   for the project's accumulated lessons (especially the performance-work
   guardrails — sub-noise wins are not wins).
3. **Documentation drift** — if you changed a config field, did
   `docs/configuration.md` get the update? A CLI flag,
   `docs/cli-reference/`? An engineering convention, the relevant doc
   section?
4. **No unrelated cleanups in the same PR.** Pre-existing nits go in
   their own PRs; mixed scope makes review harder than it needs to be.

A reviewer will not block on style/formatting (`cargo fmt` already gates
that) or on subjective code-organisation preferences. The bar is "does
this improve the project on net," not "is this exactly how I'd write it."

## Commit-message style

- **Imperative mood, present tense.** `Add UDP flow reaper`, not `Added
  UDP flow reaper` or `Adds UDP flow reaper`. Matches `git`'s own
  conventions and the existing project history.
- **Wrap the subject line at 72 chars.** Free-form body below if useful;
  explain *why* the change exists, not *what* it does (the diff already
  shows what).
- **No `Co-authored-by:` trailer.** Even if an automated tool you use
  defaults to adding one, strip it before pushing. Commits land under the
  contributor's identity only.

## Finding something to work on

For a curated list of starter tasks, see issues labelled
`good-first-issue` in the tracker:

<https://github.com/bowerscd/yggdrasil/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22>

If you have a non-trivial change in mind, opening an issue to sketch the
approach before writing code is welcome — it avoids the case where a
finished PR has to be reshaped at review time.

## Reporting bugs / security issues

Functional bugs: open an issue. Include the daemon version
(`yggdrasil --version`), the config that reproduces (redacted), and any
relevant log lines (`journalctl -u yggdrasil` JSON output is ideal).

Security issues: see [docs/security.md](docs/security.md) for the
project's threat model. For private vulnerability reports, use GitHub's
private vulnerability reporting on the repository's **Security** tab
rather than filing a public issue.
