# ratatoskr fuzz harness

[libFuzzer](https://llvm.org/docs/LibFuzzer.html)-driven fuzz targets for
the `ratatoskr` protocol library. Driven via
[`cargo-fuzz`](https://rust-fuzz.github.io/book/cargo-fuzz.html).

## Why a separate package

`cargo-fuzz` requires nightly Rust. The main workspace pins stable
`1.95.0` in the top-level `rust-toolchain.toml`. Co-locating the fuzz
package under `crates/ratatoskr/fuzz/` with its own
`rust-toolchain.toml` (pinning a specific nightly date) keeps the
toolchain split clean: stable for everything humans touch in normal
development, nightly only when explicitly running fuzz targets.

The workspace's top-level `Cargo.toml` `exclude`s this directory so
`cargo build --workspace` on stable does not try to compile it.

## Targets

| target           | entry                                        | what it covers                                                                         |
| ---------------- | -------------------------------------------- | -------------------------------------------------------------------------------------- |
| `wire_parse`     | `ratatoskr::wire::parse(&[u8])`              | Pre-auth wire framing. Anyone with UDP reachability throws bytes at this entry point.   |

(More targets land as the harness grows. See
[`docs/development.md` § Engineering conventions](../../../docs/development.md)
for the rule on when to add one.)

## Local workflow

Prerequisites:

```bash
cargo install --locked cargo-fuzz
```

Nightly Rust is pulled automatically on first invocation thanks to this
directory's `rust-toolchain.toml`.

Run a target:

```bash
# From the repo root.
cd crates/ratatoskr/fuzz

# List available targets.
cargo fuzz list

# Run for a fixed number of iterations (good for CI / smoke checks).
cargo fuzz run wire_parse -- -runs=10000

# Run for a fixed wall-clock time.
cargo fuzz run wire_parse -- -max_total_time=60

# Run unbounded (Ctrl-C to stop).
cargo fuzz run wire_parse
```

## Triaging a crash

When libFuzzer finds an input that panics / aborts, it writes the
offending bytes to `artifacts/<target>/crash-<sha1>` and prints the
panic backtrace. To reproduce locally:

```bash
cargo fuzz run wire_parse artifacts/wire_parse/crash-abc123...
```

To minimise a discovered crash to its smallest reproducer:

```bash
cargo fuzz tmin wire_parse artifacts/wire_parse/crash-abc123...
```

Commit minimised reproducers under `corpus/<target>/` as regression
seeds so future fuzz runs cover the same shape.

## Corpus management

Seed corpora (small, hand-picked valid inputs) live under
`corpus/<target>/` and **are committed**. Runtime-discovered corpora
grow into the millions of entries and are gitignored.

For coverage hand-off to deeper fuzzing infrastructure (OSS-Fuzz, when
the repo has a remote), the seed corpora are what gets shipped.
