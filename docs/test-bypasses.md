# Test-only helpers that bypass production discipline

This is an audit artifact from the Phase 1 architectural-integrity
sweep. The intent: a reader (especially a future agent extending the
test corpus) should be able to look at any test helper and tell *at
a glance* whether the discipline it bypasses is load-bearing for
security, just ergonomic, or non-existent.

## Audit scope

- `crates/yggdrasil/tests/common/mod.rs` — 15 public helpers + 1
  public struct.
- `crates/yggdrasil/tests/common/nat_gateway.rs` — 3 public types,
  documented separately because the design is deliberately the
  *opposite* shape.

## Findings

### None — no real bypasses

Every helper composes public production APIs without reaching past
any discipline. Notably:

| Helper                                                      | What it does                                          |
| ----------------------------------------------------------- | ----------------------------------------------------- |
| `echo_udp_socket` / `spawn_udp_echo`                        | Loopback UDP echo server. Pure scaffolding.           |
| `echo_tcp_listener` / `spawn_tcp_echo`                      | Loopback TCP echo server. Pure scaffolding.           |
| `pick_free_udp_port` / `pick_free_tcp_port`                 | Bind-to-zero, read assigned port, drop socket. Pure scaffolding with a tiny race window before the test rebinds; tolerated for loopback testing. |
| `drive_handshake`                                           | Drives a real Noise_IK handshake via the public `Initiator` / `Session` API. No bypass. |
| `send_heartbeat`                                            | Encodes + sends a heartbeat via `Session::encode_heartbeat`. Public API; no bypass. |
| `write_rule` / `write_terminal_rule`                        | Writes a TOML rule file to a tempdir. No bypass.       |
| `HeartbeatHarness::spawn`                                   | Spawns a `HeartbeatServer` via its public `bind`. No bypass. |
| `spawn_supervisor` / `spawn_terminal_supervisor` / `spawn_terminal_supervisor_with_certs` | Spawns a `ProxySupervisor` via its public `spawn`. No bypass. |
| `read_exact_or_timeout`                                     | Tokio-aware `read_exact` with a timeout. Pure scaffolding. |

### Historical note: `clone_kp` (removed)

An earlier version of this file documented `clone_kp` as a
test-only escape hatch for `StaticKeyPair`'s "intentional no-`Clone`
discipline." The docstring on the helper claimed:

> `StaticKeyPair` intentionally does not implement `Clone` to
> discourage passing the secret around at runtime.

This was simply false: `StaticKeyPair` carries `#[derive(Clone)]`
and always has. The helper's existence + docstring constituted a
lying-by-implication artifact — they suggested a discipline that
never existed, and someone reading the test code would have come
away believing there was a security posture being maintained.

Both the helper and its callers were removed in the same commit
that added this audit; callers now invoke `kp.clone()` directly.

If a real no-`Clone` discipline is desired in the future, it
requires more than just removing the derive: `StaticKeyPair::from_raw`
and `StaticKeyPair::secret_bytes` are both `pub` and let any caller
trivially reconstruct a clone from raw bytes. Restructuring those
APIs is a separate decision reserved for the human owner.

### `MockNatGateway` — deliberately uses the production codec

(`tests/common/nat_gateway.rs:98`)

This is the positive example, worth calling out. The mock NAT
gateway used by the NAT-traversal integration tests parses every
incoming request with the **production PCP / NAT-PMP codec**
(`yggdrasil::nat::wire::{pcp,natpmp}`), so a regression in those
codecs surfaces in the integration tests too.

The module's own docstring already explains the design intent.
Other test scaffolding should follow this pattern when feasible:
drive the production parser, not a hand-rolled mirror.

## Convention going forward

When adding a new test-only helper:

1. **Default**: compose public production APIs. No bypass needed.
2. **If a bypass seems necessary**: ask whether the production
   discipline being bypassed is genuinely load-bearing. If yes, the
   test is exercising a different code path than production — fix
   the test, don't add the bypass. If no, ask why the discipline
   exists at all (the `clone_kp` case suggests this is sometimes
   the more productive question).
3. **If a bypass genuinely lands**: add a `### N. <helper>` section
   to this file with the same shape as the historical note above
   (what it does, what it bypasses, why-load-bearing-or-not,
   disposition). Don't leave bypasses undocumented.
4. **Never** add a helper that bypasses cryptographic primitives,
   wire-format invariants, or rate-limiting / replay-protection
   without explicit human-owner sign-off recorded in this file.
