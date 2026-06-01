# Test-only helpers that bypass production discipline

This is an audit artifact from the Phase 1 architectural-integrity
sweep. It catalogues every test-only helper that reaches past a
production crate's API discipline, with an explicit disposition for
each. The intent is: a reader (especially a future LLM agent extending
the test corpus) should be able to look at any test helper and tell
*at a glance* whether the discipline it bypasses is load-bearing for
security or just ergonomic, and what the project's stance on the
bypass is.

## Audit scope

- `crates/yggdrasil/tests/common/mod.rs` — 16 public helpers + 1
  public struct.
- `crates/yggdrasil/tests/common/nat_gateway.rs` — 3 public types,
  documented separately because the design is deliberately the
  *opposite* shape.

## Findings

### 1. `clone_kp` — bypasses `StaticKeyPair`'s no-`Clone` discipline

**Helper** (`tests/common/mod.rs:31`):

```rust
pub fn clone_kp(k: &StaticKeyPair) -> StaticKeyPair {
    StaticKeyPair::from_raw(*k.secret_bytes(), *k.public_key())
}
```

**Bypass.** `StaticKeyPair` does not implement `Clone`. The
source-of-truth comment on the helper says this is "to discourage
passing the secret around at runtime."

**Why the discipline isn't load-bearing.** The bypass is trivial
because every primitive needed to reconstruct a `StaticKeyPair` is
`pub` on the type itself in production:

- `StaticKeyPair::from_raw(secret, public) -> Self` is `pub`.
- `StaticKeyPair::secret_bytes() -> &[u8; SECRET_KEY_LEN]` is `pub`.
- `StaticKeyPair::public_key() -> &[u8; PUBLIC_KEY_LEN]` is `pub`.

Any production code that wants to "clone" the keypair can do exactly
what `clone_kp` does. The no-`Clone` discipline forces one extra line
of syntax; it provides no actual safety property. Memory zeroisation
on drop is provided by `Zeroizing<...>` around the secret bytes, and
that property does hold across clones via this path (each clone
allocates its own `Zeroizing<...>`).

**Disposition.** ACCEPTED as test-only escape hatch with rationale —
but with a flag.

The discipline is honest about its intent ("discourage") rather than
"enforce," and the helper is honest about being a test bypass. That's
consistent.

The flag: removing the discipline (deriving `Clone` on
`StaticKeyPair`) would simplify the test code and admit reality. The
alternative — making `from_raw` / `secret_bytes` `#[cfg(test)]` — is
not feasible because `from_identity_bytes` in production needs both
to read the on-disk identity file. So the discipline cannot be made
load-bearing without restructuring `auth.rs`.

Whether to deriving `Clone` instead is a decision **reserved for the
human owner** per copilot-instructions ("Cryptographic primitives.
Don't swap the Noise pattern, the AEAD suite, the hash, or the
public-key curve. Even 'obviously equivalent' substitutions change
the wire format and the security argument.") — making a
secret-holding type cloneable is in the same category of decision
even if the safety argument is weak.

Until then: this file is the answer to "why is the discipline still
there?" — to make future maintainers think twice before introducing
extra clones in production paths, even though nothing prevents them.

### 2. Pure test scaffolding (no bypass)

The following helpers don't reach past any production discipline;
they wrap or compose public APIs:

| Helper                                   | What it does                                          |
| ---------------------------------------- | ----------------------------------------------------- |
| `echo_udp_socket` / `spawn_udp_echo`     | Loopback UDP echo server. Pure scaffolding.           |
| `echo_tcp_listener` / `spawn_tcp_echo`   | Loopback TCP echo server. Pure scaffolding.           |
| `pick_free_udp_port` / `pick_free_tcp_port` | Bind-to-zero, read assigned port, drop socket. Pure scaffolding with a tiny race window before the test rebinds; tolerated for loopback testing. |
| `drive_handshake`                        | Drives a real Noise_IK handshake against `HeartbeatServer` using the public `Initiator` / `Session` API. No bypass. |
| `send_heartbeat`                         | Encodes + sends a heartbeat using `Session::encode_heartbeat`. Public API; no bypass. |
| `write_rule` / `write_terminal_rule`     | Writes a TOML rule file to a tempdir. No bypass.       |
| `HeartbeatHarness::spawn`                | Spawns a `HeartbeatServer` via its public `bind`. No bypass. |
| `spawn_supervisor` / `spawn_terminal_supervisor` / `spawn_terminal_supervisor_with_certs` | Spawns a `ProxySupervisor` via its public `spawn`. No bypass. |
| `read_exact_or_timeout`                  | Tokio-aware `read_exact` with a timeout. Pure scaffolding. |

### 3. `MockNatGateway` — deliberately uses the production codec

(`tests/common/nat_gateway.rs:98`)

This is the *opposite* of a bypass and worth calling out as the
positive example. The mock NAT gateway used by the NAT-traversal
integration tests parses every incoming request with the **production
PCP / NAT-PMP codec** (`yggdrasil::nat::wire::{pcp,natpmp}`), so a
regression in those codecs surfaces in the integration tests too.

The module's own docstring already explains the design intent. Other
test scaffolding should follow this pattern when feasible: drive the
production parser, not a hand-rolled mirror.

## Convention going forward

When adding a new test-only helper:

1. **Default**: compose public production APIs. No bypass needed.
2. **If a bypass seems necessary**: ask whether the production
   discipline being bypassed is genuinely load-bearing. If yes, the
   test is exercising a different code path than production — fix
   the test, don't add the bypass. If no, add the helper and add a
   row to this file under "Findings" with the same shape as §1
   above (helper, bypass, why-not-load-bearing, disposition).
3. **Never** add a helper that bypasses cryptographic primitives,
   wire-format invariants, or rate-limiting / replay-protection
   without explicit human-owner sign-off recorded in this file.
