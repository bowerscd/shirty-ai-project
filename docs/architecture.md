# Architecture

This document is for engineers reading the code, debugging strange behaviour,
or evaluating yggdrasil before deploying it. For day-to-day operations, see
[operations.md](operations.md).

## The problem in one paragraph

You have a server with a public, static IP (the **VPS**). You have a box at
home with the application you want to expose, but its IP changes every time
the ISP renews its DHCP lease. You want internet traffic to reach
`vps.example.net:443` and end up at your home box's port 443 — without
running TLS-MITM, without a custom client, without paying for a static
residential IP. yggdrasil is a Linux daemon for the VPS side; ratatoskr is
its companion daemon for the home side.

## High-level shape

```
                      authenticated UDP (Noise_IK)
                  +------------------ heartbeats ------------------+
                  |          source IP = current home IP           |
                  v                                                |
        +-----------------+                              +-----------------+
clients |    yggdrasil    |   forwarded TCP / UDP        |   ratatoskr     | home services
------> | (VPS, public)   | ---------------------------> | (home, NAT'd)   | --------------> 22, 25565, ...
        +-----------------+                              +-----------------+
            ^      ^
            |      |
            |      +-- Prometheus /metrics
            +-- yggdrasilctl over UDS
```

yggdrasil binds three things:

1. **Heartbeat UDP socket** (`server.heartbeat_listen`). One per host.
   Carries Noise_IK control traffic only — no application data.
2. **Per-rule data-plane sockets**. Each `[[rule]]` in `branches/*.toml`
   creates exactly one TCP listener or one UDP listener.
3. **Unix control socket** (`control.socket`). Talks to `yggdrasilctl`.

ratatoskr binds nothing. It only opens an outbound UDP connection to
`yggdrasil_endpoint`, performs the handshake, and sends heartbeats.

## Crypto: Noise_IK

The control channel uses **Noise_IK_25519_ChaChaPoly_BLAKE2s** via the
`snow` crate. Same suite as WireGuard. Why this and not TLS:

- We don't need certificates or PKI. Both sides have a single long-term
  X25519 keypair pinned in their config; the trust model is identical to
  SSH `authorized_keys`. PKI buys us nothing and adds attack surface.
- Noise_IK gives mutual authentication in one round-trip (two messages):
  the responder learns the initiator's static key as part of message 1.
- The transcript is short enough to fit in a single UDP datagram on either
  side, so we don't have to invent a fragmentation/reassembly story.

After the handshake completes both sides hold a `snow::TransportState`
which we wrap as `Session` in `yggdrasil-proto/src/auth.rs`. Every
heartbeat is `Session::encode_heartbeat(now_ms, flags)` → a single AEAD-
sealed UDP datagram; every ack is `Session::encode_heartbeat_ack`.

### Replay protection

Each post-handshake packet carries an 8-byte big-endian counter in
cleartext, prefixed to the AEAD ciphertext. The receiver:

1. Reads the counter without touching crypto state.
2. **Rejects strictly-less-than-or-equal counters** before decryption.
3. If decryption succeeds, advances `last_seen_counter`.
4. If decryption fails, the counter is **not** advanced — so an attacker
   replaying a real packet plus a fake counter cannot ratchet us past
   genuine traffic.

Strict-monotonic replay (rather than a window) is fine here because UDP
delivery between the two endpoints is over a single path with one
sender per session.

## Identity & enrollment

Each side has one X25519 keypair, stored on disk as a 64-byte file (32
secret + 32 public) with mode 0600. The pubkey is publishable; the secret
is zeroized on drop.

`fingerprint = BLAKE2s-128(pubkey)` rendered as 32 hex chars. Used for
out-of-band display in TOFU flows.

Two enrollment paths, both documented in detail in
[quickstart.md](quickstart.md) and [security.md](security.md#enrollment-token-format):

- **Out-of-band token** — operator runs `yggdrasil enroll-token` against
  ratatoskr's pubkey, transfers the resulting `*.token` file, ratatoskr
  applies it. The token contains both pubkeys and the endpoint hint;
  it's not a secret.
- **TOFU** — start yggdrasil with `peer.public_key_hex = ""`, let
  ratatoskr try to handshake, then `yggdrasilctl peer pending` /
  `yggdrasilctl peer approve <fingerprint>` to admit the candidate after
  out-of-band fingerprint verification.

## Heartbeats and the peer-IP source of truth

`PeerState` (`crates/yggdrasil/src/heartbeat/peer_state.rs`) owns:

- The configured peer static pubkey (live-swappable via
  `set_peer_static_key` so TOFU approval doesn't require a restart).
- An `AtomicU64` for `last_heartbeat_ms` since process start.
- A `tokio::sync::watch::Sender<Option<IpAddr>>` for the current peer IP.

When `HeartbeatServer` processes a valid heartbeat, it calls
`peer_state.record_heartbeat(src_addr)`. That call returns one of:

- `SameIp(ip)` — most common. The watch channel **does not fire** because
  we use `send_if_modified` which skips updates when the new value
  equals the old one.
- `FirstHeartbeat(ip)` — initial `None → Some(_)` transition. Watch fires.
- `IpChanged { old, new }` — the home side rotated. Watch fires.

The data-plane code subscribes to the watch and reacts only when it
fires. **This is the structural guarantee behind the heartbeat invariance
principle** — same-IP heartbeats can't even reach the drain path, so they
can't possibly disturb in-flight UDP flows or TCP connections.

### Heartbeat invariance

The single most important property in this codebase:

> **Heartbeats with an unchanged peer IP MUST NOT disturb the data plane.**

If you're holding a stateful UDP session — a Factorio game, a Source-engine
session, Mumble, WireGuard tunnelled through the proxy — and yggdrasil
gets a heartbeat with the same IP it saw last time, **nothing changes on
the data plane**. No socket close, no flow rebind, no rekey of the proxy↔
upstream pair. The heartbeat just refreshes `last_heartbeat_ms` and ACKs.

That invariance is tested by
[`heartbeat_invariance_udp.rs`](../crates/yggdrasil/tests/heartbeat_invariance_udp.rs)
and its TCP counterpart, which fire 100+ heartbeats from a fixed source
and assert the per-flow upstream socket is byte-identical before and
after.

## Data-plane: per-rule proxies

Every `[[rule]]` becomes one `ProxyHandle` owned by `ProxySupervisor`
(`src/proxy/supervisor.rs`). Two variants:

### TCP (`proxy/tcp.rs`)

Plain async accept loop. On each new client connection:

1. Snapshot `peer_state.current_ip()`. If `None`, drop the socket
   immediately — listener stays up.
2. Dial `(peer_ip, rule.upstream_port)`. Connection failures close the
   client without sending bytes (no leaked half-open).
3. Optionally write a PROXY-protocol v1/v2 header so the upstream service
   sees the real client IP.
4. `copy_bidirectional` between the two halves until either closes.

`TCP_NODELAY` is on by default; game protocols (low-RTT pings) noticeably
benefit and bulk-byte workloads are unaffected.

### UDP (`proxy/udp.rs`)

The interesting one — UDP has no inherent connection, so we build one.

- One `Arc<UdpSocket>` per rule, bound to `rule.listen`. We deliberately
  reuse the same kernel socket for outbound responses so the client sees
  the same source IP:port pair across the whole flow.
- A `DashMap<SocketAddr, Arc<FlowEntry>>` keyed by client address. Each
  `FlowEntry` owns a freshly-bound ephemeral UDP socket connected to
  `(peer_ip, rule.upstream_port)`, plus an `AbortHandle` for the
  `upstream_to_client_loop` task.
- Inbound packets from a known client: update `last_seen_ms`, forward.
  Unknown client: read `peer_state.current_ip()` (drop if `None`), bind
  ephemeral socket, spawn the return-path task, insert atomically via
  `DashMap::entry`, forward.
- A reaper task wakes periodically and evicts flows older than the rule's
  `idle_timeout` (default 60s, configurable per rule).
- A separate **`ipchange_loop`** task subscribes to `peer_state.watch()`.
  When the channel fires (real IP change), it drains every flow:
  `flows.retain(|_, e| { e.upstream_task.abort(); false })`. Subsequent
  client packets bind fresh sockets pointed at the new IP.

The structural reason same-IP heartbeats are cheap is that the watch
channel never fires for them — `ipchange_loop` is parked, the reaper is
unaffected, and the frontend recv loop never even reads `peer_state` for
known clients (it just hashes into `DashMap`).

## Branches: hot reload

`branches_dir` is watched via `notify-debouncer-mini` with a 250 ms
debounce. The worker task:

1. On filesystem event → `load_dir(branches_dir)` → returns a fresh
   `BranchSet` (validated, cross-file uniqueness checked).
2. `previous.diff(&new) → BranchDiff { added, removed, changed, unchanged }`.
3. **Unchanged rules are strictly untouched.** The supervisor doesn't
   even look at them. Editing rule B never disturbs rule A's listener or
   its in-flight UDP flows. This is the branch-level analogue of
   heartbeat invariance.
4. Validation failures keep the previous `BranchSet` live. There is no
   "partial apply" mode — half-good reloads are worse than no reload.

Force a re-scan with `yggdrasilctl branches reload` (for filesystems where
inotify is unreliable).

## Control plane: yggdrasilctl over UDS

`/run/yggdrasil/control.sock` is a Unix domain socket carrying newline-
delimited JSON. We chose NDJSON specifically because it makes
`socat - UNIX-CONNECT:/run/yggdrasil/control.sock` and `jq` viable for
debugging — no length-prefixed framing.

Request/response definitions live in `crates/yggdrasil-proto/src/control.rs`
so `yggdrasilctl` and the server share the type surface verbatim.

Filesystem permissions are the access boundary. Run yggdrasil as a
dedicated user (e.g. `yggdrasil`), drop the socket directory's group
permissions to `yggdrasil-admin` (or whatever group you use for
administrators), and don't put untrusted users in that group.

## Process model

Both daemons are single-process, multi-task tokio applications. There is
no fork, no privileged child, no helper subprocess. Capabilities-wise:

- yggdrasil needs `CAP_NET_BIND_SERVICE` if any rule listens on a port
  < 1024 (e.g. `0.0.0.0:443`). The systemd unit in
  [install.md](install.md#systemd-units) grants this and nothing else.
- ratatoskr needs only the ability to open one outbound UDP socket.
  Standard unprivileged user, no caps.

Identity files are mode 0600 and owned by the daemon user. The
in-process `StaticKeyPair` is `zeroize::Zeroizing` so the secret is wiped
on drop even if a panic unwinds the stack.

## Why one peer

yggdrasil supports exactly **one** ratatoskr peer per instance.
Multi-peer is intentionally out of scope:

- It would force per-rule peer selection ("rule X goes to peer A"), which
  is a different product — a multi-tenant residential proxy.
- A single PeerState lets us keep `current_ip` as one cheap atomic, and
  lets the UDP proxy's `ipchange_loop` be a single global task rather
  than per-rule.
- Most home-lab users want one VPS pointing at one home box. The 80%
  case is also the simple case.

If you really need two upstream homes, run two yggdrasil instances on
the same VPS bound to different `heartbeat_listen` ports.

## Observability inventory

Logs (both daemons): `tracing` JSON to stdout. Configure verbosity per
`tracing-subscriber` env-filter via `YGGDRASIL_LOG` / `RATATOSKR_LOG`.

Metrics (yggdrasil only): Prometheus on `metrics.listen`, default
`127.0.0.1:9090/metrics`. Full list in
[operations.md → Prometheus metrics](operations.md#prometheus-metrics).

Admin: `yggdrasilctl status / branches / peer`. Reference in
[cli-reference.md](cli-reference.md#yggdrasilctl).

## Build artefacts

| Crate           | Output                              | Linkage                |
| --------------- | ----------------------------------- | ---------------------- |
| `yggdrasil-proto` | (lib only)                        | shared types + crypto  |
| `yggdrasil`     | bin `yggdrasil` + lib               | depends on proto       |
| `yggdrasilctl`  | bin `yggdrasilctl`                  | depends on proto       |
| `ratatoskr`     | bin `ratatoskr`                     | depends on proto       |
| `loadgen`       | bin `loadgen` (workspace-internal)  | depends on nothing     |

There is no FFI, no dynamic link to OpenSSL, no C build dependency. The
`snow` crate uses pure-Rust X25519/ChaCha20-Poly1305/BLAKE2s
implementations.

## Where to look next

- Wire format: `crates/yggdrasil-proto/src/wire.rs`.
- Authenticated session: `crates/yggdrasil-proto/src/auth.rs`.
- Heartbeat invariance test: `crates/yggdrasil/tests/heartbeat_invariance_udp.rs`.
- UDP flow table: `crates/yggdrasil/src/proxy/udp.rs`.
- Branch watcher: `crates/yggdrasil/src/branches/watcher.rs`.
- Control-plane request/response: `crates/yggdrasil-proto/src/control.rs`.
