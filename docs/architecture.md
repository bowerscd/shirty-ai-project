# Architecture

This document is for engineers reading the code, debugging strange behaviour,
or evaluating yggdrasil before deploying it. For day-to-day operations, see
[operations.md](operations.md).

## The problem in one paragraph

You have a server with a public, static IP (the **relay**). You have a box at
home with the application you want to expose, but its IP changes every time
the ISP renews its DHCP lease (the **terminal**). You want internet traffic
to reach `vps.example.net:443` and end up at your home box's port 443 —
without running TLS-MITM, without a custom client, without paying for a
static residential IP. yggdrasil is a Linux daemon that runs at both ends
(and at any number of intermediate hops) of a chain of authenticated UDP
control sessions.

## Cast of characters

There is exactly one daemon binary, `yggdrasil`, running in one of two modes
derived from the `[dial]` / `[accept]` tables:

| Mode       | Accepts inbound chain traffic | Dials upstream | Typical role                               |
| ---------- | ----------------------------- | -------------- | ------------------------------------------ |
| `relay`    | Yes (when `[accept]` set) | Optional   | Root VPS, or mid-chain forwarder.          |
| `terminal` | No                            | Yes (required) | Home box / chain leaf.                     |

The auxiliary binaries are:

* **yggdrasilctl** — admin CLI. Four scopes: `local` (UDS, daemon-local
  operations), `chain` (introspection across the chain), `identity`
  (file-based identity + request/grant handshake), and offline
  `validate`.
* **ratatoskr** — shared library. Wire format, Noise_IK auth, control-plane
  message types, rule schema, predicate schema, chain query envelopes.
* **bench-tools** — benchmark helper binaries (`loadgen`, `bench-echo`) used by the harness under [bench/](../bench/).

The metaphor is a navigation aid, not load-bearing: yggdrasil is the tree,
ratatoskr is the squirrel who runs messages up and down it.

## High-level shape — single-hop deployment

```
                      Noise_IK over UDP, heartbeats + control frames
                +------------------------------------------------------+
                |               source IP = terminal's current IP      |
                v                                                      |
        +-----------------+                                   +-----------------+
clients |   yggdrasil     |   forwarded TCP / UDP             |   yggdrasil     | home services
------> | (VPS, "relay")  | --------------------------------> | ("terminal")    | --------------> 22, 25565, ...
        +-----------------+                                   +-----------------+
            ^      ^
            |      |
            |      +-- yggdrasilctl over UDS:
            |          status, rules, accept, metrics, health,
            |          derived-rules, trace, chain {summary,health,ping,diff}
            +-- (no separate metrics listener — UDS only)
```

Both nodes bind:

1. **Chain listener** (relay only, when `[accept]` is set). UDP.
   Carries Noise_IK-protected control frames — heartbeats, predicate pushes,
   and recursive chain-summary queries. No application bytes.
2. **Per-rule data-plane sockets**. Each rule (on the terminal: from
   `conf.d/*.toml`; on the relay: derived from the terminal's published
   predicate set) creates exactly one TCP listener or one UDP listener.
3. **Unix control socket** (`[control].socket`). Talks to `yggdrasilctl`.
   Also serves Prometheus text (`local metrics`), health summaries
   (`local health`), and derived-rule snapshots (`local derived-rules`).
   There is no separate HTTP listener; operators who scrape Prometheus
   over TCP front the UDS with a small UDS→HTTP adapter.

The terminal additionally maintains an outbound UDP connection (the **chain
client**) to its `[dial]` endpoint, performs the Noise_IK
handshake, and runs the heartbeat / predicate-push tasks against it.

## High-level shape — multi-hop chain

```
        clients                   +---------------+   forwarded TCP/UDP   +---------------+   forwarded TCP/UDP   +---------------+   loopback dial
        ---------+--------------> |    vps        | --------------------> |    midbox     | --------------------> |    home       | ----------------> 127.0.0.1:22 etc.
                                  | relay (root)  |                       | relay (mid)   |                       | terminal      |
                                  +---------------+                       +---------------+                       +---------------+
                                       ^                                       ^      ^                              |
                                       |                                       |      |                              |
                                       | predicates flow upward                |      | predicates flow upward      |
                                       |  (terminal publishes its rule set;    |      |  ("home-tcp-echo" derived   |
                                       |   v1 mid-relays do NOT re-project)    |      |   into a TCP listener on     |
                                       |                                       |      |   midbox)                    |
                                       |                                       |      |                              |
                                       |          Noise_IK chain control       v      v                              |
                                       +------------------ heartbeats ----------------------------------------------+
```

Chain orientation rule: for any node X, `upstream(X)` is the node X dials
(and sends heartbeats to); `downstream(X)` is the node that dials X. The
terminal has only an upstream; the root relay has only a downstream;
mid-chain relays have both. v1 supports exactly one upstream and one
downstream per node.

`v1 relays do NOT re-project predicates upward.` A predicate set
originating at a terminal lands on its immediate upstream and is derived
into a `RuleSet` there. It is **not** aggregated and re-published on the
next hop. This means `vps` in the three-hop diagram above runs zero rules
(it sees no published predicates from `midbox`), and `chain diff` will
legitimately report drift at the top hop. Predicate aggregation across
intermediate hops is a deliberate v2 deferral.

### Home-hosted deployments and NAT traversal

The canonical shape (terminal-at-home dials VPS-relay) avoids needing
inbound ports on the residential side: the chain client is purely
outbound. But three other shapes are legitimate and do need inbound
reachability on a home-hosted node:

1. **Standalone home terminal** — no upstream, the terminal's own
   rule listeners are the public surface.
2. **Home gateway** — a root relay with `[accept]` on a residential
   line, dialed by some downstream terminal also at home.
3. **Mid-chain home relay** — `[dial]` + `[accept]` where the
   `[accept]` side faces a downstream that can't reach the VPS
   directly.

For all three, the operator can either forward ports manually in the
router admin UI or set `[server].nat_traversal = "auto"` to have the
daemon ask the router via PCP (RFC 6887) or NAT-PMP (RFC 6886). The
mapper subscribes to the supervisor's `current_set` watch and the
chain `[accept].listen` socket, derives the inventory of
`(protocol, internal_port)` triples it needs forwarded, reconciles
that against the gateway, and renews at half-lifetime. See
`docs/configuration.md` for the operator-facing knob and
`docs/operations.md` for diagnosis.

This does **not** bypass CGNAT. If your ISP gives you a
100.64.0.0/10 address, no NAT-mapping protocol works — your router
cannot forward a port on an IP it doesn't own. Use a VPS for the
public-facing role and let `[dial]` connect outward from home.

UPnP-IGD is intentionally not supported: SSDP multicast + SOAP/XML
is a values mismatch with the project's `#![forbid(unsafe_code)]`
and minimum-attack-surface posture. PCP and NAT-PMP are
fixed-layout binary protocols that fit the project's no-XML / no-
discovery-protocol ethos.

## Crypto: Noise_IK

The chain control channel uses **Noise_IK_25519_ChaChaPoly_BLAKE2s** via
the `snow` crate. Same suite as WireGuard. Why this and not TLS:

* No certificates or PKI. Both ends pin a single 32-byte X25519 public key
  in their config. Same trust model as SSH `authorized_keys`.
* Noise_IK gives mutual authentication in one round-trip (two messages):
  the responder learns the initiator's static key in message 1.
* The transcript fits in a single UDP datagram on either side, so we don't
  need a fragmentation/reassembly story for the handshake.

After the handshake completes both sides hold a `snow::TransportState`
which we wrap as `Session` in [`crates/ratatoskr/src/auth.rs`](../crates/ratatoskr/src/auth.rs).
Every wire frame is `Session::encode_*` → a single AEAD-sealed UDP
datagram; every ack is decoded with the matching `Session::decode_*`.

Plaintext frame budget per datagram is
`ratatoskr::wire::MAX_CONTROL_PLAINTEXT_LEN` (17 KiB), which accommodates
the largest control body (currently the recursive `ChainSummary` reply
capped at 16 KiB by `chain_query::CHAIN_HOP_REPLY_MAX_WIRE_BYTES`) plus
envelope overhead. The total UDP packet size, including preamble,
counter, ciphertext, and AEAD tag, is `ratatoskr::wire::MAX_PACKET_LEN`.
Buffers on production receive paths (heartbeat server, chain client) are
sized to that constant.

### Replay protection

Each post-handshake packet carries an 8-byte big-endian counter in
cleartext, prefixed to the AEAD ciphertext. The receiver:

1. Reads the counter without touching crypto state.
2. **Rejects strictly-less-than-or-equal counters** before decryption.
3. If decryption succeeds, advances `last_seen_counter`.
4. If decryption fails, the counter is **not** advanced — so an attacker
   replaying a real packet plus a fake counter cannot ratchet us past
   genuine traffic.

Strict-monotonic replay (rather than a window) is fine here: UDP delivery
between the two endpoints is over a single path with one sender per
session, and the in-process retransmit layer (see "Reliability" below)
handles loss above the crypto layer.

## Identity & enrollment

Each node has one X25519 keypair, stored on disk as a 64-byte file (32
secret + 32 public) with mode 0600. Default path
`/etc/yggdrasil/identity.key`, overridable via `[server].identity_file`.
Auto-generated on first daemon start if missing. The pubkey is publishable;
the secret is wrapped in `zeroize::Zeroizing` so it's wiped on drop.

Tagged pubkey form `x25519:<hex>` is used everywhere on the operator surface
and on the wire's TOML/JSON projections. Bare hex is rejected. The
`postcard`-encoded wire form uses an enum-with-discriminator so future
algorithms (`ed25519:…`, `pq:…`) can be added without breaking parsing.

`fingerprint = BLAKE2s-128(pubkey)` rendered as 32 hex chars (no `x25519:`
tag). Used for downstream TOFU approval and out-of-band confirmation.

### Request / grant handshake

Enrolment is a two-file out-of-band ceremony driven by the `identity`
scope of `yggdrasilctl`:

1. **Downstream emits a request.** On the would-be downstream:
   `yggdrasilctl identity export-request --out request.txt`
   writes the local pubkey + fingerprint + optional operator note.

2. **Upstream issues a grant.** On the would-be upstream:
   `yggdrasilctl identity add-accept --from request.txt
   --my-endpoint vps.example.net:51820 --out grant.txt`
   writes `[accept]` into the upstream's config (pinning the
   downstream's pubkey) and emits an grant file containing both pubkeys
   plus the upstream's reachable endpoint.

3. **Downstream applies the grant.** Back on the downstream:
   `yggdrasilctl identity add-dial --from grant.txt`
   verifies that the grant's `dial_pubkey` matches the local
   identity (catches "wrong grant file" mistakes) and writes
   `[dial]` into the downstream's config (pinning the upstream's
   pubkey + endpoint).

The request and grant files are not secrets. Both contain only public
material; leaking them lets an attacker learn pubkeys and the upstream
endpoint, neither of which lets them impersonate either side. The
out-of-band fingerprint check after applying the grant is the security
boundary; if you skip it, you trust whoever transported the files.

### TOFU fallback

If a downstream attempts a handshake whose pubkey isn't pinned in
`[accept]`, the upstream stages it in the **pending peer
store** and refuses traffic. The operator inspects candidates with
`yggdrasilctl local accept pending`, verifies the fingerprint
out-of-band, and approves with `yggdrasilctl local accept approve
<fingerprint>`. Approval writes `[accept].pubkey` into the
upstream's config.

TOFU staging never accepts data on its own — it only collects candidates
for human review.

## Heartbeats and the peer-IP source of truth

`PeerState` (`crates/yggdrasil/src/heartbeat/peer_state.rs`) owns:

* The pinned downstream static pubkey (live-swappable via
  `set_peer_static_key` so TOFU approval doesn't require a restart).
* An `AtomicU64` for `last_heartbeat_ms` since process start.
* A `tokio::sync::watch::Sender<Option<IpAddr>>` for the downstream's
  currently-observed IP.

When `HeartbeatServer` processes a valid heartbeat, it calls
`peer_state.record_heartbeat(src_addr)`. That call returns one of:

* `SameIp(ip)` — most common. The watch channel **does not fire** because
  we use `send_if_modified` which skips updates when the new value equals
  the old one.
* `FirstHeartbeat(ip)` — initial `None → Some(_)` transition. Watch fires.
* `IpChanged { old, new }` — the downstream rotated. Watch fires.

The data-plane code subscribes to the watch and reacts only when it fires.
**This is the structural guarantee behind the heartbeat invariance
principle** — same-IP heartbeats can't even reach the drain path, so they
can't possibly disturb in-flight UDP flows or TCP connections.

### Heartbeat invariance

The single most important property in this codebase:

> **Heartbeats with an unchanged downstream IP MUST NOT disturb the data
> plane.**

If you're holding a stateful UDP session — a Factorio game, a Source-engine
session, Mumble, WireGuard tunnelled through the proxy — and the relay
gets a heartbeat with the same IP it saw last time, **nothing changes on
the data plane**. No socket close, no flow rebind, no rekey of the proxy↔
upstream pair. The heartbeat just refreshes `last_heartbeat_ms` and
acks.

That invariance is tested by
[`heartbeat_invariance_udp.rs`](../crates/yggdrasil/tests/heartbeat_invariance_udp.rs)
and its TCP counterpart, which fire 100+ heartbeats from a fixed source
and assert the per-flow upstream socket is byte-identical before and
after.

## Data-plane: per-rule proxies

Every `[[rule]]` (in `conf.d/*.toml` on the terminal, or derived from the
predicate set on the relay) becomes one `ProxyHandle` owned by
`ProxySupervisor` (`src/proxy/supervisor.rs`). Variants:

### TCP (`proxy/tcp.rs`)

Each TCP rule runs N accept loops (defaulting to
`available_parallelism()`, configurable via `[server].workers`). With
`N > 1`, every worker binds its own `TcpListener` to `(ip, port)` with
`SO_REUSEADDR + SO_REUSEPORT`, and the kernel hash-distributes
incoming SYNs across the workers so a single rule scales accept
throughput linearly with cores. With `N = 1` the rule short-circuits
to a single plain bind (no SO_REUSEPORT machinery).

On each new accept:

1. Resolve the dial target. Relay mode: snapshot
   `peer_state.current_ip()` (drop the socket immediately if `None`),
   combine with `rule.target_port`. Terminal mode: read the rule's
   `target_addr` or DNS-resolved `target_host` directly.
2. Dial the target. Connection failures close the client without sending
   bytes (no leaked half-open).
3. Optionally write a PROXY-protocol v1/v2 header so the upstream service
   sees the real client IP. TCP-only; rejected on terminal-mode rules.
4. `copy_bidirectional` between the two halves until either closes.

`TCP_NODELAY` is on by default; game protocols (low-RTT pings) noticeably
benefit and bulk-byte workloads are unaffected.

### UDP (`proxy/udp.rs`)

The interesting one — UDP has no inherent connection, so we build one.

* Each UDP rule runs N workers (defaulting to `available_parallelism()`,
  configurable via the same daemon-wide `[server].workers` knob that
  controls TCP accept fan-out — there's no per-rule override because
  fan-out is a kernel-level concern and a per-rule knob would buy
  nothing a global default doesn't already provide).
  For multi-worker fan-out, each worker binds its own `UdpSocket` to
  `(ip, port)` with `SO_REUSEADDR + SO_REUSEPORT`; the kernel hashes inbound
  4-tuples consistently across the workers so a given client always lands on
  the same worker. The flow table is sharded per-worker, so each worker reads
  + writes its own `DashMap` shard without cross-worker contention. On
  platforms without `SO_REUSEPORT` fan-out, the proxy runs one worker.
* Each `FlowEntry` owns a freshly-bound ephemeral UDP socket connected to the
  resolved upstream, the originating worker's frontend socket, plus an
  `AbortHandle` for the `upstream_to_client_loop` task.
* Inbound packets from a known client: update `last_seen_ms`, forward.
  Unknown client: resolve dial target (drop if `None` in relay mode),
  bind ephemeral socket, spawn the return-path task, insert atomically
  via the worker's `DashMap::entry`, forward.
* Return-path datagrams use the originating worker's frontend socket via
  `send_to(client)` — this preserves the client's NAT mapping (the source
  port the client first contacted is the source port the reply comes from).
* On Linux, each worker uses `libc::recvmmsg` to drain up to 32 datagrams per
  syscall (`proxy::udp::recvmmsg_linux`). On non-Linux, and when `recvmmsg`
  returns `ENOSYS` / `EPERM` at runtime, the worker falls back to
  per-datagram `recv_from`.
* A reaper task wakes periodically and evicts flows older than the rule's
  `idle_timeout` (default 60s, configurable per rule).
* A separate **`ipchange_loop`** task subscribes to `peer_state.watch()`.
  When the channel fires (real IP change), it drains every worker shard and
  aborts each upstream task. Subsequent client packets bind fresh sockets
  pointed at the new IP. (Relay only; terminal-mode rules dial fixed
  addresses and have no `ipchange_loop`.)

The structural reason same-IP heartbeats are cheap is that the watch
channel never fires for them — `ipchange_loop` is parked, the reaper is
unaffected, and the frontend worker recv loops never even read `peer_state`
for known clients (they just hit the worker's local `DashMap` shard).

### HTTPS (`proxy/http_frontend.rs`, `proxy/h3_frontend.rs`)

Terminal-side HTTPS rules are the L7 frontend: they resolve certificates,
terminate TLS for HTTP/1.1 and HTTP/2, terminate QUIC/TLS for HTTP/3 when
HTTP/3 is enabled, perform SNI / `Host:` virtual-host routing, and forward
requests as cleartext HTTP to per-route backend URLs. Certificate
resolution stays terminal-only.

#### HTTPS-predicate derivation

When predicates flow upward, each terminal HTTPS rule publishes an HTTPS
predicate with a `https_http3` flag. The relay derives a `(Tcp, port)`
listener for every HTTPS predicate. When `https_http3 = true`, it also
derives a `(Udp, port)` listener with `idle_timeout = 30s`. TCP carries
TLS-wrapped HTTP/1.1 and HTTP/2; UDP carries QUIC datagrams for HTTP/3.
The relay is L4 passthrough on both transports: it does not resolve
certificates or inspect TLS / QUIC payloads.

For multi-hop chain traffic, `X-Forwarded-For` headers injected by the
terminal's HTTPS frontend show the immediate upstream relay's IP, not the
real client's IP. The relay-side PROXY-protocol mechanism that addresses
this for plain TCP HTTPS rules does not yet have an equivalent for UDP /
QUIC traffic (PROXY v2 over UDP datagrams). This is a documented
limitation, not a regression — the same behavior applies to TCP HTTPS rules
today when `proxy_protocol` is not set. See
[configuration.md → HTTPS rules](configuration.md#https-rules).

#### HTTP/3 (QUIC)

Each HTTPS rule with `http3 != Some(false)` auto-opens a QUIC endpoint on
UDP `(rule.listen.ip(), rule.listen.port())` alongside the TCP TLS
listener. The QUIC path uses `quinn` 0.11 + `h3` 0.0.8 + `h3-quinn` over
the same `rustls 0.23` server config built by
`build_rustls_server_config` (ALPN `h3` vs `["h2", "http/1.1"]` for TCP)
— cert resolution propagates automatically across both transports because
both hold an `Arc<dyn ResolvesServerCert>` pointing at the same
`CertStore`.

Connection migration is on; 0-RTT is explicitly off (per-route opt-in
machinery isn't in this phase — replay-safety would require it). Idle
timeout is 30 s with 15 s keep-alive PINGs; concurrent bidi streams cap is
256 per connection.

Per-request handling mirrors the TCP path byte-for-byte: extract
`:authority`, look up the route, sanitise inbound headers, inject
`X-Forwarded-For/Proto/Host` + `X-Real-IP`, rewrite the URI authority to
the backend, dispatch via the shared `hyper-util` `LegacyClient`
(HTTP/1.1 cleartext to LAN). Request bodies are buffered up to 16 MiB
(`H3_REQUEST_BODY_LIMIT`); larger uploads get 413. Response bodies stream
back in 8 KiB chunks via `send_data`.

WebSocket-over-h3 (RFC 9220 extended CONNECT) is **not** supported — any
CONNECT receives 501 with `Sec-WebSocket-Version: 13` so the client falls
back to the HTTP/2 WS handshake on the TCP path.

The TCP HTTPS path injects `Alt-Svc: h3=":<port>"; ma=86400` on every
response so capable clients upgrade to HTTP/3 on the next request.
Disabled per-rule via `alt_svc = false`.

## Rules: hot reload (terminal-side)

On the terminal, `[server].rules_dir` is watched via `notify-debouncer-mini`
with a 250 ms debounce. The worker task:

1. On filesystem event → `RuleSet::from_dir(rules_dir)` → returns a fresh
   `RuleSet` (validated, cross-file uniqueness checked).
2. `previous.diff(&new) → RuleDiff { added, removed, changed, unchanged }`.
3. **Unchanged rules are strictly untouched.** The supervisor doesn't
   even look at them. Editing rule B never disturbs rule A's listener or
   its in-flight UDP flows. This is the branch-level analogue of
   heartbeat invariance.
4. Validation failures keep the previous `RuleSet` live. There is no
   "partial apply" mode — half-good reloads are worse than no reload.
5. The new `RuleSet` is fed to the **predicate publisher** (if
   `[dial]` is set), which projects it through
   `predicate_extractor::extract` and pushes the resulting `PredicateSet`
   to the upstream chain client on its next tick.

Force a re-scan with `yggdrasilctl local rules reload` (for filesystems
where inotify is unreliable — NFS, FUSE, some container bind mounts).

A pre-validated rule set can also be pushed directly without writing to
disk via `yggdrasilctl chain apply --file rules.toml`. The daemon
re-validates and feeds the result into the same supervisor pipeline. This
is mostly useful for tests and ephemeral configurations; persistent rules
should still live in `rules_dir`.

## Chain control plane

The chain plane is a Noise_IK-protected UDP control channel between
adjacent nodes. It carries five frame body types defined as
`ratatoskr::control_frame::ControlBodyType`:

| Code | Body                 | Direction               | Purpose                                                       |
| ---- | -------------------- | ----------------------- | ------------------------------------------------------------- |
| 0    | `Reserved`           | —                       | Wire reservation; never sent.                                  |
| 1    | `Noop`               | bi-directional          | Keep-alive / handshake test frame.                            |
| 2    | `PredicateSetUpdate` | downstream → upstream   | Terminal pushes a new `PredicateSet` to its upstream.         |
| 3    | `ChainHopQuery`      | downstream → upstream   | Recursive chain query (summary / health / derived-rules).     |
| 4    | `ChainHopReply`      | upstream   → downstream | One reply per query, with a slice of `ChainHop` records.      |

Each frame is acknowledged by the receiver. The reliability layer
(`crates/yggdrasil/src/chain/reliability.rs`) sits between the Noise
transport and the body-type dispatcher and provides:

* Per-session monotonic sequence numbers (frames are encoded with a
  body-side seq independent of the AEAD counter).
* In-flight retransmit with exponential backoff until the matching ack
  arrives.
* Receiver-side dedup using a small sliding window.

The retransmit + dedup machinery lets us treat the chain as a reliable
ordered byte-channel above the per-datagram Noise layer.

### Components

```
                            (terminal)                                       (relay)
    rules_dir watcher
            |
            v
    +-----------------+    PredicateSetUpdate frames    +-----------------+
    | predicate_      | ------------------------------> | acceptor        |
    | publisher       |                                 | (apply derived  |
    +-----------------+                                 |  RuleSet)       |
                                                        +-----------------+

    +-----------------+        ChainHopQuery            +-----------------+
    | control::       | ------------------------------> | chain/acceptor: |
    | dispatch_chain_ |                                 | handle_chain_   |
    | summary         | <------------------------------ | hop_query       |
    +-----------------+        ChainHopReply            +-----------------+
```

* **`acceptor`** — relay-side dispatcher. Receives `PredicateSetUpdate`,
  validates version monotonicity, runs `derive::derive` to project it
  back into a local `RuleSet`, hands the result to the proxy
  supervisor. Also handles `ChainHopQuery`: appends a local `ChainHop`
  record, optionally forwards the query one hop further upstream, and
  returns the aggregated `ChainHopReply` with `query_rtt_ms` stamped on
  the next-hop record.
* **`predicate_publisher`** — terminal-side task. Subscribes to the
  supervisor's `current_set` channel and emits `PredicateSetUpdate` on
  the next tick after a real change.
* **`client`** — chain-client state machine. Owns the Noise handshake,
  the heartbeat tick, and dispatch of inbound body types to the
  combined handler stack.

### Chain queries

`yggdrasilctl chain {summary,health,ping,diff}` all ride the same UDS
RPC (`Request::ChainSummary`) and the same upstream `ChainHopQuery`
frame; subcommands differ only in how they render the aggregated
`ChainHop` slice returned by the daemon. The recursive walk is bounded
end-to-end by the `--timeout` flag (default `5s`); each hop times its
own upstream call with `Instant::now()` and stamps the next hop's
`query_rtt_ms` on the offset-0 record before returning.

Derived rules — what each upstream hop actually accepted — are carried
inline in each `ChainHop` record, so `chain diff` no longer needs a
side-channel HTTP fetch.

### Chain canary

`yggdrasilctl chain canary --port N [--proto tcp|udp]` is a second
recursive query that piggybacks on the chain control plane to
install per-rule arm entries, then drives a real L4 probe through
the rule's listener.

The arm phase shape mirrors `ChainHopQuery`. Wire frames live in
[`ratatoskr::canary`](../crates/ratatoskr/src/canary.rs):

```text
CanaryArm   = { query_id, depth_budget, deadline_ms,
                rule_listen: SocketAddr, rule_protocol: Protocol,
                token: [u8; 32], expires_unix_ms }
CanaryReply = { query_id, hops: Vec<CanaryHop>, partial, error }
CanaryHop   = { hop_index, pubkey, name, mode,
                rule_present, echo_armed, query_rtt_ms }
```

Each hop receives the arm, records `rule_present` for the requested
`(listen, protocol)` against its own rule set, and — when this hop is
terminal-mode and owns a matching rule — installs an entry in its
local `CanaryArmTable` keyed by the 32-byte token. The receiver then
recurses upstream and assembles the response as `[local_hop,
upstream_hops…]`. Arm TTLs are clamped server-side (≤ 60s) so a
runaway token can't linger past the probe window.

The data phase runs over the rule's normal L4 path: the originator
connects (TCP) or sends datagrams (UDP) to the rule's own listener,
prefixed with the 32-byte token. The TCP / UDP listener code in
`proxy/tcp.rs` / `proxy/udp/mod.rs` consults the arm table on each
accept / datagram via an O(1) `is_armed(listen, protocol)` guard.
When at least one arm is live, the first 32 bytes are matched
against the table; matching traffic is echoed in-process and never
reaches the configured backend. The cold-path cost on listeners
when no canary is in flight is one shard probe per accept / datagram.

The originator collects per-direction throughput, loss, and latency
into `hdrhistogram` buckets and reports back via the
`ChainCanaryResponse` UDS response. Exit codes: `0=OK`,
`1=DEGRADED`, `2=NO_SUCH_RULE`, `3=CHAIN_DEAD`, `4=RPC_ERROR`.

## Control plane: yggdrasilctl over UDS

`/run/yggdrasil/control.sock` carries newline-delimited JSON. We chose
NDJSON specifically because it makes
`socat - UNIX-CONNECT:/run/yggdrasil/control.sock` and `jq` viable for
debugging — no length-prefixed framing.

Request/response definitions live in
[`crates/ratatoskr/src/control.rs`](../crates/ratatoskr/src/control.rs) so
both sides of the wire share the type surface verbatim.

Filesystem permissions are the access boundary. Run yggdrasil as a
dedicated user, drop the socket directory's group to your admin group,
and don't put untrusted users in that group.

## Process model

The daemon is single-process, multi-task tokio. There is no fork, no
privileged child, no helper subprocess. Capabilities-wise:

* yggdrasil needs `CAP_NET_BIND_SERVICE` if any derived rule listens on a
  port < 1024 (e.g. `0.0.0.0:443`). The systemd unit in
  [install.md](install.md#systemd-units) grants this and nothing else.
* Identity files are mode 0600 and owned by the daemon user. The
  in-process `StaticKeyPair` uses `zeroize::Zeroizing` so the secret is
  wiped on drop even if a panic unwinds the stack.

## Observability inventory

Logs: `tracing` JSON to stdout. Configure verbosity per `tracing-subscriber`
env-filter via `YGGDRASIL_LOG`.

Metrics: Prometheus text served over the control UDS via
`yggdrasilctl local metrics`. Full list in
[operations.md → Prometheus metrics](operations.md#prometheus-metrics).
Scraping over TCP requires fronting the UDS with a small adapter.

Admin: `yggdrasilctl local {status,rules,accept,metrics,health,derived-rules,trace}`
plus `yggdrasilctl chain {apply,summary,health,ping,diff}` and offline
`yggdrasilctl validate`. Reference in
[cli-reference.md](cli-reference.md).

## Build artefacts

| Crate           | Output                              | Linkage                |
| --------------- | ----------------------------------- | ---------------------- |
| `ratatoskr`     | (lib only)                          | shared types + crypto  |
| `yggdrasil`     | bin `yggdrasil` + lib               | depends on `ratatoskr` |
| `yggdrasilctl`  | bin `yggdrasilctl`                  | depends on `ratatoskr` |
| `bench-tools`   | bins `loadgen`, `bench-echo` (workspace-internal) | depends on nothing     |

There is no FFI, no dynamic link to OpenSSL, no C build dependency. The
`snow` crate uses pure-Rust X25519/ChaCha20-Poly1305/BLAKE2s
implementations.

## Where to look next

* Wire format: [`crates/ratatoskr/src/wire.rs`](../crates/ratatoskr/src/wire.rs).
* Authenticated session: [`crates/ratatoskr/src/auth.rs`](../crates/ratatoskr/src/auth.rs).
* Chain plane components: [`crates/yggdrasil/src/chain/`](../crates/yggdrasil/src/chain/).
* Heartbeat invariance test: [`crates/yggdrasil/tests/heartbeat_invariance_udp.rs`](../crates/yggdrasil/tests/heartbeat_invariance_udp.rs).
* UDP flow table: [`crates/yggdrasil/src/proxy/udp.rs`](../crates/yggdrasil/src/proxy/udp.rs).
* Multi-hop chain smoke: [`tests/e2e/run-chain.sh`](../tests/e2e/run-chain.sh).
* Control-plane request/response: [`crates/ratatoskr/src/control.rs`](../crates/ratatoskr/src/control.rs).
