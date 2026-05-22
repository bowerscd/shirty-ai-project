# Security model

This page is the threat model and the list of things yggdrasil
deliberately does and doesn't protect against. Read it before deploying
on a network where the answer to "what if this gets compromised?"
matters.

## Cryptographic primitives

| Primitive               | Construction                                       | Purpose                                           |
| ----------------------- | -------------------------------------------------- | ------------------------------------------------- |
| Long-term keypair       | X25519, 32 bytes each side                          | Node identity. Pinned at every chain hop.         |
| Handshake               | Noise_IK_25519_ChaChaPoly_BLAKE2s (`snow` crate)    | Authenticated key agreement per session.          |
| Symmetric AEAD          | ChaCha20-Poly1305 (16-byte tag)                     | Payload confidentiality + integrity.              |
| Strict-monotonic replay | 8-byte counter, rejected on `<= last_accepted`      | Replay prevention.                                |
| Fingerprint             | BLAKE2s-128 over pubkey, 32 hex chars               | Human-checkable identifier for request/grant.      |

The Noise pattern is **IK**: the initiator already knows the responder's
static public key. This is the right primitive for a chain where every
neighbour is enrolled out-of-band — no SNI, no PKI, no in-band
discovery.

A handshake takes one round-trip. There's no early-data carriage;
control frames only start flowing after the handshake completes.

## Wire packet shape

Every packet on the chain transport has the structure:

```
| 4-byte preamble | 8-byte counter | ciphertext (≤ 17 KiB) | 16-byte AEAD tag |
```

`MAX_PACKET_LEN = PREAMBLE_LEN + COUNTER_LEN + MAX_CONTROL_PLAINTEXT_LEN
+ AEAD_TAG_LEN`. The 17 KiB plaintext cap means a single tunnel-data
frame carries up to 16 KiB of payload after its body header. Anything
larger is fragmented across multiple frames.

`MAX_CONTROL_PLAINTEXT_LEN` was chosen so that a single MTU 1500
fragmented IP datagram chain still fits per-platform reassembly windows.
Don't grow it above 17 KiB without auditing every UDP path.

## Identity & enrollment

### TOFU at the responder

When a previously-unseen pubkey attempts a handshake, the relay's
acceptor caches the candidate in `[server].state_dir`, completes the
handshake (no traffic is forwarded yet), and waits for an operator to
explicitly approve via `yggdrasilctl local accept approve <fingerprint>`.
A persistent attacker who watches you boot a relay for the first time
*can* land in the pending-peer store. The boundary is the operator
running `approve` — never approve a fingerprint you haven't cross-checked
against the downstream node directly.

### Request / grant handshake

The recommended flow is **offline** rather than TOFU. Two files move
out-of-band:

* **request.txt** — emitted by the downstream node via `yggdrasilctl
  identity export-request`. Contents:
    * `dial_pubkey` (tagged `x25519:<hex>`)
    * `downstream_fingerprint` (32-hex BLAKE2s-128)
    * optional operator `note`
  Encoded as base64-url-no-pad with a magic prefix; not a secret.
* **grant.txt** — emitted by the upstream via `yggdrasilctl identity
  add-accept --from request.txt --my-endpoint host:port`. Contents:
    * `upstream_pubkey`
    * `upstream_fingerprint`
    * `dial_pubkey` (echoed from the request)
    * `endpoint` (the upstream's reachable `host:port`)
    * optional `note`

`yggdrasilctl identity add-dial --from grant.txt` verifies that
`dial_pubkey` in the grant matches the local identity (catches
"wrong grant file" mistakes) before writing `[dial]`.

This buys you **two** things over TOFU:

1. The pubkeys cross the air-gap before any network traffic flows, so
   a passive attacker cannot land in the pending-peer store.
2. The downstream's `add-dial` rejects a grant that targets a
   different node, preventing a misrouted grant from compromising a
   sibling terminal.

**It does not** authenticate the request / grant files cryptographically.
You are trusting the transport you use to hand-deliver them (Signal,
encrypted email, USB stick). The fingerprint check on each end is the
boundary; print and read the 32-hex fingerprint over a voice call if
you don't trust the transport.

## What's encrypted, what isn't

| Hop                                | State                                                                                              |
| ---------------------------------- | -------------------------------------------------------------------------------------------------- |
| Internet ↔ relay's public port      | Whatever the application protocol carries: cleartext TCP/UDP, or TLS/QUIC for HTTPS / HTTP/3.       |
| Relay ↔ next hop ↔ … ↔ terminal     | Encrypted under Noise_IK + ChaCha20-Poly1305. Strict-monotonic replay window.                       |
| Terminal ↔ application backend       | Cleartext from the terminal to `127.0.0.1` (or whatever `target_addr` / `target_host` resolves to). |
| `yggdrasilctl` ↔ daemon              | Unix domain socket, no encryption. Restrict via filesystem permissions.                              |

The chain plane gives you confidentiality and integrity **only between
chain neighbours**. From the open internet to the relay, traffic has only
whatever protection the application protocol provides. From the terminal
to the actual backend, it's cleartext on the loopback interface of the
terminal host. If you need encryption across the public internet and the
chain, run TLS or QUIC on top. Terminal HTTPS rules do this for the
client-to-terminal leg while keeping certificate resolution on the
terminal; the relay is L4 passthrough, but still sees metadata such as
addresses, ports, byte counts, and timing.

* **HTTP/3 attack surface.** The QUIC endpoint terminates TLS with the
  same rustls config (and certs) as the TCP HTTPS path. Specific
  properties:

  * 0-RTT (early data) is **disabled**. We do not opt rustls into TLS
    1.3 ticket-based resumption with early-data carriage. A future
    per-route opt-in could enable it for idempotent endpoints (e.g.
    static GET) but the default stays off.
  * Connection migration is **enabled** (quinn default). A client moving
    between source IPs continues its connection; the QUIC stack validates
    the new path via address-validation tokens before shifting traffic.
  * QUIC amplification mitigations are quinn's defaults: each new path
    receives 3× as many bytes as it has validated, capping the
    amplification factor at the spec-mandated bound.
  * Stateless retry / address-validation tokens are quinn defaults; we
    don't override them.
  * **Limitation:** for multi-hop chain traffic through a relay, the
    `X-Forwarded-For` header value will reflect the
    *immediate-upstream relay's* IP, not the real client's IP. The
    relay-to-terminal PROXY-protocol mechanism that addresses this for
    plain TCP HTTPS rules does not yet have an equivalent for UDP/QUIC
    traffic (PROXY v2 over UDP datagrams). Documented separately under
    [HTTPS-predicate derivation](architecture.md#https-predicate-derivation).
    Until a follow-up lands, h3 rules behind a relay should not be used
    by applications that rely on client-IP-based authorisation or
    rate-limiting.

## What yggdrasil protects against

* **Passive eavesdropping between chain hops.** The chain transport is
  fully encrypted with ChaCha20-Poly1305; the wire is opaque without
  the long-term keys.
* **Replay of captured traffic.** Strict-monotonic counters mean any
  re-transmitted packet is dropped at the receiver.
* **Off-path injection.** Without the long-term key, an attacker cannot
  forge a valid Noise_IK handshake, so they cannot inject frames into
  an established session.
* **Trivial impersonation.** Every neighbour is pinned by pubkey; a
  handshake from a wrong static key is rejected.
* **Pending-peer takeover.** Until an operator approves, a candidate's
  traffic is not forwarded — the boundary is your operator process.

## What yggdrasil does NOT protect against

* **Application-level eavesdropping at the relay.** A relay operator
  who controls the host trivially sees every byte of every connection,
  including credentials carried over cleartext protocols. Use TLS on
  top.
* **Traffic-analysis exposure.** Packet sizes, timing, and counts are
  observable to anyone on the wire between two chain hops. Frame
  lengths leak rough payload sizes. There's no padding or cover
  traffic.
* **A compromised terminal.** If the home box is rooted, every rule
  on it is forwarding traffic to whatever the attacker wants.
* **A malicious relay operator.** A hostile relay can corrupt /
  drop / inject application-layer traffic if it isn't end-to-end
  encrypted, can publish bogus derived rules under a captured chain
  position (subject to chain-diff visibility), and can dial any
  destination allowed by the v1 loopback-only tunnel destination policy.
* **Long-term-key compromise.** If `identity.key` leaks, the attacker
  can impersonate the node. Yggdrasil does not currently warn on
  out-of-band rotation by your peers; you'd notice only when the
  Noise handshake stops succeeding. Pin fingerprints in an out-of-band
  ledger and watch them.
* **Real client IP for multi-hop HTTP/3 traffic.** Covered above under
  HTTP/3 attack surface; until UDP/QUIC client-IP propagation lands, h3
  rules behind a relay should not be used by applications that rely on
  client-IP-based authorisation or rate-limiting.
* **Side channels.** ChaCha20-Poly1305 is hardware-friendly and
  constant-time on every platform we care about, but the surrounding
  Rust code is not audited for timing side channels.
* **Denial of service.** The chain listener is a UDP receiver with no
  rate limiting beyond what the OS gives you. A flood of bogus
  handshakes is cheap to send and somewhat-expensive to reject. Front
  the chain listener with conntrack-based UDP rate limits at the
  firewall if you care.

## Firewall guidance

### Root relay

* **Inbound UDP** on `[accept].listen` from the open internet.
  Downstream IPs can roam, so this can't be pinned. Apply UDP rate
  limits if you're exposed to broad-internet traffic.
* **Inbound TCP / UDP** on every derived rule's `listen` from whatever
  population is supposed to reach those services.
* **Outbound** to the downstream's current heartbeat-observed IP. Cloud
  firewalls typically allow all outbound; if yours doesn't, you'll need
  to whitelist the home ISP's allocation.
* **Nothing inbound** for the control socket (it's `AF_UNIX`).
  There is no separate metrics listener — metrics, health, and
  derived-rules snapshots are served over the same control socket
  via `yggdrasilctl local`.

### Mid-chain relay

* **Inbound UDP** on `[accept].listen` from the immediate
  downstream's known IP only. Pin it — your mid-relay is not exposed
  to the open internet.
* **Outbound UDP** to the next-hop upstream's `[accept].listen`.
* Same proxy-rule and control-socket rules as the
  root relay.

### Terminal (home)

* **No inbound** firewall openings required. The terminal never accepts
  inbound chain traffic.
* **Outbound UDP** to the upstream's `[dial].endpoint`. Don't
  block it at your residential router.

## Operational hardening

* Run yggdrasil under the systemd hardening flags in
  [install.md](install.md#systemd--yggdrasilservice). `NoNewPrivileges`,
  `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`,
  `PrivateDevices=true`, `ReadOnlyPaths=/etc/yggdrasil`. These are
  defence-in-depth, not the primary boundary.
* `AmbientCapabilities=CAP_NET_BIND_SERVICE` is only needed if any
  derived rule listens on a port below 1024. Drop it otherwise.
* Restrict the control socket to a dedicated admin group
  (`Group=yggdrasil-admin` + `RuntimeDirectoryMode=0750` in the unit
  file). Add operators to the group; revoke when they leave.
* Back up `/etc/yggdrasil/identity.key` to a place that's at least as
  secure as your password vault. Lose it and your chain neighbours
  will need to re-run the request/grant ceremony.
* Rotate identity keys at the cadence your policy demands — there's no
  technical requirement to do so on any particular schedule, but
  shorter rotation windows shrink the blast radius of a key compromise.

## Reporting issues

If you find a security issue, do not file a public bug. Email the
maintainer directly (see `Cargo.toml` `authors`) with a description
and ideally a minimal reproducer. A coordinated disclosure window
will be arranged.
