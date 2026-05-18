# Security

Read this before putting yggdrasil on a real network. It is honest about
what the threat model does and does not cover. If anything here doesn't
fit your situation, **don't deploy** until you've understood the gap.

## TL;DR threat model

| Question                                                                     | Answer                                                                        |
| ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Can a network attacker impersonate the home box to the VPS?                  | **No.** Mutual X25519 auth via Noise_IK. Pubkeys are pinned in config.        |
| Can a network attacker reroute traffic to their own upstream?                | **No.** The proxy only forwards to whichever IP the *authenticated* peer most recently heartbeated from. |
| Can a network attacker replay old heartbeats to confuse the proxy?           | **No.** Strict-monotonic AEAD counter; replays are rejected before decrypt.   |
| Can a network attacker eavesdrop the application payload?                    | **Yes**, if the application is plaintext. yggdrasil does not encrypt the proxied stream. |
| Can the VPS operator read or modify the application payload?                 | **Yes.** Same trust model as any reverse proxy. See "What yggdrasil does NOT protect" below. |
| Can a stranger on the VPS enumerate the home box's IP just by sending traffic? | **Yes**, partially. See "Traffic-analysis exposure".                        |
| Does compromise of the VPS host leak the home box's long-term key?           | **No.** The home box's secret never leaves the home box.                       |
| Does compromise of the home box leak the VPS's long-term key?                | **No.** Likewise.                                                              |

## What yggdrasil DOES protect against

### Network-attacker impersonation

Both sides authenticate via long-term X25519 keys (Noise_IK with
ChaCha20-Poly1305 and BLAKE2s). The VPS will only accept heartbeats whose
Noise transcript proves possession of the configured peer's secret key;
the home box will only complete a handshake against the server pubkey it
was enrolled with. There are no CAs, no PKI, no trust roots — just two
pinned 32-byte pubkeys.

### Reroute-by-spoofing the source IP

The proxy's idea of "where to forward" is updated **only** by
authenticated heartbeats. Sending UDP traffic to `heartbeat_listen` from
a forged source address gets you nothing — without the peer's secret
you can't complete a Noise handshake, and unauthenticated packets are
dropped before the IP is observed.

### Replay attacks

The post-handshake packet format prefixes each AEAD-sealed message with
an 8-byte cleartext monotonic counter. The receiver rejects any
`counter ≤ last_seen_counter` before doing any crypto. On a real
decryption failure the counter is **not** advanced, so an attacker
who knows the peer key can't ratchet `last_seen` forward by replaying
garbage.

The strict-monotonic check (rather than a sliding window) is correct
here because there's exactly one sender per session, one path, and the
control channel is low-volume.

### Long-term key compromise on one side

Each side holds its own X25519 secret and nothing else. Pwning the home
box gives an attacker the home pubkey + secret, but not the VPS's secret;
they can't impersonate the VPS to any future peer.

### Forward secrecy

Noise_IK derives a fresh ChaCha20-Poly1305 session key per handshake.
A static-key compromise discovered *later* does not retroactively
decrypt past heartbeat traffic (or its ACKs) recorded by a passive
adversary. The proxied application bytes are a different matter — see
below.

## What yggdrasil does NOT protect against

### Plaintext application traffic

**yggdrasil does not encrypt the proxied stream.** A TCP rule forwarding
port 25565 carries Minecraft's raw protocol, plaintext. A UDP rule
forwarding 19132 carries Bedrock's raw protocol, plaintext.

If you need confidentiality or integrity for the application stream:

- Run TLS on top (e.g. Minecraft proxies that speak TLS, or stunnel/sniproxy
  in front of the home service).
- Use a protocol that does its own crypto (SSH, WireGuard inside the
  tunnel, QUIC).
- Treat yggdrasil as a router, not a VPN — because it isn't one.

### A malicious VPS operator

If you don't control the VPS, the VPS root user can:

- Read every byte going through every TCP/UDP rule (it's plaintext at
  the proxy).
- Modify or drop the proxied stream silently.
- Steal the VPS's long-term identity key from
  `/etc/yggdrasil/identity.key` and pose as the VPS to any future
  huginn.
- Add new rules in `/etc/yggdrasil/conf.d/` to expose ports on
  your home box that you never approved.

This is the same trust model as **any** reverse proxy. yggdrasil does not
add MITM protection against the proxy itself — that's a different
product (e.g. a Tailscale-style overlay where the VPS is dumb routing).

If "the VPS operator must not be able to inspect my traffic" is a hard
requirement, **don't use a reverse proxy at all**. Use an end-to-end
encrypted protocol, or run the VPS yourself.

### Traffic-analysis exposure

Anyone who can reach `heartbeat_listen` on the VPS can observe **that**
heartbeats arrive (from where, how often), even if they can't decrypt
them. This leaks:

- The fact that the VPS has an active home-side peer.
- The source IP of the most recent heartbeat — i.e. **your home IP** —
  to anyone with `tcpdump` on a network the heartbeat traverses.

If your threat model includes hiding your home IP from someone who can
sniff the VPS-adjacent network, yggdrasil is not enough. Tunnel
heartbeats through Tor/WireGuard, or accept that the heartbeat source
address is observable.

Similarly, the *fact* that data-plane connections to e.g. `0.0.0.0:443`
on the VPS get proxied to a residential ISP block is observable to
anyone running `nmap` against the VPS — the existence of the proxy
isn't hidden.

### Compromised home box

If your home box is rooted, the attacker gets:

- The home identity secret (`/etc/huginn/identity.key`). They can now
  send valid heartbeats from any source IP to the configured VPS,
  redirecting your proxy at their attacker-controlled upstream.
- Any data your home services were holding.

There's no remote attestation. Trust in the home box is the same as
trust in any other Linux box you administer.

### Denial of service

yggdrasil has soft caps (`MAX_FLOWS_PER_RULE_DEFAULT = 65 536` per UDP
rule) but otherwise applies no rate limits. An attacker with the VPS
reachable can:

- Burn CPU on Noise handshake attempts (cheap to drop after the first
  message, but not free).
- Fill the UDP flow table for a rule with junk client addresses,
  causing legitimate flows to be rejected. Mitigate at the firewall.
- Saturate `heartbeat_listen`, blocking real heartbeats. Mitigate at
  the firewall.

If you expect to be a target, put a stateless rate limiter (`nftables`,
`tc`) in front of yggdrasil.

## Enrollment-token format

The enrollment token emitted by `yggdrasil enroll-token` contains:

```
postcard {
    yggdrasil_public: [u8; 32],   // VPS's X25519 pubkey
    peer_public:      [u8; 32],   // huginn's X25519 pubkey (passed in as --peer-pubkey)
    endpoint_hint:    String,     // host:port — where to send heartbeats
    issued_at:        i64,        // unix seconds, informational
}
```

Wrapped as `MAGIC("YGG1") ++ TOKEN_VERSION(1) ++ postcard_body`, then
base64-url-no-pad with a `YGG1-v1.` prefix.

It contains **no secrets**. Leaking the token reveals only the VPS
pubkey, the peer pubkey (which the recipient sent to you anyway), and
the heartbeat endpoint. None of that lets an attacker impersonate
either side — they'd still need one of the two X25519 secrets.

The token is **not** authenticated end-to-end; an active MITM on the
transfer channel could substitute a different token. The mitigation is
the fingerprint cross-check in step 4 of
[quickstart.md](quickstart.md#4-apply-the-token-on-the-home-box): after
running `huginn enroll`, verify the printed `yggdrasil fingerprint`
matches what the VPS operator told you via a second channel (phone,
in-person, signed email). If you skip that check, you're trusting
whoever can intercept your transfer mechanism.

## Key rotation policy

- **Session keys** rotate automatically on `rekey_interval` (default `1h`)
  via a fresh Noise handshake. Old session keys are zeroized as soon as
  the new `TransportState` is installed.
- **Long-term identity keys** are not rotated automatically. Swap them
  manually when you have reason to suspect compromise. See
  [operations.md → Long-term key swap](operations.md#long-term-key-swap).
- **Identity secrets** are held in `zeroize::Zeroizing` wrappers in
  memory, so panic unwinds and normal drops wipe them. The on-disk file
  is mode 0600 and owned by the daemon user; protecting that is the
  filesystem's job.

## What to put on the firewall

A sane VPS firewall for yggdrasil:

| Direction | Protocol | Port range          | Notes                                                 |
| --------- | -------- | ------------------- | ----------------------------------------------------- |
| inbound   | UDP      | `heartbeat_listen`  | Required.                                             |
| inbound   | TCP/UDP  | every `[[rule]] listen` | Required, per rule.                               |
| inbound   | TCP      | metrics port        | **Leave closed externally.** Bind to loopback.        |
| inbound   | TCP      | SSH (your admin)    | Up to you.                                            |
| outbound  | any      | any                 | yggdrasil needs to reach the home box's current IP on each rule's `upstream_port`. Most cloud firewalls allow all outbound by default. |

A sane home box firewall:

| Direction | Protocol | Port range            | Notes                                                                            |
| --------- | -------- | --------------------- | -------------------------------------------------------------------------------- |
| outbound  | UDP      | VPS `heartbeat_listen` | Required.                                                                       |
| inbound   | UDP+TCP  | each rule's `upstream_port` from the VPS's source IP | Required. Restrict to the VPS IP. |
| inbound   | any      | any other source       | Block.                                                                          |

The home box does not need any inbound port reachable from the public
internet — only from the VPS. Restrict accordingly.

## Reporting a vulnerability

This is a personal project; there is no security-disclosure inbox.
Open a GitHub issue with `SECURITY:` in the title for now. **Do not**
attach exploits or proof-of-concept code that would let bystanders
repeat the attack against running deployments — describe the
vulnerability in words first.
