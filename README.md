# yggdrasil

A residential reverse proxy with a chain control plane. One binary, three
modes (terminal at home, gateway at the public-facing root, mid-chain
relay between them):

* **terminal** — runs on a home box behind a dynamic IP / CGNAT. Dials a
  gateway (or mid-chain relay) upstream over UDP, sends authenticated
  heartbeats, publishes the local TCP, UDP, and HTTPS rule set as
  predicates the chain's gateway derives its own listeners from.
* **gateway** — runs on a VPS with a stable public IP. Accepts inbound
  TCP and UDP from the internet, forwards each rule to whatever current
  address its downstream peer most recently authenticated from. Only
  accepts inbound chain traffic, never dials upstream.
* **mid-chain relay** — both accepts an inbound chain session from a
  downstream and dials further upstream toward a gateway. Mode name in
  config: `relay`.

All three modes are the same `yggdrasil` binary; the difference is
section shape: `[dial]` only => terminal, `[accept]` only => gateway,
`[dial]` + `[accept]` => relay. A deployment is a chain of one or more
relay-side nodes terminating in exactly one terminal — `home -> midbox
-> vps` works the same way `home -> vps` does
(the 3-hop chain is exercised by
[`tests/e2e/run-chain.sh`](tests/e2e/run-chain.sh) end-to-end and by
[`chain_predicate_e2e`](crates/yggdrasil/tests/chain_predicate_e2e.rs)
at the unit-integration layer).

It is **not** a tunnel. There is no overlay network, no kernel module, no
userspace TUN. The L4 data plane learns where to send traffic from
authenticated heartbeats; when the home box's residential IP changes, the
next heartbeat updates the mapping and traffic keeps flowing (the
[`ip_change`](crates/yggdrasil/tests/ip_change.rs) +
[`heartbeat_invariance`](crates/yggdrasil/tests/heartbeat_invariance_udp.rs)
integration tests cover the drain-and-resume property).

```text
internet clients -- TCP/TLS or UDP/QUIC --> relay derived listeners
                                      Noise_IK chain --> terminal HTTPS frontend
                                                           (certs, SNI, Alt-Svc)
                                                        --> HTTP backends
```

HTTPS is first-class through the chain: a terminal HTTPS rule derives TCP
for TLS-wrapped HTTP/1.1 + HTTP/2 and, by default, UDP for HTTP/3 / QUIC.
Certificates and L7 routing stay on the terminal; relays passthrough both
transports.

## Get up and running

Two-host topology (relay on VPS, terminal at home). Walkthrough in
[docs/quickstart.md](docs/quickstart.md); the shape is:

```bash
# Build everything (one-time, on each host).
cargo build --release --workspace

# Install (on each host).
sudo install -m 0755 target/release/{yggdrasil,yggdrasilctl} /usr/local/bin/
sudo mkdir -p /etc/yggdrasil/conf.d /var/lib/yggdrasil /run/yggdrasil
```

### Relay side (VPS)

```bash
# Generate this node's long-term identity.
sudo yggdrasilctl identity rotate

# Minimal /etc/yggdrasil/config.toml — listener for inbound chain traffic.
sudo tee /etc/yggdrasil/config.toml >/dev/null <<'EOF'
[server]

[accept]
listen = "0.0.0.0:51820"
EOF
```

### Terminal side (home)

```bash
# Generate this node's long-term identity.
sudo yggdrasilctl identity rotate

# Minimal /etc/yggdrasil/config.toml — terminal mode, no listener.
sudo tee /etc/yggdrasil/config.toml >/dev/null <<'EOF'
[server]
EOF
```

### Enrol the terminal at the relay

The enrolment handshake is two files exchanged out-of-band: a **request** file
the terminal emits (advertising its pubkey to the relay) and a **grant**
file the relay emits in reply (committing both pubkeys plus the relay's
reachable endpoint). The terminal applies the grant to populate
`[dial]`; the relay's `identity add-accept` step has already
written `[accept]` locally.

```bash
# Terminal: export an request file.
sudo yggdrasilctl identity export-request --out /tmp/home.request

# Relay: accept the request, mint a grant.
sudo yggdrasilctl identity add-accept \
    --from /tmp/home.request \
    --my-endpoint vps.example.net:51820 \
    --out /tmp/home.grant

# Terminal: apply the grant (writes [dial]).
sudo yggdrasilctl identity add-dial --from /tmp/home.grant
```

Verify the printed fingerprints match what `identity show` reports on the
opposite host before continuing — that's the security boundary.

### Add a forwarding rule (terminal side)

Rules live in `conf.d/*.toml` on the **terminal** node. The terminal's
predicate publisher pushes them upstream; the relay derives matching
listeners on its end.

```bash
# /etc/yggdrasil/conf.d/ssh.toml — terminal rule pointing at the local sshd.
sudo tee /etc/yggdrasil/conf.d/ssh.toml >/dev/null <<'EOF'
[[rule]]
name     = "ssh"
listen   = "0.0.0.0:2222"
protocol = "tcp"
target   = "127.0.0.1:22"
EOF
```

Start both daemons (`yggdrasil run`, or via the systemd unit in
[docs/install.md](docs/install.md)). The relay derives a matching
`0.0.0.0:2222` TCP listener from the published predicate; the terminal
treats inbound chain TCP as connections destined for `127.0.0.1:22`.

### Verify

```bash
# Relay:
sudo yggdrasilctl local status
# mode:                 gateway
# downstream_ip:        203.0.113.42        (the home box's public IP)
# last_heartbeat:       423 ms ago
# rule_count:           1                   (derived from terminal's predicate)
# downstream_enrolled:  true

# Walk the chain and surface drift between published vs accepted predicates.
sudo yggdrasilctl chain diff

# From any host on the internet:
ssh -p 2222 user@vps.example.net
```

## Documentation

* [docs/install.md](docs/install.md) — building, filesystem layout, systemd
* [docs/quickstart.md](docs/quickstart.md) — the walkthrough above in depth
* [docs/configuration.md](docs/configuration.md) — every config field
* [docs/cli-reference.md](docs/cli-reference.md) — every subcommand of
  `yggdrasil` and `yggdrasilctl`
* [docs/operations.md](docs/operations.md) — runbook (key rotation, hot
  reload, metrics, `chain diff`, troubleshooting)
* [docs/architecture.md](docs/architecture.md) — why the design looks the
  way it does (chain plane, predicate projection, half-close)
* [docs/security.md](docs/security.md) — threat model, crypto, request/grant
* [tests/e2e/run-quickstart.sh](tests/e2e/run-quickstart.sh) — 2-node podman-compose smoke (`client → gateway → terminal → apps` on segmented networks; TCP / UDP / HTTPS + SNI dispatch + cert hot-reload)
* [tests/e2e/run-chain.sh](tests/e2e/run-chain.sh) — 3-node chain podman-compose smoke (`client → gateway → relay → terminal → apps`; same scenario coverage)

## What's in the box

| Crate           | Output                              | Role                                                     |
| --------------- | ----------------------------------- | -------------------------------------------------------- |
| `yggdrasil`     | bin `yggdrasil` (daemon)            | The proxy / chain node. Same binary; three modes (terminal, gateway, mid-chain relay) derived from `[dial]` / `[accept]` shape. |
| `yggdrasilctl`  | bin `yggdrasilctl`                  | Admin CLI. Four scopes: `local` (daemon-local over UDS), `chain` (cross-chain introspection), `identity` (offline identity + request/grant), and `validate` (offline config + rules check). |
| `ratatoskr`     | (lib only)                          | Shared protocol types, wire format, Noise_IK auth.        |
| `cli-defs`      | (lib only)                          | Shared clap-derive structs both binaries + their `build.rs` scripts consume to keep the auto-generated reference in [docs/cli-reference/](docs/cli-reference/) drift-free. |
| `bench-tools`   | bins `loadgen`, `bench-echo` (workspace-internal) | Helpers used by [bench/](bench/README.md): UDP/TCP load generator and a native echo backend. |

HTTPS rules include an L7 frontend for HTTP/1.1, HTTP/2, and HTTP/3 / QUIC,
with Alt-Svc advertising enabled by default (see
[`tests/http_frontend.rs`](crates/yggdrasil/tests/http_frontend.rs) and
[`tests/http3_frontend.rs`](crates/yggdrasil/tests/http3_frontend.rs)).
Certs can be sourced from disk, an in-memory ephemeral self-signed CA
(test fixtures), or ACME (RFC 8555) — issuance is DNS-01 wildcard only
today (via Cloudflare); `yggdrasilctl local acme {list,renew}` exposes
inspection and on-demand renewal. **The ACME pipeline is unit-tested
only**: there is no end-to-end test that issues a real cert from any
CA in tree.

There is no FFI, no dynamic link to OpenSSL, no C build dependency.

## Threat model in one paragraph

The relay is untrusted with the terminal's private contents but trusted with
its IP address (the same trust property as DNS). Chain traffic is end-to-end
encrypted under Noise_IK with mutual long-term key authentication, so a relay
operator cannot impersonate the terminal, and a network attacker cannot
redirect traffic to a different terminal — but the relay operator *can*
observe and tamper with the proxied bytes (just like any reverse proxy
operator). Run TLS or QUIC on top if you need confidentiality from the relay
itself. Full details in [docs/security.md](docs/security.md).

## Status

**Greenfield**: no deployed nodes, no release tags, no operators
running it in the field. The control protocol, configuration
formats, and CLI surface have stabilised enough for self-hosted
experimentation, but every claim about operational behaviour is
backed only by the in-tree test corpus, not by elapsed wall-clock
production uptime. Treat accordingly: fine for a homelab where you
own the downtime, not yet appropriate for anything you'd page
yourself for at 3am.

New contributors should start with
[docs/development.md](docs/development.md); contribution mechanics
live in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under the [MIT License](LICENSE).
