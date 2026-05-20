# yggdrasil

A residential reverse proxy with a chain control plane. One binary, two modes:

* **relay** — runs on a VPS with a stable public IP. Accepts inbound TCP and
  UDP from the internet, forwards each rule to whatever current address its
  downstream peer most recently authenticated from.
* **terminal** — runs on a home box behind a dynamic IP / CGNAT. Dials a
  relay upstream over UDP, sends authenticated heartbeats, publishes the
  local rule set as a predicate set the relay derives its own listeners from.

Both modes are the same `yggdrasil` binary; the difference is `[server].mode`
plus whether `[accept]` or `[dial]` is configured. A
deployment is a chain of one or more relays terminating in exactly one
terminal — `home -> midbox -> vps` works the same way `home -> vps` does.

It is **not** a tunnel. There is no overlay network, no kernel module, no
userspace TUN. The L4 data plane learns where to send traffic from
authenticated heartbeats; when the home box's residential IP changes, the
next heartbeat updates the mapping and traffic keeps flowing.

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
mode = "relay"

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
mode = "terminal"
EOF
```

### Enrol the terminal at the relay

The enrolment handshake is two files exchanged out-of-band: an **intro** file
the terminal emits (advertising its pubkey to the relay) and an **invite**
file the relay emits in reply (committing both pubkeys plus the relay's
reachable endpoint). The terminal applies the invite to populate
`[dial]`; the relay's `identity add-downstream` step has already
written `[accept]` locally.

```bash
# Terminal: export an intro file.
sudo yggdrasilctl identity export-intro --out /tmp/home.intro

# Relay: accept the intro, mint an invite.
sudo yggdrasilctl identity add-downstream \
    --from /tmp/home.intro \
    --my-endpoint vps.example.net:51820 \
    --out /tmp/home.invite

# Terminal: apply the invite (writes [dial]).
sudo yggdrasilctl identity add-upstream --from /tmp/home.invite
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
name          = "ssh"
listen        = "0.0.0.0:2222"
protocol      = "tcp"
upstream_addr = "127.0.0.1:22"
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
# mode:                 relay
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
* [docs/security.md](docs/security.md) — threat model, crypto, intro/invite
* [tests/e2e/run.sh](tests/e2e/run.sh) — 2-node podman-compose smoke
* [tests/e2e/run-chain.sh](tests/e2e/run-chain.sh) — 3-node chain smoke

## What's in the box

| Crate           | Output                              | Role                                                     |
| --------------- | ----------------------------------- | -------------------------------------------------------- |
| `yggdrasil`     | bin `yggdrasil` (daemon)            | The proxy / chain node. Same binary in relay or terminal. |
| `yggdrasilctl`  | bin `yggdrasilctl`                  | Admin CLI. Three scopes: `local`, `chain`, `identity`.    |
| `ratatoskr`     | (lib only)                          | Shared protocol types, wire format, Noise_IK auth.        |
| `loadgen`       | bin `loadgen` (workspace-internal)  | UDP/TCP load generator used by [bench/](bench/README.md). |

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

The control protocol, configuration formats, and CLI surface are stable
enough to deploy in low-stakes self-hosted setups.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at
your option.
