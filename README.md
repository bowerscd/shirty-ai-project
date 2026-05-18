# yggdrasil

A residential reverse proxy. Run **yggdrasil** on a VPS with a stable public IP; run **ratatoskr** on your home server behind a dynamic IP and CGNAT. Inbound TCP and UDP from the internet are forwarded to your home box without you ever exposing it directly.

It is **not** a tunnel. There is no overlay network, no kernel module, no userspace TUN. Yggdrasil is a plain L4 reverse proxy that learns where to send traffic from authenticated heartbeats: ratatoskr signs a heartbeat with its long-term key, yggdrasil verifies it and remembers the source IP, and any rules pointing at that peer route to whatever IP the heartbeat came from. When your residential IP changes, the next heartbeat updates the mapping.

## Get up and running

These commands assume you have a VPS reachable from the public internet and a separate "home" machine where the upstream service runs.

```bash
# Build everything (one-time, on each host).
cargo build --release --workspace
```

**On the VPS** (where `yggdrasil` will run):

```bash
sudo install -m 0755 target/release/yggdrasil    /usr/local/bin/
sudo install -m 0755 target/release/yggdrasilctl /usr/local/bin/
sudo mkdir -p /etc/yggdrasil/branches /var/lib/yggdrasil /run/yggdrasil
sudo yggdrasil keygen --identity-file /etc/yggdrasil/identity.key

# Minimal /etc/yggdrasil/config.toml
sudo tee /etc/yggdrasil/config.toml >/dev/null <<'EOF'
[server]
heartbeat_listen = "0.0.0.0:51820"     # UDP, the only port ratatoskr talks to
branches_dir     = "/etc/yggdrasil/branches"

[control]
socket = "/run/yggdrasil/control.sock"
EOF
```

**On the home box** (where `ratatoskr` will run):

```bash
sudo install -m 0755 target/release/ratatoskr /usr/local/bin/
sudo mkdir -p /etc/ratatoskr
sudo ratatoskr keygen --identity-file /etc/ratatoskr/identity.key

# Seed a config so `ratatoskr enroll` has something to update.
sudo tee /etc/ratatoskr/config.toml >/dev/null <<'EOF'
[client]
yggdrasil_endpoint   = "placeholder:1"
yggdrasil_pubkey_hex = "0000000000000000000000000000000000000000000000000000000000000000"
identity_file        = "/etc/ratatoskr/identity.key"
EOF

# Copy the ratatoskr pubkey it printed and run, ON THE VPS:
#     yggdrasil enroll-token --peer-pubkey <hex> \
#         --endpoint <VPS_IP>:51820 -o ratatoskr.token
# Then scp ratatoskr.token back to the home box and:
sudo ratatoskr enroll /tmp/ratatoskr.token --config /etc/ratatoskr/config.toml
```

Add a forwarding rule on the VPS:

```bash
# /etc/yggdrasil/branches/ssh.toml — listens on :2222, forwards to home :22
sudo tee /etc/yggdrasil/branches/ssh.toml >/dev/null <<'EOF'
[[rule]]
name          = "ssh"
listen        = "0.0.0.0:2222"
protocol      = "tcp"
upstream_port = 22
EOF
```

Start both daemons (systemd unit files in [docs/install.md](docs/install.md), or just run in a screen for a smoke test):

```bash
# VPS:
sudo yggdrasil run

# Home:
sudo ratatoskr run
```

Verify it's working:

```bash
# VPS:
sudo yggdrasilctl status
# peer_ip:        203.0.113.42        (your home box's public IP)
# last_heartbeat: 1234 ms ago

# From any client on the internet:
ssh -p 2222 user@<VPS_IP>
```

That's the whole thing. Drop more `*.toml` files into `branches/` for more rules; they're picked up live.

## Documentation

- [docs/install.md](docs/install.md) — building, systemd units, file layout, upgrades
- [docs/quickstart.md](docs/quickstart.md) — the walkthrough above in more depth
- [docs/configuration.md](docs/configuration.md) — full schema reference for every config file
- [docs/cli-reference.md](docs/cli-reference.md) — every subcommand and flag for `yggdrasil`, `ratatoskr`, `yggdrasilctl`
- [docs/operations.md](docs/operations.md) — day-to-day runbook (peer rotation, hot reload, metrics, troubleshooting)
- [docs/architecture.md](docs/architecture.md) — why the design looks the way it does
- [docs/security.md](docs/security.md) — threat model, crypto, enrollment-token format
- [tests/e2e/run.sh](tests/e2e/run.sh) — full podman-compose stack exercising a real two-host topology (see [docker/compose.e2e.yml](docker/compose.e2e.yml))

## What's in the box

| Binary          | Where it runs   | What it does                                                                 |
| --------------- | --------------- | ---------------------------------------------------------------------------- |
| `yggdrasil`     | VPS             | Listens for heartbeats, runs the proxy listeners defined in `branches/*.toml`. |
| `ratatoskr`     | Home box        | Sends authenticated heartbeats to yggdrasil at a fixed interval.               |
| `yggdrasilctl`  | VPS (admin CLI) | Inspects status, manages peers, forces branch reloads. Talks to yggdrasil over a Unix socket. |

The `yggdrasil-proto` crate contains the shared wire formats and the `loadgen` crate is a benchmark tool used by [bench/](bench/README.md).

## Threat model in one paragraph

The VPS is untrusted with the home box's private contents but trusted with its IP address (the same trust property as DNS). Heartbeats are end-to-end encrypted under Noise_IK with mutual long-term key authentication, so a VPS operator cannot impersonate the home box, and a network attacker cannot redirect traffic to a different home box — but the VPS operator *can* observe and tamper with the proxied bytes (just like any reverse proxy operator). Run TLS or QUIC on top if you need confidentiality from the proxy itself. Full details in [docs/security.md](docs/security.md).

## Status

The protocol, configuration formats, and CLI surface are stable enough to deploy in low-stakes self-hosted setups. Phase 11 added end-to-end benchmarks against nginx as a comparison baseline; see [bench/README.md](bench/README.md).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
