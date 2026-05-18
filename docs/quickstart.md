# Quickstart

This walks you through provisioning yggdrasil end-to-end. By the end you'll
have a TCP rule forwarding a port on your VPS to a service on your home box,
verified with `ssh`.

Prerequisites:

- A VPS with a public IP. We'll call this `vps.example.net`.
- A home box on a dynamic residential IP. It does not need a public IP, but
  it must be able to send outbound UDP to the VPS.
- Both hosts built and installed per [install.md](install.md).

You'll do most of this from your laptop with two `ssh` sessions open.

## 1. Generate identities

On the VPS:

```bash
sudo yggdrasil keygen --identity-file /etc/yggdrasil/identity.key
# wrote /etc/yggdrasil/identity.key
# pubkey:      6c5a...0ff1
# fingerprint: ab12cd34ef56...
```

On the home box:

```bash
sudo ratatoskr keygen --identity-file /etc/ratatoskr/identity.key
# wrote /etc/ratatoskr/identity.key
# pubkey:      9d2f...4b7c
# fingerprint: 1234abcd5678...
```

Copy the **ratatoskr** pubkey (`9d2f...4b7c`) — you'll paste it into the next
step. The keys are X25519 public values; not secrets.

## 2. Write yggdrasil's config (VPS)

```bash
sudo tee /etc/yggdrasil/config.toml >/dev/null <<'EOF'
[server]
heartbeat_listen = "0.0.0.0:51820"
branches_dir     = "/etc/yggdrasil/branches"
state_dir        = "/var/lib/yggdrasil"
identity_file    = "/etc/yggdrasil/identity.key"

[metrics]
listen = "127.0.0.1:9090"

[control]
socket = "/run/yggdrasil/control.sock"

[peer]
# Filled in by `yggdrasil enroll-token` in the next step. Leave empty for now.
public_key_hex = ""
rekey_interval = "1h"
EOF
```

Heartbeats run over UDP only. Pick any port you like; the example uses
WireGuard's traditional 51820 because it's already well-known as "VPN-ish
UDP" to most firewalls.

## 3. Mint an enrollment token (VPS)

The enrollment token is a single file that carries (a) the VPS's pubkey, (b)
the heartbeat endpoint, and (c) a HMAC-signed claim that yggdrasil knows the
ratatoskr identity. It is not a secret — leak it and the worst that happens
is the recipient learns your VPS pubkey, which they could already learn by
running a single handshake against your VPS.

```bash
sudo yggdrasil enroll-token \
    --peer-pubkey 9d2f...4b7c \
    --endpoint vps.example.net:51820 \
    -o /tmp/ratatoskr.token
# wrote /tmp/ratatoskr.token
# yggdrasil_pubkey: 6c5a...0ff1
# peer_pubkey:      9d2f...4b7c
```

This **also** stamps `peer.public_key_hex = "9d2f...4b7c"` into
`/etc/yggdrasil/config.toml`. If you re-run it with a different `--peer-pubkey`
and want to overwrite an already-enrolled peer, add `--force`.

Copy the token to your home box:

```bash
scp /tmp/ratatoskr.token home.example.lan:/tmp/
```

## 4. Apply the token on the home box

```bash
# Write a minimal config first — `enroll` only fills in two fields.
sudo tee /etc/ratatoskr/config.toml >/dev/null <<'EOF'
[client]
yggdrasil_endpoint   = "placeholder:1"
yggdrasil_pubkey_hex = "0000000000000000000000000000000000000000000000000000000000000000"
identity_file        = "/etc/ratatoskr/identity.key"
heartbeat_interval   = "5s"
rekey_interval       = "1h"
EOF

sudo ratatoskr enroll /tmp/ratatoskr.token --config /etc/ratatoskr/config.toml
# updated /etc/ratatoskr/config.toml
#   client.yggdrasil_pubkey_hex = 6c5a...0ff1
#   client.yggdrasil_endpoint   = vps.example.net:51820
#   yggdrasil fingerprint       = ab12cd34ef56...
```

Sanity check that the fingerprint matches what `yggdrasil keygen` printed
back on the VPS. If they don't match, somebody altered the token in transit
— do not start the daemon.

Wipe the token file once enrolled; it's no longer needed.

```bash
sudo rm /tmp/ratatoskr.token
```

## 5. Add a forwarding rule (VPS)

Drop a branch file into `branches_dir`. Each `*.toml` file there can hold any
number of `[[rule]]` entries.

```bash
sudo tee /etc/yggdrasil/branches/ssh.toml >/dev/null <<'EOF'
[[rule]]
name          = "ssh"
listen        = "0.0.0.0:2222"
protocol      = "tcp"
upstream_port = 22
EOF
```

Schema reference: [configuration.md → branches](configuration.md#branch-files).

The watcher debounces 250ms before reloading, so you can drop several files
in quick succession and only one reload fires.

## 6. Start both daemons

```bash
# VPS
sudo systemctl start yggdrasil
sudo journalctl -u yggdrasil -f
# look for: branches loaded count=1
#           heartbeat listener started addr=0.0.0.0:51820

# Home
sudo systemctl start ratatoskr
sudo journalctl -u ratatoskr -f
# look for: handshake complete
#           heartbeat sent seq=1
```

## 7. Verify

On the VPS:

```bash
sudo yggdrasilctl status
# version:        0.1.0
# peer_ip:        203.0.113.42
# last_heartbeat: 423 ms ago
# branches:       1
# uptime:         62 s
# peer_enrolled:  true

sudo yggdrasilctl branches list
# name  proto  listen          upstream_port
# ssh   tcp    0.0.0.0:2222    22
```

`peer_ip` is the home box's public IP as observed by the heartbeat listener
— **not** anything you configured. That's the whole point: if the home box's
ISP rotates its DHCP lease, the next heartbeat updates the mapping and traffic
keeps flowing.

From any internet host:

```bash
ssh -p 2222 user@vps.example.net
```

The connection lands at `vps.example.net:2222`, gets proxied to
`203.0.113.42:22` (whatever the current home IP is), and you're in.

## 8. Add more rules

Just drop more `*.toml` files into `/etc/yggdrasil/branches/`. No restart
required. Example for a Minecraft server (UDP for Bedrock, TCP for Java):

```bash
sudo tee /etc/yggdrasil/branches/minecraft.toml >/dev/null <<'EOF'
[[rule]]
name          = "minecraft-java"
listen        = "0.0.0.0:25565"
protocol      = "tcp"
upstream_port = 25565

[[rule]]
name          = "minecraft-bedrock"
listen        = "0.0.0.0:19132"
protocol      = "udp"
upstream_port = 19132
idle_timeout  = "120s"
EOF
```

`yggdrasilctl branches list` will show all three rules within ~250ms.

## What to read next

- [operations.md](operations.md) — day-to-day runbook (rotating keys, viewing metrics, troubleshooting heartbeats).
- [configuration.md](configuration.md) — every config field reference.
- [security.md](security.md) — what the threat model does and doesn't cover before you put this on a real network.
