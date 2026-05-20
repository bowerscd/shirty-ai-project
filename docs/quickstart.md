# Quickstart

This walks you through provisioning yggdrasil end-to-end across two
hosts: a **relay** on a VPS with a public IP, and a **terminal** on a
home box behind a dynamic residential IP. By the end you'll have a TCP
rule forwarding port 2222 on the VPS to port 22 on the home box,
verified with `ssh`.

Prerequisites:

* A VPS with a public IP. We'll call this `vps.example.net`.
* A home box on a dynamic residential IP. It does not need a public IP,
  but it must be able to send outbound UDP to the VPS.
* Both hosts built and installed per [install.md](install.md).

You'll do most of this from your laptop with two `ssh` sessions open.

## 1. Generate identities

On the VPS (the **relay**):

```bash
sudo yggdrasilctl identity rotate
# wrote /etc/yggdrasil/identity.key
# pubkey:      x25519:6c5a30bb...0ff1
# fingerprint: ab12cd34ef56...
```

On the home box (the **terminal**):

```bash
sudo yggdrasilctl identity rotate
# wrote /etc/yggdrasil/identity.key
# pubkey:      x25519:9d2f04a3...4b7c
# fingerprint: 1234abcd5678...
```

Both pubkeys are public — copy them around freely. The secrets stay in
`/etc/yggdrasil/identity.key` (mode 0600) on each host.

## 2. Write the relay config (VPS)

```bash
sudo tee /etc/yggdrasil/config.toml >/dev/null <<'EOF'
[server]
mode = "relay"

[metrics]
listen = "127.0.0.1:9090"

[control]
socket = "/run/yggdrasil/control.sock"

[accept]
listen = "0.0.0.0:51820"
EOF
```

The chain listener is UDP only. Pick any port you like; the example uses
WireGuard's traditional `51820` because it's already well-known as
"VPN-ish UDP" to most firewalls. `[accept]` will be added by
the next step.

## 3. Write the terminal config (home)

```bash
sudo tee /etc/yggdrasil/config.toml >/dev/null <<'EOF'
[server]
mode = "terminal"

[metrics]
listen = "127.0.0.1:9090"

[control]
socket = "/run/yggdrasil/control.sock"
EOF
```

`[dial]` will be added by the next step. Terminal nodes don't
have `[accept]` or `[accept]` (the config validator
rejects either in `mode = "terminal"`).

## 4. Run the intro / invite handshake

The enrolment ceremony is two files exchanged out-of-band. The home box
emits an **intro** advertising its pubkey; the VPS replies with an
**invite** committing both pubkeys plus the VPS's reachable endpoint;
the home box applies the invite to populate `[dial]`.

On the home box:

```bash
sudo yggdrasilctl identity export-intro --out /tmp/home.intro
# wrote intro file
#   pubkey:      x25519:9d2f04a3...4b7c
#   fingerprint: 1234abcd5678...
```

Copy the intro to the VPS:

```bash
scp /tmp/home.intro vps.example.net:/tmp/
```

On the VPS:

```bash
sudo yggdrasilctl identity add-downstream \
    --from /tmp/home.intro \
    --my-endpoint vps.example.net:51820 \
    --out /tmp/home.invite
# updated /etc/yggdrasil/config.toml: [accept].pubkey
# wrote invite file
#   upstream_pubkey:   x25519:6c5a30bb...0ff1
#   downstream_pubkey: x25519:9d2f04a3...4b7c
#   endpoint:          vps.example.net:51820
```

Copy the invite back to the home box:

```bash
scp /tmp/home.invite home.example.lan:/tmp/
```

On the home box:

```bash
sudo yggdrasilctl identity add-upstream --from /tmp/home.invite
# verified invite targets this node (downstream_pubkey matches local identity)
# updated /etc/yggdrasil/config.toml: [dial]
#   pubkey:   x25519:6c5a30bb...0ff1
#   endpoint: vps.example.net:51820
```

Before continuing, sanity-check that the fingerprints match what
`yggdrasilctl identity show` reports on the opposite host. If they
don't match, somebody altered an intro or invite in transit — do not
start the daemons.

Wipe the transit files once enrolled; they're no longer needed:

```bash
sudo rm /tmp/home.intro /tmp/home.invite
```

## 5. Add a forwarding rule (terminal side)

Rules live in `[server].rules_dir` on the **terminal** node — the
terminal publishes them upstream as predicates, and the relay derives
matching listeners on its side.

```bash
sudo tee /etc/yggdrasil/conf.d/ssh.toml >/dev/null <<'EOF'
[[rule]]
name          = "ssh"
listen        = "0.0.0.0:2222"
protocol      = "tcp"
upstream_addr = "127.0.0.1:22"
EOF
```

Schema reference: [configuration.md → rules](configuration.md#rule-files).

The watcher debounces 250 ms before reloading, so you can drop several
files in quick succession and only one reload fires.

## 6. Start both daemons

```bash
# VPS (relay):
sudo systemctl start yggdrasil
sudo journalctl -u yggdrasil -f
# look for: chain listener started addr=0.0.0.0:51820
#           chain client handshake complete   (after the home daemon comes up)

# Home (terminal):
sudo systemctl start yggdrasil
sudo journalctl -u yggdrasil -f
# look for: chain client handshake complete
#           predicate publisher pushed set version=1
```

## 7. Verify

On the VPS:

```bash
sudo yggdrasilctl local status
# version:              0.1.0
# mode:                 relay
# downstream_ip:        203.0.113.42
# last_heartbeat:       423 ms ago
# rule_count:           1
# uptime:               62 s
# downstream_enrolled:  true

sudo yggdrasilctl local rules list
# name  proto  listen          upstream
# ssh   tcp    0.0.0.0:2222    dynamic:peer:22

sudo yggdrasilctl chain diff
# hop 0 (local x25519:9d2f04a3…): predicates=1 v=1 origin=x25519:9d2f04a3…
#   derived_rules: 1 active
# hop 1 (upstream x25519:6c5a30bb…): predicates=1 v=1 origin=x25519:9d2f04a3…
#   in sync with hop 0
#
# in sync across 2 hop(s).
```

`downstream_ip` is the home box's public IP as observed by the chain
listener — **not** anything you configured. That's the whole point: if
the home box's ISP rotates its DHCP lease, the next heartbeat updates
the mapping and traffic keeps flowing.

From any internet host:

```bash
ssh -p 2222 user@vps.example.net
```

The connection lands at `vps.example.net:2222`, gets proxied to
`203.0.113.42:22` (whatever the current home IP is), reaches the home
daemon, which forwards it to `127.0.0.1:22` on the home box, and you're
in.

## 8. Add more rules

Just drop more `*.toml` files into `/etc/yggdrasil/conf.d/` on the
**terminal**. No restart required. Example for a Minecraft server (UDP
for Bedrock, TCP for Java):

```bash
sudo tee /etc/yggdrasil/conf.d/minecraft.toml >/dev/null <<'EOF'
[[rule]]
name          = "minecraft-java"
listen        = "0.0.0.0:25565"
protocol      = "tcp"
upstream_addr = "127.0.0.1:25565"

[[rule]]
name          = "minecraft-bedrock"
listen        = "0.0.0.0:19132"
protocol      = "udp"
upstream_addr = "127.0.0.1:19132"
idle_timeout  = "120s"
EOF
```

Within ~250 ms the terminal re-validates, the predicate publisher emits
a fresh version, the relay derives the new listeners, and
`yggdrasilctl local rules list` on the VPS shows all three rules.

## What to read next

* [operations.md](operations.md) — day-to-day runbook (rotating keys,
  viewing metrics, `chain diff`, troubleshooting heartbeats).
* [configuration.md](configuration.md) — every config field reference.
* [security.md](security.md) — what the threat model does and doesn't
  cover before you put this on a real network.
