# Install

This page covers building yggdrasil from source and laying it out on a real
host. The [quickstart](quickstart.md) page assumes you've done this and
walks through the first heartbeat-to-traffic loop.

## Supported targets

* Linux x86\_64 and aarch64 (musl or glibc).
* Rust toolchain pinned in `rust-toolchain.toml` (currently `1.95.0`,
  edition 2021, MSRV 1.85).
* A POSIX-compliant init system. systemd unit files are provided below;
  OpenRC and runit users will need to adapt them.

macOS and Windows are not supported. The proxy core probably builds, but
the chain transport uses Linux-specific UDP socket behaviour and the
rules watcher relies on `inotify`.

## Building from source

```bash
git clone <repo-url> yggdrasil
cd yggdrasil
cargo build --release --workspace
```

You'll get three release binaries under `target/release/`:

| Binary          | Belongs on            | Purpose                                                  |
| --------------- | --------------------- | -------------------------------------------------------- |
| `yggdrasil`     | every chain node      | The chain daemon. Same binary in relay or terminal mode.  |
| `yggdrasilctl`  | every chain node      | Admin CLI: `local`, `chain`, and `identity` scopes.       |
| `loadgen`       | (only on bench hosts) | UDP/TCP load generator used by [bench/](../bench/).      |

`loadgen` is build-time-only for the benchmark harness; you don't need
to install it on production hosts.

## Filesystem layout

The defaults are chosen so that `--config` and `--identity-file` arguments
are rarely needed in scripts. The daemon honours `--config /alt/path/config.toml`
if you want to deviate.

| Path                              | Owner / mode    | Purpose                                                          |
| --------------------------------- | --------------- | ---------------------------------------------------------------- |
| `/usr/local/bin/yggdrasil`        | root:root 0755  | Daemon binary.                                                   |
| `/usr/local/bin/yggdrasilctl`     | root:root 0755  | Admin CLI binary.                                                |
| `/etc/yggdrasil/config.toml`      | root:root 0644  | Daemon config ([configuration.md](configuration.md)).            |
| `/etc/yggdrasil/identity.key`     | root:root 0600  | Long-term X25519 identity (64 bytes). Never copy off the host.    |
| `/etc/yggdrasil/conf.d/*.toml`    | root:root 0644  | Rule files. Hot-reloaded. Terminal nodes only — relays derive rules from the chain. |
| `/etc/yggdrasil/certs/`           | root:root 0755  | HTTPS-only. Per-hostname certs the convention rung looks under. |
| `/var/lib/yggdrasil/`             | root:root 0755  | Per-host state (TOFU candidates, runtime markers).               |
| `/run/yggdrasil/control.sock`     | root:admin 0660 | Unix socket for `yggdrasilctl`. Restrict to admin group.         |

Create them once:

```bash
sudo install -m 0755 target/release/yggdrasil    /usr/local/bin/
sudo install -m 0755 target/release/yggdrasilctl /usr/local/bin/
sudo mkdir -p /etc/yggdrasil/conf.d /var/lib/yggdrasil /run/yggdrasil
sudo chmod 0755 /etc/yggdrasil /etc/yggdrasil/conf.d /var/lib/yggdrasil
```

The identity file at `/etc/yggdrasil/identity.key` is auto-generated on
first daemon start. If you'd rather pre-generate it (e.g. to copy the
pubkey into the upstream's grant ceremony before starting the
daemon), run `yggdrasilctl identity rotate`.

## Service files

### systemd — `yggdrasil.service`

The same unit works in relay and terminal modes. The mode is derived
from `/etc/yggdrasil/config.toml` shape (`[dial]` only => terminal,
`[accept]` present => relay).

```ini
# /etc/systemd/system/yggdrasil.service
[Unit]
Description=yggdrasil chain control / reverse proxy
After=network-online.target
Wants=network-online.target

[Service]
# `notify` (paired with sd_notify(READY=1) in yggdrasil) means `is-active`
# reports `active` only after the chain listener (if any), proxy
# supervisor, and control socket have all bound — not just after the
# process forked. Dependent units therefore order correctly.
Type=notify
NotifyAccess=main
ExecStart=/usr/local/bin/yggdrasil run
Restart=on-failure
RestartSec=2s

# Hardening — yggdrasil only needs CAP_NET_BIND_SERVICE if any derived
# rule listens on a port below 1024 (e.g. 0.0.0.0:443). If all your rule
# listens are >= 1024, drop both lines below entirely.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=/var/lib/yggdrasil /run/yggdrasil
ReadOnlyPaths=/etc/yggdrasil

# yggdrasil expects /run/yggdrasil to exist for the control socket.
RuntimeDirectory=yggdrasil
RuntimeDirectoryMode=0750
# Group=yggdrasil-admin

# Log handler — JSON to journald is the default.
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable + start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now yggdrasil
```

If you set `Group=yggdrasil-admin` (recommended), the control socket ends
up `root:yggdrasil-admin 0660` — add your operator login to that group
to run `yggdrasilctl` without sudo.

## Firewall

### Root relay (public-facing)

Inbound:

* UDP for `[accept].listen` from the open internet — downstreams
  can roam, so you can't tighten this to a single IP.
* TCP / UDP for every derived `listen` port from the chain.
* Nothing for the control socket — it's `AF_UNIX`, not a TCP port. The
  daemon does not bind an HTTP metrics listener; Prometheus is served
  over the same UDS via `yggdrasilctl local metrics`.

Outbound: yggdrasil needs to reach the downstream's current IP for each
derived rule's `target_port`. Most cloud firewalls allow all outbound
by default.

### Mid-chain relay

* Inbound UDP for `[accept].listen` from the immediate downstream
  only (you know its public IP — pin it).
* Outbound UDP to the next-hop upstream's `[accept].listen`.
* TCP / UDP for derived rules at this hop, if any.

### Terminal (home)

* Inbound: none. The terminal never accepts inbound chain traffic.
* Outbound UDP to the upstream's `[dial].endpoint` port.

If the home box is double-NATted / behind CGNAT, that's fine — the
terminal initiates the heartbeats, so it punches through. Just don't
block outbound UDP at your residential router.

## Upgrades

The control protocol uses `#[serde(tag = "kind")]`-tagged unions, so
binary compatibility within `0.x` is best-effort. Recommended upgrade
order, root-relay-first:

1. Upgrade the root relay's `yggdrasil` + `yggdrasilctl` together,
   `systemctl restart yggdrasil`. The downstream's heartbeats reconnect
   automatically when the new daemon's chain listener comes back up.
2. Walk down the chain one hop at a time, restarting each node in turn.
3. The terminal is restarted last.

Identity keys do **not** rotate on upgrade — they're long-term and
survive arbitrary daemon restarts. To rotate them deliberately, see
[operations.md → Key rotation](operations.md#key-rotation).
