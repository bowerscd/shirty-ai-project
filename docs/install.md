# Install

This page covers building yggdrasil from source and laying it out on a real
host. The [quickstart](quickstart.md) page assumes you've done this and walks
through the first heartbeat-to-traffic loop.

## Supported targets

- Linux x86_64 and aarch64 (musl or glibc).
- Rust toolchain pinned in `rust-toolchain.toml` (currently `1.95.0`, edition 2021, MSRV 1.85).
- A POSIX-compliant init system. systemd unit files are provided below; OpenRC
  and runit users will need to adapt them.

macOS and Windows are not supported. The proxy core probably builds, but the
heartbeat path uses Linux-specific UDP socket behaviour and the watcher
relies on `inotify`.

## Building from source

```bash
git clone <repo-url> yggdrasil
cd yggdrasil
cargo build --release --workspace
```

You'll get four binaries under `target/release/`:

| Binary          | Belongs on       | Purpose                                                  |
| --------------- | ---------------- | -------------------------------------------------------- |
| `yggdrasil`     | VPS              | The reverse-proxy daemon.                                |
| `yggdrasilctl`  | VPS              | Admin CLI over Unix socket.                              |
| `ratatoskr`     | Home box         | Heartbeat client daemon.                                 |
| `loadgen`       | (only on bench hosts) | UDP/TCP load generator used by `bench/`.            |

You generally only need the first two on the VPS and `ratatoskr` on the home
box. `loadgen` is build-time-only for the benchmark harness.

## Filesystem layout

The defaults are chosen so that `--config` and `--identity-file` arguments are
rarely needed in scripts. All daemons honour `--config /alt/path/config.toml`
if you want to deviate.

**VPS (yggdrasil)**:

| Path                              | Owner / mode    | Purpose                                                          |
| --------------------------------- | --------------- | ---------------------------------------------------------------- |
| `/usr/local/bin/yggdrasil`        | root:root 0755  | Daemon binary.                                                   |
| `/usr/local/bin/yggdrasilctl`     | root:root 0755  | Admin CLI binary.                                                |
| `/etc/yggdrasil/config.toml`      | root:root 0644  | Daemon config (see [configuration.md](configuration.md)).        |
| `/etc/yggdrasil/identity.key`     | root:root 0600  | Long-term X25519 secret key. Never copy off the host.            |
| `/etc/yggdrasil/branches/*.toml`  | root:root 0644  | One file per logical group of rules. Hot-reloaded.               |
| `/var/lib/yggdrasil/`             | root:root 0755  | Per-host state (TOFU candidates, runtime markers).               |
| `/run/yggdrasil/control.sock`     | root:admin 0660 | Unix socket for `yggdrasilctl`. Restrict to admin group.         |

**Home box (ratatoskr)**:

| Path                              | Owner / mode    | Purpose                                                          |
| --------------------------------- | --------------- | ---------------------------------------------------------------- |
| `/usr/local/bin/ratatoskr`        | root:root 0755  | Daemon binary.                                                   |
| `/etc/ratatoskr/config.toml`      | root:root 0644  | Daemon config.                                                   |
| `/etc/ratatoskr/identity.key`     | root:root 0600  | Long-term X25519 secret key. Never copy off the host.            |

Create them once:

```bash
# VPS
sudo install -m 0755 target/release/yggdrasil    /usr/local/bin/
sudo install -m 0755 target/release/yggdrasilctl /usr/local/bin/
sudo mkdir -p /etc/yggdrasil/branches /var/lib/yggdrasil /run/yggdrasil
sudo chmod 0755 /etc/yggdrasil /etc/yggdrasil/branches /var/lib/yggdrasil

# Home
sudo install -m 0755 target/release/ratatoskr /usr/local/bin/
sudo mkdir -p /etc/ratatoskr
```

## Service files

### systemd — `yggdrasil.service`

```ini
# /etc/systemd/system/yggdrasil.service
[Unit]
Description=yggdrasil residential reverse proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/yggdrasil run
Restart=on-failure
RestartSec=2s

# Hardening — yggdrasil only needs to bind ports below 1024 if any rule does.
# If all your `listen` ports are >= 1024, drop CAP_NET_BIND_SERVICE entirely.
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
RuntimeDirectoryMode=0755

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

### systemd — `ratatoskr.service`

```ini
# /etc/systemd/system/ratatoskr.service
[Unit]
Description=ratatoskr heartbeat client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ratatoskr run
Restart=always
RestartSec=2s

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadOnlyPaths=/etc/ratatoskr

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Both services run as `root` by default in these unit files; you can drop them
to a dedicated user once you've worked out how to grant that user `CAP_NET_BIND_SERVICE`
(for yggdrasil's privileged-port listens) and ownership of the relevant
config and key files.

## Firewall

**VPS** needs inbound:

- UDP `:51820` (or whatever `server.heartbeat_listen` you chose) from the open
  internet — ratatoskr can roam, so you can't tighten this to a single IP.
- TCP/UDP for every `listen` port in `branches/*.toml`.
- Nothing for the control socket — it's `AF_UNIX`, not a TCP port.

**Home box** needs outbound to the VPS only:

- UDP `:51820` to `VPS_IP`.

If the home box is double-NATted / behind CGNAT, that's fine — ratatoskr
initiates the heartbeats, so it punches through. Just don't block outbound
UDP at your residential router.

## Upgrades

The control protocol uses `#[serde(tag = "kind")]`-tagged unions, so binary
compatibility within `0.x` is best-effort. The general upgrade order is:

1. Upgrade `yggdrasilctl` and `yggdrasil` on the VPS together.
2. Upgrade `ratatoskr` on the home box on its own schedule — the heartbeat
   wire format only changes in major versions and yggdrasil is always
   backwards-compatible with previous-minor ratatoskr.

Identity keys do **not** rotate on upgrade — they're long-term and survive
arbitrary upgrades. To rotate them deliberately, see [operations.md](operations.md#rotating-keys).
