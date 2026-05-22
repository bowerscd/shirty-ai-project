# Operations

Day-to-day runbook for a deployed yggdrasil chain. Pre-install reading
is [install.md](install.md); first-time configuration is
[quickstart.md](quickstart.md).

## Health checks

### Process state

```bash
sudo systemctl status yggdrasil
sudo journalctl -u yggdrasil -f
```

Logs default to JSON on stdout (overridable with `--log-format pretty`).
Pipe through `jq` for human-friendly inspection:

```bash
sudo journalctl -u yggdrasil --output=cat | jq -r 'select(.level=="warn" or .level=="error")'
```

### Liveness / readiness

The daemon does not expose an HTTP listener of its own; everything is
served over the control UDS at `[control].socket`. The CLI surfaces
three convenience commands on top of it:

| Command                              | Returns                                                              | Use case                                 |
| ------------------------------------ | -------------------------------------------------------------------- | ---------------------------------------- |
| `yggdrasilctl local health`          | Tiered verdict (`healthy` / `degraded` / `down` / `starting`). Exit code 0/1/2/3. | Container liveness/readiness probes.    |
| `yggdrasilctl local metrics`         | Prometheus text exposition, identical to the legacy `/metrics`.       | Scrape via a UDS→HTTP adapter sidecar.   |
| `yggdrasilctl local derived-rules`   | JSON snapshot of the current derived rule set + applied predicates.  | Used internally by `chain diff`; useful for ad-hoc inspection. |

Example systemd probe wired through the UDS:

```ini
[Service]
ExecStartPre=/usr/bin/yggdrasilctl local health --quiet
```

Operators who need TCP-reachable Prometheus front the UDS with a small
adapter (`socat TCP-LISTEN:9090,fork EXEC:'yggdrasilctl local metrics'`,
or a dedicated sidecar). There is no in-daemon HTTP listener to attack.

### Daemon-local quick checks

```bash
sudo yggdrasilctl local status
sudo yggdrasilctl local rules list
```

On the relay, `status` reports the downstream's currently-observed IP,
how long ago the last accepted heartbeat arrived, the rule count, and
the uptime. On a terminal it just shows the heartbeat sent-side stats,
because terminals don't accept inbound chain traffic.

## Metrics inventory

Every metric exposed by `yggdrasilctl local metrics`. Useful columns:
type, labels, meaning.

### Daemon-wide

| Metric                                            | Type    | Labels                          | Notes                                                                  |
| ------------------------------------------------- | ------- | ------------------------------- | ---------------------------------------------------------------------- |
| `yggdrasil_build_info`                            | gauge   | `version`                       | Constant `1`. Used to join other metrics with the deployed build.       |
| `yggdrasil_mode`                                  | gauge   | `mode` (`relay`/`terminal`)     | Constant `1`. Lets dashboards branch on mode.                          |
| `yggdrasil_rules_loaded`                          | gauge   | (none)                          | Number of rules currently in the live rule set.                         |
| `yggdrasil_https_routes`                          | gauge   | (none)                          | Number of `[[rule.route]]` entries currently loaded.                    |

### Chain heartbeat & enrollment

| Metric                                            | Type    | Labels                              | Notes                                                                       |
| ------------------------------------------------- | ------- | ----------------------------------- | --------------------------------------------------------------------------- |
| `yggdrasil_handshakes_completed_total`            | counter | (none)                              | Noise_IK responder-side handshake completions.                              |
| `yggdrasil_heartbeats_received_total`             | counter | `result` (`accepted`/`rejected`)    | Inbound heartbeats classified by replay/auth verdict.                       |
| `yggdrasil_last_heartbeat_timestamp_seconds`      | gauge   | (none)                              | UNIX timestamp of the last accepted heartbeat. Inactive heartbeats freeze this value. |
| `yggdrasil_peer_ip_changes_total`                 | counter | (none)                              | Number of times the relay's view of the downstream IP changed.              |

### Proxy

| Metric                                            | Type      | Labels                          | Notes                                                                 |
| ------------------------------------------------- | --------- | ------------------------------- | --------------------------------------------------------------------- |
| `yggdrasil_udp_workers`                           | gauge     | `rule`                          | Configured UDP frontend worker count for each rule.                    |
| `yggdrasil_udp_datagrams_received_total`          | counter   | `rule`, `worker`                | Frontend datagrams received by each zero-based UDP worker.             |
| `yggdrasil_udp_active_flows`                      | gauge     | `rule`, `worker`                | Active UDP flows currently held by each zero-based worker shard.       |
| `yggdrasil_udp_flows_drained_on_ip_change_total`  | counter   | `rule`, `worker`                | UDP flows torn down per worker because the downstream IP changed.      |
| `yggdrasil_udp_flows_rejected_total`              | counter   | `rule`, `worker`, `reason`      | UDP flows rejected before insertion (`cap`, etc.) per worker.         |
| `yggdrasil_https_tls_handshakes_total`            | counter   | `rule`, `result`                | TLS handshake outcomes for HTTPS rules.                                |
| `yggdrasil_https_cert_reload_total`               | counter   | `route`, `result`               | Per-route cert source reload outcomes.                                 |
| `yggdrasil_acme_renew_total`                      | counter   | `hostname`, `result`            | ACME issuance/renewal outcomes (`ok` / `err`).                         |
| `yggdrasil_acme_expiry_seconds`                   | gauge     | `hostname`                      | Unix-epoch `not_after` of each ACME-managed cert; useful for "renewal stuck" alerts. |
| `yggdrasil_http_requests_total`                   | counter   | `rule`, `route`, …              | Requests routed by the HTTPS frontend.                                |
| `yggdrasil_http_request_duration_seconds`         | histogram | `rule`, `route`                 | Per-route HTTPS request latency.                                       |

To roll up UDP counters across workers, use Prometheus
`sum by (rule) (yggdrasil_udp_datagrams_received_total)`.

### Suggested alerts

* `yggdrasil_handshakes_completed_total` should not be flat for more
  than `rekey_interval + 2 × heartbeat_interval` once a downstream is
  enrolled.
* `time() - yggdrasil_last_heartbeat_timestamp_seconds > 30` on a relay
  means the downstream is offline.
* `rate(yggdrasil_heartbeats_received_total{result="rejected"}[5m]) > 0`
  on a relay means inbound traffic is failing auth/replay checks —
  investigate the journal.
* `rate(yggdrasil_udp_flows_rejected_total[5m]) > 0` indicates capacity
  pressure or malformed inbound — investigate before it becomes user-visible.
* `yggdrasilctl chain health` returning a non-zero exit code (run from
  any hop) means at least one hop is `degraded` or `down`; pair with
  `chain ping` to localise the slow/unreachable hop.

## Common runbook tasks

### Approving a TOFU candidate

When a downstream contacts the relay but `[accept]` is unset,
the relay caches the candidate pubkey in `[server].state_dir` and waits
for an operator to bless it. Workflow:

```bash
sudo yggdrasilctl local accept pending
# fingerprint        first_seen          peer_endpoint
# 1234abcd...        2024-03-12T18:43Z   203.0.113.42:51820

sudo yggdrasilctl local accept approve 1234abcd5678efef...
# wrote [accept].pubkey = x25519:9d2f04a3...4b7c
```

After approve, restart the daemon for `[accept]` to take effect.
The same effect can also be produced offline via `yggdrasilctl identity
add-accept` against an request file — see [quickstart.md](quickstart.md).

### Hot-reloading rules

Drop a file into `/etc/yggdrasil/conf.d/` on the **terminal**. The
inotify watcher applies the new rule set within ~250 ms. Validation
failures keep the old rule set serving — check the journal for the
load error.

If inotify is misbehaving (NFS, container bind mounts on macOS via
docker-desktop, FUSE filesystems with cached metadata):

```bash
sudo yggdrasilctl local rules reload
```

The reload command blocks until the supervisor has swapped to the new
rule set and returns the post-swap rule count; a non-zero exit code
means the new set failed validation and the daemon kept the previous
one.

Under systemd, the unit is `Type=notify-reload` and wires
`ExecReload=/bin/kill -HUP $MAINPID`, so the canonical way to ask for
a reload is also:

```bash
sudo systemctl reload yggdrasil
```

SIGHUP forces the same rescan path. The daemon emits `RELOADING=1` +
`MONOTONIC_USEC` to systemd before the supervisor reconciles and
`READY=1` once the new set is live; `systemctl reload` only returns
after that second notification, so `is-active` reflects post-reload
state.

To push a rule file **without** writing it to disk (e.g. dry runs from
a deploy box), use `chain apply`:

```bash
sudo yggdrasilctl chain apply --file /tmp/candidate-rules.toml
```

Terminal mode only. The daemon re-validates server-side and rejects the
apply as a unit on any conflict.

### Inspecting chain drift

```bash
sudo yggdrasilctl chain diff
```

Each hop reports its predicate version + origin + derived-rule count.
"in sync" between hops means the terminal's published set matches what
the relay accepted. Drift surfaces as a `~` (changed), `+` (missing
upstream), or `-` (extra upstream) entry.

Exit code is `1` if drift is detected on at least one hop. There are
two **expected** patterns under v1 that *don't* count as drift:

1. A hop with `predicates=0` deep in the chain. Under v1, relays do not
   re-publish predicates onward; only the terminal's immediate upstream
   carries the pushed set.
2. An origin mismatch with the previous hop, which is also normal across
   chain boundaries where a relay aggregates multiple downstream terminals.

If a hop genuinely diverges (different version + same origin, or
content drift), investigate the publisher / acceptor metrics on that
hop.

### Key rotation

Identity keys are long-term. Rotate them when:

* You suspect compromise of `identity.key`.
* Hardware is being retired — generate a fresh identity on the new host
  rather than copying the old one.
* Policy requires periodic rotation.

The request/grant handshake from [quickstart.md](quickstart.md) is the
same ceremony you'll use to re-enroll across a rotation. The downstream
always emits the request; the upstream always emits the grant.

Workflow (upstream-side rotation — relay rotating its own key):

```bash
# On the relay (the upstream): interactive prompt asks you to type the
# current identity's short fingerprint (8 hex chars) before clobbering it.
# For scripted use, append `--yes-i-understand-this-breaks-existing-chains`.
sudo yggdrasilctl identity rotate --force
# pubkey:      x25519:NEW...
# fingerprint: NEW...

# The downstream emits a fresh request carrying its already-enrolled pubkey.
# (Or you can keep a cached copy of the original request file if you saved
# it — the downstream pubkey is unchanged across an upstream-side rotation.)
sudo yggdrasilctl identity export-request --out /tmp/downstream.request    # ON the downstream

# Back on the relay, re-run add-accept against the request. This rewrites
# [accept].pubkey (no-op if unchanged) and emits a fresh grant
# carrying the NEW relay pubkey + endpoint.
sudo yggdrasilctl identity add-accept \
    --from /tmp/downstream.request \
    --my-endpoint relay.example.net:51820 \
    --out /tmp/relay.grant

# Ship the grant to the downstream. There, apply it — it rewrites
# [dial].pubkey to the relay's new key.
sudo yggdrasilctl identity add-dial --from /tmp/relay.grant       # ON the downstream

# Restart both daemons.
sudo systemctl restart yggdrasil
```

Workflow (downstream-side rotation — terminal or mid-relay rotating its
own key):

```bash
# On the downstream:
sudo yggdrasilctl identity rotate --force
# (interactive fingerprint confirmation; pass
#  `--yes-i-understand-this-breaks-existing-chains` for scripted use)

# The downstream's pubkey changed, so its upstream needs to re-pin it.
sudo yggdrasilctl identity export-request --out /tmp/downstream.request

# Ship request to the upstream. There:
sudo yggdrasilctl identity remove-accept                            # ON the upstream
sudo yggdrasilctl identity add-accept \
    --from /tmp/downstream.request \
    --my-endpoint <upstream-public>:<chain-listener-port> \
    --out /tmp/upstream.grant

# Ship the fresh grant back. On the downstream:
sudo yggdrasilctl identity add-dial --from /tmp/upstream.grant

# Restart both daemons.
```

### Bringing up an additional chain hop

To insert a mid-chain relay between an existing terminal and its
upstream:

1. Provision the mid-relay (binary, identity, base config) per
  [install.md](install.md). Create a base `[server]` section but do not
  start the daemon yet; enrollment will write `[accept]` and `[dial]`.
2. On the terminal, `yggdrasilctl identity remove-dial`. Heartbeats
   to the old upstream stop.
3. Mid-relay ↔ old-upstream enrollment: run the request/grant ceremony
   so the mid-relay is the new downstream of the old upstream.
4. Terminal ↔ mid-relay enrollment: run the request/grant ceremony so
   the terminal is the new downstream of the mid-relay.
5. Restart all three daemons. `chain diff` should now report three hops.

The chain is essentially a linked list — each hop only knows about its
immediate upstream and immediate downstream.

## Troubleshooting

### Turning up verbose logging on a live daemon

The daemon's `tracing` env-filter is hot-swappable via the control UDS;
you don't need to restart it to chase a transient issue:

```bash
# Crank the proxy supervisor + chain client to debug for one investigation.
sudo yggdrasilctl local trace 'yggdrasil::proxy=debug,yggdrasil::chain=debug'
# When you're done, reset to the daemon's startup filter.
sudo yggdrasilctl local trace --reset
```

Filter syntax matches `tracing-subscriber::EnvFilter`. The reset path
restores whatever the daemon was originally launched with (typically
the value of `YGGDRASIL_LOG`).

### "chain client handshake failed"

The terminal can't complete Noise_IK against the configured upstream.

* Check `[dial].endpoint` resolves and reaches a yggdrasil chain
  listener. `nc -u <host> <port>` and watch the relay's journal for a
  rejected handshake.
* Check `[dial].pubkey` matches what
  `sudo yggdrasilctl identity show` reports on the relay. A mismatch
  here is silent except for handshake failures — Noise_IK pins the
  responder static key.
* Confirm the relay's `[accept].listen` actually bound — look for
  `chain listener started addr=...` in its journal.

### "downstream never enrolls"

The relay shows a pending candidate but no `accept` is wired.

* Run `yggdrasilctl local accept pending` to confirm the fingerprint.
* Cross-check with `yggdrasilctl identity show` on the downstream.
* If they match, `yggdrasilctl local accept approve <fingerprint>`,
  then restart the relay.

### "rules don't show up on the relay after I edit them on the terminal"

* Confirm the file landed under `[server].rules_dir`, not elsewhere.
  `yggdrasilctl local rules list` on the terminal should show the new
  rules within ~250 ms.
* Run `yggdrasilctl chain summary` to see each hop's rule + predicate
  counts in one shot. Mismatches between adjacent hops are usually
  predicate-push failures.
* Run `yggdrasilctl chain diff` to surface any drift between
  published and accepted predicate sets.
* If a hop is unreachable, `yggdrasilctl chain ping` will isolate which
  link is slow or down.

### "PROXY-protocol upstream sees the wrong client IP"

`proxy_protocol = "v1"` / `"v2"` is **TCP relay-mode only**. On a
terminal-mode rule (`target_addr` / `target_host`), the config
validator rejects `proxy_protocol`. On a UDP or HTTPS rule, same — the
validator rejects it.

### "chain diff says origin mismatch with previous hop"

Under v1, this is expected at chain boundaries — relays don't re-project
their downstream terminals' predicate sets upward, so each hop's
`predicate_origin` is the terminal it serves. Cross-boundary, the
origins legitimately differ. The `chain diff` output flags this as a
non-error.

## Backups

You only need to back up two files per host:

* `/etc/yggdrasil/identity.key` — the long-term key. Lose it and you'll
  have to re-run the request/grant ceremony with every neighbour.
* `/etc/yggdrasil/config.toml` — the daemon config (which embeds the
  enrolled chain neighbour pubkeys).

`/etc/yggdrasil/conf.d/*.toml` are also worth backing up but they're
typically tracked in version control as part of a deploy repo.

`/var/lib/yggdrasil/` contains only TOFU candidates and runtime markers —
safe to lose; the next handshake re-populates it.
