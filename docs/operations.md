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

### Liveness / readiness HTTP

The metrics listener serves three plain-HTTP endpoints alongside
`/metrics`:

| Path                       | Returns                                                      | Use case                              |
| -------------------------- | ------------------------------------------------------------ | ------------------------------------- |
| `/`                        | Plain-text landing with endpoint list.                       | Discovery from a browser.             |
| `/healthz`                 | `200 OK` if the daemon's main task hasn't aborted.           | Container liveness probe.             |
| `/readyz`                  | `200 OK` once the proxy supervisor + chain client have come up. | Container readiness probe.         |
| `/internal/derived-rules`  | JSON snapshot of the current derived rule set.               | Used by `yggdrasilctl chain diff`. Loopback-only. |

Example probe wired into systemd:

```ini
[Service]
ExecStartPre=/bin/sh -c 'curl -fsS http://127.0.0.1:9090/healthz >/dev/null'
```

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

Every metric exposed by `/metrics`. Useful columns: type, labels,
meaning.

### Daemon-wide

| Metric                                            | Type    | Labels                          | Notes                                                                  |
| ------------------------------------------------- | ------- | ------------------------------- | ---------------------------------------------------------------------- |
| `yggdrasil_build_info`                            | gauge   | `version`                       | Constant `1`. Used to join other metrics with the deployed build.       |
| `yggdrasil_mode`                                  | gauge   | `mode` (`relay`/`terminal`)     | Constant `1`. Lets dashboards branch on mode.                          |
| `yggdrasil_rules_loaded`                          | gauge   | (none)                          | Number of rules currently in the live rule set.                         |

### Chain heartbeat & enrollment

| Metric                                            | Type    | Labels             | Notes                                                                       |
| ------------------------------------------------- | ------- | ------------------ | --------------------------------------------------------------------------- |
| `yggdrasil_handshakes_completed_total`            | counter | `role`             | Noise_IK handshakes completed. `role` is `initiator` or `responder`.        |
| `yggdrasil_heartbeats_received_total`             | counter | (none)             | Inbound heartbeats accepted (replay-checked, replayed counters rejected).   |
| `yggdrasil_last_heartbeat_timestamp_seconds`      | gauge   | (none)             | UNIX timestamp of the last accepted heartbeat. Inactive heartbeats freeze this value. |
| `yggdrasil_peer_ip_changes_total`                 | counter | (none)             | Number of times the relay's view of the downstream IP changed.              |

### Chain control plane (predicates & tunnels)

| Metric                                            | Type    | Labels                                                              | Notes                                                       |
| ------------------------------------------------- | ------- | ------------------------------------------------------------------- | ----------------------------------------------------------- |
| `yggdrasil_chain_predicate_push_total`            | counter | `outcome` (`ok`, `reject`, `timeout`, `skip_dedup`, `skip_oversize`, `encode_error`, `persist_error`, `unknown_body`, `channel_closed`, `client_down`, `publisher_timeout`) | Terminal-side: predicate publisher attempts. |
| `yggdrasil_chain_predicate_recv_total`            | counter | `outcome`                                                           | Upstream-side: predicate accept-side outcomes.              |
| `yggdrasil_chain_predicate_set_size_bytes`        | gauge   | (none)                                                              | Size of the most recently encoded `PredicateSetUpdate`.     |
| `yggdrasil_chain_predicate_version`               | gauge   | (none)                                                              | Terminal-side: monotonically-increasing local set version.  |
| `yggdrasil_chain_predicate_accepted_version`      | gauge   | (none)                                                              | Upstream-side: version of the last accepted update.          |
| `yggdrasil_chain_tunnel_initiator_total`          | counter | `outcome`                                                           | `chain tunnel open` initiator-side outcomes.                 |
| `yggdrasil_chain_tunnel_forwarder_total`          | counter | `outcome`                                                           | Mid-hop forwarder outcomes.                                  |
| `yggdrasil_chain_tunnel_terminator_total`         | counter | `outcome`                                                           | Terminator-side outcomes (allow-list rejections live here). |

### Proxy

| Metric                                            | Type      | Labels                          | Notes                                                                 |
| ------------------------------------------------- | --------- | ------------------------------- | --------------------------------------------------------------------- |
| `yggdrasil_udp_flows_drained_on_ip_change_total`  | counter   | (none)                          | UDP flows torn down because the downstream IP changed under them.      |
| `yggdrasil_udp_flows_rejected_total`              | counter   | `reason`                        | UDP flows rejected before insertion (capacity, malformed, etc.).      |
| `yggdrasil_https_routes`                          | gauge     | (none)                          | Number of `[[rule.route]]` entries currently loaded.                    |
| `yggdrasil_https_tls_handshakes_total`            | counter   | `outcome`                       | TLS handshake outcomes for HTTPS rules.                                |
| `yggdrasil_https_cert_reload_total`               | counter   | `outcome`                       | Cert source rung reload outcomes (path / convention / default).        |

### Metrics HTTP

| Metric                                            | Type      | Labels                          | Notes                                                                 |
| ------------------------------------------------- | --------- | ------------------------------- | --------------------------------------------------------------------- |
| `yggdrasil_http_requests_total`                   | counter   | `endpoint`, `status`            | Requests against the metrics listener itself.                          |
| `yggdrasil_http_request_duration_seconds`         | histogram | `endpoint`                      | Per-endpoint latency histogram.                                        |

### Suggested alerts

* `yggdrasil_handshakes_completed_total{role="responder"}` should not be
  flat for more than `rekey_interval + 2 × heartbeat_interval` once a
  downstream is enrolled.
* `time() - yggdrasil_last_heartbeat_timestamp_seconds > 30` on a relay
  means the downstream is offline.
* `rate(yggdrasil_chain_predicate_push_total{outcome="ok"}[15m]) == 0`
  combined with `rate(...{outcome!="ok"}[15m]) > 0` means the publisher
  is failing — check tunnel reliability metrics next.
* `rate(yggdrasil_udp_flows_rejected_total[5m]) > 0` indicates capacity
  pressure or malformed inbound — investigate before it becomes user-visible.

## Common runbook tasks

### Approving a TOFU candidate

When a downstream contacts the relay but `[accept]` is unset,
the relay caches the candidate pubkey in `[server].state_dir` and waits
for an operator to bless it. Workflow:

```bash
sudo yggdrasilctl local downstream pending
# fingerprint        first_seen          peer_endpoint
# 1234abcd...        2024-03-12T18:43Z   203.0.113.42:51820

sudo yggdrasilctl local downstream approve 1234abcd5678efef...
# wrote [accept].pubkey = x25519:9d2f04a3...4b7c
```

After approve, restart the daemon for `[accept]` to take effect.
The same effect can also be produced offline via `yggdrasilctl identity
add-downstream` against an intro file — see [quickstart.md](quickstart.md).

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

The intro/invite handshake from [quickstart.md](quickstart.md) is the
same ceremony you'll use to re-enroll across a rotation. The downstream
always emits the intro; the upstream always emits the invite.

Workflow (upstream-side rotation — relay rotating its own key):

```bash
# On the relay (the upstream): interactive prompt asks you to type the
# current identity's short fingerprint (8 hex chars) before clobbering it.
# For scripted use, append `--yes-i-understand-this-breaks-existing-chains`.
sudo yggdrasilctl identity rotate --force
# pubkey:      x25519:NEW...
# fingerprint: NEW...

# The downstream emits a fresh intro carrying its already-enrolled pubkey.
# (Or you can keep a cached copy of the original intro file if you saved
# it — the downstream pubkey is unchanged across an upstream-side rotation.)
sudo yggdrasilctl identity export-intro --out /tmp/downstream.intro    # ON the downstream

# Back on the relay, re-run add-downstream against the intro. This rewrites
# [accept].pubkey (no-op if unchanged) and emits a fresh invite
# carrying the NEW relay pubkey + endpoint.
sudo yggdrasilctl identity add-downstream \
    --from /tmp/downstream.intro \
    --my-endpoint relay.example.net:51820 \
    --out /tmp/relay.invite

# Ship the invite to the downstream. There, apply it — it rewrites
# [dial].pubkey to the relay's new key.
sudo yggdrasilctl identity add-upstream --from /tmp/relay.invite       # ON the downstream

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
sudo yggdrasilctl identity export-intro --out /tmp/downstream.intro

# Ship intro to the upstream. There:
sudo yggdrasilctl identity remove-downstream                            # ON the upstream
sudo yggdrasilctl identity add-downstream \
    --from /tmp/downstream.intro \
    --my-endpoint <upstream-public>:<chain-listener-port> \
    --out /tmp/upstream.invite

# Ship the fresh invite back. On the downstream:
sudo yggdrasilctl identity add-upstream --from /tmp/upstream.invite

# Restart both daemons.
```

### Bringing up an additional chain hop

To insert a mid-chain relay between an existing terminal and its
upstream:

1. Provision the mid-relay (binary, identity, base config) per
  [install.md](install.md). Create a base `[server]` section but do not
  start the daemon yet; enrollment will write `[accept]` and `[dial]`.
2. On the terminal, `yggdrasilctl identity remove-upstream`. Heartbeats
   to the old upstream stop.
3. Mid-relay ↔ old-upstream enrollment: run the intro/invite ceremony
   so the mid-relay is the new downstream of the old upstream.
4. Terminal ↔ mid-relay enrollment: run the intro/invite ceremony so
   the terminal is the new downstream of the mid-relay.
5. Restart all three daemons. `chain diff` should now report three hops.

The chain is essentially a linked list — each hop only knows about its
immediate upstream and immediate downstream.

## Troubleshooting

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

* Run `yggdrasilctl local downstream pending` to confirm the fingerprint.
* Cross-check with `yggdrasilctl identity show` on the downstream.
* If they match, `yggdrasilctl local downstream approve <fingerprint>`,
  then restart the relay.

### "rules don't show up on the relay after I edit them on the terminal"

* Confirm the file landed under `[server].rules_dir`, not elsewhere.
  `yggdrasilctl local rules list` on the terminal should show the new
  rules within ~250 ms.
* Check the publisher push metric on the terminal — if the latest
  outcome is `skip_oversize`, your rule set is too big for a single
  `PredicateSetUpdate` (>16 KiB encoded). Split it across multiple
  files isn't enough — they're merged before publishing. Reduce rule
  count, shorten names, or drop unused rules.
* Run `yggdrasilctl chain diff` to surface any drift.

### "PROXY-protocol upstream sees the wrong client IP"

`proxy_protocol = "v1"` / `"v2"` is **TCP relay-mode only**. On a
terminal-mode rule (`upstream_addr` / `upstream_host`), the config
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
  have to re-run the intro/invite ceremony with every neighbour.
* `/etc/yggdrasil/config.toml` — the daemon config (which embeds the
  enrolled chain neighbour pubkeys).

`/etc/yggdrasil/conf.d/*.toml` are also worth backing up but they're
typically tracked in version control as part of a deploy repo.

`/var/lib/yggdrasil/` contains only TOFU candidates and runtime markers —
safe to lose; the next handshake re-populates it.
