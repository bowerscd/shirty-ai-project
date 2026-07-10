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
sudo yggdrasilctl local derived-rules   # gateway / relay rule state
sudo yggdrasilctl local rules list      # terminal rule files only
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
| `yggdrasil_mode`                                  | gauge   | `mode` (`gateway`/`relay`/`terminal`) | Constant `1`. Lets dashboards branch on mode.                          |
| `yggdrasil_rules_loaded`                          | gauge   | (none)                          | Number of rules currently in the live rule set.                         |
| `yggdrasil_https_routes`                          | gauge   | (none)                          | Number of cert'd top-level `[[route]]` entries currently loaded.        |
| `yggdrasil_certless_routes`                       | gauge   | `rule`, `hostname`              | One per cert-less route. Constant `1` per live entry.                   |
| `yggdrasil_certless_requests_total`               | counter | `rule`, `hostname`              | Cert-less route requests served as plaintext on `:80`.                  |
| `yggdrasil_certless_requests_denied_total`        | counter | `rule`, `reason`                | Cert-less requests denied. `reason` is `peer_not_in_lan_cidrs` or `host_not_in_routes`. Operators alert on this — non-zero rate = external probing. |

### Chain heartbeat & enrollment

| Metric                                            | Type    | Labels                              | Notes                                                                       |
| ------------------------------------------------- | ------- | ----------------------------------- | --------------------------------------------------------------------------- |
| `yggdrasil_handshakes_completed_total`            | counter | (none)                              | Noise_IK responder-side handshake completions.                              |
| `yggdrasil_heartbeat_datagrams_received_total`    | counter | (none)                              | Every UDP datagram delivered to the heartbeat socket, counted before parse/auth. Flat while a peer is failing to (re-)enroll ⇒ datagrams are not reaching the socket (transport/routing); climbing ⇒ they arrive but are dropped pre-handshake (see the per-drop debug logs). |
| `yggdrasil_heartbeats_received_total`             | counter | `result` (`accepted`/`rejected`)    | Inbound heartbeats classified by replay/auth verdict.                       |
| `yggdrasil_last_heartbeat_timestamp_seconds`      | gauge   | (none)                              | UNIX timestamp of the last accepted heartbeat. Inactive heartbeats freeze this value. |
| `yggdrasil_peer_ip_changes_total`                 | counter | (none)                              | Number of times the relay's view of the downstream IP changed.              |

### Proxy

| Metric                                            | Type      | Labels                          | Notes                                                                 |
| ------------------------------------------------- | --------- | ------------------------------- | --------------------------------------------------------------------- |
| `yggdrasil_workers`                               | gauge     | `rule`, `protocol`              | Configured SO_REUSEPORT worker count for each rule's accept path (`protocol="tcp"` or `protocol="udp"`).               |
| `yggdrasil_tcp_accept_total`                      | counter   | `rule`, `worker`                | TCP accepts per zero-based worker. Divide by `yggdrasil_tcp_bytes_total` to get per-connection byte cost.              |
| `yggdrasil_tcp_accept_errors_total`               | counter   | `rule`, `worker`                | Transient TCP accept errors (EBADF, EMFILE, etc.) per worker.          |
| `yggdrasil_tcp_dropped_no_peer_total`             | counter   | `rule`                          | Relay-mode TCP connections dropped because no heartbeat had arrived yet (downstream IP unknown). |
| `yggdrasil_tcp_upstream_connect_seconds`          | histogram | `rule`, `result`                | Time spent in `TcpStream::connect()` to the resolved upstream, success/error broken out. The relay's IP-change path shows up as a wider distribution here than the terminal's static-resolver path. |
| `yggdrasil_tcp_upstream_connect_errors_total`     | counter   | `rule`                          | Upstream-connect failures (after `accept()` succeeded). Distinct from `accept_errors_total`, which is downstream-side. |
| `yggdrasil_tcp_bytes_total`                       | counter   | `rule`, `direction`             | Bytes forwarded per direction (`client_to_upstream`/`upstream_to_client`). Counted on connection close, so streaming-but-not-closed connections aren't visible until they finish. |
| `yggdrasil_udp_datagrams_received_total`          | counter   | `rule`, `worker`                | Frontend datagrams received by each zero-based UDP worker.             |
| `yggdrasil_udp_bytes_total`                       | counter   | `rule`, `worker`, `direction`   | Bytes forwarded per direction (`client_to_upstream` / `upstream_to_client`). Recorded per datagram, so streaming workloads update this in real-time (unlike the TCP counter). |
| `yggdrasil_udp_flows_admitted_total`              | counter   | `rule`, `worker`                | New UDP flows inserted into the flow table per worker. Divide by elapsed time for flow-establishment rate (the UDP analogue of `tcp_accept_total`). |
| `yggdrasil_udp_send_errors_total`                 | counter   | `rule`, `worker`, `direction`   | Per-direction `send`/`send_to` errors. Most often `ECONNREFUSED` from the upstream side (the kernel surfaces this even on connectionless UDP when ICMP unreachable comes back). |
| `yggdrasil_udp_dropped_no_peer_total`             | counter   | `rule`, `worker`                | Relay-mode datagrams dropped because no heartbeat had arrived yet (downstream IP unknown). |
| `yggdrasil_udp_upstream_bind_seconds`             | histogram | `rule`, `result`                | Time spent in the per-flow ephemeral upstream `UdpSocket::bind() + connect()` (success/error split). The first-datagram tail latency lives here. |
| `yggdrasil_udp_active_flows`                      | gauge     | `rule`, `worker`                | Active UDP flows currently held by each zero-based worker shard.       |
| `yggdrasil_udp_flows_drained_on_ip_change_total`  | counter   | `rule`, `worker`                | UDP flows torn down per worker because the downstream IP changed.      |
| `yggdrasil_udp_flows_rejected_total`              | counter   | `rule`, `worker`, `reason`      | UDP flows rejected before insertion (`cap`, etc.) per worker.         |
| `yggdrasil_https_tls_handshakes_total`            | counter   | `rule`, `result`                | TLS handshake outcomes on the node-wide HTTPS frontend. `rule` is the synthetic frontend name (`__https__`) since HTTPS is no longer per-rule after the L7 schema cleanup.                                |
| `yggdrasil_https_cert_reload_total`               | counter   | `route`, `result`               | Per-hostname cert reload outcomes (cert-watcher debounced disk writes plus ACME renewal pushes).                                 |
| `yggdrasil_acme_renew_total`                      | counter   | `hostname`, `result`            | ACME issuance/renewal outcomes (`ok` / `err`). The renewer issues a **single wildcard cert** per terminal — `hostname` is the apex domain from `[acme].domain`, and there's exactly one series per node. **Unit-tested only**: this counter has never been driven by a live-CA issuance in tree. |
| `yggdrasil_acme_expiry_seconds`                   | gauge     | `hostname`                      | Unix-epoch `not_after` of the wildcard cert; useful for "renewal stuck" alerts. |
| `yggdrasil_http_requests_total`                   | counter   | `rule`, `route`, …              | Requests routed by the HTTPS frontend. `rule` is the synthetic frontend name; `route` is the matched hostname.                                |
| `yggdrasil_http_request_duration_seconds`         | histogram | `rule`, `route`                 | Per-route HTTPS request latency.                                       |
| `yggdrasil_hot_section_seconds`                   | histogram | `subsystem`, `section`          | **Dev-only** (requires `--features profile`). Wall-clock duration of named hot-path sections — see [profile](#profiling) for usage. `subsystem` is `udp` / `tcp` / `http`; `section` is a stable identifier like `frontend_wait`, `handle_inbound`, `flow_lookup`, `upstream_send`, `sendmmsg_to_client`. Not emitted in production builds. |

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
* `yggdrasil_nat_state{state="backoff"} == 1` (sustained ≥ 5 min) on
  a daemon with `nat_traversal != "off"` means the gateway has gone
  unresponsive. Mappings expire naturally on the router; new rule
  pushes won't get forwarded. Inspect `local status` for `last_error`.
* `rate(yggdrasil_nat_epoch_resets_total[1h]) > 1` means the router
  is repeatedly losing its mapping table (likely buggy firmware or
  thermal reset loop). Each reset triggers a full mapping rebuild —
  benign in itself but indicates router instability.

## Common runbook tasks

### Approving a TOFU candidate

When a downstream contacts a relay or gateway before `[accept].pubkey` is
set, the daemon records the offered pubkey in an in-memory pending queue
and rejects the handshake. The queue is not durable; if the daemon
restarts during enrollment, the candidate is dropped and the legitimate
peer re-knocks. Workflow:

```bash
sudo yggdrasilctl local accept pending
# fingerprint                         attempts  first_seen
# x25519:1234abcd5678efef1234abcd...  1         1710268980000

sudo yggdrasilctl local accept approve 1234abcd5678efef...
# approved x25519:1234abcd5678efef1234abcd...
```

Approval writes `[accept].pubkey` to `config.toml` and updates the live
peer state, so the next heartbeat from that key is accepted without a
daemon restart. The same durable enrollment can also be produced offline
via `yggdrasilctl identity add-accept` against a request file — see
[quickstart.md](quickstart.md).

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

Terminal mode only. The CLI queries the daemon mode before reading the
candidate file and refuses gateway / relay targets before dispatch. The
daemon re-validates server-side and rejects the apply as a unit on any
conflict.

### Driving ACME issuance and renewal

> **Status.** The ACME pipeline — DNS-01 challenge via Cloudflare,
> wildcard cert issuance, atomic on-disk writeout, scheduled renewal —
> is implemented and unit-tested but has **never been driven against a
> live CA in tree** (`README.md → What's in the box`,
> [`docs/configuration.md → [acme]`](configuration.md#acme--optional-terminal-mode-only)).
> The procedure below is the operator-facing surface as the code
> implements it, not a verified deployment recipe. The first operator
> through this path is the first end-to-end test; treat the LE staging
> directory (`https://acme-staging-v02.api.letsencrypt.org/directory`)
> as a non-optional pre-prod step.

ACME is **terminal-only** — gateways and mid-chain relays pass TLS
through and never terminate. Enable it by:

1. Add `[acme]` + `[acme.dns.cloudflare]` to the terminal's
   `/etc/yggdrasil/config.toml`. See
   [configuration.md → `[acme]`](configuration.md#acme--optional-terminal-mode-only)
   for the full field list. Minimum:

   ```toml
   [acme]
   domain                  = "example.com"
   contact_email           = "ops@example.com"
   terms_of_service_agreed = true
   # directory_url defaults to Let's Encrypt production. Override to
   # staging while shaking out a deployment:
   # directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"

   [acme.dns.cloudflare]
   api_token_env = "CLOUDFLARE_API_TOKEN"
   ```

2. Mint a Cloudflare API token scoped to **`Zone.DNS:Edit`** on the
   one zone yggdrasil should touch (Cloudflare → My Profile → API
   Tokens → Create Token → "Edit zone DNS" template, narrowed to the
   apex zone). Broader scopes work but the daemon never needs them.
   The token string itself is the value of `CLOUDFLARE_API_TOKEN` in
   the daemon's environment.

3. Inject the token into the daemon's environment. The shipped
   systemd unit
   ([`contrib/systemd/yggdrasil.service`](../contrib/systemd/yggdrasil.service))
   does not declare an `EnvironmentFile=` — operators add one via
   `systemctl edit`:

   ```bash
   # Create a 0600 file owned by root for the secret itself.
   sudo install -m 0600 /dev/null /etc/yggdrasil/acme.env
   sudo tee /etc/yggdrasil/acme.env >/dev/null <<'EOF'
   CLOUDFLARE_API_TOKEN=cf-token-goes-here
   EOF

   # Wire it into the unit via a drop-in override (preserves package upgrades).
   sudo systemctl edit yggdrasil
   # ...the editor opens an empty override; add exactly:
   # [Service]
   # EnvironmentFile=/etc/yggdrasil/acme.env

   sudo systemctl restart yggdrasil
   ```

   The unit runs as the unprivileged `yggdrasil` user, so the
   `acme.env` file must be readable by that user — `chmod 0640` +
   `chgrp yggdrasil` works, or keep it `0600 root:root` and use
   `LoadCredential=` instead (see `systemd.exec(5)`).

4. Point `[server].default_cert` / `default_key` at the renewer's
   output so the cert watcher picks up renewals automatically.
   The renewer writes atomically to
   `{storage_dir}/{domain}/{fullchain,privkey}.pem`. `storage_dir`
   defaults to `[server].cert_dir` (default `/etc/yggdrasil/certs`).
   For the example above with default paths and
   `domain = "example.com"`, that's:

   ```toml
   [server]
   default_cert = "/etc/yggdrasil/certs/example.com/fullchain.pem"
   default_key  = "/etc/yggdrasil/certs/example.com/privkey.pem"
   ```

**When issuance fires.** At daemon startup the manager checks for an
existing PEM at the storage path. If present and `not_after` is
further out than `[acme].renew_before` (default `30d`), the renewer
schedules itself for `not_after - renew_before ± renew_jitter` and
otherwise stays idle. If absent or stale, it issues immediately.
Subsequent renewals run on that same schedule until daemon stop.
The wildcard cert covers SANs `[<domain>, *.<domain>]` — one cert
for the apex and every immediate subdomain.

**Inspecting status (terminal mode only):**

```bash
sudo yggdrasilctl local acme list
# hostname           provider     state       next_renewal           not_after              last_error
# example.com        cloudflare   active      2026-07-30T04:12:00Z   2026-08-29T04:12:00Z   -
```

States are the `HostStatus` snapshot
(`crates/yggdrasil/src/proxy/acme/mod.rs::HostStatus`):

* `pending` — first issuance hasn't completed yet (ephemeral cert
  or no cert serving meanwhile).
* `active` — PEM on disk, in active rotation.
* `error` — last issuance attempt failed; whatever cert was previously
  in place is still serving.

The `last_error` column is populated whenever the last issuance attempt
failed.

**Forcing an out-of-band renewal (terminal mode only):**

```bash
sudo yggdrasilctl local acme renew example.com
```

This kicks the renewer's bounded (16-deep) channel; the call blocks
until the ACME order completes (5–60 s typical for LE) and returns
the issuance result. The cert watcher then hot-reloads the new PEM
in place — no daemon restart, no HTTPS-frontend respawn for a cert
swap (`docs/configuration.md → Hot reload semantics`).

**Observability:** `yggdrasil_acme_renew_total{hostname,result}`
counts issuance outcomes; `yggdrasil_acme_expiry_seconds{hostname}`
exposes the live `not_after` for "stuck renewal" alerts. See
[Suggested alerts](#suggested-alerts) above.

### Inspecting chain drift

```bash
sudo yggdrasilctl chain diff
```

Each hop reports its predicate origin + derived-rule count. "in sync"
between hops means the terminal's published set matches what the relay
accepted. Drift surfaces as a `~` (changed), `+` (missing upstream), or
`-` (extra upstream) entry.

Exit code is `1` if drift is detected on at least one hop. In a healthy
steady-state chain every hop reports the same `origin` + predicate
content: mid-chain relays forward the original push bytes verbatim
upstream
(`crates/yggdrasil/src/chain/acceptor.rs::handle_predicate_set_update`),
so the gateway sees byte-identically what the terminal published.

Transient inconsistencies — a hop briefly behind the others, or one
reporting `predicates=0` — are normal while a fresh push is propagating
up the chain or right after a node restarts. If a hop stays empty after
the chain has settled, check that hop's chain-client status and the
`yggdrasil_chain_predicate_recv_total` /
`yggdrasil_chain_predicate_forward_total` counters: empty means either
its downstream hasn't pushed yet or its own outbound chain session is
down. Origin mismatch between adjacent hops should only appear
transiently while a terminal rotation propagates; persistent mismatch
means the chain is in an inconsistent state.

If a hop genuinely diverges (same origin but different predicate
content) after the chain has settled, investigate the publisher /
acceptor metrics on that hop.

### Debugging a rule end-to-end with `chain canary`

`yggdrasilctl chain canary --port N [--proto tcp|udp]` probes a rule's
L4 forwarding path through the chain end-to-end. The canary's
probe traffic is prefixed with a 32-byte random arming token; the
terminal hop short-circuits matching traffic to an in-process echo
instead of forwarding to the configured backend. That means the
canary works regardless of whether the rule's `target` is
reachable — it tests the *chain*, not the backend.

Pick the port you exposed in the rule, optionally narrow by `--proto`,
and run on any node in the chain:

```bash
sudo yggdrasilctl chain canary --port 2222 --proto tcp
```

Successful output:

```
rule:   ssh  (tcp, listen 0.0.0.0:2222)
chain:  home (self)

probe:  duration 3 s, TCP byte-stream

direction         throughput      loss   p50 latency  p99 latency
client → server      1.04 Mbps   0.00 %       180 µs       340 µs
server → client      1.04 Mbps   0.00 %       180 µs       340 µs

connection establish: 220 µs

result: OK
```

Exit codes (for shell / orchestration use):

| code | meaning                                                |
|------|--------------------------------------------------------|
| 0    | OK                                                     |
| 1    | DEGRADED (probe ran, loss or p99 over thresholds)      |
| 2    | NO_SUCH_RULE (port + proto don't bind anywhere here)   |
| 3    | CHAIN_DEAD (arm phase couldn't reach a hop)            |
| 4    | RPC error reaching the daemon                          |

The `NO_SUCH_RULE` output includes a "closest matches" list — same
port different proto, then different port same proto. That's usually
the fastest way to spot a typo'd `[[rule]] listen` or a missing
predicate publish.

For terminals with `[[route]]` blocks, the canary probes TCP and UDP on
`[server].https_listen` separately and emits both reports — same command,
no extra flags. UDP is only probed when `[server].https_http3 = true`.
Pass `--json` for a machine-parseable object covering all probes.

The canary **does not** test the rule's configured backend. That's a
separate concern; verify backend reachability from the terminal host
with `nc` / `curl` if needed.

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

### Forcing the chain client to reconnect immediately

When an operator has just brought the upstream back online (router
swap, ISP outage clearing, gateway maintenance window ending), the
local chain client takes up to ~30 s to notice on its own — UDP has no
disconnect signal, so the client waits for six consecutive heartbeats
to go unacked (`ACK_DEADLINE_MULTIPLIER × heartbeat_interval`) before
deciding the session is dead and re-handshaking.

`yggdrasilctl chain reconnect` short-circuits that wait:

```
$ yggdrasilctl chain reconnect
chain reconnect signal delivered; re-handshake will follow on the chain-client task
```

The command is fire-and-forget — it returns as soon as the signal
reaches the chain client's run loop, not once the new handshake has
completed. Observe completion via `chain summary` or `chain diff`
showing a non-`partial` chain again.

Available on any node with a `[dial]` configured (terminals and
mid-chain relays). Gateways have no chain client; the CLI mode-probe
refuses there client-side, and the daemon backstops with the
`no_chain_upstream` error code if the mode probe is somehow bypassed.

## Troubleshooting

### Profiling the hot path (dev-only)

For "where does CPU time actually go inside yggdrasil under workload X"
questions, the daemon supports an opt-in in-process CPU profiler.
**This is not enabled in production binaries** — it's behind the
`profile` Cargo feature so a release build without `--features
profile` has zero overhead from this path.

The fast workflow is the bench wrapper:

```bash
# Capture a 30-second flamegraph during the tcp-connrate scenario
# against yggdrasil-terminal. Output lands at
# bench/results/<sha>-profile/tcp-connrate.svg, openable in any browser.
bench/profile.sh tcp-connrate --duration 30s

# Same workflow but emit a pprof binary instead:
bench/profile.sh tcp-connrate --pprof
# Inspect with: go tool pprof bench/results/<sha>-profile/tcp-connrate.pb
```

The wrapper rebuilds the daemon with `--features profile` plus
`RUSTFLAGS="-C force-frame-pointers=yes"` for the run, then rebuilds
without the feature so subsequent bench runs use the unmodified
production binary.

Direct invocation (for ad-hoc profiling outside the bench harness):

```bash
cargo build --release -p yggdrasil --features profile
YGGDRASIL_PROFILE_OUTPUT=/tmp/yggd.svg \
YGGDRASIL_PROFILE_FREQUENCY=99 \
YGGDRASIL_PROFILE_DURATION=30s \
  target/release/yggdrasil run --config /etc/yggdrasil/config.toml
# Daemon emits the flamegraph on SIGTERM or at the configured duration.
```

**Stack depth caveat:** pprof-rs's signal-based unwinder reliably
attributes each sample to the **leaf** function (typically a libc
syscall like `epoll_wait` / `recvmmsg` / `sendmmsg` — useful for the
"what syscall is eating cycles" question), but doesn't always walk
back into the calling Rust frames. SIGPROF often lands while a
thread is inside a syscall, where `%rbp` is kernel-managed and the
unwinder gives up after the leaf.

For "which **Rust function** called the syscall" the daemon emits
the **`yggdrasil_hot_section_seconds` histogram** alongside the
flamegraph (also gated behind the `profile` feature). Sections are
named code blocks bracketed with `crate::profile::section(subsystem,
name)` — e.g. `frontend_wait`, `handle_inbound`, `flow_lookup`,
`upstream_send`, `sendmmsg_to_client`. Scrape the control socket's
`/metrics` during or after the bench and you get a per-section
duration quantile breakdown without re-running. For deeper
analysis a developer with root + `perf` on a Linux host can use
`perf record -g -p <pid>` against the same profile-feature build.

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
* If they match, `yggdrasilctl local accept approve <fingerprint>`.
  The key is written to config and becomes live immediately.

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

For `[[rule]]`s: `proxy_protocol = "v1"` / `"v2"` is **relay-mode
only**. On a terminal-mode rule (a rule with `target` set), the
config validator rejects `proxy_protocol`. On UDP rules, only `"v2"`
is meaningful (the validator rejects `"v1"` because it's an ASCII
stream prefix, not a datagram shape).

For `[[route]]`s (HTTPS): operators do not configure `proxy_protocol`
— the relay always emits a PROXY-v2 header for HTTPS-derived rules
(prepended on the TCP leg, sent as a standalone first datagram on the
UDP/QUIC leg), and the terminal's HTTPS frontend always consumes it.
If a backend behind the terminal sees the relay's IP in
`X-Forwarded-For` rather than the real client's:

* For TCP HTTPS (HTTP/1.1, HTTP/2): check
  `yggdrasilctl local derived-rules` on the relay — the
  HTTPS-derived TCP rule must show `proxy_protocol: "v2"`. If it does
  not, the chain control plane hasn't applied the latest derive logic
  (rebuild or restart the relay).
* For HTTP/3: the terminal's interpose socket
  (`proxy/h3_interpose.rs`) requires the PROXY-v2 datagram to arrive
  **before** the client's first QUIC Initial in the same 5-tuple. The
  relay's UDP flow path emits in that order on the connected
  upstream socket; if you see XFF showing the relay's IP, capture
  with `tcpdump -i any -nn udp port 443` on the terminal and confirm
  the first datagram of a fresh flow carries the v2 magic
  (`0x0D 0x0A 0x0D 0x0A 0x00 0x0D 0x0A 0x51 0x55 0x49 0x54 0x0A`).
* For multi-hop chain HTTPS: each mid-relay reads inbound PROXY and
  uses the decoded client when emitting its own outbound PROXY, so
  the real client IP propagates end-to-end. If XFF still shows a
  mid-relay's IP, check that the mid-relay's daemon mode is `relay`
  (not `gateway`) via `yggdrasilctl local status` — only `relay`
  mode enables the inbound PROXY consumption needed for bridging.
  Gateway-mode nodes don't consume inbound PROXY (their inbound is
  real internet clients), so misconfiguring a mid-hop as
  `gateway` mode breaks the bridge.

### "chain diff says origin mismatch with previous hop"

Under v1, this is expected during transient propagation windows (for
example, while a newly-authenticated terminal's first predicate push is
walking the chain) — `chain diff` flags it as a non-error. Mid-chain
relays forward predicates verbatim (preserving origin pubkey and
predicate content) so steady-state diff is empty across the chain;
transient mismatches resolve on the next predicate-publish cycle.

### NAT traversal won't establish or keeps backing off

Run `yggdrasilctl local status` and look at the **NAT traversal**
block. The interesting fields:

* `state: backoff` — the router doesn't speak PCP / NAT-PMP, or
  drops the requests on the floor. `last_error` says which. Three
  actions, in priority order:
  1. Check the router admin UI. Most consumer routers ship with PCP
     and / or NAT-PMP disabled by default. Enable one. PCP is
     preferred (longer lifetimes, IPv6 hooks even though we don't
     use them yet); NAT-PMP is a fine fallback.
  2. If the router does speak PCP / NAT-PMP but the daemon still
     can't reach it, the discovery heuristic picked the wrong source
     interface (rare; usually only on multi-NIC hosts). v1 has no
     override knob — verify with `cat /proc/net/route` that the
     default route points at the LAN gateway you expect, and that
     the source-IP probe (a `connect()` UDP socket to 192.0.2.1)
     resolves to an interface that can reach that gateway.
  3. Set `nat_traversal = "off"` and forward ports manually in the
     router UI. The daemon serves traffic identically; only the
     auto-mapping convenience goes away.

* `state: active` but no external reachability — the router accepted
  the mapping but isn't actually forwarding traffic. Walk:
  1. `external IP` matches your real public IP per
     `curl https://ifconfig.me`? If not, you're behind CGNAT and
     PCP can't help (see `docs/architecture.md`).
  2. Try the mapping from another network. `nmap -p <external_port>
     <external_ip>`. If filtered, the router has a buggy firewall.

* `state: discovering` for more than a few seconds — the gateway
  isn't responding at all. Same as the `backoff` recovery flow but
  earlier in the timeline.

* `last error: AddressMismatch` — PCP §11.2: your internal bind IP
  and the IP the router thinks you have don't match. Most commonly
  because the host has multiple NICs and the daemon's rule is on
  one NIC while the default route is on another. v1 has no
  per-interface override; this is a deployment constraint.

Metrics worth scraping:

* `rate(yggdrasil_nat_epoch_resets_total[1h])` — should be ~0.
* `rate(yggdrasil_nat_mappings_created_total{result_code!="success"}[5m])` —
  failed mapping creates. Per-protocol, per-origin breakdown.
* `yggdrasil_nat_active_mappings` — should match the count of
  rules + accept + redirect listeners on a home-hosted node.

## Backups

Back up the terminal as the authority for operator-meaningful state:

* `/etc/yggdrasil/identity.key` — the long-term key. Lose it and you'll
  have to re-run the request/grant ceremony with every neighbour.
* `/etc/yggdrasil/config.toml` — the daemon config, including enrolled
  chain-neighbour pubkeys and ACME settings.
* `/etc/yggdrasil/conf.d/*.toml` — terminal rule files. These are often
  tracked in a deploy repo, but they are still terminal state.
* `/etc/yggdrasil/certs/` or whatever `[server].cert_dir` points at —
  convention TLS material.
* ACME account and storage paths (`[acme].account_key_path` and
  `[acme].storage_dir` when set, otherwise the defaults documented in
  [configuration.md](configuration.md#acme--optional-terminal-mode-only)).

Restoring those files on a terminal restores the complete operator state;
once the daemon starts, it republishes the current predicate set to the
chain.

For intermediaries (gateway and mid-chain relay), back up only
`identity.key` and `config.toml`. They have no received-predicate file,
no pending-peer file, and no chain predicate counter on disk. After
restore, start the daemon; the next terminal heartbeat and predicate push
rebuild the live derived listeners.
