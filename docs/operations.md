# Operations

Day-to-day runbook. Assumes both daemons are already installed
([install.md](install.md)) and you finished [quickstart.md](quickstart.md).

## Adding, changing, removing rules

Rules are live-reloadable. Edit, add, or `rm` files under
`server.rules_dir` and yggdrasil picks the change up within ~250 ms.

```bash
# Add a new rule.
sudo $EDITOR /etc/yggdrasil/conf.d/web.toml

# Confirm it was picked up.
sudo yggdrasilctl rules list

# If you suspect inotify dropped the event (NFS, FUSE, container bind mounts on macOS):
sudo yggdrasilctl rules reload
```

Validation rules to remember (see [configuration.md](configuration.md#-rule----repeatable)):

- `name` is globally unique across all rule files.
- `listen` is globally unique per `(ip, port, protocol)`.
- `idle_timeout` only applies to UDP rules; `proxy_protocol` only to TCP.

If the reload fails validation, **all** rules from the previous good
configuration keep serving. The error appears in the daemon log:

```
ERROR yggdrasil::proxy::supervisor: rule reload rejected
  error=duplicate rule name "ssh"
```

## TOFU peer enrolment

The expected enrolment path is "operator runs `yggdrasil enroll-token`
out-of-band". As a fallback, yggdrasil also supports trust-on-first-use:
if a peer attempts a handshake whose pubkey isn't in `[peer]`, the daemon
stages it and you approve it manually.

```bash
# 1. Start huginn (which will fail handshake but leave a candidate).
# 2. Observe staged candidates on the VPS.
sudo yggdrasilctl peer pending
# fingerprint                       observed_at           handshake_attempts
# 1234abcd5678efgh90ij12klmn34op56  2024-08-12T10:34:01Z  3

# 3. Verify the fingerprint matches what `huginn fingerprint` shows on
#    the home box — out-of-band, e.g. by phone.
ssh home.example.lan -- sudo huginn fingerprint
# 1234abcd5678efgh90ij12klmn34op56

# 4. Approve.
sudo yggdrasilctl peer approve 1234abcd5678efgh90ij12klmn34op56
# approved; peer.public_key_hex written to /etc/yggdrasil/config.toml
```

TOFU staging never accepts traffic on its own — it only collects candidates
for human review. The fingerprint comparison is the security boundary; if
you skip it, you're effectively trusting whoever can reach
`heartbeat_listen` on day one.

## Key rotation

### Routine rekey (automatic)

`peer.rekey_interval` and `client.rekey_interval` (default `1h` for both)
force a fresh Noise handshake at most that often, even on an otherwise
quiet link. There's nothing to operate; just confirm the metric ticks:

```promql
rate(yggdrasil_handshakes_completed_total[15m])
```

For default settings you should see at least one handshake/hour per peer.

### Long-term key swap

Long-term X25519 identities are not rotated automatically. Both ends keep
their identity for the lifetime of the install. To swap (e.g. you suspect
compromise, or you're decommissioning the home box):

1. On the home box, generate a new identity (don't overwrite the old one yet):

   ```bash
   sudo huginn keygen --identity-file /etc/huginn/identity.key.new
   # pubkey:      ...
   # fingerprint: ...
   ```

2. On the VPS, mint a new enrollment token against the new pubkey, using
   `--force` to overwrite `peer.public_key_hex`:

   ```bash
   sudo yggdrasil enroll-token \
       --peer-pubkey <new-pubkey-hex> \
       --endpoint vps.example.net:51820 \
       --force \
       -o /tmp/huginn.token
   ```

3. Copy and apply on the home box:

   ```bash
   sudo huginn enroll /tmp/huginn.token
   sudo mv /etc/huginn/identity.key{.new,}
   sudo systemctl restart huginn
   ```

4. Restart yggdrasil to apply the updated `peer.public_key_hex`:

   ```bash
   sudo systemctl restart yggdrasil
   ```

5. Confirm the next handshake completes:

   ```bash
   sudo yggdrasilctl status   # last_heartbeat should be < heartbeat_interval
   sudo journalctl -u yggdrasil -n 50 | grep handshake
   ```

There is a small mutual-down window (a few seconds) between the
restarts — schedule accordingly.

### Server key swap

Same pattern, mirrored. Run `yggdrasil keygen --identity-file ...new` on
the VPS, then issue a fresh enrolment token using the new identity, then
swap and restart. The home side will refuse the new server pubkey until you
re-`enroll` — that's the desired behaviour; it stops an attacker who can
hijack DNS or BGP for `vps.example.net` from silently switching keys.

## Monitoring

### Prometheus metrics

Exported on `[metrics] listen` (default `127.0.0.1:9090`, path `/metrics`).

| Metric                                              | Type    | Labels             | Meaning                                                                                    |
| --------------------------------------------------- | ------- | ------------------ | ------------------------------------------------------------------------------------------ |
| `yggdrasil_build_info`                              | gauge   | `version`, `git_sha` | Always 1. Use for build-version annotations.                                              |
| `yggdrasil_heartbeats_received_total`               | counter | `result=accepted\|rejected` | Heartbeat decoder outcomes. A non-zero `rejected` rate usually means a misconfigured peer. |
| `yggdrasil_handshakes_completed_total`              | counter | —                  | Successful Noise_IK handshakes. Should at least match `rekey_interval`.                    |
| `yggdrasil_peer_ip_changes_total`                   | counter | —                  | Times the peer's source IP changed between consecutive heartbeats. Each change drains the affected UDP flow table. |
| `yggdrasil_rules_loaded`                         | gauge   | —                  | Number of rules currently active.                                                          |
| `yggdrasil_udp_flows_drained_on_ip_change_total`    | counter | —                  | UDP flows dropped because the peer IP moved while the flow was in-flight.                  |

Suggested alerts:

- **Stale peer**: `time() - yggdrasil_last_heartbeat_timestamp` is not yet
  exported; until then derive staleness from `yggdrasilctl status --json`
  and Prometheus `node_exporter`-based timestamping, or use
  `increase(yggdrasil_heartbeats_received_total{result="accepted"}[2m]) == 0`.
- **Handshake storm**: `rate(yggdrasil_handshakes_completed_total[5m]) > 0.1`.
  A healthy link rehandshakes about once an hour.

`huginn` does not currently export Prometheus metrics — it logs the
relevant fields (handshake outcomes, heartbeat seq, errors) on stdout.

### Logs

Both daemons emit structured logs (`--log-format json` by default). Useful
fields:

| Field              | Where                | Meaning                                                                                |
| ------------------ | -------------------- | -------------------------------------------------------------------------------------- |
| `peer_ip`          | yggdrasil heartbeat  | Source IP of the most recent authenticated heartbeat.                                  |
| `seq`              | both heartbeat sides | Monotonic heartbeat sequence number. Skipped values may indicate UDP loss.             |
| `rule_name`      | yggdrasil proxy      | Which `[[rule]]` triggered this log line.                                              |
| `flow_id`          | yggdrasil UDP proxy  | Stable identifier for a UDP flow within the flow table.                                |
| `handshake_attempt`| huginn            | Increments each failed handshake; useful for "stuck in retry loop" alerts.             |

Set `YGGDRASIL_LOG=debug` or `HUGINN_LOG=debug` (standard `tracing`
`EnvFilter` syntax) to lift the verbosity. Both env vars accept the usual
`module::path=level,other::path=trace` syntax.

## Troubleshooting

### `yggdrasilctl status` says "peer_ip: <none>"

The server hasn't yet seen a valid heartbeat. Most common causes:

| Symptom                                                     | Likely cause                                                                                                        |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| huginn log: "connection refused" / "no route to host"    | VPS firewall is blocking UDP `heartbeat_listen`. Open it for inbound UDP.                                           |
| huginn log: "handshake response decode failed"           | `client.yggdrasil_pubkey_hex` does not match the server. Re-run `huginn enroll` with a fresh token.              |
| yggdrasil log: "rejected: unknown peer"                     | `peer.public_key_hex` is wrong or empty on the server. Re-run `yggdrasil enroll-token`.                             |
| Nothing on either side                                      | Home-side outbound UDP blocked, or `client.yggdrasil_endpoint` resolves to wrong IP. Check `dig`, then `nc -u -v`.  |

### "Permission denied" connecting `yggdrasilctl`

The control socket is created with the same uid/gid as the daemon. If you
run yggdrasil as a dedicated user (recommended in the install guide):

```bash
sudo chown root:yggdrasil-admin /run/yggdrasil
sudo chmod 0750 /run/yggdrasil
sudo usermod -aG yggdrasil-admin <your-login>
# log out / back in, then yggdrasilctl works without sudo
```

The systemd unit in [install.md](install.md#systemd-units) sets
`RuntimeDirectoryMode=0750` and `Group=yggdrasil-admin` for this.

### Rule file parse errors

```
ERROR yggdrasil::config::rules: rule reload rejected
  file=/etc/yggdrasil/conf.d/web.toml
  error=missing field `upstream_port`
```

The previous rule set keeps running. Fix the file (or `rm` it) and the
watcher picks up the change.

### "peer_ip changes" counter is spiking

`yggdrasil_peer_ip_changes_total` increments on every flap. A few per day
is normal for a residential link. Sustained churn (one per minute) usually
means:

- Two huginn instances are sharing the same identity and racing each
  other from different networks. Move one to a different identity.
- A NAT in front of the home box is rotating its public IP very
  aggressively (some CGNAT setups). Lower `heartbeat_interval` so the flow
  table drains faster after each change.

### Hot-reload not picking up changes

If `rules_dir` lives on NFS, FUSE, or a container bind mount, inotify
events may not be delivered. Use:

```bash
sudo yggdrasilctl rules reload
```

to force a re-scan. As a permanent fix, prefer running yggdrasil with its
rules directory on a local filesystem.
