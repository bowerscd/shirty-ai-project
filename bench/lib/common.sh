# shellcheck shell=bash
# Common helpers sourced by every bench/<scenario>.sh script.
#
# Conventions:
#   - All scripts must be run from the workspace root (the bench/ parent).
#   - Outputs land under bench/results/$BENCH_SHA/<scenario>-<subject>.json.
#   - The harness owns no global state — every scenario allocates a fresh tmpdir
#     and tears it down on exit.
#
# Fatal errors call die(); cleanup is wired via trap so partial runs leave no
# orphan listeners. Don't add `set -e` here — the per-scenario script does it
# AFTER sourcing so it can decide whether to inherit -E for traps.

# ---------- paths & sha ----------

bench_workspace_root() {
    # The directory containing bench/.
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P
}

bench_results_dir() {
    local sha
    sha="${BENCH_SHA:-$(git -C "$(bench_workspace_root)" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
    echo "$(bench_workspace_root)/bench/results/${sha}"
}

ensure_results_dir() {
    mkdir -p "$(bench_results_dir)"
}

# ---------- subject selection ----------
#
# Every scenario benches one or more "subjects" — `direct` (no proxy),
# `yggdrasil-terminal`, `nginx`, etc. The set varies per protocol family
# (HAProxy has no UDP L4 mode; traefik-chain TCP has an unresolved
# config interaction that collapses connrate to <200 c/s, so it's
# excluded from TCP defaults until that's debugged).
#
# `bench_subjects_for tcp|udp` is the canonical accessor. Operators
# can override either the list (`BENCH_SUBJECTS="a b c"`) or the order
# (`BENCH_SHUFFLE=1`, optionally with `BENCH_SHUFFLE_SEED=N` for
# reproducibility). The rotated harness in `bench/run-rotated.sh`
# uses these knobs to average out run-order bias across multiple runs.

bench_subjects_for() {
    local family="$1"
    python3 - "$family" "${BENCH_SHUFFLE:-0}" "${BENCH_SHUFFLE_SEED:-}" "${BENCH_SUBJECTS:-}" <<'PY'
import sys, random
family, shuffle, seed, override = sys.argv[1:5]
SUBJECTS = {
    "tcp": [
        "direct",
        "yggdrasil-terminal", "yggdrasil-chain",
        "nginx", "nginx-chain",
        "haproxy", "haproxy-chain",
        "traefik",
        # "traefik-chain" — known-broken in the harness on TCP
        # (collapses to <200 c/s, doesn't reflect a real traefik
        # property). Set BENCH_SUBJECTS to include it explicitly if
        # you're debugging the chain config.
    ],
    "udp": [
        "direct",
        "yggdrasil-terminal", "yggdrasil-chain",
        "nginx", "nginx-chain",
        "traefik", "traefik-chain",
    ],
    # L7 HTTPS comparison. `direct` here means "loadgen → bench-echo
    # http with no proxy in front" — plain HTTP, no TLS — to give a
    # ceiling for what the backend can do. The proxy subjects all do
    # the same shape: terminate TLS on $listen_port and forward plain
    # HTTP to $upstream_port. No haproxy: haproxy's HTTP mode is a
    # separate beast (it's L7 but routes by host rather than SNI,
    # and the bench harness's stream-only common path doesn't cover
    # it). No chain variants on the first pass — single-hop only.
    "http": [
        "direct",
        "yggdrasil-terminal",
        "nginx",
        "traefik",
    ],
}
if family not in SUBJECTS:
    sys.stderr.write(f"bench_subjects_for: unknown family {family!r}\n")
    sys.exit(1)
subjects = override.split() if override else list(SUBJECTS[family])
if shuffle == "1":
    if seed:
        random.seed(int(seed))
    random.shuffle(subjects)
print("\n".join(subjects))
PY
}

# ---------- logging ----------

log()  { printf '[bench %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die()  { log "FATAL: $*"; exit 1; }

# ---------- port allocation ----------
#
# We let the kernel pick an ephemeral port, then immediately release it.
# This is racy in theory; for a single-host single-runner bench it's fine.

pick_free_tcp_port() {
    python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

pick_free_udp_port() {
    python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

# ---------- process lifecycle ----------
#
# bench_spawn <pid_var_name> <log_file> -- <cmd> [args...]
# Spawns the command detached, writes its PID into the named variable,
# and registers it for teardown.

declare -a BENCH_PIDS=()
declare -a BENCH_TMPDIRS=()

bench_spawn() {
    local __pidvar="$1"; shift
    local logfile="$1"; shift
    [[ "$1" == "--" ]] || die "bench_spawn: expected -- separator"
    shift
    "$@" >"$logfile" 2>&1 &
    local pid=$!
    printf -v "$__pidvar" '%s' "$pid"
    BENCH_PIDS+=("$pid")
}

bench_wait_listen_tcp() {
    local host="$1" port="$2" deadline_s="${3:-5}"
    local deadline=$(( SECONDS + deadline_s ))
    while (( SECONDS < deadline )); do
        # Match the specific (host, port) — not just the port — so a
        # listener bound to a different loopback IP on the same port
        # (e.g. an inner haproxy on 127.0.0.2 while we wait for the
        # outer on 127.0.0.1) doesn't falsely satisfy the wait.
        if ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qx "${host}:${port}"; then
            return 0
        fi
        sleep 0.05
    done
    die "TCP $host:$port never came up within ${deadline_s}s"
}

bench_wait_listen_udp() {
    local host="$1" port="$2" deadline_s="${3:-5}"
    local deadline=$(( SECONDS + deadline_s ))
    while (( SECONDS < deadline )); do
        if ss -lunH 2>/dev/null | awk '{print $4}' | grep -qx "${host}:${port}"; then
            return 0
        fi
        sleep 0.05
    done
    die "UDP $host:$port never came up within ${deadline_s}s"
}

bench_cleanup() {
    local pid
    for pid in "${BENCH_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done
    # Give them ~500ms to settle, then SIGKILL stragglers.
    sleep 0.5
    for pid in "${BENCH_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
    done
    local dir
    for dir in "${BENCH_TMPDIRS[@]}"; do
        rm -rf -- "$dir"
    done
}

bench_install_traps() {
    trap bench_cleanup EXIT INT TERM
}

# Tear down everything spawned since the last call. Used between legs of a
# multi-subject scenario so each subject runs on a freshly-quiesced host.
bench_leg_teardown() {
    bench_cleanup
    BENCH_PIDS=()
    BENCH_TMPDIRS=()
    # Brief settle so port allocations don't collide with TIME_WAIT.
    sleep 0.3
}

bench_mktempdir() {
    local d
    d="$(mktemp -d -t yggbench.XXXXXXXX)"
    BENCH_TMPDIRS+=("$d")
    echo "$d"
}

# ---------- echo servers ----------
#
# We use the native `bench-echo` Rust binary so the backend is never the
# scenario's bottleneck. It binds N listener sockets via SO_REUSEPORT
# (defaults to available_parallelism()) so the kernel can spread the
# load across cores — matching what a "real" upstream service would do.

bench_echo_binary() {
    local root
    root="$(bench_workspace_root)"
    local bin="$root/target/release/bench-echo"
    [[ -x "$bin" ]] || die "missing $bin — run: cargo build --release -p bench-tools"
    printf '%s' "$bin"
}

# Spawn a UDP echo on 127.0.0.1:$port. Writes PID into named var.
bench_spawn_udp_echo() {
    local __pidvar="$1" port="$2" logfile="$3"
    local bin
    bin="$(bench_echo_binary)"
    bench_spawn "$__pidvar" "$logfile" -- "$bin" udp "$port"
    bench_wait_listen_udp 127.0.0.1 "$port" 3
}

# Spawn a UDP echo on 127.0.0.1:$port that ALSO originates an
# independent server→client stream at `$originate_pps` per source
# address. Pairs with `loadgen udp-duplex` to exercise both
# directions of a proxy's UDP data plane under independent load.
#
# `$originate_max_sources` caps how many distinct source-port
# originator tasks the echo will spin up. This matters when a proxy
# (notably nginx in stream mode) presents many upstream source
# ports — without a cap, bench-echo would spawn one originator per
# new source and end up sending N× the configured per-source rate.
# The bench passes `$BENCH_FLOWS` here so the originate aggregate
# stays comparable across subjects.
bench_spawn_udp_echo_duplex() {
    local __pidvar="$1" port="$2" logfile="$3" originate_pps="$4"
    local originate_bytes="${5:-64}" originate_max_sources="${6:-32}"
    local bin
    bin="$(bench_echo_binary)"
    bench_spawn "$__pidvar" "$logfile" -- "$bin" udp "$port" \
        --originate-pps "$originate_pps" \
        --originate-bytes "$originate_bytes" \
        --originate-max-sources "$originate_max_sources"
    bench_wait_listen_udp 127.0.0.1 "$port" 3
}

# Spawn a TCP echo on 127.0.0.1:$port. Writes PID into named var.
bench_spawn_tcp_echo() {
    local __pidvar="$1" port="$2" logfile="$3"
    local bin
    bin="$(bench_echo_binary)"
    bench_spawn "$__pidvar" "$logfile" -- "$bin" tcp "$port"
    bench_wait_listen_tcp 127.0.0.1 "$port" 3
}

# ---------- yggdrasil stack orchestration ----------
#
# Two flavours:
#
#   bench_spin_yggdrasil_terminal <tmp> <listen_port> <upstream_port> <proto> [extra]
#       Single daemon, terminal mode, no chain. Used by the apples-to-apples
#       single-hop comparison subject (`yggdrasil-terminal`) so we can put
#       yggdrasil head-to-head against nginx/haproxy at the same hop count.
#       Binds 127.0.0.1:$listen_port → 127.0.0.1:$upstream_port via a static
#       rule. The loadgen target is 127.0.0.1:$listen_port.
#
#   bench_spin_yggdrasil_chain <tmp> <listen_port> <upstream_port> <proto> [extra]
#       Two-daemon gateway+terminal topology on loopback (the `yggdrasil-chain`
#       subject, what real deployments run). Pins the gateway to 127.0.0.1
#       and the terminal to 127.0.0.2 via `[server].default_bind` so their
#       listeners can't collide.
#
# Exports (chain flavour):
#   YGG_LISTEN_PORT       — gateway-side proxy port (loadgen target)
#   YGG_LISTEN_ADDR       — gateway-side bind address (127.0.0.1)
#   YGG_HB_PORT           — gateway's accept (heartbeat) UDP port
#   YGG_GW_PID            — gateway daemon PID
#   YGG_TM_PID            — terminal daemon PID
#   YGG_CTRL_SOCK         — terminal control socket (rules live there)
#   YGG_CONFIG            — terminal config path
#   YGG_GATEWAY_CONFIG    — gateway config path
#   YGG_GATEWAY_CTRL_SOCK — gateway control socket
#
# Exports (terminal flavour):
#   YGG_LISTEN_PORT, YGG_LISTEN_ADDR, YGG_TM_PID, YGG_CTRL_SOCK, YGG_CONFIG
#   (the GW_*/HB_*/GATEWAY_* variables are unset)

bench_spin_yggdrasil_terminal() {
    local tmp="$1"; local listen_port="$2"; local upstream_port="$3"; local proto="$4"
    local extra="${5:-}"
    local root
    root="$(bench_workspace_root)"

    local ygg_bin="$root/target/release/yggdrasil"
    local ctl_bin="$root/target/release/yggdrasilctl"
    [[ -x "$ygg_bin" ]] || die "missing $ygg_bin — run: cargo build --release -p yggdrasil"
    [[ -x "$ctl_bin" ]] || die "missing $ctl_bin — run: cargo build --release -p yggdrasilctl"

    mkdir -p "$tmp"/{terminal,rules,tm-state,tm-run,logs}
    local tm_bind="127.0.0.1"

    # The daemon's config validator requires a [dial] OR [accept] section
    # (see `derived_mode` in crates/yggdrasil/src/config.rs). A terminal
    # mode node must have [dial], so synthesise one pointing at a closed
    # UDP port on loopback with a throwaway pubkey. The chain client will
    # retry the handshake forever in the background; the local rule
    # listener (the thing we're measuring) binds and serves regardless,
    # and the chain-failure path is async so it doesn't perturb the
    # measured TCP/UDP throughput. This is the cleanest way to spin a
    # "yggdrasil-as-a-standalone-reverse-proxy" topology for an
    # apples-to-apples comparison vs single-hop nginx/haproxy.
    local fake_upstream_key="$tmp/fake-upstream.key"
    "$ctl_bin" identity rotate --identity-file "$fake_upstream_key" --force >/dev/null
    local fake_pubkey
    fake_pubkey=$("$ctl_bin" identity show --identity-file "$fake_upstream_key" 2>/dev/null \
        | awk '/^pubkey:/ {print $2; exit}')
    [[ -n "$fake_pubkey" ]] || die "failed to extract fake upstream pubkey"
    local dummy_endpoint="127.0.0.1:1"

    local tm_cfg="$tmp/terminal/config.toml"
    local tm_key="$tmp/terminal/identity.key"
    cat > "$tm_cfg" <<EOF
[server]
rules_dir     = "$tmp/rules"
state_dir     = "$tmp/tm-state"
identity_file = "$tm_key"
default_bind  = "$tm_bind"

[control]
socket = "$tmp/tm-run/control.sock"

[dial]
pubkey   = "$fake_pubkey"
endpoint = "$dummy_endpoint"
EOF

    "$ctl_bin" --config "$tm_cfg" identity rotate \
        --identity-file "$tm_key" --force >/dev/null

    cat > "$tmp/rules/scenario.toml" <<EOF
[[rule]]
name     = "bench"
listen   = "$tm_bind:$listen_port"
protocol = "$proto"
target   = "127.0.0.1:$upstream_port"
$extra
EOF

    bench_spawn YGG_TM_PID "$tmp/logs/terminal.log" -- "$ygg_bin" --log-format json run --config "$tm_cfg"

    if [[ "$proto" == "tcp" ]]; then
        bench_wait_listen_tcp "$tm_bind" "$listen_port" 5
    else
        bench_wait_listen_udp "$tm_bind" "$listen_port" 5
    fi
    sleep 0.2

    export YGG_LISTEN_PORT="$listen_port"
    export YGG_LISTEN_ADDR="$tm_bind"
    export YGG_CTRL_SOCK="$tmp/tm-run/control.sock"
    export YGG_CONFIG="$tm_cfg"
    unset YGG_GW_PID YGG_HB_PORT YGG_GATEWAY_CONFIG YGG_GATEWAY_CTRL_SOCK
}

bench_spin_yggdrasil_chain() {
    local tmp="$1"; local listen_port="$2"; local upstream_port="$3"; local proto="$4"
    local extra="${5:-}"
    local root
    root="$(bench_workspace_root)"

    local ygg_bin="$root/target/release/yggdrasil"
    local ctl_bin="$root/target/release/yggdrasilctl"
    [[ -x "$ygg_bin" ]] || die "missing $ygg_bin — run: cargo build --release -p yggdrasil"
    [[ -x "$ctl_bin" ]] || die "missing $ctl_bin — run: cargo build --release -p yggdrasilctl"

    mkdir -p "$tmp"/{gateway,terminal,rules,gw-rules,gw-state,tm-state,gw-run,tm-run,logs}
    local accept_port; accept_port="$(pick_free_udp_port)"

    # Pin gateway and terminal to distinct loopback addresses so they don't
    # collide on the same `<addr>:<listen_port>` socket. Without this, the
    # gateway's derived listener (default bind_addr = 0.0.0.0) and the
    # terminal's rule listener both want port $listen_port on the same host
    # — the second bind() returns EADDRINUSE, only one daemon ends up
    # serving traffic, and the chain isn't exercised. 127.0.0.0/8 is loopback
    # so any 127.x.y.z works without privilege.
    local gw_bind="127.0.0.1"
    local tm_bind="127.0.0.2"

    # ---- gateway (accept-mode) ----
    local gw_cfg="$tmp/gateway/config.toml"
    local gw_key="$tmp/gateway/identity.key"
    cat > "$gw_cfg" <<EOF
[server]
rules_dir     = "$tmp/gw-rules"
state_dir     = "$tmp/gw-state"
identity_file = "$gw_key"
default_bind  = "$gw_bind"

[control]
socket = "$tmp/gw-run/control.sock"

[accept]
listen = "$gw_bind:$accept_port"
EOF

    # ---- terminal (dial-mode) ----
    local tm_cfg="$tmp/terminal/config.toml"
    local tm_key="$tmp/terminal/identity.key"
    cat > "$tm_cfg" <<EOF
[server]
rules_dir     = "$tmp/rules"
state_dir     = "$tmp/tm-state"
identity_file = "$tm_key"
default_bind  = "$tm_bind"

[control]
socket = "$tmp/tm-run/control.sock"
EOF

    "$ctl_bin" --config "$gw_cfg" identity rotate \
        --identity-file "$gw_key" --force >/dev/null
    "$ctl_bin" --config "$tm_cfg" identity rotate \
        --identity-file "$tm_key" --force >/dev/null

    "$ctl_bin" --config "$tm_cfg" identity export-request \
        --identity-file "$tm_key" \
        --out "$tmp/request.txt" \
        --note "bench terminal" >/dev/null
    "$ctl_bin" --config "$gw_cfg" identity add-accept \
        --identity-file "$gw_key" \
        --from "$tmp/request.txt" \
        --my-endpoint "$gw_bind:$accept_port" \
        --out "$tmp/grant.txt" \
        --note "bench gw->tm" >/dev/null
    "$ctl_bin" --config "$tm_cfg" identity add-dial \
        --identity-file "$tm_key" \
        --from "$tmp/grant.txt" >/dev/null
    rm -f "$tmp/request.txt" "$tmp/grant.txt"

    cat > "$tmp/rules/scenario.toml" <<EOF
[[rule]]
name     = "bench"
listen   = "$tm_bind:$listen_port"
protocol = "$proto"
target   = "127.0.0.1:$upstream_port"
$extra
EOF

    bench_spawn YGG_GW_PID "$tmp/logs/gateway.log"  -- "$ygg_bin" --log-format json run --config "$gw_cfg"
    bench_spawn YGG_TM_PID "$tmp/logs/terminal.log" -- "$ygg_bin" --log-format json run --config "$tm_cfg"

    if [[ "$proto" == "tcp" ]]; then
        bench_wait_listen_tcp "$gw_bind" "$listen_port" 5
    else
        bench_wait_listen_udp "$gw_bind" "$listen_port" 5
    fi
    sleep 0.6

    export YGG_LISTEN_PORT="$listen_port"
    export YGG_LISTEN_ADDR="$gw_bind"
    export YGG_HB_PORT="$accept_port"
    export YGG_CTRL_SOCK="$tmp/tm-run/control.sock"
    export YGG_CONFIG="$tm_cfg"
    export YGG_GATEWAY_CONFIG="$gw_cfg"
    export YGG_GATEWAY_CTRL_SOCK="$tmp/gw-run/control.sock"
}

# Back-compat alias so existing call sites keep working through the
# subject-matrix expansion. New scripts should call the explicit name.
bench_spin_yggdrasil() {
    bench_spin_yggdrasil_chain "$@"
}

# ---------- nginx orchestration ----------
#
# bench_spin_nginx <tmpdir> <listen_port> <upstream_port> <protocol>
#
# Renders an nginx.conf with a single `stream {}` block proxying to the echo
# backend, starts nginx with `-p $tmp -c nginx.conf`, and waits for the
# listener to come up.
#
# On distros that ship the stream module dynamically (Arch, RHEL/Fedora),
# we emit a `load_module` directive at the top of the rendered conf so
# the harness's self-contained file doesn't rely on `/etc/nginx/...`
# include paths. Distros where stream is statically built in (Debian's
# `libnginx-mod-stream` package wires it via `modules-enabled/`, but
# also vendor builds that bake stream in) don't need the directive; we
# detect that case by parsing `nginx -V`.

bench_nginx_stream_loader() {
    # Echo a `load_module ...;` directive (with trailing newline) if the
    # nginx binary has stream as a *dynamic* module AND we can locate the
    # .so on disk. Otherwise echo nothing. Exits non-zero with a useful
    # message on stderr if stream is dynamic but the .so is missing.
    local nginx_bin="$1"
    local vline
    vline="$("$nginx_bin" -V 2>&1 | tr ' ' '\n')"

    # Stream built statically (no `=dynamic` qualifier) — nothing to load.
    if grep -qx -- '--with-stream' <<<"$vline"; then
        return 0
    fi
    # Stream not configured at all — fatal: nginx can't proxy L4.
    if ! grep -qx -- '--with-stream=dynamic' <<<"$vline"; then
        die "nginx at $nginx_bin was built without the stream module; install a build that has --with-stream or --with-stream=dynamic"
    fi

    # Stream dynamic — locate the .so.
    local modules_path
    modules_path="$(grep -E '^--modules-path=' <<<"$vline" | head -1 | sed 's/^--modules-path=//')"
    [[ -n "$modules_path" ]] || modules_path="/usr/lib/nginx/modules"
    local so="$modules_path/ngx_stream_module.so"
    if [[ ! -f "$so" ]]; then
        die "nginx at $nginx_bin has stream as a dynamic module but $so is missing; install the distro's nginx-mod-stream / libnginx-mod-stream package"
    fi
    printf 'load_module "%s";\n' "$so"
}

bench_spin_nginx() {
    local tmp="$1"; local listen_port="$2"; local upstream_port="$3"; local proto="$4"
    local nginx_bin
    nginx_bin="${BENCH_NGINX:-$(command -v nginx || true)}"
    [[ -x "$nginx_bin" ]] || die "nginx binary not found; set BENCH_NGINX=/path/to/nginx or install nginx"

    local stream_loader
    stream_loader="$(bench_nginx_stream_loader "$nginx_bin")"

    mkdir -p "$tmp/nginx/logs"
    local udp_kw=""
    [[ "$proto" == "udp" ]] && udp_kw="udp"
    cat > "$tmp/nginx/nginx.conf" <<EOF
${stream_loader}worker_processes auto;
pid $tmp/nginx/nginx.pid;
error_log $tmp/nginx/error.log warn;
events { worker_connections 4096; }
stream {
    server {
        listen 127.0.0.1:$listen_port $udp_kw;
        proxy_pass 127.0.0.1:$upstream_port;
        proxy_timeout 60s;
        proxy_connect_timeout 5s;
    }
}
EOF
    # nginx in foreground via `-g 'daemon off;'`.
    bench_spawn NGINX_PID "$tmp/nginx/spawn.log" -- "$nginx_bin" -p "$tmp/nginx" -c "$tmp/nginx/nginx.conf" -g "daemon off;"

    if [[ "$proto" == "tcp" ]]; then
        bench_wait_listen_tcp 127.0.0.1 "$listen_port" 5
    else
        bench_wait_listen_udp 127.0.0.1 "$listen_port" 5
    fi
}

# ---------- nginx chain orchestration ----------
#
# bench_spin_nginx_chain <tmpdir> <listen_port> <upstream_port> <protocol>
#
# Spins TWO nginx processes on loopback to mirror yggdrasil's
# gateway→terminal chain topology, so chain-vs-chain comparisons are honest:
#
#   loadgen → outer nginx (127.0.0.1:$listen_port)
#           → inner nginx (127.0.0.2:$listen_port)
#           → echo        (127.0.0.1:$upstream_port)
#
# Same proto applies to both legs.  TCP and UDP both supported via
# `[udp;]` on `listen`.
#
# Exports NGINX_OUTER_PID and NGINX_INNER_PID — tcp-idle-conns sums both
# for the proxy_rss_kib metric so the chain memory cost is comparable to
# yggdrasil-chain's (gw + tm).

bench_spin_nginx_chain() {
    local tmp="$1"; local listen_port="$2"; local upstream_port="$3"; local proto="$4"
    local nginx_bin
    nginx_bin="${BENCH_NGINX:-$(command -v nginx || true)}"
    [[ -x "$nginx_bin" ]] || die "nginx binary not found; set BENCH_NGINX=/path/to/nginx or install nginx"

    local stream_loader
    stream_loader="$(bench_nginx_stream_loader "$nginx_bin")"
    local udp_kw=""
    [[ "$proto" == "udp" ]] && udp_kw="udp"

    local outer_bind="127.0.0.1"
    local inner_bind="127.0.0.2"

    # ---- inner (closer to the echo backend) ----
    mkdir -p "$tmp/nginx-inner/logs"
    cat > "$tmp/nginx-inner/nginx.conf" <<EOF
${stream_loader}worker_processes auto;
pid $tmp/nginx-inner/nginx.pid;
error_log $tmp/nginx-inner/error.log warn;
events { worker_connections 4096; }
stream {
    server {
        listen $inner_bind:$listen_port $udp_kw;
        proxy_pass 127.0.0.1:$upstream_port;
        proxy_timeout 60s;
        proxy_connect_timeout 5s;
    }
}
EOF
    bench_spawn NGINX_INNER_PID "$tmp/nginx-inner/spawn.log" -- \
        "$nginx_bin" -p "$tmp/nginx-inner" -c "$tmp/nginx-inner/nginx.conf" -g "daemon off;"
    if [[ "$proto" == "tcp" ]]; then
        bench_wait_listen_tcp "$inner_bind" "$listen_port" 5
    else
        bench_wait_listen_udp "$inner_bind" "$listen_port" 5
    fi

    # ---- outer (loadgen-facing) ----
    mkdir -p "$tmp/nginx-outer/logs"
    cat > "$tmp/nginx-outer/nginx.conf" <<EOF
${stream_loader}worker_processes auto;
pid $tmp/nginx-outer/nginx.pid;
error_log $tmp/nginx-outer/error.log warn;
events { worker_connections 4096; }
stream {
    server {
        listen $outer_bind:$listen_port $udp_kw;
        proxy_pass $inner_bind:$listen_port;
        proxy_timeout 60s;
        proxy_connect_timeout 5s;
    }
}
EOF
    bench_spawn NGINX_OUTER_PID "$tmp/nginx-outer/spawn.log" -- \
        "$nginx_bin" -p "$tmp/nginx-outer" -c "$tmp/nginx-outer/nginx.conf" -g "daemon off;"
    if [[ "$proto" == "tcp" ]]; then
        bench_wait_listen_tcp "$outer_bind" "$listen_port" 5
    else
        bench_wait_listen_udp "$outer_bind" "$listen_port" 5
    fi
}

# ---------- haproxy orchestration ----------
#
# bench_spin_haproxy <tmpdir> <listen_port> <upstream_port> <protocol>
#
# Renders a minimal HAProxy config with a `mode tcp` frontend proxying to the
# echo backend, starts haproxy in foreground (via -db), and waits for the
# listener to come up.
#
# HAProxy 3.x has `mode tcp` and `mode http` only — there is no generic
# UDP L4 forwarder, so this helper refuses non-TCP protocols.

bench_spin_haproxy() {
    local tmp="$1"; local listen_port="$2"; local upstream_port="$3"; local proto="$4"
    local haproxy_bin
    haproxy_bin="${BENCH_HAPROXY:-$(command -v haproxy || true)}"
    [[ -x "$haproxy_bin" ]] || die "haproxy binary not found; set BENCH_HAPROXY=/path/to/haproxy or install haproxy"
    [[ "$proto" == "tcp" ]] || die "bench_spin_haproxy: HAProxy has no generic UDP L4 forwarder (mode udp does not exist); got proto=$proto"

    local nthreads
    nthreads="$(nproc 2>/dev/null || echo 1)"

    mkdir -p "$tmp/haproxy"
    cat > "$tmp/haproxy/haproxy.cfg" <<EOF
global
    nbthread $nthreads
    maxconn 65535
    log /dev/null local0
defaults
    mode tcp
    timeout connect 5s
    timeout client 60s
    timeout server 60s
frontend in
    bind 127.0.0.1:$listen_port
    default_backend echo
backend echo
    server echo 127.0.0.1:$upstream_port
EOF
    # -db = foreground (overrides any 'daemon' keyword); we want bench_spawn
    # to own the PID, and -db gives us that.
    bench_spawn HAPROXY_PID "$tmp/haproxy/spawn.log" -- "$haproxy_bin" -db -f "$tmp/haproxy/haproxy.cfg"
    bench_wait_listen_tcp 127.0.0.1 "$listen_port" 5
}

# ---------- haproxy chain orchestration ----------
#
# bench_spin_haproxy_chain <tmpdir> <listen_port> <upstream_port> <protocol>
#
# Two HAProxy processes mirroring yggdrasil-chain's topology. Same loopback-IP
# pinning trick as nginx_chain. TCP only (HAProxy has no UDP L4 mode).
# Exports HAPROXY_OUTER_PID and HAPROXY_INNER_PID for chain-aware PSS sampling.

bench_spin_haproxy_chain() {
    local tmp="$1"; local listen_port="$2"; local upstream_port="$3"; local proto="$4"
    local haproxy_bin
    haproxy_bin="${BENCH_HAPROXY:-$(command -v haproxy || true)}"
    [[ -x "$haproxy_bin" ]] || die "haproxy binary not found; set BENCH_HAPROXY=/path/to/haproxy or install haproxy"
    [[ "$proto" == "tcp" ]] || die "bench_spin_haproxy_chain: HAProxy has no generic UDP L4 forwarder (mode udp does not exist); got proto=$proto"

    local nthreads
    nthreads="$(nproc 2>/dev/null || echo 1)"
    local outer_bind="127.0.0.1"
    local inner_bind="127.0.0.2"

    # ---- inner ----
    mkdir -p "$tmp/haproxy-inner"
    cat > "$tmp/haproxy-inner/haproxy.cfg" <<EOF
global
    nbthread $nthreads
    maxconn 65535
    log /dev/null local0
defaults
    mode tcp
    timeout connect 5s
    timeout client 60s
    timeout server 60s
frontend in
    bind $inner_bind:$listen_port
    default_backend echo
backend echo
    server echo 127.0.0.1:$upstream_port
EOF
    bench_spawn HAPROXY_INNER_PID "$tmp/haproxy-inner/spawn.log" -- \
        "$haproxy_bin" -db -f "$tmp/haproxy-inner/haproxy.cfg"
    bench_wait_listen_tcp "$inner_bind" "$listen_port" 5

    # ---- outer ----
    mkdir -p "$tmp/haproxy-outer"
    cat > "$tmp/haproxy-outer/haproxy.cfg" <<EOF
global
    nbthread $nthreads
    maxconn 65535
    log /dev/null local0
defaults
    mode tcp
    timeout connect 5s
    timeout client 60s
    timeout server 60s
frontend in
    bind $outer_bind:$listen_port
    default_backend chain
backend chain
    server inner $inner_bind:$listen_port
EOF
    bench_spawn HAPROXY_OUTER_PID "$tmp/haproxy-outer/spawn.log" -- \
        "$haproxy_bin" -db -f "$tmp/haproxy-outer/haproxy.cfg"
    bench_wait_listen_tcp "$outer_bind" "$listen_port" 5
}

# ---------- traefik orchestration ----------
#
# bench_spin_traefik <tmpdir> <listen_port> <upstream_port> <protocol>
#
# Renders a Traefik static-config + dynamic-config pair, starts the daemon
# in foreground, and waits for the listener.
#
# Traefik does both TCP and UDP at L4, so a single helper covers both
# protocols (with HAProxy we needed `mode tcp` only). The TCP rule uses
# the catch-all SNI matcher `HostSNI(\`*\`)` for raw-passthrough behaviour
# without inspecting the bytes.

bench_spin_traefik() {
    local tmp="$1"; local listen_port="$2"; local upstream_port="$3"; local proto="$4"
    local traefik_bin
    traefik_bin="${BENCH_TRAEFIK:-$(command -v traefik || true)}"
    [[ -x "$traefik_bin" ]] || die "traefik binary not found; set BENCH_TRAEFIK=/path/to/traefik or install traefik"

    mkdir -p "$tmp/traefik"
    _bench_render_traefik_configs "$tmp/traefik" "127.0.0.1" "$listen_port" "127.0.0.1:$upstream_port" "$proto"

    bench_spawn TRAEFIK_PID "$tmp/traefik/spawn.log" -- \
        "$traefik_bin" --configfile="$tmp/traefik/traefik.yaml"

    if [[ "$proto" == "tcp" ]]; then
        bench_wait_listen_tcp 127.0.0.1 "$listen_port" 5
    else
        bench_wait_listen_udp 127.0.0.1 "$listen_port" 5
    fi
    # Traefik binds the entry-point listener before its router/service
    # pipeline is wired through the file provider; the first connection
    # to arrive in that window stalls until the dynamic config loads.
    # Settle for a bit so the bench measures steady-state cost, not a
    # cold-start race that varies wildly between runs.
    sleep 0.4
}

# ---------- traefik chain orchestration ----------
#
# Two Traefik processes mirroring yggdrasil-chain's outer→inner topology.
# Same loopback-IP pinning (outer 127.0.0.1, inner 127.0.0.2). Supports
# both TCP and UDP. Exports TRAEFIK_OUTER_PID and TRAEFIK_INNER_PID for
# chain-aware PSS sampling.

bench_spin_traefik_chain() {
    local tmp="$1"; local listen_port="$2"; local upstream_port="$3"; local proto="$4"
    local traefik_bin
    traefik_bin="${BENCH_TRAEFIK:-$(command -v traefik || true)}"
    [[ -x "$traefik_bin" ]] || die "traefik binary not found; set BENCH_TRAEFIK=/path/to/traefik or install traefik"

    local outer_bind="127.0.0.1"
    local inner_bind="127.0.0.2"

    # ---- inner ----
    mkdir -p "$tmp/traefik-inner"
    _bench_render_traefik_configs "$tmp/traefik-inner" "$inner_bind" "$listen_port" "127.0.0.1:$upstream_port" "$proto"
    bench_spawn TRAEFIK_INNER_PID "$tmp/traefik-inner/spawn.log" -- \
        "$traefik_bin" --configfile="$tmp/traefik-inner/traefik.yaml"
    if [[ "$proto" == "tcp" ]]; then
        bench_wait_listen_tcp "$inner_bind" "$listen_port" 5
    else
        bench_wait_listen_udp "$inner_bind" "$listen_port" 5
    fi
    sleep 0.4

    # ---- outer ----
    mkdir -p "$tmp/traefik-outer"
    _bench_render_traefik_configs "$tmp/traefik-outer" "$outer_bind" "$listen_port" "$inner_bind:$listen_port" "$proto"
    bench_spawn TRAEFIK_OUTER_PID "$tmp/traefik-outer/spawn.log" -- \
        "$traefik_bin" --configfile="$tmp/traefik-outer/traefik.yaml"
    if [[ "$proto" == "tcp" ]]; then
        bench_wait_listen_tcp "$outer_bind" "$listen_port" 5
    else
        bench_wait_listen_udp "$outer_bind" "$listen_port" 5
    fi
    # Same router-pipeline-readiness settle as bench_spin_traefik; applies
    # per-instance, so we get one for inner and one for outer.
    sleep 0.4
}

# Private: render Traefik's static + dynamic config pair into $dir.
# Args: dir, bind_addr, listen_port, upstream_addr, proto
_bench_render_traefik_configs() {
    local dir="$1" bind_addr="$2" port="$3" upstream="$4" proto="$5"
    local ep_suffix=""
    [[ "$proto" == "udp" ]] && ep_suffix="/udp"

    # Static config — entryPoints + a file provider pointing at dynamic.yaml.
    # Disable the dashboard, telemetry, and access log so nothing else
    # competes for cpu/io on the bench host.
    cat > "$dir/traefik.yaml" <<EOF
global:
  checkNewVersion: false
  sendAnonymousUsage: false
log:
  level: ERROR
accessLog:
  filePath: /dev/null
entryPoints:
  bench:
    address: "$bind_addr:$port$ep_suffix"
providers:
  file:
    filename: "$dir/dynamic.yaml"
    watch: false
EOF

    # Dynamic config — one router + one service in the right protocol section.
    if [[ "$proto" == "tcp" ]]; then
        # The default `HostSNI(\`*\`)` matcher requires Traefik to peek for
        # a TLS ClientHello to extract SNI — plain TCP traffic stalls
        # forever waiting for bytes that match. `ClientIP` matches purely
        # on the source address, available right after accept(), so it's
        # the correct rule for raw L4 passthrough.
        cat > "$dir/dynamic.yaml" <<EOF
tcp:
  routers:
    bench:
      entryPoints: [bench]
      rule: "ClientIP(\`0.0.0.0/0\`) || ClientIP(\`::/0\`)"
      service: echo
  services:
    echo:
      loadBalancer:
        servers:
          - address: "$upstream"
EOF
    else
        cat > "$dir/dynamic.yaml" <<EOF
udp:
  routers:
    bench:
      entryPoints: [bench]
      service: echo
  services:
    echo:
      loadBalancer:
        servers:
          - address: "$upstream"
EOF
    fi
}

# ---------- loadgen invocation ----------
#
# bench_run_loadgen <subject> <out_json_path> <args...>
#
# Each scenario script sets a top-level `SCENARIO=...` constant before
# calling this helper. We forward it to loadgen as
# `--scenario-name $SCENARIO` so the JSON report's `scenario` field
# matches the filename (and disambiguates udp-pps vs udp-flows, which
# share the same loadgen subcommand). Without this, multiple scenarios
# would land under the same `(scenario, subject)` key in compare.py's
# aggregator and silently overwrite each other.

bench_run_loadgen() {
    local subject="$1"; local out="$2"; shift 2
    local root
    root="$(bench_workspace_root)"
    local lg="$root/target/release/loadgen"
    [[ -x "$lg" ]] || die "missing $lg — run: cargo build --release -p bench-tools"
    local scenario_arg=()
    if [[ -n "${SCENARIO:-}" ]]; then
        scenario_arg=( --scenario-name "$SCENARIO" )
    fi
    log "loadgen subject=$subject out=$(basename "$out") args: $*"
    "$lg" --subject "$subject" --report-json "$out" "${scenario_arg[@]}" "$@"
}

# ---------- L7 HTTPS bench helpers ----------
#
# bench_spawn_http_echo <pidvar> <port> <logfile> [body_size]
#
# Spawn `bench-echo http` on 127.0.0.1:$port serving a fixed body. Used
# as the upstream backend for HTTPS L7 scenarios so the proxy under
# test terminates TLS in front of a real hyper backend.
bench_spawn_http_echo() {
    local __pidvar="$1" port="$2" logfile="$3"
    local body="${4:-100}"
    local bin
    bin="$(bench_echo_binary)"
    bench_spawn "$__pidvar" "$logfile" -- "$bin" http "$port" --body-size "$body"
    bench_wait_listen_tcp 127.0.0.1 "$port" 5
}

# bench_spin_yggdrasil_https <tmp> <listen_port> <upstream_port>
#
# Single yggdrasil terminal-mode daemon with one `protocol = "https"`
# rule. Cert is `ephemeral` — yggdrasil generates a fresh self-signed
# cert at startup (no external openssl/rcgen needed). The route's
# `hostname` is `127.0.0.1` so the loadgen's SNI matches; loadgen uses
# a permissive `ServerCertVerifier` so chain validation passes trivially.
bench_spin_yggdrasil_https() {
    local tmp="$1"; local listen_port="$2"; local upstream_port="$3"
    local root
    root="$(bench_workspace_root)"

    local ygg_bin="$root/target/release/yggdrasil"
    local ctl_bin="$root/target/release/yggdrasilctl"
    [[ -x "$ygg_bin" ]] || die "missing $ygg_bin — run: cargo build --release -p yggdrasil"
    [[ -x "$ctl_bin" ]] || die "missing $ctl_bin — run: cargo build --release -p yggdrasilctl"

    mkdir -p "$tmp"/{terminal,rules,tm-state,tm-run,certs,logs}
    local tm_bind="127.0.0.1"

    # Synthesise a [dial] section so the validator accepts a
    # standalone terminal config — same trick as bench_spin_yggdrasil_terminal.
    local fake_upstream_key="$tmp/fake-upstream.key"
    "$ctl_bin" identity rotate --identity-file "$fake_upstream_key" --force >/dev/null
    local fake_pubkey
    fake_pubkey=$("$ctl_bin" identity show --identity-file "$fake_upstream_key" 2>/dev/null \
        | awk '/^pubkey:/ {print $2; exit}')
    [[ -n "$fake_pubkey" ]] || die "failed to extract fake upstream pubkey"

    local tm_cfg="$tmp/terminal/config.toml"
    local tm_key="$tmp/terminal/identity.key"
    cat > "$tm_cfg" <<EOF
[server]
rules_dir     = "$tmp/rules"
state_dir     = "$tmp/tm-state"
identity_file = "$tm_key"
default_bind  = "$tm_bind"
cert_dir      = "$tmp/certs"
http_redirect_port = 0

[control]
socket = "$tmp/tm-run/control.sock"

[dial]
pubkey   = "$fake_pubkey"
endpoint = "127.0.0.1:1"
EOF

    "$ctl_bin" --config "$tm_cfg" identity rotate \
        --identity-file "$tm_key" --force >/dev/null

    cat > "$tmp/rules/scenario.toml" <<EOF
[[rule]]
name     = "bench-https"
protocol = "https"
listen   = "$tm_bind:$listen_port"

[[rule.route]]
hostname = "localhost"
target   = "http://127.0.0.1:$upstream_port"
cert     = "ephemeral"
EOF

    bench_spawn YGG_TM_PID "$tmp/logs/terminal.log" -- \
        "$ygg_bin" --log-format json run --config "$tm_cfg"

    bench_wait_listen_tcp "$tm_bind" "$listen_port" 10
    # Give the ephemeral cert generation a beat to complete before
    # the loadgen starts hammering the handshake path.
    sleep 0.5

    export YGG_LISTEN_PORT="$listen_port"
    export YGG_LISTEN_ADDR="$tm_bind"
    export YGG_CTRL_SOCK="$tmp/tm-run/control.sock"
    export YGG_CONFIG="$tm_cfg"
}

# bench_spin_nginx_https <tmp> <listen_port> <upstream_port>
#
# Terminate TLS on $listen_port via nginx's stock `ssl_*` directives and
# proxy plain HTTP to `127.0.0.1:$upstream_port`. Generates a one-shot
# self-signed cert via openssl into $tmp/nginx/cert.pem so the harness
# is self-contained.
bench_spin_nginx_https() {
    local tmp="$1"; local listen_port="$2"; local upstream_port="$3"
    local nginx_bin
    nginx_bin="${BENCH_NGINX:-$(command -v nginx || true)}"
    [[ -x "$nginx_bin" ]] || die "nginx binary not found; set BENCH_NGINX=/path/to/nginx or install nginx"

    mkdir -p "$tmp/nginx/logs"

    # Self-signed cert. Valid for 127.0.0.1; SAN covers the IP so
    # the rustls client (which puts the IP in SNI as `127.0.0.1`)
    # is happy. The harness doesn't validate chains anyway, but we
    # need the cert to be syntactically valid for nginx to load it.
    openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout "$tmp/nginx/key.pem" -out "$tmp/nginx/cert.pem" \
        -days 1 -subj "/CN=127.0.0.1" \
        -addext "subjectAltName=IP:127.0.0.1" \
        >/dev/null 2>&1 || die "openssl req failed (is openssl installed?)"

    cat > "$tmp/nginx/nginx.conf" <<EOF
worker_processes auto;
pid $tmp/nginx/nginx.pid;
error_log $tmp/nginx/error.log warn;
events { worker_connections 4096; }
http {
    access_log off;
    client_body_temp_path $tmp/nginx/client_body_temp;
    proxy_temp_path $tmp/nginx/proxy_temp;
    fastcgi_temp_path $tmp/nginx/fastcgi_temp;
    uwsgi_temp_path $tmp/nginx/uwsgi_temp;
    scgi_temp_path $tmp/nginx/scgi_temp;
    keepalive_timeout 65s;
    keepalive_requests 1000000;
    upstream backend {
        server 127.0.0.1:$upstream_port;
        keepalive 256;
        keepalive_requests 1000000;
        keepalive_timeout 65s;
    }
    server {
        listen 127.0.0.1:$listen_port ssl;
        http2 on;
        ssl_certificate $tmp/nginx/cert.pem;
        ssl_certificate_key $tmp/nginx/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_session_cache shared:SSL:10m;
        location / {
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header Host \$host;
        }
    }
}
EOF
    bench_spawn NGINX_PID "$tmp/nginx/spawn.log" -- \
        "$nginx_bin" -p "$tmp/nginx" -c "$tmp/nginx/nginx.conf" -g "daemon off;"
    bench_wait_listen_tcp 127.0.0.1 "$listen_port" 5
}

# bench_spin_traefik_https <tmp> <listen_port> <upstream_port>
#
# Same shape as bench_spin_nginx_https but using traefik's file
# provider. The cert is the same self-signed leaf openssl produces.
bench_spin_traefik_https() {
    local tmp="$1"; local listen_port="$2"; local upstream_port="$3"
    local traefik_bin
    traefik_bin="${BENCH_TRAEFIK:-$(command -v traefik || true)}"
    [[ -x "$traefik_bin" ]] || die "traefik binary not found; set BENCH_TRAEFIK=/path/to/traefik or install traefik"

    mkdir -p "$tmp/traefik"

    openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout "$tmp/traefik/key.pem" -out "$tmp/traefik/cert.pem" \
        -days 1 -subj "/CN=127.0.0.1" \
        -addext "subjectAltName=IP:127.0.0.1" \
        >/dev/null 2>&1 || die "openssl req failed (is openssl installed?)"

    cat > "$tmp/traefik/traefik.toml" <<EOF
[entryPoints.websecure]
address = "127.0.0.1:$listen_port"

[providers.file]
filename = "$tmp/traefik/dynamic.toml"

[log]
level = "WARN"
filePath = "$tmp/traefik/traefik.log"

[accessLog]
filePath = "/dev/null"
EOF

    cat > "$tmp/traefik/dynamic.toml" <<EOF
[http.routers.bench]
rule = "HostSNI(\`*\`)"
entryPoints = ["websecure"]
service = "bench"

[http.routers.bench.tls]

[tls.certificates]]
certFile = "$tmp/traefik/cert.pem"
keyFile = "$tmp/traefik/key.pem"

[http.services.bench.loadBalancer]
[[http.services.bench.loadBalancer.servers]]
url = "http://127.0.0.1:$upstream_port"
EOF

    bench_spawn TRAEFIK_PID "$tmp/traefik/spawn.log" -- \
        "$traefik_bin" --configFile="$tmp/traefik/traefik.toml"
    bench_wait_listen_tcp 127.0.0.1 "$listen_port" 10
}
