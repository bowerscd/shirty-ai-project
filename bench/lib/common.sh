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
        if ss -ltn "sport = :$port" 2>/dev/null | grep -q LISTEN; then
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
        if ss -lun "sport = :$port" 2>/dev/null | grep -q UNCONN; then
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
# bench_spin_yggdrasil <tmpdir> <listen_port> <upstream_port> <protocol> [extra_rule_toml]
#
# Spins a two-daemon yggdrasil topology on loopback:
#
#   * gateway (accept-mode): binds the proxy listener on
#     127.0.0.1:$listen_port that the load generator hits. Owns no rules
#     of its own; the listener is derived from the chain predicate
#     published over the dial session.
#   * terminal (dial-mode):  owns the rule set under $tmp/rules and dials
#     the gateway's accept listener on 127.0.0.1:$accept_port. The local
#     echo backend on 127.0.0.1:$upstream_port runs in the same netns,
#     so target_addr resolves there.
#
# Steps:
#   1. write seed configs for gateway + terminal
#   2. mint identity keys for both
#   3. offline request/grant: terminal exports request, gateway mints
#      grant (writes [accept] to gateway config), terminal applies grant
#      (writes [dial] to terminal config)
#   4. write the bench rule under the terminal's rules dir
#   5. start both daemons; wait for the gateway-side proxy listener
#      AND give the heartbeat + chain predicate a moment to settle
#
# Exports:
#   YGG_LISTEN_PORT       — the gateway-side proxy port (loadgen target)
#   YGG_HB_PORT           — the gateway's accept (heartbeat) UDP port
#   YGG_CTRL_SOCK         — the TERMINAL's control socket (rules live here,
#                           so reload/predicate-add scenarios drive it)
#   YGG_CONFIG            — terminal config path
#   YGG_GATEWAY_CONFIG    — gateway config path
#   YGG_GATEWAY_CTRL_SOCK — gateway control socket

bench_spin_yggdrasil() {
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

    # ---- gateway (accept-mode) ----
    local gw_cfg="$tmp/gateway/config.toml"
    local gw_key="$tmp/gateway/identity.key"
    cat > "$gw_cfg" <<EOF
[server]
rules_dir     = "$tmp/gw-rules"
state_dir     = "$tmp/gw-state"
identity_file = "$gw_key"

[control]
socket = "$tmp/gw-run/control.sock"

[accept]
listen = "127.0.0.1:$accept_port"
EOF

    # ---- terminal (dial-mode) ----
    local tm_cfg="$tmp/terminal/config.toml"
    local tm_key="$tmp/terminal/identity.key"
    cat > "$tm_cfg" <<EOF
[server]
rules_dir     = "$tmp/rules"
state_dir     = "$tmp/tm-state"
identity_file = "$tm_key"

[control]
socket = "$tmp/tm-run/control.sock"
EOF

    # Mint identities (yggdrasilctl `identity rotate` writes the key file).
    "$ctl_bin" --config "$gw_cfg" identity rotate \
        --identity-file "$gw_key" --force >/dev/null
    "$ctl_bin" --config "$tm_cfg" identity rotate \
        --identity-file "$tm_key" --force >/dev/null

    # Offline request/grant handshake. Terminal asks; gateway grants.
    "$ctl_bin" --config "$tm_cfg" identity export-request \
        --identity-file "$tm_key" \
        --out "$tmp/request.txt" \
        --note "bench terminal" >/dev/null
    "$ctl_bin" --config "$gw_cfg" identity add-accept \
        --identity-file "$gw_key" \
        --from "$tmp/request.txt" \
        --my-endpoint "127.0.0.1:$accept_port" \
        --out "$tmp/grant.txt" \
        --note "bench gw->tm" >/dev/null
    "$ctl_bin" --config "$tm_cfg" identity add-dial \
        --identity-file "$tm_key" \
        --from "$tmp/grant.txt" >/dev/null
    rm -f "$tmp/request.txt" "$tmp/grant.txt"

    # Bench rule on the terminal. Gateway derives a matching listener via
    # the chain predicate pushed over the dial session.
    cat > "$tmp/rules/scenario.toml" <<EOF
[[rule]]
name        = "bench"
listen      = "127.0.0.1:$listen_port"
protocol    = "$proto"
target_addr = "127.0.0.1:$upstream_port"
$extra
EOF

    bench_spawn YGG_GW_PID "$tmp/logs/gateway.log"  -- "$ygg_bin" --log-format pretty run --config "$gw_cfg"
    bench_spawn YGG_TM_PID "$tmp/logs/terminal.log" -- "$ygg_bin" --log-format pretty run --config "$tm_cfg"

    if [[ "$proto" == "tcp" ]]; then
        bench_wait_listen_tcp 127.0.0.1 "$listen_port" 5
    else
        bench_wait_listen_udp 127.0.0.1 "$listen_port" 5
    fi
    # Give the chain predicate a beat to land + the gateway to record the
    # terminal's source IP from the first heartbeat.
    sleep 0.6

    export YGG_LISTEN_PORT="$listen_port"
    export YGG_HB_PORT="$accept_port"
    export YGG_CTRL_SOCK="$tmp/tm-run/control.sock"
    export YGG_CONFIG="$tm_cfg"
    export YGG_GATEWAY_CONFIG="$gw_cfg"
    export YGG_GATEWAY_CTRL_SOCK="$tmp/gw-run/control.sock"
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

# ---------- loadgen invocation ----------
#
# bench_run_loadgen <subject> <out_json_path> <args...>

bench_run_loadgen() {
    local subject="$1"; local out="$2"; shift 2
    local root
    root="$(bench_workspace_root)"
    local lg="$root/target/release/loadgen"
    [[ -x "$lg" ]] || die "missing $lg — run: cargo build --release -p bench-tools"
    log "loadgen subject=$subject out=$(basename "$out") args: $*"
    "$lg" --subject "$subject" --report-json "$out" "$@"
}
