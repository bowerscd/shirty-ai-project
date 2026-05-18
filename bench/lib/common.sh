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
# We use minimal Python echo servers because they're trivial to write and the
# bench is bottlenecked by the proxy under test, not the echo backend.
# For pure throughput (where the echo CAN become the bottleneck) the per-
# scenario script can swap to a Rust echo via `bench/_helpers/echo`.

# Spawn a UDP echo on 127.0.0.1:$port. Writes PID into named var.
bench_spawn_udp_echo() {
    local __pidvar="$1" port="$2" logfile="$3"
    local script
    script="$(bench_workspace_root)/bench/lib/echo_udp.py"
    bench_spawn "$__pidvar" "$logfile" -- python3 "$script" "$port"
    bench_wait_listen_udp 127.0.0.1 "$port" 3
}

# Spawn a TCP echo on 127.0.0.1:$port. Writes PID into named var.
bench_spawn_tcp_echo() {
    local __pidvar="$1" port="$2" logfile="$3"
    local script
    script="$(bench_workspace_root)/bench/lib/echo_tcp.py"
    bench_spawn "$__pidvar" "$logfile" -- python3 "$script" "$port"
    bench_wait_listen_tcp 127.0.0.1 "$port" 3
}

# ---------- yggdrasil stack orchestration ----------
#
# bench_spin_yggdrasil <tmpdir> <listen_port> <upstream_port> <protocol> [extra_branch_toml]
#
# Builds and runs the full yggdrasil + ratatoskr stack:
#   1. keygen both
#   2. enroll-token + enroll
#   3. write configs and branch
#   4. start yggdrasil + ratatoskr in background
#   5. wait until the proxy listener is up AND ratatoskr has heartbeat'd through
#
# Exports:
#   YGG_LISTEN_PORT, YGG_HB_PORT, YGG_CTRL_SOCK, YGG_CONFIG, RAT_CONFIG

bench_spin_yggdrasil() {
    local tmp="$1"; local listen_port="$2"; local upstream_port="$3"; local proto="$4"
    local extra="${5:-}"
    local root
    root="$(bench_workspace_root)"

    local ygg_bin="$root/target/release/yggdrasil"
    local rat_bin="$root/target/release/ratatoskr"
    [[ -x "$ygg_bin" ]] || die "missing $ygg_bin — run: cargo build --release -p yggdrasil"
    [[ -x "$rat_bin" ]] || die "missing $rat_bin — run: cargo build --release -p ratatoskr"

    mkdir -p "$tmp"/{yggdrasil,ratatoskr,branches,state,run,logs}
    local hb_port; hb_port="$(pick_free_udp_port)"
    local metrics_port; metrics_port="$(pick_free_tcp_port)"

    # Keys.
    "$ygg_bin" keygen --identity-file "$tmp/yggdrasil/identity.key" >/dev/null
    "$rat_bin" keygen --identity-file "$tmp/ratatoskr/identity.key" >/dev/null

    local rat_pub
    rat_pub="$("$rat_bin" pubkey --identity-file "$tmp/ratatoskr/identity.key" | tr -d '\r\n[:space:]')"

    # Write yggdrasil config FIRST (peer.public_key_hex empty for now).
    cat > "$tmp/yggdrasil/config.toml" <<EOF
[server]
heartbeat_listen = "127.0.0.1:$hb_port"
branches_dir = "$tmp/branches"
state_dir = "$tmp/state"
identity_file = "$tmp/yggdrasil/identity.key"

[metrics]
listen = "127.0.0.1:$metrics_port"

[control]
socket = "$tmp/run/control.sock"

[peer]
public_key_hex = ""
rekey_interval = "1h"
EOF

    # Mint enrollment token. This stamps peer.public_key_hex into the config.
    "$ygg_bin" enroll-token \
        --peer-pubkey "$rat_pub" \
        --endpoint "127.0.0.1:$hb_port" \
        --config "$tmp/yggdrasil/config.toml" \
        -o "$tmp/enroll.token" --force >/dev/null

    # Ratatoskr config skeleton + enroll applies the server pubkey + endpoint.
    cat > "$tmp/ratatoskr/config.toml" <<EOF
[client]
yggdrasil_endpoint = "placeholder:1"
yggdrasil_pubkey_hex = "0000000000000000000000000000000000000000000000000000000000000000"
identity_file = "$tmp/ratatoskr/identity.key"
heartbeat_interval = "200ms"
rekey_interval = "1h"
EOF
    "$rat_bin" enroll "$tmp/enroll.token" --config "$tmp/ratatoskr/config.toml" >/dev/null

    # Branch file.
    cat > "$tmp/branches/scenario.toml" <<EOF
[[rule]]
name = "bench"
listen = "127.0.0.1:$listen_port"
protocol = "$proto"
upstream_port = $upstream_port
$extra
EOF

    bench_spawn YGG_PID  "$tmp/logs/yggdrasil.log" -- "$ygg_bin"  --log-format pretty run --config "$tmp/yggdrasil/config.toml"
    bench_spawn RAT_PID  "$tmp/logs/ratatoskr.log" -- "$rat_bin" --log-format pretty run --config "$tmp/ratatoskr/config.toml"

    if [[ "$proto" == "tcp" ]]; then
        bench_wait_listen_tcp 127.0.0.1 "$listen_port" 5
    else
        bench_wait_listen_udp 127.0.0.1 "$listen_port" 5
    fi
    # Give ratatoskr a couple of heartbeats so the proxy has the peer IP.
    sleep 0.6

    export YGG_LISTEN_PORT="$listen_port" YGG_HB_PORT="$hb_port" YGG_CTRL_SOCK="$tmp/run/control.sock"
    export YGG_CONFIG="$tmp/yggdrasil/config.toml" RAT_CONFIG="$tmp/ratatoskr/config.toml"
}

# ---------- nginx orchestration ----------
#
# bench_spin_nginx <tmpdir> <listen_port> <upstream_port> <protocol>
#
# Renders an nginx.conf with a single `stream {}` block proxying to the echo
# backend, starts nginx with `-p $tmp -c nginx.conf`, and waits for the
# listener to come up.

bench_spin_nginx() {
    local tmp="$1"; local listen_port="$2"; local upstream_port="$3"; local proto="$4"
    local nginx_bin
    nginx_bin="${BENCH_NGINX:-$(command -v nginx || true)}"
    [[ -x "$nginx_bin" ]] || die "nginx binary not found; set BENCH_NGINX=/path/to/nginx or install nginx"

    mkdir -p "$tmp/nginx/logs"
    local udp_kw=""
    [[ "$proto" == "udp" ]] && udp_kw="udp"
    cat > "$tmp/nginx/nginx.conf" <<EOF
worker_processes auto;
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
    [[ -x "$lg" ]] || die "missing $lg — run: cargo build --release -p loadgen"
    log "loadgen subject=$subject out=$(basename "$out") args: $*"
    "$lg" --subject "$subject" --report-json "$out" "$@"
}
