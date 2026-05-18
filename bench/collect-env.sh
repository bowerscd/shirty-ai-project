#!/usr/bin/env bash
# Capture the host's hardware/kernel/network configuration into a JSON file.
# This is recorded alongside every result tree so that comparisons across runs
# can be invalidated automatically if the underlying machine changed.
#
# Usage: bench/collect-env.sh [output_path]
#   default output: bench/results/<sha>/env.json

set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/common.sh
source "$HERE/lib/common.sh"
ensure_results_dir

out="${1:-$(bench_results_dir)/env.json}"
mkdir -p "$(dirname "$out")"

# Try to grab cpu freq governor; missing on non-Linux or some VMs.
governor="unknown"
if [[ -r /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]]; then
    governor="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"
fi

# Sysctl values worth recording — these directly affect UDP/TCP behaviour.
declare -a sysctls=(
    net.core.rmem_max
    net.core.wmem_max
    net.core.rmem_default
    net.core.wmem_default
    net.core.netdev_max_backlog
    net.core.somaxconn
    net.core.busy_poll
    net.core.busy_read
    net.ipv4.tcp_rmem
    net.ipv4.tcp_wmem
    net.ipv4.tcp_no_delay_ack
    net.ipv4.tcp_congestion_control
    net.ipv4.udp_rmem_min
    net.ipv4.udp_wmem_min
    net.ipv4.ip_local_port_range
    net.ipv4.tcp_tw_reuse
)

declare -A sysctl_kv=()
for k in "${sysctls[@]}"; do
    if v="$(sysctl -n "$k" 2>/dev/null)"; then
        sysctl_kv["$k"]="$v"
    fi
done

cpu_model="$(awk -F: '/^model name/ {gsub(/^ */, "", $2); print $2; exit}' /proc/cpuinfo 2>/dev/null || echo unknown)"
cpu_count="$(nproc 2>/dev/null || echo 0)"
mem_kb="$(awk '/^MemTotal/ {print $2; exit}' /proc/meminfo 2>/dev/null || echo 0)"
kernel="$(uname -r)"
distro="$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || echo unknown)"
rustc_v="$(rustc --version 2>/dev/null || echo "rustc unknown")"
nginx_v="$( (nginx -v 2>&1 || echo "nginx unknown") | head -1 )"

# Build the sysctl object as a JSON literal so we don't need jq.
sysctl_json="{"
first=1
for k in "${!sysctl_kv[@]}"; do
    if (( first )); then first=0; else sysctl_json+=","; fi
    # Escape backslashes and double quotes in the value.
    safe="${sysctl_kv[$k]//\\/\\\\}"
    safe="${safe//\"/\\\"}"
    # TAB characters in tcp_rmem etc. — replace with single spaces.
    safe="${safe//	/ }"
    sysctl_json+="\"$k\":\"$safe\""
done
sysctl_json+="}"

cat > "$out" <<EOF
{
  "captured_at_unix": $(date -u +%s),
  "captured_at_iso":  "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "git_sha":          "${BENCH_SHA:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}",
  "host": {
    "kernel":     "$kernel",
    "distro":     "$distro",
    "cpu_model":  "$cpu_model",
    "cpu_count":  $cpu_count,
    "mem_kb":     $mem_kb,
    "governor":   "$governor"
  },
  "toolchain": {
    "rustc": "$rustc_v",
    "nginx": "$nginx_v"
  },
  "sysctl": $sysctl_json
}
EOF

log "wrote env snapshot to $out"
log "governor=$governor (must be 'performance' for trustworthy numbers)"
