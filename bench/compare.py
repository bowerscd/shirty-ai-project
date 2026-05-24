#!/usr/bin/env python3
"""Compare bench/results/<sha>/ trees, or aggregate rotated runs.

Usage:
    # Diff two single runs:
    bench/compare.py <baseline_dir> <candidate_dir>
    bench/compare.py --baseline=BASE --candidate=CAND [--fail-on-regress=PCT]

    # Aggregate N rotated runs into a position-corrected view:
    bench/compare.py --rotations bench/results/<sha>-rot1 ... <sha>-rotN

Exit codes:
    0 — no regression / no SLO failure
    1 — at least one scenario regressed or failed an SLO check
    2 — invalid input (missing files, malformed JSON, etc.)

A "regression" is a candidate metric that is *worse* than baseline by more than
the threshold (default 5%). Direction of "worse" is metric-specific:

    pps_rx, bytes_per_sec_rx, tx_packets   → higher is better → regression = drop
    loss_pct, p50, p99, p999, mean         → lower is better  → regression = rise

When invoked with `--check-{nginx,haproxy,traefik}`, the SLO checks
emit a row per (scenario, metric, peer) for each direction — both
"yggdrasil within budget of peer" AND "peer within budget of
yggdrasil". An imbalance in one direction is a fact about the bench
or the proxies; flagging only one direction would hide overclaims.
"""
from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


HIGHER_BETTER = {
    "pps_rx",
    "pps_tx",
    "bytes_per_sec_rx",
    "bytes_per_sec_tx",
    "tx_packets",
    "rx_packets",
}
LOWER_BETTER = {
    "loss_pct",
    "proxy_rss_kib",
    "latency.min",
    "latency.p50",
    "latency.p90",
    "latency.p99",
    "latency.p999",
    "latency.max",
    "latency.mean",
}

# Plan §11.5 acceptable deltas vs nginx (yggdrasil should be within these).
NGINX_DELTA_BUDGET = {
    # scenario : (metric, max_pct_worse)
    ("tcp-throughput",  "bytes_per_sec_rx"): 10,
    ("tcp-connrate",    "pps_rx"):           25,
    ("udp-pps",         "pps_rx"):           20,
    ("udp-flows",       "pps_rx"):           20,
    ("udp-flowchurn",   "pps_rx"):           20,
    # Per-connection memory: nginx's event-loop model is hard to beat, so
    # we budget at most a 2× (100% above) absolute PSS footprint.
    ("tcp-idle-conns",  "proxy_rss_kib"):    100,
}
# p99 must be ≤ 2× nginx for these (i.e. up to 100% worse is allowed)
NGINX_P99_BUDGET_PCT = 100

# HAProxy comparison — TCP scenarios only (HAProxy has no generic UDP L4
# forwarder). Same budget shape as nginx; HAProxy is L4-only but otherwise
# in the same ballpark as nginx stream, so the deltas should hold.
HAPROXY_DELTA_BUDGET = {
    ("tcp-throughput",  "bytes_per_sec_rx"): 10,
    ("tcp-connrate",    "pps_rx"):           25,
    ("tcp-idle-conns",  "proxy_rss_kib"):    100,
}
HAPROXY_P99_BUDGET_PCT = 100

# Traefik comparison — covers both TCP and UDP (Traefik 3.x supports both
# at L4). Same budget shape as nginx.
TRAEFIK_DELTA_BUDGET = {
    ("tcp-throughput",  "bytes_per_sec_rx"): 10,
    ("tcp-connrate",    "pps_rx"):           25,
    ("udp-pps",         "pps_rx"):           20,
    ("udp-flows",       "pps_rx"):           20,
    ("udp-flowchurn",   "pps_rx"):           20,
    ("tcp-idle-conns",  "proxy_rss_kib"):    100,
}
TRAEFIK_P99_BUDGET_PCT = 100


@dataclass
class Report:
    path:    Path
    scenario: str
    subject:  str
    stats:    Dict[str, float]
    latency:  Optional[Dict[str, float]]

    @classmethod
    def load(cls, p: Path) -> "Report":
        with p.open() as f:
            data = json.load(f)
        stats = data.get("stats", {})
        return cls(
            path=p,
            scenario=data["scenario"],
            subject=data["subject"],
            stats={k: v for k, v in stats.items() if isinstance(v, (int, float))},
            latency=stats.get("latency_us"),
        )

    def metric(self, key: str) -> Optional[float]:
        if key.startswith("latency."):
            if not self.latency:
                return None
            return self.latency.get(key.split(".", 1)[1])
        return self.stats.get(key)


def collect(dirpath: Path) -> Dict[Tuple[str, str], Report]:
    out: Dict[Tuple[str, str], Report] = {}
    for f in sorted(dirpath.glob("*.json")):
        if f.name == "env.json":
            continue
        try:
            r = Report.load(f)
        except (KeyError, json.JSONDecodeError) as e:
            print(f"warn: skipping malformed {f}: {e}", file=sys.stderr)
            continue
        out[(r.scenario, r.subject)] = r
    return out


def pct_change(baseline: float, candidate: float) -> float:
    if baseline == 0:
        return 0.0
    return (candidate - baseline) / baseline * 100.0


def is_regression(metric: str, pct: float, threshold: float) -> bool:
    if metric in HIGHER_BETTER:
        return pct < -threshold      # candidate dropped
    if metric in LOWER_BETTER:
        return pct > threshold       # candidate rose
    return False


def diff_runs(base: Dict[Tuple[str, str], Report],
              cand: Dict[Tuple[str, str], Report],
              threshold_pct: float) -> Tuple[List[str], List[str]]:
    """Returns (rows, regression_msgs)."""
    rows: List[str] = []
    regressions: List[str] = []

    metrics: Iterable[str] = (
        "pps_rx", "bytes_per_sec_rx", "loss_pct", "proxy_rss_kib",
        "latency.p50", "latency.p99", "latency.p999", "latency.mean",
    )

    rows.append(f"{'scenario':<18} {'subject':<10} {'metric':<22} "
                f"{'baseline':>14} {'candidate':>14} {'Δ%':>8}")
    rows.append("-" * 90)

    for key in sorted(set(base) | set(cand)):
        scenario, subject = key
        b = base.get(key)
        c = cand.get(key)
        if b is None:
            rows.append(f"{scenario:<18} {subject:<10} {'(new in candidate)':<22}")
            continue
        if c is None:
            rows.append(f"{scenario:<18} {subject:<10} {'(missing in candidate)':<22}")
            regressions.append(f"missing candidate result: {scenario}/{subject}")
            continue
        for m in metrics:
            bv = b.metric(m)
            cv = c.metric(m)
            if bv is None or cv is None:
                continue
            pct = pct_change(bv, cv)
            marker = ""
            if is_regression(m, pct, threshold_pct):
                marker = "  ← REGRESSION"
                regressions.append(
                    f"{scenario}/{subject}: {m} {bv:.2f} → {cv:.2f} ({pct:+.1f}%)"
                )
            rows.append(f"{scenario:<18} {subject:<10} {m:<22} "
                        f"{bv:>14.2f} {cv:>14.2f} {pct:>7.1f}%{marker}")
    return rows, regressions


def _check_pair_deltas(
    cand: Dict[Tuple[str, str], Report],
    ygg_subject: str,
    peer_subject: str,
    delta_budget: Dict[Tuple[str, str], float],
    p99_budget_pct: float,
) -> List[str]:
    """Within a single candidate run, ensure `ygg_subject` and `peer_subject`
    are within budget of each other across all scenarios both ran.

    Checks BOTH directions — emits a failure if either subject is more
    than budget% worse than the other on any metric. The original
    one-directional check only flagged yggdrasil underperformance,
    which silently hid the case where yggdrasil's "win" was actually a
    bench-harness artifact rather than a real proxy property. A
    symmetric check forces both directions to be investigated.

    Returns one failure string per metric-budget violation. Scenarios where
    either subject didn't run are silently skipped — that's how haproxy stays
    out of UDP scenarios and how either side stays out of scenarios it doesn't
    target, without a special case.
    """
    failures: List[str] = []
    scenarios = {scenario for (scenario, _subject) in cand}
    for scenario in sorted(scenarios):
        ygg = cand.get((scenario, ygg_subject))
        peer = cand.get((scenario, peer_subject))
        if not ygg or not peer:
            continue
        # Primary throughput / pps metric.
        for (sc, metric), budget_pct in delta_budget.items():
            if sc != scenario:
                continue
            ygg_v = ygg.metric(metric)
            peer_v = peer.metric(metric)
            if ygg_v is None or peer_v is None or peer_v == 0 or ygg_v == 0:
                continue
            if metric in LOWER_BETTER:
                # Lower-is-better: each side is "worse" when ABOVE the other.
                ygg_above_peer = (ygg_v - peer_v) / peer_v * 100.0
                if ygg_above_peer > budget_pct:
                    failures.append(
                        f"{scenario}: {ygg_subject} {metric}={ygg_v:.2f} is {ygg_above_peer:.1f}% "
                        f"above {peer_subject} ({peer_v:.2f}); budget allows {budget_pct}%"
                    )
                peer_above_ygg = (peer_v - ygg_v) / ygg_v * 100.0
                if peer_above_ygg > budget_pct:
                    failures.append(
                        f"{scenario}: {peer_subject} {metric}={peer_v:.2f} is {peer_above_ygg:.1f}% "
                        f"above {ygg_subject} ({ygg_v:.2f}); budget allows {budget_pct}% "
                        f"(reverse-direction check)"
                    )
            else:
                # Higher-is-better: each side is "worse" when BELOW the other.
                ygg_below_peer = (peer_v - ygg_v) / peer_v * 100.0
                if ygg_below_peer > budget_pct:
                    failures.append(
                        f"{scenario}: {ygg_subject} {metric}={ygg_v:.2f} is {ygg_below_peer:.1f}% "
                        f"below {peer_subject} ({peer_v:.2f}); budget allows {budget_pct}%"
                    )
                peer_below_ygg = (ygg_v - peer_v) / ygg_v * 100.0
                if peer_below_ygg > budget_pct:
                    failures.append(
                        f"{scenario}: {peer_subject} {metric}={peer_v:.2f} is {peer_below_ygg:.1f}% "
                        f"below {ygg_subject} ({ygg_v:.2f}); budget allows {budget_pct}% "
                        f"(reverse-direction check)"
                    )
        # p99 latency budget — also bidirectional.
        if ygg.latency and peer.latency:
            ygg_p99 = ygg.latency.get("p99")
            peer_p99 = peer.latency.get("p99")
            if ygg_p99 and peer_p99 and peer_p99 > 0 and ygg_p99 > 0:
                ygg_above_pct = (ygg_p99 - peer_p99) / peer_p99 * 100.0
                if ygg_above_pct > p99_budget_pct:
                    failures.append(
                        f"{scenario}: {ygg_subject} p99={ygg_p99:.2f}us is "
                        f"{ygg_above_pct:.0f}% above {peer_subject} p99 ({peer_p99:.2f}us); "
                        f"budget allows {p99_budget_pct}%"
                    )
                peer_above_pct = (peer_p99 - ygg_p99) / ygg_p99 * 100.0
                if peer_above_pct > p99_budget_pct:
                    failures.append(
                        f"{scenario}: {peer_subject} p99={peer_p99:.2f}us is "
                        f"{peer_above_pct:.0f}% above {ygg_subject} p99 ({ygg_p99:.2f}us); "
                        f"budget allows {p99_budget_pct}% (reverse-direction check)"
                    )
    return failures


def check_nginx_deltas(cand: Dict[Tuple[str, str], Report]) -> List[str]:
    # Two apples-to-apples pairings: single-hop terminal vs nginx, and
    # full chain vs nginx-chain. Same budget table applies to both, since
    # per-hop costs should match regardless of chain length.
    failures = _check_pair_deltas(
        cand, "yggdrasil-terminal", "nginx", NGINX_DELTA_BUDGET, NGINX_P99_BUDGET_PCT
    )
    failures += _check_pair_deltas(
        cand, "yggdrasil-chain", "nginx-chain", NGINX_DELTA_BUDGET, NGINX_P99_BUDGET_PCT
    )
    return failures


def check_haproxy_deltas(cand: Dict[Tuple[str, str], Report]) -> List[str]:
    failures = _check_pair_deltas(
        cand, "yggdrasil-terminal", "haproxy", HAPROXY_DELTA_BUDGET, HAPROXY_P99_BUDGET_PCT
    )
    failures += _check_pair_deltas(
        cand, "yggdrasil-chain", "haproxy-chain", HAPROXY_DELTA_BUDGET, HAPROXY_P99_BUDGET_PCT
    )
    return failures


def check_traefik_deltas(cand: Dict[Tuple[str, str], Report]) -> List[str]:
    failures = _check_pair_deltas(
        cand, "yggdrasil-terminal", "traefik", TRAEFIK_DELTA_BUDGET, TRAEFIK_P99_BUDGET_PCT
    )
    failures += _check_pair_deltas(
        cand, "yggdrasil-chain", "traefik-chain", TRAEFIK_DELTA_BUDGET, TRAEFIK_P99_BUDGET_PCT
    )
    return failures


def aggregate_rotations(dirs: List[Path]) -> int:
    """Read N rotation dirs (each `bench/results/<sha>-rotN/`), aggregate
    per-(scenario, subject, metric) statistics, and print the table.

    Output is mean ± stdev for each combo, plus the count of rotations
    that successfully produced a value (helps spot broken-bench cases
    where one rotation failed to emit a result).
    """
    if not dirs:
        print("error: --rotations requires at least one directory", file=sys.stderr)
        return 2
    # rotation_results[i] = {(scenario, subject): Report}
    rotations: List[Dict[Tuple[str, str], Report]] = []
    for d in dirs:
        if not d.is_dir():
            print(f"error: rotation dir {d} not found", file=sys.stderr)
            return 2
        rotations.append(collect(d))

    # Collect (scenario, subject) keys seen in ANY rotation.
    all_keys: List[Tuple[str, str]] = sorted({
        key for rot in rotations for key in rot.keys()
    })

    # Metrics we report. The throughput-style metrics are stats-level;
    # the latency metrics are nested under stats.latency_us. We use the
    # `Report.metric()` accessor which handles both.
    METRICS = [
        ("pps_rx",            "pps"),
        ("bytes_per_sec_rx",  "B/s"),
        ("loss_pct",          "%"),
        ("latency.p50",       "us"),
        ("latency.p99",       "us"),
        ("latency.p999",      "us"),
        ("proxy_rss_kib",     "KiB"),
    ]

    # Group output by scenario for readability.
    by_scenario: Dict[str, List[Tuple[str, str]]] = {}
    for (scenario, subject) in all_keys:
        by_scenario.setdefault(scenario, []).append((scenario, subject))

    print(f"# Aggregated across {len(rotations)} rotation(s):")
    for d in dirs:
        print(f"#   {d}")
    print()

    for scenario, keys in sorted(by_scenario.items()):
        # Pick the metrics this scenario actually produces (skip the
        # ones every rotation has as None).
        scenario_metrics = []
        for metric, _unit in METRICS:
            has_any = any(
                rot.get((scenario, subject)) and rot[(scenario, subject)].metric(metric) is not None
                for rot in rotations
                for (_, subject) in keys
            )
            if has_any:
                scenario_metrics.append(metric)
        if not scenario_metrics:
            continue

        print(f"## {scenario}")
        # Header.
        col_metric_w = max(len(m) for m in scenario_metrics)
        print(
            f"  {'subject':<22}  {'metric':<{col_metric_w}}  "
            f"{'n':>3}  {'mean':>14}  {'stdev':>14}  {'min':>14}  {'max':>14}"
        )
        print(
            f"  {'-'*22}  {'-'*col_metric_w}  {'-'*3}  "
            f"{'-'*14}  {'-'*14}  {'-'*14}  {'-'*14}"
        )
        for (sc, subject) in keys:
            for metric in scenario_metrics:
                vals = []
                for rot in rotations:
                    r = rot.get((sc, subject))
                    if r is None:
                        continue
                    v = r.metric(metric)
                    if v is None:
                        continue
                    vals.append(v)
                if not vals:
                    continue
                n = len(vals)
                mean = statistics.mean(vals)
                stdev = statistics.stdev(vals) if n >= 2 else 0.0
                vmin, vmax = min(vals), max(vals)
                cov = (stdev / mean * 100.0) if mean else 0.0
                # Mark high-variance cells so a reader knows where the
                # bench is noisy enough that the mean is unreliable.
                note = "  *high-variance" if cov > 20 else ""
                print(
                    f"  {subject:<22}  {metric:<{col_metric_w}}  "
                    f"{n:>3}  {mean:>14,.2f}  {stdev:>14,.2f}  "
                    f"{vmin:>14,.2f}  {vmax:>14,.2f}{note}"
                )
        print()

    # Position-corrected SLO checks: for each yggdrasil-vs-peer pair,
    # check the symmetric budget using the mean across rotations as
    # the canonical value. This is what closes the run-order-bias gap.
    print()
    return _rotation_slo_check(rotations)


def _rotation_slo_check(rotations: List[Dict[Tuple[str, str], Report]]) -> int:
    """Run the symmetric SLO checks against the per-(scenario, subject)
    mean computed from the rotation set. Returns 0 if everything's
    within budget, 1 otherwise.
    """
    # Build a synthetic "mean" report set the same shape as
    # `collect()` would return, so we can reuse the existing
    # `_check_pair_deltas` machinery.
    all_keys: List[Tuple[str, str]] = sorted({
        key for rot in rotations for key in rot.keys()
    })
    mean_set: Dict[Tuple[str, str], Report] = {}
    for (scenario, subject) in all_keys:
        # Aggregate stats and latency dicts independently.
        agg_stats: Dict[str, List[float]] = {}
        agg_lat: Dict[str, List[float]] = {}
        any_report: Optional[Report] = None
        for rot in rotations:
            r = rot.get((scenario, subject))
            if r is None:
                continue
            any_report = r
            for k, v in r.stats.items():
                agg_stats.setdefault(k, []).append(v)
            if r.latency:
                for k, v in r.latency.items():
                    agg_lat.setdefault(k, []).append(v)
        if not any_report:
            continue
        mean_set[(scenario, subject)] = Report(
            path=any_report.path,
            scenario=scenario,
            subject=subject,
            stats={k: statistics.mean(vs) for k, vs in agg_stats.items() if vs},
            latency=({k: statistics.mean(vs) for k, vs in agg_lat.items() if vs}
                     if agg_lat else None),
        )

    failures: List[str] = []
    for peer, budgets, p99_b in (
        ("nginx",   NGINX_DELTA_BUDGET,   NGINX_P99_BUDGET_PCT),
        ("haproxy", HAPROXY_DELTA_BUDGET, HAPROXY_P99_BUDGET_PCT),
        ("traefik", TRAEFIK_DELTA_BUDGET, TRAEFIK_P99_BUDGET_PCT),
    ):
        for ygg, peer_subject in (
            ("yggdrasil-terminal", peer),
            ("yggdrasil-chain",    f"{peer}-chain"),
        ):
            pair_fails = _check_pair_deltas(mean_set, ygg, peer_subject, budgets, p99_b)
            if pair_fails:
                print(f"{peer} SLO check ({ygg} vs {peer_subject}, position-corrected):")
                for f in pair_fails:
                    print(f"  FAIL: {f}")
                failures.extend(pair_fails)
    if not failures:
        print("position-corrected SLO check: all within budget (both directions)")
    return 0 if not failures else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("baseline", nargs="?", type=Path)
    ap.add_argument("candidate", nargs="?", type=Path)
    ap.add_argument("--baseline", dest="baseline_opt", type=Path)
    ap.add_argument("--candidate", dest="candidate_opt", type=Path)
    ap.add_argument("--fail-on-regress", type=float, default=5.0,
                    help="threshold percentage (default 5)")
    ap.add_argument("--check-nginx", action="store_true",
                    help="also check yggdrasil-vs-nginx SLO deltas (bidirectional)")
    ap.add_argument("--check-haproxy", action="store_true",
                    help="also check yggdrasil-vs-haproxy SLO deltas (TCP only, bidirectional)")
    ap.add_argument("--check-traefik", action="store_true",
                    help="also check yggdrasil-vs-traefik SLO deltas (TCP + UDP, bidirectional)")
    ap.add_argument("--rotations", nargs="+", type=Path, default=None,
                    help="aggregate N rotation dirs (mean ± stdev per metric, "
                         "position-corrected SLO check). Bypasses baseline/candidate.")
    args = ap.parse_args()

    # Rotation aggregation mode — independent of baseline/candidate.
    if args.rotations:
        return aggregate_rotations(args.rotations)

    base_dir = args.baseline_opt or args.baseline
    cand_dir = args.candidate_opt or args.candidate
    if not base_dir or not cand_dir:
        ap.error("baseline and candidate paths are required (or use --rotations)")

    if not base_dir.is_dir():
        print(f"error: baseline dir {base_dir} not found", file=sys.stderr)
        return 2
    if not cand_dir.is_dir():
        print(f"error: candidate dir {cand_dir} not found", file=sys.stderr)
        return 2

    base = collect(base_dir)
    cand = collect(cand_dir)
    rows, regressions = diff_runs(base, cand, args.fail_on_regress)
    for r in rows:
        print(r)

    failures: List[str] = list(regressions)
    if args.check_nginx:
        nginx_failures = check_nginx_deltas(cand)
        if nginx_failures:
            print("\nnginx SLO check:")
            for f in nginx_failures:
                print(f"  FAIL: {f}")
            failures.extend(nginx_failures)
        else:
            print("\nnginx SLO check: all within budget")
    if args.check_haproxy:
        haproxy_failures = check_haproxy_deltas(cand)
        if haproxy_failures:
            print("\nhaproxy SLO check:")
            for f in haproxy_failures:
                print(f"  FAIL: {f}")
            failures.extend(haproxy_failures)
        else:
            print("\nhaproxy SLO check: all within budget")
    if args.check_traefik:
        traefik_failures = check_traefik_deltas(cand)
        if traefik_failures:
            print("\ntraefik SLO check:")
            for f in traefik_failures:
                print(f"  FAIL: {f}")
            failures.extend(traefik_failures)
        else:
            print("\ntraefik SLO check: all within budget")

    if failures:
        print(f"\n{len(failures)} failure(s):", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print("\nno regressions detected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
