"""
Scale simulation: measure trust computation at growing network sizes.

Usage:
    python -m benchmarks.scale_simulation [--max-agents 10000]

Outputs CSV + formatted console table.
"""

import argparse
import csv
import sys
import time
import tracemalloc
from dataclasses import dataclass

from trustchain import Identity, MemoryBlockStore, TrustEngine, NetFlowTrust
from benchmarks.data_gen import build_star_network


@dataclass
class ScaleResult:
    agents: int
    block_count: int
    build_time_s: float
    single_trust_s: float
    all_trust_s: float | None
    peak_memory_mb: float


AGENT_COUNTS = [10, 50, 100, 500, 1_000, 5_000, 10_000]
ALL_SCORES_LIMIT = 1_000  # Skip compute_all_scores above this


def run_scale_test(n_agents: int, interactions_per_agent: int = 3) -> ScaleResult:
    """Run a single scale test for the given agent count."""
    tracemalloc.start()

    # Build network
    t0 = time.perf_counter()
    store, seed_pk, spoke_pks = build_star_network(n_agents, interactions_per_agent)
    build_time = time.perf_counter() - t0

    block_count = store.get_block_count()
    target = spoke_pks[len(spoke_pks) // 2]

    # Single trust computation
    engine = TrustEngine(store, seed_nodes=[seed_pk])
    t0 = time.perf_counter()
    engine.compute_trust(target)
    single_time = time.perf_counter() - t0

    # All scores (skip if too large)
    all_time = None
    if n_agents <= ALL_SCORES_LIMIT:
        netflow = NetFlowTrust(store, seed_nodes=[seed_pk])
        t0 = time.perf_counter()
        netflow.compute_all_scores()
        all_time = time.perf_counter() - t0

    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    peak_mb = peak / (1024 * 1024)

    return ScaleResult(
        agents=n_agents,
        block_count=block_count,
        build_time_s=build_time,
        single_trust_s=single_time,
        all_trust_s=all_time,
        peak_memory_mb=peak_mb,
    )


def format_time(seconds: float | None) -> str:
    if seconds is None:
        return "skipped"
    if seconds < 0.001:
        return f"{seconds * 1_000_000:.0f}us"
    if seconds < 1.0:
        return f"{seconds * 1_000:.1f}ms"
    return f"{seconds:.2f}s"


def print_table(results: list[ScaleResult]):
    header = f"{'Agents':>8} {'Blocks':>8} {'Build':>10} {'Single':>10} {'All':>10} {'Memory':>10}"
    sep = "-" * len(header)
    print(sep)
    print(header)
    print(sep)
    for r in results:
        print(
            f"{r.agents:>8} {r.block_count:>8} "
            f"{format_time(r.build_time_s):>10} "
            f"{format_time(r.single_trust_s):>10} "
            f"{format_time(r.all_trust_s):>10} "
            f"{r.peak_memory_mb:>8.1f}MB"
        )
    print(sep)


def write_csv(results: list[ScaleResult], path: str = "scale_results.csv"):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["agents", "block_count", "build_time_s", "single_trust_s", "all_trust_s", "peak_memory_mb"]
        )
        for r in results:
            writer.writerow([
                r.agents,
                r.block_count,
                f"{r.build_time_s:.6f}",
                f"{r.single_trust_s:.6f}",
                f"{r.all_trust_s:.6f}" if r.all_trust_s is not None else "",
                f"{r.peak_memory_mb:.2f}",
            ])
    print(f"\nCSV written to {path}")


def main():
    parser = argparse.ArgumentParser(description="TrustChain scale simulation")
    parser.add_argument("--max-agents", type=int, default=10_000, help="Maximum agent count to test")
    args = parser.parse_args()

    sizes = [n for n in AGENT_COUNTS if n <= args.max_agents]
    results = []

    print(f"TrustChain Scale Simulation (max {args.max_agents} agents)")
    print(f"compute_all_scores skipped above {ALL_SCORES_LIMIT} agents\n")

    for n in sizes:
        print(f"Testing {n} agents...", end=" ", flush=True)
        try:
            result = run_scale_test(n)
            results.append(result)
            print(f"done ({format_time(result.single_trust_s)} single, {result.peak_memory_mb:.1f}MB)")
        except Exception as e:
            print(f"FAILED: {e}")

    print()
    print_table(results)
    write_csv(results)


if __name__ == "__main__":
    main()
