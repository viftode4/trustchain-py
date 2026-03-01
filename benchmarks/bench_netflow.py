"""Benchmarks for NetFlowTrust — uncached vs cached graph, star + mesh topologies."""

import pytest
from trustchain import MemoryBlockStore, NetFlowTrust
from benchmarks.data_gen import build_star_network, build_mesh_network


# ---------------------------------------------------------------------------
# Uncached: single compute_trust — star topology
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("n_agents", [50, 500, 2_000])
def test_netflow_single(benchmark, n_agents):
    """Single compute_trust call (graph rebuilt each call)."""
    store, seed_pk, spoke_pks = build_star_network(n_agents, 3)
    target = spoke_pks[len(spoke_pks) // 2]
    netflow = NetFlowTrust(store, seed_nodes=[seed_pk])
    # Invalidate between runs to measure full rebuild cost.
    def run():
        netflow.invalidate_cache()
        return netflow.compute_trust(target)
    benchmark(run)


# ---------------------------------------------------------------------------
# Uncached: compute_all_scores — star
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("n_agents", [50, 200, 1_000])
def test_netflow_all_scores(benchmark, n_agents):
    """compute_all_scores (graph rebuilt each call)."""
    store, seed_pk, _ = build_star_network(n_agents, 3)
    netflow = NetFlowTrust(store, seed_nodes=[seed_pk])
    def run():
        netflow.invalidate_cache()
        return netflow.compute_all_scores()
    benchmark(run)


# ---------------------------------------------------------------------------
# Uncached: mesh topology (denser, harder for max-flow)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("n_agents,degree", [(50, 5), (200, 4), (500, 3)])
def test_netflow_mesh(benchmark, n_agents, degree):
    """Single compute_trust on mesh topology."""
    store, pubkeys = build_mesh_network(n_agents, degree, 3)
    target = pubkeys[len(pubkeys) // 2]
    netflow = NetFlowTrust(store, seed_nodes=[pubkeys[0]])
    def run():
        netflow.invalidate_cache()
        return netflow.compute_trust(target)
    benchmark(run)


# ---------------------------------------------------------------------------
# Cached: single compute_trust — star (warm cache, no graph rebuild)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("n_agents", [50, 500, 2_000])
def test_netflow_cached_single(benchmark, n_agents):
    """Single compute_trust with warm graph cache."""
    store, seed_pk, spoke_pks = build_star_network(n_agents, 3)
    target = spoke_pks[len(spoke_pks) // 2]
    netflow = NetFlowTrust(store, seed_nodes=[seed_pk])
    # Warm up.
    netflow.compute_trust(target)
    benchmark(netflow.compute_trust, target)


# ---------------------------------------------------------------------------
# Cached: compute_all_scores — star (graph reused)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("n_agents", [50, 200, 1_000])
def test_netflow_cached_all_scores(benchmark, n_agents):
    """compute_all_scores with warm graph cache."""
    store, seed_pk, _ = build_star_network(n_agents, 3)
    netflow = NetFlowTrust(store, seed_nodes=[seed_pk])
    netflow.compute_all_scores()
    benchmark(netflow.compute_all_scores)


# ---------------------------------------------------------------------------
# Large-scale single query (pedantic mode, fewer rounds)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("n_agents", [5_000])
def test_netflow_single_large(benchmark, n_agents):
    """Single trust computation at 5K agents (uncached)."""
    store, seed_pk, spoke_pks = build_star_network(n_agents, 2)
    target = spoke_pks[len(spoke_pks) // 2]
    netflow = NetFlowTrust(store, seed_nodes=[seed_pk])
    def run():
        netflow.invalidate_cache()
        return netflow.compute_trust(target)
    benchmark.pedantic(run, rounds=5, iterations=1)


@pytest.mark.parametrize("n_agents", [5_000])
def test_netflow_cached_single_large(benchmark, n_agents):
    """Single trust computation at 5K agents (cached)."""
    store, seed_pk, spoke_pks = build_star_network(n_agents, 2)
    target = spoke_pks[len(spoke_pks) // 2]
    netflow = NetFlowTrust(store, seed_nodes=[seed_pk])
    netflow.compute_trust(target)
    benchmark.pedantic(netflow.compute_trust, args=(target,), rounds=5, iterations=1)
