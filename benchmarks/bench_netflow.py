"""Benchmarks for NetFlowTrust (Edmonds-Karp max-flow) — includes graph caching."""

import pytest
from trustchain import MemoryBlockStore, NetFlowTrust
from benchmarks.data_gen import build_star_network


@pytest.mark.parametrize("n_agents", [10, 50, 100, 500])
def test_netflow_single(benchmark, n_agents):
    """Single compute_trust call at various network sizes."""
    store, seed_pk, spoke_pks = build_star_network(n_agents, 2)
    target = spoke_pks[len(spoke_pks) // 2]
    netflow = NetFlowTrust(store, seed_nodes=[seed_pk])

    benchmark(netflow.compute_trust, target)


@pytest.mark.parametrize("n_agents", [10, 50, 100])
def test_netflow_all_scores(benchmark, n_agents):
    """compute_all_scores at various network sizes."""
    store, seed_pk, spoke_pks = build_star_network(n_agents, 2)
    netflow = NetFlowTrust(store, seed_nodes=[seed_pk])

    benchmark(netflow.compute_all_scores)


@pytest.mark.parametrize("n_agents", [1_000])
def test_netflow_single_large(benchmark, n_agents):
    """Single trust computation at 1K agents."""
    store, seed_pk, spoke_pks = build_star_network(n_agents, 2)
    target = spoke_pks[len(spoke_pks) // 2]
    netflow = NetFlowTrust(store, seed_nodes=[seed_pk])

    benchmark.pedantic(netflow.compute_trust, args=(target,), rounds=5, iterations=1)


@pytest.mark.parametrize("n_agents", [10, 50, 100, 500])
def test_netflow_cached_single(benchmark, n_agents):
    """Single compute_trust with graph caching (warm cache)."""
    store, seed_pk, spoke_pks = build_star_network(n_agents, 2)
    target = spoke_pks[len(spoke_pks) // 2]
    netflow = NetFlowTrust(store, seed_nodes=[seed_pk])

    # Warm up the cache.
    netflow.compute_trust(target)

    benchmark(netflow.compute_trust, target)


@pytest.mark.parametrize("n_agents", [10, 50, 100])
def test_netflow_cached_all_scores(benchmark, n_agents):
    """compute_all_scores with graph caching (warm cache)."""
    store, seed_pk, spoke_pks = build_star_network(n_agents, 2)
    netflow = NetFlowTrust(store, seed_nodes=[seed_pk])

    # Warm up the cache.
    netflow.compute_all_scores()

    benchmark(netflow.compute_all_scores)
