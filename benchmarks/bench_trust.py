"""Benchmarks for TrustEngine at various scales — includes decay and checkpoint."""

import pytest
from trustchain import MemoryBlockStore, TrustEngine
from benchmarks.data_gen import build_chain, build_star_network


@pytest.mark.parametrize("n_blocks", [100, 1_000, 10_000])
def test_trust_engine_no_seeds(benchmark, n_blocks):
    """TrustEngine.compute_trust without seed nodes."""
    store = MemoryBlockStore()
    blocks = build_chain(store, n_blocks)
    pubkey = blocks[0].public_key

    def compute():
        engine = TrustEngine(store)
        return engine.compute_trust(pubkey)

    benchmark(compute)


@pytest.mark.parametrize("n_agents", [10, 100, 500])
def test_trust_engine_with_seeds(benchmark, n_agents):
    """TrustEngine.compute_trust with seed nodes (enables NetFlow)."""
    store, seed_pk, spoke_pks = build_star_network(n_agents, 3)
    target = spoke_pks[len(spoke_pks) // 2]

    def compute():
        engine = TrustEngine(store, seed_nodes=[seed_pk])
        return engine.compute_trust(target)

    benchmark(compute)


@pytest.mark.parametrize("n_blocks", [100, 1_000, 10_000])
def test_statistical_score(benchmark, n_blocks):
    """Statistical score component only."""
    store = MemoryBlockStore()
    blocks = build_chain(store, n_blocks)
    pubkey = blocks[0].public_key

    def compute():
        engine = TrustEngine(store)
        return engine.compute_statistical_score(pubkey)

    benchmark(compute)


@pytest.mark.parametrize("n_blocks", [100, 1_000, 10_000])
def test_chain_integrity(benchmark, n_blocks):
    """Chain integrity score component."""
    store = MemoryBlockStore()
    blocks = build_chain(store, n_blocks)
    pubkey = blocks[0].public_key

    def compute():
        engine = TrustEngine(store)
        return engine.compute_chain_integrity(pubkey)

    benchmark(compute)


@pytest.mark.parametrize("n_blocks", [100, 1_000, 10_000])
def test_chain_integrity_with_checkpoint(benchmark, n_blocks):
    """Chain integrity with checkpoint covering 90% of blocks."""
    store = MemoryBlockStore()
    blocks = build_chain(store, n_blocks)
    pubkey = blocks[0].public_key

    # Build a simple checkpoint covering 90% of blocks.
    checkpoint_seq = int(n_blocks * 0.9)

    class FakeCheckpoint:
        finalized = True
        chain_heads = {pubkey: checkpoint_seq}

    cp = FakeCheckpoint()

    def compute():
        engine = TrustEngine(store, checkpoint=cp)
        return engine.compute_chain_integrity(pubkey)

    benchmark(compute)


@pytest.mark.parametrize("n_blocks", [100, 1_000, 10_000])
def test_statistical_with_decay(benchmark, n_blocks):
    """Statistical score with temporal decay."""
    store = MemoryBlockStore()
    blocks = build_chain(store, n_blocks)
    pubkey = blocks[0].public_key

    def compute():
        engine = TrustEngine(store, decay_half_life_ms=30_000)
        return engine.compute_statistical_score(pubkey)

    benchmark(compute)


@pytest.mark.parametrize("n_blocks", [100, 1_000, 10_000])
def test_statistical_no_decay(benchmark, n_blocks):
    """Statistical score without temporal decay (baseline)."""
    store = MemoryBlockStore()
    blocks = build_chain(store, n_blocks)
    pubkey = blocks[0].public_key

    def compute():
        engine = TrustEngine(store)
        return engine.compute_statistical_score(pubkey)

    benchmark(compute)
