"""Benchmarks for TrustEngine — integrity, netflow, checkpoint."""

import pytest
from trustchain import MemoryBlockStore, TrustEngine
from benchmarks.data_gen import build_chain, build_star_network


# ---------------------------------------------------------------------------
# Full TrustEngine.compute_trust — no seeds
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("n_blocks", [500, 5_000, 50_000])
def test_trust_engine_no_seeds(benchmark, n_blocks):
    store = MemoryBlockStore()
    blocks = build_chain(store, n_blocks)
    pubkey = blocks[0].public_key
    def compute():
        engine = TrustEngine(store)
        return engine.compute_trust(pubkey)
    benchmark(compute)


# ---------------------------------------------------------------------------
# Full TrustEngine.compute_trust — with seeds (enables NetFlow)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("n_agents", [50, 500, 2_000])
def test_trust_engine_with_seeds(benchmark, n_agents):
    store, seed_pk, spoke_pks = build_star_network(n_agents, 3)
    target = spoke_pks[len(spoke_pks) // 2]
    def compute():
        engine = TrustEngine(store, seed_nodes=[seed_pk])
        return engine.compute_trust(target)
    benchmark(compute)


# ---------------------------------------------------------------------------
# Chain integrity — no checkpoint (full Ed25519 verification)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("n_blocks", [500, 5_000, 50_000])
def test_chain_integrity(benchmark, n_blocks):
    store = MemoryBlockStore()
    blocks = build_chain(store, n_blocks)
    pubkey = blocks[0].public_key
    def compute():
        engine = TrustEngine(store)
        return engine.compute_chain_integrity(pubkey)
    benchmark(compute)


# ---------------------------------------------------------------------------
# Chain integrity — checkpoint covering 90%
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("n_blocks", [500, 5_000, 50_000])
def test_chain_integrity_checkpoint_90pct(benchmark, n_blocks):
    store = MemoryBlockStore()
    blocks = build_chain(store, n_blocks)
    pubkey = blocks[0].public_key

    class FakeCheckpoint:
        finalized = True
        chain_heads = {pubkey: int(n_blocks * 0.9)}

    cp = FakeCheckpoint()
    def compute():
        engine = TrustEngine(store, checkpoint=cp)
        return engine.compute_chain_integrity(pubkey)
    benchmark(compute)


# ---------------------------------------------------------------------------
# Chain integrity — checkpoint covering 99%
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("n_blocks", [500, 5_000, 50_000])
def test_chain_integrity_checkpoint_99pct(benchmark, n_blocks):
    store = MemoryBlockStore()
    blocks = build_chain(store, n_blocks)
    pubkey = blocks[0].public_key

    class FakeCheckpoint:
        finalized = True
        chain_heads = {pubkey: int(n_blocks * 0.99)}

    cp = FakeCheckpoint()
    def compute():
        engine = TrustEngine(store, checkpoint=cp)
        return engine.compute_chain_integrity(pubkey)
    benchmark(compute)
