"""Tests for the TrustChain v2 TrustEngine."""

import pytest

from trustchain.blockstore import MemoryBlockStore
from trustchain.halfblock import GENESIS_HASH, BlockType, create_half_block
from trustchain.identity import Identity
from trustchain.trust import TrustEngine


@pytest.fixture
def identity_a():
    return Identity()


@pytest.fixture
def identity_b():
    return Identity()


@pytest.fixture
def identity_c():
    return Identity()


def _create_transaction_pair(store, id_a, id_b, seq_a, seq_b, prev_a, prev_b):
    proposal = create_half_block(
        identity=id_a,
        sequence_number=seq_a,
        link_public_key=id_b.pubkey_hex,
        link_sequence_number=0,
        previous_hash=prev_a,
        block_type=BlockType.PROPOSAL,
        transaction={"interaction_type": "service", "outcome": "completed"},
    )
    store.add_block(proposal)

    agreement = create_half_block(
        identity=id_b,
        sequence_number=seq_b,
        link_public_key=id_a.pubkey_hex,
        link_sequence_number=seq_a,
        previous_hash=prev_b,
        block_type=BlockType.AGREEMENT,
        transaction={"interaction_type": "service", "outcome": "completed"},
    )
    store.add_block(agreement)

    return proposal, agreement


class TestTrustEngine:
    def test_empty_store(self, identity_a):
        store = MemoryBlockStore()
        engine = TrustEngine(store)
        trust = engine.compute_trust(identity_a.pubkey_hex)
        # Empty chain -> integrity=1.0. No netflow -> integrity only.
        assert trust == 1.0

    def test_trust_with_seeds_increases(self, identity_a, identity_b):
        """With seeds configured, interactions create NetFlow → trust increases."""
        store = MemoryBlockStore()
        # identity_a is the seed — initially, identity_b has no interactions.
        engine = TrustEngine(store, seed_nodes=[identity_a.pubkey_hex])

        trust_before = engine.compute_trust(identity_b.pubkey_hex)
        assert trust_before == 0.0  # No interactions → no NetFlow → 0

        prev_a, prev_b = GENESIS_HASH, GENESIS_HASH
        for i in range(1, 6):
            p, a = _create_transaction_pair(
                store, identity_a, identity_b,
                i, i, prev_a, prev_b,
            )
            prev_a = p.block_hash
            prev_b = a.block_hash

        trust_after = engine.compute_trust(identity_b.pubkey_hex)
        assert trust_after > 0.0  # Now has NetFlow path from seed

    def test_chain_integrity_perfect(self, identity_a, identity_b):
        store = MemoryBlockStore()
        engine = TrustEngine(store)

        prev_a, prev_b = GENESIS_HASH, GENESIS_HASH
        for i in range(1, 4):
            p, a = _create_transaction_pair(
                store, identity_a, identity_b,
                i, i, prev_a, prev_b,
            )
            prev_a = p.block_hash
            prev_b = a.block_hash

        assert engine.compute_chain_integrity(identity_a.pubkey_hex) == 1.0

    def test_chain_integrity_empty(self, identity_a):
        store = MemoryBlockStore()
        engine = TrustEngine(store)
        assert engine.compute_chain_integrity(identity_a.pubkey_hex) == 1.0

    def test_with_seed_nodes(self, identity_a, identity_b):
        store = MemoryBlockStore()
        engine = TrustEngine(store, seed_nodes=[identity_a.pubkey_hex])

        prev_a, prev_b = GENESIS_HASH, GENESIS_HASH
        for i in range(1, 4):
            p, a = _create_transaction_pair(
                store, identity_a, identity_b,
                i, i, prev_a, prev_b,
            )
            prev_a = p.block_hash
            prev_b = a.block_hash

        trust_a = engine.compute_trust(identity_a.pubkey_hex)
        trust_b = engine.compute_trust(identity_b.pubkey_hex)
        assert trust_a > 0.0
        assert trust_b > 0.0

    def test_netflow_score_without_seeds(self, identity_a):
        store = MemoryBlockStore()
        engine = TrustEngine(store)  # No seed nodes
        assert engine.compute_netflow_score(identity_a.pubkey_hex) == 0.0

    def test_custom_weights(self, identity_a, identity_b):
        store = MemoryBlockStore()
        engine = TrustEngine(
            store,
            weights={"integrity": 0.5, "netflow": 0.5},
        )

        p, a = _create_transaction_pair(
            store, identity_a, identity_b,
            1, 1, GENESIS_HASH, GENESIS_HASH,
        )

        trust = engine.compute_trust(identity_a.pubkey_hex)
        assert 0.0 <= trust <= 1.0

    def test_trust_increases_with_interactions_no_seeds(self, identity_a, identity_b):
        """Without seed nodes, trust = integrity (always 1.0 for valid chains)."""
        store = MemoryBlockStore()
        engine = TrustEngine(store)

        prev_a, prev_b = GENESIS_HASH, GENESIS_HASH
        for i in range(1, 4):
            p, a = _create_transaction_pair(
                store, identity_a, identity_b,
                i, i, prev_a, prev_b,
            )
            prev_a = p.block_hash
            prev_b = a.block_hash

        trust = engine.compute_trust(identity_a.pubkey_hex)
        assert trust == 1.0  # Valid chain, no seeds -> integrity only
