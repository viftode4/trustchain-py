"""Tests for the TrustChain v2 NetFlow Sybil resistance."""

import pytest

from trustchain.blockstore import MemoryBlockStore
from trustchain.exceptions import NetFlowError
from trustchain.halfblock import GENESIS_HASH, BlockType, create_half_block
from trustchain.identity import Identity
from trustchain.netflow import NetFlowTrust


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
    """Create a proposal+agreement pair and store both."""
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


class TestNetFlowTrust:
    def test_requires_seed_nodes(self):
        store = MemoryBlockStore()
        with pytest.raises(NetFlowError, match="seed node"):
            NetFlowTrust(store, [])

    def test_seed_node_self_trust(self, identity_a):
        store = MemoryBlockStore()
        netflow = NetFlowTrust(store, [identity_a.pubkey_hex])
        score = netflow.compute_path_diversity(identity_a.pubkey_hex)
        assert score == float("inf")  # Seeds return infinity

    def test_unknown_agent_zero_trust(self, identity_a, identity_b):
        store = MemoryBlockStore()
        netflow = NetFlowTrust(store, [identity_a.pubkey_hex])
        assert netflow.compute_path_diversity(identity_b.pubkey_hex) == 0.0

    def test_connected_agent_gets_trust(self, identity_a, identity_b):
        store = MemoryBlockStore()
        _create_transaction_pair(
            store, identity_a, identity_b, 1, 1, GENESIS_HASH, GENESIS_HASH
        )

        netflow = NetFlowTrust(store, [identity_a.pubkey_hex])
        path_div = netflow.compute_path_diversity(identity_b.pubkey_hex)
        assert path_div > 0.0

    def test_transitive_trust(self, identity_a, identity_b, identity_c):
        """A -> B -> C: C should get some path diversity from seed A."""
        store = MemoryBlockStore()

        p_ab, a_ab = _create_transaction_pair(
            store, identity_a, identity_b, 1, 1, GENESIS_HASH, GENESIS_HASH
        )
        _create_transaction_pair(
            store, identity_b, identity_c,
            2, 1, a_ab.block_hash if a_ab.public_key == identity_b.pubkey_hex else p_ab.block_hash,
            GENESIS_HASH,
        )

        netflow = NetFlowTrust(store, [identity_a.pubkey_hex])
        pd_b = netflow.compute_path_diversity(identity_b.pubkey_hex)
        pd_c = netflow.compute_path_diversity(identity_c.pubkey_hex)

        assert pd_b > 0.0
        assert pd_c > 0.0

    def test_sybil_cluster_low_trust(self, identity_a, identity_b, identity_c):
        """Sybil cluster (B<->C with no connection to seed A) gets zero path diversity."""
        store = MemoryBlockStore()

        # B and C interact only with each other
        _create_transaction_pair(
            store, identity_b, identity_c, 1, 1, GENESIS_HASH, GENESIS_HASH
        )

        # A is seed but has no interactions
        netflow = NetFlowTrust(store, [identity_a.pubkey_hex])
        pd_b = netflow.compute_path_diversity(identity_b.pubkey_hex)
        pd_c = netflow.compute_path_diversity(identity_c.pubkey_hex)

        assert pd_b == 0.0
        assert pd_c == 0.0

    def test_compute_all_path_diversities(self, identity_a, identity_b):
        store = MemoryBlockStore()
        _create_transaction_pair(
            store, identity_a, identity_b, 1, 1, GENESIS_HASH, GENESIS_HASH
        )

        netflow = NetFlowTrust(store, [identity_a.pubkey_hex])
        scores = netflow.compute_all_path_diversities()

        assert identity_a.pubkey_hex in scores
        assert identity_b.pubkey_hex in scores
        assert scores[identity_a.pubkey_hex] == float("inf")  # Seed
        assert scores[identity_b.pubkey_hex] > 0.0

    def test_build_contribution_graph(self, identity_a, identity_b):
        store = MemoryBlockStore()
        _create_transaction_pair(
            store, identity_a, identity_b, 1, 1, GENESIS_HASH, GENESIS_HASH
        )

        netflow = NetFlowTrust(store, [identity_a.pubkey_hex])
        graph = netflow.build_contribution_graph()

        assert identity_a.pubkey_hex in graph
        assert identity_b.pubkey_hex in graph[identity_a.pubkey_hex]


class TestMultipleSeeds:
    def test_multiple_seed_nodes(self, identity_a, identity_b, identity_c):
        """Multiple seeds should all have infinite path diversity."""
        store = MemoryBlockStore()
        _create_transaction_pair(
            store, identity_a, identity_b, 1, 1, GENESIS_HASH, GENESIS_HASH
        )

        netflow = NetFlowTrust(store, [identity_a.pubkey_hex, identity_b.pubkey_hex])
        assert netflow.compute_path_diversity(identity_a.pubkey_hex) == float("inf")
        assert netflow.compute_path_diversity(identity_b.pubkey_hex) == float("inf")

    def test_compute_all_path_diversities_uses_batch(self, identity_a, identity_b):
        """compute_all_path_diversities should return scores for all known agents."""
        store = MemoryBlockStore()
        _create_transaction_pair(
            store, identity_a, identity_b, 1, 1, GENESIS_HASH, GENESIS_HASH
        )

        netflow = NetFlowTrust(store, [identity_a.pubkey_hex])
        scores = netflow.compute_all_path_diversities()

        assert len(scores) >= 2
        assert scores[identity_a.pubkey_hex] == float("inf")  # Seed
        assert scores[identity_b.pubkey_hex] > 0.0

class TestPathDiversityBounds:
    def test_non_negative_path_diversity(self, identity_a, identity_b, identity_c):
        """All path diversities should be >= 0."""
        store = MemoryBlockStore()
        p1, a1 = _create_transaction_pair(
            store, identity_a, identity_b, 1, 1, GENESIS_HASH, GENESIS_HASH
        )
        _create_transaction_pair(
            store, identity_b, identity_c, 2, 1, a1.block_hash, GENESIS_HASH
        )

        netflow = NetFlowTrust(store, [identity_a.pubkey_hex])
        for pk in store.get_all_pubkeys():
            score = netflow.compute_path_diversity(pk)
            assert score >= 0.0, f"Score {score} is negative for {pk[:16]}"

    def test_transitive_path_diversity_ordering(self, identity_a, identity_b, identity_c):
        """Closer to seed should have >= path diversity than further."""
        store = MemoryBlockStore()
        p1, a1 = _create_transaction_pair(
            store, identity_a, identity_b, 1, 1, GENESIS_HASH, GENESIS_HASH
        )
        _create_transaction_pair(
            store, identity_b, identity_c, 2, 1, a1.block_hash, GENESIS_HASH
        )

        netflow = NetFlowTrust(store, [identity_a.pubkey_hex])
        pd_b = netflow.compute_path_diversity(identity_b.pubkey_hex)
        pd_c = netflow.compute_path_diversity(identity_c.pubkey_hex)
        assert pd_b >= pd_c

    def test_incremental_cache_update(self, identity_a, identity_b, identity_c):
        """Incremental update adds new edges without full rebuild."""
        store = MemoryBlockStore()
        nf = NetFlowTrust(store, [identity_a.pubkey_hex])

        # First interaction.
        p1, a1 = _create_transaction_pair(store, identity_a, identity_b, 1, 1, GENESIS_HASH, GENESIS_HASH)

        score1 = nf.compute_path_diversity(identity_b.pubkey_hex)
        assert score1 > 0.0
        assert nf._known_seqs.get(identity_a.pubkey_hex) == 1
        assert nf._known_seqs.get(identity_b.pubkey_hex) == 1

        # Add second interaction — should trigger incremental update.
        p2, a2 = _create_transaction_pair(
            store, identity_a, identity_c, 2, 1,
            p1.block_hash, GENESIS_HASH,
        )

        score_c = nf.compute_path_diversity(identity_c.pubkey_hex)
        assert score_c > 0.0
        # Verify known_seqs updated.
        assert nf._known_seqs.get(identity_a.pubkey_hex) == 2
        assert nf._known_seqs.get(identity_c.pubkey_hex) == 1

    def test_incremental_matches_full_rebuild(self, identity_a, identity_b, identity_c):
        """Incremental update produces the same results as a full rebuild."""
        store = MemoryBlockStore()
        nf_incremental = NetFlowTrust(store, [identity_a.pubkey_hex])

        # First interaction — triggers full build.
        p1, a1 = _create_transaction_pair(store, identity_a, identity_b, 1, 1, GENESIS_HASH, GENESIS_HASH)
        nf_incremental.compute_path_diversity(identity_b.pubkey_hex)

        # Second interaction — triggers incremental.
        p2, a2 = _create_transaction_pair(
            store, identity_a, identity_c, 2, 1,
            p1.block_hash, GENESIS_HASH,
        )
        score_b_inc = nf_incremental.compute_path_diversity(identity_b.pubkey_hex)
        score_c_inc = nf_incremental.compute_path_diversity(identity_c.pubkey_hex)

        # Fresh full rebuild for comparison.
        nf_full = NetFlowTrust(store, [identity_a.pubkey_hex])
        score_b_full = nf_full.compute_path_diversity(identity_b.pubkey_hex)
        score_c_full = nf_full.compute_path_diversity(identity_c.pubkey_hex)

        assert abs(score_b_inc - score_b_full) < 1e-9
        assert abs(score_c_inc - score_c_full) < 1e-9
