"""Tests for Layer 6.1: Requester reputation (PeerTrust, Xiong & Liu 2004).

compute_requester_trust() evaluates an agent from the requester perspective:
payment reliability, rating fairness, dispute rate.
"""

from __future__ import annotations

from trustchain.blockstore import MemoryBlockStore
from trustchain.halfblock import BlockType, create_half_block
from trustchain.identity import Identity
from trustchain.trust import TrustEngine

GENESIS = "0" * 64


def _create_bilateral(
    store: MemoryBlockStore,
    proposer: Identity,
    responder: Identity,
    p_seq: int,
    r_seq: int,
    p_prev: str,
    r_prev: str,
    p_tx: dict,
    r_tx: dict,
    ts: int = 1000,
) -> tuple[str, str]:
    """Create a bilateral interaction with separate proposer/responder tx."""
    proposal = create_half_block(
        proposer, p_seq, responder.pubkey_hex, 0, p_prev,
        BlockType.PROPOSAL, p_tx, ts,
    )
    store.add_block(proposal)

    agreement = create_half_block(
        responder, r_seq, proposer.pubkey_hex, p_seq, r_prev,
        BlockType.AGREEMENT, r_tx, ts + 1,
    )
    store.add_block(agreement)
    return proposal.block_hash, agreement.block_hash


class TestRequesterTrust:
    """Layer 6.1: compute_requester_trust()."""

    def test_no_interactions(self):
        store = MemoryBlockStore()
        engine = TrustEngine(store)

        evidence = engine.compute_requester_trust("unknown")

        assert evidence["requester_trust"] is not None
        assert evidence["payment_reliability"] == 1.0  # benefit of doubt
        assert evidence["rating_fairness"] is None  # insufficient data
        assert evidence["dispute_rate"] == 0.0

    def test_good_requester(self):
        store = MemoryBlockStore()
        requester = Identity()
        provider = Identity()

        req_prev = GENESIS
        prov_prev = GENESIS
        for i in range(5):
            rh, ph = _create_bilateral(
                store, requester, provider,
                i + 1, i + 1, req_prev, prov_prev,
                {"outcome": "completed", "quality": 0.9},
                {"outcome": "completed", "quality": 0.9},
                ts=1000 + i * 100,
            )
            req_prev, prov_prev = rh, ph

        engine = TrustEngine(store)
        evidence = engine.compute_requester_trust(requester.pubkey_hex)

        assert evidence["requester_trust"] is not None
        assert evidence["requester_trust"] > 0.3
        assert evidence["payment_reliability"] > 0.8
        assert evidence["dispute_rate"] == 0.0

    def test_bad_payer(self):
        store = MemoryBlockStore()
        requester = Identity()
        provider = Identity()

        req_prev = GENESIS
        prov_prev = GENESIS
        for i in range(5):
            rh, ph = _create_bilateral(
                store, requester, provider,
                i + 1, i + 1, req_prev, prov_prev,
                {"outcome": "completed", "quality": 0.9},
                {"outcome": "failed", "quality": 0.1},
                ts=1000 + i * 100,
            )
            req_prev, prov_prev = rh, ph

        engine = TrustEngine(store)
        evidence = engine.compute_requester_trust(requester.pubkey_hex)

        assert evidence["payment_reliability"] < 0.3

    def test_high_dispute_rate(self):
        store = MemoryBlockStore()
        requester = Identity()
        provider = Identity()

        req_prev = GENESIS
        prov_prev = GENESIS
        for i in range(5):
            rh, ph = _create_bilateral(
                store, requester, provider,
                i + 1, i + 1, req_prev, prov_prev,
                {"outcome": "completed"},
                {"outcome": "disputed"},
                ts=1000 + i * 100,
            )
            req_prev, prov_prev = rh, ph

        engine = TrustEngine(store)
        evidence = engine.compute_requester_trust(requester.pubkey_hex)

        assert evidence["dispute_rate"] > 0.8

    def test_fields_none_in_standard(self):
        store = MemoryBlockStore()
        alice = Identity()
        bob = Identity()

        _create_bilateral(
            store, alice, bob, 1, 1, GENESIS, GENESIS,
            {"outcome": "completed"}, {"outcome": "completed"},
        )

        engine = TrustEngine(store)
        evidence = engine.compute_trust_with_evidence(alice.pubkey_hex)

        assert evidence["requester_trust"] is None
        assert evidence["payment_reliability"] is None
        assert evidence["rating_fairness"] is None
        assert evidence["dispute_rate"] is None

    def test_rating_fairness_insufficient_data(self):
        store = MemoryBlockStore()
        requester = Identity()
        provider = Identity()

        req_prev = GENESIS
        prov_prev = GENESIS
        for i in range(3):
            rh, ph = _create_bilateral(
                store, requester, provider,
                i + 1, i + 1, req_prev, prov_prev,
                {"outcome": "completed", "quality": 0.9, "requester_rating": 0.9},
                {"outcome": "completed", "quality": 0.9},
                ts=1000 + i * 100,
            )
            req_prev, prov_prev = rh, ph

        engine = TrustEngine(store)
        evidence = engine.compute_requester_trust(requester.pubkey_hex)

        # Only 1 unique provider rated — below 3-provider threshold.
        assert evidence["rating_fairness"] is None
