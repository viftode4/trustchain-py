"""Benchmarks for propose/agree protocol cycle."""

import pytest
from trustchain import Identity, MemoryBlockStore, TrustChainProtocol


def test_propose_agree_single(benchmark):
    """Single propose/agree cycle."""
    alice_id = Identity()
    bob_id = Identity()

    def cycle():
        alice = TrustChainProtocol(alice_id, MemoryBlockStore())
        bob = TrustChainProtocol(bob_id, MemoryBlockStore())
        proposal = alice.create_proposal(
            bob_id.pubkey_hex,
            {"interaction_type": "service", "outcome": "completed"},
        )
        bob.receive_proposal(proposal)
        agreement = bob.create_agreement(proposal)
        alice.receive_agreement(agreement)

    benchmark(cycle)


def test_propose_agree_100_sequential(benchmark):
    """100 sequential propose/agree cycles."""
    alice_id = Identity()
    bob_id = Identity()

    def run_100():
        alice = TrustChainProtocol(alice_id, MemoryBlockStore())
        bob = TrustChainProtocol(bob_id, MemoryBlockStore())
        for _ in range(100):
            proposal = alice.create_proposal(
                bob_id.pubkey_hex,
                {"interaction_type": "service", "outcome": "completed"},
            )
            bob.receive_proposal(proposal)
            agreement = bob.create_agreement(proposal)
            alice.receive_agreement(agreement)

    benchmark(run_100)
