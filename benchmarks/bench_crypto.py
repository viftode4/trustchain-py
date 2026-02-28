"""Benchmarks for Ed25519 crypto operations."""

import pytest
from trustchain import Identity, HalfBlock, BlockType, create_half_block, GENESIS_HASH


@pytest.fixture
def identity():
    return Identity()


@pytest.fixture
def bob():
    return Identity()


@pytest.fixture
def sample_block(identity, bob):
    return create_half_block(
        identity=identity,
        sequence_number=1,
        link_public_key=bob.pubkey_hex,
        link_sequence_number=0,
        previous_hash=GENESIS_HASH,
        block_type=BlockType.PROPOSAL,
        transaction={"interaction_type": "service", "outcome": "completed"},
        timestamp=1000,
    )


def test_ed25519_sign(benchmark, identity):
    data = b"benchmark payload data for signing"
    benchmark(identity.sign, data)


def test_ed25519_verify(benchmark, identity):
    data = b"benchmark payload data for signing"
    sig = identity.sign(data)
    pubkey = identity.pubkey_bytes
    benchmark(Identity.verify, data, sig, pubkey)


def test_block_create_sign(benchmark, identity, bob):
    def create():
        return create_half_block(
            identity=identity,
            sequence_number=1,
            link_public_key=bob.pubkey_hex,
            link_sequence_number=0,
            previous_hash=GENESIS_HASH,
            block_type=BlockType.PROPOSAL,
            transaction={"interaction_type": "service", "outcome": "completed"},
            timestamp=1000,
        )

    benchmark(create)


def test_block_verify(benchmark, sample_block):
    from trustchain import verify_block

    benchmark(verify_block, sample_block)


def test_identity_generate(benchmark):
    benchmark(Identity)
