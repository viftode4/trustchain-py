"""Benchmarks for BlockStore implementations (Memory vs SQLite)."""

import os
import tempfile

import pytest
from trustchain import (
    Identity,
    MemoryBlockStore,
    SQLiteBlockStore,
    BlockType,
    create_half_block,
    GENESIS_HASH,
)
from benchmarks.data_gen import build_chain


@pytest.fixture
def prebuilt_blocks():
    """Pre-create 1000 blocks for insert benchmarks."""
    alice = Identity()
    bob = Identity()
    blocks = []
    prev_hash = GENESIS_HASH
    for seq in range(1, 1001):
        block = create_half_block(
            identity=alice,
            sequence_number=seq,
            link_public_key=bob.pubkey_hex,
            link_sequence_number=0,
            previous_hash=prev_hash,
            block_type=BlockType.PROPOSAL,
            transaction={"interaction_type": "service"},
            timestamp=1000 + seq,
        )
        prev_hash = block.block_hash
        blocks.append(block)
    return blocks, alice.pubkey_hex


def test_memory_insert_1000(benchmark, prebuilt_blocks):
    """Insert 1000 blocks into MemoryBlockStore."""
    blocks, _ = prebuilt_blocks

    def insert():
        store = MemoryBlockStore()
        for b in blocks:
            store.add_block(b)

    benchmark(insert)


def test_sqlite_insert_1000(benchmark, prebuilt_blocks):
    """Insert 1000 blocks into SQLiteBlockStore."""
    blocks, _ = prebuilt_blocks

    def insert():
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            path = f.name
        try:
            store = SQLiteBlockStore(path)
            for b in blocks:
                store.add_block(b)
            store.close()
        finally:
            os.unlink(path)

    benchmark(insert)


def test_memory_get_chain_1000(benchmark, prebuilt_blocks):
    """get_chain on 1000-block MemoryBlockStore."""
    blocks, pubkey = prebuilt_blocks
    store = MemoryBlockStore()
    for b in blocks:
        store.add_block(b)

    benchmark(store.get_chain, pubkey)


def test_sqlite_get_chain_1000(benchmark, prebuilt_blocks):
    """get_chain on 1000-block SQLiteBlockStore."""
    blocks, pubkey = prebuilt_blocks
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    try:
        store = SQLiteBlockStore(path)
        for b in blocks:
            store.add_block(b)

        benchmark(store.get_chain, pubkey)
        store.close()
    finally:
        os.unlink(path)


def test_memory_get_linked_block(benchmark):
    """get_linked_block lookups on MemoryBlockStore."""
    store = MemoryBlockStore()
    blocks = build_chain(store, 100)
    # Get an agreement block to look up its linked proposal
    agreement = blocks[1]  # second block is an agreement

    benchmark(store.get_linked_block, agreement)
