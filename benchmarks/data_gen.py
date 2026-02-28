"""Shared data generators for Python benchmarks — mirrors Rust helpers."""

from trustchain import (
    Identity,
    MemoryBlockStore,
    BlockStore,
    HalfBlock,
    BlockType,
    create_half_block,
    GENESIS_HASH,
)


def make_identities(n: int) -> list[Identity]:
    """Create n fresh identities."""
    return [Identity() for _ in range(n)]


class ChainState:
    """Tracks (latest_seq, head_hash) per pubkey for incremental chain building."""

    def __init__(self):
        self.latest_seq: dict[str, int] = {}
        self.head_hash: dict[str, str] = {}

    def next_seq(self, pubkey: str) -> int:
        return self.latest_seq.get(pubkey, 0) + 1

    def prev_hash(self, pubkey: str) -> str:
        return self.head_hash.get(pubkey, GENESIS_HASH)

    def update(self, block: HalfBlock):
        self.latest_seq[block.public_key] = block.sequence_number
        self.head_hash[block.public_key] = block.block_hash


def build_chain(store: BlockStore, n: int) -> list[HalfBlock]:
    """Build n proposal+agreement pairs between two identities."""
    alice = Identity()
    bob = Identity()
    state = ChainState()
    blocks = []

    for _ in range(n):
        a_seq = state.next_seq(alice.pubkey_hex)
        a_prev = state.prev_hash(alice.pubkey_hex)
        proposal = create_half_block(
            identity=alice,
            sequence_number=a_seq,
            link_public_key=bob.pubkey_hex,
            link_sequence_number=0,
            previous_hash=a_prev,
            block_type=BlockType.PROPOSAL,
            transaction={"interaction_type": "service", "outcome": "completed"},
            timestamp=1000 + a_seq,
        )
        store.add_block(proposal)
        state.update(proposal)

        b_seq = state.next_seq(bob.pubkey_hex)
        b_prev = state.prev_hash(bob.pubkey_hex)
        agreement = create_half_block(
            identity=bob,
            sequence_number=b_seq,
            link_public_key=alice.pubkey_hex,
            link_sequence_number=a_seq,
            previous_hash=b_prev,
            block_type=BlockType.AGREEMENT,
            transaction={"interaction_type": "service", "outcome": "completed"},
            timestamp=1001 + b_seq,
        )
        store.add_block(agreement)
        state.update(agreement)

        blocks.extend([proposal, agreement])

    return blocks


def build_star_network(
    n_agents: int, interactions_per_agent: int = 2
) -> tuple[MemoryBlockStore, str, list[str]]:
    """Build star topology: one seed with n_agents spokes."""
    seed = Identity()
    seed_pk = seed.pubkey_hex
    agents = [Identity() for _ in range(n_agents)]
    store = MemoryBlockStore()
    state = ChainState()

    for agent in agents:
        agent_pk = agent.pubkey_hex
        for _ in range(interactions_per_agent):
            s_seq = state.next_seq(seed_pk)
            s_prev = state.prev_hash(seed_pk)
            proposal = create_half_block(
                identity=seed,
                sequence_number=s_seq,
                link_public_key=agent_pk,
                link_sequence_number=0,
                previous_hash=s_prev,
                block_type=BlockType.PROPOSAL,
                transaction={"interaction_type": "service", "outcome": "completed"},
                timestamp=1000 + s_seq,
            )
            store.add_block(proposal)
            state.update(proposal)

            a_seq = state.next_seq(agent_pk)
            a_prev = state.prev_hash(agent_pk)
            agreement = create_half_block(
                identity=agent,
                sequence_number=a_seq,
                link_public_key=seed_pk,
                link_sequence_number=s_seq,
                previous_hash=a_prev,
                block_type=BlockType.AGREEMENT,
                transaction={"interaction_type": "service", "outcome": "completed"},
                timestamp=1001 + a_seq,
            )
            store.add_block(agreement)
            state.update(agreement)

    spoke_pks = [a.pubkey_hex for a in agents]
    return store, seed_pk, spoke_pks
