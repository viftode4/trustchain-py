import networkx as nx
import pytest

from trustchain.block import GENESIS_HASH
from trustchain.record import create_record
from trustchain.store import RecordStore
from trustchain.trust import (
    compute_chain_trust,
    compute_transitive_trust,
    compute_trust,
    compute_trust_with_decay,
)


def _single_completed_record(identity_a, identity_b) -> tuple[RecordStore, int]:
    store = RecordStore()
    record = create_record(
        identity_a=identity_a,
        identity_b=identity_b,
        seq_a=0,
        seq_b=0,
        prev_hash_a=GENESIS_HASH,
        prev_hash_b=GENESIS_HASH,
        interaction_type="service",
        outcome="completed",
    )
    store.add_record(record)
    return store, record.timestamp


def test_compute_trust_preserves_full_precision(identity_a, identity_b):
    store, _ = _single_completed_record(identity_a, identity_b)

    trust = compute_trust(identity_a.pubkey_hex, store)

    assert trust == pytest.approx(0.3025, abs=1e-12)
    assert trust != pytest.approx(0.302, abs=1e-12)


def test_compute_trust_with_decay_preserves_full_precision(identity_a, identity_b):
    store, timestamp = _single_completed_record(identity_a, identity_b)

    trust = compute_trust_with_decay(identity_a.pubkey_hex, store, now=timestamp)

    assert trust == pytest.approx(0.3025, abs=1e-12)
    assert trust != pytest.approx(0.302, abs=1e-12)


def test_compute_chain_trust_preserves_full_precision(identity_a, identity_b, monkeypatch):
    store, _ = _single_completed_record(identity_a, identity_b)

    monkeypatch.setattr("trustchain.chain.compute_chain_integrity", lambda pubkey, records: 0.5)

    trust = compute_chain_trust(identity_a.pubkey_hex, store)

    expected = 0.3025 * (1.0 - 0.15 * (1.0 - 0.5))
    assert trust == pytest.approx(expected, abs=1e-12)
    assert trust != pytest.approx(round(expected, 3), abs=1e-12)


class _DummyStore:
    def __init__(self, graph: nx.DiGraph):
        self._graph = graph

    def get_interaction_graph(self) -> nx.DiGraph:
        return self._graph


def test_compute_transitive_trust_preserves_full_precision(monkeypatch):
    graph = nx.DiGraph()
    graph.add_edge("agent-a", "agent-b", weight=1.0)
    store = _DummyStore(graph)

    pagerank = {"agent-a": 0.1234567, "agent-b": 0.9876543}
    monkeypatch.setattr("trustchain.trust.nx.pagerank", lambda *_args, **_kwargs: pagerank)

    trust = compute_transitive_trust("agent-a", store)
    expected = pagerank["agent-a"] / pagerank["agent-b"]

    assert trust == pytest.approx(expected, abs=1e-12)
    assert trust != pytest.approx(round(expected, 3), abs=1e-12)
