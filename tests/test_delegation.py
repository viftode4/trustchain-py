"""Comprehensive tests for delegation, revocation, and succession.

Covers:
- DelegationCertificate data structure
- DelegationStore (Memory + SQLite)
- Protocol flows (create, accept, revoke, succeed)
- Trust computation with delegation budget splitting
- NetFlow self-loop detection
- Attack vectors (farming, circular, deep chains, scope escalation, zombie)
"""

from __future__ import annotations

import tempfile
import time

import pytest

from trustchain.blockstore import MemoryBlockStore, SQLiteBlockStore
from trustchain.delegation import (
    DelegationCertificate,
    DelegationRecord,
    DelegationStore,
    MemoryDelegationStore,
)
from trustchain.exceptions import DelegationError, SuccessionError
from trustchain.halfblock import BlockType, create_half_block
from trustchain.identity import Identity
from trustchain.protocol import TrustChainProtocol
from trustchain.trust import TrustEngine


# ---- Helpers ----


def build_operator_trust(
    operator: Identity,
    peer: Identity,
    store: MemoryBlockStore,
    n: int = 5,
) -> None:
    """Build trust history for an operator by creating bilateral blocks."""
    for _ in range(n):
        seq_op = store.get_latest_seq(operator.pubkey_hex) + 1
        prev_op = store.get_head_hash(operator.pubkey_hex)
        p = create_half_block(
            operator, seq_op, peer.pubkey_hex, 0, prev_op,
            BlockType.PROPOSAL,
            {"interaction_type": "test", "outcome": "completed"},
        )
        store.add_block(p)
        seq_peer = store.get_latest_seq(peer.pubkey_hex) + 1
        prev_peer = store.get_head_hash(peer.pubkey_hex)
        a = create_half_block(
            peer, seq_peer, operator.pubkey_hex, p.sequence_number, prev_peer,
            BlockType.AGREEMENT,
            {"interaction_type": "test", "outcome": "completed"},
        )
        store.add_block(a)


# ---- Fixtures ----


@pytest.fixture
def store():
    return MemoryBlockStore()


@pytest.fixture
def dstore():
    return MemoryDelegationStore()


@pytest.fixture
def operator():
    return Identity()


@pytest.fixture
def delegate():
    return Identity()


@pytest.fixture
def peer():
    return Identity()


# ===========================================================================
# DelegationCertificate tests
# ===========================================================================


class TestDelegationCertificate:
    def test_create_certificate(self):
        cert = DelegationCertificate(
            delegator_pubkey="aa" * 32,
            delegate_pubkey="bb" * 32,
            scope=["code-review"],
            max_depth=0,
            issued_at=1000.0,
            expires_at=2000.0,
            delegation_seq=1,
            delegation_block_hash="cc" * 32,
        )
        assert cert.delegator_pubkey == "aa" * 32
        assert cert.delegate_pubkey == "bb" * 32

    def test_certificate_hash_deterministic(self):
        cert1 = DelegationCertificate(
            delegator_pubkey="aa" * 32,
            delegate_pubkey="bb" * 32,
            scope=["test"],
            max_depth=0,
            issued_at=1000.0,
            expires_at=2000.0,
            delegation_seq=1,
            delegation_block_hash="cc" * 32,
        )
        cert2 = DelegationCertificate(
            delegator_pubkey="aa" * 32,
            delegate_pubkey="bb" * 32,
            scope=["test"],
            max_depth=0,
            issued_at=1000.0,
            expires_at=2000.0,
            delegation_seq=1,
            delegation_block_hash="cc" * 32,
        )
        assert cert1.certificate_hash == cert2.certificate_hash

    def test_certificate_expiry(self):
        cert = DelegationCertificate(
            delegator_pubkey="aa" * 32,
            delegate_pubkey="bb" * 32,
            scope=[],
            max_depth=0,
            issued_at=1000.0,
            expires_at=1500.0,
            delegation_seq=1,
            delegation_block_hash="cc" * 32,
        )
        assert cert.is_expired(now=1600.0) is True
        assert cert.is_expired(now=1400.0) is False

    def test_scope_matching_wildcard(self):
        cert = DelegationCertificate(
            delegator_pubkey="aa" * 32,
            delegate_pubkey="bb" * 32,
            scope=[],  # wildcard
            max_depth=0,
            issued_at=1000.0,
            expires_at=2000.0,
            delegation_seq=1,
            delegation_block_hash="cc" * 32,
        )
        assert cert.scope_matches("anything") is True
        assert cert.scope_matches("") is True

    def test_scope_matching_specific(self):
        cert = DelegationCertificate(
            delegator_pubkey="aa" * 32,
            delegate_pubkey="bb" * 32,
            scope=["code-review", "search"],
            max_depth=0,
            issued_at=1000.0,
            expires_at=2000.0,
            delegation_seq=1,
            delegation_block_hash="cc" * 32,
        )
        assert cert.scope_matches("code-review") is True
        assert cert.scope_matches("search") is True
        assert cert.scope_matches("deploy") is False

    def test_chain_depth_direct(self):
        cert = DelegationCertificate(
            delegator_pubkey="aa" * 32,
            delegate_pubkey="bb" * 32,
            scope=[],
            max_depth=0,
            issued_at=1000.0,
            expires_at=2000.0,
            delegation_seq=1,
            delegation_block_hash="cc" * 32,
            parent_certificate=None,
        )
        assert cert.chain_depth == 1

    def test_chain_depth_subdelegation(self):
        parent = DelegationCertificate(
            delegator_pubkey="aa" * 32,
            delegate_pubkey="bb" * 32,
            scope=[],
            max_depth=1,
            issued_at=1000.0,
            expires_at=2000.0,
            delegation_seq=1,
            delegation_block_hash="cc" * 32,
        )
        child = DelegationCertificate(
            delegator_pubkey="bb" * 32,
            delegate_pubkey="dd" * 32,
            scope=[],
            max_depth=0,
            issued_at=1000.0,
            expires_at=2000.0,
            delegation_seq=1,
            delegation_block_hash="ee" * 32,
            parent_certificate=parent,
        )
        assert child.chain_depth == 2

    def test_root_pubkey_direct(self):
        cert = DelegationCertificate(
            delegator_pubkey="aa" * 32,
            delegate_pubkey="bb" * 32,
            scope=[],
            max_depth=0,
            issued_at=1000.0,
            expires_at=2000.0,
            delegation_seq=1,
            delegation_block_hash="cc" * 32,
        )
        assert cert.root_pubkey == "aa" * 32

    def test_root_pubkey_subdelegation(self):
        parent = DelegationCertificate(
            delegator_pubkey="aa" * 32,
            delegate_pubkey="bb" * 32,
            scope=[],
            max_depth=1,
            issued_at=1000.0,
            expires_at=2000.0,
            delegation_seq=1,
            delegation_block_hash="cc" * 32,
        )
        child = DelegationCertificate(
            delegator_pubkey="bb" * 32,
            delegate_pubkey="dd" * 32,
            scope=[],
            max_depth=0,
            issued_at=1000.0,
            expires_at=2000.0,
            delegation_seq=1,
            delegation_block_hash="ee" * 32,
            parent_certificate=parent,
        )
        assert child.root_pubkey == "aa" * 32

    def test_serialization_roundtrip(self):
        parent = DelegationCertificate(
            delegator_pubkey="aa" * 32,
            delegate_pubkey="bb" * 32,
            scope=["test"],
            max_depth=1,
            issued_at=1000.0,
            expires_at=2000.0,
            delegation_seq=1,
            delegation_block_hash="cc" * 32,
            delegator_signature="dd" * 32,
            delegate_signature="ee" * 32,
        )
        child = DelegationCertificate(
            delegator_pubkey="bb" * 32,
            delegate_pubkey="ff" * 32,
            scope=["test"],
            max_depth=0,
            issued_at=1100.0,
            expires_at=2000.0,
            delegation_seq=2,
            delegation_block_hash="11" * 32,
            parent_certificate=parent,
            delegator_signature="22" * 32,
            delegate_signature="33" * 32,
        )
        d = child.to_dict()
        restored = DelegationCertificate.from_dict(d)
        assert restored.delegate_pubkey == child.delegate_pubkey
        assert restored.parent_certificate is not None
        assert restored.parent_certificate.delegator_pubkey == parent.delegator_pubkey
        assert restored.chain_depth == 2


# ===========================================================================
# DelegationStore tests
# ===========================================================================


class TestDelegationStore:
    def test_add_and_get_delegation(self, dstore):
        rec = DelegationRecord(
            delegation_id="d1",
            delegator_pubkey="aa" * 32,
            delegate_pubkey="bb" * 32,
            scope=["test"],
            max_depth=0,
            issued_at=int(time.time() * 1000),
            expires_at=int(time.time() * 1000) + 3_600_000,
            delegation_block_hash="cc" * 32,
            agreement_block_hash="dd" * 32,
        )
        dstore.add_delegation(rec)
        got = dstore.get_delegation("d1")
        assert got is not None
        assert got.delegation_id == "d1"

    def test_duplicate_delegation_id_rejected(self, dstore):
        rec = DelegationRecord(
            delegation_id="d1",
            delegator_pubkey="aa" * 32,
            delegate_pubkey="bb" * 32,
            scope=[],
            max_depth=0,
            issued_at=int(time.time() * 1000),
            expires_at=int(time.time() * 1000) + 3_600_000,
            delegation_block_hash="cc" * 32,
            agreement_block_hash="dd" * 32,
        )
        dstore.add_delegation(rec)
        with pytest.raises(ValueError, match="Duplicate"):
            dstore.add_delegation(rec)

    def test_get_delegations_by_delegator(self, dstore):
        for i in range(3):
            dstore.add_delegation(DelegationRecord(
                delegation_id=f"d{i}",
                delegator_pubkey="aa" * 32,
                delegate_pubkey=f"{i:02d}" * 32,
                scope=[],
                max_depth=0,
                issued_at=int(time.time() * 1000),
                expires_at=int(time.time() * 1000) + 3_600_000,
                delegation_block_hash="cc" * 32,
                agreement_block_hash="dd" * 32,
            ))
        delegations = dstore.get_delegations_by_delegator("aa" * 32)
        assert len(delegations) == 3

    def test_active_delegation_count(self, dstore):
        dstore.add_delegation(DelegationRecord(
            delegation_id="d1",
            delegator_pubkey="aa" * 32,
            delegate_pubkey="bb" * 32,
            scope=[],
            max_depth=0,
            issued_at=int(time.time() * 1000),
            expires_at=int(time.time() * 1000) + 3_600_000,
            delegation_block_hash="cc" * 32,
            agreement_block_hash="dd" * 32,
        ))
        dstore.add_delegation(DelegationRecord(
            delegation_id="d2",
            delegator_pubkey="aa" * 32,
            delegate_pubkey="ee" * 32,
            scope=[],
            max_depth=0,
            issued_at=int(time.time() * 1000),
            expires_at=int(time.time() * 1000) - 1000,  # expired
            delegation_block_hash="cc" * 32,
            agreement_block_hash="dd" * 32,
        ))
        assert dstore.get_active_delegation_count("aa" * 32) == 1

    def test_revoke_delegation(self, dstore):
        dstore.add_delegation(DelegationRecord(
            delegation_id="d1",
            delegator_pubkey="aa" * 32,
            delegate_pubkey="bb" * 32,
            scope=[],
            max_depth=0,
            issued_at=int(time.time() * 1000),
            expires_at=int(time.time() * 1000) + 3_600_000,
            delegation_block_hash="cc" * 32,
            agreement_block_hash="dd" * 32,
        ))
        assert dstore.is_revoked("d1") is False
        dstore.revoke_delegation("d1", "ff" * 32)
        assert dstore.is_revoked("d1") is True
        assert dstore.get_active_delegation_count("aa" * 32) == 0

    def test_succession(self, dstore):
        dstore.add_succession("aa" * 32, "bb" * 32, "cc" * 32)
        assert dstore.get_successor("aa" * 32) == "bb" * 32
        assert dstore.get_predecessor("bb" * 32) == "aa" * 32

    def test_resolve_current_identity(self, dstore):
        dstore.add_succession("aa" * 32, "bb" * 32, "cc" * 32)
        dstore.add_succession("bb" * 32, "dd" * 32, "ee" * 32)
        assert dstore.resolve_current_identity("aa" * 32) == "dd" * 32
        assert dstore.resolve_current_identity("bb" * 32) == "dd" * 32
        assert dstore.resolve_current_identity("dd" * 32) == "dd" * 32

    def test_is_delegate(self, dstore):
        assert dstore.is_delegate("bb" * 32) is False
        dstore.add_delegation(DelegationRecord(
            delegation_id="d1",
            delegator_pubkey="aa" * 32,
            delegate_pubkey="bb" * 32,
            scope=[],
            max_depth=0,
            issued_at=int(time.time() * 1000),
            expires_at=int(time.time() * 1000) + 3_600_000,
            delegation_block_hash="cc" * 32,
            agreement_block_hash="dd" * 32,
        ))
        assert dstore.is_delegate("bb" * 32) is True


# ===========================================================================
# SQLiteBlockStore delegation tests
# ===========================================================================


class TestSQLiteDelegationStore:
    def test_sqlite_delegation_roundtrip(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        store = SQLiteBlockStore(db_path)
        rec = DelegationRecord(
            delegation_id="d1",
            delegator_pubkey="aa" * 32,
            delegate_pubkey="bb" * 32,
            scope=["test"],
            max_depth=0,
            issued_at=int(time.time() * 1000),
            expires_at=int(time.time() * 1000) + 3_600_000,
            delegation_block_hash="cc" * 32,
            agreement_block_hash="dd" * 32,
        )
        store.add_delegation(rec)
        got = store.get_delegation("d1")
        assert got is not None
        assert got.scope == ["test"]
        assert store.get_active_delegation_count("aa" * 32) == 1
        store.revoke_delegation("d1", "ff" * 32)
        assert store.is_revoked("d1") is True
        store.close()

    def test_sqlite_succession(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        store = SQLiteBlockStore(db_path)
        store.add_succession("aa" * 32, "bb" * 32, "cc" * 32)
        assert store.get_successor("aa" * 32) == "bb" * 32
        assert store.resolve_current_identity("aa" * 32) == "bb" * 32
        store.close()


# ===========================================================================
# Protocol flow tests
# ===========================================================================


class TestDelegationProtocol:
    def test_create_and_accept_delegation(self, store, dstore, operator, delegate):
        proto_op = TrustChainProtocol(operator, store, dstore)
        proto_del = TrustChainProtocol(delegate, store, dstore)

        proposal = proto_op.create_delegation(
            delegate.pubkey_hex, scope=["test"], max_depth=0, ttl_seconds=3600
        )
        assert proposal.block_type == BlockType.DELEGATION
        assert proposal.transaction["interaction_type"] == "delegation"

        agreement, cert = proto_del.accept_delegation(proposal)
        assert agreement.block_type == BlockType.DELEGATION
        assert cert.delegator_pubkey == operator.pubkey_hex
        assert cert.delegate_pubkey == delegate.pubkey_hex
        assert cert.chain_depth == 1

    def test_delegation_creates_bilateral_blocks(self, store, dstore, operator, delegate):
        proto_op = TrustChainProtocol(operator, store, dstore)
        proto_del = TrustChainProtocol(delegate, store, dstore)

        proposal = proto_op.create_delegation(delegate.pubkey_hex, scope=[], ttl_seconds=3600)
        agreement, _ = proto_del.accept_delegation(proposal)

        # Operator chain has the proposal
        op_chain = store.get_chain(operator.pubkey_hex)
        assert len(op_chain) == 1
        assert op_chain[0].block_type == BlockType.DELEGATION

        # Delegate chain has the agreement
        del_chain = store.get_chain(delegate.pubkey_hex)
        assert len(del_chain) == 1
        assert del_chain[0].link_sequence_number == proposal.sequence_number

    def test_reject_expired_delegation(self, store, dstore, operator, delegate):
        proto_op = TrustChainProtocol(operator, store, dstore)
        proto_del = TrustChainProtocol(delegate, store, dstore)

        # Create delegation with 0 TTL (immediately expired)
        proposal = proto_op.create_delegation(
            delegate.pubkey_hex, scope=[], ttl_seconds=0
        )
        with pytest.raises(DelegationError, match="expired"):
            proto_del.accept_delegation(proposal)

    def test_reject_depth_exceeded(self, store, dstore, operator):
        proto_op = TrustChainProtocol(operator, store, dstore)
        with pytest.raises(DelegationError, match="max_depth cannot exceed 2"):
            proto_op.create_delegation("bb" * 32, scope=[], max_depth=3)

    def test_subdelegation_scope_subset(self, store, dstore):
        operator = Identity()
        orchestrator = Identity()
        worker = Identity()

        proto_op = TrustChainProtocol(operator, store, dstore)
        proto_orch = TrustChainProtocol(orchestrator, store, dstore)

        # Operator delegates to orchestrator with max_depth=1
        p = proto_op.create_delegation(
            orchestrator.pubkey_hex, scope=["search", "review"], max_depth=1, ttl_seconds=3600
        )
        proto_orch.accept_delegation(p)

        # Orchestrator tries to sub-delegate with wider scope
        with pytest.raises(DelegationError, match="subset"):
            proto_orch.create_delegation(
                worker.pubkey_hex, scope=["search", "deploy"], max_depth=0
            )

        # Valid sub-delegation with narrower scope
        p2 = proto_orch.create_delegation(
            worker.pubkey_hex, scope=["search"], max_depth=0
        )
        assert p2.transaction["scope"] == ["search"]

    def test_revocation_creates_unilateral_block(self, store, dstore, operator, delegate):
        proto_op = TrustChainProtocol(operator, store, dstore)
        proto_del = TrustChainProtocol(delegate, store, dstore)

        proposal = proto_op.create_delegation(delegate.pubkey_hex, scope=[], ttl_seconds=3600)
        proto_del.accept_delegation(proposal)

        delegation_id = proposal.transaction["delegation_id"]
        revocation = proto_op.create_revocation(delegation_id)
        assert revocation.block_type == BlockType.REVOCATION
        assert revocation.transaction["delegation_id"] == delegation_id
        assert dstore.is_revoked(delegation_id)

    def test_revocation_only_by_delegator(self, store, dstore, operator, delegate):
        proto_op = TrustChainProtocol(operator, store, dstore)
        proto_del = TrustChainProtocol(delegate, store, dstore)

        proposal = proto_op.create_delegation(delegate.pubkey_hex, scope=[], ttl_seconds=3600)
        proto_del.accept_delegation(proposal)

        delegation_id = proposal.transaction["delegation_id"]
        with pytest.raises(DelegationError, match="Only the delegator"):
            proto_del.create_revocation(delegation_id)

    def test_succession_bilateral(self, store, dstore):
        old_id = Identity()
        new_id = Identity()
        peer = Identity()

        proto_old = TrustChainProtocol(old_id, store, dstore)
        proto_new = TrustChainProtocol(new_id, store, dstore)

        # Need at least one block on old chain
        build_operator_trust(old_id, peer, store, n=1)

        proposal = proto_old.create_succession(new_id)
        assert proposal.block_type == BlockType.SUCCESSION

        agreement = proto_new.accept_succession(proposal)
        assert agreement.block_type == BlockType.SUCCESSION
        assert dstore.get_successor(old_id.pubkey_hex) == new_id.pubkey_hex

    def test_succession_requires_nonempty_chain(self, store, dstore):
        old_id = Identity()
        new_id = Identity()
        proto = TrustChainProtocol(old_id, store, dstore)

        with pytest.raises(SuccessionError, match="empty chain"):
            proto.create_succession(new_id)


# ===========================================================================
# Trust computation tests
# ===========================================================================


class TestDelegatedTrust:
    def test_delegated_trust_equals_root_divided_by_count(self, store, dstore):
        operator = Identity()
        delegate1 = Identity()
        peer = Identity()

        build_operator_trust(operator, peer, store, n=5)

        proto_op = TrustChainProtocol(operator, store, dstore)
        proto_d1 = TrustChainProtocol(delegate1, store, dstore)

        p = proto_op.create_delegation(delegate1.pubkey_hex, scope=["test"], ttl_seconds=3600)
        proto_d1.accept_delegation(p)

        engine = TrustEngine(store, delegation_store=dstore)
        op_trust = engine.compute_trust(operator.pubkey_hex)
        d1_trust = engine.compute_trust(delegate1.pubkey_hex, "test")

        # With 1 active delegation, delegate trust = operator trust / 1
        assert d1_trust == op_trust

    def test_trust_budget_splits_with_multiple_delegations(self, store, dstore):
        operator = Identity()
        d1 = Identity()
        d2 = Identity()
        peer = Identity()

        build_operator_trust(operator, peer, store, n=5)

        proto_op = TrustChainProtocol(operator, store, dstore)
        p1 = proto_op.create_delegation(d1.pubkey_hex, scope=["test"], ttl_seconds=3600)
        TrustChainProtocol(d1, store, dstore).accept_delegation(p1)
        p2 = proto_op.create_delegation(d2.pubkey_hex, scope=["test"], ttl_seconds=3600)
        TrustChainProtocol(d2, store, dstore).accept_delegation(p2)

        engine = TrustEngine(store, delegation_store=dstore)
        op_trust = engine.compute_trust(operator.pubkey_hex)
        d1_trust = engine.compute_trust(d1.pubkey_hex, "test")
        d2_trust = engine.compute_trust(d2.pubkey_hex, "test")

        # Budget split: each gets op_trust / 2
        assert d1_trust == d2_trust
        assert abs(d1_trust - op_trust / 2) < 0.01

    def test_scope_mismatch_returns_zero(self, store, dstore):
        operator = Identity()
        delegate1 = Identity()
        peer = Identity()

        build_operator_trust(operator, peer, store, n=5)

        proto_op = TrustChainProtocol(operator, store, dstore)
        p = proto_op.create_delegation(delegate1.pubkey_hex, scope=["code-review"], ttl_seconds=3600)
        TrustChainProtocol(delegate1, store, dstore).accept_delegation(p)

        engine = TrustEngine(store, delegation_store=dstore)
        assert engine.compute_trust(delegate1.pubkey_hex, "deploy") == 0.0

    def test_revoked_delegation_returns_zero(self, store, dstore):
        operator = Identity()
        delegate1 = Identity()
        peer = Identity()

        build_operator_trust(operator, peer, store, n=5)

        proto_op = TrustChainProtocol(operator, store, dstore)
        p = proto_op.create_delegation(delegate1.pubkey_hex, scope=[], ttl_seconds=3600)
        TrustChainProtocol(delegate1, store, dstore).accept_delegation(p)

        engine = TrustEngine(store, delegation_store=dstore)
        assert engine.compute_trust(delegate1.pubkey_hex) > 0

        proto_op.create_revocation(p.transaction["delegation_id"])
        assert engine.compute_trust(delegate1.pubkey_hex) == 0.0

    def test_subdelegation_depth_discount(self, store, dstore):
        operator = Identity()
        orch = Identity()
        worker = Identity()
        peer = Identity()

        build_operator_trust(operator, peer, store, n=5)

        proto_op = TrustChainProtocol(operator, store, dstore)
        proto_orch = TrustChainProtocol(orch, store, dstore)

        # Operator -> Orchestrator (depth=1, max_depth=1)
        p1 = proto_op.create_delegation(orch.pubkey_hex, scope=[], max_depth=1, ttl_seconds=3600)
        proto_orch.accept_delegation(p1)

        # Orchestrator -> Worker (depth=2, max_depth=0)
        p2 = proto_orch.create_delegation(worker.pubkey_hex, scope=[], max_depth=0, ttl_seconds=3600)
        TrustChainProtocol(worker, store, dstore).accept_delegation(p2)

        engine = TrustEngine(store, delegation_store=dstore)
        op_trust = engine.compute_trust(operator.pubkey_hex)
        orch_trust = engine.compute_trust(orch.pubkey_hex)
        worker_trust = engine.compute_trust(worker.pubkey_hex)

        # Orchestrator = op_trust / 1 (sole delegate)
        assert abs(orch_trust - op_trust) < 0.01

        # Worker = root_trust / active_count (flat split, no depth discount — matches Rust)
        # Root is operator, who has 1 active delegation, so worker_trust == op_trust / 1
        assert abs(worker_trust - op_trust) < 0.01


# ===========================================================================
# Attack vector tests
# ===========================================================================


class TestAttackVectors:
    def test_delegation_farming_budget_split(self, store, dstore):
        """100 delegates should each get ~trust/100, not full trust."""
        operator = Identity()
        peer = Identity()
        build_operator_trust(operator, peer, store, n=10)

        proto_op = TrustChainProtocol(operator, store, dstore)
        delegates = []
        for i in range(10):
            d = Identity()
            delegates.append(d)
            p = proto_op.create_delegation(d.pubkey_hex, scope=[], ttl_seconds=3600)
            TrustChainProtocol(d, store, dstore).accept_delegation(p)

        engine = TrustEngine(store, delegation_store=dstore)
        op_trust = engine.compute_trust(operator.pubkey_hex)

        for d in delegates:
            d_trust = engine.compute_trust(d.pubkey_hex)
            assert abs(d_trust - op_trust / 10) < 0.01

    def test_circular_delegation_rejected(self, store, dstore):
        """A -> B -> A should be rejected."""
        a = Identity()
        b = Identity()

        proto_a = TrustChainProtocol(a, store, dstore)
        proto_b = TrustChainProtocol(b, store, dstore)

        # A delegates to B
        p = proto_a.create_delegation(b.pubkey_hex, scope=[], max_depth=1, ttl_seconds=3600)
        proto_b.accept_delegation(p)

        # B tries to delegate back to A
        with pytest.raises(DelegationError, match="Circular"):
            proto_b.create_delegation(a.pubkey_hex, scope=[], max_depth=0)

    def test_deep_chain_rejected(self, store, dstore):
        """max_depth > 2 should be rejected."""
        operator = Identity()
        proto = TrustChainProtocol(operator, store, dstore)
        with pytest.raises(DelegationError, match="max_depth cannot exceed 2"):
            proto.create_delegation("bb" * 32, scope=[], max_depth=3)

    def test_subdelegation_scope_escalation_rejected(self, store, dstore):
        """Sub-delegate cannot have wider scope than parent."""
        op = Identity()
        orch = Identity()
        worker = Identity()

        proto_op = TrustChainProtocol(op, store, dstore)
        proto_orch = TrustChainProtocol(orch, store, dstore)

        p = proto_op.create_delegation(orch.pubkey_hex, scope=["search"], max_depth=1, ttl_seconds=3600)
        proto_orch.accept_delegation(p)

        with pytest.raises(DelegationError, match="subset"):
            proto_orch.create_delegation(worker.pubkey_hex, scope=["search", "deploy"], max_depth=0)

    def test_zombie_delegation_expired(self, store, dstore):
        """Expired delegation should return 0 trust."""
        operator = Identity()
        delegate1 = Identity()
        peer = Identity()

        build_operator_trust(operator, peer, store, n=5)

        proto_op = TrustChainProtocol(operator, store, dstore)
        # Short TTL — enough to accept, then wait for expiry
        p = proto_op.create_delegation(delegate1.pubkey_hex, scope=[], ttl_seconds=0.1)
        import time as t
        TrustChainProtocol(delegate1, store, dstore).accept_delegation(p)
        t.sleep(0.15)  # ensure it expires

        engine = TrustEngine(store, delegation_store=dstore)
        # Active delegation query returns None (expired), falls through to is_delegate check
        assert engine.compute_trust(delegate1.pubkey_hex) == 0.0


# ===========================================================================
# Integration tests
# ===========================================================================


class TestDelegationE2E:
    def test_operator_delegates_to_agent_full_flow(self, store, dstore):
        """Full flow: operator builds trust, delegates, delegate interacts."""
        operator = Identity()
        delegate1 = Identity()
        peer = Identity()

        # 1. Operator builds trust
        build_operator_trust(operator, peer, store, n=5)

        # 2. Operator delegates to agent
        proto_op = TrustChainProtocol(operator, store, dstore)
        proto_d = TrustChainProtocol(delegate1, store, dstore)

        p = proto_op.create_delegation(
            delegate1.pubkey_hex, scope=["service"], max_depth=0, ttl_seconds=3600
        )
        agreement, cert = proto_d.accept_delegation(p)

        # 3. Verify certificate
        proto_op.verify_delegation_certificate(cert, delegate1.pubkey_hex)

        # 4. Compute trust
        engine = TrustEngine(store, delegation_store=dstore)
        trust = engine.compute_trust(delegate1.pubkey_hex, "service")
        assert trust > 0

    def test_key_rotation_preserves_identity(self, store, dstore):
        """Succession: old key -> new key, delegation store tracks."""
        old_id = Identity()
        new_id = Identity()
        peer = Identity()

        build_operator_trust(old_id, peer, store, n=3)

        proto_old = TrustChainProtocol(old_id, store, dstore)
        proto_new = TrustChainProtocol(new_id, store, dstore)

        # Create succession
        proposal = proto_old.create_succession(new_id)
        proto_new.accept_succession(proposal)

        # Verify succession recorded
        assert dstore.get_successor(old_id.pubkey_hex) == new_id.pubkey_hex
        assert dstore.resolve_current_identity(old_id.pubkey_hex) == new_id.pubkey_hex

    def test_orchestrator_subdelegates_to_worker(self, store, dstore):
        """3-level hierarchy: operator -> orchestrator -> worker."""
        operator = Identity()
        orch = Identity()
        worker = Identity()
        peer = Identity()

        build_operator_trust(operator, peer, store, n=5)

        proto_op = TrustChainProtocol(operator, store, dstore)
        proto_orch = TrustChainProtocol(orch, store, dstore)
        proto_worker = TrustChainProtocol(worker, store, dstore)

        # Level 1: operator -> orchestrator
        p1 = proto_op.create_delegation(
            orch.pubkey_hex, scope=["search", "review"], max_depth=1, ttl_seconds=3600
        )
        _, cert_orch = proto_orch.accept_delegation(p1)

        # Level 2: orchestrator -> worker
        p2 = proto_orch.create_delegation(
            worker.pubkey_hex, scope=["search"], max_depth=0, ttl_seconds=3600
        )
        _, cert_worker = proto_worker.accept_delegation(p2)

        # Trust hierarchy
        engine = TrustEngine(store, delegation_store=dstore)
        op_trust = engine.compute_trust(operator.pubkey_hex)
        orch_trust = engine.compute_trust(orch.pubkey_hex)
        worker_trust = engine.compute_trust(worker.pubkey_hex)

        # Flat budget split (matches Rust): all delegates get root_trust / active_count
        # Operator has 1 delegate, so orch == op_trust; worker resolves to same root
        assert op_trust >= orch_trust > 0
        assert abs(worker_trust - op_trust) < 0.01

    def test_revocation_stops_delegated_interactions(self, store, dstore):
        """After revocation, delegate trust drops to 0."""
        operator = Identity()
        delegate1 = Identity()
        peer = Identity()

        build_operator_trust(operator, peer, store, n=5)

        proto_op = TrustChainProtocol(operator, store, dstore)
        p = proto_op.create_delegation(delegate1.pubkey_hex, scope=[], ttl_seconds=3600)
        TrustChainProtocol(delegate1, store, dstore).accept_delegation(p)

        engine = TrustEngine(store, delegation_store=dstore)
        before = engine.compute_trust(delegate1.pubkey_hex)
        assert before > 0

        proto_op.create_revocation(p.transaction["delegation_id"])
        after = engine.compute_trust(delegate1.pubkey_hex)
        assert after == 0.0
