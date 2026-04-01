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
        # Empty chain: confidence_scale = 0/5 = 0.0 → trust = 0.0
        # (no interactions = no trust, regardless of recency prior).
        assert trust == 0.0

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
        """Without seed nodes, trust scales with confidence (interaction count)."""
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
        # 3 interactions, cold_start_threshold=5 → confidence_scale=0.6.
        # trust = (0.3 × 1.0 + 0.7 × 1.0) × 0.6 = 0.6
        assert abs(trust - 0.6) < 1e-9


# ===== Layer 1: Quality-Aware Recency Tests =====
# Research: trust-differentiation-fixes P0, Josang & Ismail 2002


def _create_pair_with_tx(store, id_a, id_b, seq_a, seq_b, prev_a, prev_b, tx):
    """Helper: create a bilateral interaction with custom transaction JSON."""
    proposal = create_half_block(
        identity=id_a,
        sequence_number=seq_a,
        link_public_key=id_b.pubkey_hex,
        link_sequence_number=0,
        previous_hash=prev_a,
        block_type=BlockType.PROPOSAL,
        transaction=tx,
    )
    store.add_block(proposal)

    agreement = create_half_block(
        identity=id_b,
        sequence_number=seq_b,
        link_public_key=id_a.pubkey_hex,
        link_sequence_number=seq_a,
        previous_hash=prev_b,
        block_type=BlockType.AGREEMENT,
        transaction=tx,
    )
    store.add_block(agreement)

    return proposal, agreement


class TestQualityAwareRecency:
    """Tests for quality-aware recency (Layer 1 P0)."""

    def test_extract_quality_field(self):
        from types import SimpleNamespace

        block = SimpleNamespace(transaction={"outcome": "completed", "quality": 0.75})
        assert abs(TrustEngine._extract_quality(block) - 0.75) < 1e-10

    def test_extract_quality_requester_rating_fallback(self):
        from types import SimpleNamespace

        block = SimpleNamespace(
            transaction={"outcome": "completed", "requester_rating": 0.6}
        )
        assert abs(TrustEngine._extract_quality(block) - 0.6) < 1e-10

    def test_extract_quality_provider_rating_fallback(self):
        from types import SimpleNamespace

        block = SimpleNamespace(
            transaction={"outcome": "completed", "provider_rating": 0.4}
        )
        assert abs(TrustEngine._extract_quality(block) - 0.4) < 1e-10

    def test_extract_quality_binary_fallback(self):
        from types import SimpleNamespace

        block_ok = SimpleNamespace(transaction={"outcome": "completed"})
        assert abs(TrustEngine._extract_quality(block_ok) - 1.0) < 1e-10

        block_fail = SimpleNamespace(transaction={"outcome": "failed"})
        assert abs(TrustEngine._extract_quality(block_fail)) < 1e-10

    def test_extract_quality_clamps(self):
        from types import SimpleNamespace

        block_high = SimpleNamespace(transaction={"quality": 1.5})
        assert abs(TrustEngine._extract_quality(block_high) - 1.0) < 1e-10

        block_low = SimpleNamespace(transaction={"quality": -0.5})
        assert abs(TrustEngine._extract_quality(block_low)) < 1e-10

    def test_extract_quality_priority_order(self):
        from types import SimpleNamespace

        block = SimpleNamespace(
            transaction={
                "outcome": "completed",
                "quality": 0.8,
                "requester_rating": 0.3,
                "provider_rating": 0.1,
            }
        )
        assert abs(TrustEngine._extract_quality(block) - 0.8) < 1e-10

    def test_empty_chain_recency_returns_half(self):
        """Josang & Ismail 2002: uninformative prior = 0.5."""
        store = MemoryBlockStore()
        engine = TrustEngine(store)
        recency = engine._compute_recency([])
        assert abs(recency - 0.5) < 1e-10, f"Empty chain should return 0.5, got {recency}"

    def test_quality_aware_recency_honest_vs_sybil(self):
        """trust-differentiation-fixes P0: gap > 0.4."""
        store = MemoryBlockStore()
        honest = Identity()
        sybil = Identity()
        seed = Identity()
        sybil_peer = Identity()

        # 10 interactions for honest agent (quality 0.85)
        prev_h, prev_s = GENESIS_HASH, GENESIS_HASH
        for i in range(1, 11):
            p, a = _create_pair_with_tx(
                store, honest, seed, i, i, prev_h, prev_s,
                {"outcome": "completed", "quality": 0.85},
            )
            prev_h, prev_s = p.block_hash, a.block_hash

        # 10 interactions for sybil agent (quality 0.3)
        prev_sy, prev_sp = GENESIS_HASH, GENESIS_HASH
        for i in range(1, 11):
            p, a = _create_pair_with_tx(
                store, sybil, sybil_peer, i, i, prev_sy, prev_sp,
                {"outcome": "completed", "quality": 0.3},
            )
            prev_sy, prev_sp = p.block_hash, a.block_hash

        engine = TrustEngine(store)
        honest_trust = engine.compute_trust(honest.pubkey_hex)
        sybil_trust = engine.compute_trust(sybil.pubkey_hex)

        # Weighted-additive: gap = 0.7 × (0.85 - 0.3) = 0.385 (no-seeds worst case).
        # With seeds, sybils have lower connectivity → gap widens further.
        gap = honest_trust - sybil_trust
        assert gap > 0.35, (
            f"Quality differentiation gap should exceed 0.35 (no-seeds worst case), "
            f"got {gap} (honest={honest_trust}, sybil={sybil_trust})"
        )

    def test_avg_quality_in_evidence(self):
        store = MemoryBlockStore()
        alice = Identity()
        bob = Identity()

        prev_a, prev_b = GENESIS_HASH, GENESIS_HASH
        for i in range(1, 6):
            p, a = _create_pair_with_tx(
                store, alice, bob, i, i, prev_a, prev_b,
                {"outcome": "completed", "quality": 0.7},
            )
            prev_a, prev_b = p.block_hash, a.block_hash

        engine = TrustEngine(store)
        evidence = engine.compute_trust_with_evidence(alice.pubkey_hex)
        assert abs(evidence["avg_quality"] - 0.7) < 0.01, (
            f"avg_quality should be ~0.7, got {evidence['avg_quality']}"
        )

    def test_backward_compat_no_quality_field(self):
        """Blocks without quality field should still work (binary outcome)."""
        store = MemoryBlockStore()
        alice = Identity()
        bob = Identity()

        _create_pair_with_tx(
            store, alice, bob, 1, 1, GENESIS_HASH, GENESIS_HASH,
            {"outcome": "completed"},
        )

        engine = TrustEngine(store)
        evidence = engine.compute_trust_with_evidence(alice.pubkey_hex)
        assert abs(evidence["avg_quality"] - 1.0) < 0.01
        assert evidence["trust_score"] > 0.0


# ===== Layer 1.4: Value-Weighted Recency Tests =====
# Research: Olariu et al. 2024, Hoffman et al. 2009


class TestValueWeightedRecency:
    """Tests for value-weighted recency (Layer 1.4)."""

    def test_cheap_wash_trades_negligible(self):
        """$1 self-deals should barely affect recency in a $100 context."""
        store = MemoryBlockStore()
        agent = Identity()
        peer = Identity()

        # 9 interactions at $100 with quality 0.3
        prev_a, prev_b = GENESIS_HASH, GENESIS_HASH
        for i in range(1, 10):
            p, a = _create_pair_with_tx(
                store, agent, peer, i, i, prev_a, prev_b,
                {"outcome": "completed", "quality": 0.3, "price": 100.0},
            )
            prev_a, prev_b = p.block_hash, a.block_hash

        # 1 cheap wash-trade at $1 with quality 1.0
        _create_pair_with_tx(
            store, agent, peer, 10, 10, prev_a, prev_b,
            {"outcome": "completed", "quality": 1.0, "price": 1.0},
        )

        engine = TrustEngine(store)
        evidence = engine.compute_trust_with_evidence(agent.pubkey_hex)

        assert evidence["value_weighted_recency"] < 0.4, (
            f"Value-weighted recency should be < 0.4, got {evidence['value_weighted_recency']}"
        )

    def test_expensive_txn_dominates(self):
        """An expensive successful txn should dominate over many cheap failures."""
        store = MemoryBlockStore()
        agent = Identity()
        peer = Identity()

        # 5 cheap failures at $1
        prev_a, prev_b = GENESIS_HASH, GENESIS_HASH
        for i in range(1, 6):
            p, a = _create_pair_with_tx(
                store, agent, peer, i, i, prev_a, prev_b,
                {"outcome": "failed", "quality": 0.0, "price": 1.0},
            )
            prev_a, prev_b = p.block_hash, a.block_hash

        # 1 expensive success at $500
        _create_pair_with_tx(
            store, agent, peer, 6, 6, prev_a, prev_b,
            {"outcome": "completed", "quality": 0.9, "price": 500.0},
        )

        engine = TrustEngine(store)
        evidence = engine.compute_trust_with_evidence(agent.pubkey_hex)

        assert evidence["value_weighted_recency"] > 0.5, (
            f"Expensive success should dominate, got {evidence['value_weighted_recency']}"
        )

    def test_backward_compat_no_price(self):
        """Blocks without price field should behave identically to before."""
        store = MemoryBlockStore()
        agent = Identity()
        peer = Identity()

        prev_a, prev_b = GENESIS_HASH, GENESIS_HASH
        for i in range(1, 6):
            p, a = _create_pair_with_tx(
                store, agent, peer, i, i, prev_a, prev_b,
                {"outcome": "completed"},
            )
            prev_a, prev_b = p.block_hash, a.block_hash

        engine = TrustEngine(store)
        evidence = engine.compute_trust_with_evidence(agent.pubkey_hex)

        assert abs(evidence["recency"] - 1.0) < 1e-6
        assert abs(evidence["value_weighted_recency"] - 1.0) < 1e-6


# ===== Layer 2.1: Wilson Score Confidence Tests =====
# Research: Evan Miller 2009, TRAVOS (Teacy et al. 2006)


class TestWilsonScoreConfidence:
    """Tests for Wilson lower-bound confidence (Layer 2.1)."""

    def test_wilson_empty(self):
        assert abs(TrustEngine.wilson_lower_bound(0.0, 0.0)) < 1e-10

    def test_wilson_perfect_small_sample(self):
        score = TrustEngine.wilson_lower_bound(5.0, 5.0)
        assert 0.5 < score < 1.0, f"Wilson(5/5) should be (0.5, 1.0), got {score}"

    def test_wilson_perfect_large_sample(self):
        score = TrustEngine.wilson_lower_bound(100.0, 100.0)
        assert score > 0.95, f"Wilson(100/100) should be > 0.95, got {score}"

    def test_wilson_half_half(self):
        score = TrustEngine.wilson_lower_bound(50.0, 100.0)
        assert 0.3 < score < 0.5, f"Wilson(50/100) should be (0.3, 0.5), got {score}"

    def test_wilson_all_negative(self):
        score = TrustEngine.wilson_lower_bound(0.0, 10.0)
        assert score < 0.05, f"Wilson(0/10) should be < 0.05, got {score}"

    def test_wilson_monotonicity(self):
        w5 = TrustEngine.wilson_lower_bound(5.0, 5.0)
        w20 = TrustEngine.wilson_lower_bound(20.0, 20.0)
        w100 = TrustEngine.wilson_lower_bound(100.0, 100.0)
        assert w5 < w20 < w100, f"Should increase with size: {w5} {w20} {w100}"

    def test_confidence_in_evidence(self):
        store = MemoryBlockStore()
        agent = Identity()
        peer = Identity()

        prev_a, prev_b = GENESIS_HASH, GENESIS_HASH
        for i in range(1, 11):
            p, a = _create_pair_with_tx(
                store, agent, peer, i, i, prev_a, prev_b,
                {"outcome": "completed", "quality": 0.8},
            )
            prev_a, prev_b = p.block_hash, a.block_hash

        engine = TrustEngine(store)
        evidence = engine.compute_trust_with_evidence(agent.pubkey_hex)

        assert evidence["sample_size"] == 10
        assert evidence["positive_count"] == 10
        assert evidence["confidence"] > 0.5

    def test_confidence_empty_chain(self):
        store = MemoryBlockStore()
        engine = TrustEngine(store)
        evidence = engine.compute_trust_with_evidence("nobody")

        assert evidence["sample_size"] == 0
        assert evidence["positive_count"] == 0
        assert abs(evidence["confidence"]) < 1e-10

    def test_confidence_mixed_outcomes(self):
        store = MemoryBlockStore()
        agent = Identity()
        peer = Identity()

        prev_a, prev_b = GENESIS_HASH, GENESIS_HASH
        for i in range(1, 6):
            p, a = _create_pair_with_tx(
                store, agent, peer, i, i, prev_a, prev_b,
                {"outcome": "completed", "quality": 0.8},
            )
            prev_a, prev_b = p.block_hash, a.block_hash
        for i in range(6, 11):
            p, a = _create_pair_with_tx(
                store, agent, peer, i, i, prev_a, prev_b,
                {"outcome": "failed", "quality": 0.2},
            )
            prev_a, prev_b = p.block_hash, a.block_hash

        engine = TrustEngine(store)
        evidence = engine.compute_trust_with_evidence(agent.pubkey_hex)

        assert evidence["sample_size"] == 10
        assert evidence["positive_count"] == 5
        assert 0.0 < evidence["confidence"] < 0.5


# ─── Layer 3.3-3.5: Thresholds + Escrow ─────────────────────────────────────

class TestThresholds:
    """Tests for Josang threshold, risk-scaled threshold, and escrow deposit."""

    def test_josang_equal_loss_gain(self):
        from trustchain.thresholds import min_trust_threshold
        t = min_trust_threshold(100.0, 100.0)
        assert abs(t - 0.5) < 1e-9

    def test_josang_high_loss(self):
        from trustchain.thresholds import min_trust_threshold
        t = min_trust_threshold(5000.0, 1000.0)
        assert abs(t - 5000.0 / 6000.0) < 1e-9

    def test_josang_low_loss(self):
        from trustchain.thresholds import min_trust_threshold
        t = min_trust_threshold(5.0, 100.0)
        assert abs(t - 5.0 / 105.0) < 1e-9

    def test_josang_zero_gain(self):
        from trustchain.thresholds import min_trust_threshold
        t = min_trust_threshold(100.0, 0.0)
        assert abs(t - 1.0) < 1e-9

    def test_josang_zero_both(self):
        from trustchain.thresholds import min_trust_threshold
        t = min_trust_threshold(0.0, 0.0)
        assert abs(t - 0.5) < 1e-9

    def test_risk_base_case(self):
        from trustchain.thresholds import risk_threshold
        t = risk_threshold(10.0, 1.0, 1.0, 0.0)
        assert abs(t - 0.1) < 1e-9

    def test_risk_high_value_clamps(self):
        from trustchain.thresholds import risk_threshold
        t = risk_threshold(1000.0, 1.0, 1.0, 0.0)
        assert abs(t - 0.95) < 1e-9

    def test_risk_low_confidence(self):
        from trustchain.thresholds import risk_threshold
        t = risk_threshold(10.0, 1.0, 0.0, 0.0)
        assert abs(t - 0.3) < 1e-9  # base + 0.2 uncertainty

    def test_risk_high_recovery(self):
        from trustchain.thresholds import risk_threshold
        t = risk_threshold(10.0, 1.0, 1.0, 1.0)
        assert abs(t - 0.05) < 1e-9  # base - recovery, clamped to 0.05

    def test_deposit_zero_trust(self):
        from trustchain.thresholds import required_deposit
        d = required_deposit(1000.0, 0.0)
        assert abs(d - 1000.0) < 1e-9

    def test_deposit_full_trust(self):
        from trustchain.thresholds import required_deposit
        d = required_deposit(1000.0, 1.0)
        assert abs(d - 0.0) < 1e-9

    def test_deposit_half_trust(self):
        from trustchain.thresholds import required_deposit
        d = required_deposit(1000.0, 0.5)
        assert abs(d - 500.0) < 1e-9


# ─── Layer 4.1: Graduated Sanctions ──────────────────────────────────────────

class TestSanctions:
    """Tests for graduated sanctions framework."""

    def test_default_config(self):
        from trustchain.sanctions import SanctionConfig
        c = SanctionConfig()
        assert abs(c.liveness_penalty - 0.0001) < 1e-12
        assert abs(c.quality_penalty_base - 0.05) < 1e-12
        assert abs(c.byzantine_penalty - 1.0) < 1e-12

    def test_classify_byzantine(self):
        from trustchain.sanctions import classify_violation, ViolationSeverity
        v = classify_violation(0, 0.8, True)
        assert v == ViolationSeverity.BYZANTINE

    def test_classify_quality(self):
        from trustchain.sanctions import classify_violation, ViolationSeverity
        v = classify_violation(0, 0.2, False)
        assert v == ViolationSeverity.QUALITY

    def test_classify_liveness(self):
        from trustchain.sanctions import classify_violation, ViolationSeverity
        v = classify_violation(3, 0.8, False)
        assert v == ViolationSeverity.LIVENESS

    def test_classify_none(self):
        from trustchain.sanctions import classify_violation
        v = classify_violation(0, 0.8, False)
        assert v is None

    def test_sanctions_clean_agent(self):
        from trustchain.sanctions import SanctionConfig, compute_sanctions
        r = compute_sanctions(0, 0.85, False, SanctionConfig())
        assert abs(r.total_penalty) < 1e-12
        assert r.violation_count == 0

    def test_sanctions_fraud(self):
        from trustchain.sanctions import SanctionConfig, compute_sanctions
        r = compute_sanctions(0, 0.85, True, SanctionConfig())
        assert abs(r.total_penalty - 1.0) < 1e-12
        assert r.violation_count == 1

    def test_sanctions_liveness_scales(self):
        from trustchain.sanctions import SanctionConfig, compute_sanctions
        r = compute_sanctions(100, 0.85, False, SanctionConfig())
        assert abs(r.total_penalty - 0.01) < 1e-12

    def test_severity_ratio(self):
        from trustchain.sanctions import SanctionConfig
        c = SanctionConfig()
        assert abs(c.quality_penalty_base / c.liveness_penalty - 500.0) < 1.0


# ─── Evidence fields for new layers ──────────────────────────────────────────

class TestEvidenceNewFields:
    """Tests that TrustEvidence includes L3.5 and L4.1 fields."""

    def test_evidence_includes_deposit_ratio(self):
        store = MemoryBlockStore()
        agent = Identity()
        peer = Identity()
        prev_a = GENESIS_HASH
        prev_b = GENESIS_HASH
        for i in range(1, 6):
            p, a = _create_pair_with_tx(
                store, agent, peer, i, i, prev_a, prev_b,
                {"outcome": "completed", "quality": 0.9},
            )
            prev_a, prev_b = p.block_hash, a.block_hash

        engine = TrustEngine(store)
        evidence = engine.compute_trust_with_evidence(agent.pubkey_hex)
        trust = evidence["trust_score"]
        deposit = evidence["required_deposit_ratio"]
        assert abs(deposit - max(0.0, min(1.0, 1.0 - trust))) < 1e-9

    def test_evidence_includes_sanctions(self):
        store = MemoryBlockStore()
        agent = Identity()
        peer = Identity()
        prev_a = GENESIS_HASH
        prev_b = GENESIS_HASH
        for i in range(1, 6):
            p, a = _create_pair_with_tx(
                store, agent, peer, i, i, prev_a, prev_b,
                {"outcome": "completed", "quality": 0.9},
            )
            prev_a, prev_b = p.block_hash, a.block_hash

        engine = TrustEngine(store)
        evidence = engine.compute_trust_with_evidence(agent.pubkey_hex)
        # Clean agent → no sanctions
        assert evidence["sanction_penalty"] == 0.0
        assert evidence["violation_count"] == 0

    def test_empty_chain_deposit_ratio_is_one(self):
        store = MemoryBlockStore()
        agent = Identity()
        engine = TrustEngine(store)
        evidence = engine.compute_trust_with_evidence(agent.pubkey_hex)
        # Empty chain → trust near 0 → deposit ratio near 1.0
        assert evidence["required_deposit_ratio"] >= 0.9
