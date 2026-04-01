"""Tests for forgiveness / trust recovery (Layer 4.4).

Mirrors Rust trustchain-core/src/forgiveness.rs inline tests.
"""

from trustchain.forgiveness import (
    ForgivenessConfig,
    RecoverySeverity,
    apply_forgiveness,
    asymmetric_decay_weight,
    recovery_ceiling,
)


class TestForgivenessConfig:
    def test_defaults(self):
        c = ForgivenessConfig()
        assert abs(c.decay_per_good_interaction - 0.8) < 1e-12
        assert abs(c.liveness_recovery_ceiling - 1.0) < 1e-12
        assert abs(c.quality_recovery_ceiling - 0.75) < 1e-12
        assert abs(c.fraud_recovery_ceiling - 0.25) < 1e-12
        assert abs(c.negative_decay_speedup - 1.5) < 1e-12


class TestRecoveryCeiling:
    def test_liveness(self):
        c = ForgivenessConfig()
        assert abs(recovery_ceiling(RecoverySeverity.LIVENESS, c) - 1.0) < 1e-12

    def test_quality(self):
        c = ForgivenessConfig()
        assert abs(recovery_ceiling(RecoverySeverity.QUALITY, c) - 0.75) < 1e-12

    def test_fraud(self):
        c = ForgivenessConfig()
        assert abs(recovery_ceiling(RecoverySeverity.FRAUD, c) - 0.25) < 1e-12

    def test_systemic(self):
        c = ForgivenessConfig()
        assert abs(recovery_ceiling(RecoverySeverity.SYSTEMIC, c) - 0.0) < 1e-12


class TestApplyForgiveness:
    def test_zero_good_interactions(self):
        c = ForgivenessConfig()
        p = apply_forgiveness(0.05, 0, RecoverySeverity.QUALITY, c)
        assert abs(p - 0.05) < 1e-12

    def test_one_good_interaction(self):
        c = ForgivenessConfig()
        p = apply_forgiveness(0.05, 1, RecoverySeverity.QUALITY, c)
        assert abs(p - 0.04) < 1e-12

    def test_ten_good_interactions_liveness(self):
        c = ForgivenessConfig()
        expected = 0.01 * (0.8 ** 10)
        p = apply_forgiveness(0.01, 10, RecoverySeverity.LIVENESS, c)
        assert abs(p - expected) < 1e-9

    def test_quality_scar_floor(self):
        c = ForgivenessConfig()
        p = apply_forgiveness(0.1, 50, RecoverySeverity.QUALITY, c)
        floor = 0.1 * 0.25
        assert abs(p - floor) < 1e-9

    def test_fraud_scar_floor(self):
        c = ForgivenessConfig()
        p = apply_forgiveness(0.5, 100, RecoverySeverity.FRAUD, c)
        floor = 0.5 * 0.75
        assert abs(p - floor) < 1e-9

    def test_systemic_no_recovery(self):
        c = ForgivenessConfig()
        p = apply_forgiveness(0.8, 1000, RecoverySeverity.SYSTEMIC, c)
        assert abs(p - 0.8) < 1e-12

    def test_zero_penalty(self):
        c = ForgivenessConfig()
        p = apply_forgiveness(0.0, 10, RecoverySeverity.QUALITY, c)
        assert abs(p - 0.0) < 1e-12


class TestAsymmetricDecayWeight:
    def test_positive_unchanged(self):
        w = asymmetric_decay_weight(0.95, 5, False, 1.5)
        expected = 0.95 ** 5
        assert abs(w - expected) < 1e-12

    def test_negative_faster(self):
        w_neg = asymmetric_decay_weight(0.95, 5, True, 1.5)
        w_pos = asymmetric_decay_weight(0.95, 5, False, 1.5)
        assert w_neg < w_pos
        expected = 0.95 ** 7.5
        assert abs(w_neg - expected) < 1e-12

    def test_custom_speedup(self):
        w = asymmetric_decay_weight(0.95, 10, True, 2.0)
        expected = 0.95 ** 20.0
        assert abs(w - expected) < 1e-12
