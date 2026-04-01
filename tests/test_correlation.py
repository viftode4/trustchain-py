"""Tests for correlation-based delegation penalty (Layer 4.2).

Mirrors Rust trustchain-core/src/correlation.rs inline tests.
"""

from trustchain.correlation import (
    CorrelationConfig,
    compute_delegator_correlation_penalty,
    delegation_tree_penalty,
    delegator_penalty,
)


class TestCorrelationConfig:
    def test_defaults(self):
        c = CorrelationConfig()
        assert abs(c.correlation_multiplier - 3.0) < 1e-12
        assert abs(c.delegator_propagation - 0.4) < 1e-12


class TestDelegationTreePenalty:
    def test_single_failure_in_large_tree(self):
        c = CorrelationConfig()
        # 1/10 failed, base_penalty = 0.05 → 0.05 * 3.0 * 0.1 = 0.015
        p = delegation_tree_penalty(1, 10, 0.05, c)
        assert abs(p - 0.015) < 1e-12

    def test_all_failures_capped(self):
        c = CorrelationConfig()
        # 10/10 failed, base_penalty = 0.5 → 0.5 * 3.0 * 1.0 = 1.5, clamped to 1.0
        p = delegation_tree_penalty(10, 10, 0.5, c)
        assert abs(p - 1.0) < 1e-12

    def test_zero_failures(self):
        c = CorrelationConfig()
        p = delegation_tree_penalty(0, 10, 0.5, c)
        assert abs(p - 0.0) < 1e-12

    def test_empty_tree(self):
        c = CorrelationConfig()
        p = delegation_tree_penalty(0, 0, 0.5, c)
        assert abs(p - 0.0) < 1e-12

    def test_amplifies_with_fraction(self):
        c = CorrelationConfig()
        p1 = delegation_tree_penalty(1, 10, 0.1, c)
        p5 = delegation_tree_penalty(5, 10, 0.1, c)
        assert p5 > p1
        assert abs(p1 - 0.03) < 1e-12
        assert abs(p5 - 0.15) < 1e-12


class TestDelegatorPenalty:
    def test_40_percent(self):
        c = CorrelationConfig()
        p = delegator_penalty(0.5, c)
        assert abs(p - 0.2) < 1e-12

    def test_zero_worker(self):
        c = CorrelationConfig()
        p = delegator_penalty(0.0, c)
        assert abs(p - 0.0) < 1e-12

    def test_capped(self):
        c = CorrelationConfig()
        p = delegator_penalty(3.0, c)
        assert abs(p - 1.0) < 1e-12


class TestComputeDelegatorCorrelationPenalty:
    def test_empty_list(self):
        c = CorrelationConfig()
        p = compute_delegator_correlation_penalty([], c)
        assert abs(p - 0.0) < 1e-12

    def test_no_failures(self):
        c = CorrelationConfig()
        delegates = [(0.0, False), (0.0, False), (0.0, False)]
        p = compute_delegator_correlation_penalty(delegates, c)
        assert abs(p - 0.0) < 1e-12

    def test_single_failure(self):
        c = CorrelationConfig()
        delegates = [(0.05, True), (0.0, False), (0.0, False)]
        p = compute_delegator_correlation_penalty(delegates, c)
        assert abs(p - 0.02) < 1e-12

    def test_multiple_failures_amplified(self):
        c = CorrelationConfig()
        delegates = [(0.1, True), (0.1, True), (0.1, True), (0.0, False), (0.0, False)]
        p = compute_delegator_correlation_penalty(delegates, c)
        assert abs(p - 0.216) < 1e-9

    def test_all_failed_capped(self):
        c = CorrelationConfig()
        delegates = [(1.0, True), (1.0, True), (1.0, True)]
        p = compute_delegator_correlation_penalty(delegates, c)
        assert abs(p - 1.0) < 1e-12

    def test_custom_config(self):
        c = CorrelationConfig(correlation_multiplier=5.0, delegator_propagation=0.3)
        p = delegation_tree_penalty(2, 4, 0.1, c)
        assert abs(p - 0.25) < 1e-12
        dp = delegator_penalty(1.0, c)
        assert abs(dp - 0.3) < 1e-12
