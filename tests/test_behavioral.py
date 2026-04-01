"""Tests for trustchain.behavioral — mirrors Rust behavioral.rs tests 1:1."""

from trustchain.behavioral import (
    BehavioralConfig,
    failure_rate,
    detect_behavioral_change,
    detect_selective_targeting,
)


class TestBehavioralConfig:
    def test_defaults(self) -> None:
        c = BehavioralConfig()
        assert c.recent_window == 10
        assert c.baseline_window == 30
        assert abs(c.anomaly_threshold - 0.3) < 1e-12
        assert abs(c.selective_targeting_multiplier - 2.0) < 1e-12
        assert c.selective_min_samples == 3


class TestFailureRate:
    def test_empty(self) -> None:
        assert abs(failure_rate([]) - 0.0) < 1e-12

    def test_all_good(self) -> None:
        assert abs(failure_rate([1.0, 0.8, 0.6]) - 0.0) < 1e-12

    def test_all_bad(self) -> None:
        assert abs(failure_rate([0.1, 0.2, 0.3]) - 1.0) < 1e-12

    def test_mixed(self) -> None:
        assert abs(failure_rate([0.9, 0.1, 0.9, 0.1]) - 0.5) < 1e-12

    def test_boundary(self) -> None:
        assert abs(failure_rate([0.5]) - 0.0) < 1e-12
        assert abs(failure_rate([0.49]) - 1.0) < 1e-12


class TestDetectBehavioralChange:
    def test_insufficient_history(self) -> None:
        c = BehavioralConfig()
        result = detect_behavioral_change([0.1] * 10, c)
        assert not result.is_anomalous
        assert abs(result.change_magnitude - 0.0) < 1e-12

    def test_stable(self) -> None:
        c = BehavioralConfig()
        result = detect_behavioral_change([0.8] * 40, c)
        assert abs(result.recent_failure_rate - 0.0) < 1e-12
        assert abs(result.baseline_failure_rate - 0.0) < 1e-12
        assert abs(result.change_magnitude - 0.0) < 1e-12
        assert not result.is_anomalous

    def test_worsening(self) -> None:
        c = BehavioralConfig()
        qualities = [0.9] * 30 + [0.1] * 10
        result = detect_behavioral_change(qualities, c)
        assert abs(result.recent_failure_rate - 1.0) < 1e-12
        assert abs(result.baseline_failure_rate - 0.0) < 1e-12
        assert abs(result.change_magnitude - 1.0) < 1e-12
        assert result.is_anomalous

    def test_improving(self) -> None:
        c = BehavioralConfig()
        qualities = [0.1] * 30 + [0.9] * 10
        result = detect_behavioral_change(qualities, c)
        assert abs(result.recent_failure_rate - 0.0) < 1e-12
        assert abs(result.baseline_failure_rate - 1.0) < 1e-12
        assert abs(result.change_magnitude - (-1.0)) < 1e-12
        assert not result.is_anomalous  # negative change is not anomalous

    def test_below_threshold(self) -> None:
        c = BehavioralConfig()
        # Baseline: 30 entries, 10% failure
        qualities = [0.9] * 27 + [0.1] * 3
        # Recent: 10 entries, 20% failure
        qualities += [0.9] * 8 + [0.1] * 2
        result = detect_behavioral_change(qualities, c)
        assert abs(result.change_magnitude - 0.1) < 1e-12
        assert not result.is_anomalous

    def test_exactly_at_threshold(self) -> None:
        c = BehavioralConfig()
        # Baseline: 30 entries, 0 failures
        qualities = [0.9] * 30
        # Recent: 10 entries, 3 failures = 30%
        qualities += [0.9] * 7 + [0.1] * 3
        result = detect_behavioral_change(qualities, c)
        assert abs(result.change_magnitude - 0.3) < 1e-12
        assert result.is_anomalous


class TestDetectSelectiveTargeting:
    def test_not_flagged(self) -> None:
        c = BehavioralConfig()
        to_new = [0.9, 0.1, 0.9, 0.1, 0.9]
        to_est = [0.9, 0.1, 0.9, 0.1, 0.9]
        result = detect_selective_targeting(to_new, to_est, c)
        assert not result.is_selective

    def test_flagged(self) -> None:
        c = BehavioralConfig()
        to_new = [0.1, 0.1, 0.1, 0.1, 0.9]  # 0.8
        to_est = [0.9, 0.9, 0.9, 0.9, 0.1]  # 0.2
        result = detect_selective_targeting(to_new, to_est, c)
        assert abs(result.failure_rate_to_new - 0.8) < 1e-12
        assert abs(result.failure_rate_to_established - 0.2) < 1e-12
        assert result.is_selective

    def test_insufficient_samples(self) -> None:
        c = BehavioralConfig()
        to_new = [0.1, 0.1]
        to_est = [0.9, 0.9, 0.9, 0.9, 0.9]
        result = detect_selective_targeting(to_new, to_est, c)
        assert not result.is_selective

    def test_both_high_failure(self) -> None:
        c = BehavioralConfig()
        to_new = [0.1, 0.1, 0.1, 0.1]
        to_est = [0.1, 0.1, 0.1, 0.1]
        result = detect_selective_targeting(to_new, to_est, c)
        assert not result.is_selective

    def test_new_low_established_zero(self) -> None:
        c = BehavioralConfig()
        to_new = [0.1, 0.1, 0.9, 0.9, 0.9]  # 0.4
        to_est = [0.9, 0.9, 0.9]  # 0.0
        result = detect_selective_targeting(to_new, to_est, c)
        assert result.is_selective
