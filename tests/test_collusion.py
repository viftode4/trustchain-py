"""Tests for trustchain.collusion — mirrors Rust collusion.rs tests 1:1."""

from trustchain.collusion import (
    CollusionConfig,
    has_reciprocity_anomaly,
    peer_concentration,
    detect_collusion,
)


class TestCollusionConfig:
    def test_defaults(self) -> None:
        c = CollusionConfig()
        assert abs(c.min_cluster_density - 0.6) < 1e-12
        assert abs(c.max_external_ratio - 0.3) < 1e-12
        assert c.reciprocity_min_interactions == 3
        assert abs(c.reciprocity_symmetry_threshold - 0.05) < 1e-12
        assert abs(c.concentration_threshold - 0.8) < 1e-12
        assert c.concentration_top_n == 3


class TestHasReciprocityAnomaly:
    def test_symmetric_high(self) -> None:
        c = CollusionConfig()
        assert has_reciprocity_anomaly([(0.95, 0.96, 5)], c)

    def test_asymmetric(self) -> None:
        c = CollusionConfig()
        assert not has_reciprocity_anomaly([(0.9, 0.3, 5)], c)

    def test_insufficient_count(self) -> None:
        c = CollusionConfig()
        assert not has_reciprocity_anomaly([(0.95, 0.95, 2)], c)

    def test_low_scores(self) -> None:
        c = CollusionConfig()
        assert not has_reciprocity_anomaly([(0.3, 0.3, 5)], c)

    def test_empty(self) -> None:
        c = CollusionConfig()
        assert not has_reciprocity_anomaly([], c)

    def test_one_clean_one_suspicious(self) -> None:
        c = CollusionConfig()
        pairs = [(0.5, 0.9, 5), (0.92, 0.93, 4)]
        assert has_reciprocity_anomaly(pairs, c)


class TestPeerConcentration:
    def test_empty(self) -> None:
        assert abs(peer_concentration([], 0, 3) - 0.0) < 1e-12

    def test_diverse(self) -> None:
        counts = [10, 8, 7, 6, 5, 4]
        result = peer_concentration(counts, 40, 3)
        assert abs(result - 0.625) < 1e-12, f"expected 0.625, got {result}"

    def test_monopoly(self) -> None:
        counts = [50, 1, 1]
        result = peer_concentration(counts, 52, 3)
        assert abs(result - 1.0) < 1e-12, f"expected 1.0, got {result}"

    def test_fewer_peers_than_top_n(self) -> None:
        counts = [10, 5]
        result = peer_concentration(counts, 15, 3)
        assert abs(result - 1.0) < 1e-12, f"expected 1.0, got {result}"


class TestDetectCollusion:
    def test_clean(self) -> None:
        c = CollusionConfig()
        pairs = [(0.7, 0.5, 4), (0.6, 0.8, 3)]
        counts = [5, 4, 3, 2, 1]
        result = detect_collusion(0.0, 0.0, False, pairs, counts, 15, c)
        assert not result.reciprocity_anomaly
        assert abs(result.peer_concentration - 0.8) < 1e-12
        assert not result.temporal_burst

    def test_reciprocity_flagged(self) -> None:
        c = CollusionConfig()
        pairs = [(0.95, 0.96, 5)]
        counts = [5]
        result = detect_collusion(0.0, 0.0, False, pairs, counts, 5, c)
        assert result.reciprocity_anomaly
        assert abs(result.peer_concentration - 1.0) < 1e-12

    def test_passthrough_metrics(self) -> None:
        c = CollusionConfig()
        result = detect_collusion(0.75, 0.05, True, [], [], 0, c)
        assert abs(result.cluster_density - 0.75) < 1e-12
        assert abs(result.external_connection_ratio - 0.05) < 1e-12
        assert result.temporal_burst
