"""Collusion ring detection signals (Layer 5.3).

Mirrors Rust ``trustchain-core/src/collusion.rs``.

Detection signals (MVP — Session 6):
- **Reciprocity anomaly:** peer pairs giving each other near-perfect ratings.
- **Peer concentration:** fraction of interactions going to top-N peers.

Deferred signals (future sessions):
- Cluster density, external connection ratio, temporal burst.

All functions are stateless utilities operating on pre-computed metrics.

Research: Sun et al. 2012, Mukherjee et al. 2012 (GSRank), Hooi et al. 2016
(FRAUDAR), negative-feedback-punishment §4.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple


# ─── Types ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CollusionConfig:
    """Configuration for collusion ring detection."""

    min_cluster_density: float = 0.6
    max_external_ratio: float = 0.3
    reciprocity_min_interactions: int = 3
    reciprocity_symmetry_threshold: float = 0.05
    concentration_threshold: float = 0.8
    concentration_top_n: int = 3


@dataclass(frozen=True)
class CollusionSignals:
    """Collusion signal bundle returned by detection."""

    cluster_density: float
    external_connection_ratio: float
    temporal_burst: bool
    reciprocity_anomaly: bool
    peer_concentration: float


# ─── Functions ──────────────────────────────────────────────────────────────


def has_reciprocity_anomaly(
    pairs: List[Tuple[float, float, int]],
    config: CollusionConfig = CollusionConfig(),
) -> bool:
    """Check if any peer pair shows a reciprocity anomaly.

    Each entry is ``(avg_quality_given, avg_quality_received, interaction_count)``.

    Returns ``True`` if any pair satisfies ALL of:
    1. ``count >= config.reciprocity_min_interactions``
    2. Both ``given >= 0.9`` and ``received >= 0.9``
    3. ``|given - received| < config.reciprocity_symmetry_threshold``

    Research: Sun et al. 2012.
    """
    return any(
        count >= config.reciprocity_min_interactions
        and given >= 0.9
        and received >= 0.9
        and abs(given - received) < config.reciprocity_symmetry_threshold
        for given, received, count in pairs
    )


def peer_concentration(
    counts: List[int],
    total_interactions: int,
    top_n: int,
) -> float:
    """Fraction of interactions going to top-N peers.

    ``counts`` must be sorted descending. Returns 0.0 for empty inputs.
    Result is clamped to [0.0, 1.0].
    """
    if total_interactions == 0 or not counts:
        return 0.0
    top_sum = sum(counts[:top_n])
    return min(max(top_sum / total_interactions, 0.0), 1.0)


def detect_collusion(
    cluster_density: float,
    external_ratio: float,
    temporal_burst: bool,
    reciprocity_pairs: List[Tuple[float, float, int]],
    peer_interaction_counts: List[int],
    total_interactions: int,
    config: CollusionConfig = CollusionConfig(),
) -> CollusionSignals:
    """Detect collusion signals from pre-computed metrics.

    ``cluster_density``, ``external_ratio``, and ``temporal_burst`` are
    passed through. Reciprocity anomaly and peer concentration are computed.

    Research: Sun 2012, Mukherjee 2012, Hooi 2016.
    """
    reciprocity_anomaly = has_reciprocity_anomaly(reciprocity_pairs, config)
    concentration = peer_concentration(
        peer_interaction_counts, total_interactions, config.concentration_top_n
    )

    return CollusionSignals(
        cluster_density=cluster_density,
        external_connection_ratio=external_ratio,
        temporal_burst=temporal_burst,
        reciprocity_anomaly=reciprocity_anomaly,
        peer_concentration=concentration,
    )
