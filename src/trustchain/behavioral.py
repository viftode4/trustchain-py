"""Behavioral change detection and selective scamming analysis (Layer 5.1-5.2).

Mirrors Rust ``trustchain-core/src/behavioral.rs``.

Provides the **derivative component** of the trust PID controller:
- **Behavioral change** (L5.1): rolling-window failure rate vs baseline.
- **Selective targeting** (L5.2): different failure rates toward new vs established peers.

All functions are stateless utilities operating on quality lists.

Research: Olfati-Saber et al. 2007 (PID control), Hoffman et al. 2009
(value imbalance attack), Olariu et al. 2024 (cross-segment farming),
trust-model-gaps §5.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List


# ─── Types ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class BehavioralConfig:
    """Configuration for behavioral change detection."""

    recent_window: int = 10
    baseline_window: int = 30
    anomaly_threshold: float = 0.3
    selective_targeting_multiplier: float = 2.0
    selective_min_samples: int = 3


@dataclass(frozen=True)
class BehavioralAnalysis:
    """Result of rolling-window behavioral change detection (Layer 5.1)."""

    recent_failure_rate: float
    baseline_failure_rate: float
    change_magnitude: float
    is_anomalous: bool


@dataclass(frozen=True)
class SelectiveTargetingResult:
    """Result of selective targeting / scamming detection (Layer 5.2)."""

    failure_rate_to_new: float
    failure_rate_to_established: float
    is_selective: bool


# ─── Functions ──────────────────────────────────────────────────────────────


def failure_rate(qualities: List[float]) -> float:
    """Fraction of quality values below 0.5. Returns 0.0 for empty lists."""
    if not qualities:
        return 0.0
    failures = sum(1 for q in qualities if q < 0.5)
    return failures / len(qualities)


def detect_behavioral_change(
    qualities: List[float],
    config: BehavioralConfig = BehavioralConfig(),
) -> BehavioralAnalysis:
    """Detect behavioral change using rolling window vs baseline.

    Splits the quality history (oldest first) into:
    - **recent:** last ``config.recent_window`` entries.
    - **baseline:** the ``config.baseline_window`` entries immediately before recent.

    Research: PID derivative component (Olfati-Saber et al. 2007).
    """
    length = len(qualities)

    if length <= config.recent_window:
        rate = failure_rate(qualities)
        return BehavioralAnalysis(
            recent_failure_rate=rate,
            baseline_failure_rate=rate,
            change_magnitude=0.0,
            is_anomalous=False,
        )

    recent_start = length - config.recent_window
    recent = qualities[recent_start:]

    baseline_end = recent_start
    baseline_start = max(0, baseline_end - config.baseline_window)
    baseline = qualities[baseline_start:baseline_end]

    recent_rate = failure_rate(recent)
    baseline_rate = failure_rate(baseline)
    change = recent_rate - baseline_rate

    return BehavioralAnalysis(
        recent_failure_rate=recent_rate,
        baseline_failure_rate=baseline_rate,
        change_magnitude=change,
        is_anomalous=change >= config.anomaly_threshold,
    )


def detect_selective_targeting(
    qualities_to_new: List[float],
    qualities_to_established: List[float],
    config: BehavioralConfig = BehavioralConfig(),
) -> SelectiveTargetingResult:
    """Detect selective targeting: different failure rates toward new vs established peers.

    Flags selective targeting when:
    1. Both partitions have >= ``config.selective_min_samples`` entries, AND
    2. ``rate_new >= multiplier * max(rate_est, 0.01)``, AND
    3. ``rate_new >= config.anomaly_threshold`` (absolute floor).

    Research: Hoffman et al. 2009, Olariu et al. 2024.
    """
    rate_new = failure_rate(qualities_to_new)
    rate_est = failure_rate(qualities_to_established)

    is_selective = (
        len(qualities_to_new) >= config.selective_min_samples
        and len(qualities_to_established) >= config.selective_min_samples
        and rate_new >= config.selective_targeting_multiplier * max(rate_est, 0.01)
        and rate_new >= config.anomaly_threshold
    )

    return SelectiveTargetingResult(
        failure_rate_to_new=rate_new,
        failure_rate_to_established=rate_est,
        is_selective=is_selective,
    )
