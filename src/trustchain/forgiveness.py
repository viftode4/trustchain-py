"""Forgiveness and trust recovery after violations.

Implements graduated trust recovery with severity-dependent ceilings
and asymmetric decay (negative outcomes decay faster than positive).

Mirrors Rust ``trustchain-core/src/forgiveness.rs``.

Research: Josang, Ismail, Boyd 2007; Axelrod 1984; Vasalou et al. 2008;
Nowak & Sigmund 1992; ``negative-feedback-punishment.md`` §5.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


# ── Types ────────────────────────────────────────────────────────────────────


class RecoverySeverity(str, Enum):
    """Recovery severity classification for ceiling determination.

    Extends ViolationSeverity with SYSTEMIC for delegation-propagated fraud.
    """

    LIVENESS = "liveness"
    QUALITY = "quality"
    FRAUD = "fraud"
    SYSTEMIC = "systemic"


@dataclass(frozen=True)
class ForgivenessConfig:
    """Configuration for forgiveness / trust recovery.

    Use default values for research-validated parameters.
    """

    decay_per_good_interaction: float = 0.8
    """Each good interaction reduces remaining penalty by 20%."""

    liveness_recovery_ceiling: float = 1.0
    """Full recovery possible for liveness violations."""

    quality_recovery_ceiling: float = 0.75
    """Recovery ceiling for quality violations (-25% scar)."""

    fraud_recovery_ceiling: float = 0.25
    """Recovery ceiling for fraud (-75% scar)."""

    negative_decay_speedup: float = 1.5
    """Negatives age 50% faster than positives in recency."""


# ── Functions ────────────────────────────────────────────────────────────────


def recovery_ceiling(severity: RecoverySeverity, config: ForgivenessConfig) -> float:
    """Get the recovery ceiling for a given severity level.

    Returns a value in [0.0, 1.0].
    """
    if severity == RecoverySeverity.LIVENESS:
        return config.liveness_recovery_ceiling
    if severity == RecoverySeverity.QUALITY:
        return config.quality_recovery_ceiling
    if severity == RecoverySeverity.FRAUD:
        return config.fraud_recovery_ceiling
    # SYSTEMIC
    return 0.0


def apply_forgiveness(
    initial_penalty: float,
    good_interactions_since: int,
    severity: RecoverySeverity,
    config: ForgivenessConfig,
) -> float:
    """Compute the forgiveness-adjusted penalty.

    Formula: ``adjusted = initial_penalty * decay^good_interactions``

    The result is further bounded by the recovery ceiling (trust scar).
    Returns 0.0 when initial_penalty is 0.0 or negative.
    Result is clamped to [0.0, 1.0].
    """
    if initial_penalty <= 0.0:
        return 0.0

    ceiling = recovery_ceiling(severity, config)

    # Systemic: no recovery at all
    if ceiling <= 0.0:
        return max(0.0, min(1.0, initial_penalty))

    # Decay penalty by good interactions
    decayed = initial_penalty * (config.decay_per_good_interaction ** good_interactions_since)

    # Floor: penalty cannot drop below the scar level
    scar_floor = initial_penalty * (1.0 - ceiling)

    return max(0.0, min(1.0, max(decayed, scar_floor)))


def asymmetric_decay_weight(
    base_lambda: float,
    age: int,
    is_negative: bool,
    negative_decay_speedup: float,
) -> float:
    """Compute asymmetric decay weight for recency computation.

    Positive outcomes: ``lambda^age``.
    Negative outcomes: ``lambda^(age * speedup)``.
    """
    if is_negative:
        return base_lambda ** (age * negative_decay_speedup)
    return base_lambda ** age
