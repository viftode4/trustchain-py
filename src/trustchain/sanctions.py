"""Graduated sanctions framework for trust violations.

Implements Ostrom's Principle #5 (graduated sanctions, 1990) with a
Cosmos/Ethereum-inspired severity hierarchy (500x ratio between levels).

Mirrors Rust ``trustchain-core/src/sanctions.rs``.

Research: Ostrom 1990, Cox et al. 2010, Cosmos slashing model,
``negative-feedback-punishment.md`` §2.1.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


# ── Types ────────────────────────────────────────────────────────────────────

class ViolationSeverity(str, Enum):
    """Violation severity classification.

    Severity hierarchy: Liveness(0.0001) → Quality(0.05) → Byzantine(1.0).
    ~500x ratio between adjacent levels (Cosmos-inspired).
    """

    LIVENESS = "liveness"
    QUALITY = "quality"
    BYZANTINE = "byzantine"


@dataclass(frozen=True)
class SanctionConfig:
    """Configuration for graduated sanctions.

    Use default values for research-validated parameters.
    """

    liveness_penalty: float = 0.0001
    quality_penalty_base: float = 0.05
    byzantine_penalty: float = 1.0
    forgiveness_decay: float = 0.95


@dataclass(frozen=True)
class Violation:
    """A single classified violation with its computed penalty."""

    severity: ViolationSeverity
    penalty: float


@dataclass(frozen=True)
class SanctionResult:
    """Result of sanctions computation: cumulative penalties."""

    total_penalty: float
    violation_count: int
    violations: List[Violation] = field(default_factory=list)


# ── Functions ────────────────────────────────────────────────────────────────

def classify_violation(
    timeout_count: int,
    avg_quality: float,
    fraud: bool,
) -> Optional[ViolationSeverity]:
    """Classify observable evidence into the highest-severity violation.

    Priority: Byzantine > Quality > Liveness > None.
    """
    if fraud:
        return ViolationSeverity.BYZANTINE
    if avg_quality < 0.3:
        return ViolationSeverity.QUALITY
    if timeout_count > 0:
        return ViolationSeverity.LIVENESS
    return None


def compute_penalty(
    severity: ViolationSeverity,
    config: SanctionConfig,
    quality_gap: float = 0.0,
) -> float:
    """Compute penalty for a single violation type.

    - Liveness: ``config.liveness_penalty`` (flat per occurrence).
    - Quality: ``config.quality_penalty_base * quality_gap``.
    - Byzantine: ``config.byzantine_penalty`` (always 1.0).
    """
    if severity == ViolationSeverity.LIVENESS:
        return config.liveness_penalty
    if severity == ViolationSeverity.QUALITY:
        return config.quality_penalty_base * max(0.0, quality_gap)
    if severity == ViolationSeverity.BYZANTINE:
        return config.byzantine_penalty
    return 0.0  # unreachable


def compute_sanctions(
    timeout_count: int,
    avg_quality: float,
    fraud: bool,
    config: SanctionConfig,
) -> SanctionResult:
    """Compute cumulative sanctions from observable trust evidence.

    Multiple violation types can stack. Total penalty is capped at 1.0.
    """
    violations: List[Violation] = []
    total = 0.0

    # Byzantine: proven fraud
    if fraud:
        penalty = config.byzantine_penalty
        violations.append(Violation(
            severity=ViolationSeverity.BYZANTINE,
            penalty=penalty,
        ))
        total += penalty

    # Quality: avg_quality below threshold
    if avg_quality < 0.3:
        quality_gap = max(0.0, 0.5 - avg_quality)
        penalty = config.quality_penalty_base * quality_gap
        violations.append(Violation(
            severity=ViolationSeverity.QUALITY,
            penalty=penalty,
        ))
        total += penalty

    # Liveness: timeouts
    if timeout_count > 0:
        penalty = config.liveness_penalty * timeout_count
        violations.append(Violation(
            severity=ViolationSeverity.LIVENESS,
            penalty=penalty,
        ))
        total += penalty

    return SanctionResult(
        total_penalty=max(0.0, min(1.0, total)),
        violation_count=len(violations),
        violations=violations,
    )
