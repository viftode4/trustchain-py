"""Correlation-based delegation penalty for trust violation amplification.

Implements Ethereum PoS-style correlation penalty (Buterin et al. 2020) and
supply chain liability (Management Science 2024) for delegation trees.

Mirrors Rust ``trustchain-core/src/correlation.rs``.

Research: Ethereum PoS correlation penalty (Buterin et al. 2020),
Management Science 2024 (supply chain liability, 0.3-0.5 range).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple


# ── Types ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CorrelationConfig:
    """Configuration for correlation-based delegation penalties.

    Use default values for research-validated parameters.
    """

    correlation_multiplier: float = 3.0
    """Ethereum-inspired multiplier for correlated failures."""

    delegator_propagation: float = 0.4
    """Fraction of worker penalty propagated to delegator (0.3-0.5 range)."""


# ── Functions ────────────────────────────────────────────────────────────────


def delegation_tree_penalty(
    failed_count: int,
    total_in_tree: int,
    base_penalty: float,
    config: CorrelationConfig,
) -> float:
    """Compute correlation penalty for a delegation tree.

    Formula: ``base_penalty * correlation_multiplier * (failed_count / total_in_tree)``

    Returns 0.0 when total_in_tree is 0 or failed_count is 0.
    Result is clamped to [0.0, 1.0].
    """
    if total_in_tree == 0 or failed_count == 0:
        return 0.0
    fraction = failed_count / total_in_tree
    return max(0.0, min(1.0, base_penalty * config.correlation_multiplier * fraction))


def delegator_penalty(
    worker_penalty: float,
    config: CorrelationConfig,
) -> float:
    """Compute the penalty propagated from a worker to its delegator.

    Formula: ``worker_penalty * delegator_propagation``

    Returns 0.0 when worker_penalty is 0.0 or negative.
    Result is clamped to [0.0, 1.0].
    """
    if worker_penalty <= 0.0:
        return 0.0
    return max(0.0, min(1.0, worker_penalty * config.delegator_propagation))


def compute_delegator_correlation_penalty(
    delegate_penalties: List[Tuple[float, bool]],
    config: CorrelationConfig,
) -> float:
    """Compute the total correlation-adjusted penalty for a delegator.

    Each entry in ``delegate_penalties`` is ``(individual_penalty, is_failed)``.

    1. Sums individual delegate penalties propagated to the delegator.
    2. Computes the correlation fraction (failed / total).
    3. Applies the Ethereum-style correlation multiplier.

    Returns 0.0 when the list is empty or no delegates have failed.
    Result is clamped to [0.0, 1.0].
    """
    if not delegate_penalties:
        return 0.0

    total = len(delegate_penalties)
    failed_count = sum(1 for _, failed in delegate_penalties if failed)

    if failed_count == 0:
        return 0.0

    # Sum propagated penalties from failed delegates
    propagated_sum = sum(
        delegator_penalty(penalty, config)
        for penalty, failed in delegate_penalties
        if failed
    )

    # Apply correlation amplification
    fraction = failed_count / total
    correlation_factor = config.correlation_multiplier * fraction

    return max(0.0, min(1.0, propagated_sum * correlation_factor))
