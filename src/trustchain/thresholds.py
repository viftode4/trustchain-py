"""Decision-support trust thresholds for risk-adjusted transacting.

Three pure functions:

- :func:`min_trust_threshold` — Josang & Presti 2004 decision trust.
- :func:`risk_threshold` — composite risk-scaled threshold.
- :func:`required_deposit` — trust-gated escrow (Asgaonkar & Krishnamachari 2019).

Mirrors Rust ``trustchain-core/src/thresholds.rs``.
"""

from __future__ import annotations

import math

# ── Constants for risk_threshold formula ─────────────────────────────────────

_BASE: float = 0.1
_V_FACTOR: float = 0.25
_D_FACTOR: float = 0.15
_U_PENALTY: float = 0.2
_R_DISCOUNT: float = 0.1
_BASE_VALUE: float = 10.0
_BASE_DURATION: float = 1.0


# ── L3.3: Josang Decision Trust Threshold ────────────────────────────────────

def min_trust_threshold(transaction_value: float, expected_gain: float) -> float:
    """Minimum trust threshold for a transaction (Josang & Presti 2004).

    Formula: ``threshold = loss / (loss + gain)``.

    Returns 0.5 when both values are zero or negative.
    Result is clamped to [0.0, 1.0].
    """
    if transaction_value <= 0.0 and expected_gain <= 0.0:
        return 0.5
    denom = transaction_value + expected_gain
    if denom <= 0.0:
        return 0.5
    return max(0.0, min(1.0, transaction_value / denom))


# ── L3.4: Risk-Scaled Threshold ──────────────────────────────────────────────

def risk_threshold(
    value: float,
    duration_hours: float,
    confidence: float,
    recovery_rate: float,
) -> float:
    """Composite risk-scaled trust threshold.

    Combines Josang decision trust + TRAVOS confidence + actuarial risk.
    Research: ``risk-scaled-trust-thresholds.md`` §9.6.

    Result is clamped to [0.05, 0.95].
    """
    result = (
        _BASE
        + _V_FACTOR * max(0.0, math.log(value / _BASE_VALUE))
        + _D_FACTOR * max(0.0, math.log(duration_hours / _BASE_DURATION))
        + _U_PENALTY * (1.0 - confidence)
        - _R_DISCOUNT * recovery_rate
    )
    return max(0.05, min(0.95, result))


# ── L3.5: Trust-Gated Escrow ─────────────────────────────────────────────────

def required_deposit(transaction_value: float, trust_score: float) -> float:
    """Required deposit for a transaction (Asgaonkar & Krishnamachari 2019).

    Formula: ``deposit = value * (1 - trust)``.

    Trust score is clamped to [0.0, 1.0] before computation.
    """
    clamped = max(0.0, min(1.0, trust_score))
    return transaction_value * (1.0 - clamped)
