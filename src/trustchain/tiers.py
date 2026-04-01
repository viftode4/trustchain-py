"""Trust tier system — progressive unlocking based on trust and history.

Prevents cross-segment reputation farming, limits rug-pull damage.
Research: risk-scaled-trust-thresholds §9.2, market-mechanisms §4
(Rothschild-Stiglitz screening), Armendariz & Morduch 2010.
"""

from __future__ import annotations

from enum import Enum


class TrustTier(str, Enum):
    """Trust tier levels — progressive access to higher-value transactions."""

    SPOT = "spot"           # T0: trust >= 0.10, no history required
    BASIC = "basic"         # T1: trust >= 0.25, 5+ interactions
    STANDARD = "standard"   # T2: trust >= 0.40, 10+ interactions
    PREMIUM = "premium"     # T3: trust >= 0.55, 20+ interactions
    ENTERPRISE = "enterprise"  # T4: trust >= 0.70, 50+ interactions


# Requirements: (tier, min_trust, min_interactions)
TIER_REQUIREMENTS = [
    (TrustTier.SPOT, 0.10, 0),
    (TrustTier.BASIC, 0.25, 5),
    (TrustTier.STANDARD, 0.40, 10),
    (TrustTier.PREMIUM, 0.55, 20),
    (TrustTier.ENTERPRISE, 0.70, 50),
]


def compute_tier(trust_score: float, interactions: int) -> TrustTier:
    """Compute the highest tier an agent qualifies for.

    CRITICAL: Success at Tier N does NOT automatically grant Tier N+1.
    Must have interactions at Tier N before qualifying for N+1.
    For now, uses total interaction count as proxy for tier history.
    """
    best = TrustTier.SPOT
    for tier, min_trust, min_interactions in TIER_REQUIREMENTS:
        if trust_score >= min_trust and interactions >= min_interactions:
            best = tier
    return best


def max_transaction_value(tier_history: dict[TrustTier, int] | None = None) -> float:
    """Max transaction value based on trust and history.

    Progressive: 20% growth per successful cycle, capped at 50.
    Research: Armendariz & Morduch 2010 (microfinance progressive lending).
    """
    if not tier_history:
        return 10.0
    base = 10.0
    rate = 1.2
    weighted_successes = min(sum(tier_history.values()), 50)
    return base * rate ** weighted_successes
