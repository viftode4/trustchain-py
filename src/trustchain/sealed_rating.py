"""Simultaneous-reveal rating protocol (commit-reveal).

Prevents retaliatory rating by requiring both parties to commit their
ratings before either can see the other's. Eliminates the eBay pathology
where >99% of feedback is positive due to fear of retaliation.

Mirrors Rust ``trustchain-core/src/sealed_rating.rs``.

Research: Bolton, Greiner, Ockenfels 2013 — "Engineering Trust: Reciprocity
in the Production of Reputation Information", Management Science 59(2).
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Optional


# ── Constants ────────────────────────────────────────────────────────────────

DEFAULT_REVEAL_TIMEOUT_MS: int = 3_600_000
"""Default timeout for reveal phase (milliseconds). 1 hour."""

DEFAULT_TIMEOUT_RATING: float = 0.5
"""Default rating when reveal times out (uncertain/neutral)."""

MIN_NONCE_LENGTH: int = 16
"""Minimum valid nonce length in bytes (hex-encoded = 2x this)."""


# ── Types ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SealedRatingConfig:
    """Configuration for the sealed rating protocol."""

    reveal_timeout_ms: int = DEFAULT_REVEAL_TIMEOUT_MS
    timeout_default_rating: float = DEFAULT_TIMEOUT_RATING


@dataclass(frozen=True)
class RatingCommitment:
    """A rating commitment: SHA-256 of (formatted rating || nonce)."""

    commitment_hash: str
    committed_at: int


@dataclass(frozen=True)
class RatingReveal:
    """A revealed rating with its nonce for verification."""

    rating: float
    nonce: str


# ── Functions ────────────────────────────────────────────────────────────────


def _compute_commitment_hash(rating: float, nonce_hex: str) -> str:
    """Compute commitment hash: SHA-256(f"{rating:.6f}{nonce_hex}") as hex.

    This format is canonical across Rust and Python SDKs.
    """
    input_str = f"{rating:.6f}{nonce_hex}"
    return hashlib.sha256(input_str.encode("utf-8")).hexdigest()


def create_commitment(rating: float, timestamp_ms: int) -> tuple[RatingCommitment, str]:
    """Create a commitment for a rating.

    Returns (commitment, nonce_hex). The caller must store the nonce
    secretly until the reveal phase.
    """
    nonce_bytes = os.urandom(MIN_NONCE_LENGTH)
    nonce_hex = nonce_bytes.hex()

    commitment_hash = _compute_commitment_hash(rating, nonce_hex)

    commitment = RatingCommitment(
        commitment_hash=commitment_hash,
        committed_at=timestamp_ms,
    )

    return commitment, nonce_hex


def verify_reveal(commitment: RatingCommitment, reveal: RatingReveal) -> bool:
    """Verify that a reveal matches a commitment.

    Recomputes hash and compares to stored commitment hash.
    """
    expected = _compute_commitment_hash(reveal.rating, reveal.nonce)
    return expected == commitment.commitment_hash


def extract_sealed_rating(transaction: dict) -> Optional[float]:
    """Extract a verified sealed rating from a transaction dict.

    Returns the rating if revealed and valid, None if sealed-but-pending
    or no sealed rating fields, None if reveal is invalid.
    """
    commitment_hash = transaction.get("rating_commitment")
    if commitment_hash is None:
        return None

    revealed_rating = transaction.get("revealed_rating")
    nonce = transaction.get("rating_nonce")

    if revealed_rating is None or nonce is None:
        return None  # Sealed but not revealed

    commitment = RatingCommitment(
        commitment_hash=str(commitment_hash),
        committed_at=0,
    )
    reveal = RatingReveal(
        rating=float(revealed_rating),
        nonce=str(nonce),
    )

    if verify_reveal(commitment, reveal):
        return max(0.0, min(1.0, float(revealed_rating)))
    return None  # Invalid reveal


def is_reveal_timed_out(
    commitment: RatingCommitment,
    now_ms: int,
    config: SealedRatingConfig,
) -> bool:
    """Check if a rating commitment has timed out."""
    return now_ms > commitment.committed_at + config.reveal_timeout_ms


def effective_sealed_rating(
    transaction: dict,
    now_ms: int,
    config: SealedRatingConfig,
) -> Optional[float]:
    """Get the effective rating from a sealed rating transaction.

    1. Revealed and verified -> use revealed rating.
    2. Timed out -> use default rating (0.5).
    3. Sealed but within reveal window -> None (pending).
    """
    commitment_hash = transaction.get("rating_commitment")
    if commitment_hash is None:
        return None

    # Check if revealed
    revealed_rating = transaction.get("revealed_rating")
    nonce = transaction.get("rating_nonce")

    if revealed_rating is not None and nonce is not None:
        commitment = RatingCommitment(
            commitment_hash=str(commitment_hash),
            committed_at=0,
        )
        reveal = RatingReveal(
            rating=float(revealed_rating),
            nonce=str(nonce),
        )
        if verify_reveal(commitment, reveal):
            return max(0.0, min(1.0, float(revealed_rating)))
        # Invalid reveal falls through to timeout check

    # Check timeout
    committed_at = transaction.get("rating_committed_at", 0)
    commitment = RatingCommitment(
        commitment_hash=str(commitment_hash),
        committed_at=int(committed_at),
    )

    if is_reveal_timed_out(commitment, now_ms, config):
        return config.timeout_default_rating

    return None  # Pending reveal
