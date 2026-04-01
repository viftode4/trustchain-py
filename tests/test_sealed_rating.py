"""Tests for simultaneous-reveal rating protocol (Layer 4.3).

Mirrors Rust trustchain-core/src/sealed_rating.rs inline tests.
"""

from trustchain.sealed_rating import (
    DEFAULT_REVEAL_TIMEOUT_MS,
    DEFAULT_TIMEOUT_RATING,
    MIN_NONCE_LENGTH,
    RatingCommitment,
    RatingReveal,
    SealedRatingConfig,
    _compute_commitment_hash,
    create_commitment,
    effective_sealed_rating,
    extract_sealed_rating,
    is_reveal_timed_out,
    verify_reveal,
)


class TestSealedRatingConfig:
    def test_defaults(self):
        c = SealedRatingConfig()
        assert c.reveal_timeout_ms == 3_600_000
        assert abs(c.timeout_default_rating - 0.5) < 1e-12


class TestCreateCommitment:
    def test_unique_nonces(self):
        c1, n1 = create_commitment(0.8, 1000)
        c2, n2 = create_commitment(0.8, 1000)
        assert n1 != n2
        assert c1.commitment_hash != c2.commitment_hash

    def test_deterministic_hash(self):
        h1 = _compute_commitment_hash(0.85, "deadbeef")
        h2 = _compute_commitment_hash(0.85, "deadbeef")
        assert h1 == h2


class TestVerifyReveal:
    def test_valid(self):
        commitment, nonce = create_commitment(0.75, 5000)
        reveal = RatingReveal(rating=0.75, nonce=nonce)
        assert verify_reveal(commitment, reveal) is True

    def test_wrong_rating(self):
        commitment, nonce = create_commitment(0.75, 5000)
        reveal = RatingReveal(rating=0.80, nonce=nonce)
        assert verify_reveal(commitment, reveal) is False

    def test_wrong_nonce(self):
        commitment, _nonce = create_commitment(0.75, 5000)
        reveal = RatingReveal(rating=0.75, nonce="wrong_nonce")
        assert verify_reveal(commitment, reveal) is False


class TestExtractSealedRating:
    def test_revealed(self):
        commitment, nonce = create_commitment(0.9, 1000)
        tx = {
            "rating_commitment": commitment.commitment_hash,
            "revealed_rating": 0.9,
            "rating_nonce": nonce,
        }
        result = extract_sealed_rating(tx)
        assert result == 0.9

    def test_sealed_only(self):
        commitment, _nonce = create_commitment(0.9, 1000)
        tx = {"rating_commitment": commitment.commitment_hash}
        result = extract_sealed_rating(tx)
        assert result is None

    def test_no_commitment(self):
        tx = {"quality": 0.85}
        result = extract_sealed_rating(tx)
        assert result is None

    def test_invalid_nonce(self):
        commitment, _nonce = create_commitment(0.9, 1000)
        tx = {
            "rating_commitment": commitment.commitment_hash,
            "revealed_rating": 0.9,
            "rating_nonce": "totally_wrong_nonce",
        }
        result = extract_sealed_rating(tx)
        assert result is None


class TestIsRevealTimedOut:
    def test_timed_out(self):
        c = SealedRatingConfig()
        commitment = RatingCommitment(commitment_hash="abc", committed_at=1000)
        assert is_reveal_timed_out(commitment, 3_601_001, c) is True

    def test_within_window(self):
        c = SealedRatingConfig()
        commitment = RatingCommitment(commitment_hash="abc", committed_at=1000)
        assert is_reveal_timed_out(commitment, 2_000_000, c) is False


class TestEffectiveSealedRating:
    def test_revealed(self):
        c = SealedRatingConfig()
        commitment, nonce = create_commitment(0.7, 1000)
        tx = {
            "rating_commitment": commitment.commitment_hash,
            "rating_committed_at": 1000,
            "revealed_rating": 0.7,
            "rating_nonce": nonce,
        }
        result = effective_sealed_rating(tx, 2000, c)
        assert result == 0.7

    def test_timed_out(self):
        c = SealedRatingConfig()
        commitment, _nonce = create_commitment(0.7, 1000)
        tx = {
            "rating_commitment": commitment.commitment_hash,
            "rating_committed_at": 1000,
        }
        result = effective_sealed_rating(tx, 100_000_000, c)
        assert result == 0.5

    def test_pending(self):
        c = SealedRatingConfig()
        commitment, _nonce = create_commitment(0.7, 1000)
        tx = {
            "rating_commitment": commitment.commitment_hash,
            "rating_committed_at": 1000,
        }
        result = effective_sealed_rating(tx, 2000, c)
        assert result is None

    def test_no_sealed_fields(self):
        c = SealedRatingConfig()
        tx = {"outcome": "completed"}
        assert effective_sealed_rating(tx, 5000, c) is None

    def test_rating_precision(self):
        precise_rating = 0.123456
        commitment, nonce = create_commitment(precise_rating, 1000)
        reveal = RatingReveal(rating=precise_rating, nonce=nonce)
        assert verify_reveal(commitment, reveal) is True

    def test_nonce_minimum_length(self):
        _commitment, nonce = create_commitment(0.5, 1000)
        assert len(nonce) >= MIN_NONCE_LENGTH * 2
