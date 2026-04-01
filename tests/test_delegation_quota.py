"""Tests for Layer 6.2: Delegation quota limits.

MAX_ACTIVE_DELEGATIONS = 10 per delegator.
Revoked and expired delegations don't count against the quota.
"""

from __future__ import annotations

import pytest

from trustchain.blockstore import MemoryBlockStore
from trustchain.delegation import MemoryDelegationStore
from trustchain.exceptions import DelegationError
from trustchain.identity import Identity
from trustchain.protocol import (
    MAX_ACTIVE_DELEGATIONS,
    TrustChainProtocol,
)


def _make_protocol() -> TrustChainProtocol:
    """Create a protocol instance with a random identity."""
    return TrustChainProtocol(Identity(), MemoryBlockStore())


def _create_n_delegations(
    delegator: TrustChainProtocol,
    ds: MemoryDelegationStore,
    n: int,
) -> None:
    """Create n accepted delegations from delegator to fresh identities."""
    for _ in range(n):
        delegate = _make_protocol()
        delegate.delegation_store = ds
        proposal = delegator.create_delegation(
            delegate.pubkey, scope=[], max_depth=0, ttl_seconds=3600.0,
        )
        delegate.accept_delegation(proposal)


class TestDelegationQuota:
    """Layer 6.2: MAX_ACTIVE_DELEGATIONS enforcement."""

    def test_below_limit_succeeds(self):
        delegator = _make_protocol()
        ds = MemoryDelegationStore()
        delegator.delegation_store = ds

        _create_n_delegations(delegator, ds, 9)

        # 10th should succeed (at the limit, not over).
        delegate = _make_protocol()
        delegate.delegation_store = ds
        proposal = delegator.create_delegation(
            delegate.pubkey, scope=[], max_depth=0, ttl_seconds=3600.0,
        )
        delegate.accept_delegation(proposal)
        assert ds.get_active_delegation_count(delegator.pubkey) == 10

    def test_at_limit_rejects(self):
        delegator = _make_protocol()
        ds = MemoryDelegationStore()
        delegator.delegation_store = ds

        _create_n_delegations(delegator, ds, MAX_ACTIVE_DELEGATIONS)

        with pytest.raises(DelegationError, match="delegation quota exceeded"):
            delegator.create_delegation(
                _make_protocol().pubkey,
                scope=[],
                max_depth=0,
                ttl_seconds=3600.0,
            )

    def test_revoked_dont_count(self):
        delegator = _make_protocol()
        ds = MemoryDelegationStore()
        delegator.delegation_store = ds

        _create_n_delegations(delegator, ds, MAX_ACTIVE_DELEGATIONS)

        # Revoke one delegation.
        delegations = ds.get_delegations_by_delegator(delegator.pubkey)
        ds.revoke_delegation(delegations[0].delegation_id, "revoke_hash")

        # Now should succeed — only 9 active.
        delegate = _make_protocol()
        delegate.delegation_store = ds
        proposal = delegator.create_delegation(
            delegate.pubkey, scope=[], max_depth=0, ttl_seconds=3600.0,
        )
        delegate.accept_delegation(proposal)

    def test_no_store_no_check(self):
        """Without a delegation store, quota is not enforced."""
        delegator = _make_protocol()
        # delegation_store is None by default.
        assert delegator.delegation_store is None
        delegate = _make_protocol()
        # Should succeed without any quota check.
        proposal = delegator.create_delegation(
            delegate.pubkey, scope=[], max_depth=0, ttl_seconds=3600.0,
        )
        assert proposal is not None
