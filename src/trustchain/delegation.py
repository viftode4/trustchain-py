"""Delegation, revocation, and succession for ephemeral agent identities.

Extends TrustChain's bilateral half-block model (IETF draft-pouwelse-trustchain-01)
to support hierarchical delegation: persistent identities (operators) delegate
authority to ephemeral identities (agents) with scope, depth, and TTL constraints.

Trust budget splits across active delegations (never copies) to preserve
Sybil resistance (IETF §5). Fraud by delegates propagates upward to the
delegator (hard zero, matching the double-spend penalty in trust computation).
"""

from __future__ import annotations

import hashlib
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DelegationCertificate:
    """Proof that a persistent identity has delegated authority to an ephemeral agent.

    Carried by the ephemeral agent and presented during the proposal phase.
    The counterparty verifies the chain of delegation back to a persistent
    identity and looks up that identity's trust score.
    """

    # The delegator (parent) who grants authority
    delegator_pubkey: str  # Ed25519 pubkey hex

    # The delegate (child) who receives authority
    delegate_pubkey: str  # Ed25519 pubkey hex

    # Scope and constraints
    scope: List[str]  # Allowed interaction types (empty = wildcard)
    max_depth: int  # Sub-delegations allowed (0 = leaf, max 2)

    # Time bounds
    issued_at: float  # Unix timestamp
    expires_at: float  # Unix timestamp; hard TTL

    # Chain linkage
    delegation_seq: int  # Seq number of Delegation block on delegator's chain
    delegation_block_hash: str  # Hash of the Delegation block

    # Parent delegation chain (for sub-delegations)
    parent_certificate: Optional[DelegationCertificate] = None

    # Signatures
    delegator_signature: str = ""  # Ed25519 sig by delegator over canonical payload
    delegate_signature: str = ""  # Ed25519 sig by delegate (proves key possession)

    @property
    def certificate_hash(self) -> str:
        """SHA-256 of the canonical payload (excluding signatures)."""
        payload = {
            "delegator_pubkey": self.delegator_pubkey,
            "delegate_pubkey": self.delegate_pubkey,
            "scope": sorted(self.scope),
            "max_depth": self.max_depth,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "delegation_seq": self.delegation_seq,
            "delegation_block_hash": self.delegation_block_hash,
        }
        if self.parent_certificate is not None:
            payload["parent_certificate_hash"] = self.parent_certificate.certificate_hash
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    @property
    def chain_depth(self) -> int:
        """How deep this delegation is. Direct=1, sub-delegation=2, etc."""
        if self.parent_certificate is None:
            return 1
        return 1 + self.parent_certificate.chain_depth

    @property
    def root_pubkey(self) -> str:
        """The persistent identity at the root of the delegation chain."""
        if self.parent_certificate is None:
            return self.delegator_pubkey
        return self.parent_certificate.root_pubkey

    def is_expired(self, now: Optional[int] = None) -> bool:
        """Check if the certificate has expired."""
        if now is None:
            now = int(time.time() * 1000)
        return now >= self.expires_at

    def scope_matches(self, interaction_type: str) -> bool:
        """Check if this delegation covers the given interaction type."""
        if not self.scope:  # empty = wildcard
            return True
        return interaction_type in self.scope

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-compatible dictionary."""
        d: Dict[str, Any] = {
            "delegator_pubkey": self.delegator_pubkey,
            "delegate_pubkey": self.delegate_pubkey,
            "scope": self.scope,
            "max_depth": self.max_depth,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "delegation_seq": self.delegation_seq,
            "delegation_block_hash": self.delegation_block_hash,
            "delegator_signature": self.delegator_signature,
            "delegate_signature": self.delegate_signature,
        }
        if self.parent_certificate is not None:
            d["parent_certificate"] = self.parent_certificate.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DelegationCertificate:
        """Deserialize from a dictionary."""
        parent = None
        if "parent_certificate" in data and data["parent_certificate"] is not None:
            parent = cls.from_dict(data["parent_certificate"])
        return cls(
            delegator_pubkey=data["delegator_pubkey"],
            delegate_pubkey=data["delegate_pubkey"],
            scope=data["scope"],
            max_depth=data["max_depth"],
            issued_at=data["issued_at"],
            expires_at=data["expires_at"],
            delegation_seq=data["delegation_seq"],
            delegation_block_hash=data["delegation_block_hash"],
            parent_certificate=parent,
            delegator_signature=data.get("delegator_signature", ""),
            delegate_signature=data.get("delegate_signature", ""),
        )


@dataclass
class DelegationRecord:
    """In-store representation of a delegation relationship."""

    delegation_id: str
    delegator_pubkey: str
    delegate_pubkey: str
    scope: List[str]
    max_depth: int
    issued_at: float
    expires_at: float
    delegation_block_hash: str  # Hash of the delegation proposal block
    agreement_block_hash: str  # Hash of the delegation agreement block
    revoked: bool = False
    revocation_block_hash: Optional[str] = None
    revoked_at: Optional[float] = None
    parent_delegation_id: Optional[str] = None  # For sub-delegations

    @property
    def is_active(self) -> bool:
        """A delegation is active if it is not revoked and not expired."""
        if self.revoked:
            return False
        return int(time.time() * 1000) < self.expires_at


class DelegationStore(ABC):
    """Storage extensions for delegation, revocation, and succession.

    Introduced as a mixin rather than modifying BlockStore to
    preserve backward compatibility with existing implementations.
    """

    @abstractmethod
    def add_delegation(self, delegation: DelegationRecord) -> None:
        """Store a delegation record. Raises on duplicate delegation_id."""

    @abstractmethod
    def get_delegation(self, delegation_id: str) -> Optional[DelegationRecord]:
        """Retrieve a delegation by its ID."""

    @abstractmethod
    def get_delegations_by_delegator(self, delegator_pubkey: str) -> List[DelegationRecord]:
        """Get all delegations issued by a delegator (active and inactive)."""

    @abstractmethod
    def get_delegation_by_delegate(self, delegate_pubkey: str) -> Optional[DelegationRecord]:
        """Get the delegation for a given delegate (if any).

        A delegate has at most one active delegation.
        """

    @abstractmethod
    def get_active_delegation_count(self, delegator_pubkey: str) -> int:
        """Count active (non-revoked, non-expired) delegations for a delegator."""

    @abstractmethod
    def revoke_delegation(self, delegation_id: str, revocation_block_hash: str) -> None:
        """Mark a delegation as revoked."""

    @abstractmethod
    def is_revoked(self, delegation_id: str) -> bool:
        """Check if a delegation has been revoked."""

    @abstractmethod
    def is_delegate(self, pubkey: str) -> bool:
        """Check if a pubkey has ever been a delegate (active, revoked, or expired)."""

    @abstractmethod
    def add_succession(self, old_pubkey: str, new_pubkey: str, succession_block_hash: str) -> None:
        """Record a key succession."""

    @abstractmethod
    def get_successor(self, old_pubkey: str) -> Optional[str]:
        """Get the successor pubkey for a retired key, if any."""

    @abstractmethod
    def get_predecessor(self, new_pubkey: str) -> Optional[str]:
        """Get the predecessor pubkey for a key that was rotated to, if any."""

    @abstractmethod
    def resolve_current_identity(self, pubkey: str) -> str:
        """Follow the succession chain to find the current active pubkey."""


class MemoryDelegationStore(DelegationStore):
    """In-memory implementation of DelegationStore for testing."""

    def __init__(self) -> None:
        self._delegations: Dict[str, DelegationRecord] = {}  # delegation_id -> record
        self._successions: Dict[str, str] = {}  # old_pubkey -> new_pubkey
        self._reverse_successions: Dict[str, str] = {}  # new_pubkey -> old_pubkey

    def add_delegation(self, delegation: DelegationRecord) -> None:
        if delegation.delegation_id in self._delegations:
            raise ValueError(f"Duplicate delegation_id: {delegation.delegation_id}")
        self._delegations[delegation.delegation_id] = delegation

    def get_delegation(self, delegation_id: str) -> Optional[DelegationRecord]:
        return self._delegations.get(delegation_id)

    def get_delegations_by_delegator(self, delegator_pubkey: str) -> List[DelegationRecord]:
        return [
            d for d in self._delegations.values()
            if d.delegator_pubkey == delegator_pubkey
        ]

    def get_delegation_by_delegate(self, delegate_pubkey: str) -> Optional[DelegationRecord]:
        for d in self._delegations.values():
            if d.delegate_pubkey == delegate_pubkey and d.is_active:
                return d
        return None

    def get_active_delegation_count(self, delegator_pubkey: str) -> int:
        return sum(
            1 for d in self._delegations.values()
            if d.delegator_pubkey == delegator_pubkey and d.is_active
        )

    def revoke_delegation(self, delegation_id: str, revocation_block_hash: str) -> None:
        d = self._delegations.get(delegation_id)
        if d is None:
            raise ValueError(f"Unknown delegation_id: {delegation_id}")
        d.revoked = True
        d.revocation_block_hash = revocation_block_hash
        d.revoked_at = int(time.time() * 1000)

    def is_revoked(self, delegation_id: str) -> bool:
        d = self._delegations.get(delegation_id)
        if d is None:
            return False
        return d.revoked

    def is_delegate(self, pubkey: str) -> bool:
        return any(d.delegate_pubkey == pubkey for d in self._delegations.values())

    def add_succession(self, old_pubkey: str, new_pubkey: str, succession_block_hash: str) -> None:
        if old_pubkey in self._successions:
            raise ValueError(f"Succession already exists for {old_pubkey[:16]}...")
        self._successions[old_pubkey] = new_pubkey
        self._reverse_successions[new_pubkey] = old_pubkey

    def get_successor(self, old_pubkey: str) -> Optional[str]:
        return self._successions.get(old_pubkey)

    def get_predecessor(self, new_pubkey: str) -> Optional[str]:
        return self._reverse_successions.get(new_pubkey)

    def resolve_current_identity(self, pubkey: str) -> str:
        current = pubkey
        seen: set[str] = {current}
        while current in self._successions:
            current = self._successions[current]
            if current in seen:
                break  # cycle protection
            seen.add(current)
        return current
