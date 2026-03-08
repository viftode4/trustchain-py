"""TrustChain v2 protocol engine — two-phase proposal/agreement flow.

Implements the real TU Delft TrustChain protocol:
  1. A creates a PROPOSAL half-block (link_sequence_number=0), signs it, sends to B
  2. B validates, creates an AGREEMENT half-block linking back to A's, signs it
  3. Both parties store both half-blocks

Per Otte, de Vos, Pouwelse 2020; IETF draft-pouwelse-trustchain-01.
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from trustchain.blockstore import BlockStore
from trustchain.delegation import (
    DelegationCertificate,
    DelegationRecord,
    DelegationStore,
)
from trustchain.exceptions import (
    AgreementError,
    DelegationError,
    PrevHashMismatchError,
    ProposalError,
    SequenceGapError,
    SignatureError,
    SuccessionError,
)
from trustchain.halfblock import (
    GENESIS_HASH,
    BlockType,
    HalfBlock,
    _now_ms,
    create_half_block,
    verify_block,
)
from trustchain.identity import Identity

logger = logging.getLogger("trustchain.protocol")

# Maximum allowed TTL for a delegation: 30 days in milliseconds.
# Enforced in the core protocol so it cannot be bypassed regardless of transport.
MAX_DELEGATION_TTL_MS = 30 * 24 * 3600 * 1000  # 2_592_000_000 ms


class TrustChainProtocol:
    """Two-phase proposal/agreement protocol engine.

    Each instance is bound to a single identity and block store.
    """

    def __init__(
        self,
        identity: Identity,
        store: BlockStore,
        delegation_store: Optional[DelegationStore] = None,
    ) -> None:
        self.identity = identity
        self.store = store
        self.delegation_store = delegation_store

    @property
    def pubkey(self) -> str:
        return self.identity.pubkey_hex

    def create_proposal(
        self,
        counterparty_pubkey: str,
        transaction: Dict[str, Any],
        timestamp: Optional[float] = None,
    ) -> HalfBlock:
        """Create and sign a PROPOSAL half-block.

        - seq = store.get_latest_seq(my_pubkey) + 1
        - prev_hash = store.get_head_hash(my_pubkey)
        - link_sequence_number = 0 (unknown until agreement)
        - Sign with own key, store locally
        """
        # Scope enforcement: if we are a delegate with a restricted scope,
        # only allow proposals for interaction types within that scope.
        if self.delegation_store is not None:
            my_delegation = self.delegation_store.get_delegation_by_delegate(self.pubkey)
            if my_delegation is not None and my_delegation.is_active and my_delegation.scope:
                interaction_type = transaction.get("interaction_type", "")
                if interaction_type and interaction_type not in my_delegation.scope:
                    raise DelegationError(
                        self.pubkey,
                        detail=f"Interaction type '{interaction_type}' not in delegation scope {my_delegation.scope}",
                    )

        seq = self.store.get_latest_seq(self.pubkey) + 1
        prev_hash = self.store.get_head_hash(self.pubkey)

        block = create_half_block(
            identity=self.identity,
            sequence_number=seq,
            link_public_key=counterparty_pubkey,
            link_sequence_number=0,  # proposal: counterparty seq unknown
            previous_hash=prev_hash,
            block_type=BlockType.PROPOSAL,
            transaction=transaction,
            timestamp=timestamp or _now_ms(),
        )

        self.store.add_block(block)
        logger.debug(
            "Created proposal: %s seq=%d -> %s",
            self.identity.short_id,
            seq,
            counterparty_pubkey[:16],
        )
        return block

    def receive_proposal(self, proposal: HalfBlock) -> bool:
        """Validate an incoming proposal from a counterparty.

        Checks:
        - Block type is PROPOSAL
        - link_public_key matches our pubkey (proposal is for us)
        - Signature is valid
        - Hash is valid
        - Sequence is valid for proposer's known chain

        Returns True if valid. Raises on failure.
        """
        if proposal.block_type != BlockType.PROPOSAL:
            raise ProposalError(
                proposal.public_key,
                proposal.sequence_number,
                f"Expected proposal, got {proposal.block_type}",
            )

        if proposal.link_public_key != self.pubkey:
            raise ProposalError(
                proposal.public_key,
                proposal.sequence_number,
                f"Proposal not addressed to us ({self.pubkey[:16]}...)",
            )

        if not verify_block(proposal):
            raise SignatureError(
                proposal.public_key,
                proposal.sequence_number,
            )

        # Validate sequence continuity for proposer's chain (if we know it)
        known_seq = self.store.get_latest_seq(proposal.public_key)
        if known_seq > 0:
            if proposal.sequence_number <= known_seq:
                raise ProposalError(
                    proposal.public_key,
                    proposal.sequence_number,
                    f"Sequence {proposal.sequence_number} <= known latest {known_seq}",
                )
            if proposal.sequence_number > known_seq + 1:
                raise SequenceGapError(
                    pubkey=proposal.public_key,
                    expected=known_seq + 1,
                    got=proposal.sequence_number,
                )

            # Verify previous_hash links to our stored predecessor
            expected_prev = self.store.get_head_hash(proposal.public_key)
            if proposal.previous_hash != expected_prev:
                raise PrevHashMismatchError(
                    pubkey=proposal.public_key,
                    seq=proposal.sequence_number,
                    expected=expected_prev,
                    got=proposal.previous_hash,
                )

        # Store the proposal (counterparty's block, in our store for verification)
        try:
            self.store.add_block(proposal)
        except ValueError:
            pass  # Already stored (idempotent)

        logger.debug(
            "Received valid proposal from %s seq=%d",
            proposal.public_key[:16],
            proposal.sequence_number,
        )
        return True

    def create_agreement(
        self,
        proposal: HalfBlock,
        timestamp: Optional[float] = None,
    ) -> HalfBlock:
        """Create an AGREEMENT half-block in response to a valid proposal.

        - seq = store.get_latest_seq(my_pubkey) + 1
        - prev_hash = store.get_head_hash(my_pubkey)
        - link_public_key = proposal.public_key
        - link_sequence_number = proposal.sequence_number
        - transaction = copy of proposal's transaction
        - Sign with own key, store locally
        """
        if proposal.block_type != BlockType.PROPOSAL:
            raise AgreementError(
                self.pubkey,
                detail=f"Cannot agree to non-proposal block type: {proposal.block_type}",
            )

        if proposal.link_public_key != self.pubkey:
            raise AgreementError(
                self.pubkey,
                detail="Proposal is not addressed to us",
            )

        # Defense-in-depth: verify proposal integrity even if receive_proposal was called
        if not verify_block(proposal):
            raise SignatureError(
                proposal.public_key,
                proposal.sequence_number,
            )

        seq = self.store.get_latest_seq(self.pubkey) + 1
        prev_hash = self.store.get_head_hash(self.pubkey)

        block = create_half_block(
            identity=self.identity,
            sequence_number=seq,
            link_public_key=proposal.public_key,
            link_sequence_number=proposal.sequence_number,
            previous_hash=prev_hash,
            block_type=BlockType.AGREEMENT,
            transaction=proposal.transaction,
            timestamp=timestamp or _now_ms(),
        )

        self.store.add_block(block)
        logger.debug(
            "Created agreement: %s seq=%d -> %s seq=%d",
            self.identity.short_id,
            seq,
            proposal.public_key[:16],
            proposal.sequence_number,
        )
        return block

    def receive_agreement(self, agreement: HalfBlock) -> bool:
        """Validate and store an incoming agreement.

        Checks:
        - Block type is AGREEMENT
        - It links back to one of our proposals
        - Signature and hash are valid
        - The linked proposal exists in our store

        Returns True if valid. Raises on failure.
        """
        if agreement.block_type != BlockType.AGREEMENT:
            raise AgreementError(
                agreement.public_key,
                agreement.sequence_number,
                f"Expected agreement, got {agreement.block_type}",
            )

        if agreement.link_public_key != self.pubkey:
            raise AgreementError(
                agreement.public_key,
                agreement.sequence_number,
                "Agreement does not link to our chain",
            )

        if not verify_block(agreement):
            raise SignatureError(
                agreement.public_key,
                agreement.sequence_number,
            )

        # Verify the linked proposal exists
        proposal = self.store.get_block(
            self.pubkey, agreement.link_sequence_number
        )
        if proposal is None:
            raise AgreementError(
                agreement.public_key,
                agreement.sequence_number,
                f"No proposal found at ({self.pubkey[:16]}..., seq={agreement.link_sequence_number})",
            )

        if proposal.block_type != BlockType.PROPOSAL:
            raise AgreementError(
                agreement.public_key,
                agreement.sequence_number,
                f"Linked block is not a proposal: {proposal.block_type}",
            )

        # Verify transaction content matches the proposal
        if agreement.transaction != proposal.transaction:
            raise AgreementError(
                agreement.public_key,
                agreement.sequence_number,
                "Agreement transaction does not match proposal transaction",
            )

        # Store the agreement
        try:
            self.store.add_block(agreement)
        except ValueError:
            pass  # Already stored (idempotent)

        logger.debug(
            "Received valid agreement from %s seq=%d for our proposal seq=%d",
            agreement.public_key[:16],
            agreement.sequence_number,
            agreement.link_sequence_number,
        )
        return True

    def validate_chain(self, pubkey: str) -> bool:
        """Full chain validation for a given agent.

        Checks:
        - Contiguous sequence numbers starting at 1
        - Hash links: each block's previous_hash matches prior block's block_hash
        - All signatures valid
        """
        chain = self.store.get_chain(pubkey)
        if not chain:
            return True  # Empty chain is valid

        for i, block in enumerate(chain):
            expected_seq = i + 1
            if block.sequence_number != expected_seq:
                raise SequenceGapError(
                    pubkey=pubkey,
                    expected=expected_seq,
                    got=block.sequence_number,
                )

            expected_prev = (
                GENESIS_HASH if i == 0 else chain[i - 1].block_hash
            )
            if block.previous_hash != expected_prev:
                raise PrevHashMismatchError(
                    pubkey=pubkey,
                    seq=block.sequence_number,
                    expected=expected_prev,
                    got=block.previous_hash,
                )

            if not verify_block(block):
                raise SignatureError(pubkey=pubkey, seq=block.sequence_number)

        return True

    def integrity_score(self, pubkey: str) -> float:
        """Chain integrity as float [0.0, 1.0].

        Returns fraction of blocks that are valid before the first break.
        """
        chain = self.store.get_chain(pubkey)
        if not chain:
            return 1.0

        valid_count = 0
        for i, block in enumerate(chain):
            expected_seq = i + 1
            if block.sequence_number != expected_seq:
                break

            expected_prev = (
                GENESIS_HASH if i == 0 else chain[i - 1].block_hash
            )
            if block.previous_hash != expected_prev:
                break

            if not verify_block(block):
                break

            valid_count += 1

        return valid_count / len(chain)

    # --- Delegation protocol ---

    def create_delegation(
        self,
        delegate_pubkey: str,
        scope: List[str],
        max_depth: int = 0,
        ttl_seconds: float = 3600.0,
    ) -> HalfBlock:
        """Create a DELEGATION proposal for an ephemeral agent.

        The delegator proposes, the delegate must agree (bilateral).
        Returns the delegator's half-block (proposal).
        """
        if max_depth > 2:
            raise DelegationError(self.pubkey, detail="max_depth cannot exceed 2")

        ttl_ms = int(ttl_seconds * 1000)
        if ttl_ms > MAX_DELEGATION_TTL_MS:
            raise DelegationError(
                self.pubkey,
                detail=(
                    f"TTL {ttl_ms} ms exceeds maximum allowed "
                    f"{MAX_DELEGATION_TTL_MS} ms (30 days)"
                ),
            )

        now = _now_ms()
        delegation_id = hashlib.sha256(
            f"{self.pubkey}:{delegate_pubkey}:{now}".encode()
        ).hexdigest()

        # Validate sub-delegation constraints
        if self.delegation_store is not None:
            my_delegation = self.delegation_store.get_delegation_by_delegate(self.pubkey)
            if my_delegation is not None:
                if max_depth >= my_delegation.max_depth:
                    raise DelegationError(
                        self.pubkey,
                        detail=f"Sub-delegation max_depth {max_depth} must be < parent's {my_delegation.max_depth}",
                    )
                if my_delegation.scope:
                    if not scope:
                        # Empty scope = unrestricted, which is a superset of
                        # the parent's restricted scope — this is escalation.
                        raise DelegationError(
                            self.pubkey,
                            detail="Sub-delegation scope must not be unrestricted when parent scope is restricted",
                        )
                    if not set(scope).issubset(set(my_delegation.scope)):
                        raise DelegationError(
                            self.pubkey,
                            detail="Sub-delegation scope must be subset of parent scope",
                        )
                if not my_delegation.is_active:
                    raise DelegationError(
                        self.pubkey, detail="Cannot sub-delegate from expired/revoked delegation"
                    )

            # Circular delegation check
            self._check_circular_delegation(delegate_pubkey)

        transaction = {
            "interaction_type": "delegation",
            "outcome": "proposed",
            "scope": scope,
            "max_depth": max_depth,
            "expires_at": now + ttl_ms,
            "delegation_id": delegation_id,
        }

        seq = self.store.get_latest_seq(self.pubkey) + 1
        prev_hash = self.store.get_head_hash(self.pubkey)

        block = create_half_block(
            identity=self.identity,
            sequence_number=seq,
            link_public_key=delegate_pubkey,
            link_sequence_number=0,
            previous_hash=prev_hash,
            block_type=BlockType.DELEGATION,
            transaction=transaction,
            timestamp=now,
        )

        self.store.add_block(block)
        logger.debug(
            "Created delegation proposal: %s -> %s (scope=%s, depth=%d)",
            self.identity.short_id,
            delegate_pubkey[:16],
            scope,
            max_depth,
        )
        return block

    def accept_delegation(
        self, delegation_proposal: HalfBlock
    ) -> Tuple[HalfBlock, DelegationCertificate]:
        """Accept a delegation proposal (delegate side).

        Creates an agreement half-block and returns both the block and
        a DelegationCertificate for presentation during interactions.
        """
        if delegation_proposal.block_type != BlockType.DELEGATION:
            raise DelegationError(self.pubkey, detail="Not a delegation proposal")

        if delegation_proposal.link_public_key != self.pubkey:
            raise DelegationError(self.pubkey, detail="Delegation not addressed to us")

        if not verify_block(delegation_proposal):
            raise SignatureError(
                delegation_proposal.public_key, delegation_proposal.sequence_number
            )

        tx = delegation_proposal.transaction

        # Check TTL
        if _now_ms() >= tx["expires_at"]:
            raise DelegationError(self.pubkey, detail="Delegation already expired")

        # Check if this delegation was already revoked
        if self.delegation_store is not None:
            existing = self.delegation_store.get_delegation(tx["delegation_id"])
            if existing is not None and existing.revoked:
                raise DelegationError(self.pubkey, detail="Delegation has been revoked")

        # Create agreement
        seq = self.store.get_latest_seq(self.pubkey) + 1
        prev_hash = self.store.get_head_hash(self.pubkey)

        agreement_tx = {
            "interaction_type": "delegation",
            "outcome": "accepted",
            "scope": tx["scope"],
            "max_depth": tx["max_depth"],
            "expires_at": tx["expires_at"],
            "delegation_id": tx["delegation_id"],
        }

        agreement = create_half_block(
            identity=self.identity,
            sequence_number=seq,
            link_public_key=delegation_proposal.public_key,
            link_sequence_number=delegation_proposal.sequence_number,
            previous_hash=prev_hash,
            block_type=BlockType.DELEGATION,
            transaction=agreement_tx,
        )

        self.store.add_block(agreement)

        # Resolve parent certificate for sub-delegations
        parent_cert = None
        parent_delegation_id = None
        if self.delegation_store is not None:
            my_delegation = self.delegation_store.get_delegation_by_delegate(
                delegation_proposal.public_key
            )
            if my_delegation is not None:
                parent_delegation_id = my_delegation.delegation_id

        # Build DelegationCertificate
        cert = DelegationCertificate(
            delegator_pubkey=delegation_proposal.public_key,
            delegate_pubkey=self.pubkey,
            scope=tx["scope"],
            max_depth=tx["max_depth"],
            issued_at=delegation_proposal.timestamp,
            expires_at=tx["expires_at"],
            delegation_seq=delegation_proposal.sequence_number,
            delegation_block_hash=delegation_proposal.block_hash,
            parent_certificate=parent_cert,
            delegator_signature=delegation_proposal.signature,
            delegate_signature=agreement.signature,
        )

        # Store the delegation record
        if self.delegation_store is not None:
            record = DelegationRecord(
                delegation_id=tx["delegation_id"],
                delegator_pubkey=delegation_proposal.public_key,
                delegate_pubkey=self.pubkey,
                scope=tx["scope"],
                max_depth=tx["max_depth"],
                issued_at=delegation_proposal.timestamp,
                expires_at=tx["expires_at"],
                delegation_block_hash=delegation_proposal.block_hash,
                agreement_block_hash=agreement.block_hash,
                parent_delegation_id=parent_delegation_id,
            )
            self.delegation_store.add_delegation(record)

        logger.debug(
            "Accepted delegation from %s (id=%s)",
            delegation_proposal.public_key[:16],
            tx["delegation_id"][:16],
        )
        return agreement, cert

    def create_revocation(self, delegation_id: str) -> HalfBlock:
        """Revoke a delegation. Unilateral: only delegator signs.

        Returns the revocation block.
        """
        if self.delegation_store is None:
            raise DelegationError(self.pubkey, detail="No delegation store configured")

        delegation = self.delegation_store.get_delegation(delegation_id)
        if delegation is None:
            raise DelegationError(self.pubkey, detail=f"Unknown delegation: {delegation_id}")

        if delegation.delegator_pubkey != self.pubkey:
            raise DelegationError(self.pubkey, detail="Only the delegator can revoke")

        if delegation.revoked:
            raise DelegationError(self.pubkey, detail="Already revoked")

        seq = self.store.get_latest_seq(self.pubkey) + 1
        prev_hash = self.store.get_head_hash(self.pubkey)

        block = create_half_block(
            identity=self.identity,
            sequence_number=seq,
            link_public_key=delegation.delegate_pubkey,
            link_sequence_number=0,  # unilateral — no counterparty seq
            previous_hash=prev_hash,
            block_type=BlockType.REVOCATION,
            transaction={
                "interaction_type": "revocation",
                "outcome": "revoked",
                "delegation_id": delegation_id,
            },
        )

        self.store.add_block(block)
        self.delegation_store.revoke_delegation(delegation_id, block.block_hash)

        logger.debug(
            "Revoked delegation %s (delegate=%s)",
            delegation_id[:16],
            delegation.delegate_pubkey[:16],
        )
        return block

    def create_succession(self, new_identity: Identity) -> HalfBlock:
        """Create a succession proposal to rotate to a new key.

        Both the old key (self.identity) and new key must sign.
        Returns the old key's proposal half-block.
        """
        now = _now_ms()
        succession_id = hashlib.sha256(
            f"{self.pubkey}:{new_identity.pubkey_hex}:{now}".encode()
        ).hexdigest()

        # Old chain must have at least one block
        if self.store.get_latest_seq(self.pubkey) == 0:
            raise SuccessionError(
                self.pubkey, new_identity.pubkey_hex,
                detail="Cannot succeed from an empty chain",
            )

        seq = self.store.get_latest_seq(self.pubkey) + 1
        prev_hash = self.store.get_head_hash(self.pubkey)

        block = create_half_block(
            identity=self.identity,
            sequence_number=seq,
            link_public_key=new_identity.pubkey_hex,
            link_sequence_number=0,
            previous_hash=prev_hash,
            block_type=BlockType.SUCCESSION,
            transaction={
                "interaction_type": "succession",
                "outcome": "proposed",
                "succession_id": succession_id,
            },
            timestamp=now,
        )

        self.store.add_block(block)
        logger.debug(
            "Created succession proposal: %s -> %s",
            self.identity.short_id,
            new_identity.pubkey_hex[:16],
        )
        return block

    def accept_succession(self, succession_proposal: HalfBlock) -> HalfBlock:
        """Accept a succession proposal (new key side).

        Returns the new key's agreement half-block.
        """
        if succession_proposal.block_type != BlockType.SUCCESSION:
            raise SuccessionError(
                succession_proposal.public_key,
                detail="Not a succession proposal",
            )

        if succession_proposal.link_public_key != self.pubkey:
            raise SuccessionError(
                succession_proposal.public_key,
                self.pubkey,
                detail="Succession not addressed to us",
            )

        if not verify_block(succession_proposal):
            raise SignatureError(
                succession_proposal.public_key,
                succession_proposal.sequence_number,
            )

        seq = self.store.get_latest_seq(self.pubkey) + 1
        prev_hash = self.store.get_head_hash(self.pubkey)

        agreement = create_half_block(
            identity=self.identity,
            sequence_number=seq,
            link_public_key=succession_proposal.public_key,
            link_sequence_number=succession_proposal.sequence_number,
            previous_hash=prev_hash,
            block_type=BlockType.SUCCESSION,
            transaction={
                "interaction_type": "succession",
                "outcome": "accepted",
                "succession_id": succession_proposal.transaction["succession_id"],
            },
        )

        self.store.add_block(agreement)

        # Record the succession
        if self.delegation_store is not None:
            self.delegation_store.add_succession(
                old_pubkey=succession_proposal.public_key,
                new_pubkey=self.pubkey,
                succession_block_hash=succession_proposal.block_hash,
            )

        logger.debug(
            "Accepted succession from %s -> %s",
            succession_proposal.public_key[:16],
            self.identity.short_id,
        )
        return agreement

    def create_proposal_with_delegation(
        self,
        counterparty_pubkey: str,
        transaction: Dict[str, Any],
        delegation_certificate: DelegationCertificate,
        timestamp: Optional[float] = None,
    ) -> HalfBlock:
        """Create a proposal that embeds a delegation certificate.

        Used by delegated agents to prove their authority during interactions.
        """
        if delegation_certificate.is_expired():
            raise DelegationError(self.pubkey, detail="Delegation certificate has expired")

        if delegation_certificate.delegate_pubkey != self.pubkey:
            raise DelegationError(self.pubkey, detail="Certificate is not for us")

        # Embed cert in transaction
        enriched_tx = {**transaction, "_delegation": delegation_certificate.to_dict()}
        return self.create_proposal(counterparty_pubkey, enriched_tx, timestamp)

    def verify_delegation_certificate(
        self,
        cert: DelegationCertificate,
        proposer_pubkey: str,
        interaction_type: Optional[str] = None,
    ) -> None:
        """Verify a delegation certificate chain.

        Called by the counterparty when receiving a proposal with _delegation.
        Raises DelegationError on any validation failure.
        """
        from trustchain.identity import Identity

        # 1. Certificate is for the proposing agent
        if cert.delegate_pubkey != proposer_pubkey:
            raise DelegationError(proposer_pubkey, detail="Certificate delegate mismatch")

        # 2. Not expired
        if cert.is_expired():
            raise DelegationError(proposer_pubkey, detail="Delegation certificate expired")

        # 3. Depth check
        if cert.chain_depth > 2:
            raise DelegationError(proposer_pubkey, detail="Delegation chain too deep (max 2)")

        # 4. Scope enforcement
        if interaction_type and not cert.scope_matches(interaction_type):
            raise DelegationError(
                proposer_pubkey,
                detail=f"Delegation scope does not cover '{interaction_type}'",
            )

        # 5. Verify via backing block — the block IS the proof of delegation.
        # The delegator_signature on the cert is the block's Ed25519 signature
        # (over the block hash, not the certificate hash). We verify the block
        # itself to confirm the delegator actually signed the delegation.
        delegator_block = self.store.get_block(cert.delegator_pubkey, cert.delegation_seq)
        if delegator_block is not None:
            if not verify_block(delegator_block):
                raise DelegationError(
                    proposer_pubkey, detail="Invalid delegator block signature"
                )
            # Confirm the block hash matches the certificate
            if delegator_block.block_hash != cert.delegation_block_hash:
                raise DelegationError(
                    proposer_pubkey, detail="Delegation block hash mismatch"
                )
        elif not cert.delegator_signature:
            # No block in our store AND no signature on the cert — can't verify
            raise DelegationError(
                proposer_pubkey,
                detail="Cannot verify delegation: no backing block available",
            )

        # 7. Check revocation
        if self.delegation_store is not None:
            delegator_block = self.store.get_block(cert.delegator_pubkey, cert.delegation_seq)
            if delegator_block is not None:
                delegation_id = delegator_block.transaction.get("delegation_id")
                if delegation_id and self.delegation_store.is_revoked(delegation_id):
                    raise DelegationError(proposer_pubkey, detail="Delegation has been revoked")

        # 8. Verify parent certificate recursively
        if cert.parent_certificate is not None:
            self.verify_delegation_certificate(cert.parent_certificate, cert.delegator_pubkey)

    def create_audit(
        self,
        transaction: Dict[str, Any],
        timestamp: Optional[float] = None,
    ) -> HalfBlock:
        """Create a self-referencing AUDIT block.

        Audit blocks record unilateral events (no counterparty needed).
        - block_type = BlockType.AUDIT
        - link_public_key = self.pubkey (self-referencing)
        - link_sequence_number = 0
        """
        seq = self.store.get_latest_seq(self.pubkey) + 1
        prev_hash = self.store.get_head_hash(self.pubkey)

        block = create_half_block(
            identity=self.identity,
            sequence_number=seq,
            link_public_key=self.pubkey,
            link_sequence_number=0,
            previous_hash=prev_hash,
            block_type=BlockType.AUDIT,
            transaction=transaction,
            timestamp=timestamp or _now_ms(),
        )

        self.store.add_block(block)
        logger.debug(
            "Created audit block: %s seq=%d action=%s",
            self.identity.short_id,
            seq,
            transaction.get("action", "unknown"),
        )
        return block

    def _check_circular_delegation(self, delegate_pubkey: str) -> None:
        """Reject delegation if it would create a circular chain."""
        if self.delegation_store is None:
            return

        # Walk up from OURSELVES to see if the proposed delegate is an ancestor
        # This catches: A delegates to B, then B tries to delegate back to A
        current = self.pubkey
        seen: set[str] = set()
        while current not in seen:
            seen.add(current)
            deleg = self.delegation_store.get_delegation_by_delegate(current)
            if deleg is None:
                return  # reached root — no cycle
            if deleg.delegator_pubkey == delegate_pubkey:
                raise DelegationError(
                    self.pubkey,
                    detail=f"Circular delegation detected: {self.pubkey[:16]}... -> {delegate_pubkey[:16]}...",
                )
            current = deleg.delegator_pubkey
