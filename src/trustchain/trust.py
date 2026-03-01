"""Trust score computation for TrustChain.

v2 adds TrustEngine class that unifies chain integrity, NetFlow, and statistical
scoring. Original v1 functions are preserved as deprecated compat shims.
"""

from __future__ import annotations

import logging
import math
import warnings
from collections import Counter
from typing import Dict, List, Optional, Set

import networkx as nx

from trustchain.blockstore import BlockStore
from trustchain.delegation import DelegationRecord, DelegationStore
from trustchain.netflow import NetFlowTrust
from trustchain.protocol import TrustChainProtocol
from trustchain.store import RecordStore

logger = logging.getLogger("trustchain.trust")


# ===========================================================================
# v2 TrustEngine
# ===========================================================================


class TrustEngine:
    """Unified trust computation combining chain integrity, NetFlow, and statistics.

    Weights:
    - Chain integrity (0.3) — broken chain = major penalty
    - NetFlow score (0.4) — Sybil resistance via max-flow
    - Statistical score (0.3) — interaction history features
    """

    DEFAULT_WEIGHTS = {
        "integrity": 0.3,
        "netflow": 0.4,
        "statistical": 0.3,
    }

    def __init__(
        self,
        store: BlockStore,
        seed_nodes: Optional[List[str]] = None,
        weights: Optional[Dict[str, float]] = None,
        delegation_store: Optional[DelegationStore] = None,
        decay_half_life_ms: Optional[int] = None,
        checkpoint=None,
    ) -> None:
        self.store = store
        self.weights = weights or self.DEFAULT_WEIGHTS.copy()
        self._protocol = TrustChainProtocol(
            # Dummy identity — protocol is used only for validation
            identity=None,  # type: ignore[arg-type]
            store=store,
        )
        self.delegation_store = delegation_store
        self.decay_half_life_ms = decay_half_life_ms
        self.checkpoint = checkpoint
        self.netflow: Optional[NetFlowTrust] = None
        if seed_nodes:
            self.netflow = NetFlowTrust(
                store, seed_nodes, delegation_store=delegation_store
            )

    def compute_trust(
        self, pubkey: str, interaction_type: Optional[str] = None
    ) -> float:
        """Combined trust score [0.0, 1.0].

        If pubkey is a delegated identity and a DelegationStore is configured,
        returns delegated trust (budget-split from the root identity's trust).
        Otherwise, returns the standard trust computation.

        Components (standard path):
        - Chain integrity (weight: 0.3) — broken chain = major penalty
        - NetFlow score (weight: 0.4) — Sybil resistance
        - Statistical score (weight: 0.3) — interaction history

        If NetFlow is not configured (no seed nodes), its weight is
        redistributed to the other components proportionally.
        """
        # Check if this is a delegated identity
        if self.delegation_store is not None:
            # Check active delegation first
            delegation = self.delegation_store.get_delegation_by_delegate(pubkey)
            if delegation is not None:
                return self._compute_delegated_trust(delegation, interaction_type)

            # Check if this was a delegate whose delegation was revoked
            # Revoked delegates get 0 trust — they lost their authority
            if self.delegation_store.is_delegate(pubkey):
                return 0.0

        return self._compute_standard_trust(pubkey)

    def _compute_standard_trust(self, pubkey: str) -> float:
        """Standard trust computation for persistent identities."""
        # Check for fraud by ANY delegate (active OR revoked) — fraud propagation upward.
        # Revoking a delegation does NOT erase the fraud penalty (IETF §5).
        if self.delegation_store is not None:
            delegations = self.delegation_store.get_delegations_by_delegator(pubkey)
            for d in delegations:
                delegate_chain = self.store.get_chain(d.delegate_pubkey)
                if self._has_double_spend(delegate_chain):
                    return 0.0  # Hard zero: delegate fraud = delegator fraud

        integrity = self.compute_chain_integrity(pubkey)
        statistical = self.compute_statistical_score(pubkey)

        if self.netflow:
            netflow_score = self.compute_netflow_score(pubkey)
            score = (
                self.weights["integrity"] * integrity
                + self.weights["netflow"] * netflow_score
                + self.weights["statistical"] * statistical
            )
        else:
            # Redistribute netflow weight
            total_non_nf = self.weights["integrity"] + self.weights["statistical"]
            if total_non_nf > 0:
                w_int = self.weights["integrity"] / total_non_nf
                w_stat = self.weights["statistical"] / total_non_nf
            else:
                w_int = w_stat = 0.5
            score = w_int * integrity + w_stat * statistical

        return round(min(max(score, 0.0), 1.0), 3)

    def _compute_delegated_trust(
        self, delegation: DelegationRecord, interaction_type: Optional[str] = None
    ) -> float:
        """Compute trust for a delegated identity.

        Matches Rust TrustEngine: flat budget split from the root identity's trust.
        effective = root_trust / active_delegation_count_at_root
        No per-level split or depth discount (IETF §5 Sybil resistance).
        """
        # Check expiry
        if not delegation.is_active:
            return 0.0

        # Check scope
        if interaction_type and delegation.scope:
            if interaction_type not in delegation.scope:
                return 0.0

        # Resolve the root identity
        root_pubkey = self._resolve_root(delegation)

        # Compute the root's trust (standard computation)
        root_trust = self._compute_standard_trust(root_pubkey)

        # Flat budget split: root_trust / active_delegation_count at root level
        active_count = self.delegation_store.get_active_delegation_count(root_pubkey)
        active_count = max(active_count, 1)  # avoid division by zero
        effective = root_trust / active_count

        return round(min(max(effective, 0.0), 1.0), 3)

    def _resolve_root(self, delegation: DelegationRecord) -> str:
        """Walk up the delegation chain to find the root persistent identity."""
        if delegation.parent_delegation_id is None:
            return delegation.delegator_pubkey
        parent = self.delegation_store.get_delegation(delegation.parent_delegation_id)
        if parent is None:
            return delegation.delegator_pubkey
        return self._resolve_root(parent)

    def _build_delegation_chain(
        self, delegation: DelegationRecord
    ) -> List[DelegationRecord]:
        """Build the chain from root to this delegation, ordered root-first."""
        chain = [delegation]
        current = delegation
        while current.parent_delegation_id is not None:
            parent = self.delegation_store.get_delegation(current.parent_delegation_id)
            if parent is None:
                break
            chain.append(parent)
            current = parent
        chain.reverse()
        return chain

    @staticmethod
    def _has_double_spend(chain: List) -> bool:
        """Check if a chain contains double-spend evidence (same seq, different hash)."""
        seen_seqs: Dict[int, str] = {}
        for block in chain:
            if block.sequence_number in seen_seqs:
                if seen_seqs[block.sequence_number] != block.block_hash:
                    return True
            seen_seqs[block.sequence_number] = block.block_hash
        return False

    def compute_chain_integrity(self, pubkey: str) -> float:
        """Chain integrity score alone [0.0, 1.0].

        When a finalized checkpoint is attached, blocks with sequence ≤ the
        checkpoint head are trusted (structural checks only, no Ed25519 verify).
        """
        chain = self.store.get_chain(pubkey)
        if not chain:
            return 1.0

        from trustchain.halfblock import GENESIS_HASH, verify_block

        # Determine checkpoint-covered sequence for this pubkey.
        checkpoint_seq = 0
        if self.checkpoint is not None and getattr(self.checkpoint, "finalized", False):
            checkpoint_seq = getattr(self.checkpoint, "chain_heads", {}).get(pubkey, 0)

        valid_count = 0
        for i, block in enumerate(chain):
            expected_seq = i + 1
            if block.sequence_number != expected_seq:
                break

            expected_prev = GENESIS_HASH if i == 0 else chain[i - 1].block_hash
            if block.previous_hash != expected_prev:
                break

            # Skip Ed25519 verification for blocks covered by checkpoint.
            if block.sequence_number > checkpoint_seq:
                if not verify_block(block):
                    break

            valid_count += 1

        return valid_count / len(chain)

    def compute_netflow_score(self, pubkey: str) -> float:
        """NetFlow score alone [0.0, 1.0]."""
        if not self.netflow:
            return 0.0
        return self.netflow.compute_trust(pubkey)

    def compute_statistical_score(self, pubkey: str) -> float:
        """Statistical score from interaction history [0.0, 1.0].

        Features:
        - interaction_count: total half-blocks (saturates at 20)
        - unique_counterparties: diversity (saturates at 5) — structural, no decay
        - completion_rate: completed/total transactions
        - account_age: time span (saturates at 60s for demo timescale) — structural, no decay
        - entropy: Shannon entropy of counterparty distribution

        When ``decay_half_life_ms`` is set, applies ``2^(-age_ms / half_life_ms)``
        per block to interaction_count, completion_rate, and entropy.
        """
        chain = self.store.get_chain(pubkey)
        if not chain:
            return 0.0

        # Reference time for decay: latest block timestamp.
        now_ms = max(b.timestamp for b in chain)

        def decay_weight(block_ts: int) -> float:
            if self.decay_half_life_ms is not None and self.decay_half_life_ms > 0:
                age_ms = max(0, now_ms - block_ts)
                return 2.0 ** (-(age_ms / self.decay_half_life_ms))
            return 1.0

        counterparties: List[str] = []
        counterparties_weighted: Dict[str, float] = {}
        weighted_completed = 0.0
        weighted_total = 0.0
        weighted_count = 0.0

        for block in chain:
            w = decay_weight(block.timestamp)
            weighted_count += w
            counterparties.append(block.link_public_key)
            counterparties_weighted[block.link_public_key] = (
                counterparties_weighted.get(block.link_public_key, 0.0) + w
            )
            tx = block.transaction
            if tx.get("outcome") is not None:
                weighted_total += w
                if tx.get("outcome") == "completed":
                    weighted_completed += w

        unique_counterparties = len(set(counterparties))

        # Feature 1: interaction count with decay (saturates at 20).
        count_score = min(weighted_count / 20.0, 1.0)

        # Feature 2: unique counterparties (structural, no decay).
        diversity_score = min(unique_counterparties / 5.0, 1.0)

        # Feature 3: completion rate (decay-weighted).
        # Matches Rust: falls back to proposal/agreement pairing via linked blocks
        # when no blocks have an explicit outcome field.
        if weighted_total > 0:
            completion_rate = weighted_completed / weighted_total
        else:
            # Fallback: check linked blocks (proposals that have agreements).
            proposals = [b for b in chain if b.block_type == "proposal"]
            if not proposals:
                completion_rate = 1.0
            else:
                completed = sum(
                    1 for p in proposals
                    if self.store.get_linked_block(p) is not None
                )
                completion_rate = completed / len(proposals)

        # Feature 4: account age (structural, no decay).
        timestamps = [b.timestamp for b in chain]
        account_age = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0
        age_score = min(account_age / 60_000.0, 1.0)

        # Feature 5: Shannon entropy (decay-weighted distribution).
        if unique_counterparties <= 1:
            normalized_entropy = 0.0
        else:
            total_w = sum(counterparties_weighted.values())
            entropy = 0.0
            for c in counterparties_weighted.values():
                p = c / total_w
                if p > 0:
                    entropy -= p * math.log2(p)
            max_entropy = math.log2(unique_counterparties) if unique_counterparties > 1 else 1.0
            normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0.0

        weights = {
            "count": 0.25,
            "diversity": 0.20,
            "completion": 0.25,
            "age": 0.10,
            "entropy": 0.20,
        }

        score = (
            weights["count"] * count_score
            + weights["diversity"] * diversity_score
            + weights["completion"] * completion_rate
            + weights["age"] * age_score
            + weights["entropy"] * normalized_entropy
        )
        return round(min(max(score, 0.0), 1.0), 3)


# ===========================================================================
# v1 compat functions (deprecated — delegate to RecordStore-based logic)
# ===========================================================================


def compute_trust(pubkey: str, store: RecordStore) -> float:
    """Compute a trust score in [0.0, 1.0] for an agent based on its TrustChain history.

    .. deprecated:: 2.0
        Use ``TrustEngine.compute_trust()`` for v2 half-block model.

    Features:
    - interaction_count: total bilateral records
    - unique_counterparties: diversity of interaction partners
    - completion_rate: fraction with outcome='completed'
    - account_age: seconds since first interaction
    - counterparty_diversity_entropy: Shannon entropy of partner distribution
    """
    records = store.get_records_for(pubkey)
    if not records:
        return 0.0

    counterparties: List[str] = []
    completed = 0
    for r in records:
        other = r.agent_b_pubkey if r.agent_a_pubkey == pubkey else r.agent_a_pubkey
        counterparties.append(other)
        if r.outcome == "completed":
            completed += 1

    interaction_count = len(records)
    unique_counterparties = len(set(counterparties))
    completion_rate = completed / interaction_count if interaction_count else 0.0

    timestamps = [r.timestamp for r in records]
    account_age = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0

    counts = Counter(counterparties)
    total = sum(counts.values())
    entropy = 0.0
    for c in counts.values():
        p = c / total
        if p > 0:
            entropy -= p * math.log2(p)
    max_entropy = math.log2(unique_counterparties) if unique_counterparties > 1 else 1.0
    normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0.0

    count_score = min(interaction_count / 20.0, 1.0)
    diversity_score = min(unique_counterparties / 5.0, 1.0)
    age_score = min(account_age / 60.0, 1.0)

    weights = {
        "count": 0.25,
        "diversity": 0.20,
        "completion": 0.25,
        "age": 0.10,
        "entropy": 0.20,
    }

    trust = (
        weights["count"] * count_score
        + weights["diversity"] * diversity_score
        + weights["completion"] * completion_rate
        + weights["age"] * age_score
        + weights["entropy"] * normalized_entropy
    )
    return round(min(max(trust, 0.0), 1.0), 3)


def is_sybil_cluster(pubkeys: Set[str], store: RecordStore) -> bool:
    """Detect if a set of agents forms an isolated cluster (Sybil signal).

    .. deprecated:: 2.0
        Use ``NetFlowTrust.compute_trust()`` for graph-based Sybil resistance.
    """
    if len(pubkeys) < 2:
        return False

    internal_interactions = 0
    external_interactions = 0

    for pk in pubkeys:
        for r in store.get_records_for(pk):
            other = r.agent_b_pubkey if r.agent_a_pubkey == pk else r.agent_a_pubkey
            if other in pubkeys:
                internal_interactions += 1
            else:
                external_interactions += 1

    internal_interactions //= 2

    total = internal_interactions + external_interactions
    if total == 0:
        return False

    internal_ratio = internal_interactions / total
    return internal_ratio > 0.8


def compute_transitive_trust(pubkey: str, store: RecordStore, alpha: float = 0.85) -> float:
    """Compute transitive trust via PageRank on the interaction graph.

    .. deprecated:: 2.0
        Use ``TrustEngine`` with NetFlow for graph-based trust.
    """
    G = store.get_interaction_graph()
    if len(G.nodes) < 2 or pubkey not in G:
        return 0.0

    pr = nx.pagerank(G, alpha=alpha, weight="weight")
    max_pr = max(pr.values())
    if max_pr == 0:
        return 0.0
    return round(pr.get(pubkey, 0.0) / max_pr, 3)


def compute_chain_trust(
    pubkey: str, store: RecordStore, integrity_weight: float = 0.15
) -> float:
    """Blend statistical trust with chain integrity score.

    .. deprecated:: 2.0
        Use ``TrustEngine.compute_trust()`` for unified scoring.
    """
    from trustchain.chain import compute_chain_integrity

    base_trust = compute_trust(pubkey, store)
    records = store.get_records_for(pubkey)

    if not records:
        return base_trust

    integrity = compute_chain_integrity(pubkey, records)

    if integrity < 1.0:
        penalty = 1.0 - integrity_weight * (1.0 - integrity)
        penalized = base_trust * penalty
        if integrity == 0.0:
            penalized = min(penalized, 0.1)
        return round(min(max(penalized, 0.0), 1.0), 3)

    return base_trust


def compute_trust_with_decay(
    pubkey: str, store: RecordStore, half_life: float = 30.0, now: Optional[float] = None
) -> float:
    """Compute trust with time-decay weighting on interaction records.

    .. deprecated:: 2.0
        Use ``TrustEngine.compute_trust()`` for v2 scoring.
    """
    import time as _time

    records = store.get_records_for(pubkey)
    if not records:
        return 0.0

    if now is None:
        now = _time.time()

    counterparties: List[str] = []
    weighted_completed = 0.0
    total_weight = 0.0

    for r in records:
        age = now - r.timestamp
        w = 2.0 ** (-age / half_life) if half_life > 0 else 1.0
        other = r.agent_b_pubkey if r.agent_a_pubkey == pubkey else r.agent_a_pubkey
        counterparties.append(other)
        total_weight += w
        if r.outcome == "completed":
            weighted_completed += w

    count_score = min(total_weight / 20.0, 1.0)
    unique_counterparties = len(set(counterparties))
    diversity_score = min(unique_counterparties / 5.0, 1.0)
    completion_rate = weighted_completed / total_weight if total_weight > 0 else 0.0

    timestamps = [r.timestamp for r in records]
    account_age = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0
    age_score = min(account_age / 60.0, 1.0)

    counts = Counter(counterparties)
    total_counts = sum(counts.values())
    entropy = 0.0
    for c in counts.values():
        p = c / total_counts
        if p > 0:
            entropy -= p * math.log2(p)
    max_entropy = math.log2(unique_counterparties) if unique_counterparties > 1 else 1.0
    normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0.0

    weights = {
        "count": 0.25,
        "diversity": 0.20,
        "completion": 0.25,
        "age": 0.10,
        "entropy": 0.20,
    }

    trust = (
        weights["count"] * count_score
        + weights["diversity"] * diversity_score
        + weights["completion"] * completion_rate
        + weights["age"] * age_score
        + weights["entropy"] * normalized_entropy
    )
    return round(min(max(trust, 0.0), 1.0), 3)
