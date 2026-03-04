"""Trust score computation for TrustChain.

v2 adds TrustEngine class that unifies chain integrity and NetFlow scoring.
Original v1 functions are preserved as deprecated compat shims.
"""

from __future__ import annotations

import logging
import math
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


DEFAULT_CONNECTIVITY_THRESHOLD = 3.0
DEFAULT_DIVERSITY_THRESHOLD = 5.0


class TrustEngine:
    """Unified trust computation: Trust = connectivity × integrity × diversity.

    - connectivity = min(path_diversity / K, 1.0) — Sybil resistance
    - integrity = chain_integrity — hash linkage, signatures
    - diversity = min(unique_peers / M, 1.0) — interaction partner spread
    """

    def __init__(
        self,
        store: BlockStore,
        seed_nodes: Optional[List[str]] = None,
        weights: Optional[Dict[str, float]] = None,  # backward compat, ignored
        delegation_store: Optional[DelegationStore] = None,
        checkpoint=None,
        connectivity_threshold: float = DEFAULT_CONNECTIVITY_THRESHOLD,
        diversity_threshold: float = DEFAULT_DIVERSITY_THRESHOLD,
    ) -> None:
        self.store = store
        self.connectivity_threshold = connectivity_threshold
        self.diversity_threshold = diversity_threshold
        self._protocol = TrustChainProtocol(
            # Dummy identity — protocol is used only for validation
            identity=None,  # type: ignore[arg-type]
            store=store,
        )
        self.delegation_store = delegation_store
        self.checkpoint = checkpoint
        self.netflow: Optional[NetFlowTrust] = None
        self.seed_nodes = seed_nodes or []
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
        - Chain integrity (weight: 0.5) — broken chain = major penalty
        - NetFlow score (weight: 0.5) — Sybil resistance

        If NetFlow is not configured (no seed nodes), returns integrity only.
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
        """Standard trust computation: connectivity × integrity × diversity."""
        evidence = self._compute_standard_trust_evidence(pubkey)
        return evidence["trust_score"]

    def _compute_standard_trust_evidence(self, pubkey: str) -> dict:
        """Compute trust with full evidence for the standard (non-delegated) path."""
        chain = self.store.get_chain(pubkey)
        unique_peers = self._count_unique_peers(chain)
        interactions = len(chain)

        # Check for fraud by ANY delegate (active OR revoked).
        if self.delegation_store is not None:
            delegations = self.delegation_store.get_delegations_by_delegator(pubkey)
            for d in delegations:
                delegate_chain = self.store.get_chain(d.delegate_pubkey)
                if self._has_double_spend(delegate_chain):
                    return {
                        "trust_score": 0.0, "connectivity": 0.0,
                        "integrity": 0.0, "diversity": 0.0,
                        "unique_peers": unique_peers, "interactions": interactions,
                        "fraud": True, "path_diversity": 0.0,
                    }

        integrity = self.compute_chain_integrity(pubkey)

        if self.netflow:
            # Seed nodes get trust = 1.0
            if pubkey in self.seed_nodes:
                return {
                    "trust_score": 1.0, "connectivity": 1.0,
                    "integrity": 1.0, "diversity": 1.0,
                    "unique_peers": unique_peers, "interactions": interactions,
                    "fraud": False, "path_diversity": float("inf"),
                }

            path_div = self.netflow.compute_path_diversity(pubkey)
            diversity = min(unique_peers / self.diversity_threshold, 1.0)

            # Sybil gate: if no path from seeds, trust is zero.
            if path_div < 1e-10:
                return {
                    "trust_score": 0.0, "connectivity": 0.0,
                    "integrity": integrity, "diversity": diversity,
                    "unique_peers": unique_peers, "interactions": interactions,
                    "fraud": False, "path_diversity": path_div,
                }

            connectivity = min(path_div / self.connectivity_threshold, 1.0)
            trust_score = min(max(connectivity * integrity * diversity, 0.0), 1.0)

            return {
                "trust_score": trust_score, "connectivity": connectivity,
                "integrity": integrity, "diversity": diversity,
                "unique_peers": unique_peers, "interactions": interactions,
                "fraud": False, "path_diversity": path_div,
            }

        # No seeds configured — no Sybil resistance, use integrity only.
        return {
            "trust_score": integrity, "connectivity": 1.0,
            "integrity": integrity, "diversity": 1.0,
            "unique_peers": unique_peers, "interactions": interactions,
            "fraud": False, "path_diversity": 0.0,
        }

    def _count_unique_peers(self, chain) -> int:
        """Count distinct link_public_keys in a chain."""
        peers: Set[str] = set()
        for block in chain:
            if block.public_key != block.link_public_key:
                peers.add(block.link_public_key)
        return len(peers)

    def compute_trust_with_evidence(
        self, pubkey: str, interaction_type: Optional[str] = None
    ) -> dict:
        """Compute trust with full evidence bundle (delegation-aware)."""
        if self.delegation_store is not None:
            delegation = self.delegation_store.get_delegation_by_delegate(pubkey)
            if delegation is not None:
                if not delegation.is_active:
                    return {
                        "trust_score": 0.0, "connectivity": 0.0,
                        "integrity": 0.0, "diversity": 0.0,
                        "unique_peers": 0, "interactions": 0,
                        "fraud": False, "path_diversity": 0.0,
                    }
                root_pubkey = self._resolve_root(delegation)
                root_evidence = self._compute_standard_trust_evidence(root_pubkey)
                active_count = max(
                    self.delegation_store.get_active_delegation_count(root_pubkey), 1
                )
                effective = min(max(root_evidence["trust_score"] / active_count, 0.0), 1.0)
                return {**root_evidence, "trust_score": effective}

            if self.delegation_store.is_delegate(pubkey):
                return {
                    "trust_score": 0.0, "connectivity": 0.0,
                    "integrity": 0.0, "diversity": 0.0,
                    "unique_peers": 0, "interactions": 0,
                    "fraud": False, "path_diversity": 0.0,
                }

        return self._compute_standard_trust_evidence(pubkey)

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

        return min(max(effective, 0.0), 1.0)

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
        """Raw path diversity score (not normalized).

        .. deprecated:: 2.3
            Use ``compute_trust_with_evidence()`` for the full breakdown.
        """
        if not self.netflow:
            return 0.0
        return self.netflow.compute_path_diversity(pubkey)


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
    age_score = min(account_age / 60_000, 1.0)  # milliseconds

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
    pubkey: str, store: RecordStore, half_life: float = 30_000, now: Optional[int] = None
) -> float:
    """Compute trust with time-decay weighting on interaction records.

    Args:
        half_life: Decay half-life in milliseconds (default 30s = 30_000ms).
        now: Current time in milliseconds since epoch.

    .. deprecated:: 2.0
        Use ``TrustEngine.compute_trust()`` for v2 scoring.
    """
    import time as _time

    records = store.get_records_for(pubkey)
    if not records:
        return 0.0

    if now is None:
        now = int(_time.time() * 1000)

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
    age_score = min(account_age / 60_000, 1.0)  # milliseconds

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
