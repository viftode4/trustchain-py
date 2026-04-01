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
from trustchain.forgiveness import (
    ForgivenessConfig,
    RecoverySeverity,
    apply_forgiveness,
    asymmetric_decay_weight,
)
from trustchain.netflow import NetFlowTrust
from trustchain.protocol import TrustChainProtocol
from trustchain.sanctions import SanctionConfig, ViolationSeverity, compute_sanctions
from trustchain.behavioral import (
    BehavioralConfig,
    detect_behavioral_change,
    detect_selective_targeting,
)
from trustchain.collusion import CollusionConfig, detect_collusion
from trustchain.sealed_rating import extract_sealed_rating
from trustchain.store import RecordStore

logger = logging.getLogger("trustchain.trust")


# ===========================================================================
# v2 TrustEngine
# ===========================================================================


DEFAULT_CONNECTIVITY_THRESHOLD = 3.0
DEFAULT_DIVERSITY_THRESHOLD = 5.0
DEFAULT_RECENCY_LAMBDA = 0.95


class TrustEngine:
    """Unified trust computation (weighted-additive, Layer 2.2).

    Trust = (0.3 × structural + 0.7 × behavioral) × confidence_scale
    - structural = connectivity × integrity (Sybil resistance + chain health)
    - behavioral = recency (quality-weighted track record)
    - confidence_scale = min(interactions / cold_start_threshold, 1.0)
    - Sybil gate: connectivity < ε → hard zero
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
        recency_lambda: float = DEFAULT_RECENCY_LAMBDA,
        cold_start_threshold: int = 5,
        delegation_factor: float = 0.8,
    ) -> None:
        self.store = store
        self.connectivity_threshold = connectivity_threshold
        self.diversity_threshold = diversity_threshold
        self.recency_lambda = recency_lambda
        self.cold_start_threshold = cold_start_threshold
        self.delegation_factor = delegation_factor
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
        uses cold start blending between delegation trust and direct trust.
        Otherwise, returns the standard trust computation.

        Standard path (weighted-additive, Layer 2.2):
        Trust = (0.3 × structural + 0.7 × behavioral) × confidence_scale
        - structural = connectivity × integrity
        - behavioral = recency (quality-weighted)
        - confidence_scale = min(interactions / cold_start_threshold, 1.0)
        - Sybil gate: hard zero if no path from seeds
        """
        # Check if this is a delegated identity
        if self.delegation_store is not None:
            # Check active delegation first
            delegation = self.delegation_store.get_delegation_by_delegate(pubkey)
            if delegation is not None:
                return self._compute_delegated_trust(
                    pubkey, delegation, interaction_type
                )

            # Check if this was a delegate whose delegation was revoked
            if self.delegation_store.is_delegate(pubkey):
                return 0.0

        return self._compute_standard_trust(pubkey, interaction_type)

    def _compute_standard_trust(
        self, pubkey: str, context: Optional[str] = None
    ) -> float:
        """Standard trust: (0.3 × structural + 0.7 × behavioral) × confidence_scale."""
        evidence = self._compute_standard_trust_evidence(pubkey, context)
        return evidence["trust_score"]

    def _get_chain_for_context(
        self, pubkey: str, context: Optional[str] = None
    ) -> list:
        """Get the chain filtered by context (interaction_type), or full chain."""
        chain = self.store.get_chain(pubkey)
        if context is None:
            return chain
        return [
            b for b in chain
            if (
                getattr(b, "transaction", {}).get("interaction_type", "") == context
                or getattr(b, "transaction", {})
                .get("interaction_type", "")
                .startswith(f"{context}:")
            )
        ]

    def _compute_recency(self, chain, extra_negatives: int = 0) -> float:
        """Compute recency: value-weighted exponential-decay outcome quality.

        Empty chain returns 0.5 (uninformative prior, Josang & Ismail 2002).
        Quality extracted via fallback chain: quality > requester_rating >
        provider_rating > binary outcome.

        Value weighting: each interaction weighted by price/avg_price so cheap
        wash-trades contribute negligibly. Research: Olariu et al. 2024.

        extra_negatives: virtual quality=0.0 entries for expired timeouts
        (Layer 1.5). Each gets weight 1.0 (most recent equivalent).
        """
        if not chain and extra_negatives == 0:
            return 0.5
        lam = self.recency_lambda
        n = len(chain)
        avg_price = self._compute_avg_price(chain)
        fg_config = ForgivenessConfig()
        weighted_sum = 0.0
        weight_total = 0.0
        for k, block in enumerate(chain):
            quality = self._extract_quality(block)
            # Layer 4.4: Asymmetric decay — negative outcomes decay faster.
            age = n - 1 - k
            is_negative = quality < 0.5
            decay = asymmetric_decay_weight(
                lam, age, is_negative, fg_config.negative_decay_speedup
            )
            price = self._extract_price(block)
            value_weight = price / avg_price if avg_price > 1e-10 else 1.0
            weight = decay * value_weight
            weighted_sum += weight * quality
            weight_total += weight
        # Add virtual negatives for timeouts (quality=0.0, weight=1.0).
        weight_total += extra_negatives
        if weight_total < 1e-10:
            return 0.5
        return min(max(weighted_sum / weight_total, 0.0), 1.0)

    @staticmethod
    def _extract_price(block) -> float:
        """Extract price from a block's transaction, defaulting to 1.0."""
        tx = getattr(block, "transaction", {})
        if not isinstance(tx, dict):
            return 1.0
        price = tx.get("price")
        if price is not None:
            try:
                return max(0.0, float(price))
            except (TypeError, ValueError):
                pass
        return 1.0

    @staticmethod
    def _compute_avg_price(chain) -> float:
        """Compute average price across a chain. Returns 1.0 for empty chains."""
        if not chain:
            return 1.0
        total = sum(TrustEngine._extract_price(b) for b in chain)
        avg = total / len(chain)
        return avg if avg > 1e-10 else 1.0

    @staticmethod
    def wilson_lower_bound(positive: float, total: float, z: float = 1.96) -> float:
        """Wilson lower-bound confidence score.

        Research: Evan Miller 2009 "How Not To Sort By Average Rating",
        TRAVOS (Teacy et al. 2006).
        """
        if total == 0.0:
            return 0.0
        p = positive / total
        d = 1.0 + z * z / total
        center = p + z * z / (2.0 * total)
        spread = z * math.sqrt((p * (1.0 - p) + z * z / (4.0 * total)) / total)
        return max((center - spread) / d, 0.0)

    @staticmethod
    def _beta_reputation(chain) -> float | None:
        """Beta reputation: Bayesian updating with temporal decay.

        Returns None for empty chains, score in [0, 1] otherwise.
        Research: Josang & Ismail 2002, Josang, Luo, Chen 2008.
        """
        if not chain:
            return None
        lam = 0.95
        alpha = 1.0  # prior
        beta_param = 1.0  # prior
        for block in chain:
            quality = TrustEngine._extract_quality(block)
            alpha = lam * alpha + quality
            beta_param = lam * beta_param + (1.0 - quality)
        return min(max(alpha / (alpha + beta_param), 0.0), 1.0)

    def _count_timeouts(self, pubkey: str, chain) -> int:
        """Count expired orphan proposals directed at pubkey (timeouts).

        Scans counterparties' chains for proposals with expired deadline_ms
        and no matching agreement.

        Research: trust-model-gaps §4 "Timeout Enforcement".
        """
        # Collect counterparties from the target's chain.
        counterparties: Set[str] = set()
        for block in chain:
            if block.public_key != block.link_public_key:
                counterparties.add(block.link_public_key)

        # Use latest timestamp in chain as proxy for "now".
        now_ms = max((b.timestamp for b in chain), default=0)
        if now_ms == 0:
            import time
            now_ms = int(time.time() * 1000)

        timeout_count = 0
        for cp_pk in counterparties:
            cp_chain = self.store.get_chain(cp_pk)
            for block in cp_chain:
                bt = getattr(block, "block_type", "")
                if bt != "proposal" or block.link_public_key != pubkey:
                    continue
                tx = getattr(block, "transaction", {})
                if not isinstance(tx, dict):
                    continue
                deadline = tx.get("deadline_ms")
                if deadline is None:
                    continue
                try:
                    deadline = int(deadline)
                except (TypeError, ValueError):
                    continue
                if deadline >= now_ms:
                    continue
                # Check if target has a matching agreement.
                linked = self.store.get_linked_block(block) if hasattr(self.store, "get_linked_block") else None
                if linked is None:
                    timeout_count += 1
        return timeout_count

    @staticmethod
    def _extract_quality(block) -> float:
        """Extract quality signal from a block's transaction.

        Fallback chain (first present value wins):
          1. ``quality`` field (continuous 0.0-1.0)
          2. ``requester_rating`` field (continuous 0.0-1.0)
          3. ``provider_rating`` field (continuous 0.0-1.0)
          4. Binary outcome: completed/success -> 1.0, failed/error -> 0.0
          5. Unknown -> 1.0 (backward compat)

        Research: trust-differentiation-fixes P0, reputation-game-theory §3.
        """
        tx = getattr(block, "transaction", {})
        if not isinstance(tx, dict):
            return 1.0
        # 0. Layer 4.3: Check for sealed rating (commit-reveal protocol).
        sealed = extract_sealed_rating(tx)
        if sealed is not None:
            return max(0.0, min(sealed, 1.0))
        # If sealed but not yet revealed (pending), use backward-compat default.
        if tx.get("rating_commitment") is not None and tx.get("revealed_rating") is None:
            return 1.0  # Pending reveal
        # 1. Explicit quality
        quality = tx.get("quality")
        if quality is not None:
            try:
                return max(0.0, min(float(quality), 1.0))
            except (TypeError, ValueError):
                pass
        # 2. Requester rating
        rr = tx.get("requester_rating")
        if rr is not None:
            try:
                return max(0.0, min(float(rr), 1.0))
            except (TypeError, ValueError):
                pass
        # 3. Provider rating
        pr = tx.get("provider_rating")
        if pr is not None:
            try:
                return max(0.0, min(float(pr), 1.0))
            except (TypeError, ValueError):
                pass
        # 4. Binary outcome
        outcome_str = tx.get("outcome", "")
        if outcome_str in ("completed", "success"):
            return 1.0
        if outcome_str in ("failed", "error"):
            return 0.0
        return 1.0  # backward compat

    @staticmethod
    def _compute_avg_quality(chain) -> float:
        """Compute average quality across a chain."""
        if not chain:
            return 0.0
        total = sum(TrustEngine._extract_quality(b) for b in chain)
        return total / len(chain)

    @staticmethod
    def _count_good_since_violation(chain) -> int:
        """Count consecutive good interactions since the last violation.

        Scans chain from most recent backward. Good = quality >= 0.5.
        Stops at first violation (quality < 0.3).
        """
        count = 0
        for block in reversed(chain):
            quality = TrustEngine._extract_quality(block)
            if quality < 0.3:
                break
            if quality >= 0.5:
                count += 1
        return count

    def _compute_standard_trust_evidence(
        self, pubkey: str, context: Optional[str] = None
    ) -> dict:
        """Compute trust with full evidence for the standard (non-delegated) path."""
        chain = self.store.get_chain(pubkey)
        filtered_chain = (
            self._get_chain_for_context(pubkey, context) if context else chain
        )
        unique_peers = self._count_unique_peers(filtered_chain)
        interactions = len(filtered_chain)

        # Zero-evidence helper for fraud/failure.
        zero = {
            "trust_score": 0.0, "connectivity": 0.0,
            "integrity": 0.0, "diversity": 0.0, "recency": 0.0,
            "unique_peers": unique_peers, "interactions": interactions,
            "fraud": False, "path_diversity": 0.0,
            "avg_quality": 0.0, "value_weighted_recency": 0.0,
            "timeout_count": 0, "confidence": 0.0,
            "sample_size": 0, "positive_count": 0,
            "required_deposit_ratio": 1.0,
            "sanction_penalty": 0.0, "violation_count": 0,
            "correlation_penalty": 0.0,
            "forgiveness_factor": 1.0,
            "good_interactions_since_violation": 0,
            "behavioral_change": 0.0,
            "behavioral_anomaly": False,
            "selective_scamming": False,
            "collusion_cluster_density": 0.0,
            "collusion_external_ratio": 0.0,
            "collusion_temporal_burst": False,
            "collusion_reciprocity_anomaly": False,
            "requester_trust": None,
            "payment_reliability": None,
            "rating_fairness": None,
            "dispute_rate": None,
        }

        # Check for fraud by ANY delegate (active OR revoked).
        if self.delegation_store is not None:
            delegations = self.delegation_store.get_delegations_by_delegator(pubkey)
            for d in delegations:
                delegate_chain = self.store.get_chain(d.delegate_pubkey)
                if self._has_double_spend(delegate_chain):
                    return {**zero, "fraud": True,
                            "sanction_penalty": 1.0, "violation_count": 1,
                            "correlation_penalty": 1.0}

        integrity = self.compute_chain_integrity(pubkey)
        avg_quality = self._compute_avg_quality(filtered_chain)

        # Layer 1.5: Timeout enforcement.
        timeout_count = self._count_timeouts(pubkey, filtered_chain)

        # Layer 1.4: Value-weighted recency with timeout integration.
        recency = self._compute_recency(filtered_chain, timeout_count)
        value_weighted_recency = self._compute_recency(filtered_chain, 0)

        # Layer 2.1: Wilson score confidence.
        sample_size = interactions
        positive_count = sum(
            1 for b in filtered_chain
            if self._extract_quality(b) >= 0.5
        )
        confidence = self.wilson_lower_bound(positive_count, sample_size)

        # Layer 2.3: Beta reputation (Josang & Ismail 2002).
        beta_rep = self._beta_reputation(filtered_chain)

        # Common fields for all evidence dicts.
        common = {
            "avg_quality": avg_quality,
            "value_weighted_recency": value_weighted_recency,
            "timeout_count": timeout_count,
            "confidence": confidence,
            "sample_size": sample_size,
            "positive_count": positive_count,
            "beta_reputation": beta_rep,
        }

        # Layer 4.1: Graduated sanctions (Ostrom 1990).
        _sr = compute_sanctions(timeout_count, avg_quality, False, SanctionConfig())

        if self.netflow:
            # Seed nodes get trust = 1.0
            if pubkey in self.seed_nodes:
                return {
                    "trust_score": 1.0, "connectivity": 1.0,
                    "integrity": 1.0, "diversity": 1.0, "recency": 1.0,
                    "unique_peers": unique_peers, "interactions": interactions,
                    "fraud": False, "path_diversity": float("inf"),
                    **common,
                    "confidence": 1.0, "value_weighted_recency": 1.0,
                    "timeout_count": 0,
                    "required_deposit_ratio": 0.0,
                    "sanction_penalty": 0.0, "violation_count": 0,
                    "correlation_penalty": 0.0,
                    "forgiveness_factor": 1.0,
                    "good_interactions_since_violation": 0,
                    "behavioral_change": 0.0,
                    "behavioral_anomaly": False,
                    "selective_scamming": False,
                    "collusion_cluster_density": 0.0,
                    "collusion_external_ratio": 0.0,
                    "collusion_temporal_burst": False,
                    "collusion_reciprocity_anomaly": False,
                    "requester_trust": None,
                    "payment_reliability": None,
                    "rating_fairness": None,
                    "dispute_rate": None,
                }

            path_div = self.netflow.compute_path_diversity(pubkey)
            diversity = min(unique_peers / self.diversity_threshold, 1.0)

            # Sybil gate: if no path from seeds, trust is zero.
            if path_div < 1e-10:
                return {
                    "trust_score": 0.0, "connectivity": 0.0,
                    "integrity": integrity, "diversity": diversity,
                    "recency": recency,
                    "unique_peers": unique_peers, "interactions": interactions,
                    "fraud": False, "path_diversity": path_div,
                    **common,
                    "required_deposit_ratio": 1.0,
                    "sanction_penalty": _sr.total_penalty,
                    "violation_count": _sr.violation_count,
                    "correlation_penalty": 0.0,
                    "forgiveness_factor": 1.0,
                    "good_interactions_since_violation": 0,
                    "behavioral_change": 0.0,
                    "behavioral_anomaly": False,
                    "selective_scamming": False,
                    "collusion_cluster_density": 0.0,
                    "collusion_external_ratio": 0.0,
                    "collusion_temporal_burst": False,
                    "collusion_reciprocity_anomaly": False,
                    "requester_trust": None,
                    "payment_reliability": None,
                    "rating_fairness": None,
                    "dispute_rate": None,
                }

            connectivity = min(path_div / self.connectivity_threshold, 1.0)

            # Layer 2.2: Weighted-additive trust formula.
            structural = min(connectivity, 1.0) * integrity
            behavioral = recency
            confidence_scale = min(
                interactions / max(self.cold_start_threshold, 1), 1.0
            )
            trust_score = min(
                max((0.3 * structural + 0.7 * behavioral) * confidence_scale, 0.0),
                1.0,
            )

            # Layer 4.4: Forgiveness (Josang 2007, Axelrod 1984).
            good_since = self._count_good_since_violation(filtered_chain)
            fg_severity = (
                RecoverySeverity(
                    {ViolationSeverity.LIVENESS: "liveness",
                     ViolationSeverity.QUALITY: "quality",
                     ViolationSeverity.BYZANTINE: "fraud"}[_sr.violations[0].severity]
                )
                if _sr.violations
                else RecoverySeverity.LIVENESS
            )
            forgiven = apply_forgiveness(
                _sr.total_penalty, good_since, fg_severity, ForgivenessConfig()
            )
            fg_factor = forgiven / _sr.total_penalty if _sr.total_penalty > 1e-12 else 1.0

            # Layer 5.1-5.3: Behavioral detection + collusion signals.
            beh, sel, col = self._compute_layer5_signals(pubkey, filtered_chain)

            return {
                "trust_score": trust_score, "connectivity": connectivity,
                "integrity": integrity, "diversity": diversity,
                "recency": recency,
                "unique_peers": unique_peers, "interactions": interactions,
                "fraud": False, "path_diversity": path_div,
                **common,
                "required_deposit_ratio": max(0.0, min(1.0, 1.0 - trust_score)),
                "sanction_penalty": forgiven,
                "violation_count": _sr.violation_count,
                "correlation_penalty": 0.0,
                "forgiveness_factor": fg_factor,
                "good_interactions_since_violation": good_since,
                "behavioral_change": beh.change_magnitude,
                "behavioral_anomaly": beh.is_anomalous,
                "selective_scamming": sel.is_selective,
                "collusion_cluster_density": col.cluster_density,
                "collusion_external_ratio": col.external_connection_ratio,
                "collusion_temporal_burst": col.temporal_burst,
                "collusion_reciprocity_anomaly": col.reciprocity_anomaly,
                "requester_trust": None,
                "payment_reliability": None,
                "rating_fairness": None,
                "dispute_rate": None,
            }

        # No seeds configured — no Sybil resistance. Weighted-additive with
        # connectivity=1.0. Confidence still scales by interactions.
        confidence_scale = min(
            interactions / max(self.cold_start_threshold, 1), 1.0
        )
        _ts_no_seeds = min(
            max((0.3 * integrity + 0.7 * recency) * confidence_scale, 0.0),
            1.0,
        )
        # Layer 4.4: Forgiveness (Josang 2007, Axelrod 1984).
        good_since_ns = self._count_good_since_violation(filtered_chain)
        fg_severity_ns = (
            RecoverySeverity(
                {ViolationSeverity.LIVENESS: "liveness",
                 ViolationSeverity.QUALITY: "quality",
                 ViolationSeverity.BYZANTINE: "fraud"}[_sr.violations[0].severity]
            )
            if _sr.violations
            else RecoverySeverity.LIVENESS
        )
        forgiven_ns = apply_forgiveness(
            _sr.total_penalty, good_since_ns, fg_severity_ns, ForgivenessConfig()
        )
        fg_factor_ns = forgiven_ns / _sr.total_penalty if _sr.total_penalty > 1e-12 else 1.0

        # Layer 5.1-5.3: Behavioral detection + collusion signals.
        beh_ns, sel_ns, col_ns = self._compute_layer5_signals(pubkey, filtered_chain)

        return {
            "trust_score": _ts_no_seeds,
            "connectivity": 1.0,
            "integrity": integrity, "diversity": 1.0, "recency": recency,
            "unique_peers": unique_peers, "interactions": interactions,
            "fraud": False, "path_diversity": 0.0,
            **common,
            "required_deposit_ratio": max(0.0, min(1.0, 1.0 - _ts_no_seeds)),
            "sanction_penalty": forgiven_ns,
            "violation_count": _sr.violation_count,
            "correlation_penalty": 0.0,
            "forgiveness_factor": fg_factor_ns,
            "good_interactions_since_violation": good_since_ns,
            "behavioral_change": beh_ns.change_magnitude,
            "behavioral_anomaly": beh_ns.is_anomalous,
            "selective_scamming": sel_ns.is_selective,
            "collusion_cluster_density": col_ns.cluster_density,
            "collusion_external_ratio": col_ns.external_connection_ratio,
            "collusion_temporal_burst": col_ns.temporal_burst,
            "collusion_reciprocity_anomaly": col_ns.reciprocity_anomaly,
            "requester_trust": None,
            "payment_reliability": None,
            "rating_fairness": None,
            "dispute_rate": None,
        }

    def _compute_layer5_signals(self, pubkey: str, filtered_chain: list):
        """Compute Layer 5 signals: behavioral change, selective targeting, collusion.

        Returns (BehavioralAnalysis, SelectiveTargetingResult, CollusionSignals).
        """
        beh_config = BehavioralConfig()
        col_config = CollusionConfig()

        # Extract quality values.
        qualities = [self._extract_quality(b) for b in filtered_chain]

        # L5.1: Behavioral change detection.
        behavioral = detect_behavioral_change(qualities, beh_config)

        # Build peer interaction counts.
        peer_counts: Dict[str, int] = {}
        for block in filtered_chain:
            if block.public_key != block.link_public_key:
                peer_counts[block.link_public_key] = (
                    peer_counts.get(block.link_public_key, 0) + 1
                )

        # L5.2: Selective scamming — partition by counterparty newness.
        qualities_to_new: List[float] = []
        qualities_to_established: List[float] = []
        for block in filtered_chain:
            if block.public_key == block.link_public_key:
                continue
            q = self._extract_quality(block)
            count = peer_counts.get(block.link_public_key, 0)
            if count > 2:
                qualities_to_established.append(q)
            else:
                qualities_to_new.append(q)
        selective = detect_selective_targeting(
            qualities_to_new, qualities_to_established, beh_config
        )

        # L5.3: Collusion signals — reciprocity + concentration.
        reciprocity_map: Dict[str, tuple] = {}
        for block in filtered_chain:
            if block.public_key == block.link_public_key:
                continue
            q = self._extract_quality(block)
            pk = block.link_public_key
            if pk not in reciprocity_map:
                reciprocity_map[pk] = ([], [])
            reciprocity_map[pk][0].append(q)

        # Load peer chains for reciprocity.
        for peer_pk in peer_counts:
            try:
                peer_chain = self.store.get_chain(peer_pk)
            except Exception:
                continue
            for block in peer_chain:
                if block.link_public_key == pubkey:
                    q = self._extract_quality(block)
                    if peer_pk not in reciprocity_map:
                        reciprocity_map[peer_pk] = ([], [])
                    reciprocity_map[peer_pk][1].append(q)

        reciprocity_pairs = []
        for given, received in reciprocity_map.values():
            avg_given = sum(given) / len(given) if given else 0.0
            avg_received = sum(received) / len(received) if received else 0.0
            count = min(len(given), len(received))
            reciprocity_pairs.append((avg_given, avg_received, count))

        sorted_counts = sorted(peer_counts.values(), reverse=True)

        collusion = detect_collusion(
            0.0, 0.0, False,
            reciprocity_pairs, sorted_counts, len(filtered_chain), col_config,
        )

        return behavioral, selective, collusion

    def _count_unique_peers(self, chain) -> int:
        """Count distinct link_public_keys in a chain."""
        peers: Set[str] = set()
        for block in chain:
            if block.public_key != block.link_public_key:
                peers.add(block.link_public_key)
        return len(peers)

    # -------------------------------------------------------------------
    # Layer 6.1: Requester reputation (PeerTrust, Xiong & Liu 2004)
    # -------------------------------------------------------------------

    def _get_requester_chain(self, pubkey: str) -> list:
        """Get blocks from counterparties' chains where they record interactions
        with ``pubkey`` as the requester (initiator)."""
        own_chain = self.store.get_chain(pubkey)
        peers: Set[str] = set()
        for block in own_chain:
            if block.public_key != block.link_public_key:
                peers.add(block.link_public_key)

        requester_chain = []
        for peer_pk in peers:
            for block in self.store.get_chain(peer_pk):
                if block.link_public_key == pubkey:
                    requester_chain.append(block)
        return requester_chain

    @staticmethod
    def _compute_payment_reliability(chain: list) -> float:
        """Fraction of requester-chain interactions with successful outcome."""
        if not chain:
            return 1.0  # benefit of doubt
        paid = sum(
            1
            for b in chain
            if (
                b.transaction.get("payment_status") in ("completed", "paid")
                or TrustEngine._extract_quality(b) >= 0.5
            )
        )
        return paid / len(chain)

    def _compute_rating_fairness(
        self, _requester_chain: list, pubkey: str
    ) -> Optional[float]:
        """Agreement between requester's ratings and provider consensus.

        Returns ``None`` if fewer than 3 providers were rated.
        """
        own_chain = self.store.get_chain(pubkey)

        # Map provider → requester's ratings of that provider.
        requester_ratings: Dict[str, List[float]] = {}
        for block in own_chain:
            if block.public_key == block.link_public_key:
                continue
            rating = block.transaction.get(
                "requester_rating", block.transaction.get("quality")
            )
            if rating is not None:
                requester_ratings.setdefault(block.link_public_key, []).append(
                    float(rating)
                )

        if len(requester_ratings) < 3:
            return None

        deviations = []
        for provider_pk, ratings in requester_ratings.items():
            provider_chain = self.store.get_chain(provider_pk)
            if not provider_chain:
                continue
            consensus = self._compute_avg_quality(provider_chain)
            avg_rating = sum(ratings) / len(ratings)
            deviations.append(abs(avg_rating - consensus))

        if not deviations:
            return None

        avg_deviation = sum(deviations) / len(deviations)
        return max(0.0, min(1.0, 1.0 - avg_deviation))

    @staticmethod
    def _compute_dispute_rate(chain: list) -> float:
        """Fraction of requester-chain interactions resulting in disputes."""
        if not chain:
            return 0.0
        disputed = sum(
            1
            for b in chain
            if (
                b.transaction.get("outcome") == "disputed"
                or b.transaction.get("dispute") is True
            )
        )
        return disputed / len(chain)

    def compute_requester_trust(self, pubkey: str) -> dict:
        """Compute trust from the requester (initiator) perspective.

        Uses the same weighted-additive formula but evaluates this agent's
        behavior as a requester: payment reliability, rating fairness,
        dispute rate.

        Research: trust-model-gaps §6, PeerTrust (Xiong & Liu 2004).
        """
        # Start with standard provider-perspective evidence.
        evidence = self._compute_standard_trust_evidence(pubkey)

        # Get counterparties' records about this agent.
        requester_chain = self._get_requester_chain(pubkey)

        # Requester-perspective recency.
        if not requester_chain:
            requester_recency = 0.5  # uninformative prior
        else:
            requester_recency = self._compute_recency(requester_chain, 0)

        # Same weighted-additive formula.
        confidence_scale = min(
            evidence["interactions"] / max(self.cold_start_threshold, 1), 1.0
        )
        structural = evidence["connectivity"] * evidence["integrity"]
        requester_score = max(
            0.0,
            min(
                1.0,
                (0.3 * structural + 0.7 * requester_recency) * confidence_scale,
            ),
        )

        evidence["requester_trust"] = requester_score
        evidence["payment_reliability"] = self._compute_payment_reliability(
            requester_chain
        )
        evidence["rating_fairness"] = self._compute_rating_fairness(
            requester_chain, pubkey
        )
        evidence["dispute_rate"] = self._compute_dispute_rate(requester_chain)
        return evidence

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
                        "integrity": 0.0, "diversity": 0.0, "recency": 0.0,
                        "unique_peers": 0, "interactions": 0,
                        "fraud": False, "path_diversity": 0.0,
                        "avg_quality": 0.0,
                        "required_deposit_ratio": 1.0,
                        "sanction_penalty": 0.0, "violation_count": 0,
                        "requester_trust": None,
                        "payment_reliability": None,
                        "rating_fairness": None,
                        "dispute_rate": None,
                    }
                root_pubkey = self._resolve_root(delegation)
                root_evidence = self._compute_standard_trust_evidence(
                    root_pubkey  # full context — root's overall trust backs delegation
                )
                blended = self._compute_delegated_trust(
                    pubkey, delegation, interaction_type
                )
                return {**root_evidence, "trust_score": blended}

            if self.delegation_store.is_delegate(pubkey):
                return {
                    "trust_score": 0.0, "connectivity": 0.0,
                    "integrity": 0.0, "diversity": 0.0, "recency": 0.0,
                    "unique_peers": 0, "interactions": 0,
                    "fraud": False, "path_diversity": 0.0,
                    "avg_quality": 0.0,
                    "required_deposit_ratio": 1.0,
                    "sanction_penalty": 0.0, "violation_count": 0,
                    "requester_trust": None,
                    "payment_reliability": None,
                    "rating_fairness": None,
                    "dispute_rate": None,
                }

        return self._compute_standard_trust_evidence(pubkey, interaction_type)

    def _compute_delegated_trust(
        self,
        pubkey: str,
        delegation: DelegationRecord,
        interaction_type: Optional[str] = None,
    ) -> float:
        """Compute trust for a delegated identity with cold start blending.

        Blends delegation-based trust with emerging direct trust as
        interactions accumulate. Once cold_start_threshold interactions
        are reached, direct trust is used exclusively.
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

        # Compute delegation depth
        depth = len(self._build_delegation_chain(delegation))

        # Compute delegated trust: root_trust * factor / active_count.
        # Root trust uses full context (no filter) — the delegator's overall
        # credibility backs the delegation, not just one interaction type.
        root_trust = self._compute_standard_trust(root_pubkey)
        active_count = max(
            self.delegation_store.get_active_delegation_count(root_pubkey), 1
        )
        depth_factor = (
            self.delegation_factor ** (depth - 1) if depth > 1 else 1.0
        )
        delegated = (
            root_trust * self.delegation_factor * depth_factor / active_count
        )

        # Cold start blending
        filtered_chain = self._get_chain_for_context(pubkey, interaction_type)
        direct_interactions = len(filtered_chain)

        if direct_interactions >= self.cold_start_threshold:
            return self._compute_standard_trust(pubkey, interaction_type)

        blend = direct_interactions / max(self.cold_start_threshold, 1)
        direct = (
            self._compute_standard_trust(pubkey, interaction_type)
            if direct_interactions > 0
            else 0.0
        )
        blended = delegated * (1.0 - blend) + direct * blend
        return min(max(blended, 0.0), 1.0)

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
