"""NetFlow — graph-based Sybil resistance for TrustChain v2.

Implements max-flow based trust computation per the TrustChain/Tribler NetFlow
algorithm. Sybil clusters have no real contributions to honest agents, so their
max-flow from seed nodes is ~0.

Reference: Otte, de Vos, Pouwelse (2020) — "TrustChain: A Sybil-resistant
scalable blockchain"
"""

from __future__ import annotations

import copy
import logging
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set

from typing import TYPE_CHECKING

from trustchain.blockstore import BlockStore
from trustchain.exceptions import NetFlowError

if TYPE_CHECKING:
    from trustchain.delegation import DelegationStore

logger = logging.getLogger("trustchain.netflow")


class NetFlowTrust:
    """Max-flow based trust computation for Sybil resistance.

    Trust flows from seed nodes (trusted bootstrapping identities) through
    the contribution graph. Agents with real interaction history receive
    trust proportional to their contribution volume. Sybil clusters, having
    no real contributions to honest nodes, receive near-zero trust.
    """

    def __init__(
        self,
        store: BlockStore,
        seed_nodes: List[str],
        delegation_store: Optional["DelegationStore"] = None,
    ) -> None:
        if not seed_nodes:
            raise NetFlowError(detail="At least one seed node required")
        self.store = store
        self.seeds = seed_nodes
        self.delegation_store = delegation_store
        # Graph cache: invalidates when block count changes.
        self._cached_graph: Optional[Dict[str, Dict[str, float]]] = None
        self._last_block_count: int = 0
        # Per-pubkey sequence numbers for incremental graph updates.
        self._known_seqs: Dict[str, int] = {}

    def invalidate_cache(self) -> None:
        """Explicitly invalidate the cached contribution graph."""
        self._cached_graph = None
        self._last_block_count = 0
        self._known_seqs.clear()

    def _get_or_build_graph(self) -> Dict[str, Dict[str, float]]:
        """Return the cached contribution graph, rebuilding or incrementally updating as needed.

        On first call, performs a full graph build. On subsequent calls, if the block
        count has changed, only processes new blocks (chains that have grown) rather
        than rebuilding the entire graph from scratch. This mirrors the Rust
        CachedNetFlow::ensure_graph() incremental update strategy.
        """
        current_count = self.store.get_block_count()
        if self._cached_graph is None:
            # Full rebuild.
            self._cached_graph = self.build_contribution_graph()
            self._last_block_count = current_count
            # Record per-pubkey sequence numbers.
            self._known_seqs.clear()
            for pubkey in self.store.get_all_pubkeys():
                chain = self.store.get_chain(pubkey)
                if chain:
                    self._known_seqs[pubkey] = len(chain)
        elif current_count != self._last_block_count:
            # Incremental update: only process new blocks.
            graph = self._cached_graph
            for pubkey in self.store.get_all_pubkeys():
                chain = self.store.get_chain(pubkey)
                known_seq = self._known_seqs.get(pubkey, 0)
                current_seq = len(chain)
                if current_seq <= known_seq:
                    continue
                # Process only new blocks.
                for block in chain[known_seq:]:
                    source = self._resolve_to_root(block.public_key)
                    target = self._resolve_to_root(block.link_public_key)
                    if source == target:
                        continue
                    if source not in graph:
                        graph[source] = {}
                    graph[source][target] = min(graph.get(source, {}).get(target, 0.0) + 0.5, 1.0)
                self._known_seqs[pubkey] = current_seq
            self._last_block_count = current_count
        return self._cached_graph

    def _resolve_to_root(self, pubkey: str) -> str:
        """Resolve a pubkey to its root identity if delegated."""
        if self.delegation_store is None:
            return pubkey
        delegation = self.delegation_store.get_delegation_by_delegate(pubkey)
        if delegation is None or not delegation.is_active:
            return pubkey
        # Walk up to root
        current = delegation
        while current.parent_delegation_id is not None:
            parent = self.delegation_store.get_delegation(current.parent_delegation_id)
            if parent is None:
                break
            current = parent
        return current.delegator_pubkey

    def build_contribution_graph(self) -> Dict[str, Dict[str, float]]:
        """Build a directed contribution graph from all stored half-blocks.

        Edge weight = total interaction volume between agents (sum of completed
        transactions). Each proposal/agreement pair counts as 1 unit of
        contribution in both directions.

        When a delegation store is configured, delegated agents' contributions
        are attributed to their root identity. Self-loops between delegates
        of the same operator are skipped (IETF §5 Sybil resistance).

        Returns: {source_pubkey: {target_pubkey: weight}}
        """
        graph: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))

        for pubkey in self.store.get_all_pubkeys():
            chain = self.store.get_chain(pubkey)
            for block in chain:
                source = self._resolve_to_root(block.public_key)
                target = self._resolve_to_root(block.link_public_key)
                if source == target:
                    continue  # Skip self-loops (including same-operator delegates)
                # Each half-block represents a contribution of 0.5
                # (proposal + agreement = 1.0 total per transaction)
                graph[source][target] = min(graph[source][target] + 0.5, 1.0)

        return {k: dict(v) for k, v in graph.items()}

    def _bfs_capacity(
        self,
        residual: Dict[str, Dict[str, float]],
        source: str,
        sink: str,
        parent: Dict[str, Optional[str]],
    ) -> float:
        """BFS to find augmenting path in residual graph. Returns bottleneck capacity."""
        visited: Set[str] = {source}
        queue: deque = deque([source])
        parent.clear()
        parent[source] = None

        while queue:
            u = queue.popleft()
            for v, cap in residual.get(u, {}).items():
                if v not in visited and cap > 1e-9:
                    visited.add(v)
                    parent[v] = u
                    if v == sink:
                        # Trace back to find bottleneck
                        path_flow = float("inf")
                        node = sink
                        while parent[node] is not None:
                            prev = parent[node]
                            path_flow = min(path_flow, residual[prev][node])
                            node = prev
                        return path_flow
                    queue.append(v)

        return 0.0

    def _max_flow(
        self,
        graph: Dict[str, Dict[str, float]],
        source: str,
        sink: str,
    ) -> float:
        """Edmonds-Karp max-flow algorithm (BFS-based Ford-Fulkerson).

        Note: Dinic's algorithm was considered but deliberately skipped. Profiling
        shows graph *building* (scanning chains) accounts for ~99% of compute_trust()
        time, not the max-flow computation itself. Edmonds-Karp is already fast on
        the small residual graphs. Incremental graph updates provide far more benefit.
        """
        if source == sink:
            return float("inf")

        # Build residual graph
        residual: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        for u in graph:
            for v, cap in graph[u].items():
                residual[u][v] += cap

        total_flow = 0.0
        parent: Dict[str, Optional[str]] = {}

        while True:
            path_flow = self._bfs_capacity(residual, source, sink, parent)
            if path_flow <= 1e-9:
                break

            # Update residual capacities
            node = sink
            while parent[node] is not None:
                prev = parent[node]
                residual[prev][node] -= path_flow
                residual[node][prev] += path_flow
                node = prev

            total_flow += path_flow

        return total_flow

    def _prepare_graph_with_super_source(
        self, graph: Dict[str, Dict[str, float]]
    ) -> tuple:
        """Add a virtual super-source to the graph (on a copy) and compute max_possible.

        Returns (augmented_graph, super_source_name, max_possible_flow).
        """
        super_source = "__super_source__"
        assert super_source not in graph, "Node name collision with virtual super-source"

        augmented = copy.deepcopy(graph)
        augmented[super_source] = {}
        for seed in self.seeds:
            if seed in graph or any(seed in g for g in graph.values()):
                augmented[super_source][seed] = float("inf")

        # max_possible = total outgoing capacity from seeds (not counting super-source edges)
        max_possible = sum(
            sum(graph.get(seed, {}).values())
            for seed in self.seeds
        )

        return augmented, super_source, max_possible

    def compute_path_diversity(self, target_pubkey: str) -> float:
        """Compute raw path diversity (max-flow) for a target agent.

        Returns the raw max-flow value (not normalized):
        - Seed nodes return float('inf')
        - Unknown/disconnected nodes return 0.0
        - Others get the raw max-flow from super-source

        Edge weights are capped at 1.0 per peer pair, so max-flow measures
        the number of independent paths (topology), not interaction volume.
        """
        if target_pubkey in self.seeds:
            return float("inf")

        graph = self._get_or_build_graph()
        if not graph:
            return 0.0

        augmented, super_source, max_possible = self._prepare_graph_with_super_source(graph)

        if max_possible <= 0:
            return 0.0

        return self._max_flow(augmented, super_source, target_pubkey)

    def compute_trust(self, target_pubkey: str) -> float:
        """Backward-compatible wrapper: returns compute_path_diversity result.

        .. deprecated:: 2.3
            Use ``compute_path_diversity()`` instead.
        """
        return self.compute_path_diversity(target_pubkey)

    def compute_all_path_diversities(self) -> Dict[str, float]:
        """Batch computation of raw path diversity for all known agents.

        Seeds return float('inf'). Builds the graph once and reuses it.
        """
        all_pubkeys = self.store.get_all_pubkeys()
        if not all_pubkeys:
            return {}

        graph = self._get_or_build_graph()
        if not graph:
            return {pk: (float("inf") if pk in self.seeds else 0.0) for pk in all_pubkeys}

        augmented, super_source, max_possible = self._prepare_graph_with_super_source(graph)

        scores: Dict[str, float] = {}
        for pk in all_pubkeys:
            if pk in self.seeds:
                scores[pk] = float("inf")
            elif max_possible <= 0:
                scores[pk] = 0.0
            else:
                raw_flow = self._max_flow(augmented, super_source, pk)
                scores[pk] = raw_flow

        return scores

    def compute_all_scores(self) -> Dict[str, float]:
        """Backward-compatible wrapper.

        .. deprecated:: 2.3
            Use ``compute_all_path_diversities()`` instead.
        """
        return self.compute_all_path_diversities()
