"""
Blast radius analysis module for computing downstream reachability from a compromised asset
in a NetworkX MultiDiGraph.

This module implements a bounded multi-objective label-setting algorithm (Bellman-Ford style
with Pareto frontiers per node per depth) to compute the blast radius of a compromised asset.
"""
from collections import defaultdict
from dataclasses import dataclass
from typing import List, Dict, Optional
import networkx as nx


@dataclass(frozen=True, order=True)
class Label:
    """
    A non-dominated (cost, probability) pair at a specific depth.
    The `order=True` gives cost-first then prob for deterministic set ordering.
    """
    cost: float
    prob: float


@dataclass
class ReachabilityDetail:
    """
    Aggregated reachability metrics for a single asset across all depths.
    """
    asset_id: str
    depth: int              # minimum depth at which asset is reachable
    min_traversal_cost: float  # minimum cost across ALL paths (any depth)
    max_probability: float     # maximum probability across ALL paths (any depth)

    def to_dict(self) -> dict:
        return {
            "asset_id": self.asset_id,
            "depth": self.depth,
            "min_traversal_cost": self.min_traversal_cost,
            "max_probability": self.max_probability,
        }


@dataclass
class BlastRadiusResult:
    """
    Complete blast radius result for a source asset.
    """
    source_asset: str
    affected_assets: List[str]           # sorted asset IDs
    affected_asset_count: int
    crown_jewels_reached: List[str]      # sorted subset
    max_depth_reached: int
    reachability_details: List[ReachabilityDetail]  # sorted by asset_id

    def to_dict(self) -> dict:
        return {
            "source_asset": self.source_asset,
            "affected_assets": self.affected_assets,
            "affected_asset_count": self.affected_asset_count,
            "crown_jewels_reached": self.crown_jewels_reached,
            "max_depth_reached": self.max_depth_reached,
            "reachability_details": [rd.to_dict() for rd in self.reachability_details],
        }


def compute_blast_radius(
    graph: nx.MultiDiGraph,
    source_asset_id: str,
    max_depth: int = 10,
) -> BlastRadiusResult:
    """
    Compute the blast radius from a compromised asset.

    This uses a bounded label-setting algorithm with Pareto frontiers per (node, depth).
    For each node and exact depth d ∈ [0, max_depth], we maintain the set of
    non-dominated (cost, probability) labels that reach that node in exactly d hops.

    Args:
        graph: Canonical security graph (MultiDiGraph).
        source_asset_id: Starting asset node ID (must exist and be type='asset').
        max_depth: Maximum edge traversals from source (source = depth 0). Must be >= 0.

    Returns:
        BlastRadiusResult with affected assets, crown jewels, reachability details.

    Raises:
        ValueError: If source_asset_id not found, not an asset node, or max_depth < 0.
    """
    # Validate max_depth
    if max_depth < 0:
        raise ValueError("max_depth must be >= 0")

    # Validate source exists and is an asset
    if source_asset_id not in graph:
        raise ValueError(f"Source node {source_asset_id} not in graph")
    if graph.nodes[source_asset_id].get('type') != 'asset':
        raise ValueError(f"Source {source_asset_id} is not an asset node")

    # Labels per node per depth: labels[node_id][depth] = List[Label]
    # Each Label represents an actual path to (node, depth)
    labels: Dict[str, Dict[int, List[Label]]] = defaultdict(lambda: defaultdict(list))

    # Initialize with source at depth 0
    labels[source_asset_id][0] = [Label(cost=0.0, prob=1.0)]

    # Queue entries: (depth, node_id, cost, prob)
    queue: List[tuple] = [(0, source_asset_id, 0.0, 1.0)]

    # Track maximum depth actually processed
    max_depth_reached = 0

    while queue:
        # Deterministic pop order: (depth, cost, -prob, node_id)
        queue.sort(key=lambda x: (x[0], x[1], -x[2], x[3]))
        depth, node, cost, prob = queue.pop(0)

        # Update max depth reached
        if depth > max_depth_reached:
            max_depth_reached = depth

        # Depth bound: do not expand beyond max_depth
        if depth >= max_depth:
            continue

        # Skip if this exact label was dominated after enqueueing
        current_labels = labels[node][depth]
        if not any(lbl.cost == cost and lbl.prob == prob for lbl in current_labels):
            continue

        # Expand to neighbors
        for neighbor in sorted(graph.neighbors(node)):
            edge_data_dict = graph.get_edge_data(node, neighbor)
            if not edge_data_dict:
                continue

            for edge_key in sorted(edge_data_dict.keys()):
                edge = edge_data_dict[edge_key]
                edge_cost = edge.get('traversal_cost', 0.0)
                edge_prob = edge.get('probability', 0.0)

                new_depth = depth + 1
                new_cost = cost + edge_cost
                new_prob = prob * edge_prob
                new_label = Label(cost=new_cost, prob=new_prob)

                # Check dominance against existing labels at (neighbor, new_depth)
                neighbor_labels = labels[neighbor][new_depth]

                # Skip if dominated by existing label at this depth
                dominated = False
                for existing in neighbor_labels:
                    if existing.cost <= new_cost and existing.prob >= new_prob:
                        dominated = True
                        break
                if dominated:
                    continue

                # Remove existing labels dominated by the new one
                labels[neighbor][new_depth] = [
                    lbl for lbl in neighbor_labels
                    if not (new_cost <= lbl.cost and new_prob >= lbl.prob)
                ]

                # Add new label
                labels[neighbor][new_depth].append(new_label)

                # Enqueue for further expansion
                queue.append((new_depth, neighbor, new_cost, new_prob))

    # Aggregate results per asset across all depths
    reachable_assets = {}

    for node_id, depth_map in labels.items():
        # Only include asset nodes in the final result
        if graph.nodes[node_id].get('type') != 'asset':
            continue

        all_labels = [lbl for depth_labels in depth_map.values() for lbl in depth_labels]
        if not all_labels:
            continue

        # Minimum depth at which this asset is reachable
        min_depth = min(
            d for d, dl in depth_map.items() if dl
        )

        # Minimum cost and maximum probability across ALL paths (any depth)
        min_cost = min(lbl.cost for lbl in all_labels)
        max_prob = max(lbl.prob for lbl in all_labels)

        reachable_assets[node_id] = {
            'min_depth': min_depth,
            'min_cost': min_cost,
            'max_prob': max_prob,
        }

    # Build deterministic result
    affected_assets = sorted(reachable_assets.keys())
    crown_jewels = sorted(
        aid for aid in affected_assets
        if graph.nodes[aid].get('is_crown_jewel', False)
    )

    reachability_details = [
        ReachabilityDetail(
            asset_id=aid,
            depth=reachable_assets[aid]['min_depth'],
            min_traversal_cost=reachable_assets[aid]['min_cost'],
            max_probability=reachable_assets[aid]['max_prob'],
        )
        for aid in affected_assets
    ]

    return BlastRadiusResult(
        source_asset=source_asset_id,
        affected_assets=affected_assets,
        affected_asset_count=len(affected_assets),
        crown_jewels_reached=crown_jewels,
        max_depth_reached=max_depth_reached,
        reachability_details=reachability_details,
    )