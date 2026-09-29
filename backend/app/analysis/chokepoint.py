"""
Chokepoint analysis module for identifying critical attack-path bottlenecks
in a NetworkX MultiDiGraph.

This module implements a post-processing layer over the existing attack-path
engine to identify actionable entities (assets and findings) whose remediation
would eliminate a significant amount of attack-path feasibility between
entry points and crown jewels.

The primary metric is ChokepointScore, a normalized measure of how much
risk-weighted attack-path feasibility (probability/cost) passes through
each entity across all discovered attack paths.
"""
from collections import defaultdict
from dataclasses import dataclass
from typing import List, Dict, Literal, Optional
import networkx as nx

from backend.app.analysis.path_analysis import find_attack_paths, AttackPath


EPSILON = 1e-9


@dataclass
class ChokepointDetail:
    """
    Detailed chokepoint metrics for a single entity (asset or finding).
    """
    entity_id: str
    entity_type: Literal["asset", "finding"]
    chokepoint_score: float                    # normalized [0, 1]
    path_feasibility_criticality: float        # raw RWPC (sum of PathFeasibility)
    path_count: int                            # number of attack paths through entity
    unique_entry_points: int                   # explanatory
    unique_crown_jewels: int                   # explanatory
    min_path_depth: int                        # explanatory
    max_path_depth: int                        # explanatory

    def to_dict(self) -> dict:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "chokepoint_score": self.chokepoint_score,
            "path_feasibility_criticality": self.path_feasibility_criticality,
            "path_count": self.path_count,
            "unique_entry_points": self.unique_entry_points,
            "unique_crown_jewels": self.unique_crown_jewels,
            "min_path_depth": self.min_path_depth,
            "max_path_depth": self.max_path_depth,
        }


@dataclass
class ChokepointResult:
    """
    Complete chokepoint analysis result.
    """
    chokepoints: List[ChokepointDetail]        # sorted by score desc, then entity_id
    total_entities_analyzed: int
    max_chokepoint_score: float
    total_attack_paths_analyzed: int
    max_depth_used: int
    max_paths_used: int

    def to_dict(self) -> dict:
        return {
            "chokepoints": [c.to_dict() for c in self.chokepoints],
            "total_entities_analyzed": self.total_entities_analyzed,
            "max_chokepoint_score": self.max_chokepoint_score,
            "total_attack_paths_analyzed": self.total_attack_paths_analyzed,
            "max_depth_used": self.max_depth_used,
            "max_paths_used": self.max_paths_used,
        }


def compute_chokepoints(
    graph: nx.MultiDiGraph,
    max_depth: int = 10,
    max_paths: int = 100,
    entity_types: Literal["asset", "finding", "all"] = "all",
) -> ChokepointResult:
    """
    Compute chokepoints from the canonical attack graph.

    This is a post-processing layer over the existing attack-path engine.
    It identifies actionable entities (assets and findings) whose remediation
    would eliminate a significant amount of attack-path feasibility between
    entry points and crown jewels.

    Args:
        graph: Canonical security graph (MultiDiGraph).
        max_depth: Maximum hops per attack path (passed to find_attack_paths).
        max_paths: Maximum paths to discover (passed to find_attack_paths).
        entity_types: "asset", "finding", or "all".

    Returns:
        ChokepointResult with scored entities.

    Note:
        The analysis is based on the attack paths returned by find_attack_paths().
        If max_paths truncates path discovery, chokepoint scores reflect only
        the discovered paths. Results are deterministic for the same graph and
        parameters but may not be mathematically complete when max_paths
        truncates traversal.
    """
    # Validate entity_types
    if entity_types not in ("asset", "finding", "all"):
        raise ValueError(f"entity_types must be 'asset', 'finding', or 'all', got '{entity_types}'")

    # Discover attack paths using existing engine
    paths = find_attack_paths(graph, max_depth=max_depth, max_paths=max_paths)

    if not paths:
        return ChokepointResult(
            chokepoints=[],
            total_entities_analyzed=0,
            max_chokepoint_score=0.0,
            total_attack_paths_analyzed=0,
            max_depth_used=max_depth,
            max_paths_used=max_paths,
        )

    # Compute PathFeasibility for each path
    # PathFeasibility(p) = P(p) / max(C(p), EPSILON)
    path_feasibility = {}
    for p in paths:
        cost = p.total_traversal_cost
        prob = p.total_probability
        path_feasibility[p.id] = prob / max(cost, EPSILON)

    # Aggregate per entity
    entity_data = defaultdict(lambda: {
        "entity_type": None,
        "path_ids": [],
        "entry_points": set(),
        "crown_jewels": set(),
        "depths": [],
    })

    for p in paths:
        pf = path_feasibility[p.id]
        # Use set to ensure each entity is counted at most once per path
        unique_nodes_in_path = set(p.nodes)
        for node_id in unique_nodes_in_path:
            node_type = graph.nodes[node_id].get("type")
            if node_type not in ("asset", "finding"):
                continue

            data = entity_data[node_id]
            data["entity_type"] = node_type
            data["path_ids"].append(p.id)
            data["entry_points"].add(p.entry_point)
            data["crown_jewels"].add(p.crown_jewel)
            data["depths"].append(p.hop_count)

    # Filter by requested entity_types
    if entity_types != "all":
        entity_data = {k: v for k, v in entity_data.items()
                       if v["entity_type"] == entity_types}

    # Compute RWPC (path_feasibility_criticality) for each entity
    rwpc_map = {}
    for eid, data in entity_data.items():
        rwpc = sum(path_feasibility[pid] for pid in data["path_ids"])
        rwpc_map[eid] = rwpc

    max_rwpc = max(rwpc_map.values()) if rwpc_map else 0.0

    # Build sorted results
    chokepoints = []
    for eid, data in entity_data.items():
        rwpc = rwpc_map[eid]
        score = rwpc / max_rwpc if max_rwpc > 0 else 0.0

        chokepoints.append(ChokepointDetail(
            entity_id=eid,
            entity_type=data["entity_type"],
            chokepoint_score=score,
            path_feasibility_criticality=rwpc,
            path_count=len(data["path_ids"]),
            unique_entry_points=len(data["entry_points"]),
            unique_crown_jewels=len(data["crown_jewels"]),
            min_path_depth=min(data["depths"]) if data["depths"] else 0,
            max_path_depth=max(data["depths"]) if data["depths"] else 0,
        ))

    # Deterministic sort: score desc, then entity_id asc
    chokepoints.sort(key=lambda c: (-c.chokepoint_score, c.entity_id))

    return ChokepointResult(
        chokepoints=chokepoints,
        total_entities_analyzed=len(chokepoints),
        max_chokepoint_score=chokepoints[0].chokepoint_score if chokepoints else 0.0,
        total_attack_paths_analyzed=len(paths),
        max_depth_used=max_depth,
        max_paths_used=max_paths,
    )