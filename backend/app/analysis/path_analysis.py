"""
Attack path analysis module for finding paths from entry points to crown jewels
in a NetworkX MultiDiGraph.
"""
from typing import List, Dict, Any, Optional, Tuple
import heapq
import networkx as nx
from dataclasses import dataclass, field
@dataclass
class AttackPath:
    """Represents an attack path from an entry point to a crown jewel."""
    id: str
    entry_point: str
    crown_jewel: str
    nodes: List[str]
    edges: List[str]
    hop_count: int
    total_traversal_cost: float
    total_probability: float
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for JSON serialization."""
        return {
            "id": self.id,
            "entry_point": self.entry_point,
            "crown_jewel": self.crown_jewel,
            "nodes": self.nodes,
            "edges": self.edges,
            "hop_count": self.hop_count,
            "total_traversal_cost": self.total_traversal_cost,
            "total_probability": self.total_probability,
        }
def find_attack_paths(
    graph: nx.MultiDiGraph,
    max_depth: int = 10,
    max_paths: int = 100,
) -> List[AttackPath]:
    """
    Find all feasible attack paths from entry points to crown jewels.
    Args:
        graph: The canonical security graph (MultiDiGraph).
        max_depth: Maximum number of hops allowed in a path.
        max_paths: Maximum number of paths to return.
    Returns:
        List of AttackPath objects, sorted by hop count (ascending) then by
        total traversal cost (ascending) for deterministic ordering.
    """
    # Identify entry points and crown jewels
    entry_points = [
        node for node, data in graph.nodes(data=True)
        if data.get('is_entry_point', False)
    ]
    crown_jewels = [
        node for node, data in graph.nodes(data=True)
        if data.get('is_crown_jewel', False)
    ]
    if not entry_points or not crown_jewels:
        return []
    all_paths: List[AttackPath] = []
    path_id_counter = 0
    # For each entry point, perform a BFS limited by depth
    for entry in entry_points:
        # Queue items: (current_node, path_nodes, path_edges, cost, prob, depth)
        queue: List[Tuple[
            str,  # current node
            List[str],  # path nodes so far
            List[str],  # path edge IDs so far
            float,  # cumulative cost
            float,  # cumulative probability
            int,  # depth (number of edges traversed)
        ]] = [
            (entry, [entry], [], 0.0, 1.0, 0)
        ]
        while queue and len(all_paths) < max_paths:
            current_node, path_nodes, path_edges, cost, prob, depth = queue.pop(0)
            # If we have reached a crown jewel and the path is not just the entry point
            if current_node in crown_jewels and len(path_nodes) > 1:
                # Create a path ID
                path_id = f"path_{path_id_counter}"
                path_id_counter += 1
                attack_path = AttackPath(
                    id=path_id,
                    entry_point=path_nodes[0],
                    crown_jewel=path_nodes[-1],
                    nodes=path_nodes.copy(),
                    edges=path_edges.copy(),
                    hop_count=len(path_edges),
                    total_traversal_cost=cost,
                    total_probability=prob,
                )
                all_paths.append(attack_path)
                # We do not break here because we want to find all paths (up to max_paths)
                # Continue to explore other paths from this entry point
            # If we have reached the maximum depth, do not expand further
            if depth >= max_depth:
                continue
            # Explore neighbors
            for neighbor in sorted(graph.neighbors(current_node)):
                # Avoid cycles: do not revisit a node already in the current path
                if neighbor in path_nodes:
                    continue
                # Get all edge data between current_node and neighbor
                edge_data_dict = graph.get_edge_data(current_node, neighbor)
                if edge_data_dict is None:
                    continue
                # In a MultiDiGraph, edge_data_dict is a dict keyed by edge ID
                for edge_key in sorted(edge_data_dict.keys()):
                    edge_data = edge_data_dict[edge_key]
                    # Extract traversal cost and probability from edge data
                    edge_cost = edge_data.get("traversal_cost", 0.0)
                    edge_prob = edge_data.get("probability", 0.0)
                    
                    # Skip edges with zero probability? Not necessarily, but we can still traverse.
                    # However, if probability is zero, the path probability becomes zero.
                    # We'll still allow it.
                    new_path_nodes = path_nodes + [neighbor]
                    new_path_edges = path_edges + [edge_data["edge_id"]]
                    new_cost = cost + edge_cost
                    new_prob = prob * edge_prob
                    new_depth = depth + 1
                    
                    queue.append(
                        (neighbor, new_path_nodes, new_path_edges, new_cost, new_prob, new_depth)
                    )
    # Sort paths for deterministic ordering: first by hop count, then by cost, then by ID
    all_paths.sort(key=lambda p: (p.hop_count, p.total_traversal_cost, p.id))
    # Trim to max_paths if we have more (though we already limited in the loop)
    return all_paths[:max_paths]
def _entry_points_and_crowns(
    graph: nx.MultiDiGraph,
) -> Tuple[List[str], set]:
    """Entry points (graph node order) and crown jewels (lookup set)."""
    entry_points = [
        node for node, data in graph.nodes(data=True)
        if data.get('is_entry_point', False)
    ]
    crown_jewels = {
        node for node, data in graph.nodes(data=True)
        if data.get('is_crown_jewel', False)
    }
    return entry_points, crown_jewels


def _ordered_extensions(
    graph: nx.MultiDiGraph,
    path_nodes: Tuple[str, ...],
    visited: set,
):
    """Yield (neighbor, edge_key, edge_data) in deterministic order.

    Mirrors the traversal order of find_attack_paths: neighbors sorted,
    parallel edges in sorted key order, cycle-safe (no node revisited).
    """
    current_node = path_nodes[-1]
    for neighbor in sorted(graph.neighbors(current_node)):
        if neighbor in visited:
            continue
        edge_data_dict = graph.get_edge_data(current_node, neighbor)
        if edge_data_dict is None:
            continue
        for edge_key in sorted(edge_data_dict.keys()):
            yield neighbor, edge_key, edge_data_dict[edge_key]


def _best_first_path(
    graph: nx.MultiDiGraph,
    max_depth: int,
    priority,
) -> Optional[AttackPath]:
    """Return the optimal simple attack path under a heap priority.

    priority(depth, cost, entry_index, nodes, edges) -> comparable key.
    The heap pops states in priority order, so the first crown jewel popped
    (excluding the trivial single-node stay) is globally optimal: every other
    heap state — and any path extending it, since traversal costs are
    non-negative — is ordered at or after it. Expansion is cycle-safe,
    depth-bounded, and deterministic (sorted neighbors, sorted edge keys).
    """
    entry_points, crown_jewels = _entry_points_and_crowns(graph)
    if not entry_points or not crown_jewels:
        return None
    heap: List[Tuple[Any, ...]] = []
    for entry_index, entry in enumerate(entry_points):
        heapq.heappush(
            heap,
            (priority(0, 0.0, entry_index, (entry,), ()), 0.0, entry_index, (entry,), (), 1.0),
        )
    while heap:
        _, cost, entry_index, path_nodes, path_edges, prob = heapq.heappop(heap)
        if path_nodes[-1] in crown_jewels and len(path_nodes) > 1:
            return AttackPath(
                id="path_0",
                entry_point=path_nodes[0],
                crown_jewel=path_nodes[-1],
                nodes=list(path_nodes),
                edges=list(path_edges),
                hop_count=len(path_edges),
                total_traversal_cost=cost,
                total_probability=prob,
            )
        depth = len(path_edges)
        if depth >= max_depth:
            continue
        visited = set(path_nodes)
        for neighbor, _, edge_data in _ordered_extensions(graph, path_nodes, visited):
            edge_cost = edge_data.get("traversal_cost", 0.0)
            edge_prob = edge_data.get("probability", 0.0)
            new_nodes = path_nodes + (neighbor,)
            new_edges = path_edges + (edge_data["edge_id"],)
            new_cost = cost + edge_cost
            heapq.heappush(
                heap,
                (
                    priority(
                        depth + 1, new_cost, entry_index, new_nodes, new_edges,
                    ),
                    new_cost,
                    entry_index,
                    new_nodes,
                    new_edges,
                    prob * edge_prob,
                ),
            )
    return None


def get_shortest_path(graph: nx.MultiDiGraph, max_depth: int = 10) -> Optional[AttackPath]:
    """
    Get the shortest path (by hop count) from entry points to crown jewels.
    The result is globally optimal: minimal hops, then minimal traversal
    cost, then deterministic (entry order, node sequence, edge sequence).
    Args:
        graph: The canonical security graph (MultiDiGraph).
        max_depth: Maximum number of hops allowed.
    Returns:
        The shortest AttackPath, or None if no path exists.
    """
    return _best_first_path(
        graph,
        max_depth,
        lambda depth, cost, entry_index, nodes, edges: (
            depth, cost, entry_index, nodes, edges,
        ),
    )
def get_cheapest_path(graph: nx.MultiDiGraph, max_depth: int = 10) -> Optional[AttackPath]:
    """
    Get the cheapest path (by total traversal cost) from entry points to crown jewels.
    The result is globally optimal within max_depth: minimal traversal cost,
    then fewer hops, then deterministic (entry order, node sequence, edge
    sequence). Exact for the project's non-negative traversal-cost model;
    no arbitrary path-count cap is involved.
    Args:
        graph: The canonical security graph (MultiDiGraph).
        max_depth: Maximum number of hops allowed.
    Returns:
        The cheapest AttackPath, or None if no path exists.
    """
    return _best_first_path(
        graph,
        max_depth,
        lambda depth, cost, entry_index, nodes, edges: (
            cost, depth, entry_index, nodes, edges,
        ),
    )
