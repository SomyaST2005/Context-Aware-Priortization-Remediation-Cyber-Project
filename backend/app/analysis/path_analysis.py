"""
Attack path analysis module for finding paths from entry points to crown jewels
in a NetworkX MultiDiGraph.
"""
from typing import List, Dict, Any, Optional, Tuple
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
def get_shortest_path(graph: nx.MultiDiGraph, max_depth: int = 10) -> Optional[AttackPath]:
    """
    Get the shortest path (by hop count) from entry points to crown jewels.
    Args:
        graph: The canonical security graph (MultiDiGraph).
        max_depth: Maximum number of hops allowed.
    Returns:
        The shortest AttackPath, or None if no path exists.
    """
    paths = find_attack_paths(graph, max_depth=max_depth, max_paths=1)
    return paths[0] if paths else None
def get_cheapest_path(graph: nx.MultiDiGraph, max_depth: int = 10) -> Optional[AttackPath]:
    """
    Get the cheapest path (by total traversal cost) from entry points to crown jewels.
    Args:
        graph: The canonical security graph (MultiDiGraph).
        max_depth: Maximum number of hops allowed.
    Returns:
        The cheapest AttackPath, or None if no path exists.
    """
    # We need to find all paths up to max_depth and then select the one with minimum cost.
    # We'll set a reasonable max_paths to avoid too much computation.
    paths = find_attack_paths(graph, max_depth=max_depth, max_paths=1000)
    if not paths:
        return None
    # Sort by total traversal cost
    paths.sort(key=lambda p: p.total_traversal_cost)
    return paths[0]
