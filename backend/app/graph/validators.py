"""
Graph integrity validators for the canonical security graph.
"""
from typing import List, Tuple, Dict, Any
import networkx as nx
from backend.app.graph.edge_semantics import EdgeType


def validate_graph_structure(graph: nx.DiGraph) -> Tuple[bool, List[str]]:
    """
    Validate the overall structure of the security graph.
    
    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []
    
    # Check for nodes
    if graph.number_of_nodes() == 0:
        errors.append("Graph has no nodes")
        return False, errors
    
    # Check for node types (should have 'type' attribute)
    for node_id, node_data in graph.nodes(data=True):
        if 'type' not in node_data:
            errors.append(f"Node {node_id} missing 'type' attribute")
        elif node_data['type'] not in ['asset', 'vulnerability', 'finding']:
            errors.append(f"Node {node_id} has invalid type: {node_data['type']}")
    
    # Check for edge types
    for u, v, edge_data in graph.edges(data=True):
        if 'edge_type' not in edge_data:
            errors.append(f"Edge {u}->{v} missing 'edge_type' attribute")
        elif edge_data['edge_type'] not in [e.value for e in EdgeType]:
            errors.append(f"Edge {u}->{v} has invalid edge_type: {edge_data['edge_type']}")
        
        # Validate traversal_cost is non-negative
        if 'traversal_cost' in edge_data and edge_data['traversal_cost'] < 0:
            errors.append(f"Edge {u}->{v} has negative traversal_cost: {edge_data['traversal_cost']}")
        
        # Validate probability is between 0 and 1
        if 'probability' in edge_data and not (0 <= edge_data['probability'] <= 1):
            errors.append(f"Edge {u}->{v} has invalid probability: {edge_data['probability']}")
    
    # Check for dangling references (edges pointing to non-existent nodes)
    # This is handled by NetworkX automatically when adding edges, but we double-check
    for u, v in graph.edges():
        if u not in graph.nodes():
            errors.append(f"Edge source node {u} does not exist")
        if v not in graph.nodes():
            errors.append(f"Edge target node {v} does not exist")
    
    # Check for self-loops (generally not meaningful in attack graphs)
    self_loops = list(nx.nodes_with_selfloops(graph))
    if self_loops:
        errors.append(f"Graph contains self-loops on nodes: {self_loops}")
    
    return len(errors) == 0, errors


def validate_edge_consistency(graph: nx.DiGraph) -> Tuple[bool, List[str]]:
    """
    Validate that edges are consistent with their source/target node types.
    
    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []
    
    for u, v, edge_data in graph.edges(data=True):
        edge_type = edge_data.get('edge_type')
        source_type = graph.nodes[u].get('type')
        target_type = graph.nodes[v].get('type')
        
        # Define valid source/target type combinations for each edge type
        valid_combinations = {
            EdgeType.EXPLOITS: [('finding', 'asset')],  # Finding (vulnerability) -> Asset
            EdgeType.CAN_REACH: [('asset', 'asset'), ('asset', 'finding'), ('finding', 'asset')],
            EdgeType.LATERAL_MOVEMENT: [('asset', 'asset'), ('finding', 'finding')],
            EdgeType.PRIVILEGE_ESCALATION: [('asset', 'asset'), ('finding', 'finding')],
            EdgeType.CREDENTIAL_ACCESS: [('finding', 'asset'), ('asset', 'asset')],
            EdgeType.TRUSTED_ACCESS: [('asset', 'asset')],
        }
        
        if edge_type in [e.value for e in EdgeType]:
            edge_type_enum = EdgeType(edge_type)
            valid_combos = valid_combinations.get(edge_type_enum, [])
            
            if (source_type, target_type) not in valid_combos and valid_combos:
                errors.append(
                    f"Edge {u}->{v} with type '{edge_type}' has invalid "
                    f"node types: {source_type} -> {target_type}"
                )
    
    return len(errors) == 0, errors


def validate_no_dangling_references(graph: nx.DiGraph) -> Tuple[bool, List[str]]:
    """
    Validate that there are no dangling references in the graph.
    
    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []
    node_ids = set(graph.nodes())
    
    # Check that all edge source and target IDs exist as nodes
    for u, v, edge_data in graph.edges(data=True):
        if u not in node_ids:
            errors.append(f"Edge source '{u}' does not exist as a node")
        if v not in node_ids:
            errors.append(f"Edge target '{v}' does not exist as a node")
    
    return len(errors) == 0, errors


def validate_graph_size(graph: nx.DiGraph, max_nodes: int = 10000, max_edges: int = 50000) -> Tuple[bool, List[str]]:
    """
    Validate that the graph size is within reasonable limits.
    
    Args:
        graph: The graph to validate
        max_nodes: Maximum allowed number of nodes
        max_edges: Maximum allowed number of edges
    
    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []
    
    node_count = graph.number_of_nodes()
    edge_count = graph.number_of_edges()
    
    if node_count > max_nodes:
        errors.append(f"Graph has too many nodes: {node_count} > {max_nodes}")
    
    if edge_count > max_edges:
        errors.append(f"Graph has too many edges: {edge_count} > {max_edges}")
    
    return len(errors) == 0, errors


def validate_graph(graph: nx.DiGraph) -> Tuple[bool, List[str]]:
    """
    Perform all validation checks on the graph.
    
    Returns:
        Tuple of (is_valid, list_of_all_errors)
    """
    all_errors = []
    
    # Run all validation functions
    validators = [
        validate_graph_structure,
        validate_edge_consistency,
        validate_no_dangling_references,
        validate_graph_size,
    ]
    
    for validator in validators:
        is_valid, errors = validator(graph)
        all_errors.extend(errors)
    
    return len(all_errors) == 0, all_errors