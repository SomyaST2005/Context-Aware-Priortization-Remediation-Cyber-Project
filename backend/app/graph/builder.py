"""
Canonical graph builder service for constructing NetworkX MultiDiGraph from domain models.
"""
import networkx as nx
from typing import Dict, List, Any, Optional
from sqlalchemy.orm import Session

from backend.app.models.database import (
    Asset, Vulnerability, Finding, Edge, RemediationAction, Scenario
)
from backend.app.graph.edge_semantics import EdgeType, EDGE_TYPE_BASE_COSTS, EDGE_TYPE_PROBABILITIES
from backend.app.graph.validators import validate_graph


class CanonicalGraphBuilder:
    """Builds a canonical NetworkX MultiDiGraph from domain entities."""
    
    def __init__(self, db_session: Session):
        self.db_session = db_session
        self.graph = nx.MultiDiGraph()
    
    def build_graph_from_scenario(self, scenario_id: str) -> nx.MultiDiGraph:
        """
        Build a canonical security graph for the given scenario.
         
        Args:
            scenario_id: The ID of the scenario to build the graph for
             
        Returns:
            NetworkX MultiDiGraph representing the canonical security graph
        """
        # Clear any existing graph
        self.graph.clear()
        
        # Get scenario data
        scenario = self.db_session.query(Scenario).filter(Scenario.id == scenario_id).first()
        if not scenario:
            raise ValueError(f"Scenario with ID {scenario_id} not found")
        
        # Store scenario_id for use in helper methods
        self.scenario_id = scenario_id
        
        # Add assets as nodes
        self._add_asset_nodes()
        
        # Add vulnerabilities as nodes (optional - can be accessed via findings)
        self._add_vulnerability_nodes()
        
        # Add findings as nodes
        self._add_finding_nodes()
        
        # Add edges (attack transitions)
        self._add_edges()
        
        # Validate the constructed graph
        is_valid, errors = validate_graph(self.graph)
        if not is_valid:
            raise ValueError(f"Graph validation failed: {', '.join(errors)}")
        
        return self.graph
    
    def _add_asset_nodes(self) -> None:
        """Add asset nodes to the graph."""
        assets = self.db_session.query(Asset).filter(Asset.scenario_id == self.scenario_id).all()
        for asset in assets:
            self.graph.add_node(
                asset.id,
                type="asset",
                asset_id=asset.id,
                name=asset.name,
                asset_type=asset.type.value if asset.type else None,
                criticality=asset.criticality,
                environment=asset.environment.value if asset.environment else None,
                network_zone=asset.network_zone.value if asset.network_zone else None,
                is_entry_point=asset.is_entry_point,
                is_crown_jewel=asset.is_crown_jewel,
                owner=asset.owner,
                ip_address=asset.ip_address,
                description=asset.description
            )
    
    def _add_vulnerability_nodes(self) -> None:
        """Add vulnerability nodes to the graph (optional)."""
        vulnerabilities = self.db_session.query(Vulnerability).filter(Vulnerability.scenario_id == self.scenario_id).all()
        for vuln in vulnerabilities:
            self.graph.add_node(
                vuln.id,
                type="vulnerability",
                vulnerability_id=vuln.id,
                cve_id=vuln.cve_id,
                title=vuln.title,
                description=vuln.description,
                cvss_score=vuln.cvss_score,
                severity=vuln.severity.value if vuln.severity else None,
                epss_score=vuln.epss_score,
                known_exploited=vuln.known_exploited,
                attack_vector=vuln.attack_vector.value if vuln.attack_vector else None,
                attack_complexity=vuln.attack_complexity.value if vuln.attack_complexity else None,
                privileges_required=vuln.privileges_required.value if vuln.privileges_required else None,
                user_interaction=vuln.user_interaction.value if vuln.user_interaction else None,
                remediation_effort=vuln.remediation_effort
            )
    
    def _add_finding_nodes(self) -> None:
        """Add finding nodes to the graph."""
        findings = self.db_session.query(Finding).filter(Finding.scenario_id == self.scenario_id).all()
        for finding in findings:
            self.graph.add_node(
                finding.id,
                type="finding",
                finding_id=finding.id,
                asset_id=finding.asset_id,
                vulnerability_id=finding.vulnerability_id,
                port=finding.port,
                service_name=finding.service_name,
                status=finding.status.value if finding.status else None,
                discovered_at=finding.discovered_at.isoformat() if finding.discovered_at else None
            )
    
    def _add_edges(self) -> None:
        """Add edges (attack transitions) to the graph."""
        edges = self.db_session.query(Edge).filter(Edge.scenario_id == self.scenario_id).all()
        for edge in edges:
            # Determine source and target types for validation
            source_node = self.graph.nodes.get(edge.source_id, {})
            target_node = self.graph.nodes.get(edge.target_id, {})
            source_type = source_node.get('type', 'unknown')
            target_type = target_node.get('type', 'unknown')
            
            # Use provided values or fall back to defaults based on edge type
            traversal_cost = edge.traversal_cost
            probability = edge.probability
            
            # If not explicitly set, use defaults from edge semantics
            if traversal_cost is 0.0:  # Assuming 0.0 means not set
                edge_type_enum = EdgeType(edge.edge_type)
                traversal_cost = EDGE_TYPE_BASE_COSTS.get(edge_type_enum, 1.0)
            
            if probability is 0.0:  # Assuming 0.0 means not set
                edge_type_enum = EdgeType(edge.edge_type)
                probability = EDGE_TYPE_PROBABILITIES.get(edge_type_enum, 0.5)
            
            self.graph.add_edge(
                edge.source_id,
                edge.target_id,
                edge_id=edge.id,
                type="edge",
                edge_type=edge.edge_type.value,
                port=edge.port,
                protocol=edge.protocol,
                traversal_cost=traversal_cost,
                probability=probability,
                finding_id=edge.finding_id,
                description=edge.description
            )
    
    def get_graph_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the current graph.
         
        Returns:
            Dictionary containing graph statistics
        """
        if self.graph.number_of_nodes() == 0:
            return {
                "nodes": 0,
                "edges": 0,
                "asset_nodes": 0,
                "finding_nodes": 0,
                "vulnerability_nodes": 0,
                "entry_points": 0,
                "crown_jewels": 0
            }
        
        asset_count = sum(1 for _, data in self.graph.nodes(data=True) if data.get('type') == 'asset')
        finding_count = sum(1 for _, data in self.graph.nodes(data=True) if data.get('type') == 'finding')
        vulnerability_count = sum(1 for _, data in self.graph.nodes(data=True) if data.get('type') == 'vulnerability')
        entry_point_count = sum(1 for _, data in self.graph.nodes(data=True) if data.get('is_entry_point', False))
        crown_jewel_count = sum(1 for _, data in self.graph.nodes(data=True) if data.get('is_crown_jewel', False))
        
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "asset_nodes": asset_count,
            "finding_nodes": finding_count,
            "vulnerability_nodes": vulnerability_count,
            "entry_points": entry_point_count,
            "crown_jewels": crown_jewel_count
        }
    
    def get_entry_points(self) -> List[str]:
        """
        Get list of entry point node IDs.
         
        Returns:
            List of node IDs that are entry points
        """
        return [
            node_id for node_id, data in self.graph.nodes(data=True)
            if data.get('is_entry_point', False)
        ]
    
    def get_crown_jewels(self) -> List[str]:
        """
        Get list of crown jewel node IDs.
         
        Returns:
            List of node IDs that are crown jewels
        """
        return [
            node_id for node_id, data in self.graph.nodes(data=True)
            if data.get('is_crown_jewel', False)
        ]
    
    def get_assets_by_type(self, asset_type: str) -> List[str]:
        """
        Get list of asset node IDs by type.
         
        Args:
            asset_type: The type of asset to filter by
             
        Returns:
            List of asset node IDs matching the type
        """
        return [
            node_id for node_id, data in self.graph.nodes(data=True)
            if data.get('type') == 'asset' and data.get('asset_type') == asset_type
        ]
    
    def get_assets_by_zone(self, network_zone: str) -> List[str]:
        """
        Get list of asset node IDs by network zone.
         
        Args:
            network_zone: The network zone to filter by
             
        Returns:
            List of asset node IDs in the specified zone
        """
        return [
            node_id for node_id, data in self.graph.nodes(data=True)
            if data.get('type') == 'asset' and data.get('network_zone') == network_zone
        ]
    

def build_canonical_graph(db_session: Session, scenario_id: str) -> nx.MultiDiGraph:
    """
    Convenience function to build a canonical graph from a scenario.
     
    Args:
        db_session: SQLAlchemy database session
        scenario_id: ID of the scenario to build graph for
         
    Returns:
        NetworkX MultiDiGraph representing the canonical security graph
    """
    builder = CanonicalGraphBuilder(db_session)
    return builder.build_graph_from_scenario(scenario_id)

