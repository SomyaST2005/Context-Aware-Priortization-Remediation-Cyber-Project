"""
Test cases for blast radius analysis.
"""
import pytest
import networkx as nx
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.analysis.blast_radius import (
    compute_blast_radius,
    BlastRadiusResult,
    ReachabilityDetail,
)
from backend.app.core.database import SessionLocal
from backend.app.graph.builder import build_canonical_graph
from backend.app.models.database import Scenario


def create_test_graph() -> nx.MultiDiGraph:
    """Create a simple test graph for blast radius testing."""
    graph = nx.MultiDiGraph()

    # Assets
    graph.add_node("asset-source", type="asset", is_entry_point=True, is_crown_jewel=False)
    graph.add_node("asset-mid", type="asset", is_entry_point=False, is_crown_jewel=False)
    graph.add_node("asset-target", type="asset", is_entry_point=False, is_crown_jewel=True)
    graph.add_node("asset-isolated", type="asset", is_entry_point=False, is_crown_jewel=False)

    # Findings
    graph.add_node("finding-1", type="finding", asset_id="asset-mid")
    graph.add_node("finding-2", type="finding", asset_id="asset-target")

    # Edges: source -> finding-1 -> mid -> finding-2 -> target
    graph.add_edge(
        "asset-source", "finding-1",
        edge_id="edge-1", edge_type="CAN_REACH", traversal_cost=1.0, probability=0.9
    )
    graph.add_edge(
        "finding-1", "asset-mid",
        edge_id="edge-2", edge_type="EXPLOITS", traversal_cost=2.0, probability=0.7
    )
    graph.add_edge(
        "asset-mid", "finding-2",
        edge_id="edge-3", edge_type="CAN_REACH", traversal_cost=1.0, probability=0.8
    )
    graph.add_edge(
        "finding-2", "asset-target",
        edge_id="edge-4", edge_type="EXPLOITS", traversal_cost=2.5, probability=0.6
    )

    # Direct edge source -> target (alternative path)
    graph.add_edge(
        "asset-source", "asset-target",
        edge_id="edge-direct", edge_type="CAN_REACH", traversal_cost=5.0, probability=0.3
    )

    return graph


def create_cyclic_graph() -> nx.MultiDiGraph:
    """Create a graph with a cycle to test cycle safety."""
    graph = nx.MultiDiGraph()

    graph.add_node("asset-source", type="asset", is_entry_point=True, is_crown_jewel=False)
    graph.add_node("asset-a", type="asset", is_entry_point=False, is_crown_jewel=False)
    graph.add_node("asset-b", type="asset", is_entry_point=False, is_crown_jewel=True)

    # Cycle: source -> a -> b -> a
    graph.add_edge("asset-source", "asset-a", edge_id="e1", edge_type="CAN_REACH", traversal_cost=1.0, probability=0.9)
    graph.add_edge("asset-a", "asset-b", edge_id="e2", edge_type="CAN_REACH", traversal_cost=1.0, probability=0.8)
    graph.add_edge("asset-b", "asset-a", edge_id="e3", edge_type="CAN_REACH", traversal_cost=1.0, probability=0.7)

    return graph


def create_multi_path_graph() -> nx.MultiDiGraph:
    """Create a graph with multiple paths to the same asset."""
    graph = nx.MultiDiGraph()

    graph.add_node("asset-source", type="asset", is_entry_point=True, is_crown_jewel=False)
    graph.add_node("asset-target", type="asset", is_entry_point=False, is_crown_jewel=True)
    graph.add_node("asset-intermediate", type="asset", is_entry_point=False, is_crown_jewel=False)

    # Path 1: source -> intermediate -> target (cost 3, prob 0.6)
    graph.add_edge("asset-source", "asset-intermediate", edge_id="e1", edge_type="CAN_REACH", traversal_cost=1.0, probability=0.9)
    graph.add_edge("asset-intermediate", "asset-target", edge_id="e2", edge_type="CAN_REACH", traversal_cost=2.0, probability=0.6)

    # Path 2: source -> target directly (cost 5, prob 0.3)
    graph.add_edge("asset-source", "asset-target", edge_id="e3", edge_type="CAN_REACH", traversal_cost=5.0, probability=0.3)

    return graph


def create_zero_prob_graph() -> nx.MultiDiGraph:
    """Create a graph with zero-probability edges."""
    graph = nx.MultiDiGraph()

    graph.add_node("asset-source", type="asset", is_entry_point=True, is_crown_jewel=False)
    graph.add_node("asset-target", type="asset", is_entry_point=False, is_crown_jewel=True)

    # Zero probability edge - still reachable but prob=0
    graph.add_edge("asset-source", "asset-target", edge_id="e1", edge_type="CAN_REACH", traversal_cost=1.0, probability=0.0)

    return graph


class TestBlastRadiusBasic:
    """Basic reachability tests."""

    def test_basic_reachability(self):
        """Test that source reaches direct neighbors."""
        graph = create_test_graph()
        result = compute_blast_radius(graph, "asset-source", max_depth=2)

        assert isinstance(result, BlastRadiusResult)
        assert result.source_asset == "asset-source"
        assert "asset-source" in result.affected_assets
        assert "asset-mid" in result.affected_assets
        assert result.affected_asset_count >= 2

    def test_multi_hop_reachability(self):
        """Test multi-hop reachability through intermediate nodes."""
        graph = create_test_graph()
        result = compute_blast_radius(graph, "asset-source", max_depth=5)

        # Should reach all three assets
        assert set(result.affected_assets) == {"asset-source", "asset-mid", "asset-target"}
        assert result.affected_asset_count == 3
        assert "asset-target" in result.crown_jewels_reached

    def test_source_only_max_depth_zero(self):
        """Test max_depth=0 returns only source asset."""
        graph = create_test_graph()
        result = compute_blast_radius(graph, "asset-source", max_depth=0)

        assert result.affected_assets == ["asset-source"]
        assert result.affected_asset_count == 1
        assert result.max_depth_reached == 0
        assert len(result.reachability_details) == 1
        detail = result.reachability_details[0]
        assert detail.asset_id == "asset-source"
        assert detail.depth == 0
        assert detail.min_traversal_cost == 0.0
        assert detail.max_probability == 1.0

    def test_negative_max_depth_raises(self):
        """Test that negative max_depth raises ValueError."""
        graph = create_test_graph()
        with pytest.raises(ValueError, match="max_depth must be >= 0"):
            compute_blast_radius(graph, "asset-source", max_depth=-1)

    def test_invalid_source_raises(self):
        """Test that non-existent source raises ValueError."""
        graph = create_test_graph()
        with pytest.raises(ValueError, match="not in graph"):
            compute_blast_radius(graph, "non-existent", max_depth=10)

    def test_non_asset_source_raises(self):
        """Test that non-asset source raises ValueError."""
        graph = create_test_graph()
        with pytest.raises(ValueError, match="not an asset node"):
            compute_blast_radius(graph, "finding-1", max_depth=10)


class TestBlastRadiusCycles:
    """Cycle safety tests."""

    def test_cycle_safety(self):
        """Test that cycles don't cause infinite loops."""
        graph = create_cyclic_graph()
        result = compute_blast_radius(graph, "asset-source", max_depth=10)

        # Should reach all three assets without looping infinitely
        assert set(result.affected_assets) == {"asset-source", "asset-a", "asset-b"}
        assert result.affected_asset_count == 3
        assert "asset-b" in result.crown_jewels_reached
        # max_depth_reached should be <= max_depth (10)
        assert result.max_depth_reached <= 10


class TestBlastRadiusAggregation:
    """Tests for multi-path aggregation."""

    def test_multiple_paths_same_asset(self):
        """Test that multiple paths to same asset are aggregated correctly."""
        graph = create_multi_path_graph()
        result = compute_blast_radius(graph, "asset-source", max_depth=3)

        # Should reach both assets
        assert set(result.affected_assets) == {"asset-source", "asset-intermediate", "asset-target"}

        # Check reachability details for target
        target_detail = next(d for d in result.reachability_details if d.asset_id == "asset-target")
        # Min cost should be 3.0 (path via intermediate: 1.0 + 2.0)
        assert target_detail.min_traversal_cost == 3.0
        # Max prob should be 0.54 (path via intermediate: 0.9 * 0.6)
        # Direct path has prob 0.3, intermediate path has prob 0.54
        assert target_detail.max_probability == 0.54
        # Min depth should be 1 (direct path)
        assert target_detail.depth == 1

    def test_crown_jewel_reached(self):
        """Test that crown jewels are correctly identified."""
        graph = create_test_graph()
        result = compute_blast_radius(graph, "asset-source", max_depth=5)

        assert "asset-target" in result.crown_jewels_reached
        assert len(result.crown_jewels_reached) == 1


class TestBlastRadiusDeterminism:
    """Deterministic output tests."""

    def test_deterministic_output(self):
        """Test that same input produces identical output."""
        graph = create_test_graph()
        result1 = compute_blast_radius(graph, "asset-source", max_depth=5)
        result2 = compute_blast_radius(graph, "asset-source", max_depth=5)

        assert result1.to_dict() == result2.to_dict()

    def test_deterministic_ordering(self):
        """Test that affected_assets and details are sorted."""
        graph = create_multi_path_graph()
        result = compute_blast_radius(graph, "asset-source", max_depth=3)

        # affected_assets should be sorted
        assert result.affected_assets == sorted(result.affected_assets)
        # crown_jewels_reached should be sorted
        assert result.crown_jewels_reached == sorted(result.crown_jewels_reached)
        # reachability_details should be sorted by asset_id
        asset_ids = [d.asset_id for d in result.reachability_details]
        assert asset_ids == sorted(asset_ids)


class TestBlastRadiusMaxDepth:
    """Max depth boundary tests."""

    def test_max_depth_boundary(self):
        """Test that max_depth limits traversal correctly."""
        graph = create_test_graph()
        # max_depth=1: source -> finding-1 (not an asset) AND source -> asset-target (direct, depth 1)
        # max_depth=2: source -> finding-1 -> asset-mid
        # max_depth=4: source -> finding-1 -> asset-mid -> finding-2 -> asset-target
        # max_depth=5: same + direct path

        result1 = compute_blast_radius(graph, "asset-source", max_depth=1)
        # Source and target (direct edge at depth 1)
        assert set(result1.affected_assets) == {"asset-source", "asset-target"}

        result2 = compute_blast_radius(graph, "asset-source", max_depth=2)
        assert "asset-mid" in result2.affected_assets
        assert "asset-target" in result2.affected_assets

        result4 = compute_blast_radius(graph, "asset-source", max_depth=4)
        assert "asset-target" in result4.affected_assets


class TestBlastRadiusEdgeCases:
    """Edge case tests."""

    def test_no_downstream_nodes(self):
        """Test source with no outgoing edges."""
        graph = nx.MultiDiGraph()
        graph.add_node("asset-source", type="asset", is_entry_point=True, is_crown_jewel=False)
        graph.add_node("asset-isolated", type="asset", is_entry_point=False, is_crown_jewel=False)
        # No edges

        result = compute_blast_radius(graph, "asset-source", max_depth=5)
        assert result.affected_assets == ["asset-source"]
        assert result.affected_asset_count == 1

    def test_zero_probability_edge(self):
        """Test that zero-probability edges are handled (reachable but prob=0)."""
        graph = create_zero_prob_graph()
        result = compute_blast_radius(graph, "asset-source", max_depth=2)

        assert "asset-target" in result.affected_assets
        target_detail = next(d for d in result.reachability_details if d.asset_id == "asset-target")
        assert target_detail.max_probability == 0.0
        assert target_detail.min_traversal_cost == 1.0

    def test_source_is_crown_jewel(self):
        """Test when source itself is a crown jewel."""
        graph = nx.MultiDiGraph()
        graph.add_node("asset-source", type="asset", is_entry_point=True, is_crown_jewel=True)
        graph.add_node("asset-target", type="asset", is_entry_point=False, is_crown_jewel=True)
        graph.add_edge("asset-source", "asset-target", edge_id="e1", edge_type="CAN_REACH", traversal_cost=1.0, probability=0.9)

        result = compute_blast_radius(graph, "asset-source", max_depth=5)
        assert "asset-source" in result.crown_jewels_reached
        assert "asset-target" in result.crown_jewels_reached


class TestBlastRadiusWithSeedScenario:
    """Integration tests using the seed scenario."""

    def test_seed_scenario_blast_radius(self):
        """Test blast radius with the actual seed scenario."""
        from backend.app.core.database import SessionLocal
        from backend.app.graph.builder import build_canonical_graph
        from backend.app.models.database import Scenario

        db = SessionLocal()
        try:
            scenario = db.query(Scenario).filter(Scenario.id == "basic_test_scenario").first()
            assert scenario is not None
            graph = build_canonical_graph(db, scenario.id)

            # Test from web server (entry point)
            result = compute_blast_radius(graph, "asset-web-01", max_depth=10)

            assert result.source_asset == "asset-web-01"
            assert "asset-web-01" in result.affected_assets
            assert "asset-app-01" in result.affected_assets
            assert "asset-db-01" in result.affected_assets
            assert "asset-db-01" in result.crown_jewels_reached
            assert result.affected_asset_count == 3
            assert result.max_depth_reached > 0

        finally:
            db.close()


class TestBlastRadiusAPI:
    """API endpoint tests for blast radius."""

    @pytest.fixture
    def client(self):
        return TestClient(app)

    def test_blast_radius_success(self, client):
        """Test successful blast-radius request."""
        response = client.get(
            "/api/scenarios/basic_test_scenario/blast-radius/asset-web-01",
            params={"max_depth": 10},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["source_asset"] == "asset-web-01"
        assert "asset-web-01" in data["affected_assets"]
        assert "asset-app-01" in data["affected_assets"]
        assert "asset-db-01" in data["affected_assets"]
        assert "asset-db-01" in data["crown_jewels_reached"]
        assert data["affected_asset_count"] == 3
        assert data["max_depth_reached"] > 0
        assert len(data["reachability_details"]) == 3
        # Verify structure of reachability_details
        for detail in data["reachability_details"]:
            assert "asset_id" in detail
            assert "depth" in detail
            assert "min_traversal_cost" in detail
            assert "max_probability" in detail

    def test_blast_radius_nonexistent_scenario(self, client):
        """Test 404 for nonexistent scenario."""
        response = client.get(
            "/api/scenarios/nonexistent/blast-radius/asset-web-01",
        )
        assert response.status_code == 404
        assert response.json()["detail"] == "Scenario not found"

    def test_blast_radius_invalid_source_asset(self, client):
        """Test 400 for invalid source asset ID."""
        response = client.get(
            "/api/scenarios/basic_test_scenario/blast-radius/non-existent-asset",
        )
        assert response.status_code == 400
        assert "not in graph" in response.json()["detail"]

    def test_blast_radius_non_asset_source(self, client):
        """Test 400 for non-asset source node."""
        response = client.get(
            "/api/scenarios/basic_test_scenario/blast-radius/finding-01",
        )
        assert response.status_code == 400
        assert "not an asset node" in response.json()["detail"]

    def test_blast_radius_max_depth_zero(self, client):
        """Test max_depth=0 returns only source asset."""
        response = client.get(
            "/api/scenarios/basic_test_scenario/blast-radius/asset-web-01",
            params={"max_depth": 0},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["affected_assets"] == ["asset-web-01"]
        assert data["affected_asset_count"] == 1
        assert data["max_depth_reached"] == 0
        assert len(data["reachability_details"]) == 1
        detail = data["reachability_details"][0]
        assert detail["asset_id"] == "asset-web-01"
        assert detail["depth"] == 0
        assert detail["min_traversal_cost"] == 0.0
        assert detail["max_probability"] == 1.0

    def test_blast_radius_negative_max_depth(self, client):
        """Test 400 for negative max_depth."""
        response = client.get(
            "/api/scenarios/basic_test_scenario/blast-radius/asset-web-01",
            params={"max_depth": -1},
        )
        assert response.status_code == 400
        assert "max_depth must be >= 0" in response.json()["detail"]

    def test_blast_radius_response_structure(self, client):
        """Test response matches BlastRadiusResponse structure."""
        response = client.get(
            "/api/scenarios/basic_test_scenario/blast-radius/asset-web-01",
        )
        assert response.status_code == 200
        data = response.json()
        # Required fields
        required_fields = {
            "source_asset",
            "affected_assets",
            "affected_asset_count",
            "crown_jewels_reached",
            "max_depth_reached",
            "reachability_details",
        }
        assert set(data.keys()) == required_fields
        # Types
        assert isinstance(data["source_asset"], str)
        assert isinstance(data["affected_assets"], list)
        assert isinstance(data["affected_asset_count"], int)
        assert isinstance(data["crown_jewels_reached"], list)
        assert isinstance(data["max_depth_reached"], int)
        assert isinstance(data["reachability_details"], list)
        # Details structure
        for detail in data["reachability_details"]:
            assert isinstance(detail["asset_id"], str)
            assert isinstance(detail["depth"], int)
            assert isinstance(detail["min_traversal_cost"], float)
            assert isinstance(detail["max_probability"], float)
            assert detail["depth"] >= 0
            assert detail["min_traversal_cost"] >= 0.0
            assert 0.0 <= detail["max_probability"] <= 1.0
        # Sorted ordering
        assert data["affected_assets"] == sorted(data["affected_assets"])
        assert data["crown_jewels_reached"] == sorted(data["crown_jewels_reached"])
        detail_ids = [d["asset_id"] for d in data["reachability_details"]]
        assert detail_ids == sorted(detail_ids)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])