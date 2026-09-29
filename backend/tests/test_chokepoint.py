from types import SimpleNamespace

import networkx as nx
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.analysis import chokepoint
from backend.app.analysis.chokepoint import compute_chokepoints


def make_graph(*nodes):
    graph = nx.MultiDiGraph()

    for node_id, node_type in nodes:
        graph.add_node(node_id, type=node_type)

    return graph


def make_path(
    path_id,
    nodes,
    probability,
    cost,
    entry_point="entry-1",
    crown_jewel="crown-1",
    hop_count=None,
):
    if hop_count is None:
        hop_count = max(len(nodes) - 1, 0)

    return SimpleNamespace(
        id=path_id,
        nodes=list(nodes),
        total_probability=probability,
        total_traversal_cost=cost,
        entry_point=entry_point,
        crown_jewel=crown_jewel,
        hop_count=hop_count,
    )


def mock_paths(monkeypatch, paths):
    monkeypatch.setattr(
        chokepoint,
        "find_attack_paths",
        lambda graph, max_depth=10, max_paths=100: paths,
    )


def get_result(result, entity_id):
    for item in result.chokepoints:
        if item.entity_id == entity_id:
            return item

    raise AssertionError(f"Entity {entity_id!r} not found")


def test_chokepoint_single_path(monkeypatch):
    graph = make_graph(
        ("entry", "asset"),
        ("app", "asset"),
        ("db", "asset"),
    )

    paths = [
        make_path(
            "path-1",
            ["entry", "app", "db"],
            probability=0.8,
            cost=2.0,
        )
    ]

    mock_paths(monkeypatch, paths)

    result = compute_chokepoints(graph)

    assert result.total_attack_paths_analyzed == 1
    assert result.total_entities_analyzed == 3
    assert result.max_chokepoint_score == pytest.approx(1.0)

    entry = get_result(result, "entry")
    app = get_result(result, "app")
    db = get_result(result, "db")

    expected = 0.8 / 2.0

    assert entry.path_feasibility_criticality == pytest.approx(expected)
    assert app.path_feasibility_criticality == pytest.approx(expected)
    assert db.path_feasibility_criticality == pytest.approx(expected)

    assert entry.chokepoint_score == pytest.approx(1.0)
    assert app.chokepoint_score == pytest.approx(1.0)
    assert db.chokepoint_score == pytest.approx(1.0)

    assert entry.path_count == 1
    assert app.path_count == 1
    assert db.path_count == 1


def test_chokepoint_converging_paths(monkeypatch):
    graph = make_graph(
        ("entry", "asset"),
        ("a", "asset"),
        ("b", "asset"),
        ("c", "asset"),
        ("crown", "asset"),
    )

    paths = [
        make_path(
            "path-1",
            ["entry", "a", "c", "crown"],
            probability=0.8,
            cost=2.0,
        ),
        make_path(
            "path-2",
            ["entry", "b", "c", "crown"],
            probability=0.8,
            cost=2.0,
        ),
    ]

    mock_paths(monkeypatch, paths)

    result = compute_chokepoints(graph)

    c = get_result(result, "c")
    entry = get_result(result, "entry")
    crown = get_result(result, "crown")

    expected_single = 0.8 / 2.0
    expected_converging = expected_single * 2

    assert c.path_count == 2
    assert c.path_feasibility_criticality == pytest.approx(
        expected_converging
    )
    assert c.chokepoint_score == pytest.approx(1.0)

    assert entry.path_count == 2
    assert crown.path_count == 2

    assert entry.path_feasibility_criticality == pytest.approx(
        expected_converging
    )


def test_chokepoint_feasibility_vs_count(monkeypatch):
    graph = make_graph(
        ("entry", "asset"),
        ("x", "asset"),
        ("y", "asset"),
    )

    paths = [
        make_path(
            "high-feasibility",
            ["entry", "x"],
            probability=0.9,
            cost=1.0,
        )
    ]

    for index in range(10):
        paths.append(
            make_path(
                f"low-feasibility-{index}",
                ["entry", "y"],
                probability=0.1,
                cost=5.0,
            )
        )

    mock_paths(monkeypatch, paths)

    result = compute_chokepoints(graph)

    x = get_result(result, "x")
    y = get_result(result, "y")

    assert x.path_count == 1
    assert y.path_count == 10

    assert x.path_feasibility_criticality == pytest.approx(0.9)
    assert y.path_feasibility_criticality == pytest.approx(0.2)

    assert x.chokepoint_score > y.chokepoint_score


def test_chokepoint_multiple_entry_points(monkeypatch):
    graph = make_graph(
        ("entry-1", "asset"),
        ("entry-2", "asset"),
        ("app", "asset"),
        ("db", "asset"),
    )

    paths = [
        make_path(
            "path-1",
            ["entry-1", "app", "db"],
            probability=0.8,
            cost=2.0,
            entry_point="entry-1",
        ),
        make_path(
            "path-2",
            ["entry-2", "app", "db"],
            probability=0.6,
            cost=2.0,
            entry_point="entry-2",
        ),
    ]

    mock_paths(monkeypatch, paths)

    result = compute_chokepoints(graph)

    app = get_result(result, "app")

    assert app.path_count == 2
    assert app.unique_entry_points == 2


def test_chokepoint_multiple_crown_jewels(monkeypatch):
    graph = make_graph(
        ("entry", "asset"),
        ("app", "asset"),
        ("db-1", "asset"),
        ("db-2", "asset"),
    )

    paths = [
        make_path(
            "path-1",
            ["entry", "app", "db-1"],
            probability=0.8,
            cost=2.0,
            crown_jewel="db-1",
        ),
        make_path(
            "path-2",
            ["entry", "app", "db-2"],
            probability=0.7,
            cost=2.0,
            crown_jewel="db-2",
        ),
    ]

    mock_paths(monkeypatch, paths)

    result = compute_chokepoints(graph)

    app = get_result(result, "app")

    assert app.path_count == 2
    assert app.unique_crown_jewels == 2


def test_chokepoint_zero_probability(monkeypatch):
    graph = make_graph(
        ("entry", "asset"),
        ("app", "asset"),
    )

    paths = [
        make_path(
            "zero-prob",
            ["entry", "app"],
            probability=0.0,
            cost=1.0,
        )
    ]

    mock_paths(monkeypatch, paths)

    result = compute_chokepoints(graph)

    app = get_result(result, "app")

    assert app.path_feasibility_criticality == pytest.approx(0.0)
    assert app.chokepoint_score == pytest.approx(0.0)


def test_chokepoint_high_cost(monkeypatch):
    graph = make_graph(
        ("entry", "asset"),
        ("app", "asset"),
    )

    paths = [
        make_path(
            "expensive",
            ["entry", "app"],
            probability=1.0,
            cost=1_000_000.0,
        )
    ]

    mock_paths(monkeypatch, paths)

    result = compute_chokepoints(graph)

    app = get_result(result, "app")

    assert app.path_feasibility_criticality == pytest.approx(1e-6)
    assert app.path_feasibility_criticality < 0.00001


def test_chokepoint_zero_cost(monkeypatch):
    graph = make_graph(
        ("entry", "asset"),
        ("app", "asset"),
    )

    paths = [
        make_path(
            "zero-cost",
            ["entry", "app"],
            probability=0.5,
            cost=0.0,
        )
    ]

    mock_paths(monkeypatch, paths)

    result = compute_chokepoints(graph)

    app = get_result(result, "app")

    assert app.path_feasibility_criticality == pytest.approx(
        0.5 / 1e-9
    )

    assert app.chokepoint_score == pytest.approx(1.0)
    assert app.path_feasibility_criticality != float("inf")
    assert app.path_feasibility_criticality == pytest.approx(500_000_000.0)


def test_chokepoint_no_paths(monkeypatch):
    graph = make_graph(
        ("entry", "asset"),
        ("app", "asset"),
        ("db", "asset"),
    )

    mock_paths(monkeypatch, [])

    result = compute_chokepoints(graph)

    assert result.chokepoints == []
    assert result.total_entities_analyzed == 0
    assert result.max_chokepoint_score == pytest.approx(0.0)
    assert result.total_attack_paths_analyzed == 0


def test_chokepoint_cycle_safety(monkeypatch):
    graph = make_graph(
        ("a", "asset"),
        ("b", "asset"),
        ("c", "asset"),
    )

    graph.add_edge("a", "b")
    graph.add_edge("b", "c")
    graph.add_edge("c", "a")

    paths = [
        make_path(
            "cycle-safe-path",
            ["a", "b", "c"],
            probability=0.8,
            cost=3.0,
        )
    ]

    mock_paths(monkeypatch, paths)

    result = compute_chokepoints(
        graph,
        max_depth=10,
        max_paths=100,
    )

    assert result.total_attack_paths_analyzed == 1

    assert len(result.chokepoints) == 3


def test_chokepoint_multidigraph_parallel_edges(monkeypatch):
    graph = make_graph(
        ("entry", "asset"),
        ("app", "asset"),
        ("db", "asset"),
    )

    graph.add_edge(
        "entry",
        "app",
        key="edge-1",
        traversal_cost=1.0,
        probability=0.9,
    )

    graph.add_edge(
        "entry",
        "app",
        key="edge-2",
        traversal_cost=2.0,
        probability=0.5,
    )

    paths = [
        make_path(
            "parallel-path-1",
            ["entry", "app", "db"],
            probability=0.9,
            cost=2.0,
        ),
        make_path(
            "parallel-path-2",
            ["entry", "app", "db"],
            probability=0.5,
            cost=3.0,
        ),
    ]

    mock_paths(monkeypatch, paths)

    result = compute_chokepoints(graph)

    app = get_result(result, "app")

    expected = (0.9 / 2.0) + (0.5 / 3.0)

    assert app.path_count == 2
    assert app.path_feasibility_criticality == pytest.approx(expected)


def test_chokepoint_deterministic(monkeypatch):
    graph = make_graph(
        ("entry", "asset"),
        ("z-node", "asset"),
        ("a-node", "asset"),
        ("m-node", "asset"),
    )

    paths = [
        make_path(
            "path-z",
            ["entry", "z-node"],
            probability=0.5,
            cost=1.0,
        ),
        make_path(
            "path-a",
            ["entry", "a-node"],
            probability=0.5,
            cost=1.0,
        ),
        make_path(
            "path-m",
            ["entry", "m-node"],
            probability=0.5,
            cost=1.0,
        ),
    ]

    mock_paths(monkeypatch, paths)

    result_1 = compute_chokepoints(graph)
    result_2 = compute_chokepoints(graph)

    # Same input should produce identical output (deterministic)
    assert result_1.to_dict() == result_2.to_dict()

    # Verify the ordering is deterministic and follows the specified sort order:
    # 1. chokepoint_score descending
    # 2. entity_id ascending (for ties)
    ids = [item.entity_id for item in result_1.chokepoints]
    scores = [item.chokepoint_score for item in result_1.chokepoints]

    # Scores should be non-increasing
    assert scores == sorted(scores, reverse=True)

    # entry is on all 3 paths (score 1.0), others on 1 path each (score 0.33...)
    # So entry comes first, then a-node, m-node, z-node sorted alphabetically
    expected_order = ["entry", "a-node", "m-node", "z-node"]
    assert ids == expected_order


def test_chokepoint_max_paths_limit(monkeypatch):
    graph = make_graph(
        ("entry", "asset"),
        ("a", "asset"),
        ("b", "asset"),
    )

    paths = [
        make_path(
            "path-a",
            ["entry", "a"],
            probability=0.9,
            cost=1.0,
        ),
        make_path(
            "path-b",
            ["entry", "b"],
            probability=0.5,
            cost=1.0,
        ),
    ]

    def limited_paths(graph, max_depth=10, max_paths=100):
        return paths[:max_paths]

    monkeypatch.setattr(
        chokepoint,
        "find_attack_paths",
        limited_paths,
    )

    result_one = compute_chokepoints(
        graph,
        max_paths=1,
    )

    result_two = compute_chokepoints(
        graph,
        max_paths=2,
    )

    assert result_one.total_attack_paths_analyzed == 1
    assert result_two.total_attack_paths_analyzed == 2

    assert result_one.total_entities_analyzed < result_two.total_entities_analyzed


def test_chokepoint_max_depth_limit(monkeypatch):
    graph = make_graph(
        ("entry", "asset"),
        ("a", "asset"),
        ("b", "asset"),
        ("deep", "asset"),
    )

    paths = [
        make_path(
            "shallow",
            ["entry", "a"],
            probability=0.9,
            cost=1.0,
            hop_count=1,
        ),
        make_path(
            "deep",
            ["entry", "a", "b", "deep"],
            probability=0.8,
            cost=2.0,
            hop_count=3,
        ),
    ]

    def limited_paths(graph, max_depth=10, max_paths=100):
        return [
            path
            for path in paths
            if path.hop_count <= max_depth
        ][:max_paths]

    monkeypatch.setattr(
        chokepoint,
        "find_attack_paths",
        limited_paths,
    )

    result = compute_chokepoints(
        graph,
        max_depth=1,
    )

    assert result.total_attack_paths_analyzed == 1

    ids = {item.entity_id for item in result.chokepoints}

    assert "entry" in ids
    assert "a" in ids
    assert "b" not in ids
    assert "deep" not in ids


def test_chokepoint_asset_vs_finding(monkeypatch):
    graph = make_graph(
        ("entry", "asset"),
        ("finding-1", "finding"),
        ("app", "asset"),
        ("finding-2", "finding"),
        ("db", "asset"),
    )

    paths = [
        make_path(
            "path-1",
            ["entry", "finding-1", "app", "finding-2", "db"],
            probability=0.8,
            cost=4.0,
        )
    ]

    mock_paths(monkeypatch, paths)

    result = compute_chokepoints(graph)

    finding_1 = get_result(result, "finding-1")
    finding_2 = get_result(result, "finding-2")
    app = get_result(result, "app")

    assert finding_1.entity_type == "finding"
    assert finding_2.entity_type == "finding"
    assert app.entity_type == "asset"

    assert finding_1.path_count == 1
    assert finding_2.path_count == 1
    assert app.path_count == 1


def test_chokepoint_entity_type_filter(monkeypatch):
    graph = make_graph(
        ("entry", "asset"),
        ("finding-1", "finding"),
        ("app", "asset"),
        ("finding-2", "finding"),
    )

    paths = [
        make_path(
            "path-1",
            ["entry", "finding-1", "app", "finding-2"],
            probability=0.8,
            cost=4.0,
        )
    ]

    mock_paths(monkeypatch, paths)

    asset_result = compute_chokepoints(
        graph,
        entity_types="asset",
    )

    finding_result = compute_chokepoints(
        graph,
        entity_types="finding",
    )

    all_result = compute_chokepoints(
        graph,
        entity_types="all",
    )

    assert all(
        item.entity_type == "asset"
        for item in asset_result.chokepoints
    )

    assert all(
        item.entity_type == "finding"
        for item in finding_result.chokepoints
    )

    types = {item.entity_type for item in all_result.chokepoints}

    assert types == {"asset", "finding"}


def test_chokepoint_entity_counted_once_per_path(monkeypatch):
    graph = make_graph(
        ("entry", "asset"),
        ("app", "asset"),
    )

    # Deliberately repeat "app" in the path to ensure one path
    # contributes only once to the entity.
    paths = [
        make_path(
            "repeated-node-path",
            ["entry", "app", "app"],
            probability=0.8,
            cost=2.0,
        )
    ]

    mock_paths(monkeypatch, paths)

    result = compute_chokepoints(graph)

    app = get_result(result, "app")

    assert app.path_count == 1
    assert app.path_feasibility_criticality == pytest.approx(0.4)


def test_chokepoint_to_dict_structure(monkeypatch):
    graph = make_graph(
        ("entry", "asset"),
        ("app", "asset"),
    )

    paths = [
        make_path(
            "path-1",
            ["entry", "app"],
            probability=0.8,
            cost=2.0,
        )
    ]

    mock_paths(monkeypatch, paths)

    result = compute_chokepoints(graph)

    data = result.to_dict()

    assert "chokepoints" in data
    assert "total_entities_analyzed" in data
    assert "max_chokepoint_score" in data
    assert "total_attack_paths_analyzed" in data
    assert "max_depth_used" in data
    assert "max_paths_used" in data

    detail = data["chokepoints"][0]

    assert "entity_id" in detail
    assert "entity_type" in detail
    assert "chokepoint_score" in detail
    assert "path_feasibility_criticality" in detail
    assert "path_count" in detail
    assert "unique_entry_points" in detail
    assert "unique_crown_jewels" in detail
    assert "min_path_depth" in detail
    assert "max_path_depth" in detail


def test_chokepoint_metadata(monkeypatch):
    graph = make_graph(
        ("entry-1", "asset"),
        ("entry-2", "asset"),
        ("app", "asset"),
        ("db-1", "asset"),
        ("db-2", "asset"),
    )

    paths = [
        make_path(
            "path-1",
            ["entry-1", "app", "db-1"],
            probability=0.8,
            cost=2.0,
            entry_point="entry-1",
            crown_jewel="db-1",
            hop_count=2,
        ),
        make_path(
            "path-2",
            ["entry-2", "app", "db-2"],
            probability=0.6,
            cost=3.0,
            entry_point="entry-2",
            crown_jewel="db-2",
            hop_count=2,
        ),
    ]

    mock_paths(monkeypatch, paths)

    result = compute_chokepoints(graph)

    app = get_result(result, "app")

    assert app.path_count == 2
    assert app.unique_entry_points == 2
    assert app.unique_crown_jewels == 2
    assert app.min_path_depth == 2
    assert app.max_path_depth == 2


def test_chokepoint_same_score_sorted_by_entity_id(monkeypatch):
    graph = make_graph(
        ("entry", "asset"),
        ("zeta", "asset"),
        ("alpha", "asset"),
        ("beta", "asset"),
    )

    paths = [
        make_path(
            "path-z",
            ["entry", "zeta"],
            probability=0.5,
            cost=1.0,
        ),
        make_path(
            "path-alpha",
            ["entry", "alpha"],
            probability=0.5,
            cost=1.0,
        ),
        make_path(
            "path-beta",
            ["entry", "beta"],
            probability=0.5,
            cost=1.0,
        ),
    ]

    mock_paths(monkeypatch, paths)

    result = compute_chokepoints(graph)

    # All entities have equal feasibility, so tie-breaking
    # must use entity_id ascending.
    scored_ids = [
        item.entity_id
        for item in result.chokepoints
        if item.entity_id != "entry"
    ]

    assert scored_ids == ["alpha", "beta", "zeta"]


class TestChokepointAPI:
    """API endpoint tests for chokepoint analysis."""

    @pytest.fixture
    def client(self):
        return TestClient(app)

    def test_chokepoint_api_success(self, client):
        """Test successful chokepoint request."""
        response = client.get(
            "/api/scenarios/basic_test_scenario/chokepoints",
            params={"max_depth": 10},
        )
        assert response.status_code == 200
        data = response.json()
        
        # Verify required fields
        assert "chokepoints" in data
        assert "total_entities_analyzed" in data
        assert "max_chokepoint_score" in data
        assert "total_attack_paths_analyzed" in data
        assert "max_depth_used" in data
        assert "max_paths_used" in data
        
        # Verify chokepoint structure
        assert isinstance(data["chokepoints"], list)
        assert len(data["chokepoints"]) > 0
        
        for chokepoint in data["chokepoints"]:
            assert "entity_id" in chokepoint
            assert "entity_type" in chokepoint
            assert "chokepoint_score" in chokepoint
            assert "path_feasibility_criticality" in chokepoint
            assert "path_count" in chokepoint
            assert "unique_entry_points" in chokepoint
            assert "unique_crown_jewels" in chokepoint
            assert "min_path_depth" in chokepoint
            assert "max_path_depth" in chokepoint
            
            assert chokepoint["entity_type"] in ("asset", "finding")
            assert 0.0 <= chokepoint["chokepoint_score"] <= 1.0
            assert chokepoint["path_feasibility_criticality"] >= 0.0
            assert chokepoint["path_count"] >= 0
            assert chokepoint["unique_entry_points"] >= 0
            assert chokepoint["unique_crown_jewels"] >= 0
            assert chokepoint["min_path_depth"] >= 0
            assert chokepoint["max_path_depth"] >= 0
            assert chokepoint["min_path_depth"] <= chokepoint["max_path_depth"]

    def test_chokepoint_nonexistent_scenario(self, client):
        """Test 404 for nonexistent scenario."""
        response = client.get(
            "/api/scenarios/nonexistent/chokepoints",
        )
        assert response.status_code == 404
        assert response.json()["detail"] == "Scenario not found"

    def test_chokepoint_max_depth_zero(self, client):
        """Test max_depth=0."""
        response = client.get(
            "/api/scenarios/basic_test_scenario/chokepoints",
            params={"max_depth": 0},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["max_depth_used"] == 0

    def test_chokepoint_negative_max_depth(self, client):
        """Test 400 for negative max_depth."""
        response = client.get(
            "/api/scenarios/basic_test_scenario/chokepoints",
            params={"max_depth": -1},
        )
        assert response.status_code == 400
        assert "max_depth must be >= 0" in response.json()["detail"]

    def test_chokepoint_negative_max_paths(self, client):
        """Test 400 for negative max_paths."""
        response = client.get(
            "/api/scenarios/basic_test_scenario/chokepoints",
            params={"max_paths": -1},
        )
        assert response.status_code == 400
        assert "max_paths must be >= 0" in response.json()["detail"]

    def test_chokepoint_negative_limit(self, client):
        """Test 400 for negative limit."""
        response = client.get(
            "/api/scenarios/basic_test_scenario/chokepoints",
            params={"limit": -1},
        )
        assert response.status_code == 400
        assert "limit must be >= 0" in response.json()["detail"]

    def test_chokepoint_invalid_min_score(self, client):
        """Test 400 for invalid min_score."""
        response = client.get(
            "/api/scenarios/basic_test_scenario/chokepoints",
            params={"min_score": 1.5},
        )
        assert response.status_code == 400
        assert "min_score must be between 0.0 and 1.0" in response.json()["detail"]

    def test_chokepoint_entity_type_asset(self, client):
        """Test entity_type=asset filter."""
        response = client.get(
            "/api/scenarios/basic_test_scenario/chokepoints",
            params={"entity_type": "asset"},
        )
        assert response.status_code == 200
        data = response.json()
        for chokepoint in data["chokepoints"]:
            assert chokepoint["entity_type"] == "asset"

    def test_chokepoint_entity_type_finding(self, client):
        """Test entity_type=finding filter."""
        response = client.get(
            "/api/scenarios/basic_test_scenario/chokepoints",
            params={"entity_type": "finding"},
        )
        assert response.status_code == 200
        data = response.json()
        for chokepoint in data["chokepoints"]:
            assert chokepoint["entity_type"] == "finding"

    def test_chokepoint_entity_type_all(self, client):
        """Test entity_type=all returns both types."""
        response = client.get(
            "/api/scenarios/basic_test_scenario/chokepoints",
            params={"entity_type": "all"},
        )
        assert response.status_code == 200
        data = response.json()
        types = {cp["entity_type"] for cp in data["chokepoints"]}
        assert types <= {"asset", "finding"}

    def test_chokepoint_min_score_filter(self, client):
        """Test min_score filtering."""
        # First get all results
        response_all = client.get(
            "/api/scenarios/basic_test_scenario/chokepoints",
            params={"min_score": 0.0},
        )
        assert response_all.status_code == 200
        all_chokepoints = response_all.json()["chokepoints"]
        
        # Get max score
        if not all_chokepoints:
            pytest.skip("No chokepoints found")
        
        max_score = max(cp["chokepoint_score"] for cp in all_chokepoints)
        mid_score = max_score / 2.0
        
        # Filter with mid_score
        response_filtered = client.get(
            "/api/scenarios/basic_test_scenario/chokepoints",
            params={"min_score": mid_score},
        )
        assert response_filtered.status_code == 200
        filtered = response_filtered.json()["chokepoints"]
        
        # All returned should have score >= mid_score
        for cp in filtered:
            assert cp["chokepoint_score"] >= mid_score - 1e-9
        
        # Filtered should be subset of all
        assert len(filtered) <= len(all_chokepoints)

    def test_chokepoint_limit_filter(self, client):
        """Test limit filtering."""
        response = client.get(
            "/api/scenarios/basic_test_scenario/chokepoints",
            params={"limit": 2},
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data["chokepoints"]) <= 2

    def test_chokepoint_min_score_then_limit_preserves_order(self, client):
        """Test min_score then limit preserves score ordering."""
        response = client.get(
            "/api/scenarios/basic_test_scenario/chokepoints",
            params={"min_score": 0.0, "limit": 5},
        )
        assert response.status_code == 200
        data = response.json()
        
        scores = [cp["chokepoint_score"] for cp in data["chokepoints"]]
        # Should be in descending order
        assert scores == sorted(scores, reverse=True)

    def test_chokepoint_response_structure(self, client):
        """Test response matches ChokepointResponse structure."""
        response = client.get(
            "/api/scenarios/basic_test_scenario/chokepoints",
        )
        assert response.status_code == 200
        data = response.json()
        
        # Required top-level fields
        required_fields = {
            "chokepoints",
            "total_entities_analyzed",
            "max_chokepoint_score",
            "total_attack_paths_analyzed",
            "max_depth_used",
            "max_paths_used",
        }
        assert set(data.keys()) == required_fields
        
        # Types
        assert isinstance(data["chokepoints"], list)
        assert isinstance(data["total_entities_analyzed"], int)
        assert isinstance(data["max_chokepoint_score"], float)
        assert isinstance(data["total_attack_paths_analyzed"], int)
        assert isinstance(data["max_depth_used"], int)
        assert isinstance(data["max_paths_used"], int)
        
        # Score bounds
        assert 0.0 <= data["max_chokepoint_score"] <= 1.0
        
        # Chokepoint detail fields
        for cp in data["chokepoints"]:
            assert isinstance(cp["entity_id"], str)
            assert cp["entity_type"] in ("asset", "finding")
            assert isinstance(cp["chokepoint_score"], float)
            assert 0.0 <= cp["chokepoint_score"] <= 1.0
            assert isinstance(cp["path_feasibility_criticality"], float)
            assert cp["path_feasibility_criticality"] >= 0.0
            assert isinstance(cp["path_count"], int)
            assert cp["path_count"] >= 0
            assert isinstance(cp["unique_entry_points"], int)
            assert cp["unique_entry_points"] >= 0
            assert isinstance(cp["unique_crown_jewels"], int)
            assert cp["unique_crown_jewels"] >= 0
            assert isinstance(cp["min_path_depth"], int)
            assert cp["min_path_depth"] >= 0
            assert isinstance(cp["max_path_depth"], int)
            assert cp["max_path_depth"] >= 0
            assert cp["min_path_depth"] <= cp["max_path_depth"]
        
        # Deterministic ordering: score desc, then entity_id
        scores = [cp["chokepoint_score"] for cp in data["chokepoints"]]
        assert scores == sorted(scores, reverse=True)

    def test_chokepoint_max_paths_parameter(self, client):
        """Test max_paths parameter is passed through."""
        response = client.get(
            "/api/scenarios/basic_test_scenario/chokepoints",
            params={"max_paths": 50},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["max_paths_used"] == 50

    def test_chokepoint_max_depth_parameter(self, client):
        """Test max_depth parameter is passed through."""
        response = client.get(
            "/api/scenarios/basic_test_scenario/chokepoints",
            params={"max_depth": 5},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["max_depth_used"] == 5

    def test_chokepoint_min_score_then_limit_preserves_score_order(self, client):
        """Test min_score then limit preserves score ordering (descending)."""
        response = client.get(
            "/api/scenarios/basic_test_scenario/chokepoints",
            params={"min_score": 0.1, "limit": 10},
        )
        assert response.status_code == 200
        data = response.json()
        
        scores = [cp["chokepoint_score"] for cp in data["chokepoints"]]
        # Should be in descending order
        assert scores == sorted(scores, reverse=True)