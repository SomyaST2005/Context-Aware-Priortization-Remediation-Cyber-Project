"""
Tests for contextual prioritization.

The analysis tests use small in-memory graphs and monkeypatched upstream
analysis functions so the prioritization layer can be tested independently.
API tests exercise the real FastAPI application and the existing seeded DB.
"""
from __future__ import annotations

from dataclasses import dataclass

import networkx as nx
import pytest
from fastapi.testclient import TestClient

from backend.app.analysis import prioritization as pz
from backend.app.analysis.path_analysis import AttackPath
from backend.app.main import app


client = TestClient(app)


@dataclass
class FakeReachabilityDetail:
    min_traversal_cost: float
    max_probability: float


@dataclass
class FakeBlastRadiusResult:
    source_asset: str
    affected_asset_count: int
    crown_jewels_reached: list[str]
    max_depth_reached: int
    reachability_details: list[FakeReachabilityDetail]


@dataclass
class FakeChokepoint:
    entity_id: str
    chokepoint_score: float
    path_feasibility_criticality: float
    path_count: int


@dataclass
class FakeChokepointResult:
    chokepoints: list[FakeChokepoint]


def make_graph() -> nx.MultiDiGraph:
    graph = nx.MultiDiGraph()

    graph.add_node(
        "entry-asset",
        type="asset",
        criticality=8.0,
        is_entry_point=True,
        is_crown_jewel=False,
        network_zone="dmz",
    )
    graph.add_node(
        "internal-asset",
        type="asset",
        criticality=9.0,
        is_entry_point=False,
        is_crown_jewel=False,
        network_zone="app_tier",
    )
    graph.add_node(
        "db-asset",
        type="asset",
        criticality=10.0,
        is_entry_point=False,
        is_crown_jewel=True,
        network_zone="db_tier",
    )

    graph.add_node(
        "finding-high",
        type="finding",
        asset_id="entry-asset",
        vulnerability_id="vuln-high",
        status="active",
    )
    graph.add_node(
        "finding-low",
        type="finding",
        asset_id="internal-asset",
        vulnerability_id="vuln-low",
        status="active",
    )

    graph.add_node(
        "vuln-high",
        type="vulnerability",
        cvss_score=9.8,
        epss_score=0.85,
        known_exploited=True,
    )
    graph.add_node(
        "vuln-low",
        type="vulnerability",
        cvss_score=5.0,
        epss_score=None,
        known_exploited=False,
    )

    return graph


def fake_paths() -> list[AttackPath]:
    return [
        AttackPath(
            id="path-1",
            entry_point="entry-asset",
            crown_jewel="db-asset",
            nodes=["entry-asset", "finding-high", "db-asset"],
            edges=["e1", "e2"],
            hop_count=2,
            total_traversal_cost=2.0,
            total_probability=0.9,
        ),
        AttackPath(
            id="path-2",
            entry_point="entry-asset",
            crown_jewel="db-asset",
            nodes=["entry-asset", "finding-high", "internal-asset", "db-asset"],
            edges=["e3", "e4", "e5"],
            hop_count=3,
            total_traversal_cost=6.0,
            total_probability=0.6,
        ),
    ]


def install_fake_upstreams(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pz, "find_attack_paths", lambda *args, **kwargs: fake_paths())

    def fake_blast_radius(graph, asset_id, max_depth=10):
        if asset_id == "entry-asset":
            return FakeBlastRadiusResult(
                source_asset=asset_id,
                affected_asset_count=2,
                crown_jewels_reached=["db-asset"],
                max_depth_reached=min(max_depth, 2),
                reachability_details=[
                    FakeReachabilityDetail(2.0, 0.45),
                    FakeReachabilityDetail(4.0, 0.30),
                ],
            )
        return FakeBlastRadiusResult(
            source_asset=asset_id,
            affected_asset_count=1,
            crown_jewels_reached=["db-asset"],
            max_depth_reached=min(max_depth, 1),
            reachability_details=[FakeReachabilityDetail(2.0, 0.4)],
        )

    monkeypatch.setattr(pz, "compute_blast_radius", fake_blast_radius)

    monkeypatch.setattr(
        pz,
        "compute_chokepoints",
        lambda *args, **kwargs: FakeChokepointResult(
            chokepoints=[
                FakeChokepoint("finding-high", 1.0, 0.75, 2),
                FakeChokepoint("entry-asset", 0.5, 0.45, 2),
            ]
        ),
    )


def test_profile_cvss_normalization() -> None:
    assert pz.normalize_cvss(10.0) == 1.0
    assert pz.normalize_cvss(5.0) == 0.5
    assert pz.normalize_cvss(0.0) == 0.0


def test_profile_feasibility_normalization() -> None:
    assert pz.normalize_path_feasibility(0.0) == 0.0
    assert pz.normalize_path_feasibility(1.0) == pytest.approx(0.5)
    assert pz.normalize_path_feasibility(3.0) == pytest.approx(0.75)
    assert pz.normalize_path_feasibility(1000.0) < 1.0


def test_profile_severity_boundaries() -> None:
    expected = {
        0.0: "NONE",
        0.1: "LOW",
        3.9: "LOW",
        4.0: "MEDIUM",
        6.9: "MEDIUM",
        7.0: "HIGH",
        8.9: "HIGH",
        9.0: "CRITICAL",
        10.0: "CRITICAL",
    }
    for score, category in expected.items():
        assert pz.cvss_to_severity(score) == category


def test_profile_epss_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    install_fake_upstreams(monkeypatch)
    results = pz.compute_prioritization(make_graph(), scenario_id="test")
    low = next(r for r in results if r.profile.finding_id == "finding-low")
    assert low.profile.epss_score is None
    assert low.profile.epss_available is False


def test_profile_finding_path_mapping(monkeypatch: pytest.MonkeyPatch) -> None:
    install_fake_upstreams(monkeypatch)
    results = pz.compute_prioritization(make_graph(), scenario_id="test")
    high = next(r for r in results if r.profile.finding_id == "finding-high")
    low = next(r for r in results if r.profile.finding_id == "finding-low")
    assert high.profile.path_participation_count == 2
    assert low.profile.path_participation_count == 0


def test_profile_blast_radius_aggregation(monkeypatch: pytest.MonkeyPatch) -> None:
    install_fake_upstreams(monkeypatch)
    results = pz.compute_prioritization(make_graph(), scenario_id="test")
    high = next(r for r in results if r.profile.finding_id == "finding-high")
    assert high.profile.blast_radius_min_cost == pytest.approx(2.0)
    assert high.profile.blast_radius_max_prob == pytest.approx(0.45)
    assert high.profile.blast_radius_crown_jewels == 1


def test_profile_finding_vs_asset_chokepoint(monkeypatch: pytest.MonkeyPatch) -> None:
    install_fake_upstreams(monkeypatch)
    results = pz.compute_prioritization(make_graph(), scenario_id="test")
    high = next(r for r in results if r.profile.finding_id == "finding-high")
    assert high.profile.finding_chokepoint_score == pytest.approx(1.0)
    assert high.profile.asset_chokepoint_score == pytest.approx(0.5)


def test_ordering_crown_jewel_first() -> None:
    profile_a = pz.PriorityProfile(
        finding_id="a", asset_id="asset-a", vulnerability_id="v-a",
        cvss_normalized=0.1, epss_score=0.1, epss_available=True, known_exploited=False, severity_category="LOW",
        path_participation_count=1, max_path_feasibility=1.0, max_path_feasibility_normalized=0.5, avg_path_feasibility=1.0,
        crown_jewel_reachable=True, unique_entry_points=1, unique_crown_jewels=1, min_path_depth=1, max_path_depth=1,
        asset_criticality_normalized=0.1, is_entry_point=False, is_crown_jewel=False, network_zone="app_tier",
        blast_radius_asset_count=0, blast_radius_crown_jewels=0, blast_radius_max_depth=0, blast_radius_min_cost=0.0, blast_radius_max_prob=0.0,
        finding_chokepoint_score=0.0, finding_path_feasibility_criticality=0.0, finding_path_count=1,
        asset_chokepoint_score=0.0, asset_path_feasibility_criticality=0.0, asset_path_count=0,
        remediation_cost=0.0, implementation_complexity=None, downtime_required=False, action_type=None,
    )
    profile_b = profile_a.__class__(**{**profile_a.__dict__, "finding_id": "b", "crown_jewel_reachable": False})
    ka = pz.compute_ordering_keys(profile_a, pz.DEFAULT_POLICY)
    kb = pz.compute_ordering_keys(profile_b, pz.DEFAULT_POLICY)
    assert ka.sort_key() < kb.sort_key()


def test_ordering_kev_tier() -> None:
    base = dict(
        finding_id="a", asset_id="asset-a", vulnerability_id="v-a",
        cvss_normalized=0.5, epss_score=0.5, epss_available=True, severity_category="MEDIUM",
        path_participation_count=0, max_path_feasibility=0.0, max_path_feasibility_normalized=0.0, avg_path_feasibility=0.0,
        crown_jewel_reachable=False, unique_entry_points=0, unique_crown_jewels=0, min_path_depth=0, max_path_depth=0,
        asset_criticality_normalized=0.5, is_entry_point=False, is_crown_jewel=False, network_zone="app_tier",
        blast_radius_asset_count=0, blast_radius_crown_jewels=0, blast_radius_max_depth=0, blast_radius_min_cost=0.0, blast_radius_max_prob=0.0,
        finding_chokepoint_score=0.0, finding_path_feasibility_criticality=0.0, finding_path_count=0,
        asset_chokepoint_score=0.0, asset_path_feasibility_criticality=0.0, asset_path_count=0,
        remediation_cost=0.0, implementation_complexity=None, downtime_required=False, action_type=None,
    )
    non_kev = pz.PriorityProfile(**base, known_exploited=False)
    kev = pz.PriorityProfile(**{**base, "known_exploited": True, "finding_id": "b"})
    assert pz.compute_ordering_keys(kev, pz.DEFAULT_POLICY).sort_key() < pz.compute_ordering_keys(non_kev, pz.DEFAULT_POLICY).sort_key()


def test_ordering_policy_flags_control_tiers() -> None:
    base = dict(
        finding_id="a", asset_id="asset-a", vulnerability_id="v-a",
        cvss_normalized=0.2, epss_score=0.2, epss_available=True, known_exploited=False, severity_category="LOW",
        path_participation_count=0, max_path_feasibility=0.0, max_path_feasibility_normalized=0.0, avg_path_feasibility=0.0,
        crown_jewel_reachable=True, unique_entry_points=True, unique_crown_jewels=1, min_path_depth=1, max_path_depth=1,
        asset_criticality_normalized=0.2, is_entry_point=True, is_crown_jewel=False, network_zone="dmz",
        blast_radius_asset_count=0, blast_radius_crown_jewels=0, blast_radius_max_depth=0, blast_radius_min_cost=0.0, blast_radius_max_prob=0.0,
        finding_chokepoint_score=0.0, finding_path_feasibility_criticality=0.0, finding_path_count=0,
        asset_chokepoint_score=0.0, asset_path_feasibility_criticality=0.0, asset_path_count=0,
        remediation_cost=0.0, implementation_complexity=None, downtime_required=False, action_type=None,
    )
    profile = pz.PriorityProfile(**base)
    disabled = pz.OrderingPolicy(crown_jewel_first=False, entry_point_first=False, kev_tier=False)
    enabled = pz.compute_ordering_keys(profile, pz.DEFAULT_POLICY)
    assert enabled.tiers == (0, 0, 1)
    assert pz.compute_ordering_keys(profile, disabled).tiers == ()


def test_ordering_negative_weights_rejected() -> None:
    with pytest.raises(ValueError):
        pz.OrderingPolicy(cvss_weight=-1.0)


def test_ordering_same_asset_final_finding_id_tiebreaker() -> None:
    base = dict(
        asset_id="same-asset", vulnerability_id="v-a", cvss_normalized=0.5, epss_score=0.5,
        epss_available=True, known_exploited=False, severity_category="MEDIUM",
        path_participation_count=0, max_path_feasibility=0.0, max_path_feasibility_normalized=0.0, avg_path_feasibility=0.0,
        crown_jewel_reachable=False, unique_entry_points=0, unique_crown_jewels=0, min_path_depth=0, max_path_depth=0,
        asset_criticality_normalized=0.5, is_entry_point=False, is_crown_jewel=False, network_zone="app_tier",
        blast_radius_asset_count=0, blast_radius_crown_jewels=0, blast_radius_max_depth=0, blast_radius_min_cost=0.0, blast_radius_max_prob=0.0,
        finding_chokepoint_score=0.0, finding_path_feasibility_criticality=0.0, finding_path_count=0,
        asset_chokepoint_score=0.0, asset_path_feasibility_criticality=0.0, asset_path_count=0,
        remediation_cost=0.0, implementation_complexity=None, downtime_required=False, action_type=None,
    )
    a = pz.PriorityProfile(finding_id="finding-a", **base)
    b = pz.PriorityProfile(finding_id="finding-b", **base)
    policy = pz.OrderingPolicy(tiebreaker="asset_id")
    assert pz.compute_ordering_keys(a, policy).sort_key() < pz.compute_ordering_keys(b, policy).sort_key()


def test_ordering_operational_score_single_source() -> None:
    base = dict(
        finding_id="f", asset_id="a", vulnerability_id="v",
        cvss_normalized=0.7, epss_score=0.6, epss_available=True, known_exploited=False, severity_category="HIGH",
        path_participation_count=1, max_path_feasibility=2.0, max_path_feasibility_normalized=2.0 / 3.0, avg_path_feasibility=2.0,
        crown_jewel_reachable=False, unique_entry_points=1, unique_crown_jewels=0, min_path_depth=1, max_path_depth=2,
        asset_criticality_normalized=0.5, is_entry_point=True, is_crown_jewel=False, network_zone="dmz",
        blast_radius_asset_count=1, blast_radius_crown_jewels=0, blast_radius_max_depth=1, blast_radius_min_cost=2.0, blast_radius_max_prob=0.5,
        finding_chokepoint_score=0.4, finding_path_feasibility_criticality=0.4, finding_path_count=1,
        asset_chokepoint_score=0.2, asset_path_feasibility_criticality=0.2, asset_path_count=1,
        remediation_cost=100.0, implementation_complexity=None, downtime_required=False, action_type=None,
    )
    profile = pz.PriorityProfile(**base)
    keys = pz.compute_ordering_keys(profile, pz.DEFAULT_POLICY)
    assert keys.composite_score == pytest.approx(
        0.4 + (2.0 / 3.0) + 0.7 + (0.6 * 0.5) + (0.5 * 0.5)
    )


def test_weight_sensitivity() -> None:
    base = dict(
        finding_id="f", asset_id="a", vulnerability_id="v",
        cvss_normalized=0.2, epss_score=0.2, epss_available=True, known_exploited=False, severity_category="LOW",
        path_participation_count=1, max_path_feasibility=1.0, max_path_feasibility_normalized=0.5, avg_path_feasibility=1.0,
        crown_jewel_reachable=False, unique_entry_points=0, unique_crown_jewels=0, min_path_depth=1, max_path_depth=1,
        asset_criticality_normalized=0.2, is_entry_point=False, is_crown_jewel=False, network_zone="app_tier",
        blast_radius_asset_count=0, blast_radius_crown_jewels=0, blast_radius_max_depth=0, blast_radius_min_cost=0.0, blast_radius_max_prob=0.0,
        finding_chokepoint_score=0.2, finding_path_feasibility_criticality=0.2, finding_path_count=1,
        asset_chokepoint_score=0.0, asset_path_feasibility_criticality=0.0, asset_path_count=0,
        remediation_cost=0.0, implementation_complexity=None, downtime_required=False, action_type=None,
    )
    profile = pz.PriorityProfile(**base)
    low = pz.compute_ordering_keys(profile, pz.OrderingPolicy(chokepoint_weight=0.5)).composite_score
    high = pz.compute_ordering_keys(profile, pz.OrderingPolicy(chokepoint_weight=2.0)).composite_score
    assert high > low


def test_no_paths_still_profiles(monkeypatch: pytest.MonkeyPatch) -> None:
    graph = make_graph()
    monkeypatch.setattr(pz, "find_attack_paths", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        pz,
        "compute_blast_radius",
        lambda graph, asset_id, max_depth=10: FakeBlastRadiusResult(
            source_asset=asset_id,
            affected_asset_count=0,
            crown_jewels_reached=[],
            max_depth_reached=0,
            reachability_details=[],
        ),
    )
    monkeypatch.setattr(pz, "compute_chokepoints", lambda *args, **kwargs: FakeChokepointResult([]))
    results = pz.compute_prioritization(graph, scenario_id="test")
    assert len(results) == 2
    for result in results:
        assert result.profile.path_participation_count == 0
        assert result.profile.max_path_feasibility_normalized == 0.0


# ----------------------------- API tests -----------------------------


def test_prioritization_api_success() -> None:
    response = client.get("/api/scenarios/basic_test_scenario/prioritization")
    assert response.status_code == 200
    data = response.json()
    assert data["scenario_id"] == "basic_test_scenario"
    assert data["total_findings"] >= 1
    assert isinstance(data["items"], list)


def test_prioritization_api_nonexistent_scenario() -> None:
    response = client.get("/api/scenarios/nonexistent/prioritization")
    assert response.status_code == 404
    assert response.json()["detail"] == "Scenario not found"


def test_prioritization_api_negative_depth() -> None:
    response = client.get(
        "/api/scenarios/basic_test_scenario/prioritization",
        params={"max_depth": -1},
    )
    assert response.status_code == 400
    assert "max_depth must be >= 0" in response.json()["detail"]


def test_prioritization_api_negative_paths() -> None:
    response = client.get(
        "/api/scenarios/basic_test_scenario/prioritization",
        params={"max_paths": -1},
    )
    assert response.status_code == 400
    assert "max_paths must be >= 0" in response.json()["detail"]


def test_prioritization_api_negative_weight() -> None:
    response = client.get(
        "/api/scenarios/basic_test_scenario/prioritization",
        params={"cvss_weight": -1},
    )
    assert response.status_code == 400
    assert "cvss_weight must be >= 0" in response.json()["detail"]


def test_prioritization_api_sort_by() -> None:
    response = client.get(
        "/api/scenarios/basic_test_scenario/prioritization",
        params={"sort_by": "cvss"},
    )
    assert response.status_code == 200
    data = response.json()
    scores = [item["profile"]["cvss_normalized"] for item in data["items"]]
    assert scores == sorted(scores, reverse=True)


def test_prioritization_api_min_operational_score() -> None:
    all_response = client.get(
        "/api/scenarios/basic_test_scenario/prioritization",
        params={"min_operational_score": 0.0},
    )
    assert all_response.status_code == 200
    all_items = all_response.json()["items"]
    if not all_items:
        pytest.skip("No active findings in seed scenario")

    threshold = min(item["operational_score"] for item in all_items)
    filtered = client.get(
        "/api/scenarios/basic_test_scenario/prioritization",
        params={"min_operational_score": threshold},
    )
    assert filtered.status_code == 200
    for item in filtered.json()["items"]:
        assert item["operational_score"] >= threshold


def test_prioritization_api_limit() -> None:
    response = client.get(
        "/api/scenarios/basic_test_scenario/prioritization",
        params={"limit": 1},
    )
    assert response.status_code == 200
    assert len(response.json()["items"]) <= 1


def test_prioritization_api_zero_depth() -> None:
    response = client.get(
        "/api/scenarios/basic_test_scenario/prioritization",
        params={"max_depth": 0},
    )
    assert response.status_code == 200
    for item in response.json()["items"]:
        assert item["profile"]["path_participation_count"] == 0
        assert item["profile"]["max_path_feasibility_normalized"] == 0.0


def test_prioritization_api_response_structure() -> None:
    response = client.get("/api/scenarios/basic_test_scenario/prioritization")
    assert response.status_code == 200
    data = response.json()

    required = {
        "scenario_id",
        "total_findings",
        "returned_findings",
        "max_depth_used",
        "max_paths_used",
        "min_operational_score",
        "sort_by",
        "policy",
        "items",
    }
    assert set(data.keys()) == required

    for item in data["items"]:
        profile = item["profile"]
        assert "finding_id" in profile
        assert 0.0 <= profile["cvss_normalized"] <= 1.0
        assert 0.0 <= profile["max_path_feasibility_normalized"] < 1.0
        assert profile["severity_category"] in {
            "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"
        }
        assert "evidence" in item
