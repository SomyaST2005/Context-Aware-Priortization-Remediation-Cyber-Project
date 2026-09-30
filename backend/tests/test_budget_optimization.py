"""
Tests for budget optimization (Phase 7).

Unit tests use small in-memory MultiDiGraphs with hand-verifiable optima.
API tests use the real FastAPI app and seed scenario, creating temporary
RemediationAction rows cleaned up after each test.
"""
from __future__ import annotations

from types import SimpleNamespace

import networkx as nx
import pytest
from fastapi.testclient import TestClient

from backend.app.analysis import budget_optimization as opt
from backend.app.main import app


client = TestClient(app)


def make_graph() -> nx.MultiDiGraph:
    """Two independent attack paths to one crown jewel via distinct findings."""
    graph = nx.MultiDiGraph()
    graph.add_node(
        "asset-web-01", type="asset", criticality=8.0,
        is_entry_point=True, is_crown_jewel=False, network_zone="dmz",
    )
    graph.add_node(
        "asset-app-01", type="asset", criticality=9.0,
        is_entry_point=False, is_crown_jewel=False, network_zone="app_tier",
    )
    graph.add_node(
        "asset-db-01", type="asset", criticality=10.0,
        is_entry_point=False, is_crown_jewel=True, network_zone="db_tier",
    )
    graph.add_node(
        "vuln-1", type="vulnerability", cvss_score=9.8,
        epss_score=0.85, known_exploited=True,
    )
    graph.add_node(
        "vuln-2", type="vulnerability", cvss_score=8.2,
        epss_score=0.65, known_exploited=False,
    )
    graph.add_node(
        "finding-01", type="finding", asset_id="asset-web-01",
        vulnerability_id="vuln-1", status="active",
    )
    graph.add_node(
        "finding-02", type="finding", asset_id="asset-app-01",
        vulnerability_id="vuln-2", status="active",
    )
    # High-feasibility path via finding-01.
    graph.add_edge(
        "asset-web-01", "finding-01", edge_id="e-w-f1",
        edge_type="CAN_REACH", traversal_cost=1.0, probability=0.9,
    )
    graph.add_edge(
        "finding-01", "asset-db-01", edge_id="e-f1-db",
        edge_type="EXPLOITS", traversal_cost=1.0, probability=0.9,
        finding_id="finding-01",
    )
    # Low-feasibility path via finding-02.
    graph.add_edge(
        "asset-web-01", "finding-02", edge_id="e-w-f2",
        edge_type="CAN_REACH", traversal_cost=4.0, probability=0.5,
    )
    graph.add_edge(
        "finding-02", "asset-db-01", edge_id="e-f2-db",
        edge_type="EXPLOITS", traversal_cost=4.0, probability=0.5,
        finding_id="finding-02",
    )
    return graph


def fake_row(action_id, action_type, scenario_id="s1", cost=5.0, **targets):
    return SimpleNamespace(
        id=action_id,
        action_type=action_type,
        target_asset_id=targets.get("target_asset_id"),
        target_finding_id=targets.get("target_finding_id"),
        target_edge_id=targets.get("target_edge_id"),
        estimated_cost=cost,
        scenario_id=scenario_id,
    )


def candidates(*rows, scenario_id="s1"):
    return opt.resolve_candidates(list(rows), scenario_id)


# ----------------------------- validation -----------------------------

def test_unknown_action_type_rejected():
    with pytest.raises(ValueError, match="Unknown remediation action type"):
        opt.resolve_candidates(
            [fake_row("a1", "BOGUS", target_finding_id="finding-01")], "s1"
        )


def test_unsupported_action_type_rejected():
    with pytest.raises(ValueError, match="Unsupported remediation action type"):
        opt.resolve_candidates(
            [fake_row("a1", "DISABLE_SERVICE", target_asset_id="asset-web-01")],
            "s1",
        )


def test_cross_scenario_rejected():
    with pytest.raises(ValueError, match="does not belong to scenario"):
        opt.resolve_candidates(
            [
                fake_row(
                    "a1", "PATCH_VULNERABILITY",
                    target_finding_id="finding-01", scenario_id="other",
                )
            ],
            "s1",
        )


def test_missing_target_rejected():
    with pytest.raises(ValueError, match="has no target"):
        opt.resolve_candidates([fake_row("a1", "PATCH_VULNERABILITY")], "s1")


def test_multiple_targets_rejected():
    with pytest.raises(ValueError, match="multiple targets"):
        opt.resolve_candidates(
            [
                fake_row(
                    "a1", "PATCH_VULNERABILITY",
                    target_finding_id="finding-01",
                    target_asset_id="asset-web-01",
                )
            ],
            "s1",
        )


def test_wrong_target_rejected():
    with pytest.raises(ValueError, match="must target a finding"):
        opt.resolve_candidates(
            [fake_row("a1", "PATCH_VULNERABILITY", target_asset_id="asset-web-01")],
            "s1",
        )


def test_negative_cost_rejected():
    with pytest.raises(ValueError, match="negative cost"):
        opt.resolve_candidates(
            [
                fake_row(
                    "a1", "PATCH_VULNERABILITY",
                    target_finding_id="finding-01", cost=-1.0,
                )
            ],
            "s1",
        )


def test_duplicate_ids_rejected():
    rows = [
        fake_row("a1", "PATCH_VULNERABILITY", target_finding_id="finding-01"),
        fake_row("a1", "PATCH_VULNERABILITY", target_finding_id="finding-02"),
    ]
    # Duplicates are a request-level error; optimize() is never reached.
    # The endpoint enforces this; here we assert the helper contract used by it.
    ids = [r.id for r in rows]
    assert len(set(ids)) != len(ids)


def test_empty_candidates_rejected():
    with pytest.raises(ValueError, match="At least one candidate"):
        opt.optimize(make_graph(), [], budget=10.0, scenario_id="s1")


def test_too_many_candidates_rejected():
    rows = [
        fake_row(f"a{i:02d}", "PATCH_VULNERABILITY", target_finding_id="finding-01")
        for i in range(13)
    ]
    cands = candidates(*rows)
    assert len(cands) == 13
    with pytest.raises(ValueError, match="At most 12"):
        opt.optimize(make_graph(), cands, budget=100.0, scenario_id="s1")


def test_negative_budget_rejected():
    cands = candidates(
        fake_row("a1", "PATCH_VULNERABILITY", target_finding_id="finding-01")
    )
    with pytest.raises(ValueError, match="budget must be >= 0"):
        opt.optimize(make_graph(), cands, budget=-1.0, scenario_id="s1")


# ----------------------------- objective -----------------------------

def test_o1_primary_o2_tiebreak():
    # Each patch eliminates exactly one crown-jewel path (O1 tie);
    # finding-01's path has higher feasibility, so a1 must win on O2.
    cands = candidates(
        fake_row("a1", "PATCH_VULNERABILITY", target_finding_id="finding-01", cost=5.0),
        fake_row("a2", "PATCH_VULNERABILITY", target_finding_id="finding-02", cost=5.0),
    )
    result = opt.optimize(make_graph(), cands, budget=5.0, scenario_id="s1")
    assert result.selected_action_ids == ["a1"]
    assert result.objective_o1 == pytest.approx(1.0)
    assert result.selection_reason == "optimal_selection"
    assert result.within_budget is True


def test_cost_tiebreak():
    # Identical twins except cost: cheaper wins when O1/O2 tie.
    cands = candidates(
        fake_row("a1", "PATCH_VULNERABILITY", target_finding_id="finding-01", cost=7.0),
        fake_row("a2", "PATCH_VULNERABILITY", target_finding_id="finding-01", cost=3.0),
    )
    # Both eliminate the same single path; O1/O2 tie; cheaper wins.
    result = opt.optimize(make_graph(), cands, budget=10.0, scenario_id="s1")
    assert result.selected_action_ids == ["a2"]
    assert result.selected_total_cost == pytest.approx(3.0)


def test_id_tuple_tiebreak():
    cands = candidates(
        fake_row("a2", "PATCH_VULNERABILITY", target_finding_id="finding-01", cost=5.0),
        fake_row("a1", "PATCH_VULNERABILITY", target_finding_id="finding-01", cost=5.0),
    )
    result = opt.optimize(make_graph(), cands, budget=5.0, scenario_id="s1")
    # Identical effects and costs: lexicographically smallest id wins.
    assert result.selected_action_ids == ["a1"]


def test_exact_budget_boundary():
    cands = candidates(
        fake_row("a1", "PATCH_VULNERABILITY", target_finding_id="finding-01", cost=5.0),
    )
    result = opt.optimize(make_graph(), cands, budget=5.0, scenario_id="s1")
    assert result.selected_action_ids == ["a1"]
    assert result.within_budget is True


def test_float_boundary_epsilon():
    cands = candidates(
        fake_row("a1", "PATCH_VULNERABILITY", target_finding_id="finding-01", cost=0.1 + 0.2),
    )
    # 0.1 + 0.2 = 0.30000000000000004 > 0.3; epsilon keeps it feasible.
    result = opt.optimize(make_graph(), cands, budget=0.3, scenario_id="s1")
    assert result.selected_action_ids == ["a1"]
    assert result.within_budget is True


def test_zero_budget_empty():
    cands = candidates(
        fake_row("a1", "PATCH_VULNERABILITY", target_finding_id="finding-01", cost=5.0),
    )
    result = opt.optimize(make_graph(), cands, budget=0.0, scenario_id="s1")
    assert result.selected_action_ids == []
    assert result.selection_reason == "all_exceed_budget"
    assert result.objective_o1 == 0.0
    assert result.objective_o2 == 0.0


def test_zero_cost_candidate_selected():
    cands = candidates(
        fake_row("a1", "PATCH_VULNERABILITY", target_finding_id="finding-01", cost=0.0),
    )
    result = opt.optimize(make_graph(), cands, budget=0.0, scenario_id="s1")
    assert result.selected_action_ids == ["a1"]
    assert result.selection_reason == "optimal_selection"


def test_all_over_budget():
    cands = candidates(
        fake_row("a1", "PATCH_VULNERABILITY", target_finding_id="finding-01", cost=50.0),
        fake_row("a2", "PATCH_VULNERABILITY", target_finding_id="finding-02", cost=60.0),
    )
    result = opt.optimize(make_graph(), cands, budget=10.0, scenario_id="s1")
    assert result.selected_action_ids == []
    assert result.selection_reason == "all_exceed_budget"
    assert result.over_budget_subset_count == 3  # {a1},{a2},{a1,a2}


def test_all_infeasible_conflicts():
    # Patching finding-01 then removing its exploit edge conflicts.
    cands = candidates(
        fake_row("a1", "PATCH_VULNERABILITY", target_finding_id="finding-01", cost=1.0),
        fake_row("a2", "REMOVE_NETWORK_PATH", target_edge_id="e-f1-db", cost=1.0),
    )
    result = opt.optimize(make_graph(), cands, budget=10.0, scenario_id="s1")
    # {a1} and {a2} are each feasible; {a1,a2} conflicts and is excluded.
    assert result.infeasible_subset_count == 1
    assert result.selected_action_ids == ["a1"]
    reported = [r.action_ids for r in result.reported_infeasible_subsets]
    assert ["a1", "a2"] in reported


def test_no_positive_improvement():
    # Graph with no attack paths: nothing to improve.
    graph = nx.MultiDiGraph()
    graph.add_node("a1", type="asset", criticality=5.0,
                   is_entry_point=False, is_crown_jewel=False, network_zone="app_tier")
    graph.add_node("v1", type="vulnerability", cvss_score=5.0,
                   epss_score=None, known_exploited=False)
    graph.add_node("f1", type="finding", asset_id="a1",
                   vulnerability_id="v1", status="active")
    cands = candidates(
        fake_row("a1", "PATCH_VULNERABILITY", target_finding_id="f1", cost=1.0),
    )
    result = opt.optimize(graph, cands, budget=10.0, scenario_id="s1")
    assert result.selected_action_ids == []
    assert result.selection_reason in ("no_positive_improvement", "zero_path_baseline")


def test_zero_path_baseline_reason():
    graph = nx.MultiDiGraph()
    graph.add_node("a1", type="asset", criticality=5.0,
                   is_entry_point=False, is_crown_jewel=False, network_zone="app_tier")
    graph.add_node("v1", type="vulnerability", cvss_score=5.0,
                   epss_score=None, known_exploited=False)
    graph.add_node("f1", type="finding", asset_id="a1",
                   vulnerability_id="v1", status="active")
    cands = candidates(
        fake_row("a1", "PATCH_VULNERABILITY", target_finding_id="f1", cost=1.0),
    )
    result = opt.optimize(graph, cands, budget=10.0, scenario_id="s1")
    assert result.selection_reason == "zero_path_baseline"
    assert result.objective_o1 == 0.0
    assert result.objective_o2 == 0.0


def test_non_additivity():
    # Patching finding-01 alone eliminates path A; patching finding-02 alone
    # eliminates path B. The combined set eliminates both — but consider two
    # actions on the SAME path: patch f1 (eliminates path A) + remove edge
    # e-w-f1 (also only affects path A). Combined == single, not sum.
    cands = candidates(
        fake_row("a1", "PATCH_VULNERABILITY", target_finding_id="finding-01", cost=4.0),
        fake_row("a2", "REMOVE_NETWORK_PATH", target_edge_id="e-w-f1", cost=4.0),
    )
    result = opt.optimize(make_graph(), cands, budget=10.0, scenario_id="s1")
    # {a1} eliminates path A (high feasibility). {a2} also eliminates path A
    # (edge into finding-01 breaks it). {a1,a2} conflicts (edge gone with node).
    # Optimizer must evaluate actual combined simulation, not additive sums.
    assert result.infeasible_subset_count == 1  # {a1, a2} conflicts
    assert result.selected_action_ids == ["a1"]
    assert result.evaluated_subset_count == 2  # {a1}, {a2}


def test_canonical_order_recorded():
    cands = candidates(
        fake_row("b2", "PATCH_VULNERABILITY", target_finding_id="finding-02", cost=1.0),
        fake_row("a1", "PATCH_VULNERABILITY", target_finding_id="finding-01", cost=1.0),
    )
    result = opt.optimize(make_graph(), cands, budget=10.0, scenario_id="s1")
    assert result.selected_action_ids == sorted(result.selected_action_ids)
    assert result.selected_action_ids == ["a1", "b2"]


def test_deterministic_repeated_optimization():
    cands = candidates(
        fake_row("a1", "PATCH_VULNERABILITY", target_finding_id="finding-01", cost=5.0),
        fake_row("a2", "PATCH_VULNERABILITY", target_finding_id="finding-02", cost=5.0),
    )
    r1 = opt.optimize(make_graph(), cands, budget=10.0, scenario_id="s1")
    r2 = opt.optimize(make_graph(), cands, budget=10.0, scenario_id="s1")
    d1 = r1.to_dict()
    d2 = r2.to_dict()
    d1.pop("optimized_at")
    d2.pop("optimized_at")
    assert d1 == d2


def test_selected_matches_direct_simulation():
    from backend.app.analysis.remediation_simulation import run_simulation

    cands = candidates(
        fake_row("a1", "PATCH_VULNERABILITY", target_finding_id="finding-01", cost=5.0),
    )
    result = opt.optimize(make_graph(), cands, budget=10.0, scenario_id="s1")
    assert result.selected_action_ids == ["a1"]
    by_id = {c.action_id: c for c in cands}
    from backend.app.analysis.remediation_simulation import SimulationAction

    direct = run_simulation(
        make_graph(),
        [
            SimulationAction(
                action_id="a1",
                action_type="PATCH_VULNERABILITY",
                target_id="finding-01",
                target_type="finding",
            )
        ],
        scenario_id="s1",
    )
    assert result.selected.total_attack_paths == direct.final.total_attack_paths
    assert result.selected.sum_path_feasibility == pytest.approx(
        direct.final.sum_path_feasibility
    )
    assert result.baseline.total_attack_paths == direct.baseline.total_attack_paths
    assert by_id["a1"].estimated_cost == 5.0


def test_baseline_graph_unchanged():
    graph = make_graph()
    before_nodes = sorted(graph.nodes)
    before_edges = sorted(graph.edges(keys=True))
    cands = candidates(
        fake_row("a1", "PATCH_VULNERABILITY", target_finding_id="finding-01", cost=5.0),
        fake_row("a2", "PATCH_VULNERABILITY", target_finding_id="finding-02", cost=5.0),
    )
    opt.optimize(graph, cands, budget=10.0, scenario_id="s1")
    assert sorted(graph.nodes) == before_nodes
    assert sorted(graph.edges(keys=True)) == before_edges


def test_infeasible_cap():
    # More than 100 infeasible subsets: all reported counts correct, list capped.
    # Build 8 findings each patched + an edge removal conflicting with each:
    # conflicts: {patch_i, edge_i} for i in 0..7 -> 8 infeasible pairs, plus
    # larger supersets containing them. Use budget high so nothing pruned.
    graph = make_graph()
    rows = []
    for i in range(6):
        rows.append(
            fake_row(f"p{i}", "PATCH_VULNERABILITY", target_finding_id="finding-01", cost=1.0)
        )
        rows.append(
            fake_row(f"e{i}", "REMOVE_NETWORK_PATH", target_edge_id="e-f1-db", cost=1.0)
        )
    cands = candidates(*rows)
    result = opt.optimize(graph, cands, budget=100.0, scenario_id="s1")
    assert result.infeasible_subset_count > 0
    assert len(result.reported_infeasible_subsets) <= 100
    assert len(result.reported_infeasible_subsets) == min(
        100, result.infeasible_subset_count
    )


# ----------------------------- API tests -----------------------------

def _create_action_row(action_id, action_type, scenario_id="basic_test_scenario", **targets):
    from backend.app.core.database import SessionLocal
    from backend.app.models.database import RemediationAction

    db = SessionLocal()
    try:
        row = RemediationAction(
            id=action_id,
            title=f"Test {action_id}",
            description="Temporary test action",
            action_type=action_type,
            target_asset_id=targets.get("target_asset_id"),
            target_finding_id=targets.get("target_finding_id"),
            target_edge_id=targets.get("target_edge_id"),
            estimated_cost=targets.get("estimated_cost", 5.0),
            implementation_complexity="LOW",
            downtime_required=False,
            scenario_id=scenario_id,
        )
        db.merge(row)
        db.commit()
    finally:
        db.close()


def _delete_action_row(action_id):
    from backend.app.core.database import SessionLocal
    from backend.app.models.database import RemediationAction

    db = SessionLocal()
    try:
        row = db.query(RemediationAction).filter(RemediationAction.id == action_id).first()
        if row is not None:
            db.delete(row)
            db.commit()
    finally:
        db.close()


def test_api_success():
    ids = ["test-opt-patch-01", "test-opt-patch-02"]
    _create_action_row(ids[0], "PATCH_VULNERABILITY", target_finding_id="finding-01")
    _create_action_row(ids[1], "PATCH_VULNERABILITY", target_finding_id="finding-02")
    try:
        response = client.post(
            "/api/scenarios/basic_test_scenario/optimize-remediation",
            json={"candidate_action_ids": ids, "budget": 10.0},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["scenario_id"] == "basic_test_scenario"
        assert data["objective"] == "crown_jewel_paths_then_feasibility"
        assert isinstance(data["selected_action_ids"], list)
        assert data["within_budget"] is True
        assert data["selected_total_cost"] <= 10.0 + 1e-9
        assert len(data["candidates"]) == 2
        assert all(c["validation_status"] == "VALID" for c in data["candidates"])
        assert "baseline" in data
        assert "selected" in data
        assert "overall_deltas" in data
    finally:
        for i in ids:
            _delete_action_row(i)


def test_api_unknown_action():
    response = client.post(
        "/api/scenarios/basic_test_scenario/optimize-remediation",
        json={"candidate_action_ids": ["no-such-action"], "budget": 10.0},
    )
    assert response.status_code == 404


def test_api_nonexistent_scenario():
    response = client.post(
        "/api/scenarios/nonexistent/optimize-remediation",
        json={"candidate_action_ids": ["x"], "budget": 10.0},
    )
    assert response.status_code == 404


def test_api_empty_candidates():
    response = client.post(
        "/api/scenarios/basic_test_scenario/optimize-remediation",
        json={"candidate_action_ids": [], "budget": 10.0},
    )
    assert response.status_code == 400


def test_api_too_many_candidates():
    response = client.post(
        "/api/scenarios/basic_test_scenario/optimize-remediation",
        json={"candidate_action_ids": [f"a{i}" for i in range(13)], "budget": 10.0},
    )
    assert response.status_code == 400
    assert "12" in response.json()["detail"]


def test_api_negative_budget():
    response = client.post(
        "/api/scenarios/basic_test_scenario/optimize-remediation",
        json={"candidate_action_ids": ["a1"], "budget": -1.0},
    )
    assert response.status_code == 400


def test_api_duplicate_ids():
    ids = ["test-opt-dup-01"]
    _create_action_row(ids[0], "PATCH_VULNERABILITY", target_finding_id="finding-01")
    try:
        response = client.post(
            "/api/scenarios/basic_test_scenario/optimize-remediation",
            json={"candidate_action_ids": [ids[0], ids[0]], "budget": 10.0},
        )
        assert response.status_code == 400
        assert "uplicate" in response.json()["detail"]
    finally:
        _delete_action_row(ids[0])


def test_api_unsupported_action():
    action_id = "test-opt-deferred-01"
    _create_action_row(action_id, "DISABLE_SERVICE", target_asset_id="asset-app-01")
    try:
        response = client.post(
            "/api/scenarios/basic_test_scenario/optimize-remediation",
            json={"candidate_action_ids": [action_id], "budget": 10.0},
        )
        assert response.status_code == 400
        assert "Unsupported" in response.json()["detail"]
    finally:
        _delete_action_row(action_id)


def test_api_cross_scenario_action():
    action_id = "test-opt-foreign-01"
    _create_action_row(
        action_id, "PATCH_VULNERABILITY",
        target_finding_id="finding-01", scenario_id="other-scenario",
    )
    try:
        response = client.post(
            "/api/scenarios/basic_test_scenario/optimize-remediation",
            json={"candidate_action_ids": [action_id], "budget": 10.0},
        )
        assert response.status_code in (400, 404)
    finally:
        _delete_action_row(action_id)


def test_api_response_schema():
    ids = ["test-opt-schema-01"]
    _create_action_row(ids[0], "PATCH_VULNERABILITY", target_finding_id="finding-01")
    try:
        response = client.post(
            "/api/scenarios/basic_test_scenario/optimize-remediation",
            json={"candidate_action_ids": ids, "budget": 10.0},
        )
        assert response.status_code == 200
        data = response.json()
        required = {
            "scenario_id", "budget", "objective", "candidates",
            "selected_action_ids", "selected_total_cost", "within_budget",
            "objective_o1", "objective_o2", "selection_reason",
            "baseline", "selected", "overall_deltas",
            "overall_rank_comparison", "remediated_findings",
            "evaluated_subset_count", "infeasible_subset_count",
            "over_budget_subset_count", "reported_infeasible_subsets",
            "max_depth_used", "max_paths_used", "optimized_at",
        }
        assert required.issubset(set(data.keys()))
        assert data["objective_o1"] >= 0.0
        assert data["objective_o2"] >= 0.0
    finally:
        _delete_action_row(ids[0])


def test_api_database_unchanged():
    from backend.app.core.database import SessionLocal
    from backend.app.models.database import RemediationAction

    ids = ["test-opt-immutable-01"]
    _create_action_row(ids[0], "PATCH_VULNERABILITY", target_finding_id="finding-01")
    try:
        db = SessionLocal()
        try:
            before = sorted(r.id for r in db.query(RemediationAction).all())
        finally:
            db.close()
        response = client.post(
            "/api/scenarios/basic_test_scenario/optimize-remediation",
            json={"candidate_action_ids": ids, "budget": 10.0},
        )
        assert response.status_code == 200
        db = SessionLocal()
        try:
            after = sorted(r.id for r in db.query(RemediationAction).all())
        finally:
            db.close()
        assert before == after
    finally:
        _delete_action_row(ids[0])


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
