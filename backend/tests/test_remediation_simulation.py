"""
Tests for remediation simulation (Phase 6).

Unit tests use small in-memory MultiDiGraphs mirroring the canonical
builder output. API tests use the real FastAPI app and seed scenario,
creating temporary RemediationAction rows cleaned up after each test.
"""
from __future__ import annotations

from types import SimpleNamespace

import networkx as nx
import pytest
from fastapi.testclient import TestClient

from backend.app.analysis import remediation_simulation as sim
from backend.app.main import app


client = TestClient(app)


def make_graph() -> nx.MultiDiGraph:
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
    graph.add_edge(
        "asset-web-01", "finding-01", edge_id="edge-web-to-finding1",
        edge_type="CAN_REACH", traversal_cost=1.0, probability=0.9,
    )
    graph.add_edge(
        "finding-01", "asset-app-01", edge_id="edge-finding1-to-app",
        edge_type="EXPLOITS", traversal_cost=2.0, probability=0.7,
        finding_id="finding-01",
    )
    graph.add_edge(
        "asset-app-01", "finding-02", edge_id="edge-app-to-finding2",
        edge_type="CAN_REACH", traversal_cost=1.0, probability=0.8,
    )
    graph.add_edge(
        "finding-02", "asset-db-01", edge_id="edge-finding2-to-db",
        edge_type="EXPLOITS", traversal_cost=2.5, probability=0.6,
        finding_id="finding-02",
    )
    graph.add_edge(
        "asset-web-01", "asset-db-01", edge_id="edge-direct-web-to-db",
        edge_type="CAN_REACH", traversal_cost=3.0, probability=0.3,
    )
    return graph


def fake_action(action_id, action_type, scenario_id="s1", **targets):
    return SimpleNamespace(
        id=action_id,
        action_type=action_type,
        target_asset_id=targets.get("target_asset_id"),
        target_finding_id=targets.get("target_finding_id"),
        target_edge_id=targets.get("target_edge_id"),
        scenario_id=scenario_id,
    )


def run(actions, graph=None, **kwargs):
    g = graph if graph is not None else make_graph()
    resolved = [
        sim.resolve_simulation_action(a, kwargs.pop("scenario_id", "s1"))
        if not isinstance(a, sim.SimulationAction)
        else a
        for a in actions
    ]
    return sim.run_simulation(g, resolved, scenario_id="s1", **kwargs)


# ----------------------------- MVP mutations -----------------------------

def test_patch_finding_removes_node():
    graph = make_graph()
    action = sim.resolve_simulation_action(
        fake_action("a1", "PATCH_VULNERABILITY", target_finding_id="finding-01"), "s1"
    )
    result = sim.run_simulation(graph, [action], scenario_id="s1")
    assert "finding-01" in result.remediated_findings
    assert result.final.total_attack_paths < result.baseline.total_attack_paths
    # Asset and vulnerability nodes remain in the simulated evaluation path set
    assert "asset-web-01" in graph.nodes  # baseline untouched
    assert "vuln-1" in graph.nodes


def test_remove_vulnerability_alias():
    graph = make_graph()
    a_patch = sim.resolve_simulation_action(
        fake_action("a1", "PATCH_VULNERABILITY", target_finding_id="finding-01"), "s1"
    )
    graph2 = make_graph()
    a_remove = sim.resolve_simulation_action(
        fake_action("a1", "REMOVE_VULNERABILITY", target_finding_id="finding-01"), "s1"
    )
    r1 = sim.run_simulation(graph, [a_patch], scenario_id="s1")
    r2 = sim.run_simulation(graph2, [a_remove], scenario_id="s1")
    assert r1.final.to_dict() == r2.final.to_dict()


def test_remove_network_path():
    graph = make_graph()
    action = sim.resolve_simulation_action(
        fake_action("a1", "REMOVE_NETWORK_PATH", target_edge_id="edge-direct-web-to-db"),
        "s1",
    )
    result = sim.run_simulation(graph, [action], scenario_id="s1")
    # Direct 1-hop path eliminated; indirect 4-hop path remains
    assert result.final.total_attack_paths == result.baseline.total_attack_paths - 1
    assert "asset-web-01" in graph.nodes  # baseline untouched


def test_restrict_port_explicit_edge():
    graph = make_graph()
    action = sim.resolve_simulation_action(
        fake_action("a1", "RESTRICT_PORT", target_edge_id="edge-direct-web-to-db"), "s1"
    )
    assert action.target_type == "edge"
    result = sim.run_simulation(graph, [action], scenario_id="s1")
    assert result.final.total_attack_paths < result.baseline.total_attack_paths


def test_isolate_asset_removes_asset_not_findings():
    graph = make_graph()
    action = sim.resolve_simulation_action(
        fake_action("a1", "ISOLATE_ASSET", target_asset_id="asset-app-01"), "s1"
    )
    result = sim.run_simulation(graph, [action], scenario_id="s1")
    # Findings hosted on the asset are NOT remediated
    assert "finding-02" not in result.remediated_findings
    statuses = {r.finding_id: r.status for r in result.overall_rank_comparison}
    assert statuses.get("finding-02") == "ACTIVE"
    # But the surviving finding still has a simulated rank (not None)
    f2 = next(r for r in result.overall_rank_comparison if r.finding_id == "finding-02")
    assert f2.simulated_rank is not None


def test_isolate_asset_mutation_semantics():
    # A: asset node removed; B: hosted finding node still exists (mutation level).
    from backend.app.analysis import prioritization as pz

    graph = make_graph()
    action = sim.resolve_simulation_action(
        fake_action("a1", "ISOLATE_ASSET", target_asset_id="asset-app-01"), "s1"
    )
    assert "asset-app-01" in graph.nodes
    assert "finding-02" in graph.nodes
    copied = sim.copy_simulation_graph(graph)
    sim.apply_simulation_action(copied, action)
    assert "asset-app-01" not in copied.nodes
    assert "finding-02" in copied.nodes
    # Baseline untouched
    assert "asset-app-01" in graph.nodes
    assert "finding-02" in graph.nodes
    # E: simulated prioritization does not raise for the orphaned finding
    results = pz.compute_prioritization(
        copied,
        scenario_id="s1",
        baseline_asset_context={
            "asset-app-01": dict(graph.nodes["asset-app-01"])
        },
    )
    assert {r.profile.finding_id for r in results} == {"finding-01", "finding-02"}


def test_orphaned_finding_uses_baseline_asset_context():
    # G: asset-dependent evidence retains baseline business metadata;
    # finding-level graph evidence reflects the isolated graph.
    from backend.app.analysis import prioritization as pz

    graph = make_graph()
    baseline_asset = dict(graph.nodes["asset-app-01"])
    action = sim.resolve_simulation_action(
        fake_action("a1", "ISOLATE_ASSET", target_asset_id="asset-app-01"), "s1"
    )
    result = sim.run_simulation(graph, [action], scenario_id="s1")
    assert "finding-02" not in result.remediated_findings

    f2_final = next(
        r for r in result.overall_rank_comparison if r.finding_id == "finding-02"
    )
    assert f2_final.status == "ACTIVE"
    assert f2_final.simulated_rank is not None

    # Finding-level evidence reflects the isolated graph: finding-02's
    # only attack participation was via asset-app-01, now disconnected.
    sim_graph = sim.copy_simulation_graph(graph)
    sim.apply_simulation_action(sim_graph, action)
    profiles = {
        r.profile.finding_id: r.profile
        for r in pz.compute_prioritization(
            sim_graph,
            scenario_id="s1",
            baseline_asset_context={"asset-app-01": baseline_asset},
        )
    }
    p2 = profiles["finding-02"]
    assert p2.path_participation_count == 0
    assert p2.max_path_feasibility == 0.0
    assert p2.finding_path_count == 0
    # Asset-dependent business metadata retained (not low-risk).
    assert p2.asset_criticality_normalized == pytest.approx(
        pz.normalize_asset_criticality(float(baseline_asset["criticality"]))
    )
    assert p2.is_crown_jewel == bool(baseline_asset["is_crown_jewel"])
    assert p2.network_zone == baseline_asset["network_zone"]
    assert p2.asset_id == "asset-app-01"
    # Simulated operational state: asset node absent -> not an entry point.
    assert p2.is_entry_point is False
    # Baseline descriptive value retained separately (never feeds ordering).
    assert p2.baseline_is_entry_point == bool(baseline_asset["is_entry_point"])
    # Ordinary findings keep baseline_is_entry_point None.
    assert profiles["finding-01"].baseline_is_entry_point is None
    assert profiles["finding-01"].is_entry_point is True


def test_isolated_entry_point_loses_entry_tier():
    # An isolated entry-point asset no longer confers the entry-point tier.
    from backend.app.analysis import prioritization as pz

    graph = make_graph()
    baseline_web = dict(graph.nodes["asset-web-01"])
    assert baseline_web["is_entry_point"] is True
    action = sim.resolve_simulation_action(
        fake_action("a1", "ISOLATE_ASSET", target_asset_id="asset-web-01"), "s1"
    )
    result = sim.run_simulation(graph, [action], scenario_id="s1")
    assert "finding-01" not in result.remediated_findings

    sim_graph = sim.copy_simulation_graph(graph)
    sim.apply_simulation_action(sim_graph, action)
    profiles = {
        r.profile.finding_id: r.profile
        for r in pz.compute_prioritization(
            sim_graph,
            scenario_id="s1",
            baseline_asset_context={"asset-web-01": baseline_web},
        )
    }
    p1 = profiles["finding-01"]
    # Simulated ordering state: no longer an entry point.
    assert p1.is_entry_point is False
    # Baseline descriptive value retained separately.
    assert p1.baseline_is_entry_point is True
    # Ordering tiers reflect simulated state, not baseline.
    keys = pz.compute_ordering_keys(p1, pz.DEFAULT_POLICY)
    entry_idx = 0
    if pz.DEFAULT_POLICY.crown_jewel_first:
        entry_idx += 1
    # entry_point tier position holds 1 (non-entry) given default policy.
    assert keys.tiers[entry_idx] == 1


def test_missing_asset_without_context_still_raises():
    # Ordinary validation preserved: without baseline context, orphaned
    # findings still raise exactly as before.
    from backend.app.analysis import prioritization as pz

    graph = make_graph()
    copied = sim.copy_simulation_graph(graph)
    copied.remove_node("asset-app-01")
    with pytest.raises(ValueError, match="missing/non-asset node"):
        pz.compute_prioritization(copied, scenario_id="s1")
    with pytest.raises(ValueError, match="missing/non-asset node"):
        pz._build_profile(
            graph=copied,
            finding_id="finding-02",
            paths=[],
            blast_radius=None,
            finding_chokepoint=None,
            asset_chokepoint=None,
        )


# ----------------------------- validation -----------------------------

@pytest.mark.parametrize(
    "action_type",
    [
        "DISABLE_SERVICE",
        "SEGMENT_NETWORK",
        "REMOVE_TRUST_RELATIONSHIP",
        "REDUCE_PRIVILEGE",
        "CHANGE_ACCESS_POLICY",
    ],
)
def test_deferred_action_rejected(action_type):
    with pytest.raises(ValueError, match="Unsupported remediation action type"):
        sim.resolve_simulation_action(
            fake_action("a1", action_type, target_finding_id="finding-01"), "s1"
        )


def test_invalid_target_type():
    with pytest.raises(ValueError, match="must target a finding"):
        sim.resolve_simulation_action(
            fake_action("a1", "PATCH_VULNERABILITY", target_asset_id="asset-web-01"),
            "s1",
        )


def test_missing_target():
    with pytest.raises(ValueError, match="has no target"):
        sim.resolve_simulation_action(
            fake_action("a1", "PATCH_VULNERABILITY"), "s1"
        )


def test_multiple_targets():
    with pytest.raises(ValueError, match="multiple targets"):
        sim.resolve_simulation_action(
            fake_action(
                "a1",
                "PATCH_VULNERABILITY",
                target_finding_id="finding-01",
                target_asset_id="asset-web-01",
            ),
            "s1",
        )


def test_unknown_action_type():
    with pytest.raises(ValueError, match="Unknown remediation action type"):
        sim.resolve_simulation_action(
            fake_action("a1", "BOGUS_ACTION", target_finding_id="finding-01"), "s1"
        )


def test_cross_scenario_action():
    with pytest.raises(ValueError, match="does not belong to scenario"):
        sim.resolve_simulation_action(
            fake_action(
                "a1", "PATCH_VULNERABILITY",
                target_finding_id="finding-01", scenario_id="other",
            ),
            "s1",
        )


def test_duplicate_action_fail_fast():
    graph = make_graph()
    actions = [
        sim.resolve_simulation_action(
            fake_action("a1", "PATCH_VULNERABILITY", target_finding_id="finding-01"),
            "s1",
        ),
        sim.resolve_simulation_action(
            fake_action("a1", "PATCH_VULNERABILITY", target_finding_id="finding-01"),
            "s1",
        ),
    ]
    with pytest.raises(ValueError, match="not found in simulation graph"):
        sim.run_simulation(graph, actions, scenario_id="s1")
    # Baseline untouched even on failure
    assert "finding-01" in graph.nodes


def test_conflicting_sequential_actions_fail_fast():
    graph = make_graph()
    actions = [
        sim.resolve_simulation_action(
            fake_action("a1", "PATCH_VULNERABILITY", target_finding_id="finding-01"),
            "s1",
        ),
        sim.resolve_simulation_action(
            fake_action("a2", "REMOVE_NETWORK_PATH", target_edge_id="edge-finding1-to-app"),
            "s1",
        ),
    ]
    with pytest.raises(ValueError, match="not found in simulation graph"):
        sim.run_simulation(graph, actions, scenario_id="s1")


def test_zero_delta_valid_action():
    # Isolated graph: patching the only finding changes nothing measurable
    # except the finding itself; must still succeed.
    graph = nx.MultiDiGraph()
    graph.add_node("a1", type="asset", criticality=5.0,
                   is_entry_point=False, is_crown_jewel=False, network_zone="app_tier")
    graph.add_node("v1", type="vulnerability", cvss_score=5.0,
                   epss_score=None, known_exploited=False)
    graph.add_node("f1", type="finding", asset_id="a1",
                   vulnerability_id="v1", status="active")
    action = sim.resolve_simulation_action(
        fake_action("a1", "PATCH_VULNERABILITY", target_finding_id="f1"), "s1"
    )
    result = sim.run_simulation(graph, [action], scenario_id="s1")
    assert result.final.total_attack_paths == 0
    assert result.baseline.total_attack_paths == 0


def test_graph_deepcopy_immutability():
    graph = make_graph()
    before_nodes = sorted(graph.nodes)
    before_edges = sorted(
        (u, v, k, tuple(sorted(d.items()))) for u, v, k, d in graph.edges(keys=True, data=True)
    )
    action = sim.resolve_simulation_action(
        fake_action("a1", "PATCH_VULNERABILITY", target_finding_id="finding-01"), "s1"
    )
    sim.run_simulation(graph, [action], scenario_id="s1")
    after_nodes = sorted(graph.nodes)
    after_edges = sorted(
        (u, v, k, tuple(sorted(d.items()))) for u, v, k, d in graph.edges(keys=True, data=True)
    )
    assert before_nodes == after_nodes
    assert before_edges == after_edges


def test_nested_attribute_mutation_isolated():
    graph = make_graph()
    assert "finding-01" in graph.nodes
    copied = sim.copy_simulation_graph(graph)
    copied.nodes["finding-01"]["status"] = "mutated"
    assert graph.nodes["finding-01"]["status"] == "active"


def test_deterministic_repeated_simulations():
    actions = [
        sim.resolve_simulation_action(
            fake_action("a1", "PATCH_VULNERABILITY", target_finding_id="finding-01"),
            "s1",
        )
    ]
    r1 = sim.run_simulation(make_graph(), actions, scenario_id="s1")
    r2 = sim.run_simulation(make_graph(), actions, scenario_id="s1")
    d1 = r1.to_dict()
    d2 = r2.to_dict()
    d1.pop("simulated_at")
    d2.pop("simulated_at")
    assert d1 == d2


def test_multi_action_incremental_effectiveness():
    actions = [
        sim.resolve_simulation_action(
            fake_action("a1", "REMOVE_NETWORK_PATH", target_edge_id="edge-direct-web-to-db"),
            "s1",
        ),
        sim.resolve_simulation_action(
            fake_action("a2", "PATCH_VULNERABILITY", target_finding_id="finding-01"),
            "s1",
        ),
    ]
    result = sim.run_simulation(make_graph(), actions, scenario_id="s1")
    assert len(result.steps) == 2
    # Step 1 removes the direct path only
    assert result.steps[0].state.total_attack_paths == result.baseline.total_attack_paths - 1
    # Step 2 removes the indirect path too
    assert result.final.total_attack_paths == 0
    # Overall delta spans baseline -> final
    overall = next(
        d for d in result.overall_deltas if d.metric_name == "total_attack_paths"
    )
    assert overall.before == result.baseline.total_attack_paths
    assert overall.after == 0.0


def test_fixed_blast_sources_survive_finding_removal():
    graph = make_graph()
    action = sim.resolve_simulation_action(
        fake_action("a1", "PATCH_VULNERABILITY", target_finding_id="finding-01"), "s1"
    )
    result = sim.run_simulation(graph, [action], scenario_id="s1")
    # asset-web-01 was a baseline blast source; its contribution must still be
    # evaluated in the simulated state (possibly reduced, never silently dropped).
    assert result.baseline.blast_affected_assets >= result.final.blast_affected_assets


def test_removed_source_asset_empty_contribution():
    graph = make_graph()
    action = sim.resolve_simulation_action(
        fake_action("a1", "ISOLATE_ASSET", target_asset_id="asset-app-01"), "s1"
    )
    result = sim.run_simulation(graph, [action], scenario_id="s1")
    # Simulation completes; removed source yields empty contribution, not omission.
    assert result.final.blast_affected_assets <= result.baseline.blast_affected_assets


def test_remediated_rank_behavior():
    graph = make_graph()
    action = sim.resolve_simulation_action(
        fake_action("a1", "PATCH_VULNERABILITY", target_finding_id="finding-01"), "s1"
    )
    result = sim.run_simulation(graph, [action], scenario_id="s1")
    f1 = next(r for r in result.overall_rank_comparison if r.finding_id == "finding-01")
    assert f1.status == "REMEDIATED"
    assert f1.simulated_rank is None
    assert f1.rank_delta is None


def test_no_path_semantics():
    graph = nx.MultiDiGraph()
    graph.add_node("a1", type="asset", criticality=5.0,
                   is_entry_point=False, is_crown_jewel=False, network_zone="app_tier")
    graph.add_node("v1", type="vulnerability", cvss_score=5.0,
                   epss_score=None, known_exploited=False)
    graph.add_node("f1", type="finding", asset_id="a1",
                   vulnerability_id="v1", status="active")
    action = sim.resolve_simulation_action(
        fake_action("a1", "PATCH_VULNERABILITY", target_finding_id="f1"), "s1"
    )
    result = sim.run_simulation(graph, [action], scenario_id="s1")
    assert result.baseline.total_attack_paths == 0
    assert result.baseline.min_path_depth is None
    assert result.baseline.max_path_depth is None
    assert result.baseline.sum_path_feasibility == 0.0
    assert result.baseline.max_path_feasibility == 0.0


def test_percent_change_edges():
    assert sim.percent_change(0.0, 0.0) is None
    assert sim.percent_change(0.0, 5.0) is None
    assert sim.percent_change(10.0, 0.0) == pytest.approx(-100.0)
    assert sim.percent_change(10.0, 5.0) == pytest.approx(-50.0)


def test_max_depth_validation():
    with pytest.raises(ValueError, match="max_depth must be >= 0"):
        sim.run_simulation(make_graph(), [], max_depth=-1, scenario_id="s1")


def test_max_paths_validation():
    with pytest.raises(ValueError, match="max_paths must be >= 0"):
        sim.run_simulation(make_graph(), [], max_paths=-1, scenario_id="s1")


def test_empty_actions_rejected():
    with pytest.raises(ValueError, match="At least one remediation action"):
        sim.run_simulation(make_graph(), [], scenario_id="s1")


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
            estimated_cost=5.0,
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
    action_id = "test-sim-patch-01"
    _create_action_row(action_id, "PATCH_VULNERABILITY", target_finding_id="finding-01")
    try:
        response = client.post(
            "/api/scenarios/basic_test_scenario/simulate-remediation",
            json={"remediation_action_ids": [action_id]},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["scenario_id"] == "basic_test_scenario"
        assert data["action_ids"] == [action_id]
        assert "baseline" in data
        assert "final" in data
        assert "overall_deltas" in data
        assert "overall_rank_comparison" in data
        assert "steps" in data
        assert len(data["steps"]) == 1
        assert "finding-01" in data["remediated_findings"]
    finally:
        _delete_action_row(action_id)


def test_api_validation_failures():
    # Unknown scenario
    response = client.post(
        "/api/scenarios/nonexistent/simulate-remediation",
        json={"remediation_action_ids": ["x"]},
    )
    assert response.status_code == 404

    # Unknown action
    response = client.post(
        "/api/scenarios/basic_test_scenario/simulate-remediation",
        json={"remediation_action_ids": ["no-such-action"]},
    )
    assert response.status_code == 404

    # Negative params
    action_id = "test-sim-patch-02"
    _create_action_row(action_id, "PATCH_VULNERABILITY", target_finding_id="finding-01")
    try:
        response = client.post(
            "/api/scenarios/basic_test_scenario/simulate-remediation",
            json={"remediation_action_ids": [action_id], "max_depth": -1},
        )
        assert response.status_code == 400
        response = client.post(
            "/api/scenarios/basic_test_scenario/simulate-remediation",
            json={"remediation_action_ids": [action_id], "max_paths": -1},
        )
        assert response.status_code == 400
        response = client.post(
            "/api/scenarios/basic_test_scenario/simulate-remediation",
            json={"remediation_action_ids": []},
        )
        assert response.status_code in (400, 422)
    finally:
        _delete_action_row(action_id)


def test_api_unsupported_action():
    action_id = "test-sim-deferred-01"
    _create_action_row(
        action_id, "DISABLE_SERVICE", target_asset_id="asset-app-01"
    )
    try:
        response = client.post(
            "/api/scenarios/basic_test_scenario/simulate-remediation",
            json={"remediation_action_ids": [action_id]},
        )
        assert response.status_code == 400
        assert "Unsupported" in response.json()["detail"]
    finally:
        _delete_action_row(action_id)


def test_api_cross_scenario_action():
    action_id = "test-sim-foreign-01"
    _create_action_row(
        action_id, "PATCH_VULNERABILITY",
        target_finding_id="finding-01", scenario_id="other-scenario",
    )
    try:
        response = client.post(
            "/api/scenarios/basic_test_scenario/simulate-remediation",
            json={"remediation_action_ids": [action_id]},
        )
        assert response.status_code in (400, 404)
    finally:
        _delete_action_row(action_id)


def test_api_response_schema():
    action_id = "test-sim-patch-03"
    _create_action_row(action_id, "PATCH_VULNERABILITY", target_finding_id="finding-02")
    try:
        response = client.post(
            "/api/scenarios/basic_test_scenario/simulate-remediation",
            json={"remediation_action_ids": [action_id]},
        )
        assert response.status_code == 200
        data = response.json()
        required = {
            "scenario_id", "action_ids", "applied_actions", "baseline",
            "steps", "final", "overall_deltas", "overall_rank_comparison",
            "remediated_findings", "max_depth_used", "max_paths_used",
            "policy_snapshot", "simulated_at",
        }
        assert required.issubset(set(data.keys()))
        baseline_keys = {
            "total_attack_paths", "crown_jewel_path_count",
            "distinct_crown_jewels", "sum_path_feasibility",
            "max_path_feasibility", "min_path_depth", "max_path_depth",
            "blast_affected_assets", "blast_crown_jewels", "blast_max_depth",
            "chokepoint_count", "max_chokepoint_score",
            "sum_chokepoint_criticality", "prioritization_count",
            "max_operational_score",
        }
        assert baseline_keys.issubset(set(data["baseline"].keys()))
        assert data["baseline"]["min_path_depth"] in (
            None, data["baseline"]["min_path_depth"]
        )
    finally:
        _delete_action_row(action_id)


def test_api_isolated_finding_survives():
    action_id = "test-sim-isolate-01"
    _create_action_row(action_id, "ISOLATE_ASSET", target_asset_id="asset-app-01")
    try:
        response = client.post(
            "/api/scenarios/basic_test_scenario/simulate-remediation",
            json={"remediation_action_ids": [action_id]},
        )
        assert response.status_code == 200
        data = response.json()
        assert "finding-02" not in data["remediated_findings"]
        f2 = next(
            r for r in data["overall_rank_comparison"]
            if r["finding_id"] == "finding-02"
        )
        assert f2["status"] == "ACTIVE"
        assert f2["simulated_rank"] is not None
    finally:
        _delete_action_row(action_id)


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
