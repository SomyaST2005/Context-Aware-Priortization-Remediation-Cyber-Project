"""
Remediation simulation analysis.

Deterministic what-if simulation: copy a baseline canonical graph,
apply remediation actions sequentially to the copy, re-run the existing
analysis pipeline, and compare baseline vs simulated state.

The baseline graph and database are never mutated.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Tuple

import networkx as nx

from backend.app.analysis.blast_radius import BlastRadiusResult, compute_blast_radius
from backend.app.analysis.chokepoint import compute_chokepoints
from backend.app.analysis.path_analysis import find_attack_paths
from backend.app.analysis.prioritization import (
    DEFAULT_POLICY,
    OrderingPolicy,
    compute_prioritization,
    path_feasibility,
)


EPSILON = 1e-9

TargetType = Literal["finding", "asset", "edge"]

MVP_ACTION_TYPES = (
    "PATCH_VULNERABILITY",
    "REMOVE_VULNERABILITY",
    "REMOVE_NETWORK_PATH",
    "RESTRICT_PORT",
    "ISOLATE_ASSET",
)

DEFERRED_ACTION_TYPES = (
    "DISABLE_SERVICE",
    "SEGMENT_NETWORK",
    "REMOVE_TRUST_RELATIONSHIP",
    "REDUCE_PRIVILEGE",
    "CHANGE_ACCESS_POLICY",
)


def _enum_value(value: Any) -> Any:
    """Return an enum's value when present, otherwise the original value."""
    return getattr(value, "value", value)


@dataclass(frozen=True)
class SimulationAction:
    """Validated, simulation-ready remediation action."""

    action_id: str
    action_type: str
    target_id: str
    target_type: TargetType


def resolve_simulation_action(action_row: Any, scenario_id: str) -> SimulationAction:
    """Validate a RemediationAction DB record and resolve its simulation target.

    Raises:
        ValueError: on unknown/unsupported/cross-scenario/mistargeted actions.
    """
    action_id = str(getattr(action_row, "id"))
    action_type = str(_enum_value(getattr(action_row, "action_type")))
    row_scenario = getattr(action_row, "scenario_id", None)
    if row_scenario is not None and str(row_scenario) != str(scenario_id):
        raise ValueError(
            f"Remediation action '{action_id}' does not belong to scenario '{scenario_id}'"
        )

    if action_type in DEFERRED_ACTION_TYPES:
        raise ValueError(f"Unsupported remediation action type: {action_type}")
    if action_type not in MVP_ACTION_TYPES:
        raise ValueError(f"Unknown remediation action type: {action_type}")

    target_asset = getattr(action_row, "target_asset_id", None)
    target_finding = getattr(action_row, "target_finding_id", None)
    target_edge = getattr(action_row, "target_edge_id", None)
    populated = [
        name
        for name, value in (
            ("target_asset_id", target_asset),
            ("target_finding_id", target_finding),
            ("target_edge_id", target_edge),
        )
        if value is not None
    ]
    if len(populated) == 0:
        raise ValueError(f"Remediation action '{action_id}' has no target")
    if len(populated) > 1:
        raise ValueError(
            f"Remediation action '{action_id}' has multiple targets: {', '.join(populated)}"
        )

    if action_type in ("PATCH_VULNERABILITY", "REMOVE_VULNERABILITY"):
        if target_finding is None:
            raise ValueError(
                f"Remediation action '{action_id}' of type {action_type} "
                "must target a finding (target_finding_id)"
            )
        return SimulationAction(
            action_id=action_id,
            action_type=action_type,
            target_id=str(target_finding),
            target_type="finding",
        )
    if action_type in ("REMOVE_NETWORK_PATH", "RESTRICT_PORT"):
        if target_edge is None:
            raise ValueError(
                f"Remediation action '{action_id}' of type {action_type} "
                "must target an edge (target_edge_id)"
            )
        return SimulationAction(
            action_id=action_id,
            action_type=action_type,
            target_id=str(target_edge),
            target_type="edge",
        )
    # ISOLATE_ASSET
    if target_asset is None:
        raise ValueError(
            f"Remediation action '{action_id}' of type {action_type} "
            "must target an asset (target_asset_id)"
        )
    return SimulationAction(
        action_id=action_id,
        action_type=action_type,
        target_id=str(target_asset),
        target_type="asset",
    )


def copy_simulation_graph(baseline_graph: nx.MultiDiGraph) -> nx.MultiDiGraph:
    """Deep-copy the baseline graph so simulation never mutates it."""
    return copy.deepcopy(baseline_graph)


def apply_simulation_action(graph: nx.MultiDiGraph, action: SimulationAction) -> None:
    """Apply one validated action to the simulation graph in place.

    Raises:
        ValueError: if the target is missing or of the wrong node type.
    """
    if action.target_type == "finding":
        if action.target_id not in graph.nodes:
            raise ValueError(
                f"Action '{action.action_id}' target finding "
                f"'{action.target_id}' not found in simulation graph"
            )
        if graph.nodes[action.target_id].get("type") != "finding":
            raise ValueError(
                f"Action '{action.action_id}' target '{action.target_id}' "
                "is not a finding node"
            )
        graph.remove_node(action.target_id)
        return

    if action.target_type == "asset":
        if action.target_id not in graph.nodes:
            raise ValueError(
                f"Action '{action.action_id}' target asset "
                f"'{action.target_id}' not found in simulation graph"
            )
        if graph.nodes[action.target_id].get("type") != "asset":
            raise ValueError(
                f"Action '{action.action_id}' target '{action.target_id}' "
                "is not an asset node"
            )
        # Findings hosted on the asset remain as graph nodes; they are NOT
        # classified as REMEDIATED. Only their incident edges disappear.
        graph.remove_node(action.target_id)
        return

    # Edge target: resolve by Edge.id stored in the edge_id attribute.
    matches: List[Tuple[str, str, Any]] = []
    for u, v, key, data in graph.edges(keys=True, data=True):
        if data.get("edge_id") == action.target_id:
            matches.append((u, v, key))
    if not matches:
        raise ValueError(
            f"Action '{action.action_id}' target edge "
            f"'{action.target_id}' not found in simulation graph"
        )
    for u, v, key in matches:
        graph.remove_edge(u, v, key)


def percent_change(before: float, after: float) -> Optional[float]:
    """Percent change with explicit undefined-value semantics."""
    if before == 0.0 and after == 0.0:
        return None
    if before == 0.0:
        return None
    return (after - before) / before * 100.0


@dataclass
class MetricDelta:
    metric_name: str
    before: Optional[float]
    after: Optional[float]
    absolute_delta: Optional[float]
    percent_change: Optional[float]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metric_name": self.metric_name,
            "before": self.before,
            "after": self.after,
            "absolute_delta": self.absolute_delta,
            "percent_change": self.percent_change,
        }


def _numeric_delta(name: str, before: float, after: float) -> MetricDelta:
    return MetricDelta(
        metric_name=name,
        before=float(before),
        after=float(after),
        absolute_delta=float(after - before),
        percent_change=percent_change(float(before), float(after)),
    )


def _optional_int_delta(
    name: str, before: Optional[int], after: Optional[int]
) -> MetricDelta:
    if before is None or after is None:
        return MetricDelta(
            metric_name=name,
            before=float(before) if before is not None else None,
            after=float(after) if after is not None else None,
            absolute_delta=None,
            percent_change=None,
        )
    return _numeric_delta(name, float(before), float(after))


@dataclass
class FindingRankComparison:
    finding_id: str
    asset_id: str
    status: Literal["ACTIVE", "REMEDIATED"]
    baseline_rank: Optional[int]
    simulated_rank: Optional[int]
    rank_delta: Optional[int]
    baseline_operational_score: Optional[float]
    simulated_operational_score: Optional[float]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "asset_id": self.asset_id,
            "status": self.status,
            "baseline_rank": self.baseline_rank,
            "simulated_rank": self.simulated_rank,
            "rank_delta": self.rank_delta,
            "baseline_operational_score": self.baseline_operational_score,
            "simulated_operational_score": self.simulated_operational_score,
        }


@dataclass
class StateSummary:
    total_attack_paths: int
    crown_jewel_path_count: int
    distinct_crown_jewels: int
    sum_path_feasibility: float
    max_path_feasibility: float
    min_path_depth: Optional[int]
    max_path_depth: Optional[int]
    blast_affected_assets: int
    blast_crown_jewels: int
    blast_max_depth: int
    chokepoint_count: int
    max_chokepoint_score: float
    sum_chokepoint_criticality: float
    prioritization_count: int
    max_operational_score: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_attack_paths": self.total_attack_paths,
            "crown_jewel_path_count": self.crown_jewel_path_count,
            "distinct_crown_jewels": self.distinct_crown_jewels,
            "sum_path_feasibility": self.sum_path_feasibility,
            "max_path_feasibility": self.max_path_feasibility,
            "min_path_depth": self.min_path_depth,
            "max_path_depth": self.max_path_depth,
            "blast_affected_assets": self.blast_affected_assets,
            "blast_crown_jewels": self.blast_crown_jewels,
            "blast_max_depth": self.blast_max_depth,
            "chokepoint_count": self.chokepoint_count,
            "max_chokepoint_score": self.max_chokepoint_score,
            "sum_chokepoint_criticality": self.sum_chokepoint_criticality,
            "prioritization_count": self.prioritization_count,
            "max_operational_score": self.max_operational_score,
        }


@dataclass
class StepResult:
    action: SimulationAction
    state: StateSummary
    incremental_deltas: List[MetricDelta]
    incremental_rank_comparison: List[FindingRankComparison]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": {
                "action_id": self.action.action_id,
                "action_type": self.action.action_type,
                "target_id": self.action.target_id,
                "target_type": self.action.target_type,
            },
            "state": self.state.to_dict(),
            "incremental_deltas": [d.to_dict() for d in self.incremental_deltas],
            "incremental_rank_comparison": [
                r.to_dict() for r in self.incremental_rank_comparison
            ],
        }


@dataclass
class SimulationResult:
    scenario_id: str
    action_ids: List[str]
    applied_actions: List[SimulationAction]
    baseline: StateSummary
    steps: List[StepResult]
    final: StateSummary
    overall_deltas: List[MetricDelta]
    overall_rank_comparison: List[FindingRankComparison]
    remediated_findings: List[str]
    max_depth_used: int
    max_paths_used: int
    policy_snapshot: Dict[str, Any]
    simulated_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "action_ids": list(self.action_ids),
            "applied_actions": [
                {
                    "action_id": a.action_id,
                    "action_type": a.action_type,
                    "target_id": a.target_id,
                    "target_type": a.target_type,
                }
                for a in self.applied_actions
            ],
            "baseline": self.baseline.to_dict(),
            "steps": [s.to_dict() for s in self.steps],
            "final": self.final.to_dict(),
            "overall_deltas": [d.to_dict() for d in self.overall_deltas],
            "overall_rank_comparison": [
                r.to_dict() for r in self.overall_rank_comparison
            ],
            "remediated_findings": sorted(self.remediated_findings),
            "max_depth_used": self.max_depth_used,
            "max_paths_used": self.max_paths_used,
            "policy_snapshot": dict(self.policy_snapshot),
            "simulated_at": self.simulated_at,
        }


def _summarize_paths(paths: List[Any]) -> Dict[str, Any]:
    feasibilities = [
        path_feasibility(p.total_probability, p.total_traversal_cost) for p in paths
    ]
    if not paths:
        return {
            "total": 0,
            "crown_jewel_count": 0,
            "distinct_crown_jewels": 0,
            "sum_feasibility": 0.0,
            "max_feasibility": 0.0,
            "min_depth": None,
            "max_depth": None,
        }
    return {
        "total": len(paths),
        "crown_jewel_count": len(paths),
        "distinct_crown_jewels": len({str(p.crown_jewel) for p in paths}),
        "sum_feasibility": float(sum(feasibilities)),
        "max_feasibility": float(max(feasibilities)),
        "min_depth": min(int(p.hop_count) for p in paths),
        "max_depth": max(int(p.hop_count) for p in paths),
    }


def _empty_blast() -> Dict[str, Any]:
    return {
        "affected_asset_count": 0,
        "crown_jewels_reached": 0,
        "max_depth_reached": 0,
    }


def evaluate_state(
    graph: nx.MultiDiGraph,
    *,
    blast_sources: List[str],
    max_depth: int,
    max_paths: int,
    policy: OrderingPolicy,
    scenario_id: str,
    baseline_asset_context: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Tuple[StateSummary, Dict[str, Any]]:
    """Run the full reused analysis pipeline on one graph state.

    Returns the serializable summary plus raw rank/score maps used for
    prioritization comparison.

    baseline_asset_context optionally carries baseline asset node attributes
    so surviving findings whose asset was removed (e.g. ISOLATE_ASSET) can
    still be profiled with explicit baseline business metadata.
    """
    paths = find_attack_paths(graph, max_depth=max_depth, max_paths=max_paths)
    path_info = _summarize_paths(paths)

    blast_affected = 0
    blast_crowns: set[str] = set()
    blast_max_depth = 0
    for source in blast_sources:
        if source in graph.nodes and graph.nodes[source].get("type") == "asset":
            result = compute_blast_radius(graph, source, max_depth=max_depth)
        else:
            result = BlastRadiusResult(
                source_asset=source,
                affected_assets=[],
                affected_asset_count=0,
                crown_jewels_reached=[],
                max_depth_reached=0,
                reachability_details=[],
            )
        blast_affected += int(result.affected_asset_count)
        blast_crowns.update(str(c) for c in result.crown_jewels_reached)
        blast_max_depth = max(blast_max_depth, int(result.max_depth_reached))

    chokepoints = compute_chokepoints(graph, max_depth=max_depth, max_paths=max_paths)
    choke_details = list(chokepoints.chokepoints)
    sum_choke = float(
        sum(float(d.path_feasibility_criticality) for d in choke_details)
    )
    max_choke = float(chokepoints.max_chokepoint_score) if choke_details else 0.0

    prioritization = compute_prioritization(
        graph,
        max_depth=max_depth,
        max_paths=max_paths,
        policy=policy,
        scenario_id=scenario_id,
        baseline_asset_context=baseline_asset_context,
    )
    rank_map = {
        str(r.profile.finding_id): (
            int(r.operational_rank),
            float(r.operational_score),
            str(r.profile.asset_id),
        )
        for r in prioritization
    }
    max_op = max((float(r.operational_score) for r in prioritization), default=0.0)

    summary = StateSummary(
        total_attack_paths=int(path_info["total"]),
        crown_jewel_path_count=int(path_info["crown_jewel_count"]),
        distinct_crown_jewels=int(path_info["distinct_crown_jewels"]),
        sum_path_feasibility=float(path_info["sum_feasibility"]),
        max_path_feasibility=float(path_info["max_feasibility"]),
        min_path_depth=path_info["min_depth"],
        max_path_depth=path_info["max_depth"],
        blast_affected_assets=int(blast_affected),
        blast_crown_jewels=int(len(blast_crowns)),
        blast_max_depth=int(blast_max_depth),
        chokepoint_count=int(len(choke_details)),
        max_chokepoint_score=max_choke,
        sum_chokepoint_criticality=sum_choke,
        prioritization_count=int(len(prioritization)),
        max_operational_score=float(max_op),
    )
    return summary, rank_map


def compare_summaries(before: StateSummary, after: StateSummary) -> List[MetricDelta]:
    """Overall/incremental deltas between two state summaries."""
    deltas = [
        _numeric_delta(
            "total_attack_paths",
            float(before.total_attack_paths),
            float(after.total_attack_paths),
        ),
        _numeric_delta(
            "crown_jewel_path_count",
            float(before.crown_jewel_path_count),
            float(after.crown_jewel_path_count),
        ),
        _numeric_delta(
            "distinct_crown_jewels",
            float(before.distinct_crown_jewels),
            float(after.distinct_crown_jewels),
        ),
        _numeric_delta(
            "sum_path_feasibility",
            float(before.sum_path_feasibility),
            float(after.sum_path_feasibility),
        ),
        _numeric_delta(
            "max_path_feasibility",
            float(before.max_path_feasibility),
            float(after.max_path_feasibility),
        ),
        _optional_int_delta(
            "min_path_depth", before.min_path_depth, after.min_path_depth
        ),
        _optional_int_delta(
            "max_path_depth", before.max_path_depth, after.max_path_depth
        ),
        _numeric_delta(
            "blast_affected_assets",
            float(before.blast_affected_assets),
            float(after.blast_affected_assets),
        ),
        _numeric_delta(
            "blast_crown_jewels",
            float(before.blast_crown_jewels),
            float(after.blast_crown_jewels),
        ),
        _numeric_delta(
            "blast_max_depth",
            float(before.blast_max_depth),
            float(after.blast_max_depth),
        ),
        _numeric_delta(
            "chokepoint_count",
            float(before.chokepoint_count),
            float(after.chokepoint_count),
        ),
        _numeric_delta(
            "max_chokepoint_score",
            float(before.max_chokepoint_score),
            float(after.max_chokepoint_score),
        ),
        _numeric_delta(
            "sum_chokepoint_criticality",
            float(before.sum_chokepoint_criticality),
            float(after.sum_chokepoint_criticality),
        ),
        _numeric_delta(
            "prioritization_count",
            float(before.prioritization_count),
            float(after.prioritization_count),
        ),
        _numeric_delta(
            "max_operational_score",
            float(before.max_operational_score),
            float(after.max_operational_score),
        ),
    ]
    return deltas


def compare_ranks(
    before_ranks: Dict[str, Tuple[int, float, str]],
    after_ranks: Dict[str, Tuple[int, float, str]],
    removed_findings: set[str],
) -> List[FindingRankComparison]:
    """Rank comparison with explicit REMEDIATED status for removed findings."""
    comparisons: List[FindingRankComparison] = []
    for finding_id in sorted(set(before_ranks) | set(after_ranks) | removed_findings):
        if finding_id in removed_findings:
            baseline = before_ranks.get(finding_id)
            comparisons.append(
                FindingRankComparison(
                    finding_id=finding_id,
                    asset_id=baseline[2] if baseline else "",
                    status="REMEDIATED",
                    baseline_rank=baseline[0] if baseline else None,
                    simulated_rank=None,
                    rank_delta=None,
                    baseline_operational_score=baseline[1] if baseline else None,
                    simulated_operational_score=None,
                )
            )
            continue
        if finding_id in before_ranks and finding_id in after_ranks:
            b_rank, b_score, asset_id = before_ranks[finding_id]
            a_rank, a_score, _ = after_ranks[finding_id]
            comparisons.append(
                FindingRankComparison(
                    finding_id=finding_id,
                    asset_id=asset_id,
                    status="ACTIVE",
                    baseline_rank=b_rank,
                    simulated_rank=a_rank,
                    rank_delta=int(b_rank - a_rank),
                    baseline_operational_score=float(b_score),
                    simulated_operational_score=float(a_score),
                )
            )
    comparisons.sort(key=lambda r: r.finding_id)
    return comparisons


def _policy_snapshot(policy: OrderingPolicy) -> Dict[str, Any]:
    return {
        "crown_jewel_first": bool(policy.crown_jewel_first),
        "entry_point_first": bool(policy.entry_point_first),
        "kev_tier": bool(policy.kev_tier),
        "chokepoint_weight": float(policy.chokepoint_weight),
        "feasibility_weight": float(policy.feasibility_weight),
        "cvss_weight": float(policy.cvss_weight),
        "epss_weight": float(policy.epss_weight),
        "asset_criticality_weight": float(policy.asset_criticality_weight),
        "tiebreaker": str(policy.tiebreaker),
    }


def run_simulation(
    baseline_graph: nx.MultiDiGraph,
    actions: List[SimulationAction],
    *,
    max_depth: int = 10,
    max_paths: int = 100,
    policy: Optional[OrderingPolicy] = None,
    scenario_id: str = "",
) -> SimulationResult:
    """Run deterministic remediation simulation on a deep copy.

    The baseline graph is never mutated. Actions apply sequentially;
    any invalid action fails the entire simulation.
    """
    if max_depth < 0:
        raise ValueError("max_depth must be >= 0")
    if max_paths < 0:
        raise ValueError("max_paths must be >= 0")
    if not actions:
        raise ValueError("At least one remediation action is required")

    active_policy = policy if policy is not None else DEFAULT_POLICY

    # Fixed blast-radius source population from BASELINE active findings.
    # Baseline asset snapshot for orphaned-finding comparison context.
    # The simulated graph is never re-populated with these nodes.
    baseline_finding_assets: List[str] = []
    baseline_asset_context: Dict[str, Dict[str, Any]] = {}
    for node_id, data in baseline_graph.nodes(data=True):
        if data.get("type") == "asset":
            baseline_asset_context[str(node_id)] = dict(data)
        if data.get("type") == "finding" and str(
            getattr(data.get("status"), "value", data.get("status"))
        ) == "active":
            baseline_finding_assets.append(str(data.get("asset_id")))
    blast_sources = sorted(set(baseline_finding_assets))

    baseline_summary, baseline_ranks = evaluate_state(
        baseline_graph,
        blast_sources=blast_sources,
        max_depth=max_depth,
        max_paths=max_paths,
        policy=active_policy,
        scenario_id=scenario_id,
        baseline_asset_context=baseline_asset_context,
    )

    sim_graph = copy_simulation_graph(baseline_graph)
    steps: List[StepResult] = []
    previous_summary = baseline_summary
    previous_ranks = dict(baseline_ranks)
    removed_findings: set[str] = set()

    for action in actions:
        apply_simulation_action(sim_graph, action)
        if action.target_type == "finding":
            removed_findings.add(action.target_id)

        summary, ranks = evaluate_state(
            sim_graph,
            blast_sources=blast_sources,
            max_depth=max_depth,
            max_paths=max_paths,
            policy=active_policy,
            scenario_id=scenario_id,
            baseline_asset_context=baseline_asset_context,
        )
        incremental = compare_summaries(previous_summary, summary)
        rank_cmp = compare_ranks(previous_ranks, ranks, removed_findings)
        steps.append(
            StepResult(
                action=action,
                state=summary,
                incremental_deltas=incremental,
                incremental_rank_comparison=rank_cmp,
            )
        )
        previous_summary = summary
        previous_ranks = dict(ranks)

    overall_deltas = compare_summaries(baseline_summary, previous_summary)
    overall_ranks = compare_ranks(baseline_ranks, previous_ranks, removed_findings)

    return SimulationResult(
        scenario_id=scenario_id,
        action_ids=[a.action_id for a in actions],
        applied_actions=list(actions),
        baseline=baseline_summary,
        steps=steps,
        final=previous_summary,
        overall_deltas=overall_deltas,
        overall_rank_comparison=overall_ranks,
        remediated_findings=sorted(removed_findings),
        max_depth_used=max_depth,
        max_paths_used=max_paths,
        policy_snapshot=_policy_snapshot(active_policy),
        simulated_at=datetime.now(timezone.utc),
    )
