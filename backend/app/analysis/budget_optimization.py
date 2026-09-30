"""
Budget optimization analysis.

Deterministic exact subset selection over candidate remediation actions.
Each candidate subset is evaluated with the Phase 6 simulation engine;
selection maximizes crown-jewel path elimination (O1), then
path-feasibility reduction (O2), then lower cost, then lexicographic order.

There is no universal security score. O1/O2 are an explicit,
policy-independent optimization objective declared for the MVP.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Tuple

import networkx as nx

from backend.app.analysis.remediation_simulation import (
    SimulationAction,
    SimulationResult,
    StateSummary,
    compare_ranks,
    compare_summaries,
    evaluate_state,
    resolve_simulation_action,
    run_simulation,
)


MAX_CANDIDATE_ACTIONS = 12
MAX_REPORTED_INFEASIBLE_SUBSETS = 100
BUDGET_EPSILON = 1e-9

OBJECTIVE_NAME = "crown_jewel_paths_then_feasibility"


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


@dataclass(frozen=True)
class CandidateAction:
    """Validated optimization candidate with its Phase 6 action and cost."""

    action_id: str
    action_type: str
    target_id: str
    target_type: str
    estimated_cost: float
    validation_status: Literal["VALID"] = "VALID"


def resolve_candidates(action_rows: Any, scenario_id: str) -> List[CandidateAction]:
    """Resolve DB remediation rows into validated optimization candidates.

    Raises:
        ValueError: on unknown/unsupported/cross-scenario/mistargeted actions
            or invalid costs.
    """
    candidates: List[CandidateAction] = []
    for row in action_rows:
        resolved = resolve_simulation_action(row, scenario_id)
        raw_cost = getattr(row, "estimated_cost", None)
        if raw_cost is None:
            raise ValueError(
                f"Remediation action '{resolved.action_id}' has no estimated_cost"
            )
        cost = float(raw_cost)
        if cost < 0.0:
            raise ValueError(
                f"Remediation action '{resolved.action_id}' has negative cost"
            )
        candidates.append(
            CandidateAction(
                action_id=resolved.action_id,
                action_type=resolved.action_type,
                target_id=resolved.target_id,
                target_type=resolved.target_type,
                estimated_cost=cost,
            )
        )
    return candidates


@dataclass
class InfeasibleSubsetRecord:
    action_ids: List[str]
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {"action_ids": list(self.action_ids), "reason": self.reason}


@dataclass
class OptimizationResult:
    scenario_id: str
    budget: float
    objective: str
    candidates: List[CandidateAction]
    selected_action_ids: List[str]
    selected_total_cost: float
    within_budget: bool
    objective_o1: float
    objective_o2: float
    selection_reason: str
    baseline: StateSummary
    selected: StateSummary
    overall_deltas: List[Any]
    overall_rank_comparison: List[Any]
    remediated_findings: List[str]
    evaluated_subset_count: int
    infeasible_subset_count: int
    over_budget_subset_count: int
    reported_infeasible_subsets: List[InfeasibleSubsetRecord]
    max_depth_used: int
    max_paths_used: int
    optimized_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "budget": self.budget,
            "objective": self.objective,
            "candidates": [
                {
                    "action_id": c.action_id,
                    "action_type": c.action_type,
                    "target_id": c.target_id,
                    "target_type": c.target_type,
                    "estimated_cost": c.estimated_cost,
                    "validation_status": c.validation_status,
                }
                for c in self.candidates
            ],
            "selected_action_ids": list(self.selected_action_ids),
            "selected_total_cost": self.selected_total_cost,
            "within_budget": self.within_budget,
            "objective_o1": self.objective_o1,
            "objective_o2": self.objective_o2,
            "selection_reason": self.selection_reason,
            "baseline": self.baseline.to_dict(),
            "selected": self.selected.to_dict(),
            "overall_deltas": [d.to_dict() for d in self.overall_deltas],
            "overall_rank_comparison": [
                r.to_dict() for r in self.overall_rank_comparison
            ],
            "remediated_findings": sorted(self.remediated_findings),
            "evaluated_subset_count": self.evaluated_subset_count,
            "infeasible_subset_count": self.infeasible_subset_count,
            "over_budget_subset_count": self.over_budget_subset_count,
            "reported_infeasible_subsets": [
                r.to_dict() for r in self.reported_infeasible_subsets
            ],
            "max_depth_used": self.max_depth_used,
            "max_paths_used": self.max_paths_used,
            "optimized_at": self.optimized_at,
        }


def _subset_cost(
    subset: Tuple[CandidateAction, ...],
) -> float:
    return float(sum(c.estimated_cost for c in subset))


def _objective_key(
    o1: float, o2: float, cost: float, ids: Tuple[str, ...]
) -> Tuple[float, float, float, Tuple[str, ...]]:
    # Compared with explicit lexicographic logic in optimize():
    # higher O1, higher O2, lower cost (stored negated), smaller id tuple.
    return (o1, o2, -cost, ids)


def _tuple_is_smaller(a: Tuple[str, ...], b: Tuple[str, ...]) -> bool:
    return a < b


def optimize(
    baseline_graph: nx.MultiDiGraph,
    candidates: List[CandidateAction],
    *,
    budget: float,
    max_depth: int = 10,
    max_paths: int = 100,
    scenario_id: str = "",
) -> OptimizationResult:
    """Select the optimal feasible remediation subset by exact enumeration.

    The baseline graph is never mutated. Every evaluated subset runs the
    Phase 6 simulation in canonical ascending action-id order.
    """
    if budget < 0.0:
        raise ValueError("budget must be >= 0")
    if max_depth < 0:
        raise ValueError("max_depth must be >= 0")
    if max_paths < 0:
        raise ValueError("max_paths must be >= 0")
    if not candidates:
        raise ValueError("At least one candidate action is required")
    if len(candidates) > MAX_CANDIDATE_ACTIONS:
        raise ValueError(
            f"At most {MAX_CANDIDATE_ACTIONS} candidate actions are supported "
            f"for exact enumeration, got {len(candidates)}"
        )

    ordered = sorted(candidates, key=lambda c: c.action_id)
    by_id = {c.action_id: c for c in ordered}

    # Fixed blast-radius source population from BASELINE active findings,
    # mirroring run_simulation so the standalone baseline evaluation matches.
    baseline_asset_context: Dict[str, Dict[str, Any]] = {}
    baseline_finding_assets: List[str] = []
    for node_id, data in baseline_graph.nodes(data=True):
        if data.get("type") == "asset":
            baseline_asset_context[str(node_id)] = dict(data)
        if data.get("type") == "finding" and str(
            getattr(data.get("status"), "value", data.get("status"))
        ) == "active":
            baseline_finding_assets.append(str(data.get("asset_id")))
    blast_sources = sorted(set(baseline_finding_assets))

    from backend.app.analysis.prioritization import DEFAULT_POLICY

    baseline_summary, baseline_ranks = evaluate_state(
        baseline_graph,
        blast_sources=blast_sources,
        max_depth=max_depth,
        max_paths=max_paths,
        policy=DEFAULT_POLICY,
        scenario_id=scenario_id,
        baseline_asset_context=baseline_asset_context,
    )

    evaluated = 0
    infeasible = 0
    over_budget = 0
    reported_infeasible: List[InfeasibleSubsetRecord] = []

    best_key: Optional[Tuple[float, float, float, Tuple[str, ...]]] = None
    best_ids: Optional[Tuple[str, ...]] = None
    best_result: Optional[SimulationResult] = None

    ids = [c.action_id for c in ordered]
    for size in range(1, len(ids) + 1):
        for combo in itertools.combinations(ids, size):
            subset = tuple(by_id[i] for i in combo)
            total = _subset_cost(subset)
            if total > budget + BUDGET_EPSILON:
                over_budget += 1
                continue
            ordered_actions = [
                SimulationAction(
                    action_id=c.action_id,
                    action_type=c.action_type,
                    target_id=c.target_id,
                    target_type=c.target_type,
                )
                for c in subset
            ]
            try:
                result = run_simulation(
                    baseline_graph,
                    ordered_actions,
                    max_depth=max_depth,
                    max_paths=max_paths,
                    scenario_id=scenario_id,
                )
            except ValueError as exc:
                infeasible += 1
                if len(reported_infeasible) < MAX_REPORTED_INFEASIBLE_SUBSETS:
                    reported_infeasible.append(
                        InfeasibleSubsetRecord(
                            action_ids=list(combo), reason=str(exc)
                        )
                    )
                continue
            evaluated += 1
            o1 = float(result.baseline.crown_jewel_path_count) - float(
                result.final.crown_jewel_path_count
            )
            o2 = float(result.baseline.sum_path_feasibility) - float(
                result.final.sum_path_feasibility
            )
            key = _objective_key(o1, o2, total, combo)
            if best_key is None:
                better = True
            else:
                better = (
                    key[0] > best_key[0]
                    or (key[0] == best_key[0] and key[1] > best_key[1])
                    or (
                        key[0] == best_key[0]
                        and key[1] == best_key[1]
                        and key[2] > best_key[2]
                    )
                    or (
                        key[0] == best_key[0]
                        and key[1] == best_key[1]
                        and key[2] == best_key[2]
                        and _tuple_is_smaller(key[3], best_key[3])
                    )
                )
            if better:
                best_key = key
                best_ids = combo
                best_result = result

    # Empty selection when nothing evaluated or no positive improvement.
    positive = (
        best_key is not None and (best_key[0] > 0.0 or best_key[1] > 0.0)
    )
    if not positive:
        if baseline_summary.total_attack_paths == 0:
            reason = "zero_path_baseline"
        elif evaluated == 0 and infeasible > 0:
            reason = "all_infeasible"
        elif evaluated == 0 and over_budget > 0:
            reason = "all_exceed_budget"
        else:
            reason = "no_positive_improvement"
        zero_deltas = compare_summaries(baseline_summary, baseline_summary)
        zero_ranks = compare_ranks(baseline_ranks, baseline_ranks, set())
        return OptimizationResult(
            scenario_id=scenario_id,
            budget=float(budget),
            objective=OBJECTIVE_NAME,
            candidates=list(ordered),
            selected_action_ids=[],
            selected_total_cost=0.0,
            within_budget=True,
            objective_o1=0.0,
            objective_o2=0.0,
            selection_reason=reason,
            baseline=baseline_summary,
            selected=baseline_summary,
            overall_deltas=zero_deltas,
            overall_rank_comparison=zero_ranks,
            remediated_findings=[],
            evaluated_subset_count=evaluated,
            infeasible_subset_count=infeasible,
            over_budget_subset_count=over_budget,
            reported_infeasible_subsets=reported_infeasible,
            max_depth_used=max_depth,
            max_paths_used=max_paths,
            optimized_at=datetime.now(timezone.utc),
        )

    assert best_result is not None and best_ids is not None and best_key is not None
    total_cost = float(sum(by_id[i].estimated_cost for i in best_ids))
    return OptimizationResult(
        scenario_id=scenario_id,
        budget=float(budget),
        objective=OBJECTIVE_NAME,
        candidates=list(ordered),
        selected_action_ids=list(best_ids),
        selected_total_cost=total_cost,
        within_budget=bool(total_cost <= budget + BUDGET_EPSILON),
        objective_o1=float(best_key[0]),
        objective_o2=float(best_key[1]),
        selection_reason="optimal_selection",
        baseline=best_result.baseline,
        selected=best_result.final,
        overall_deltas=list(best_result.overall_deltas),
        overall_rank_comparison=list(best_result.overall_rank_comparison),
        remediated_findings=sorted(best_result.remediated_findings),
        evaluated_subset_count=evaluated,
        infeasible_subset_count=infeasible,
        over_budget_subset_count=over_budget,
        reported_infeasible_subsets=reported_infeasible,
        max_depth_used=max_depth,
        max_paths_used=max_paths,
        optimized_at=datetime.now(timezone.utc),
    )
