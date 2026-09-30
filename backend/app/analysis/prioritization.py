"""
Contextual prioritization analysis.

This module builds a policy-independent PriorityProfile for every active finding
and then converts those profiles into a policy-specific operational ordering.
The analytical profile deliberately contains no universal "priority score".
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from math import isfinite
from typing import Any, Dict, Iterable, List, Literal, Optional, Tuple

import networkx as nx

from backend.app.analysis.path_analysis import AttackPath, find_attack_paths
from backend.app.analysis.blast_radius import BlastRadiusResult, compute_blast_radius
from backend.app.analysis.chokepoint import ChokepointResult, compute_chokepoints


EPSILON = 1e-9

EntityType = Literal["asset", "finding"]
Tiebreaker = Literal["finding_id", "asset_id"]


def normalize_cvss(score: float) -> float:
    """Normalize CVSS v3 score from 0..10 to 0..1."""
    value = float(score)
    if not isfinite(value):
        raise ValueError("CVSS score must be finite")
    return max(0.0, min(1.0, value / 10.0))


def normalize_asset_criticality(criticality: float) -> float:
    """Normalize asset criticality from 1..10 to 0..1."""
    value = float(criticality)
    if not isfinite(value):
        raise ValueError("Asset criticality must be finite")
    return max(0.0, min(1.0, (value - 1.0) / 9.0))


def path_feasibility(probability: float, traversal_cost: float) -> float:
    """Compute the approved PathFeasibility metric."""
    probability = float(probability)
    traversal_cost = float(traversal_cost)
    if not isfinite(probability) or not isfinite(traversal_cost):
        raise ValueError("Path probability and traversal cost must be finite")
    if probability < 0.0:
        raise ValueError("Path probability cannot be negative")
    if traversal_cost < 0.0:
        raise ValueError("Path traversal cost cannot be negative")
    return probability / max(traversal_cost, EPSILON)


def normalize_path_feasibility(feasibility: float) -> float:
    """
    Zero-preserving bounded monotonic transform.

    f(x) = x / (1 + x)
    """
    value = float(feasibility)
    if not isfinite(value):
        raise ValueError("Path feasibility must be finite")
    if value <= 0.0:
        return 0.0
    return value / (1.0 + value)


def cvss_to_severity(cvss: float) -> str:
    """Standard CVSS v3.1 severity mapping."""
    value = float(cvss)
    if value >= 9.0:
        return "CRITICAL"
    if value >= 7.0:
        return "HIGH"
    if value >= 4.0:
        return "MEDIUM"
    if value > 0.0:
        return "LOW"
    return "NONE"


def _enum_value(value: Any) -> Any:
    """Return an enum's value when present, otherwise return the original value."""
    return getattr(value, "value", value)


def _float_or_zero(value: Any) -> float:
    if value is None:
        return 0.0
    return float(value)


def _bool_value(value: Any) -> bool:
    return bool(value)


def get_active_findings(graph: nx.MultiDiGraph) -> List[str]:
    """Return active finding node IDs in deterministic order."""
    finding_ids: List[str] = []
    for node_id, data in graph.nodes(data=True):
        if data.get("type") != "finding":
            continue
        status = _enum_value(data.get("status"))
        if status == "active":
            finding_ids.append(str(node_id))
    return sorted(finding_ids)


def build_finding_path_mapping(
    paths: Iterable[AttackPath],
    graph: nx.MultiDiGraph,
) -> Dict[str, List[AttackPath]]:
    """
    Map each finding ID to the attack paths containing that finding node.

    This is deliberately finding-level: two findings on the same asset can
    participate in different attack paths.
    """
    mapping: Dict[str, List[AttackPath]] = {}
    for path in paths:
        seen_in_path: set[str] = set()
        for node_id in path.nodes:
            if node_id in seen_in_path:
                continue
            seen_in_path.add(node_id)
            node_data = graph.nodes.get(node_id, {})
            if node_data.get("type") != "finding":
                continue
            mapping.setdefault(str(node_id), []).append(path)
    return mapping


def aggregate_blast_radius(result: BlastRadiusResult) -> Dict[str, Any]:
    """Aggregate downstream Blast Radius details into profile-level evidence."""
    details = list(result.reachability_details)
    if not details:
        return {
            "source_asset_id": result.source_asset,
            "affected_asset_count": 0,
            "crown_jewels_reached": 0,
            "max_depth_reached": int(result.max_depth_reached),
            "min_traversal_cost": 0.0,
            "max_probability": 0.0,
        }

    return {
        "source_asset_id": result.source_asset,
        "affected_asset_count": int(result.affected_asset_count),
        "crown_jewels_reached": len(result.crown_jewels_reached),
        "max_depth_reached": int(result.max_depth_reached),
        "min_traversal_cost": min(float(d.min_traversal_cost) for d in details),
        "max_probability": max(float(d.max_probability) for d in details),
    }


def _find_remediation_context(graph: nx.MultiDiGraph, finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Read optional remediation metadata from the finding node.

    The current canonical graph builder does not materialize RemediationAction
    objects as graph nodes/attributes, so these values default to None/0 when
    unavailable. This keeps remediation context descriptive without modifying
    the graph-builder contract.
    """
    return {
        "remediation_cost": _float_or_zero(finding.get("remediation_cost")),
        "implementation_complexity": finding.get("implementation_complexity"),
        "downtime_required": _bool_value(finding.get("downtime_required")),
        "action_type": finding.get("action_type"),
    }


@dataclass
class PriorityProfile:
    """Policy-independent contextual evidence for one active finding."""

    finding_id: str
    asset_id: str
    vulnerability_id: str

    # Vulnerability-intrinsic
    cvss_normalized: float
    epss_score: Optional[float]
    epss_available: bool
    known_exploited: bool
    severity_category: str

    # Attack-path context (finding-level)
    path_participation_count: int
    max_path_feasibility: float
    max_path_feasibility_normalized: float
    avg_path_feasibility: float
    crown_jewel_reachable: bool
    unique_entry_points: int
    unique_crown_jewels: int
    min_path_depth: int
    max_path_depth: int

    # Environmental/business (asset-level)
    asset_criticality_normalized: float
    is_entry_point: bool
    is_crown_jewel: bool
    network_zone: Optional[str]
    blast_radius_asset_count: int
    blast_radius_crown_jewels: int
    blast_radius_max_depth: int
    blast_radius_min_cost: float
    blast_radius_max_prob: float

    # Chokepoint evidence
    finding_chokepoint_score: float
    finding_path_feasibility_criticality: float
    finding_path_count: int
    asset_chokepoint_score: float
    asset_path_feasibility_criticality: float
    asset_path_count: int

    # Remediation context (descriptive only)
    remediation_cost: float
    implementation_complexity: Optional[str]
    downtime_required: bool
    action_type: Optional[str]

    # Baseline descriptive context for orphaned findings (simulation only).
    # None for ordinary findings whose asset exists in the analyzed graph.
    baseline_is_entry_point: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "asset_id": self.asset_id,
            "vulnerability_id": self.vulnerability_id,
            "cvss_normalized": self.cvss_normalized,
            "epss_score": self.epss_score,
            "epss_available": self.epss_available,
            "known_exploited": self.known_exploited,
            "severity_category": self.severity_category,
            "path_participation_count": self.path_participation_count,
            "max_path_feasibility": self.max_path_feasibility,
            "max_path_feasibility_normalized": self.max_path_feasibility_normalized,
            "avg_path_feasibility": self.avg_path_feasibility,
            "crown_jewel_reachable": self.crown_jewel_reachable,
            "unique_entry_points": self.unique_entry_points,
            "unique_crown_jewels": self.unique_crown_jewels,
            "min_path_depth": self.min_path_depth,
            "max_path_depth": self.max_path_depth,
            "asset_criticality_normalized": self.asset_criticality_normalized,
            "is_entry_point": self.is_entry_point,
            "is_crown_jewel": self.is_crown_jewel,
            "network_zone": self.network_zone,
            "blast_radius_asset_count": self.blast_radius_asset_count,
            "blast_radius_crown_jewels": self.blast_radius_crown_jewels,
            "blast_radius_max_depth": self.blast_radius_max_depth,
            "blast_radius_min_cost": self.blast_radius_min_cost,
            "blast_radius_max_prob": self.blast_radius_max_prob,
            "finding_chokepoint_score": self.finding_chokepoint_score,
            "finding_path_feasibility_criticality": self.finding_path_feasibility_criticality,
            "finding_path_count": self.finding_path_count,
            "asset_chokepoint_score": self.asset_chokepoint_score,
            "asset_path_feasibility_criticality": self.asset_path_feasibility_criticality,
            "asset_path_count": self.asset_path_count,
            "remediation_cost": self.remediation_cost,
            "implementation_complexity": self.implementation_complexity,
            "downtime_required": self.downtime_required,
            "action_type": self.action_type,
            "baseline_is_entry_point": self.baseline_is_entry_point,
        }


@dataclass
class VulnerabilityEvidence:
    cvss_normalized: float
    epss_score: Optional[float]
    known_exploited: bool
    severity_category: str


@dataclass
class AttackPathEvidence:
    path_count: int
    max_feasibility: float
    avg_feasibility: float
    crown_jewel_reachable: bool
    unique_entry_points: int
    unique_crown_jewels: int
    max_depth: int
    min_depth: int


@dataclass
class EnvironmentalEvidence:
    asset_criticality_normalized: float
    is_entry_point: bool
    is_crown_jewel: bool
    network_zone: Optional[str]
    blast_radius_assets: int
    blast_radius_crown_jewels: int
    blast_radius_max_depth: int
    blast_radius_min_cost: float
    blast_radius_max_prob: float


@dataclass
class ChokepointEvidence:
    finding_chokepoint_score: float
    finding_path_feasibility_criticality: float
    finding_path_count: int
    asset_chokepoint_score: float
    asset_path_feasibility_criticality: float
    asset_path_count: int


@dataclass
class RemediationEvidence:
    remediation_cost: float
    implementation_complexity: Optional[str]
    downtime_required: bool
    action_type: Optional[str]


@dataclass
class EvidenceBreakdown:
    vulnerability_intrinsic: VulnerabilityEvidence
    attack_path_context: AttackPathEvidence
    environmental: EnvironmentalEvidence
    chokepoint: ChokepointEvidence
    remediation_context: RemediationEvidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vulnerability_intrinsic": self.vulnerability_intrinsic.__dict__,
            "attack_path_context": self.attack_path_context.__dict__,
            "environmental": self.environmental.__dict__,
            "chokepoint": self.chokepoint.__dict__,
            "remediation_context": self.remediation_context.__dict__,
        }


@dataclass
class OrderingPolicy:
    """Explicit, configurable policy for converting profiles into an order."""

    crown_jewel_first: bool = True
    entry_point_first: bool = True
    kev_tier: bool = True
    chokepoint_weight: float = 1.0
    feasibility_weight: float = 1.0
    cvss_weight: float = 1.0
    epss_weight: float = 0.5
    asset_criticality_weight: float = 0.5
    tiebreaker: Tiebreaker = "finding_id"

    def __post_init__(self) -> None:
        for name, value in (
            ("chokepoint_weight", self.chokepoint_weight),
            ("feasibility_weight", self.feasibility_weight),
            ("cvss_weight", self.cvss_weight),
            ("epss_weight", self.epss_weight),
            ("asset_criticality_weight", self.asset_criticality_weight),
        ):
            if not isfinite(float(value)):
                raise ValueError(f"{name} must be finite")
            if float(value) < 0.0:
                raise ValueError(f"{name} must be >= 0")
        if self.tiebreaker not in ("finding_id", "asset_id"):
            raise ValueError("tiebreaker must be 'finding_id' or 'asset_id'")


DEFAULT_POLICY = OrderingPolicy()


@dataclass
class OrderingKeys:
    tiers: Tuple[int, ...]
    composite_score: float
    tiebreaker: str
    finding_id: str
    asset_id: str

    def sort_key(self) -> Tuple[Any, ...]:
        return (
            self.tiers,
            -self.composite_score,
            self.tiebreaker,
            self.finding_id,
        )


@dataclass
class PrioritizationResult:
    profile: PriorityProfile
    operational_rank: int
    ordering_keys: OrderingKeys
    operational_score: float
    evidence: EvidenceBreakdown
    scenario_id: str
    computed_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile": self.profile.to_dict(),
            "operational_rank": self.operational_rank,
            "ordering_keys": {
                "tiers": list(self.ordering_keys.tiers),
                "composite_score": self.ordering_keys.composite_score,
                "tiebreaker": self.ordering_keys.tiebreaker,
                "finding_id": self.ordering_keys.finding_id,
                "asset_id": self.ordering_keys.asset_id,
            },
            "operational_score": self.operational_score,
            "evidence": self.evidence.to_dict(),
            "scenario_id": self.scenario_id,
            "computed_at": self.computed_at,
        }


@dataclass
class OperationalItem:
    profile: PriorityProfile
    operational_rank: int
    ordering_keys: OrderingKeys
    operational_score: float


@dataclass
class OperationalOrdering:
    items: List[OperationalItem]
    policy: OrderingPolicy


def compute_ordering_keys(
    profile: PriorityProfile,
    policy: OrderingPolicy,
) -> OrderingKeys:
    """Build deterministic ordering keys and compute the composite exactly once."""
    tiers: List[int] = []

    if policy.crown_jewel_first:
        tiers.append(0 if profile.crown_jewel_reachable else 1)

    if policy.entry_point_first:
        tiers.append(0 if profile.is_entry_point else 1)

    if policy.kev_tier:
        tiers.append(0 if profile.known_exploited else 1)

    composite = (
        policy.chokepoint_weight * profile.finding_chokepoint_score
        + policy.feasibility_weight * profile.max_path_feasibility_normalized
        + policy.cvss_weight * profile.cvss_normalized
        + policy.epss_weight * (profile.epss_score or 0.0)
        + policy.asset_criticality_weight * profile.asset_criticality_normalized
    )

    return OrderingKeys(
        tiers=tuple(tiers),
        composite_score=float(composite),
        tiebreaker=str(getattr(profile, policy.tiebreaker)),
        finding_id=profile.finding_id,
        asset_id=profile.asset_id,
    )


def _build_evidence_breakdown(profile: PriorityProfile) -> EvidenceBreakdown:
    return EvidenceBreakdown(
        vulnerability_intrinsic=VulnerabilityEvidence(
            cvss_normalized=profile.cvss_normalized,
            epss_score=profile.epss_score,
            known_exploited=profile.known_exploited,
            severity_category=profile.severity_category,
        ),
        attack_path_context=AttackPathEvidence(
            path_count=profile.path_participation_count,
            max_feasibility=profile.max_path_feasibility,
            avg_feasibility=profile.avg_path_feasibility,
            crown_jewel_reachable=profile.crown_jewel_reachable,
            unique_entry_points=profile.unique_entry_points,
            unique_crown_jewels=profile.unique_crown_jewels,
            max_depth=profile.max_path_depth,
            min_depth=profile.min_path_depth,
        ),
        environmental=EnvironmentalEvidence(
            asset_criticality_normalized=profile.asset_criticality_normalized,
            is_entry_point=profile.is_entry_point,
            is_crown_jewel=profile.is_crown_jewel,
            network_zone=profile.network_zone,
            blast_radius_assets=profile.blast_radius_asset_count,
            blast_radius_crown_jewels=profile.blast_radius_crown_jewels,
            blast_radius_max_depth=profile.blast_radius_max_depth,
            blast_radius_min_cost=profile.blast_radius_min_cost,
            blast_radius_max_prob=profile.blast_radius_max_prob,
        ),
        chokepoint=ChokepointEvidence(
            finding_chokepoint_score=profile.finding_chokepoint_score,
            finding_path_feasibility_criticality=profile.finding_path_feasibility_criticality,
            finding_path_count=profile.finding_path_count,
            asset_chokepoint_score=profile.asset_chokepoint_score,
            asset_path_feasibility_criticality=profile.asset_path_feasibility_criticality,
            asset_path_count=profile.asset_path_count,
        ),
        remediation_context=RemediationEvidence(
            remediation_cost=profile.remediation_cost,
            implementation_complexity=profile.implementation_complexity,
            downtime_required=profile.downtime_required,
            action_type=profile.action_type,
        ),
    )


def _build_profile(
    graph: nx.MultiDiGraph,
    finding_id: str,
    paths: List[AttackPath],
    blast_radius: Optional[BlastRadiusResult],
    finding_chokepoint: Optional[Any],
    asset_chokepoint: Optional[Any],
    baseline_asset: Optional[Dict[str, Any]] = None,
) -> PriorityProfile:
    finding = graph.nodes[finding_id]
    asset_id = str(finding.get("asset_id"))
    vulnerability_id = str(finding.get("vulnerability_id"))

    if asset_id not in graph.nodes or graph.nodes[asset_id].get("type") != "asset":
        if baseline_asset is None:
            raise ValueError(f"Finding '{finding_id}' references missing/non-asset node '{asset_id}'")
        # Simulation compatibility: the asset node was intentionally removed
        # (e.g. ISOLATE_ASSET) while the finding survives. Retain the baseline
        # asset's descriptive/business metadata as comparison context, except
        # for is_entry_point: entry-point status is current topological /
        # operational state, so the simulated ordering value is False while
        # the historical baseline value is preserved separately. All
        # graph-derived evidence is still recalculated from the simulated graph.
        asset = baseline_asset
        asset_missing = True
    else:
        asset = graph.nodes[asset_id]
        asset_missing = False
    if vulnerability_id not in graph.nodes or graph.nodes[vulnerability_id].get("type") != "vulnerability":
        raise ValueError(
            f"Finding '{finding_id}' references missing/non-vulnerability node '{vulnerability_id}'"
        )

    vulnerability = graph.nodes[vulnerability_id]

    feasibility_values = [
        path_feasibility(p.total_probability, p.total_traversal_cost)
        for p in paths
    ]

    if feasibility_values:
        max_feasibility = max(feasibility_values)
        avg_feasibility = sum(feasibility_values) / len(feasibility_values)
        min_depth = min(int(p.hop_count) for p in paths)
        max_depth = max(int(p.hop_count) for p in paths)
        unique_entry_points = len({str(p.entry_point) for p in paths})
        unique_crown_jewels = len({str(p.crown_jewel) for p in paths})
        crown_jewel_reachable = bool(unique_crown_jewels)
    else:
        max_feasibility = 0.0
        avg_feasibility = 0.0
        min_depth = 0
        max_depth = 0
        unique_entry_points = 0
        unique_crown_jewels = 0
        crown_jewel_reachable = False

    blast = (
        aggregate_blast_radius(blast_radius)
        if blast_radius is not None
        else {
            "affected_asset_count": 0,
            "crown_jewels_reached": 0,
            "max_depth_reached": 0,
            "min_traversal_cost": 0.0,
            "max_probability": 0.0,
        }
    )

    finding_chokepoint_score = float(getattr(finding_chokepoint, "chokepoint_score", 0.0))
    finding_rwp = float(
        getattr(finding_chokepoint, "path_feasibility_criticality", 0.0)
    )
    finding_path_count = int(getattr(finding_chokepoint, "path_count", 0))
    asset_chokepoint_score = float(getattr(asset_chokepoint, "chokepoint_score", 0.0))
    asset_rwp = float(getattr(asset_chokepoint, "path_feasibility_criticality", 0.0))
    asset_path_count = int(getattr(asset_chokepoint, "path_count", 0))

    remediation = _find_remediation_context(graph, finding)

    epss_raw = vulnerability.get("epss_score")
    epss_score = None if epss_raw is None else float(epss_raw)

    return PriorityProfile(
        finding_id=finding_id,
        asset_id=asset_id,
        vulnerability_id=vulnerability_id,
        cvss_normalized=normalize_cvss(_float_or_zero(vulnerability.get("cvss_score"))),
        epss_score=epss_score,
        epss_available=epss_raw is not None,
        known_exploited=_bool_value(vulnerability.get("known_exploited", False)),
        severity_category=cvss_to_severity(_float_or_zero(vulnerability.get("cvss_score"))),
        path_participation_count=len(paths),
        max_path_feasibility=max_feasibility,
        max_path_feasibility_normalized=normalize_path_feasibility(max_feasibility),
        avg_path_feasibility=avg_feasibility,
        crown_jewel_reachable=crown_jewel_reachable,
        unique_entry_points=unique_entry_points,
        unique_crown_jewels=unique_crown_jewels,
        min_path_depth=min_depth,
        max_path_depth=max_depth,
        asset_criticality_normalized=normalize_asset_criticality(
            _float_or_zero(asset.get("criticality"))
        ),
        is_entry_point=(
            False if asset_missing else _bool_value(asset.get("is_entry_point", False))
        ),
        is_crown_jewel=_bool_value(asset.get("is_crown_jewel", False)),
        network_zone=asset.get("network_zone"),
        blast_radius_asset_count=int(blast.get("affected_asset_count", 0)),
        blast_radius_crown_jewels=int(blast.get("crown_jewels_reached", 0)),
        blast_radius_max_depth=int(blast.get("max_depth_reached", 0)),
        blast_radius_min_cost=float(blast.get("min_traversal_cost", 0.0)),
        blast_radius_max_prob=float(blast.get("max_probability", 0.0)),
        finding_chokepoint_score=finding_chokepoint_score,
        finding_path_feasibility_criticality=finding_rwp,
        finding_path_count=finding_path_count,
        asset_chokepoint_score=asset_chokepoint_score,
        asset_path_feasibility_criticality=asset_rwp,
        asset_path_count=asset_path_count,
        remediation_cost=float(remediation["remediation_cost"]),
        implementation_complexity=remediation["implementation_complexity"],
        downtime_required=bool(remediation["downtime_required"]),
        action_type=remediation["action_type"],
        baseline_is_entry_point=(
            _bool_value(asset.get("is_entry_point", False)) if asset_missing else None
        ),
    )


def compute_prioritization(
    graph: nx.MultiDiGraph,
    max_depth: int = 10,
    max_paths: int = 100,
    policy: OrderingPolicy = DEFAULT_POLICY,
    scenario_id: str = "",
    baseline_asset_context: Optional[Dict[str, Dict[str, Any]]] = None,
) -> List[PrioritizationResult]:
    """
    Compute contextual profiles and policy-specific operational ordering.

    The analysis layer is deterministic and read-only with respect to the graph.

    baseline_asset_context optionally maps asset_id -> baseline asset node
    attributes. It is used ONLY for findings whose asset node is absent from
    the graph (e.g. after simulation removed the asset while the finding
    survives). When None (default), missing assets raise ValueError as before.
    """
    if max_depth < 0:
        raise ValueError("max_depth must be >= 0")
    if max_paths < 0:
        raise ValueError("max_paths must be >= 0")

    active_finding_ids = get_active_findings(graph)

    # 1. Attack paths (single shared computation)
    paths = find_attack_paths(graph, max_depth=max_depth, max_paths=max_paths)
    finding_to_paths = build_finding_path_mapping(paths, graph)

    # 2. Blast radius for unique active-finding-associated assets
    active_asset_ids = sorted(
        {
            str(graph.nodes[finding_id].get("asset_id"))
            for finding_id in active_finding_ids
        }
    )
    blast_results: Dict[str, BlastRadiusResult] = {}
    for asset_id in active_asset_ids:
        if asset_id in graph.nodes and graph.nodes[asset_id].get("type") == "asset":
            blast_results[asset_id] = compute_blast_radius(
                graph,
                asset_id,
                max_depth=max_depth,
            )

    # 3. Chokepoint analysis (single shared computation)
    chokepoint_result: ChokepointResult = compute_chokepoints(
        graph,
        max_depth=max_depth,
        max_paths=max_paths,
    )
    entity_to_chokepoint = {
        str(detail.entity_id): detail
        for detail in chokepoint_result.chokepoints
    }

    # 4. Build policy-independent profiles
    computed_at = datetime.now(timezone.utc)
    results: List[PrioritizationResult] = []

    for finding_id in active_finding_ids:
        finding_node = graph.nodes[finding_id]
        asset_id = str(finding_node.get("asset_id"))
        baseline_asset = None
        if baseline_asset_context is not None:
            baseline_asset = baseline_asset_context.get(asset_id)
        profile = _build_profile(
            graph=graph,
            finding_id=finding_id,
            paths=finding_to_paths.get(finding_id, []),
            blast_radius=blast_results.get(asset_id),
            finding_chokepoint=entity_to_chokepoint.get(finding_id),
            asset_chokepoint=entity_to_chokepoint.get(asset_id),
            baseline_asset=baseline_asset,
        )
        ordering_keys = compute_ordering_keys(profile, policy)
        evidence = _build_evidence_breakdown(profile)
        results.append(
            PrioritizationResult(
                profile=profile,
                operational_rank=0,
                ordering_keys=ordering_keys,
                operational_score=ordering_keys.composite_score,
                evidence=evidence,
                scenario_id=scenario_id,
                computed_at=computed_at,
            )
        )

    # 5. Deterministic policy ordering
    results.sort(key=lambda result: result.ordering_keys.sort_key())
    for rank, result in enumerate(results, start=1):
        result.operational_rank = rank

    return results
