"""
Pydantic response schemas for contextual prioritization.
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Literal, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field


class VulnerabilityEvidenceResponse(BaseModel):
    cvss_normalized: float = Field(..., ge=0.0, le=1.0)
    epss_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    known_exploited: bool
    severity_category: Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


class AttackPathEvidenceResponse(BaseModel):
    path_count: int = Field(..., ge=0)
    max_feasibility: float = Field(..., ge=0.0)
    avg_feasibility: float = Field(..., ge=0.0)
    crown_jewel_reachable: bool
    unique_entry_points: int = Field(..., ge=0)
    unique_crown_jewels: int = Field(..., ge=0)
    max_depth: int = Field(..., ge=0)
    min_depth: int = Field(..., ge=0)


class EnvironmentalEvidenceResponse(BaseModel):
    asset_criticality_normalized: float = Field(..., ge=0.0, le=1.0)
    is_entry_point: bool
    is_crown_jewel: bool
    network_zone: Optional[str] = None
    blast_radius_assets: int = Field(..., ge=0)
    blast_radius_crown_jewels: int = Field(..., ge=0)
    blast_radius_max_depth: int = Field(..., ge=0)
    blast_radius_min_cost: float = Field(..., ge=0.0)
    blast_radius_max_prob: float = Field(..., ge=0.0, le=1.0)


class ChokepointEvidenceResponse(BaseModel):
    finding_chokepoint_score: float = Field(..., ge=0.0, le=1.0)
    finding_path_feasibility_criticality: float = Field(..., ge=0.0)
    finding_path_count: int = Field(..., ge=0)
    asset_chokepoint_score: float = Field(..., ge=0.0, le=1.0)
    asset_path_feasibility_criticality: float = Field(..., ge=0.0)
    asset_path_count: int = Field(..., ge=0)


class RemediationEvidenceResponse(BaseModel):
    remediation_cost: float = Field(..., ge=0.0)
    implementation_complexity: Optional[Literal["LOW", "MEDIUM", "HIGH"]] = None
    downtime_required: bool
    action_type: Optional[str] = None


class EvidenceBreakdownResponse(BaseModel):
    vulnerability_intrinsic: VulnerabilityEvidenceResponse
    attack_path_context: AttackPathEvidenceResponse
    environmental: EnvironmentalEvidenceResponse
    chokepoint: ChokepointEvidenceResponse
    remediation_context: RemediationEvidenceResponse


class PriorityProfileResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    finding_id: str
    asset_id: str
    vulnerability_id: str

    cvss_normalized: float = Field(..., ge=0.0, le=1.0)
    epss_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    epss_available: bool
    known_exploited: bool
    severity_category: Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    path_participation_count: int = Field(..., ge=0)
    max_path_feasibility: float = Field(..., ge=0.0)
    max_path_feasibility_normalized: float = Field(..., ge=0.0, lt=1.0)
    avg_path_feasibility: float = Field(..., ge=0.0)
    crown_jewel_reachable: bool
    unique_entry_points: int = Field(..., ge=0)
    unique_crown_jewels: int = Field(..., ge=0)
    min_path_depth: int = Field(..., ge=0)
    max_path_depth: int = Field(..., ge=0)

    asset_criticality_normalized: float = Field(..., ge=0.0, le=1.0)
    is_entry_point: bool
    is_crown_jewel: bool
    network_zone: Optional[str] = None
    blast_radius_asset_count: int = Field(..., ge=0)
    blast_radius_crown_jewels: int = Field(..., ge=0)
    blast_radius_max_depth: int = Field(..., ge=0)
    blast_radius_min_cost: float = Field(..., ge=0.0)
    blast_radius_max_prob: float = Field(..., ge=0.0, le=1.0)

    finding_chokepoint_score: float = Field(..., ge=0.0, le=1.0)
    finding_path_feasibility_criticality: float = Field(..., ge=0.0)
    finding_path_count: int = Field(..., ge=0)
    asset_chokepoint_score: float = Field(..., ge=0.0, le=1.0)
    asset_path_feasibility_criticality: float = Field(..., ge=0.0)
    asset_path_count: int = Field(..., ge=0)

    remediation_cost: float = Field(..., ge=0.0)
    implementation_complexity: Optional[Literal["LOW", "MEDIUM", "HIGH"]] = None
    downtime_required: bool
    action_type: Optional[str] = None
    baseline_is_entry_point: Optional[bool] = None


class OrderingKeysResponse(BaseModel):
    tiers: Tuple[int, ...]
    composite_score: float = Field(..., ge=0.0)
    tiebreaker: str
    finding_id: str
    asset_id: str


class OrderingPolicyResponse(BaseModel):
    crown_jewel_first: bool
    entry_point_first: bool
    kev_tier: bool
    chokepoint_weight: float = Field(..., ge=0.0)
    feasibility_weight: float = Field(..., ge=0.0)
    cvss_weight: float = Field(..., ge=0.0)
    epss_weight: float = Field(..., ge=0.0)
    asset_criticality_weight: float = Field(..., ge=0.0)
    tiebreaker: Literal["finding_id", "asset_id"]


class PrioritizationResultResponse(BaseModel):
    profile: PriorityProfileResponse
    operational_rank: int = Field(..., ge=1)
    ordering_keys: OrderingKeysResponse
    operational_score: float = Field(..., ge=0.0)
    evidence: EvidenceBreakdownResponse
    scenario_id: str
    computed_at: datetime


class PrioritizationResponse(BaseModel):
    scenario_id: str
    total_findings: int = Field(..., ge=0)
    returned_findings: int = Field(..., ge=0)
    max_depth_used: int = Field(..., ge=0)
    max_paths_used: int = Field(..., ge=0)
    min_operational_score: float = Field(..., ge=0.0)
    sort_by: Literal[
        "operational_rank",
        "chokepoint_score",
        "cvss",
        "feasibility",
        "asset_criticality",
    ]
    policy: OrderingPolicyResponse
    items: List[PrioritizationResultResponse]
