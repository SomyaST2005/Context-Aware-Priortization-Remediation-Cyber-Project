"""
Pydantic schemas for remediation simulation.
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class SimulationActionResponse(BaseModel):
    action_id: str
    action_type: str
    target_id: str
    target_type: Literal["finding", "asset", "edge"]


class MetricDeltaResponse(BaseModel):
    metric_name: str
    before: Optional[float] = None
    after: Optional[float] = None
    absolute_delta: Optional[float] = None
    percent_change: Optional[float] = None


class FindingRankComparisonResponse(BaseModel):
    finding_id: str
    asset_id: str
    status: Literal["ACTIVE", "REMEDIATED"]
    baseline_rank: Optional[int] = Field(None, ge=1)
    simulated_rank: Optional[int] = Field(None, ge=1)
    rank_delta: Optional[int] = None
    baseline_operational_score: Optional[float] = Field(None, ge=0.0)
    simulated_operational_score: Optional[float] = Field(None, ge=0.0)


class StateSummaryResponse(BaseModel):
    total_attack_paths: int = Field(..., ge=0)
    crown_jewel_path_count: int = Field(..., ge=0)
    distinct_crown_jewels: int = Field(..., ge=0)
    sum_path_feasibility: float = Field(..., ge=0.0)
    max_path_feasibility: float = Field(..., ge=0.0)
    min_path_depth: Optional[int] = Field(None, ge=0)
    max_path_depth: Optional[int] = Field(None, ge=0)
    blast_affected_assets: int = Field(..., ge=0)
    blast_crown_jewels: int = Field(..., ge=0)
    blast_max_depth: int = Field(..., ge=0)
    chokepoint_count: int = Field(..., ge=0)
    max_chokepoint_score: float = Field(..., ge=0.0, le=1.0)
    sum_chokepoint_criticality: float = Field(..., ge=0.0)
    prioritization_count: int = Field(..., ge=0)
    max_operational_score: float = Field(..., ge=0.0)


class StepResultResponse(BaseModel):
    action: SimulationActionResponse
    state: StateSummaryResponse
    incremental_deltas: List[MetricDeltaResponse]
    incremental_rank_comparison: List[FindingRankComparisonResponse]


class SimulationRequest(BaseModel):
    remediation_action_ids: List[str] = Field(...)
    max_depth: int = 10
    max_paths: int = 100
    crown_jewel_first: bool = True
    entry_point_first: bool = True
    kev_tier: bool = True
    chokepoint_weight: float = 1.0
    feasibility_weight: float = 1.0
    cvss_weight: float = 1.0
    epss_weight: float = 0.5
    asset_criticality_weight: float = 0.5
    tiebreaker: Literal["finding_id", "asset_id"] = "finding_id"
    crown_jewel_first: bool = True
    entry_point_first: bool = True
    kev_tier: bool = True
    chokepoint_weight: float = Field(1.0, ge=0.0)
    feasibility_weight: float = Field(1.0, ge=0.0)
    cvss_weight: float = Field(1.0, ge=0.0)
    epss_weight: float = Field(0.5, ge=0.0)
    asset_criticality_weight: float = Field(0.5, ge=0.0)
    tiebreaker: Literal["finding_id", "asset_id"] = "finding_id"


class SimulationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    scenario_id: str
    action_ids: List[str]
    applied_actions: List[SimulationActionResponse]
    baseline: StateSummaryResponse
    steps: List[StepResultResponse]
    final: StateSummaryResponse
    overall_deltas: List[MetricDeltaResponse]
    overall_rank_comparison: List[FindingRankComparisonResponse]
    remediated_findings: List[str]
    max_depth_used: int = Field(..., ge=0)
    max_paths_used: int = Field(..., ge=0)
    policy_snapshot: dict
    simulated_at: datetime
