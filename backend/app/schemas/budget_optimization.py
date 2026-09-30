"""
Pydantic schemas for budget optimization.
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from backend.app.schemas.remediation_simulation import (
    FindingRankComparisonResponse,
    MetricDeltaResponse,
    StateSummaryResponse,
)


class CandidateActionResponse(BaseModel):
    action_id: str
    action_type: str
    target_id: str
    target_type: Literal["finding", "asset", "edge"]
    estimated_cost: float = Field(..., ge=0.0)
    validation_status: Literal["VALID"]


class InfeasibleSubsetResponse(BaseModel):
    action_ids: List[str]
    reason: str


class OptimizationRequest(BaseModel):
    candidate_action_ids: List[str] = Field(...)
    budget: float = 0.0
    max_depth: int = 10
    max_paths: int = 100


class OptimizationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    scenario_id: str
    budget: float = Field(..., ge=0.0)
    objective: str
    candidates: List[CandidateActionResponse]
    selected_action_ids: List[str]
    selected_total_cost: float = Field(..., ge=0.0)
    within_budget: bool
    objective_o1: float = Field(..., ge=0.0)
    objective_o2: float = Field(..., ge=0.0)
    selection_reason: str
    baseline: StateSummaryResponse
    selected: StateSummaryResponse
    overall_deltas: List[MetricDeltaResponse]
    overall_rank_comparison: List[FindingRankComparisonResponse]
    remediated_findings: List[str]
    evaluated_subset_count: int = Field(..., ge=0)
    infeasible_subset_count: int = Field(..., ge=0)
    over_budget_subset_count: int = Field(..., ge=0)
    reported_infeasible_subsets: List[InfeasibleSubsetResponse]
    max_depth_used: int = Field(..., ge=0)
    max_paths_used: int = Field(..., ge=0)
    optimized_at: datetime
