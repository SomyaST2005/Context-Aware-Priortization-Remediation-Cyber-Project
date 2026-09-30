"""
Pydantic schemas for AI explanation (Phase 8).

Discriminated request models (one variant per explanation_type),
structured claim/reference models, and the explanation response envelope.
"""
from __future__ import annotations

from typing import List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field


class FindingExplanationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    explanation_type: Literal["finding"]
    finding_id: str = Field(..., min_length=1)
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
    user_question: Optional[str] = None


class SimulationExplanationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    explanation_type: Literal["simulation"]
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
    user_question: Optional[str] = None


class OptimizationExplanationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    explanation_type: Literal["optimization"]
    candidate_action_ids: List[str] = Field(...)
    budget: float = 0.0
    max_depth: int = 10
    max_paths: int = 100
    user_question: Optional[str] = None


class EvidenceRefResponse(BaseModel):
    ref_id: str
    source_path: str
    value: Optional[float | int | str | bool] = None


class ExplanationClaimResponse(BaseModel):
    type: Literal["FACT", "INTERPRETATION", "LIMITATION"]
    statement: str
    evidence_refs: List[EvidenceRefResponse]


class ExplanationSummaryResponse(BaseModel):
    statement: str
    evidence_refs: List[EvidenceRefResponse]


class ExplanationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    scenario_id: str
    explanation_type: Literal["finding", "simulation", "optimization"]
    summary: ExplanationSummaryResponse
    key_factors: List[ExplanationClaimResponse]
    impact: List[ExplanationClaimResponse]
    changes: List[ExplanationClaimResponse]
    limitations: List[ExplanationClaimResponse]
    status: Literal["AVAILABLE", "FALLBACK", "UNAVAILABLE"]
    origin: Literal["model", "fallback-template", "none"]


class ExplainResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    deterministic_result: dict
    explanation: ExplanationResponse
